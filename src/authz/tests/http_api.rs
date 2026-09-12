use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use authguard_authz::cache::{IAuthorizationCache, MemoryAuthorizationCache};
use authguard_authz::config::{
    AppConfigProperties, IdentityProperties, ScopeDeliveryProperties, SqliteProperties,
};
use authguard_authz::handler::{DefaultAuthorizationHandler, PolicyHandler, PrincipalHandler};
use authguard_authz::model::access_context_v1::access_context_service_server::AccessContextService;
use authguard_authz::model::AccessContextSigner;
use authguard_authz::principal::ScimPrincipalDiscovery;
use authguard_authz::server::AuthguardServer;
use authguard_authz::storage::{AuthzSqliteRepository, PolicyRepository, PrincipalRepository};
use authguard_authz::AuthzMetrics;
use authguard_authz::{
    AccessContext, AuthorizationConditionSpec, Effect, HttpRouteMatcher, IamActionInfo,
    IamPolicyInfo, IamPrincipalInfo, IamRoleBindingInfo, IamRoleInfo, PrincipalKind,
    PrincipalStatus,
};
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request as HttpRequest, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use envoy_types::ext_authz::v3::pb::{Authorization, CheckRequest};
use envoy_types::pb::envoy::service::auth::v3::{
    attribute_context, check_response, AttributeContext,
};
use serde_json::{json, Value};
use tonic::Request;
use tower::ServiceExt as _;

const ISSUER: &str = "https://identity.example.com/realms/customer-growth";
const USER_ID: &str = "principal-alice";
const GROUP_ID: &str = "principal-growth-team";
const CONTEXT_SIGNING_KEY: [u8; 32] = [7; 32];

struct TestRuntime {
    policy: PolicyHandler,
    principals: PrincipalHandler,
    authorization: DefaultAuthorizationHandler,
    cache: Arc<dyn IAuthorizationCache>,
    metrics: AuthzMetrics,
    repository: Arc<AuthzSqliteRepository>,
}

async fn runtime(scope_delivery: ScopeDeliveryProperties) -> TestRuntime {
    let repository = Arc::new(
        AuthzSqliteRepository::connect(&SqliteProperties {
            url: "sqlite::memory:".to_string(),
            max_connections: 1,
            connect_timeout: Duration::from_secs(2),
        })
        .await
        .expect("connect SQLite"),
    );
    repository.upsert(&principal(USER_ID, "alice", PrincipalKind::User)).await.expect("user");
    repository
        .upsert(&principal(GROUP_ID, "group:growth-team", PrincipalKind::Group))
        .await
        .expect("group");
    let policy_document = policy();
    repository.replace(&policy_document).await.expect("seed policy");
    let cache: Arc<dyn IAuthorizationCache> = Arc::new(MemoryAuthorizationCache::default());
    let metrics = AuthzMetrics::default();
    let policy = PolicyHandler::open(repository.clone(), repository.clone(), metrics.clone(), None)
        .await
        .expect("policy handler");
    let scim = ScimPrincipalDiscovery::new("corporate-scim", ISSUER).expect("SCIM discovery");
    let principals = PrincipalHandler::new(repository.clone(), Vec::new(), Some(scim));
    let authorization = DefaultAuthorizationHandler::new(
        policy.clone(),
        principals.clone(),
        cache.clone(),
        metrics.clone(),
        IdentityProperties::default(),
        scope_delivery,
        AccessContextSigner::new(CONTEXT_SIGNING_KEY).expect("test signer"),
        None,
    );
    TestRuntime { policy, principals, authorization, cache, metrics, repository }
}

fn principal(id: &str, display_name: &str, kind: PrincipalKind) -> IamPrincipalInfo {
    IamPrincipalInfo {
        id: id.to_string(),
        kind,
        display_name: display_name.to_string(),
        status: PrincipalStatus::Active,
        authorization_state: BTreeMap::new(),
    }
}

fn policy() -> IamPolicyInfo {
    IamPolicyInfo {
        revision: 1,
        actions: vec![IamActionInfo {
            identifier: "customer-growth.job.read".to_string(),
            description: "Read customer growth jobs".to_string(),
            route_matchers: vec![HttpRouteMatcher {
                id: "customer-growth-job-read".to_string(),
                methods: vec!["GET".to_string()],
                hosts: vec!["api.example.com".to_string()],
                path: "/customer-growth/jobs/{job_id}".to_string(),
                resource_urn: "urn:iam:prod:customer-growth:global:{tenant_id}:workspace/growth/project/acquisition/job/{job_id}".to_string(),
                parent_urns: Vec::new(),
            }],
        }],
        roles: vec![IamRoleInfo {
            id: "customer-growth-reader".to_string(),
            name: "Customer Growth Reader".to_string(),
            description: String::new(),
            action_ids: vec!["customer-growth.job.read".to_string()],
        }],
        role_bindings: vec![IamRoleBindingInfo {
            id: "growth-team-reader".to_string(),
            principal_id: GROUP_ID.to_string(),
            role_id: "customer-growth-reader".to_string(),
            effect: Effect::Allow,
            resource_urn: "urn:iam:prod:customer-growth:global:example-corp:workspace/growth/project/acquisition/job/*".to_string(),
            conditions: AuthorizationConditionSpec::default(),
        }],
    }
}

fn jwt(principal_id: &str, principal_kind: &str, groups: &[&str]) -> String {
    jwt_with_subject(principal_id, principal_id, principal_kind, groups)
}

fn jwt_with_subject(
    principal_id: &str,
    subject: &str,
    principal_kind: &str,
    groups: &[&str],
) -> String {
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": "authguard-authn",
            "sub": subject,
            "principal_id": principal_id,
            "principal_kind": principal_kind,
            "authguard_group_ids": groups,
            "tenant_id": "example-corp",
            "name": "Alice Analyst"
        }))
        .expect("JWT claims"),
    );
    format!("header.{payload}.signature")
}

fn check_request(token: Option<&str>) -> CheckRequest {
    let mut headers = HashMap::new();
    if let Some(token) = token {
        headers.insert("x-authguard-id-token".to_string(), token.to_string());
    }
    CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(attribute_context::Request {
                http: Some(attribute_context::HttpRequest {
                    method: "GET".to_string(),
                    path: "/customer-growth/jobs/daily-acquisition-score".to_string(),
                    host: "api.example.com".to_string(),
                    scheme: "https".to_string(),
                    headers,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

fn context_header(response: &envoy_types::ext_authz::v3::pb::CheckResponse) -> Option<&str> {
    let check_response::HttpResponse::OkResponse(ok) = response.http_response.as_ref()? else {
        return None;
    };
    ok.headers
        .iter()
        .filter_map(|header| header.header.as_ref())
        .find(|header| header.key == "x-authguard-context")
        .map(|header| header.value.as_str())
}

fn scope_token(response: &envoy_types::ext_authz::v3::pb::CheckResponse) -> Option<&str> {
    let check_response::HttpResponse::OkResponse(ok) = response.http_response.as_ref()? else {
        return None;
    };
    ok.headers
        .iter()
        .filter_map(|header| header.header.as_ref())
        .find(|header| header.key == "x-authguard-scope-token")
        .map(|header| header.value.as_str())
}

fn decode_direct_context(compact: &str) -> AccessContext {
    let codec = AccessContextSigner::new(CONTEXT_SIGNING_KEY).expect("test signer");
    let encoded = codec.verify(compact).expect("verify signed context");
    AccessContext::decode(&encoded).expect("decode context")
}

fn api_config() -> AppConfigProperties {
    let mut config = AppConfigProperties::default();
    config.authz.api_token = "api-secret".to_string();
    config
}

fn api_request(method: Method, uri: &str, body: &Value) -> HttpRequest<Body> {
    HttpRequest::builder()
        .method(method)
        .uri(uri)
        .header("authorization", "Bearer api-secret")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).expect("JSON")))
        .expect("request")
}

fn api_mutation(
    method: Method,
    uri: &str,
    policy_revision: u64,
    body: &Value,
) -> HttpRequest<Body> {
    api_request_with_if_match(method, uri, &format!("\"{policy_revision}\""), body)
}

fn api_request_with_if_match(
    method: Method,
    uri: &str,
    if_match: &str,
    body: &Value,
) -> HttpRequest<Body> {
    let mut request = api_request(method, uri, body);
    request.headers_mut().insert("if-match", if_match.parse().expect("If-Match value"));
    request
}

fn response_revision(response: &axum::response::Response) -> u64 {
    response
        .headers()
        .get("etag")
        .expect("ETag")
        .to_str()
        .expect("ETag text")
        .trim_matches('"')
        .parse()
        .expect("policy revision ETag")
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

async fn assert_deleted_policy_resources(app: &axum::Router, uris: &[&str]) {
    for uri in uris {
        let response = app
            .clone()
            .oneshot(api_request(Method::GET, uri, &json!({})))
            .await
            .unwrap_or_else(|error| panic!("verify deleted resource `{uri}`: {error}"));
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "deleted resource `{uri}`");
        assert_eq!(response_json(response).await["code"], "resource_not_found");
    }
}

async fn assert_updated_role_is_listed(app: &axum::Router, expected_revision: u64) {
    let get_role = app
        .clone()
        .oneshot(api_request(Method::GET, "/api/v1/roles/customer-growth-runner", &json!({})))
        .await
        .expect("get role");
    assert_eq!(get_role.status(), StatusCode::OK);
    assert_eq!(response_revision(&get_role), expected_revision);
    let role_body = response_json(get_role).await;
    assert_eq!(role_body["resource"]["name"], "Customer Growth Job Runner");
    assert_eq!(role_body["resource"]["action_ids"], json!(["customer-growth.job.execute"]));

    let list_roles = app
        .clone()
        .oneshot(api_request(Method::GET, "/api/v1/roles", &json!({})))
        .await
        .expect("list roles");
    assert_eq!(list_roles.status(), StatusCode::OK);
    assert_eq!(response_revision(&list_roles), expected_revision);
    assert_eq!(response_json(list_roles).await["total"], 2);
}

#[tokio::test]
async fn envoy_ext_auth_returns_internal_principal_and_resource_scope() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    let response = runtime
        .authorization
        .check(Request::new(check_request(Some(&jwt(USER_ID, "USER", &[GROUP_ID])))))
        .await
        .expect("check")
        .into_inner();

    assert_eq!(response.status.as_ref().expect("status").code, 0);
    let context = decode_direct_context(context_header(&response).expect("context"));
    assert_eq!(context.principal_id, USER_ID);
    assert_eq!(context.action, "customer-growth.job.read");
    assert_eq!(context.policy_revision, 1);
    assert_eq!(context.allow_resource_urns.len(), 1);
}

#[tokio::test]
async fn unknown_canonical_principal_fails_closed_without_jit_creation() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    let response = runtime
        .authorization
        .check(Request::new(check_request(Some(&jwt("principal-new-user", "USER", &[GROUP_ID])))))
        .await
        .expect("check")
        .into_inner();
    assert_eq!(response.status.as_ref().expect("status").code, tonic::Code::Unauthenticated as i32);
    assert!(runtime.repository.get("principal-new-user").await.expect("query").is_none());
}

#[tokio::test]
async fn canonical_principal_ids_drive_resolution() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    runtime
        .repository
        .upsert(&principal("principal-bob", "Bob", PrincipalKind::User))
        .await
        .expect("second IamPrincipalInfo");
    let first = authguard_common::AuthenticatedPrincipalContext {
        principal_id: USER_ID.to_string(),
        kind: PrincipalKind::User,
        stable_group_ids: Vec::new(),
        trusted_claims: HashMap::new(),
        acr: None,
        amr: Vec::new(),
    };
    let second = authguard_common::AuthenticatedPrincipalContext {
        principal_id: "principal-bob".to_string(),
        ..first.clone()
    };
    let first = runtime.principals.resolve_request(&first).await.expect("first");
    let second = runtime.principals.resolve_request(&second).await.expect("second");
    assert_ne!(first.principal_id, second.principal_id);
}

#[tokio::test]
async fn unknown_group_principal_is_ignored() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    let principals = PrincipalHandler::new(runtime.repository.clone(), Vec::new(), None);
    let identity = authguard_common::AuthenticatedPrincipalContext {
        principal_id: USER_ID.to_string(),
        kind: PrincipalKind::User,
        stable_group_ids: vec!["principal-not-materialized".to_string()],
        trusted_claims: HashMap::new(),
        acr: None,
        amr: Vec::new(),
    };

    let resolved = principals.resolve_request(&identity).await.expect("known primary principal");

    assert_eq!(resolved.principal_id, USER_ID);
    assert!(resolved.group_principal_ids.is_empty());
}

#[tokio::test]
async fn disabled_principal_fails_closed_before_policy_evaluation() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    runtime.principals.update_status(USER_ID, PrincipalStatus::Disabled).await.expect("disable");
    let response = runtime
        .authorization
        .check(Request::new(check_request(Some(&jwt(USER_ID, "USER", &[GROUP_ID])))))
        .await
        .expect("check")
        .into_inner();
    assert_eq!(
        response.status.as_ref().expect("status").code,
        tonic::Code::PermissionDenied as i32
    );
}

#[tokio::test]
async fn explicit_user_deny_overrides_group_allow_on_the_envoy_path() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    runtime
        .policy
        .create_role_binding(
            1,
            IamRoleBindingInfo {
                id: "alice-sensitive-job-deny".to_string(),
                principal_id: USER_ID.to_string(),
                role_id: "customer-growth-reader".to_string(),
                effect: Effect::Deny,
                resource_urn: "urn:iam:prod:customer-growth:global:example-corp:workspace/growth/project/acquisition/job/daily-acquisition-score".to_string(),
                conditions: AuthorizationConditionSpec::default(),
            },
        )
        .await
        .expect("persist explicit deny role binding");

    let response = runtime
        .authorization
        .check(Request::new(check_request(Some(&jwt(USER_ID, "USER", &[GROUP_ID])))))
        .await
        .expect("check")
        .into_inner();

    assert_eq!(
        response.status.as_ref().expect("status").code,
        tonic::Code::PermissionDenied as i32
    );
    assert!(context_header(&response).is_none());
    assert!(scope_token(&response).is_none());
}

#[tokio::test]
async fn provider_subject_claims_cannot_replace_canonical_principal_ids() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    let response = runtime
        .authorization
        .check(Request::new(check_request(Some(&jwt_with_subject(
            USER_ID,
            "github-user-987654",
            "USER",
            &[GROUP_ID],
        )))))
        .await
        .expect("check")
        .into_inner();

    assert_eq!(response.status.as_ref().expect("status").code, tonic::Code::Ok as i32);
    let context = decode_direct_context(context_header(&response).expect("context"));
    assert_eq!(context.principal_id, USER_ID);
    assert_ne!(context.principal_id, "github-user-987654");
}

#[tokio::test]
async fn envoy_path_fails_closed_for_missing_identity_and_unmapped_http_tuple() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    let missing_identity = runtime
        .authorization
        .check(Request::new(check_request(None)))
        .await
        .expect("missing identity check")
        .into_inner();
    assert_eq!(
        missing_identity.status.as_ref().expect("status").code,
        tonic::Code::Unauthenticated as i32
    );

    let mut unmapped = check_request(Some(&jwt(USER_ID, "USER", &[GROUP_ID])));
    unmapped
        .attributes
        .as_mut()
        .and_then(|attributes| attributes.request.as_mut())
        .and_then(|request| request.http.as_mut())
        .expect("HTTP request")
        .path = "/unmapped".to_string();
    let unmapped = runtime
        .authorization
        .check(Request::new(unmapped))
        .await
        .expect("unmapped route check")
        .into_inner();
    assert_eq!(
        unmapped.status.as_ref().expect("status").code,
        tonic::Code::PermissionDenied as i32
    );
}

#[tokio::test]
async fn large_scope_uses_opaque_token_resolved_by_grpc_service() {
    let runtime = runtime(ScopeDeliveryProperties {
        direct_urn_limit: 0,
        ..ScopeDeliveryProperties::default()
    })
    .await;
    let response = runtime
        .authorization
        .clone()
        .check(Request::new(check_request(Some(&jwt(USER_ID, "USER", &[GROUP_ID])))))
        .await
        .expect("check")
        .into_inner();
    let token = scope_token(&response).expect("opaque token").to_string();
    let encoded = runtime
        .authorization
        .resolve_scope(Request::new(token))
        .await
        .expect("resolve")
        .into_inner();
    assert_eq!(AccessContext::decode(&encoded).expect("context").principal_id, USER_ID);
}

#[tokio::test]
async fn principal_api_status_and_reference_conflict_are_enforced() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        &api_config(),
    );
    let list = app
        .clone()
        .oneshot(api_request(Method::GET, "/api/v1/principals?limit=10", &json!({})))
        .await
        .expect("list");
    assert_eq!(list.status(), StatusCode::OK);

    let disable = app
        .clone()
        .oneshot(api_request(
            Method::PATCH,
            &format!("/api/v1/principals/{USER_ID}"),
            &json!({"status":"DISABLED"}),
        ))
        .await
        .expect("disable");
    assert_eq!(disable.status(), StatusCode::OK);

    let delete_unreferenced = app
        .clone()
        .oneshot(api_request(Method::DELETE, &format!("/api/v1/principals/{USER_ID}"), &json!({})))
        .await
        .expect("delete unreferenced principal");
    assert_eq!(delete_unreferenced.status(), StatusCode::NO_CONTENT);
    let deleted = app
        .clone()
        .oneshot(api_request(Method::GET, &format!("/api/v1/principals/{USER_ID}"), &json!({})))
        .await
        .expect("get deleted principal");
    assert_eq!(deleted.status(), StatusCode::NOT_FOUND);

    let referenced = app
        .oneshot(api_request(Method::DELETE, &format!("/api/v1/principals/{GROUP_ID}"), &json!({})))
        .await
        .expect("delete");
    assert_eq!(referenced.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn policy_crud_rejects_referenced_resources_and_stale_revision() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        &api_config(),
    );
    let read_policy = app
        .clone()
        .oneshot(api_request(Method::GET, "/api/v1/policy", &json!({})))
        .await
        .expect("read policy");
    assert_eq!(read_policy.status(), StatusCode::OK);
    assert_eq!(response_revision(&read_policy), 1);
    let list_actions = app
        .clone()
        .oneshot(api_request(Method::GET, "/api/v1/actions", &json!({})))
        .await
        .expect("list actions");
    assert_eq!(list_actions.status(), StatusCode::OK);
    assert_eq!(response_revision(&list_actions), 1);

    let missing_precondition = app
        .clone()
        .oneshot(api_request(
            Method::POST,
            "/api/v1/actions",
            &json!({
                "identifier":"customer-growth.job.create",
                "description":"Create customer growth jobs",
                "route_matchers":[]
            }),
        ))
        .await
        .expect("missing precondition");
    assert_eq!(missing_precondition.status(), StatusCode::PRECONDITION_REQUIRED);

    let invalid_precondition = app
        .clone()
        .oneshot(api_request_with_if_match(
            Method::POST,
            "/api/v1/actions",
            "not-a-revision",
            &json!({
                "identifier":"customer-growth.job.create",
                "description":"Create customer growth jobs",
                "route_matchers":[]
            }),
        ))
        .await
        .expect("invalid precondition");
    assert_eq!(invalid_precondition.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(invalid_precondition).await["code"], "invalid_if_match");

    let delete_action = app
        .clone()
        .oneshot(api_mutation(
            Method::DELETE,
            "/api/v1/actions/customer-growth.job.read",
            1,
            &json!({}),
        ))
        .await
        .expect("delete action");
    assert_eq!(delete_action.status(), StatusCode::CONFLICT);
    let delete_role = app
        .clone()
        .oneshot(api_mutation(
            Method::DELETE,
            "/api/v1/roles/customer-growth-reader",
            1,
            &json!({}),
        ))
        .await
        .expect("delete role");
    assert_eq!(delete_role.status(), StatusCode::CONFLICT);

    let create_action = app
        .clone()
        .oneshot(api_mutation(
            Method::POST,
            "/api/v1/actions",
            1,
            &json!({
                "identifier":"customer-growth.job.create",
                "description":"Create customer growth jobs",
                "route_matchers":[]
            }),
        ))
        .await
        .expect("create action");
    assert_eq!(create_action.status(), StatusCode::CREATED);
    assert_eq!(response_revision(&create_action), 2);

    let stale = app
        .oneshot(api_mutation(Method::PUT, "/api/v1/policy", 1, &json!(policy())))
        .await
        .expect("replace");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(response_json(stale).await["code"], "policy_revision_conflict");
}

#[tokio::test]
async fn action_role_and_role_binding_support_complete_api_crud() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        &api_config(),
    );

    let create_action = app
        .clone()
        .oneshot(api_mutation(
            Method::POST,
            "/api/v1/actions",
            1,
            &json!({
                "identifier":"customer-growth.job.execute",
                "description":"Execute customer growth jobs",
                "route_matchers":[]
            }),
        ))
        .await
        .expect("create action");
    assert_eq!(create_action.status(), StatusCode::CREATED);
    assert_eq!(response_revision(&create_action), 2);
    let get_action = app
        .clone()
        .oneshot(api_request(
            Method::GET,
            "/api/v1/actions/customer-growth.job.execute",
            &json!({}),
        ))
        .await
        .expect("get action");
    assert_eq!(get_action.status(), StatusCode::OK);
    assert_eq!(response_revision(&get_action), 2);
    let update_action = app
        .clone()
        .oneshot(api_mutation(
            Method::PUT,
            "/api/v1/actions/customer-growth.job.execute",
            2,
            &json!({
                "identifier":"customer-growth.job.execute",
                "description":"Execute an approved customer growth job",
                "route_matchers":[]
            }),
        ))
        .await
        .expect("update action");
    assert_eq!(update_action.status(), StatusCode::OK);
    assert_eq!(response_revision(&update_action), 3);

    let create_role = app
        .clone()
        .oneshot(api_mutation(
            Method::POST,
            "/api/v1/roles",
            3,
            &json!({
                "id":"customer-growth-runner",
                "name":"Customer Growth Runner",
                "description":"Runs approved jobs",
                "action_ids":["customer-growth.job.execute"]
            }),
        ))
        .await
        .expect("create role");
    assert_eq!(create_role.status(), StatusCode::CREATED);
    assert_eq!(response_revision(&create_role), 4);
    let update_role = app
        .clone()
        .oneshot(api_mutation(
            Method::PUT,
            "/api/v1/roles/customer-growth-runner",
            4,
            &json!({
                "id":"customer-growth-runner",
                "name":"Customer Growth Job Runner",
                "description":"Runs approved customer growth jobs",
                "action_ids":["customer-growth.job.execute"]
            }),
        ))
        .await
        .expect("update role");
    assert_eq!(update_role.status(), StatusCode::OK);
    assert_eq!(response_revision(&update_role), 5);
    assert_updated_role_is_listed(&app, 5).await;

    let binding = json!({
        "id":"alice-customer-growth-runner",
        "principal_id":USER_ID,
        "role_id":"customer-growth-runner",
        "effect":"ALLOW",
        "resource_urn":"urn:iam:prod:customer-growth:global:example-corp:workspace/growth/project/acquisition/job/*",
        "conditions":{}
    });
    let create_binding = app
        .clone()
        .oneshot(api_mutation(Method::POST, "/api/v1/role-bindings", 5, &binding))
        .await
        .expect("create binding");
    assert_eq!(create_binding.status(), StatusCode::CREATED);
    assert_eq!(response_revision(&create_binding), 6);
    let get_binding = app
        .clone()
        .oneshot(api_request(
            Method::GET,
            "/api/v1/role-bindings/alice-customer-growth-runner",
            &json!({}),
        ))
        .await
        .expect("get binding");
    assert_eq!(get_binding.status(), StatusCode::OK);
    assert_eq!(response_revision(&get_binding), 6);
    let update_binding = app
        .clone()
        .oneshot(api_mutation(
            Method::PUT,
            "/api/v1/role-bindings/alice-customer-growth-runner",
            6,
            &binding,
        ))
        .await
        .expect("update binding");
    assert_eq!(update_binding.status(), StatusCode::OK);
    assert_eq!(response_revision(&update_binding), 7);
    let list_bindings = app
        .clone()
        .oneshot(api_request(Method::GET, "/api/v1/role-bindings", &json!({})))
        .await
        .expect("list role bindings");
    assert_eq!(list_bindings.status(), StatusCode::OK);
    assert_eq!(response_revision(&list_bindings), 7);
    let bindings_body = response_json(list_bindings).await;
    assert_eq!(bindings_body["total"], 2);
    assert!(bindings_body["items"].as_array().expect("binding items").iter().any(|binding| {
        binding["id"] == "alice-customer-growth-runner"
            && binding["effect"] == "ALLOW"
            && binding["principal_id"] == USER_ID
    }));

    for (uri, kind, expected_revision) in [
        ("/api/v1/role-bindings/alice-customer-growth-runner", "binding", 7),
        ("/api/v1/roles/customer-growth-runner", "role", 8),
        ("/api/v1/actions/customer-growth.job.execute", "action", 9),
    ] {
        let response = app
            .clone()
            .oneshot(api_mutation(Method::DELETE, uri, expected_revision, &json!({})))
            .await
            .unwrap_or_else(|error| panic!("delete {kind}: {error}"));
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "delete {kind}");
        assert_eq!(response_revision(&response), expected_revision + 1);
    }

    assert_deleted_policy_resources(
        &app,
        &[
            "/api/v1/role-bindings/alice-customer-growth-runner",
            "/api/v1/roles/customer-growth-runner",
            "/api/v1/actions/customer-growth.job.execute",
        ],
    )
    .await;
}

#[tokio::test]
async fn complete_policy_replace_rejects_disabled_binding_principal() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    runtime.principals.update_status(USER_ID, PrincipalStatus::Disabled).await.expect("disable");
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        &api_config(),
    );
    let mut replacement = policy();
    replacement.role_bindings[0].principal_id = USER_ID.to_string();

    let response = app
        .oneshot(api_mutation(Method::PUT, "/api/v1/policy", 1, &json!(replacement)))
        .await
        .expect("replace policy");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response_json(response).await["code"], "principal_disabled");
}

#[tokio::test]
async fn policy_delete_resets_the_authorization_catalog_with_revision_guard() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        &api_config(),
    );

    let missing = app
        .clone()
        .oneshot(api_request(Method::DELETE, "/api/v1/policy", &json!({})))
        .await
        .expect("delete without precondition");
    assert_eq!(missing.status(), StatusCode::PRECONDITION_REQUIRED);

    let reset = app
        .clone()
        .oneshot(api_mutation(Method::DELETE, "/api/v1/policy", 1, &json!({})))
        .await
        .expect("reset policy");
    assert_eq!(reset.status(), StatusCode::NO_CONTENT);
    assert_eq!(response_revision(&reset), 2);

    let current = app
        .clone()
        .oneshot(api_request(Method::GET, "/api/v1/policy", &json!({})))
        .await
        .expect("read reset policy");
    assert_eq!(current.status(), StatusCode::OK);
    assert_eq!(response_revision(&current), 2);
    let body = response_json(current).await;
    assert!(body.get("id").is_none());
    assert_eq!(body["revision"], 2);
    assert_eq!(body["actions"], json!([]));
    assert_eq!(body["roles"], json!([]));
    assert_eq!(body["role_bindings"], json!([]));

    let stale = app
        .oneshot(api_mutation(Method::DELETE, "/api/v1/policy", 1, &json!({})))
        .await
        .expect("stale reset");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn management_authorize_route_delegates_allow_and_default_deny_decisions() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        &api_config(),
    );
    let request = |resource_urn: &str| {
        api_request(
            Method::POST,
            "/api/v1/authorize",
            &json!({
                "principal_id":USER_ID,
                "group_principal_ids":[GROUP_ID],
                "action":"customer-growth.job.read",
                "resource_urn":resource_urn,
                "parent_urns":[],
                "context":{}
            }),
        )
    };

    let allowed = app
        .clone()
        .oneshot(request("urn:iam:prod:customer-growth:global:example-corp:workspace/growth/project/acquisition/job/daily-acquisition-score"))
        .await
        .expect("allow decision");
    assert_eq!(allowed.status(), StatusCode::OK);
    let allowed = response_json(allowed).await;
    assert_eq!(allowed["allowed"], true);
    assert_eq!(allowed["role_binding_id"], "growth-team-reader");

    let denied = app
        .oneshot(request("urn:iam:prod:customer-growth:global:another-company:workspace/growth/project/acquisition/job/daily-acquisition-score"))
        .await
        .expect("deny decision");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let denied = response_json(denied).await;
    assert_eq!(denied["allowed"], false);
    assert_eq!(denied["reason"], "default deny");
}

#[tokio::test]
async fn readiness_requires_durable_storage() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    runtime.policy.readiness().await.expect("reachable SQLite authorization storage");

    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        &api_config(),
    );
    let response = app
        .oneshot(api_request(Method::GET, "/readyz", &json!({})))
        .await
        .expect("readiness response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn scim_provisioning_projects_and_tombstones_principal() {
    let runtime = runtime(ScopeDeliveryProperties::default()).await;
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        &api_config(),
    );
    let create = app
        .clone()
        .oneshot(api_request(
            Method::POST,
            "/api/v1/principal-discovery/scim/events",
            &json!({
                "operation":"upsert_user",
                "principal_id":"principal-scim-alice",
                "resource": {"id":"scim-user-1","userName":"scim.alice","active":true}
            }),
        ))
        .await
        .expect("SCIM upsert");
    assert_eq!(create.status(), StatusCode::OK);
    let created = response_json(create).await;
    let id = created["id"].as_str().expect("principal id").to_string();

    let delete = app
        .oneshot(api_request(
            Method::POST,
            "/api/v1/principal-discovery/scim/events",
            &json!({
                "operation":"delete",
                "principal_id":"principal-scim-alice"
            }),
        ))
        .await
        .expect("SCIM tombstone");
    assert_eq!(delete.status(), StatusCode::OK);
    assert_eq!(response_json(delete).await["id"], id);
}
