use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use authguard_core::cache::{IAuthorizationCache, MemoryAuthorizationCache};
use authguard_core::config::{AuthguardConfig, IdentityConfig, ScopeDeliveryConfig, SqliteConfig};
use authguard_core::handler::{DefaultAuthorizationHandler, PolicyHandler, PrincipalHandler};
use authguard_core::model::access_context_v1::access_context_service_server::AccessContextService;
use authguard_core::model::AccessContextSigner;
use authguard_core::principal::{JitPrincipalDiscovery, ScimPrincipalDiscovery};
use authguard_core::server::AuthguardServer;
use authguard_core::storage::{
    PolicyRepository, PrincipalRepository, SqliteAuthorizationRepository,
};
use authguard_core::utils::MetricsRegistry;
use authguard_core::{
    AccessContext, Action, AuthorizationConditionSpec, Effect, HttpRouteMatcher, Policy, Principal,
    PrincipalKind, PrincipalStatus, Role, RoleBinding,
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
const SECOND_ISSUER: &str = "https://partners.example.com/oidc";
const USER_ID: &str = "principal-alice";
const GROUP_ID: &str = "principal-growth-team";
const CONTEXT_SIGNING_KEY: [u8; 32] = [7; 32];

struct TestRuntime {
    policy: PolicyHandler,
    principals: PrincipalHandler,
    authorization: DefaultAuthorizationHandler,
    cache: Arc<dyn IAuthorizationCache>,
    metrics: MetricsRegistry,
    repository: Arc<SqliteAuthorizationRepository>,
}

async fn runtime(scope_delivery: ScopeDeliveryConfig) -> TestRuntime {
    let repository = Arc::new(
        SqliteAuthorizationRepository::connect(&SqliteConfig {
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
    repository.compare_and_replace(0, &policy_document).await.expect("seed policy");
    let cache: Arc<dyn IAuthorizationCache> = Arc::new(MemoryAuthorizationCache::default());
    let metrics = MetricsRegistry::default();
    let policy = PolicyHandler::open(repository.clone(), repository.clone(), metrics.clone(), None)
        .await
        .expect("policy handler");
    let jit = JitPrincipalDiscovery::new(
        "verified-oidc",
        [ISSUER.to_string(), SECOND_ISSUER.to_string()],
        false,
    )
    .expect("JIT discovery");
    let scim = ScimPrincipalDiscovery::new("corporate-scim", ISSUER).expect("SCIM discovery");
    let principals = PrincipalHandler::new(repository.clone(), Some(jit), None, Some(scim));
    let authorization = DefaultAuthorizationHandler::new(
        policy.clone(),
        principals.clone(),
        cache.clone(),
        metrics.clone(),
        IdentityConfig::default(),
        scope_delivery,
        AccessContextSigner::new(CONTEXT_SIGNING_KEY).expect("test signer"),
    );
    TestRuntime { policy, principals, authorization, cache, metrics, repository }
}

fn principal(id: &str, external_id: &str, kind: PrincipalKind) -> Principal {
    Principal {
        id: id.to_string(),
        issuer: ISSUER.to_string(),
        external_id: external_id.to_string(),
        kind,
        display_name: external_id.to_string(),
        status: PrincipalStatus::Active,
        attributes: BTreeMap::new(),
    }
}

fn policy() -> Policy {
    Policy {
        id: "default".to_string(),
        revision: 1,
        name: "Customer growth authorization".to_string(),
        description: String::new(),
        actions: vec![Action {
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
        roles: vec![Role {
            id: "customer-growth-reader".to_string(),
            name: "Customer Growth Reader".to_string(),
            description: String::new(),
            action_ids: vec!["customer-growth.job.read".to_string()],
        }],
        role_bindings: vec![RoleBinding {
            id: "growth-team-reader".to_string(),
            principal_id: GROUP_ID.to_string(),
            role_id: "customer-growth-reader".to_string(),
            effect: Effect::Allow,
            resource_urn: "urn:iam:prod:customer-growth:global:example-corp:workspace/growth/project/acquisition/job/*".to_string(),
            conditions: AuthorizationConditionSpec::default(),
        }],
    }
}

fn jwt(issuer: &str, subject: &str, groups: &[&str]) -> String {
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": issuer,
            "sub": subject,
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

fn admin_config() -> AuthguardConfig {
    let mut config = AuthguardConfig::default();
    config.auth.admin_token = "admin-secret".to_string();
    config
}

fn admin_request(method: Method, uri: &str, body: &Value) -> HttpRequest<Body> {
    HttpRequest::builder()
        .method(method)
        .uri(uri)
        .header("authorization", "Bearer admin-secret")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).expect("JSON")))
        .expect("request")
}

fn admin_mutation(
    method: Method,
    uri: &str,
    policy_revision: u64,
    body: &Value,
) -> HttpRequest<Body> {
    admin_request_with_if_match(method, uri, &format!("\"{policy_revision}\""), body)
}

fn admin_request_with_if_match(
    method: Method,
    uri: &str,
    if_match: &str,
    body: &Value,
) -> HttpRequest<Body> {
    let mut request = admin_request(method, uri, body);
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
            .oneshot(admin_request(Method::GET, uri, &json!({})))
            .await
            .unwrap_or_else(|error| panic!("verify deleted resource `{uri}`: {error}"));
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "deleted resource `{uri}`");
        assert_eq!(response_json(response).await["code"], "resource_not_found");
    }
}

async fn assert_updated_role_is_listed(app: &axum::Router, expected_revision: u64) {
    let get_role = app
        .clone()
        .oneshot(admin_request(Method::GET, "/adm/v1/roles/customer-growth-runner", &json!({})))
        .await
        .expect("get role");
    assert_eq!(get_role.status(), StatusCode::OK);
    assert_eq!(response_revision(&get_role), expected_revision);
    let role_body = response_json(get_role).await;
    assert_eq!(role_body["resource"]["name"], "Customer Growth Job Runner");
    assert_eq!(role_body["resource"]["action_ids"], json!(["customer-growth.job.execute"]));

    let list_roles = app
        .clone()
        .oneshot(admin_request(Method::GET, "/adm/v1/roles", &json!({})))
        .await
        .expect("list roles");
    assert_eq!(list_roles.status(), StatusCode::OK);
    assert_eq!(response_revision(&list_roles), expected_revision);
    assert_eq!(response_json(list_roles).await["total"], 2);
}

#[tokio::test]
async fn envoy_ext_auth_returns_internal_principal_and_resource_scope() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    let response = runtime
        .authorization
        .check(Request::new(check_request(Some(&jwt(ISSUER, "alice", &["growth-team"])))))
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
async fn unknown_verified_identity_is_jit_projected_before_authorization() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    let response = runtime
        .authorization
        .check(Request::new(check_request(Some(&jwt(ISSUER, "new-user", &["growth-team"])))))
        .await
        .expect("check")
        .into_inner();
    assert_eq!(response.status.as_ref().expect("status").code, 0);
    let projected = runtime
        .repository
        .find_by_external_key(ISSUER, "new-user")
        .await
        .expect("query")
        .expect("JIT projection");
    assert_eq!(projected.kind, PrincipalKind::User);
}

#[tokio::test]
async fn same_external_id_from_two_issuers_resolves_to_distinct_principals() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    let first = authguard_core::utils::RequestIdentity {
        issuer: ISSUER.to_string(),
        external_id: "shared-sub".to_string(),
        group_external_ids: Vec::new(),
        claims: HashMap::new(),
    };
    let second = authguard_core::utils::RequestIdentity {
        issuer: SECOND_ISSUER.to_string(),
        ..first.clone()
    };
    let first = runtime.principals.resolve_request(&first).await.expect("first");
    let second = runtime.principals.resolve_request(&second).await.expect("second");
    assert_ne!(first.principal_id, second.principal_id);
}

#[tokio::test]
async fn unprojected_group_is_ignored_when_jit_discovery_is_disabled() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    let principals = PrincipalHandler::new(runtime.repository.clone(), None, None, None);
    let identity = authguard_core::utils::RequestIdentity {
        issuer: ISSUER.to_string(),
        external_id: "alice".to_string(),
        group_external_ids: vec!["not-authorized-and-not-projected".to_string()],
        claims: HashMap::new(),
    };

    let resolved = principals.resolve_request(&identity).await.expect("known primary principal");

    assert_eq!(resolved.principal_id, USER_ID);
    assert!(resolved.group_principal_ids.is_empty());
}

#[tokio::test]
async fn disabled_principal_fails_closed_before_policy_evaluation() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    runtime.principals.update_status(USER_ID, PrincipalStatus::Disabled).await.expect("disable");
    let response = runtime
        .authorization
        .check(Request::new(check_request(Some(&jwt(ISSUER, "alice", &["growth-team"])))))
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
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    runtime
        .policy
        .create_role_binding(
            1,
            RoleBinding {
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
        .check(Request::new(check_request(Some(&jwt(ISSUER, "alice", &["growth-team"])))))
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
async fn issuer_scoped_identity_does_not_inherit_same_named_subject_or_group_access() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    let response = runtime
        .authorization
        .check(Request::new(check_request(Some(&jwt(SECOND_ISSUER, "alice", &["growth-team"])))))
        .await
        .expect("check")
        .into_inner();

    assert_eq!(
        response.status.as_ref().expect("status").code,
        tonic::Code::PermissionDenied as i32
    );
    let partner_user = runtime
        .repository
        .find_by_external_key(SECOND_ISSUER, "alice")
        .await
        .expect("query partner issuer")
        .expect("JIT-projected partner user");
    assert_ne!(partner_user.id, USER_ID);
    let partner_group = runtime
        .repository
        .find_by_external_key(SECOND_ISSUER, "group:growth-team")
        .await
        .expect("query partner group")
        .expect("JIT-projected partner group");
    assert_ne!(partner_group.id, GROUP_ID);
}

#[tokio::test]
async fn envoy_path_fails_closed_for_missing_identity_and_unmapped_http_tuple() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
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

    let mut unmapped = check_request(Some(&jwt(ISSUER, "alice", &["growth-team"])));
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
    let runtime =
        runtime(ScopeDeliveryConfig { direct_urn_limit: 0, ..ScopeDeliveryConfig::default() })
            .await;
    let response = runtime
        .authorization
        .clone()
        .check(Request::new(check_request(Some(&jwt(ISSUER, "alice", &["growth-team"])))))
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
async fn principal_admin_status_and_reference_conflict_are_enforced() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        admin_config(),
    );
    let list = app
        .clone()
        .oneshot(admin_request(Method::GET, "/adm/v1/principals?limit=10", &json!({})))
        .await
        .expect("list");
    assert_eq!(list.status(), StatusCode::OK);

    let disable = app
        .clone()
        .oneshot(admin_request(
            Method::PATCH,
            &format!("/adm/v1/principals/{USER_ID}"),
            &json!({"status":"DISABLED"}),
        ))
        .await
        .expect("disable");
    assert_eq!(disable.status(), StatusCode::OK);

    let delete_unreferenced = app
        .clone()
        .oneshot(admin_request(
            Method::DELETE,
            &format!("/adm/v1/principals/{USER_ID}"),
            &json!({}),
        ))
        .await
        .expect("delete unreferenced principal");
    assert_eq!(delete_unreferenced.status(), StatusCode::NO_CONTENT);
    let deleted = app
        .clone()
        .oneshot(admin_request(Method::GET, &format!("/adm/v1/principals/{USER_ID}"), &json!({})))
        .await
        .expect("get deleted principal");
    assert_eq!(deleted.status(), StatusCode::NOT_FOUND);

    let referenced = app
        .oneshot(admin_request(
            Method::DELETE,
            &format!("/adm/v1/principals/{GROUP_ID}"),
            &json!({}),
        ))
        .await
        .expect("delete");
    assert_eq!(referenced.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn policy_crud_rejects_referenced_resources_and_stale_revision() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        admin_config(),
    );
    let read_policy = app
        .clone()
        .oneshot(admin_request(Method::GET, "/adm/v1/policy", &json!({})))
        .await
        .expect("read policy");
    assert_eq!(read_policy.status(), StatusCode::OK);
    assert_eq!(response_revision(&read_policy), 1);
    let list_actions = app
        .clone()
        .oneshot(admin_request(Method::GET, "/adm/v1/actions", &json!({})))
        .await
        .expect("list actions");
    assert_eq!(list_actions.status(), StatusCode::OK);
    assert_eq!(response_revision(&list_actions), 1);

    let missing_precondition = app
        .clone()
        .oneshot(admin_request(
            Method::POST,
            "/adm/v1/actions",
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
        .oneshot(admin_request_with_if_match(
            Method::POST,
            "/adm/v1/actions",
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
        .oneshot(admin_mutation(
            Method::DELETE,
            "/adm/v1/actions/customer-growth.job.read",
            1,
            &json!({}),
        ))
        .await
        .expect("delete action");
    assert_eq!(delete_action.status(), StatusCode::CONFLICT);
    let delete_role = app
        .clone()
        .oneshot(admin_mutation(
            Method::DELETE,
            "/adm/v1/roles/customer-growth-reader",
            1,
            &json!({}),
        ))
        .await
        .expect("delete role");
    assert_eq!(delete_role.status(), StatusCode::CONFLICT);

    let create_action = app
        .clone()
        .oneshot(admin_mutation(
            Method::POST,
            "/adm/v1/actions",
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
        .oneshot(admin_mutation(Method::PUT, "/adm/v1/policy", 1, &json!(policy())))
        .await
        .expect("replace");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(response_json(stale).await["code"], "policy_revision_conflict");
}

#[tokio::test]
async fn action_role_and_role_binding_support_complete_admin_crud() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        admin_config(),
    );

    let create_action = app
        .clone()
        .oneshot(admin_mutation(
            Method::POST,
            "/adm/v1/actions",
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
        .oneshot(admin_request(
            Method::GET,
            "/adm/v1/actions/customer-growth.job.execute",
            &json!({}),
        ))
        .await
        .expect("get action");
    assert_eq!(get_action.status(), StatusCode::OK);
    assert_eq!(response_revision(&get_action), 2);
    let update_action = app
        .clone()
        .oneshot(admin_mutation(
            Method::PUT,
            "/adm/v1/actions/customer-growth.job.execute",
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
        .oneshot(admin_mutation(
            Method::POST,
            "/adm/v1/roles",
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
        .oneshot(admin_mutation(
            Method::PUT,
            "/adm/v1/roles/customer-growth-runner",
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
        .oneshot(admin_mutation(Method::POST, "/adm/v1/role-bindings", 5, &binding))
        .await
        .expect("create binding");
    assert_eq!(create_binding.status(), StatusCode::CREATED);
    assert_eq!(response_revision(&create_binding), 6);
    let get_binding = app
        .clone()
        .oneshot(admin_request(
            Method::GET,
            "/adm/v1/role-bindings/alice-customer-growth-runner",
            &json!({}),
        ))
        .await
        .expect("get binding");
    assert_eq!(get_binding.status(), StatusCode::OK);
    assert_eq!(response_revision(&get_binding), 6);
    let update_binding = app
        .clone()
        .oneshot(admin_mutation(
            Method::PUT,
            "/adm/v1/role-bindings/alice-customer-growth-runner",
            6,
            &binding,
        ))
        .await
        .expect("update binding");
    assert_eq!(update_binding.status(), StatusCode::OK);
    assert_eq!(response_revision(&update_binding), 7);
    let list_bindings = app
        .clone()
        .oneshot(admin_request(Method::GET, "/adm/v1/role-bindings", &json!({})))
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
        ("/adm/v1/role-bindings/alice-customer-growth-runner", "binding", 7),
        ("/adm/v1/roles/customer-growth-runner", "role", 8),
        ("/adm/v1/actions/customer-growth.job.execute", "action", 9),
    ] {
        let response = app
            .clone()
            .oneshot(admin_mutation(Method::DELETE, uri, expected_revision, &json!({})))
            .await
            .unwrap_or_else(|error| panic!("delete {kind}: {error}"));
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "delete {kind}");
        assert_eq!(response_revision(&response), expected_revision + 1);
    }

    assert_deleted_policy_resources(
        &app,
        &[
            "/adm/v1/role-bindings/alice-customer-growth-runner",
            "/adm/v1/roles/customer-growth-runner",
            "/adm/v1/actions/customer-growth.job.execute",
        ],
    )
    .await;
}

#[tokio::test]
async fn complete_policy_replace_rejects_disabled_binding_principal() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    runtime.principals.update_status(USER_ID, PrincipalStatus::Disabled).await.expect("disable");
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        admin_config(),
    );
    let mut replacement = policy();
    replacement.role_bindings[0].principal_id = USER_ID.to_string();

    let response = app
        .oneshot(admin_mutation(Method::PUT, "/adm/v1/policy", 1, &json!(replacement)))
        .await
        .expect("replace policy");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response_json(response).await["code"], "principal_disabled");
}

#[tokio::test]
async fn policy_delete_resets_the_singleton_aggregate_with_revision_cas() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        admin_config(),
    );

    let missing = app
        .clone()
        .oneshot(admin_request(Method::DELETE, "/adm/v1/policy", &json!({})))
        .await
        .expect("delete without precondition");
    assert_eq!(missing.status(), StatusCode::PRECONDITION_REQUIRED);

    let reset = app
        .clone()
        .oneshot(admin_mutation(Method::DELETE, "/adm/v1/policy", 1, &json!({})))
        .await
        .expect("reset policy");
    assert_eq!(reset.status(), StatusCode::NO_CONTENT);
    assert_eq!(response_revision(&reset), 2);

    let current = app
        .clone()
        .oneshot(admin_request(Method::GET, "/adm/v1/policy", &json!({})))
        .await
        .expect("read reset policy");
    assert_eq!(current.status(), StatusCode::OK);
    assert_eq!(response_revision(&current), 2);
    let body = response_json(current).await;
    assert_eq!(body["id"], "default");
    assert_eq!(body["revision"], 2);
    assert_eq!(body["actions"], json!([]));
    assert_eq!(body["roles"], json!([]));
    assert_eq!(body["role_bindings"], json!([]));

    let stale = app
        .oneshot(admin_mutation(Method::DELETE, "/adm/v1/policy", 1, &json!({})))
        .await
        .expect("stale reset");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn management_authorize_route_delegates_allow_and_default_deny_decisions() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        admin_config(),
    );
    let request = |resource_urn: &str| {
        admin_request(
            Method::POST,
            "/adm/v1/authorize",
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
async fn readiness_requires_durable_storage_and_a_fresh_policy_snapshot() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    runtime
        .policy
        .readiness(Duration::from_secs(1))
        .await
        .expect("reachable SQLite and fresh initial snapshot");

    tokio::time::sleep(Duration::from_millis(2)).await;
    let stale = runtime.policy.readiness(Duration::ZERO).await.expect_err("stale snapshot");
    assert!(stale.to_string().contains("policy snapshot storage sync is stale"));

    runtime.policy.refresh_if_newer().await.expect("refresh policy snapshot");
    runtime.policy.readiness(Duration::from_secs(1)).await.expect("refresh restores readiness");

    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        admin_config(),
    );
    let response = app
        .oneshot(admin_request(Method::GET, "/readyz", &json!({})))
        .await
        .expect("readiness response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn scim_refresh_projects_and_tombstones_principal() {
    let runtime = runtime(ScopeDeliveryConfig::default()).await;
    let app = AuthguardServer::management_router(
        runtime.policy,
        runtime.principals,
        runtime.cache,
        runtime.metrics,
        admin_config(),
    );
    let create = app
        .clone()
        .oneshot(admin_request(
            Method::POST,
            "/adm/v1/principal-discovery/scim/refresh",
            &json!({
                "operation":"upsert_user",
                "resource": {"id":"scim-user-1","userName":"scim.alice","active":true}
            }),
        ))
        .await
        .expect("SCIM upsert");
    assert_eq!(create.status(), StatusCode::OK);
    let created = response_json(create).await;
    let id = created["id"].as_str().expect("principal id").to_string();

    let delete = app
        .oneshot(admin_request(
            Method::POST,
            "/adm/v1/principal-discovery/scim/refresh",
            &json!({
                "operation":"delete",
                "resource": {
                    "provider_id":"corporate-scim",
                    "issuer":ISSUER,
                    "external_id":"scim-user-1"
                }
            }),
        ))
        .await
        .expect("SCIM tombstone");
    assert_eq!(delete.status(), StatusCode::OK);
    assert_eq!(response_json(delete).await["id"], id);
}
