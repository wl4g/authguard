//! Real-middleware principal discovery IT tests.
//!
//! Each provider test runs against a live identity server:
//!
//! * `AUTHGUARD_IT_KEYCLOAK_URL` — Keycloak admin API root of the realm
//!   provisioned by [`../deploy/keycloak`]. Tests the `FED_KEYCLOAK`
//!   federated search (search → materialize) and the Keycloak SCIM v2
//!   endpoint (pull users/groups → Authguard SCIM refresh ingestion).
//!   `AUTHGUARD_IT_KEYCLOAK_CLIENT_SECRET` may override the bootstrap
//!   default `it-client-secret`.
//! * `AUTHGUARD_IT_LDAP_URL` — `GLAuth` directory from
//!   [`../deploy/glauth`]. Tests the `FED_LDAP` federated search
//!   (search → materialize). Credentials are the static bootstrap defaults
//!   of that stack.
//!
//! When the corresponding environment variable is absent the test is
//! skipped, so `cargo test` stays green without the middleware. `make test`
//! therefore runs the whole Rust matrix as before.
//!
//! The tests exercise the public handler/route surface (management API
//! routes for search/materialize/refresh and the Envoy `Check` service for
//! JIT), i.e. the real E2E path through Authguard with the real protocols
//! (Keycloak Admin REST, SCIM v2, RFC 4511 LDAP) on the wire.
//!
//! [`../deploy/keycloak`]: ../deploy/keycloak
//! [`../deploy/glauth`]: ../deploy/glauth

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use authguard_core::cache::{IAuthorizationCache, MemoryAuthorizationCache};
use authguard_core::config::{
    AuthguardConfig, IdentityConfig, KeycloakPrincipalDiscoveryConfig,
    LdapPrincipalDiscoveryConfig, ScopeDeliveryConfig, SqliteConfig,
};
use authguard_core::handler::{DefaultAuthorizationHandler, PolicyHandler, PrincipalHandler};
use authguard_core::model::{AccessContextSigner, PrincipalKind, PrincipalStatus};
use authguard_core::principal::{
    JitPrincipalDiscovery, KeycloakPrincipalDiscovery, LdapPrincipalDiscovery,
    ScimPrincipalDiscovery, ScimUserResource,
};
use authguard_core::server::AuthguardServer;
use authguard_core::storage::{PrincipalRepository, SqliteAuthorizationRepository};
use authguard_core::MetricsRegistry;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request as HttpRequest, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use envoy_types::ext_authz::v3::pb::{Authorization, CheckRequest};
use envoy_types::pb::envoy::service::auth::v3::{attribute_context, AttributeContext};
use serde_json::{json, Value};
use tonic::Request;
use tower::ServiceExt as _;

const IT_KEYCLOAK_URL: &str = "AUTHGUARD_IT_KEYCLOAK_URL";
const IT_LDAP_URL: &str = "AUTHGUARD_IT_LDAP_URL";
const IT_KEYCLOAK_CLIENT_SECRET: &str = "AUTHGUARD_IT_KEYCLOAK_CLIENT_SECRET";

const KEYCLOAK_ISSUER: &str = "http://localhost:8080/realms/authguard-it";
const KEYCLOAK_PROVIDER_ID: &str = "it-keycloak";
const KEYCLOAK_REALM: &str = "authguard-it";
const KEYCLOAK_CLIENT_ID: &str = "authguard-it";
const KEYCLOAK_BOOTSTRAP_CLIENT_SECRET: &str = "it-client-secret";
const KEYCLOAK_SCIM_ENDPOINT_PATH: &str = "/scim/v2";

const LDAP_ISSUER: &str = "https://ldap.example.com";
const LDAP_PROVIDER_ID: &str = "it-glauth";
const LDAP_BIND_DN: &str = "cn=svc-authguard,ou=Users,dc=example,dc=com";
const LDAP_BIND_PASSWORD: &str = "password123";

const JIT_ISSUER: &str = "https://identity.example.com/realms/customer-growth";
const CONTEXT_SIGNING_KEY: [u8; 32] = [7; 32];

struct TestRuntime {
    principals: PrincipalHandler,
    authorization: DefaultAuthorizationHandler,
    cache: Arc<dyn IAuthorizationCache>,
    metrics: MetricsRegistry,
    repository: Arc<SqliteAuthorizationRepository>,
}

/// One immutable set of in-process handlers per runtime; the management router
/// is cloned per request like the other HTTP API tests.
async fn runtime(
    federated: Vec<Arc<authguard_core::principal::PrincipalSearchDiscovery>>,
) -> TestRuntime {
    let repository = Arc::new(
        SqliteAuthorizationRepository::connect(&SqliteConfig {
            url: "sqlite::memory:".to_string(),
            max_connections: 1,
            connect_timeout: Duration::from_secs(2),
        })
        .await
        .expect("connect SQLite"),
    );
    let cache: Arc<dyn IAuthorizationCache> = Arc::new(MemoryAuthorizationCache::default());
    let metrics = MetricsRegistry::default();
    let policy = PolicyHandler::open(repository.clone(), repository.clone(), metrics.clone(), None)
        .await
        .expect("policy handler");
    let jit = JitPrincipalDiscovery::new("verified-oidc", [JIT_ISSUER.to_string()], false)
        .expect("JIT discovery");
    let scim = ScimPrincipalDiscovery::new("it-scim", KEYCLOAK_ISSUER).expect("SCIM discovery");
    let principals = PrincipalHandler::new(repository.clone(), Some(jit), federated, Some(scim));
    let authorization = DefaultAuthorizationHandler::new(
        policy,
        principals.clone(),
        cache.clone(),
        metrics.clone(),
        IdentityConfig::default(),
        ScopeDeliveryConfig::default(),
        AccessContextSigner::new(CONTEXT_SIGNING_KEY).expect("test signer"),
        None,
    );
    TestRuntime { principals, authorization, cache, metrics, repository }
}

fn admin_config() -> AuthguardConfig {
    let mut config = AuthguardConfig::default();
    config.auth.admin_token = "admin-secret".to_string();
    config
}

async fn call(app: &axum::Router, request: HttpRequest<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.expect("management request");
    let status = response.status();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.expect("body"))
            .unwrap_or_else(|_| json!({}));
    (status, body)
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

/// Extracts the materialized local principal id from the JSON response of
/// `/adm/v1/principal-discovery/materialize`.
fn principal_id(body: &Value) -> &str {
    body["id"].as_str().expect("materialize response carries principal id")
}

/// POSTs one management API call and returns the status and JSON body.
async fn post(app: &axum::Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    call(app, admin_request(Method::POST, uri, body)).await
}

/// Runs one federated search through the management API.
async fn search(app: &axum::Router, text: &str, kind: &str) -> (StatusCode, Value) {
    post(
        app,
        "/adm/v1/principal-discovery/search",
        &json!({
            "text": text,
            "kinds": [kind],
            "per_provider_limit": 10,
        }),
    )
    .await
}

/// Materializes one search candidate through the management API, echoing the
/// `provider_id` the search returned (the configured `discovery_id`).
async fn materialize(
    app: &axum::Router,
    provider_id: &str,
    issuer: &str,
    external_id: &str,
) -> (StatusCode, Value) {
    post(
        app,
        "/adm/v1/principal-discovery/materialize",
        &json!({
            "provider_id": provider_id,
            "issuer": issuer,
            "external_id": external_id,
        }),
    )
    .await
}

/// Pushes one normalized SCIM event through the refresh route.
async fn scim_refresh(app: &axum::Router, operation: &str, resource: Value) -> (StatusCode, Value) {
    post(
        app,
        "/adm/v1/principal-discovery/scim/refresh",
        &json!({
            "operation": operation,
            "resource": resource,
        }),
    )
    .await
}

/// Pulls one SCIM resource collection with the required content negotiation.
async fn scim_collection(client: &reqwest::Client, url: &str, bearer: &str, name: &str) -> Value {
    let response = client
        .get(format!("{url}/{name}"))
        .bearer_auth(bearer)
        .header("Accept", "application/scim+json")
        .send()
        .await
        .expect("SCIM request");
    assert_eq!(response.status(), reqwest::StatusCode::OK, "SCIM {name} endpoint is mounted");
    response.json().await.expect("SCIM JSON")
}

/// Extracts the principals of one search page filtered to the given kind.
fn principals_of_kind<'a>(body: &'a Value, kind: &str) -> Vec<&'a Value> {
    body["principals"]
        .as_array()
        .expect("search principals array")
        .iter()
        .filter(|item| item["kind"] == kind)
        .collect()
}

/// Builds the handler wiring for the management router.
async fn app(runtime: &TestRuntime) -> axum::Router {
    let policy = PolicyHandler::open(
        runtime.repository.clone(),
        runtime.repository.clone(),
        MetricsRegistry::default(),
        None,
    )
    .await
    .expect("policy handler");
    AuthguardServer::management_router(
        policy,
        runtime.principals.clone(),
        runtime.cache.clone(),
        runtime.metrics.clone(),
        admin_config(),
    )
}

/// One fake-but-verified JWT with the given claims for the JIT path.
/// Authguard trusts Envoy to have verified it and decodes without checking
/// the signature (see the JIT projection contract in `http_api.rs`).
fn jwt(issuer: &str, subject: &str, groups: &[&str]) -> String {
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": issuer,
            "sub": subject,
            "authguard_group_ids": groups,
            "tenant_id": "example-corp",
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
                    path: "/unmapped-for-jit".to_string(),
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

// ===========================================================================
// Provider construction helpers.
// ===========================================================================

fn keycloak_env() -> Option<(String, String)> {
    let base_url = std::env::var(IT_KEYCLOAK_URL).ok()?;
    let secret = std::env::var(IT_KEYCLOAK_CLIENT_SECRET)
        .unwrap_or_else(|_| KEYCLOAK_BOOTSTRAP_CLIENT_SECRET.to_string());
    Some((base_url, secret))
}

fn keycloak_config(base_url: &str) -> KeycloakPrincipalDiscoveryConfig {
    KeycloakPrincipalDiscoveryConfig {
        enabled: true,
        discovery_id: KEYCLOAK_PROVIDER_ID.to_string(),
        base_url: base_url.to_string(),
        issuer: KEYCLOAK_ISSUER.to_string(),
        realm: KEYCLOAK_REALM.to_string(),
        client_id: KEYCLOAK_CLIENT_ID.to_string(),
        client_secret: String::new(),
        client_secret_file: String::new(),
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(30),
        max_page_size: 50,
        allow_insecure_http: true,
    }
}

fn ldap_config(url: &str) -> LdapPrincipalDiscoveryConfig {
    // The GLAuth DIT nests users under ou=users/{primary-group} and groups
    // under ou=groups; both are searched from the base DN with an
    // objectClass filter that keeps only the requested object type.
    LdapPrincipalDiscoveryConfig {
        enabled: true,
        discovery_id: LDAP_PROVIDER_ID.to_string(),
        url: url.to_string(),
        issuer: LDAP_ISSUER.to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: LDAP_BIND_DN.to_string(),
        bind_password: LDAP_BIND_PASSWORD.to_string(),
        bind_password_file: String::new(),
        user: authguard_core::config::LdapObjectMappingConfig {
            search_base: String::new(),
            object_filter: "(objectClass=posixAccount)".to_string(),
            id_attribute: "cn".to_string(),
            name_attribute: "cn".to_string(),
            display_name_attribute: None,
            email_attribute: Some("mail".to_string()),
            enabled_attribute: Some("accountStatus".to_string()),
            search_attributes: vec!["cn".to_string(), "mail".to_string(), "sn".to_string()],
        },
        group: authguard_core::config::LdapObjectMappingConfig {
            search_base: "ou=groups".to_string(),
            object_filter: "(objectClass=groupOfUniqueNames)".to_string(),
            id_attribute: "ou".to_string(),
            name_attribute: "ou".to_string(),
            display_name_attribute: None,
            email_attribute: None,
            enabled_attribute: None,
            search_attributes: vec!["ou".to_string()],
        },
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(30),
        max_page_size: 50,
        allow_insecure: true,
    }
}

/// Renders a Keycloak token endpoint URL and fetches a fresh client-credentials
/// token for the bootstrap client.
async fn keycloak_token(
    client: &reqwest::Client,
    base_url: &str,
    secret: &str,
) -> reqwest::Response {
    client
        .post(format!("{base_url}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", KEYCLOAK_CLIENT_ID),
            ("client_secret", secret),
        ])
        .send()
        .await
        .expect("token request")
}

/// Picks the `external_id` carried by one SCIM user resource. Keycloak does not
/// return `externalId` by default, so Authguard falls back to the SCIM
/// resource id (`user.id`).
fn scim_user_external_id(user: &ScimUserResource) -> String {
    user.external_id.as_deref().unwrap_or(&user.id).to_string()
}

// ===========================================================================
// JIT: the Envoy Check path projects a verified-but-unknown identity without
// any federation search.
// ===========================================================================

#[tokio::test]
async fn jit_projection_materializes_verified_identity_on_envoy_check() {
    let runtime = runtime(Vec::new()).await;
    // A verified identity that is unknown locally must be JIT-projected.
    let response = runtime
        .authorization
        .clone()
        .check(Request::new(check_request(Some(&jwt(JIT_ISSUER, "jit-user-1", &["growth-team"])))))
        .await
        .expect("check")
        .into_inner();
    assert_eq!(
        response.status.as_ref().expect("status").code,
        tonic::Code::PermissionDenied as i32,
        "unmapped route fails closed"
    );

    // ... and the projection must now exist locally.
    let projected = runtime
        .repository
        .find_by_external_key(JIT_ISSUER, "jit-user-1")
        .await
        .expect("query")
        .expect("JIT projection");
    assert_eq!(projected.kind, PrincipalKind::User);
    assert_eq!(projected.status, PrincipalStatus::Active);
    let projected_group = runtime
        .repository
        .find_by_external_key(JIT_ISSUER, "group:growth-team")
        .await
        .expect("query")
        .expect("JIT group projection");
    assert_eq!(projected_group.kind, PrincipalKind::Group);
}

// ===========================================================================
// FED_KEYCLOAK: search the Keycloak Admin REST API and materialize.
// ===========================================================================

#[tokio::test]
async fn keycloak_federated_search_and_materialize() {
    let Some((base_url, secret)) = keycloak_env() else {
        eprintln!("skipping: {IT_KEYCLOAK_URL} is not set");
        return;
    };

    let provider = Arc::new(
        KeycloakPrincipalDiscovery::with_client_credentials(
            &keycloak_config(&base_url),
            KEYCLOAK_CLIENT_ID,
            secret,
        )
        .expect("keycloak provider"),
    );
    let runtime = runtime(vec![provider]).await;
    let app = app(&runtime).await;

    // 1. Federated user search via the management API.
    let (status, body) = search(&app, "ada", "USER").await;
    assert_eq!(status, StatusCode::OK, "federated search response: {body}");
    let adalwin = principals_of_kind(&body, "USER")
        .into_iter()
        .find(|item| item["username"] == "adalwin")
        .unwrap_or_else(|| panic!("adalwin in search results: {body}"));
    assert_eq!(adalwin["reference"]["provider_id"], KEYCLOAK_PROVIDER_ID);
    assert_eq!(adalwin["reference"]["issuer"], KEYCLOAK_ISSUER);
    let adalwin_external_id =
        adalwin["reference"]["external_id"].as_str().expect("external id").to_string();
    assert_eq!(adalwin["display_name"], "Ada Lwin", "first/last joined display name");
    assert_eq!(adalwin["email"], "adalwin@example.com");

    // 2. Materialize the search result through the management API.
    let (status, body) =
        materialize(&app, KEYCLOAK_PROVIDER_ID, KEYCLOAK_ISSUER, &adalwin_external_id).await;
    assert_eq!(status, StatusCode::CREATED, "materialize response: {body}");
    let materialized_id = principal_id(&body).to_string();

    // 3. The local projection must be searchable through the principals
    //    listing endpoint and carry the provider metadata.
    let (status, body) =
        call(&app, admin_request(Method::GET, "/adm/v1/principals?limit=100", &json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let materialized = body["items"]
        .as_array()
        .expect("principal items")
        .iter()
        .find(|item| item["id"] == materialized_id)
        .unwrap_or_else(|| panic!("materialized principal in list: {body}"));
    assert_eq!(materialized["kind"], "USER");
    assert_eq!(materialized["external_id"], adalwin_external_id);
    assert_eq!(materialized["attributes"]["provider_id"], KEYCLOAK_PROVIDER_ID);
    assert_eq!(materialized["attributes"]["username"], "adalwin");

    // 4. Group search: deterministic subgroup with stable external ids.
    let (status, body) = search(&app, "growth", "GROUP").await;
    assert_eq!(status, StatusCode::OK, "group search response: {body}");
    let growth = principals_of_kind(&body, "GROUP")
        .into_iter()
        .find(|item| item["display_name"] == "growth-team")
        .unwrap_or_else(|| panic!("growth-team in search results: {body}"));
    let growth_external_id =
        growth["reference"]["external_id"].as_str().expect("external id").to_string();
    assert!(growth_external_id.starts_with("group:"), "group external ids are namespaced");

    // 5. Materializing the group yields a GROUP projection with the same key.
    let (status, body) =
        materialize(&app, KEYCLOAK_PROVIDER_ID, KEYCLOAK_ISSUER, &growth_external_id).await;
    assert_eq!(status, StatusCode::CREATED, "group materialize response: {body}");
    let group_principal = runtime
        .repository
        .get(principal_id(&body))
        .await
        .expect("query")
        .expect("group projection");
    assert_eq!(group_principal.kind, PrincipalKind::Group);
    assert_eq!(group_principal.external_id, growth_external_id);
}

// ===========================================================================
// SCIM: pull real resources from the Keycloak SCIM v2 endpoint and push them
// through the Authguard SCIM refresh route.
// ===========================================================================

#[tokio::test]
async fn scim_refresh_ingests_keycloak_scim_users_and_groups() {
    let Some((base_url, secret)) = keycloak_env() else {
        eprintln!("skipping: {IT_KEYCLOAK_URL} is not set");
        return;
    };

    // Get a real SCIM bearer token with the required audience claim and pull
    // the resources straight from Keycloak's SCIM v2 endpoint.
    let client = reqwest::Client::new();
    let response = keycloak_token(&client, &base_url, &secret).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK, "client credentials token");
    let token: Value = response.json().await.expect("token JSON");
    let bearer = token["access_token"].as_str().expect("access token").to_string();

    let scim_url = format!("{base_url}/realms/{KEYCLOAK_REALM}{KEYCLOAK_SCIM_ENDPOINT_PATH}");
    let users = scim_collection(&client, &scim_url, &bearer, "Users").await;
    let scim_users = users["Resources"].as_array().expect("SCIM Resources array");
    let groups = scim_collection(&client, &scim_url, &bearer, "Groups").await;
    let scim_groups = groups["Resources"].as_array().expect("SCIM group Resources array");
    assert!(!scim_groups.is_empty(), "seeded groups are visible through SCIM");

    // Feed the raw SCIM users into Authguard through the refresh route.
    let runtime = runtime(Vec::new()).await;
    let app = app(&runtime).await;
    let mut ingested_users = Vec::new();
    for resource in scim_users {
        let user = serde_json::from_value::<ScimUserResource>(resource.clone())
            .expect("SCIM user resource");
        let external_id = scim_user_external_id(&user);
        let (status, body) = scim_refresh(&app, "upsert_user", resource.clone()).await;
        assert_eq!(status, StatusCode::OK, "SCIM upsert response: {body}");
        ingested_users.push((external_id, body["id"].as_str().expect("id").to_string()));
    }

    // Every SCIM user projection must exist locally with a USER kind and the
    // SCIM issuer, converging on the same external id the federated Keycloak
    // search would report (the Keycloak user id).
    assert_eq!(ingested_users.len(), 3, "all seeded users were ingested");
    for (external_id, scim_principal_id) in &ingested_users {
        let (status, body) = call(
            &app,
            admin_request(
                Method::GET,
                &format!("/adm/v1/principals/{scim_principal_id}"),
                &json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["kind"], "USER");
        assert_eq!(body["external_id"], external_id.as_str());
        assert_eq!(body["issuer"], KEYCLOAK_ISSUER);
    }

    // Ingest one group and verify the tombstone path for an unknown id.
    let group = serde_json::from_value::<authguard_core::principal::ScimGroupResource>(
        scim_groups[0].clone(),
    )
    .expect("SCIM group resource");
    let group_external_id = format!("group:{}", group.external_id.as_deref().unwrap_or(&group.id));
    let (status, body) = scim_refresh(&app, "upsert_group", scim_groups[0].clone()).await;
    assert_eq!(status, StatusCode::OK, "group upsert response: {body}");
    assert_eq!(body["kind"], "GROUP");

    // DELETE tombstone: unknown external id must be a no-op.
    let (status, body) = scim_refresh(
        &app,
        "delete",
        json!({
            "provider_id": "it-scim",
            "issuer": KEYCLOAK_ISSUER,
            "external_id": "not-a-real-scim-id",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "delete response: {body}");
    assert!(body["id"].is_null(), "unknown SCIM delete is a no-op");

    // DELETE tombstone: the known group must be disabled.
    let (status, body) = scim_refresh(
        &app,
        "delete",
        json!({
            "provider_id": "it-scim",
            "issuer": KEYCLOAK_ISSUER,
            "external_id": group_external_id,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "known delete response: {body}");
    assert_eq!(body["status"], "DISABLED", "SCIM delete is a tombstone");
}

// ===========================================================================
// FED_LDAP: search the GLAuth directory and materialize.
// ===========================================================================

#[tokio::test]
async fn ldap_federated_search_and_materialize() {
    let Some(url) = std::env::var(IT_LDAP_URL).ok() else {
        eprintln!("skipping: {IT_LDAP_URL} is not set");
        return;
    };

    let provider =
        Arc::new(LdapPrincipalDiscovery::new(&ldap_config(&url)).expect("ldap provider"));
    let runtime = runtime(vec![provider]).await;
    let app = app(&runtime).await;

    // 1. Federated user search through the management API.
    let (status, body) = search(&app, "doe", "USER").await;
    assert_eq!(status, StatusCode::OK, "LDAP search response: {body}");
    let jdoe = principals_of_kind(&body, "USER")
        .into_iter()
        .find(|item| item["username"] == "jdoe")
        .unwrap_or_else(|| panic!("jdoe in LDAP search results: {body}"));
    assert_eq!(jdoe["reference"]["provider_id"], LDAP_PROVIDER_ID);
    assert_eq!(jdoe["reference"]["issuer"], LDAP_ISSUER);
    assert_eq!(jdoe["reference"]["external_id"], "jdoe");
    assert_eq!(jdoe["email"], "jdoe@example.com");

    // 2. Materialize the search result through the management API, echoing
    //    the provider_id returned by the search (the configured discovery id).
    let (status, body) = materialize(&app, LDAP_PROVIDER_ID, LDAP_ISSUER, "jdoe").await;
    assert_eq!(status, StatusCode::CREATED, "LDAP materialize response: {body}");
    let materialized_id = principal_id(&body).to_string();

    let materialized = runtime
        .repository
        .get(&materialized_id)
        .await
        .expect("query")
        .expect("materialized projection");
    assert_eq!(materialized.kind, PrincipalKind::User);
    assert_eq!(materialized.external_id, "jdoe");
    assert_eq!(materialized.attributes["provider_id"], LDAP_PROVIDER_ID);
    assert_eq!(materialized.attributes["username"], "jdoe");

    // 3. Group search and materialization.
    let (status, body) = search(&app, "eng", "GROUP").await;
    assert_eq!(status, StatusCode::OK, "LDAP group search response: {body}");
    let engineering = principals_of_kind(&body, "GROUP")
        .into_iter()
        .find(|item| item["display_name"] == "Engineering")
        .unwrap_or_else(|| panic!("Engineering in LDAP search results: {body}"));
    let group_external_id =
        engineering["reference"]["external_id"].as_str().expect("external id").to_string();
    assert_eq!(group_external_id, "group:Engineering");

    let (status, body) = materialize(&app, LDAP_PROVIDER_ID, LDAP_ISSUER, &group_external_id).await;
    assert_eq!(status, StatusCode::CREATED, "LDAP group materialize response: {body}");
    let group_principal_id = principal_id(&body).to_string();
    let group_principal = runtime
        .repository
        .get(&group_principal_id)
        .await
        .expect("query")
        .expect("group projection");
    assert_eq!(group_principal.kind, PrincipalKind::Group);
    assert_eq!(group_principal.external_id, "group:Engineering");
}
