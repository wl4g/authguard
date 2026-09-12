use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode as AxumStatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::*;

struct FixedToken;

#[async_trait]
impl BearerTokenProvider for FixedToken {
    async fn bearer_token(&self) -> Result<String, PrincipalDiscoveryError> {
        Ok("admin-token".to_string())
    }
}

#[derive(Clone, Default)]
struct TestState {
    token_requests: Arc<AtomicUsize>,
    user_searches: Arc<AtomicUsize>,
    group_searches: Arc<AtomicUsize>,
}

async fn start_server() -> (String, TestState, JoinHandle<()>) {
    let state = TestState::default();
    let app = Router::new()
        .route("/realms/{realm}/protocol/openid-connect/token", post(token))
        .route("/admin/realms/{realm}/users", get(search))
        .route("/admin/realms/{realm}/users/{id}", get(resolve))
        .route("/admin/realms/{realm}/groups", get(search_groups))
        .route("/admin/realms/{realm}/groups/{id}", get(resolve_group))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test server");
    let address = listener.local_addr().expect("test address");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    (format!("http://{address}"), state, handle)
}

async fn token(State(state): State<TestState>, Path(realm): Path<String>) -> impl IntoResponse {
    assert_eq!(realm, "customer-growth");
    state.token_requests.fetch_add(1, Ordering::Relaxed);
    Json(json!({
        "access_token": "admin-token",
        "expires_in": 300,
        "token_type": "Bearer"
    }))
}

async fn search(
    State(state): State<TestState>,
    Path(realm): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    assert_eq!(realm, "customer-growth");
    assert_eq!(
        headers.get("authorization").and_then(|value| value.to_str().ok()),
        Some("Bearer admin-token")
    );
    assert!(
        query.get("search").is_some_and(|value| !value.is_empty())
            || query.get("username").is_some_and(|value| !value.is_empty())
    );
    state.user_searches.fetch_add(1, Ordering::Relaxed);
    assert_eq!(query.get("max").map(String::as_str), Some("2"));
    let users = json!([
        {
            "id": "user-42",
            "username": "alice",
            "firstName": "Alice",
            "lastName": "Analyst",
            "email": "alice@example.com",
            "enabled": true,
            "attributes": {"department": ["growth"]}
        },
        {
            "id": "workload-7",
            "username": "service-account-growth-job",
            "enabled": true,
            "serviceAccountClientId": "growth-job",
            "attributes": {}
        }
    ]);
    if query.contains_key("username") {
        Json(Value::Array(vec![users[1].clone()]))
    } else {
        Json(users)
    }
}

async fn resolve(
    Path((_realm, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    assert_eq!(
        headers.get("authorization").and_then(|value| value.to_str().ok()),
        Some("Bearer admin-token")
    );
    if id == "missing" {
        return (AxumStatusCode::NOT_FOUND, Json(Value::Null));
    }
    (
        AxumStatusCode::OK,
        Json(json!({
            "id": id,
            "username": "alice",
            "firstName": "Alice",
            "lastName": "Analyst",
            "enabled": true,
            "attributes": {}
        })),
    )
}

async fn search_groups(
    State(state): State<TestState>,
    Path(realm): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    assert_eq!(realm, "customer-growth");
    assert_eq!(
        headers.get("authorization").and_then(|value| value.to_str().ok()),
        Some("Bearer admin-token")
    );
    assert!(query.get("search").is_some_and(|value| !value.is_empty()));
    state.group_searches.fetch_add(1, Ordering::Relaxed);
    if query.get("search").map(String::as_str) == Some("mixed-principal") {
        Json(json!([
            {
                "id": "growth-team-id",
                "name": "Growth Analytics",
                "path": "/growth-analytics",
                "attributes": {"department": ["growth"]}
            },
            {
                "id": "campaign-team-id",
                "name": "Campaign Analytics",
                "path": "/campaign-analytics",
                "attributes": {"department": ["growth"]}
            }
        ]))
    } else {
        Json(json!([{
            "id": "growth-team-id",
            "name": "Growth Analytics",
            "path": "/growth-analytics",
            "attributes": {"department": ["growth"]}
        }]))
    }
}

async fn resolve_group(
    Path((_realm, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    assert_eq!(
        headers.get("authorization").and_then(|value| value.to_str().ok()),
        Some("Bearer admin-token")
    );
    Json(json!({"id": id, "name": "Growth Analytics", "path": "/growth-analytics"}))
}

fn test_config(base_url: String) -> KeycloakPrincipalDiscoveryProperties {
    KeycloakPrincipalDiscoveryProperties {
        discovery_id: "corporate-keycloak".to_string(),
        base_url,
        realm: "customer-growth".to_string(),
        allow_insecure_http: true,
        max_page_size: 2,
        ..KeycloakPrincipalDiscoveryProperties::default()
    }
}

#[test]
fn service_account_username_fallback_preserves_workload_kind() {
    let config = test_config("http://127.0.0.1:8080".to_string());
    let provider = KeycloakPrincipalDiscovery::with_bearer_provider(&config, Arc::new(FixedToken))
        .expect("provider");
    let principal = provider
        .map_user(KeycloakUser {
            id: Some("workload-7".to_string()),
            username: Some("service-account-growth-job".to_string()),
            first_name: None,
            last_name: None,
            email: None,
            enabled: Some(true),
            service_account_client_id: None,
            attributes: BTreeMap::new(),
        })
        .expect("service account projection");

    assert_eq!(principal.kind, PrincipalKind::Workload);
}

#[test]
fn rejects_plain_http_by_default() {
    let config = KeycloakPrincipalDiscoveryProperties {
        discovery_id: "corporate-keycloak".to_string(),
        base_url: "http://id.example.com".to_string(),
        realm: "customer-growth".to_string(),
        ..KeycloakPrincipalDiscoveryProperties::default()
    };
    let result = KeycloakPrincipalDiscovery::with_bearer_provider(&config, Arc::new(FixedToken));
    assert!(matches!(result, Err(PrincipalDiscoveryError::InvalidConfiguration(_))));
}

#[tokio::test]
async fn search_maps_users_workloads_and_stream_cursor() {
    let (base_url, _state, server) = start_server().await;
    let expected_issuer = "https://identity.example.com/realms/customer-growth";
    let mut config = test_config(base_url);
    config.issuer = expected_issuer.to_string();
    let provider = KeycloakPrincipalDiscovery::with_bearer_provider(&config, Arc::new(FixedToken))
        .expect("provider");
    let mut query = PrincipalSearchQuery::new("alice@example.com");
    query.per_provider_limit = 2;
    query.cursors.insert("corporate-keycloak:users".to_string(), "20".to_string());
    query.kinds.extend([PrincipalKind::User, PrincipalKind::Workload]);

    let page = provider.discover(query).await.expect("search");

    assert_eq!(page.principals.len(), 2);
    assert_eq!(page.principals[0].kind, PrincipalKind::User);
    assert_eq!(page.principals[0].display_name, "Alice Analyst");
    assert_eq!(page.principals[0].identity_key(), (expected_issuer, "user-42"));
    assert_eq!(page.principals[0].reference.external_id, "user-42");
    assert_eq!(page.principals[1].kind, PrincipalKind::Workload);
    assert_eq!(page.next_cursors.get("corporate-keycloak:users").map(String::as_str), Some("22"));
    server.abort();
}

#[tokio::test]
async fn workload_only_search_uses_exact_service_account_username() {
    let (base_url, state, server) = start_server().await;
    let provider = KeycloakPrincipalDiscovery::with_bearer_provider(
        &test_config(base_url),
        Arc::new(FixedToken),
    )
    .expect("provider");
    let mut query = PrincipalSearchQuery::new("service-account-growth-job");
    query.per_provider_limit = 2;
    query.kinds.insert(PrincipalKind::Workload);

    let page = provider.discover(query).await.expect("workload search");

    assert_eq!(state.user_searches.load(Ordering::Relaxed), 1);
    assert_eq!(page.principals.len(), 1);
    assert_eq!(page.principals[0].kind, PrincipalKind::Workload);
    assert_eq!(page.principals[0].username.as_deref(), Some("service-account-growth-job"));
    server.abort();
}

#[tokio::test]
async fn resolve_returns_principal_or_none() {
    let (base_url, _state, server) = start_server().await;
    let provider = KeycloakPrincipalDiscovery::with_bearer_provider(
        &test_config(base_url),
        Arc::new(FixedToken),
    )
    .expect("provider");
    let existing = ExternalPrincipalRef {
        provider_id: "corporate-keycloak".to_string(),
        issuer: provider.issuer.clone(),
        external_id: "user-42".to_string(),
    };
    let missing = ExternalPrincipalRef { external_id: "missing".to_string(), ..existing.clone() };

    assert!(provider.resolve_principal(&existing).await.expect("resolve existing").is_some());
    assert!(provider.resolve_principal(&missing).await.expect("resolve missing").is_none());
    server.abort();
}

#[tokio::test]
async fn resolves_group_reference_using_namespaced_external_id() {
    let (base_url, _state, server) = start_server().await;
    let provider = KeycloakPrincipalDiscovery::with_bearer_provider(
        &test_config(base_url),
        Arc::new(FixedToken),
    )
    .expect("provider");
    let reference = ExternalPrincipalRef {
        provider_id: "corporate-keycloak".to_string(),
        issuer: provider.issuer.clone(),
        external_id: "group:growth-team-id".to_string(),
    };

    let principal = provider.resolve_principal(&reference).await.expect("resolve").expect("group");

    assert_eq!(principal.kind, PrincipalKind::Group);
    assert_eq!(principal.reference, reference);
    server.abort();
}

#[tokio::test]
async fn client_credentials_token_is_reused_until_refresh() {
    let (base_url, state, server) = start_server().await;
    let provider = KeycloakPrincipalDiscovery::with_client_credentials(
        &test_config(base_url),
        "authguard-federation",
        "not-logged-secret",
    )
    .expect("provider");
    let mut query = PrincipalSearchQuery::new("alice@example.com");
    query.per_provider_limit = 2;
    query.cursors.insert("corporate-keycloak".to_string(), "20".to_string());
    query.kinds.insert(PrincipalKind::User);

    provider.discover(query.clone()).await.expect("first search");
    provider.discover(query).await.expect("second search");

    assert_eq!(state.token_requests.load(Ordering::Relaxed), 1);
    server.abort();
}

#[tokio::test]
async fn invalid_provider_cursor_fails_before_http_request() {
    let (base_url, state, server) = start_server().await;
    let provider = KeycloakPrincipalDiscovery::with_client_credentials(
        &test_config(base_url),
        "authguard-federation",
        "not-logged-secret",
    )
    .expect("provider");
    let mut query = PrincipalSearchQuery::new("alice@example.com");
    query.cursors.insert("corporate-keycloak:users".to_string(), "invalid".to_string());

    let result = provider.discover(query).await;

    assert!(matches!(result, Err(PrincipalDiscoveryError::InvalidQuery(_))));
    assert_eq!(state.token_requests.load(Ordering::Relaxed), 0);
    server.abort();
}

#[tokio::test]
async fn group_only_search_does_not_call_the_user_endpoint() {
    let (base_url, state, server) = start_server().await;
    let provider = KeycloakPrincipalDiscovery::with_client_credentials(
        &test_config(base_url),
        "authguard-federation",
        "not-logged-secret",
    )
    .expect("provider");
    let mut query = PrincipalSearchQuery::new("growth-team");
    query.kinds.insert(PrincipalKind::Group);

    let page = provider.discover(query).await.expect("search");

    assert_eq!(page.principals.len(), 1);
    assert_eq!(page.principals[0].kind, PrincipalKind::Group);
    assert_eq!(page.principals[0].reference.external_id, "group:growth-team-id");
    assert_eq!(state.token_requests.load(Ordering::Relaxed), 1);
    assert_eq!(state.user_searches.load(Ordering::Relaxed), 0);
    assert_eq!(state.group_searches.load(Ordering::Relaxed), 1);
    server.abort();
}

#[tokio::test]
async fn default_search_queries_users_and_groups_with_independent_cursors() {
    let (base_url, state, server) = start_server().await;
    let provider = KeycloakPrincipalDiscovery::with_client_credentials(
        &test_config(base_url),
        "authguard-federation",
        "not-logged-secret",
    )
    .expect("provider");
    let mut query = PrincipalSearchQuery::new("mixed-principal");
    query.per_provider_limit = 2;
    query.cursors.insert("corporate-keycloak:users".to_string(), "20".to_string());
    query.cursors.insert("corporate-keycloak:groups".to_string(), "40".to_string());

    let page = provider.discover(query).await.expect("mixed search");

    assert_eq!(page.principals.len(), 4);
    assert_eq!(state.user_searches.load(Ordering::Relaxed), 1);
    assert_eq!(state.group_searches.load(Ordering::Relaxed), 1);
    assert_eq!(state.token_requests.load(Ordering::Relaxed), 1);
    assert_eq!(page.next_cursors.get("corporate-keycloak:users").map(String::as_str), Some("22"));
    assert_eq!(page.next_cursors.get("corporate-keycloak:groups").map(String::as_str), Some("42"));
    server.abort();
}

#[tokio::test]
async fn resolve_rejects_issuer_mismatch_before_requesting_a_token() {
    let (base_url, state, server) = start_server().await;
    let provider = KeycloakPrincipalDiscovery::with_client_credentials(
        &test_config(base_url),
        "authguard-federation",
        "not-logged-secret",
    )
    .expect("provider");
    let reference = ExternalPrincipalRef {
        provider_id: "corporate-keycloak".to_string(),
        issuer: "https://attacker.example/realms/customer-growth".to_string(),
        external_id: "user-42".to_string(),
    };

    let result = provider.resolve_principal(&reference).await;

    assert!(matches!(result, Err(PrincipalDiscoveryError::InvalidQuery(_))));
    assert_eq!(state.token_requests.load(Ordering::Relaxed), 0);
    server.abort();
}

#[test]
fn preserves_explicit_issuer_exactly() {
    let mut config = test_config("http://127.0.0.1:9".to_string());
    let issuer = "https://identity.example.com/realms/customer-growth/";
    config.issuer = issuer.to_string();

    let provider = KeycloakPrincipalDiscovery::with_bearer_provider(&config, Arc::new(FixedToken))
        .expect("provider");

    assert_eq!(provider.issuer, issuer);
}

#[test]
fn rejects_configuration_with_surrounding_whitespace() {
    let config = KeycloakPrincipalDiscoveryProperties {
        discovery_id: "corporate-keycloak".to_string(),
        base_url: " https://identity.example.com".to_string(),
        realm: "customer-growth".to_string(),
        ..KeycloakPrincipalDiscoveryProperties::default()
    };

    assert!(matches!(
        KeycloakPrincipalDiscovery::with_bearer_provider(&config, Arc::new(FixedToken)),
        Err(PrincipalDiscoveryError::InvalidConfiguration(_))
    ));
}

#[tokio::test]
async fn oversized_search_text_fails_before_requesting_a_token() {
    let (base_url, state, server) = start_server().await;
    let provider = KeycloakPrincipalDiscovery::with_client_credentials(
        &test_config(base_url),
        "authguard-federation",
        "not-logged-secret",
    )
    .expect("provider");
    let query = PrincipalSearchQuery::new("x".repeat(PrincipalSearchQuery::MAX_TEXT_BYTES + 1));

    let result = provider.discover(query).await;

    assert!(matches!(result, Err(PrincipalDiscoveryError::InvalidQuery(_))));
    assert_eq!(state.token_requests.load(Ordering::Relaxed), 0);
    server.abort();
}
