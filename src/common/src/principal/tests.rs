use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query};
use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode as AxumStatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::PrincipalSearchQuery;
use super::*;

struct TestState {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

async fn start_server() -> (String, TestState, JoinHandle<()>) {
    let state = TestState { calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)) };
    let calls = state.calls.clone();
    let app = Router::new().route(
        "/api/dsp/{kind}/search",
        get(
            move |Query(params): Query<std::collections::HashMap<String, String>>,
                  Path(kind): Path<String>,
                  headers: axum::http::HeaderMap| {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if headers.get(AUTHORIZATION)
                        != Some(&axum::http::HeaderValue::from_static("Bearer dsp-token"))
                    {
                        return (AxumStatusCode::UNAUTHORIZED, Json(json!({}))).into_response();
                    }
                    if let Some(id) = params.get("id") {
                        if id == "missing" {
                            return (AxumStatusCode::NOT_FOUND, Json(json!({}))).into_response();
                        }
                        return Json(json!({
                            "id": id,
                            "display_name": format!("DSP {id}"),
                            "username": format!("user-{id}"),
                            "email": format!("{id}@example.com"),
                            "enabled": true,
                            "kind": "USER",
                        }))
                        .into_response();
                    }
                    let offset: usize = params.get("offset").unwrap().parse().unwrap();
                    let limit: usize = params.get("limit").unwrap().parse().unwrap();
                    let items = (offset..offset + limit)
                        .map(|i| {
                            json!({
                                "id": format!("dsp-{i}"),
                                "display_name": format!("DSP {i}"),
                                "username": format!("dsp{i}"),
                                "email": format!("dsp{i}@example.com"),
                                "enabled": i % 2 == 0,
                                "kind": kind,
                            })
                        })
                        .collect::<Vec<_>>();
                    Json(json!({ "items": items })).into_response()
                }
            },
        ),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (address, state, server)
}

fn config(url: &str) -> CustomPrincipalDiscoveryProperties {
    use crate::config::{CustomRequestBindingProperties, CustomResponseMappingProperties};
    CustomPrincipalDiscoveryProperties {
        discovery_id: "dsp-directory".to_string(),
        url: url.to_string(),
        issuer: "https://dsp.example.com".to_string(),
        jwt_token: "dsp-token".to_string(),
        request: CustomRequestBindingProperties {
            path: "api/dsp/{{kind}}/search".to_string(),
            text_param: "search".to_string(),
            offset_param: "offset".to_string(),
            limit_param: "limit".to_string(),
            external_id_param: "id".to_string(),
            body_template: None,
        },
        response: CustomResponseMappingProperties {
            array_path: "/items".to_string(),
            id_attr: "id".to_string(),
            display_name_attr: "display_name".to_string(),
            username_attr: Some("username".to_string()),
            email_attr: Some("email".to_string()),
            enabled_attr: Some("enabled".to_string()),
            kind_attr: Some("kind".to_string()),
        },
        connect_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(2),
        max_page_size: 100,
        allow_insecure_http: true,
        ..CustomPrincipalDiscoveryProperties::default()
    }
}

fn query(text: &str, kinds: &[PrincipalKind]) -> PrincipalSearchQuery {
    PrincipalSearchQuery {
        text: text.to_string(),
        kinds: kinds.iter().copied().collect(),
        provider_ids: std::collections::BTreeSet::new(),
        per_provider_limit: 10,
        cursors: std::collections::BTreeMap::new(),
    }
}

#[test]
fn query_kind_filter_is_open_by_default_and_exact_when_configured() {
    let all = query("alice", &[]);
    assert!(all.supports_kind(PrincipalKind::User));
    assert!(all.supports_kind(PrincipalKind::Group));

    let users = query("alice", &[PrincipalKind::User]);
    assert!(users.supports_kind(PrincipalKind::User));
    assert!(!users.supports_kind(PrincipalKind::Group));
}

#[test]
fn offset_cursor_is_stream_scoped_and_rejects_non_numeric_values() {
    let mut query = query("alice", &[]);
    let key = PrincipalSearchQuery::cursor_key("keycloak", "users");
    query.cursors.insert(key, "42".to_string());
    assert_eq!(query.offset_cursor("keycloak", "users").unwrap(), 42);
    assert_eq!(query.offset_cursor("keycloak", "groups").unwrap(), 0);

    query
        .cursors
        .insert(PrincipalSearchQuery::cursor_key("keycloak", "groups"), "invalid".to_string());
    assert!(matches!(
        query.offset_cursor("keycloak", "groups"),
        Err(PrincipalDiscoveryError::InvalidQuery(_))
    ));
}

#[test]
fn render_keeps_unknown_placeholders_and_renders_known_ones() {
    let template = "{\"q\":\"{{search}}\",\"kind\":\"{{kind}}\",\"fixed\":\"{{vendor}}\"}";
    assert_eq!(
        CustomPrincipalDiscovery::render(template, |name| match name {
            SEARCH_PLACEHOLDER => Some("alice".to_string()),
            KIND_PLACEHOLDER => Some("user".to_string()),
            _ => None,
        }),
        "{\"q\":\"alice\",\"kind\":\"user\",\"fixed\":\"{{vendor}}\"}"
    );
}

#[tokio::test]
async fn search_maps_kind_aware_entries_and_streams_user_group_cursors() {
    let (address, _state, _server) = start_server().await;
    let discovery = CustomPrincipalDiscovery::new(&config(&address)).unwrap();
    assert_eq!(discovery.provider(), "FED_CUSTOM");

    let page = discovery
        .discover(query("alice", &[PrincipalKind::User, PrincipalKind::Group]))
        .await
        .unwrap();
    // 10 users + 10 groups, both streams returning a full page.
    assert_eq!(page.principals.len(), 20);
    let user = &page.principals[0];
    assert_eq!(user.reference.external_id, "dsp-0");
    assert_eq!(user.reference.issuer, "https://dsp.example.com");
    assert_eq!(user.kind, PrincipalKind::User);
    assert_eq!(user.display_name, "DSP 0");
    assert_eq!(user.username.as_deref(), Some("dsp0"));
    assert_eq!(user.email.as_deref(), Some("dsp0@example.com"));
    assert!(user.enabled);
    let group = &page.principals[10];
    assert_eq!(group.reference.external_id, "group:dsp-0");
    assert_eq!(group.kind, PrincipalKind::Group);
    assert_eq!(page.next_cursors.len(), 2);

    let users_only = discovery.discover(query("alice", &[PrincipalKind::User])).await.unwrap();
    assert_eq!(users_only.principals.len(), 10);
    assert!(users_only.principals.iter().all(|p| p.kind == PrincipalKind::User));
    assert_eq!(users_only.next_cursors.len(), 1);
}

#[tokio::test]
async fn resolve_maps_exact_entry_and_reports_unknown_external_ids() {
    let (address, _state, _server) = start_server().await;
    let discovery = CustomPrincipalDiscovery::new(&config(&address)).unwrap();
    let principal = discovery
        .resolve_principal(&ExternalPrincipalRef {
            provider_id: "dsp-directory".to_string(),
            issuer: "https://dsp.example.com".to_string(),
            external_id: "dsp-7".to_string(),
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(principal.reference.external_id, "dsp-7");
    assert_eq!(principal.display_name, "DSP dsp-7");

    let missing = discovery
        .resolve_principal(&ExternalPrincipalRef {
            provider_id: "dsp-directory".to_string(),
            issuer: "https://dsp.example.com".to_string(),
            external_id: "missing".to_string(),
        })
        .await
        .unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn resolve_requires_configured_jwt_bearer_auth() {
    let (address, state, _server) = start_server().await;
    let discovery = CustomPrincipalDiscovery::new(&config(&address)).unwrap();
    assert!(discovery
        .resolve_principal(&ExternalPrincipalRef {
            provider_id: "dsp-directory".to_string(),
            issuer: "https://dsp.example.com".to_string(),
            external_id: "dsp-0".to_string(),
        })
        .await
        .is_ok());
    assert_eq!(state.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn configuration_rejects_unsafe_or_incomplete_bindings() {
    let base = config("https://dsp.example.com");
    assert!(CustomPrincipalDiscovery::new(&base).is_ok());

    let mut absolute_path = base.clone();
    absolute_path.request.path = "/api/dsp/search".to_string();
    assert!(matches!(
        CustomPrincipalDiscovery::new(&absolute_path),
        Err(PrincipalDiscoveryError::InvalidConfiguration(_))
    ));

    let mut bad_template = base.clone();
    bad_template.request.body_template = Some("not json".to_string());
    assert!(matches!(
        CustomPrincipalDiscovery::new(&bad_template),
        Err(PrincipalDiscoveryError::InvalidConfiguration(_))
    ));

    let mut bad_array = base.clone();
    bad_array.response.array_path = "items".to_string();
    assert!(matches!(
        CustomPrincipalDiscovery::new(&bad_array),
        Err(PrincipalDiscoveryError::InvalidConfiguration(_))
    ));

    let mut empty_token = base;
    empty_token.jwt_token = " ".to_string();
    assert!(matches!(
        CustomPrincipalDiscovery::new(&empty_token),
        Err(PrincipalDiscoveryError::InvalidConfiguration(_))
    ));
}
