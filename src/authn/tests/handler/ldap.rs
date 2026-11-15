use super::*;
use crate::authentication::TokenIssuer;
use authguard_common::config::{AuthnProperties, SqliteProperties};
use authguard_common::storage::{AuthnSqliteRepository, IdentityBindingRepository};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt as _;

struct Fixture;
impl Fixture {
    fn directory_config() -> LdapAuthnProperties {
        let mut config = Self::config();
        config.url = std::env::var("AUTHGUARD_TEST_LDAP_URL").unwrap();
        config.allow_insecure = true;
        config.bind_dn = "cn=reader,ou=service,dc=example,dc=com".into();
        config.bind_password = "reader-password".into();
        config.subject_attribute = "uidNumber".into();
        config.user_filter = "(&(objectClass=posixAccount)(cn={login}))".into();
        config
    }
    fn config() -> LdapAuthnProperties {
        LdapAuthnProperties {
            enabled: true,
            url: "ldaps://directory.example".into(),
            issuer: "urn:example:ldap".into(),
            base_dn: "dc=example,dc=com".into(),
            bind_dn: "cn=reader,dc=example,dc=com".into(),
            bind_password: "search-secret".into(),
            ..LdapAuthnProperties::default()
        }
    }
    async fn setup(config: LdapAuthnProperties) -> (LdapHandler, Arc<AuthnSqliteRepository>) {
        let repository = Arc::new(
            AuthnSqliteRepository::connect(&SqliteProperties {
                url: "sqlite::memory:".into(),
                max_connections: 1,
                ..SqliteProperties::default()
            })
            .await
            .unwrap(),
        );
        let mut authn = AuthnProperties { ldap: config.clone(), ..AuthnProperties::default() };
        authn.account_linking.authoritative_providers.insert(config.provider_id.clone());
        authn.token.private_key = include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
            "/../../use-cases/customer-growth-job-service/deploy/authguard/config/jwt-keys/resign-jwt-key.pem")).into();
        let pipeline = AuthenticationPipeline::new(
            authn.account_linking.clone(),
            repository.clone() as Arc<dyn IdentityBindingRepository>,
            TokenIssuer::from_config(&authn).unwrap(),
        );
        (LdapHandler::new(config, Arc::new(pipeline), AuthnMetrics::default()).unwrap(), repository)
    }
    async fn handler(config: LdapAuthnProperties) -> LdapHandler {
        Self::setup(config).await.0
    }
    async fn request(
        handler: LdapHandler,
        login: &str,
        password: &str,
    ) -> axum::response::Response {
        crate::route::ldap::LdapRoutes::router(handler)
            .oneshot(
                Request::post("/auth/ldap/login")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"login":login,"password":password}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
}

#[test]
fn rejects_insecure_or_ambiguous_configuration_without_exposing_passwords() {
    let mut c = Fixture::config();
    assert!(c.validate().is_ok());
    c.url = "ldap://directory.example".into();
    assert!(c.validate().is_err());
    c.start_tls = true;
    assert!(c.validate().is_ok());
    c.bind_password_file = "/tmp/another-secret".into();
    assert!(c.validate().is_err());
    assert!(!format!("{c:?}").contains("search-secret"));
}

#[test]
fn extracts_stable_case_insensitive_and_binary_subjects_without_guessing() {
    let mut entry = SearchEntry {
        dn: "uid=alice,dc=example".into(),
        attrs: std::collections::HashMap::default(),
        bin_attrs: std::collections::HashMap::default(),
    };
    entry.attrs.insert("entryUUID".into(), vec!["immutable-id".into()]);
    assert_eq!(LdapHandler::subject(&entry, "entryuuid"), Some("immutable-id".into()));
    entry.bin_attrs.insert("objectGUID".into(), vec![vec![1, 2, 3, 4]]);
    assert_eq!(LdapHandler::subject(&entry, "OBJECTGUID"), Some("AQIDBA".into()));
    entry.attrs.insert("entryUUID".into(), vec!["one".into(), "two".into()]);
    assert!(LdapHandler::subject(&entry, "entryUUID").is_none());
}

#[tokio::test]
async fn rejects_empty_credentials_before_directory_access() {
    let handler = Fixture::handler(Fixture::config()).await;
    for (login, password) in [("alice", ""), ("", "password"), ("a\0b", "password")] {
        assert_eq!(
            Fixture::request(handler.clone(), login, password).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
#[ignore = "requires disposable AUTHGUARD_TEST_LDAP_URL (glauth example.com fixture)"]
async fn real_directory_password_login_uses_jit_and_never_falls_back_to_local_credentials() {
    let config = Fixture::directory_config();
    let handler = Fixture::handler(config.clone()).await;
    for (login, password) in
        [("alice", "wrong"), ("absent", "alice-password"), ("alice*)(uid=*)", "alice-password")]
    {
        assert_eq!(
            Fixture::request(handler.clone(), login, password).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let response = Fixture::request(handler.clone(), "alice", "alice-password").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("set-cookie").unwrap().to_str().unwrap().contains("HttpOnly"));
    let first: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    let response = Fixture::request(handler, "alice", "alice-password").await;
    assert_eq!(response.status(), StatusCode::OK);
    let second: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(first["principal"]["principalId"], second["principal"]["principalId"]);
    assert_eq!(first["principal"]["kind"], "USER");
    assert_eq!(first["principal"]["amr"], json!(["pwd"]));
    assert!(!first.to_string().contains("alice-password"));

    for (kind, status, expected) in [
        (PrincipalKind::User, crate::PrincipalStatus::Active, StatusCode::OK),
        (PrincipalKind::User, crate::PrincipalStatus::Disabled, StatusCode::FORBIDDEN),
        (PrincipalKind::Workload, crate::PrincipalStatus::Active, StatusCode::UNAUTHORIZED),
    ] {
        let (prepared, repository) = Fixture::setup(config.clone()).await;
        let principal = crate::IamPrincipalInfo {
            id: "P_pre_authorized".into(),
            kind,
            display_name: "Alice".into(),
            status,
            authorization_state: BTreeMap::new(),
        };
        repository
            .create_principal_and_bind(
                &principal,
                &ExternalIdentity {
                    provider: config.provider_id.clone(),
                    issuer: config.issuer.clone(),
                    subject: "1001".into(),
                    claims: BTreeMap::new(),
                },
            )
            .await
            .unwrap();
        let response = Fixture::request(prepared, "alice", "alice-password").await;
        assert_eq!(response.status(), expected);
        if expected == StatusCode::OK {
            let value: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap())
                    .unwrap();
            assert_eq!(value["principal"]["principalId"], "P_pre_authorized");
        }
    }
    let mut ambiguous = config.clone();
    ambiguous.user_filter = "(&(objectClass=posixAccount)(cn=*{login}*))".into();
    assert_eq!(
        Fixture::request(Fixture::handler(ambiguous).await, "a", "alice-password").await.status(),
        StatusCode::UNAUTHORIZED
    );
    let mut missing = config;
    missing.subject_attribute = "nonexistentStableAttribute".into();
    assert_eq!(
        Fixture::request(Fixture::handler(missing).await, "alice", "alice-password").await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
#[ignore = "requires LDAPS fixture and SSL_CERT_FILE pointing to an untrusted/empty CA bundle"]
async fn real_directory_rejects_untrusted_tls() {
    let config = Fixture::directory_config();
    assert!(config.url.starts_with("ldaps://"));
    let response =
        Fixture::request(Fixture::handler(config).await, "alice", "alice-password").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
