use std::collections::BTreeMap;

use authguard_authn::config::{PostgresProperties, SqliteProperties};
use authguard_authn::model::{
    ExternalIdentity, IamPrincipalInfo, IamStandaloneCredential, PrincipalKind, PrincipalStatus,
    StandaloneCredentialKind,
};
use authguard_authn::storage::{
    AuthnPostgresRepository, AuthnSqliteRepository, IdentityBindingRepository,
    IdentityRepositoryError, StandaloneCredentialRepository,
};
use serde_json::json;

#[tokio::test]
async fn sqlite_persists_canonical_principal_identity_bindings() {
    let repository = AuthnSqliteRepository::connect(&SqliteProperties {
        url: "sqlite::memory:".to_string(),
        max_connections: 1,
        ..SqliteProperties::default()
    })
    .await
    .expect("initialize SQLite AuthN repository");
    assert_identity_binding_contract(&repository).await;
    assert_standalone_credential_contract(&repository).await;
}

#[tokio::test]
#[ignore = "requires a disposable AUTHGUARD_TEST_POSTGRES_URL database"]
async fn postgres_persists_canonical_principal_identity_bindings() {
    let url = std::env::var("AUTHGUARD_TEST_POSTGRES_URL").expect("test database URL");
    let repository = AuthnPostgresRepository::connect(&PostgresProperties {
        url,
        max_connections: 2,
        ..PostgresProperties::default()
    })
    .await
    .expect("initialize PostgreSQL AuthN repository");
    assert_identity_binding_contract(&repository).await;
    assert_standalone_credential_contract(&repository).await;
}

async fn assert_standalone_credential_contract<R>(repository: &R)
where
    R: IdentityBindingRepository + StandaloneCredentialRepository,
{
    let principal = IamPrincipalInfo {
        id: "principal-standalone-storage-contract".to_string(),
        kind: PrincipalKind::User,
        display_name: "Standalone User".to_string(),
        status: PrincipalStatus::Active,
        authorization_state: BTreeMap::new(),
    };
    let identity = ExternalIdentity {
        provider: "standalone".to_string(),
        issuer: "authguard:standalone".to_string(),
        subject: "local_stable_subject".to_string(),
        claims: BTreeMap::new(),
    };
    repository
        .create_principal_and_bind(&principal, &identity)
        .await
        .expect("persist standalone identity");
    let key = identity.key().expect("standalone key");
    repository
        .create_credential(&IamStandaloneCredential {
            id: "pwd-storage-contract".to_string(),
            identity: key.clone(),
            kind: StandaloneCredentialKind::Password,
            credential_key: Some("alice@example.com".to_string()),
            secret_data: Some("$argon2id$v=19$example".to_string()),
            credential_data: None,
        })
        .await
        .expect("persist password credential");
    let found = repository
        .find_by_key(
            "authguard:standalone",
            StandaloneCredentialKind::Password,
            "alice@example.com",
        )
        .await
        .expect("find password credential")
        .expect("password credential exists");
    assert_eq!(found.external_identity.subject, "local_stable_subject");
    assert_eq!(found.credential.identity, key);

    repository
        .create_credential(&IamStandaloneCredential {
            id: "totp-storage-contract".to_string(),
            identity: key.clone(),
            kind: StandaloneCredentialKind::Totp,
            credential_key: None,
            secret_data: Some("v1:encrypted".to_string()),
            credential_data: Some(json!({"lastCounter": 40})),
        })
        .await
        .expect("persist TOTP credential");
    assert!(repository
        .advance_totp_counter("totp-storage-contract", 41)
        .await
        .expect("advance TOTP counter"));
    assert!(!repository
        .advance_totp_counter("totp-storage-contract", 41)
        .await
        .expect("reject replayed TOTP counter"));
    let totp = repository
        .list_by_identity(&key, StandaloneCredentialKind::Totp)
        .await
        .expect("list TOTP credentials");
    assert_eq!(totp[0].credential_data, Some(json!({"lastCounter": 41})));

    repository
        .create_credential(&IamStandaloneCredential {
            id: "webauthn-storage-contract".to_string(),
            identity: key,
            kind: StandaloneCredentialKind::Webauthn,
            credential_key: Some("credential-id".to_string()),
            secret_data: None,
            credential_data: Some(json!({"cred": {"counter": 1}})),
        })
        .await
        .expect("persist WebAuthn credential");
    assert!(repository
        .compare_and_swap_credential_data(
            "webauthn-storage-contract",
            &json!({"cred": {"counter": 1}}),
            &json!({"cred": {"counter": 3}}),
        )
        .await
        .expect("advance WebAuthn credential state"));
    assert!(!repository
        .compare_and_swap_credential_data(
            "webauthn-storage-contract",
            &json!({"cred": {"counter": 1}}),
            &json!({"cred": {"counter": 2}}),
        )
        .await
        .expect("reject stale WebAuthn credential state"));
}

async fn assert_identity_binding_contract<R>(repository: &R)
where
    R: IdentityBindingRepository,
{
    let principal = IamPrincipalInfo {
        id: "principal-storage-contract".to_string(),
        kind: PrincipalKind::User,
        display_name: "Storage Contract User".to_string(),
        status: PrincipalStatus::Active,
        authorization_state: BTreeMap::from([("department".to_string(), json!("growth"))]),
    };
    let corporate = identity("corporate-dsp", "EMP00123");
    let github = identity("github", "987654");

    assert_eq!(
        repository
            .create_principal_and_bind(&principal, &corporate)
            .await
            .expect("persist Principal and authoritative identity"),
        principal
    );
    assert_eq!(
        repository
            .find_principal_by_identity(&corporate.key().expect("identity key"))
            .await
            .expect("resolve authoritative identity"),
        Some(principal.clone())
    );
    assert!(repository
        .principal_has_provider(&principal.id, "corporate-dsp")
        .await
        .expect("check authoritative provider"));

    assert_eq!(
        repository.bind_identity(&principal.id, &github).await.expect("bind secondary identity"),
        principal
    );
    assert_eq!(
        repository
            .find_principal_by_identity(&github.key().expect("identity key"))
            .await
            .expect("resolve secondary identity"),
        Some(principal.clone())
    );
    assert_eq!(
        repository.bind_identity(&principal.id, &github).await,
        Err(IdentityRepositoryError::IdentityAlreadyBound)
    );
}

fn identity(provider: &str, subject: &str) -> ExternalIdentity {
    ExternalIdentity {
        provider: provider.to_string(),
        issuer: format!("https://{provider}.example"),
        subject: subject.to_string(),
        claims: BTreeMap::from([("username".to_string(), json!(subject))]),
    }
}
