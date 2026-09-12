use std::collections::BTreeMap;

use authguard_authn::config::{PostgresProperties, SqliteProperties};
use authguard_authn::model::{ExternalIdentity, IamPrincipalInfo, PrincipalKind, PrincipalStatus};
use authguard_authn::storage::{
    AuthnPostgresRepository, AuthnSqliteRepository, IdentityBindingRepository,
    IdentityRepositoryError,
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
