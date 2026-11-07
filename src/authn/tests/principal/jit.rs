use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use super::*;
use crate::model::ExternalIdentityKey;
use async_trait::async_trait;
use chrono::Utc;

#[derive(Default)]
struct MemoryRepository {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    bindings: BTreeMap<ExternalIdentityKey, IamPrincipalInfo>,
    providers: BTreeMap<String, BTreeSet<String>>,
}

#[async_trait]
impl IdentityBindingRepository for MemoryRepository {
    async fn find_principal_by_identity(
        &self,
        identity: &ExternalIdentityKey,
    ) -> Result<Option<IamPrincipalInfo>, IdentityRepositoryError> {
        Ok(self.state.lock().expect("state").bindings.get(identity).cloned())
    }

    async fn create_principal_and_bind(
        &self,
        principal: &IamPrincipalInfo,
        identity: &ExternalIdentity,
    ) -> Result<IamPrincipalInfo, IdentityRepositoryError> {
        let mut state = self.state.lock().expect("state");
        let key =
            identity.key().map_err(|error| IdentityRepositoryError::Backend(error.to_string()))?;
        state.bindings.insert(key, principal.clone());
        state.providers.entry(principal.id.clone()).or_default().insert(identity.provider.clone());
        Ok(principal.clone())
    }

    async fn bind_identity(
        &self,
        principal_id: &str,
        identity: &ExternalIdentity,
    ) -> Result<IamPrincipalInfo, IdentityRepositoryError> {
        let mut state = self.state.lock().expect("state");
        let key =
            identity.key().map_err(|error| IdentityRepositoryError::Backend(error.to_string()))?;
        if state.bindings.contains_key(&key) {
            return Err(IdentityRepositoryError::IdentityAlreadyBound);
        }
        let principal = state
            .bindings
            .values()
            .find(|principal| principal.id == principal_id)
            .cloned()
            .ok_or_else(|| IdentityRepositoryError::Backend("missing principal".into()))?;
        state.bindings.insert(key, principal.clone());
        state.providers.entry(principal.id.clone()).or_default().insert(identity.provider.clone());
        Ok(principal)
    }

    async fn principal_has_provider(
        &self,
        principal_id: &str,
        provider: &str,
    ) -> Result<bool, IdentityRepositoryError> {
        Ok(self
            .state
            .lock()
            .expect("state")
            .providers
            .get(principal_id)
            .is_some_and(|providers| providers.contains(provider)))
    }

    async fn rollback_identity_binding(
        &self,
        principal_id: &str,
        identity: &ExternalIdentityKey,
    ) -> Result<(), IdentityRepositoryError> {
        let mut state = self.state.lock().expect("state");
        if state.bindings.get(identity).is_some_and(|value| value.id == principal_id) {
            state.bindings.remove(identity);
        }
        if !state.bindings.values().any(|value| value.id == principal_id) {
            state.providers.remove(principal_id);
        }
        Ok(())
    }
}

fn identity(provider: &str, subject: &str) -> ExternalIdentity {
    ExternalIdentity {
        provider: provider.to_string(),
        issuer: format!("https://{provider}.example"),
        subject: subject.to_string(),
        claims: BTreeMap::new(),
    }
}

fn authentication(provider: &str, subject: &str) -> AuthenticationResult {
    AuthenticationResult::new(identity(provider, subject), ["test"], None, Utc::now())
}

fn service() -> AccountLinkingService<MemoryRepository> {
    AccountLinkingService::new(
        AccountLinkingProperties {
            strategy: LinkingStrategy::Explicit,
            authoritative_providers: BTreeSet::from(["corporate-dsp".to_string()]),
            allow_link: BTreeMap::from([(
                "corporate-dsp".to_string(),
                BTreeSet::from(["github".to_string(), "wechat".to_string()]),
            )]),
        },
        MemoryRepository::default(),
    )
}

#[tokio::test]
async fn explicit_strategy_rejects_unbound_secondary_login() {
    let service = service();
    let result =
        service.resolve_login(&authentication("github", "987654"), PrincipalKind::User).await;
    assert!(matches!(result, Err(AccountLinkingError::AuthoritativeLoginRequired { .. })));
}

#[tokio::test]
async fn explicit_link_converges_two_identities_on_one_principal() {
    let service = service();
    let corporate = service
        .resolve_login(&authentication("corporate-dsp", "EMP00123"), PrincipalKind::User)
        .await
        .expect("authoritative login");
    let github = service
        .link_identity(&corporate.principal_id, &authentication("github", "987654"))
        .await
        .expect("link GitHub");
    let later_login = service
        .resolve_login(&authentication("github", "987654"), PrincipalKind::User)
        .await
        .expect("GitHub login");

    assert_eq!(github.principal_id, corporate.principal_id);
    assert_eq!(later_login.principal_id, corporate.principal_id);
}

#[tokio::test]
async fn first_login_reuses_one_identity_but_never_merges_providers_by_email() {
    let service = AccountLinkingService::new(
        AccountLinkingProperties {
            strategy: LinkingStrategy::FirstLogin,
            ..AccountLinkingProperties::default()
        },
        MemoryRepository::default(),
    );
    let mut github = authentication("github", "987654");
    github
        .external_identity
        .claims
        .insert("email".to_string(), serde_json::json!("alice@example.com"));
    let mut wechat = authentication("wechat", "openid-123");
    wechat
        .external_identity
        .claims
        .insert("email".to_string(), serde_json::json!("alice@example.com"));

    let first =
        service.resolve_login(&github, PrincipalKind::User).await.expect("first GitHub login");
    let repeated =
        service.resolve_login(&github, PrincipalKind::User).await.expect("repeated GitHub login");
    let other_provider =
        service.resolve_login(&wechat, PrincipalKind::User).await.expect("first WeChat login");

    assert_eq!(repeated.principal_id, first.principal_id);
    assert_ne!(other_provider.principal_id, first.principal_id);
}

#[tokio::test]
async fn linking_preserves_protocol_supplied_authentication_metadata() {
    let service = AccountLinkingService::new(
        AccountLinkingProperties {
            strategy: LinkingStrategy::FirstLogin,
            ..AccountLinkingProperties::default()
        },
        MemoryRepository::default(),
    );
    let authentication = AuthenticationResult::new(
        identity("wallet", "eip155:1:0x0000000000000000000000000000000000000001"),
        ["wallet", "siwx", "eoa"],
        Some("urn:authguard:loa:wallet".to_string()),
        Utc::now(),
    );

    let context =
        service.resolve_login(&authentication, PrincipalKind::User).await.expect("wallet login");

    assert_eq!(context.amr, ["wallet", "siwx", "eoa"]);
    assert_eq!(context.acr.as_deref(), Some("urn:authguard:loa:wallet"));
}
