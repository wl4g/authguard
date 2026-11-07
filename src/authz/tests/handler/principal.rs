use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::PrincipalHandler;
use crate::model::{IamPrincipalInfo, PrincipalKind, PrincipalStatus};
use crate::principal::{
    ExternalPrincipalRef, IPrincipalDiscovery, IPrincipalSearchDiscovery, PrincipalDiscoveryError,
    PrincipalMaterializationRequest, PrincipalProjection, PrincipalSearchPage,
    PrincipalSearchQuery,
};
use crate::storage::PrincipalRepository;

/// Minimal search provider for the materialize dispatch regression test:
/// the protocol label and the configured `discovery_id` are different
/// strings, mirroring a production deployment such as the example
/// `discovery_id: corporate-ldap` under protocol `FED_LDAP`.
struct StubProvider;

#[async_trait]
impl IPrincipalDiscovery<PrincipalSearchQuery> for StubProvider {
    type Output = PrincipalSearchPage;

    fn provider(&self) -> &'static str {
        "FED_LDAP"
    }

    fn provider_id(&self) -> &'static str {
        "corporate-ldap"
    }

    async fn discover(
        &self,
        _query: PrincipalSearchQuery,
    ) -> Result<Self::Output, PrincipalDiscoveryError> {
        Ok(PrincipalSearchPage::default())
    }

    async fn resolve_principal(
        &self,
        reference: &ExternalPrincipalRef,
    ) -> Result<Option<PrincipalProjection>, PrincipalDiscoveryError> {
        if reference.provider_id != self.provider_id() {
            return Err(PrincipalDiscoveryError::UnknownProvider(reference.provider_id.clone()));
        }
        Ok(Some(PrincipalProjection {
            reference: reference.clone(),
            kind: PrincipalKind::User,
            display_name: "Jane Doe".to_string(),
            username: Some("jdoe".to_string()),
            email: None,
            enabled: true,
            attributes: BTreeMap::new(),
        }))
    }
}

#[derive(Default)]
struct StubRepository {
    upserted: Mutex<Vec<IamPrincipalInfo>>,
}

#[async_trait]
impl PrincipalRepository for StubRepository {
    async fn upsert(&self, principal: &IamPrincipalInfo) -> anyhow::Result<IamPrincipalInfo> {
        self.upserted.lock().expect("stub lock").push(principal.clone());
        Ok(principal.clone())
    }

    async fn get(&self, _id: &str) -> anyhow::Result<Option<IamPrincipalInfo>> {
        Ok(None)
    }

    async fn find_by_ids(&self, _ids: &[String]) -> anyhow::Result<Vec<IamPrincipalInfo>> {
        Ok(Vec::new())
    }

    async fn list(
        &self,
        _query: &str,
        _after_id: Option<&str>,
        _limit: u32,
    ) -> anyhow::Result<Vec<IamPrincipalInfo>> {
        Ok(Vec::new())
    }

    async fn update_status(
        &self,
        _id: &str,
        _status: PrincipalStatus,
    ) -> anyhow::Result<Option<IamPrincipalInfo>> {
        Ok(None)
    }

    async fn delete(&self, _id: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
}

#[test]
fn principal_projection_identity_key_is_cloneable() {
    let reference = ExternalPrincipalRef {
        provider_id: "FED_KEYCLOAK".to_string(),
        issuer: "https://id.example.com/realms/customer-growth".to_string(),
        external_id: "user-42".to_string(),
    };
    let projection = PrincipalProjection {
        reference,
        kind: PrincipalKind::User,
        display_name: "Alice Analyst".to_string(),
        username: Some("alice".to_string()),
        email: Some("alice@example.com".to_string()),
        enabled: true,
        attributes: BTreeMap::new(),
    };
    assert_eq!(projection.clone().identity_key(), projection.identity_key());
}

/// `materialize` must dispatch on the configured `discovery_id` echoed by
/// search results, not on the protocol label. Search results from a
/// production deployment with `discovery_id: corporate-ldap` carry that
/// id, and materializing them with the protocol string previously failed
/// with `UnknownProvider`.
#[tokio::test]
async fn materialize_dispatches_on_discovery_id_not_protocol() {
    let repository = Arc::new(StubRepository::default());
    let federated = vec![Arc::new(StubProvider) as Arc<dyn IPrincipalSearchDiscovery>];
    let handler = PrincipalHandler::new(repository.clone(), federated, None);
    let reference = ExternalPrincipalRef {
        provider_id: "corporate-ldap".to_string(),
        issuer: "https://ldap.example.com".to_string(),
        external_id: "jdoe".to_string(),
    };
    let request =
        PrincipalMaterializationRequest { principal_id: "principal-jane".to_string(), reference };
    let materialized = handler.materialize(&request).await.expect("materialize");
    assert_eq!(materialized.id, "principal-jane");
    assert!(materialized.authorization_state.is_empty());
    {
        let upserted = repository.upserted.lock().expect("stub lock");
        assert_eq!(upserted.len(), 1);
    }
    assert!(handler
        .materialize(&PrincipalMaterializationRequest {
            principal_id: "principal-jane".to_string(),
            reference: ExternalPrincipalRef {
                provider_id: "FED_LDAP".to_string(),
                ..request.reference
            },
        })
        .await
        .is_err());
}

#[tokio::test]
async fn search_filter_dispatches_on_discovery_id_not_protocol() {
    let repository = Arc::new(StubRepository::default());
    let federated = vec![Arc::new(StubProvider) as Arc<dyn IPrincipalSearchDiscovery>];
    let handler = PrincipalHandler::new(repository, federated, None);
    let mut query = PrincipalSearchQuery::new("jdoe");
    query.provider_ids.insert("corporate-ldap".to_string());
    handler.search(query).await.expect("search by configured discovery id");

    let mut protocol_query = PrincipalSearchQuery::new("jdoe");
    protocol_query.provider_ids.insert("FED_LDAP".to_string());
    assert!(handler.search(protocol_query).await.is_err());
}
