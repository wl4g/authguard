//! Principal federation, materialization, and lifecycle handlers.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use tokio::task::JoinSet;

use serde::Serialize;
use thiserror::Error;

use crate::model::{IamPrincipalInfo, PrincipalKind, PrincipalStatus};
use crate::principal::{
    validate_search_query, IPrincipalSearchDiscovery, PrincipalDiscoveryError,
    PrincipalMaterializationRequest, PrincipalProjection, PrincipalSearchPage,
    PrincipalSearchQuery, ScimPrincipalDiscovery, ScimProjectionEvent, ScimProvisioningRequest,
};
use crate::storage::{PrincipalReferenced, PrincipalRepository};
use authguard_common::AuthenticatedPrincipalContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRequestPrincipal {
    pub principal_id: String,
    pub group_principal_ids: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PrincipalHandlerError {
    #[error("principal `{0}` was not found")]
    NotFound(String),
    #[error("principal `{0}` is disabled")]
    Disabled(String),
    #[error("principal `{0}` kind does not match the authenticated context")]
    KindMismatch(String),
    #[error("principal `{0}` is still referenced by a role binding")]
    Referenced(String),
    #[error("principal provider is not configured")]
    ProviderUnavailable,
    #[error("principal discovery failed: {0}")]
    Discovery(#[from] PrincipalDiscoveryError),
    #[error("principal storage unavailable: {0}")]
    Storage(#[source] anyhow::Error),
}

/// Orchestrates principal discovery, durable projection, and status checks.
///
/// External discovery is deliberately kept out of the hot authorization path.
/// Security-sensitive Principal state is read directly from durable storage so
/// disable and delete operations take effect without cache-revocation races.
#[derive(Clone)]
pub struct PrincipalHandler {
    repository: Arc<dyn PrincipalRepository>,
    federated: Vec<Arc<dyn IPrincipalSearchDiscovery>>,
    scim: Option<ScimPrincipalDiscovery>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrincipalPage {
    pub total: usize,
    pub items: Vec<IamPrincipalInfo>,
    pub next_cursor: Option<String>,
}

impl PrincipalHandler {
    #[must_use]
    pub fn new(
        repository: Arc<dyn PrincipalRepository>,
        federated: Vec<Arc<dyn IPrincipalSearchDiscovery>>,
        scim: Option<ScimPrincipalDiscovery>,
    ) -> Self {
        Self { repository, federated, scim }
    }

    /// Validates canonical Principal IDs supplied by `AuthN`.
    ///
    /// # Errors
    ///
    /// Fails closed for missing/disabled Principals or unavailable storage.
    pub async fn resolve_request(
        &self,
        identity: &AuthenticatedPrincipalContext,
    ) -> Result<ResolvedRequestPrincipal, PrincipalHandlerError> {
        let started = Instant::now();
        let mut requested_ids = Vec::with_capacity(identity.stable_group_ids.len() + 1);
        requested_ids.push(identity.principal_id.clone());
        requested_ids.extend(identity.stable_group_ids.iter().cloned());
        let mut projected = self
            .repository
            .find_by_ids(&requested_ids)
            .await
            .map_err(PrincipalHandlerError::Storage)?
            .into_iter()
            .map(|principal| (principal.id.clone(), principal))
            .collect::<BTreeMap<_, _>>();
        tracing::debug!(
            authguard.principal.requested_projection_count = requested_ids.len(),
            authguard.principal.existing_projection_count = projected.len(),
            "loaded canonical request Principals"
        );
        let primary = projected
            .remove(&identity.principal_id)
            .ok_or_else(|| PrincipalHandlerError::NotFound(identity.principal_id.clone()))?;
        if primary.status != PrincipalStatus::Active {
            return Err(PrincipalHandlerError::Disabled(primary.id));
        }
        if primary.kind != identity.kind {
            return Err(PrincipalHandlerError::KindMismatch(primary.id));
        }

        let mut group_principal_ids = Vec::with_capacity(identity.stable_group_ids.len());
        for group_id in &identity.stable_group_ids {
            if let Some(group_principal) = projected.remove(group_id) {
                if group_principal.status == PrincipalStatus::Active
                    && group_principal.kind == PrincipalKind::Group
                {
                    group_principal_ids.push(group_principal.id);
                }
            }
        }
        group_principal_ids.sort();
        group_principal_ids.dedup();
        tracing::debug!(
            authguard.principal_id = %primary.id,
            authguard.principal_kind = primary.kind.as_str(),
            authguard.principal_group_count = group_principal_ids.len(),
            duration_seconds = started.elapsed().as_secs_f64(),
            "request principal resolution completed"
        );
        Ok(ResolvedRequestPrincipal { principal_id: primary.id, group_principal_ids })
    }

    /// Searches configured external identity systems without materializing results.
    ///
    /// # Errors
    ///
    /// Returns a provider configuration, authentication, or transport error.
    pub async fn search(
        &self,
        query: PrincipalSearchQuery,
    ) -> Result<PrincipalSearchPage, PrincipalHandlerError> {
        let started = Instant::now();
        let provider_filter_count = query.provider_ids.len();
        let kind_filter_count = query.kinds.len();
        let requested_page_size = query.per_provider_limit;
        let provider_id = query
            .provider_ids
            .iter()
            .next()
            .filter(|_| query.provider_ids.len() == 1)
            .map_or("federated", String::as_str);
        tracing::info!(
            event = "authguard.authz.principal_discovery.started",
            authguard.principal.provider_id = provider_id,
            authguard.principal.provider_filter_count = provider_filter_count,
            authguard.principal.kind_filter_count = kind_filter_count,
            "federated principal search started"
        );
        validate_search_query(&query).map_err(PrincipalHandlerError::Discovery)?;
        if self.federated.is_empty() {
            return Err(PrincipalHandlerError::ProviderUnavailable);
        }
        let selected = Self::selected_search_providers(&self.federated, &query.provider_ids)
            .map_err(PrincipalHandlerError::Discovery)?;
        let mut tasks = JoinSet::new();
        for provider in selected {
            let query = query.clone();
            let provider_id = provider.provider_id().to_string();
            tasks.spawn(
                async move { provider.discover(query).await.map(|page| (provider_id, page)) },
            );
        }

        let mut pages = BTreeMap::new();
        while let Some(result) = tasks.join_next().await {
            let (protocol, page) = result.map_err(|error| {
                PrincipalHandlerError::Discovery(PrincipalDiscoveryError::Task(error.to_string()))
            })??;
            pages.insert(protocol, page);
        }

        let mut aggregate = PrincipalSearchPage::default();
        for page in pages.into_values() {
            aggregate.principals.extend(page.principals);
            aggregate.next_cursors.extend(page.next_cursors);
        }
        Self::deduplicate_principals(&mut aggregate.principals);
        tracing::info!(
            event = "authguard.authz.principal_discovery.succeeded",
            authguard.principal.discovery = "federation",
            authguard.principal.provider_id = provider_id,
            authguard.principal.provider_filter_count = provider_filter_count,
            authguard.principal.kind_filter_count = kind_filter_count,
            authguard.principal.requested_page_size = requested_page_size,
            authguard.principal.result_count = aggregate.principals.len(),
            authguard.principal.next_cursor_count = aggregate.next_cursors.len(),
            duration_seconds = started.elapsed().as_secs_f64(),
            "federated principal search completed"
        );
        Ok(aggregate)
    }

    /// Re-resolves a selected external candidate and persists its local projection.
    ///
    /// # Errors
    ///
    /// Returns not-found, provider, validation, or storage errors.
    pub async fn materialize(
        &self,
        request: &PrincipalMaterializationRequest,
    ) -> Result<IamPrincipalInfo, PrincipalHandlerError> {
        tracing::info!(
            event = "authguard.authz.principal_materialization.started",
            authguard.principal.provider_id = %request.reference.provider_id,
            authguard.principal_id = %request.principal_id,
            "external principal materialization started"
        );
        let provider = self
            .federated
            .iter()
            .find(|provider| provider.provider_id() == request.reference.provider_id)
            .ok_or_else(|| {
                PrincipalHandlerError::Discovery(PrincipalDiscoveryError::UnknownProvider(
                    request.reference.provider_id.clone(),
                ))
            })?;
        let external = provider.resolve_principal(&request.reference).await?.ok_or_else(|| {
            PrincipalHandlerError::NotFound(request.reference.external_id.clone())
        })?;
        let principal =
            self.upsert_external(&request.principal_id, external, provider.provider()).await?;
        tracing::info!(
            event = "authguard.authz.principal_materialization.succeeded",
            authguard.principal.provider_id = %request.reference.provider_id,
            authguard.principal_id = %principal.id,
            "external principal materialization completed"
        );
        Ok(principal)
    }

    /// Applies one normalized SCIM provisioning event to the local projection.
    ///
    /// SCIM DELETE is represented as a disabled tombstone so existing role
    /// bindings and audit references remain intact.
    ///
    /// # Errors
    ///
    /// Returns validation or storage errors.
    pub async fn apply_scim_projection(
        &self,
        event: ScimProjectionEvent,
    ) -> Result<Option<IamPrincipalInfo>, PrincipalHandlerError> {
        match event {
            ScimProjectionEvent::Upsert { principal_id, projection } => {
                self.upsert_external(&principal_id, projection, "SCIM").await.map(Some)
            }
            ScimProjectionEvent::Delete { principal_id } => {
                let Some(principal) = self.get(&principal_id).await? else {
                    tracing::debug!(
                        authguard.principal.discovery = "SCIM",
                        authguard.principal.operation = "disable",
                        "SCIM deletion referenced an unknown canonical IamPrincipalInfo"
                    );
                    return Ok(None);
                };
                self.update_status(&principal.id, PrincipalStatus::Disabled).await.map(Some)
            }
        }
    }

    /// Normalizes and applies one SCIM provisioning change.
    ///
    /// # Errors
    ///
    /// Returns an error when SCIM is disabled or normalization/persistence fails.
    pub async fn provision_scim(
        &self,
        request: ScimProvisioningRequest,
    ) -> Result<Option<IamPrincipalInfo>, PrincipalHandlerError> {
        let discovery = self.scim.as_ref().ok_or(PrincipalHandlerError::ProviderUnavailable)?;
        let event = discovery.provision(request).await?;
        self.apply_scim_projection(event).await
    }

    /// Loads one locally projected principal.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub async fn get(&self, id: &str) -> Result<Option<IamPrincipalInfo>, PrincipalHandlerError> {
        self.repository.get(id).await.map_err(PrincipalHandlerError::Storage)
    }

    /// Lists locally projected principals using a stable ID cursor.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub async fn list_page(
        &self,
        query: &str,
        after_id: Option<&str>,
        limit: u32,
    ) -> Result<PrincipalPage, PrincipalHandlerError> {
        let limit = limit.clamp(1, 100);
        let items = self
            .repository
            .list(query, after_id, limit)
            .await
            .map_err(PrincipalHandlerError::Storage)?;
        let next_cursor = (items.len() == limit as usize)
            .then(|| items.last().map(|principal| principal.id.clone()))
            .flatten();
        Ok(PrincipalPage { total: items.len(), items, next_cursor })
    }

    /// Updates a local projection status.
    ///
    /// # Errors
    ///
    /// Returns not-found or storage errors.
    pub async fn update_status(
        &self,
        id: &str,
        status: PrincipalStatus,
    ) -> Result<IamPrincipalInfo, PrincipalHandlerError> {
        let updated = self
            .repository
            .update_status(id, status)
            .await
            .map_err(PrincipalHandlerError::Storage)?
            .ok_or_else(|| PrincipalHandlerError::NotFound(id.to_string()))?;
        tracing::info!(
            authguard.principal_id = %updated.id,
            authguard.principal_kind = updated.kind.as_str(),
            authguard.principal_status = updated.status.as_str(),
            "principal projection status updated"
        );
        Ok(updated)
    }

    /// Deletes one unreferenced local projection.
    ///
    /// # Errors
    ///
    /// Returns not-found, reference-conflict, or storage errors.
    pub async fn delete(&self, id: &str) -> Result<(), PrincipalHandlerError> {
        let deleted = self.repository.delete(id).await.map_err(Self::map_storage_error)?;
        if !deleted {
            return Err(PrincipalHandlerError::NotFound(id.to_string()));
        }
        tracing::info!(
            authguard.principal_id = %id,
            "principal projection deleted"
        );
        Ok(())
    }

    /// Selects configured provider instances for a search.
    ///
    /// An empty filter selects all configured providers. An unknown filter
    /// value fails the whole search instead of silently returning nothing.
    fn selected_search_providers(
        providers: &[Arc<dyn IPrincipalSearchDiscovery>],
        filter: &BTreeSet<String>,
    ) -> Result<Vec<Arc<dyn IPrincipalSearchDiscovery>>, PrincipalDiscoveryError> {
        if filter.is_empty() {
            return Ok(providers.to_vec());
        }
        filter
            .iter()
            .map(|provider_id| {
                let mut matching = providers
                    .iter()
                    .filter(|provider| provider.provider_id() == provider_id)
                    .cloned();
                let selected = matching
                    .next()
                    .ok_or_else(|| PrincipalDiscoveryError::UnknownProvider(provider_id.clone()))?;
                if matching.next().is_some() {
                    return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
                        "duplicate search provider id `{provider_id}`"
                    )));
                }
                Ok(selected)
            })
            .collect()
    }

    /// Deduplicates merged results by the stable `(issuer, external_id)` key.
    ///
    /// Cursors are per-provider and are preserved untouched; only principals
    /// from overlapping provider result sets are collapsed.
    fn deduplicate_principals(principals: &mut Vec<PrincipalProjection>) {
        let mut unique = BTreeMap::new();
        for principal in principals.drain(..) {
            let key = (principal.reference.issuer.clone(), principal.reference.external_id.clone());
            unique.entry(key).or_insert(principal);
        }
        principals.extend(unique.into_values());
    }

    async fn upsert_external(
        &self,
        principal_id: &str,
        external: PrincipalProjection,
        discovery: &'static str,
    ) -> Result<IamPrincipalInfo, PrincipalHandlerError> {
        let principal = IamPrincipalInfo {
            id: principal_id.to_string(),
            kind: external.kind,
            display_name: external.display_name,
            status: if external.enabled {
                PrincipalStatus::Active
            } else {
                PrincipalStatus::Disabled
            },
            authorization_state: BTreeMap::new(),
        };
        let projected =
            self.repository.upsert(&principal).await.map_err(PrincipalHandlerError::Storage)?;
        tracing::info!(
            authguard.principal.discovery = discovery,
            authguard.principal_id = %projected.id,
            authguard.principal_kind = projected.kind.as_str(),
            authguard.principal_status = projected.status.as_str(),
            "canonical IamPrincipalInfo materialized"
        );
        Ok(projected)
    }

    fn map_storage_error(error: anyhow::Error) -> PrincipalHandlerError {
        if let Some(conflict) = error.downcast_ref::<PrincipalReferenced>() {
            return PrincipalHandlerError::Referenced(conflict.id.clone());
        }
        PrincipalHandlerError::Storage(error)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::PrincipalHandler;
    use crate::model::{IamPrincipalInfo, PrincipalKind, PrincipalStatus};
    use crate::principal::{
        ExternalPrincipalRef, IPrincipalDiscovery, IPrincipalSearchDiscovery,
        PrincipalDiscoveryError, PrincipalMaterializationRequest, PrincipalProjection,
        PrincipalSearchPage, PrincipalSearchQuery,
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
                return Err(PrincipalDiscoveryError::UnknownProvider(
                    reference.provider_id.clone(),
                ));
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
        let request = PrincipalMaterializationRequest {
            principal_id: "principal-jane".to_string(),
            reference,
        };
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
}
