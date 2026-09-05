use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use tokio::task::JoinSet;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::model::{Principal, PrincipalKind, PrincipalStatus};
use crate::principal::{
    validate_search_query, ExternalPrincipal, ExternalPrincipalRef, IPrincipalDiscovery,
    JitPrincipalDiscovery, PrincipalDiscoveryError, PrincipalProjection, PrincipalSearchDiscovery,
    PrincipalSearchPage, PrincipalSearchQuery, ScimPrincipalDiscovery, ScimProjectionEvent,
    ScimRefreshRequest, VerifiedOidcPrincipal,
};
use crate::storage::{PrincipalReferenced, PrincipalRepository};
use crate::utils::RequestIdentity;

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
/// External discovery is deliberately kept out of the hot authorization path
/// except for the bounded JIT projection of an already verified OIDC identity.
/// Security-sensitive Principal state is read directly from durable storage so
/// disable and delete operations take effect without cache-revocation races.
#[derive(Clone)]
pub struct PrincipalHandler {
    repository: Arc<dyn PrincipalRepository>,
    jit: Option<JitPrincipalDiscovery>,
    federated: Vec<Arc<PrincipalSearchDiscovery>>,
    scim: Option<ScimPrincipalDiscovery>,
}

impl PrincipalHandler {
    #[must_use]
    pub fn new(
        repository: Arc<dyn PrincipalRepository>,
        jit: Option<JitPrincipalDiscovery>,
        federated: Vec<Arc<PrincipalSearchDiscovery>>,
        scim: Option<ScimPrincipalDiscovery>,
    ) -> Self {
        Self { repository, jit, federated, scim }
    }

    /// Resolves an already authenticated request identity to local Principal IDs.
    ///
    /// # Errors
    ///
    /// Fails closed for disabled principals, unavailable storage, untrusted JIT
    /// issuers, or identities that cannot be projected.
    pub async fn resolve_request(
        &self,
        identity: &RequestIdentity,
    ) -> Result<ResolvedRequestPrincipal, PrincipalHandlerError> {
        let started = Instant::now();
        let group_external_ids = identity
            .group_external_ids
            .iter()
            .map(|group| (Self::namespaced_group_external_id(group), group.as_str()))
            .collect::<BTreeMap<_, _>>();
        let mut requested_external_ids = Vec::with_capacity(group_external_ids.len() + 1);
        requested_external_ids.push(identity.external_id.clone());
        requested_external_ids.extend(group_external_ids.keys().cloned());
        let mut projected = self
            .repository
            .find_by_external_keys(&identity.issuer, &requested_external_ids)
            .await
            .map_err(PrincipalHandlerError::Storage)?
            .into_iter()
            .map(|principal| (principal.external_id.clone(), principal))
            .collect::<BTreeMap<_, _>>();
        tracing::debug!(
            authguard.identity.issuer = %identity.issuer,
            authguard.principal.requested_projection_count = requested_external_ids.len(),
            authguard.principal.existing_projection_count = projected.len(),
            "loaded request principal projections"
        );
        let primary = self
            .resolve_or_project(
                Self::verified_principal(identity, Self::request_principal_kind(identity), None),
                projected.remove(&identity.external_id),
            )
            .await?;
        if primary.status != PrincipalStatus::Active {
            return Err(PrincipalHandlerError::Disabled(primary.id));
        }

        let mut group_principal_ids = Vec::with_capacity(group_external_ids.len());
        for (external_id, group) in group_external_ids {
            let Some(group_principal) = self
                .resolve_optional_group(
                    Self::verified_principal(
                        identity,
                        PrincipalKind::Group,
                        Some((&external_id, group)),
                    ),
                    projected.remove(&external_id),
                )
                .await?
            else {
                continue;
            };
            if group_principal.status == PrincipalStatus::Active {
                group_principal_ids.push(group_principal.id);
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
        validate_search_query(&query).map_err(PrincipalHandlerError::Discovery)?;
        if self.federated.is_empty() {
            return Err(PrincipalHandlerError::ProviderUnavailable);
        }
        let selected = Self::selected_search_providers(&self.federated, &query.provider_ids)
            .map_err(PrincipalHandlerError::Discovery)?;
        let mut tasks = JoinSet::new();
        for provider in selected {
            let query = query.clone();
            let protocol = provider.provider();
            tasks.spawn(async move { provider.discover(query).await.map(|page| (protocol, page)) });
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
            authguard.principal.discovery = "federation",
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
        reference: &ExternalPrincipalRef,
    ) -> Result<Principal, PrincipalHandlerError> {
        let provider = self
            .federated
            .iter()
            .find(|provider| provider.provider_id() == reference.provider_id)
            .ok_or_else(|| {
                PrincipalHandlerError::Discovery(PrincipalDiscoveryError::UnknownProvider(
                    reference.provider_id.clone(),
                ))
            })?;
        let external = provider
            .resolve_principal(reference)
            .await?
            .ok_or_else(|| PrincipalHandlerError::NotFound(reference.external_id.clone()))?;
        self.upsert_external(external, provider.provider()).await
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
    ) -> Result<Option<Principal>, PrincipalHandlerError> {
        match event {
            ScimProjectionEvent::Upsert(external) => {
                self.upsert_external(external, "SCIM").await.map(Some)
            }
            ScimProjectionEvent::Delete(reference) => {
                let Some(principal) =
                    self.find_external(&reference.issuer, &reference.external_id).await?
                else {
                    tracing::debug!(
                        authguard.principal.discovery = "SCIM",
                        authguard.principal.operation = "disable",
                        "SCIM deletion referenced an unknown principal projection"
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
    pub async fn refresh_scim(
        &self,
        request: ScimRefreshRequest,
    ) -> Result<Option<Principal>, PrincipalHandlerError> {
        let discovery = self.scim.as_ref().ok_or(PrincipalHandlerError::ProviderUnavailable)?;
        let event = discovery.refresh(request).await?;
        self.apply_scim_projection(event).await
    }

    /// Loads one locally projected principal.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub async fn get(&self, id: &str) -> Result<Option<Principal>, PrincipalHandlerError> {
        self.repository.get(id).await.map_err(PrincipalHandlerError::Storage)
    }

    /// Lists locally projected principals using a stable ID cursor.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub async fn list(
        &self,
        query: &str,
        after_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<Principal>, PrincipalHandlerError> {
        self.repository.list(query, after_id, limit).await.map_err(PrincipalHandlerError::Storage)
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
    ) -> Result<Principal, PrincipalHandlerError> {
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

    /// Selects providers for a search, enforcing the duplicate-protocol rule.
    ///
    /// An empty filter selects all configured providers. An unknown filter
    /// value fails the whole search instead of silently returning nothing.
    fn selected_search_providers(
        providers: &[Arc<PrincipalSearchDiscovery>],
        filter: &BTreeSet<String>,
    ) -> Result<Vec<Arc<PrincipalSearchDiscovery>>, PrincipalDiscoveryError> {
        if filter.is_empty() {
            return Ok(providers.to_vec());
        }
        filter
            .iter()
            .map(|protocol| {
                let mut matching =
                    providers.iter().filter(|provider| provider.provider() == protocol).cloned();
                let selected = matching
                    .next()
                    .ok_or_else(|| PrincipalDiscoveryError::UnknownProvider(protocol.clone()))?;
                if matching.next().is_some() {
                    return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
                        "duplicate search provider protocol `{protocol}`"
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

    async fn resolve_or_project(
        &self,
        verified: VerifiedOidcPrincipal,
        projected: Option<Principal>,
    ) -> Result<Principal, PrincipalHandlerError> {
        if let Some(principal) = projected {
            return Ok(principal);
        }
        let projector = self.jit.as_ref().ok_or(PrincipalHandlerError::ProviderUnavailable)?;
        let external = projector.discover(verified).await?;
        self.upsert_external(external, "JIT").await
    }

    async fn resolve_optional_group(
        &self,
        verified: VerifiedOidcPrincipal,
        projected: Option<Principal>,
    ) -> Result<Option<Principal>, PrincipalHandlerError> {
        if let Some(principal) = projected {
            return Ok(Some(principal));
        }
        let Some(discovery) = self.jit.as_ref() else {
            // Unprojected groups cannot have a local role binding, so ignoring
            // them is both safe and necessary when JIT projection is disabled.
            return Ok(None);
        };
        let external = discovery.discover(verified).await?;
        self.upsert_external(external, "JIT").await.map(Some)
    }

    async fn find_external(
        &self,
        issuer: &str,
        external_id: &str,
    ) -> Result<Option<Principal>, PrincipalHandlerError> {
        self.repository
            .find_by_external_key(issuer, external_id)
            .await
            .map_err(PrincipalHandlerError::Storage)
    }

    async fn upsert_external(
        &self,
        external: ExternalPrincipal,
        discovery: &'static str,
    ) -> Result<Principal, PrincipalHandlerError> {
        let mut attributes = external.attributes;
        attributes.insert(
            "provider_id".to_string(),
            serde_json::Value::String(external.reference.provider_id),
        );
        if let Some(username) = external.username {
            attributes.insert("username".to_string(), serde_json::Value::String(username));
        }
        if let Some(email) = external.email {
            attributes.insert("email".to_string(), serde_json::Value::String(email));
        }
        let principal = Principal {
            id: Self::stable_principal_id(
                &external.reference.issuer,
                &external.reference.external_id,
            ),
            issuer: external.reference.issuer,
            external_id: external.reference.external_id,
            kind: external.kind,
            display_name: external.display_name,
            status: if external.enabled {
                PrincipalStatus::Active
            } else {
                PrincipalStatus::Disabled
            },
            attributes,
        };
        let projected =
            self.repository.upsert(&principal).await.map_err(PrincipalHandlerError::Storage)?;
        tracing::info!(
            authguard.principal.discovery = discovery,
            authguard.principal_id = %projected.id,
            authguard.principal_kind = projected.kind.as_str(),
            authguard.principal_status = projected.status.as_str(),
            authguard.identity.issuer = %projected.issuer,
            "principal projection persisted"
        );
        Ok(projected)
    }

    fn verified_principal(
        identity: &RequestIdentity,
        kind: PrincipalKind,
        group: Option<(&str, &str)>,
    ) -> VerifiedOidcPrincipal {
        let (subject, display_name) = group.map_or_else(
            || {
                let display = identity
                    .claims
                    .get("name")
                    .or_else(|| identity.claims.get("preferred_username"))
                    .cloned();
                (identity.external_id.clone(), display)
            },
            |(external_id, name)| (external_id.to_string(), Some(name.to_string())),
        );
        VerifiedOidcPrincipal {
            issuer: identity.issuer.clone(),
            subject,
            kind,
            display_name,
            username: identity.claims.get("preferred_username").cloned(),
            email: identity.claims.get("email").cloned(),
            enabled: true,
            attributes: identity
                .claims
                .iter()
                .map(|(name, value)| (name.clone(), serde_json::Value::String(value.clone())))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    fn request_principal_kind(identity: &RequestIdentity) -> PrincipalKind {
        match identity.claims.get("principal_type").map(String::as_str) {
            Some("WORKLOAD" | "workload" | "SERVICE_ACCOUNT" | "service_account") => {
                PrincipalKind::Workload
            }
            _ => PrincipalKind::User,
        }
    }

    fn namespaced_group_external_id(group: &str) -> String {
        group
            .strip_prefix("group:")
            .map_or_else(|| format!("group:{group}"), |id| format!("group:{id}"))
    }

    fn stable_principal_id(issuer: &str, external_id: &str) -> String {
        let mut digest = Sha256::new();
        digest.update(issuer.as_bytes());
        digest.update([0]);
        digest.update(external_id.as_bytes());
        format!("principal-{:x}", digest.finalize())
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
    use crate::model::{Principal, PrincipalKind, PrincipalStatus};
    use crate::principal::{
        ExternalPrincipalRef, IPrincipalDiscovery, PrincipalDiscoveryError, PrincipalProjection,
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
        upserted: Mutex<Vec<Principal>>,
    }

    #[async_trait]
    impl PrincipalRepository for StubRepository {
        async fn upsert(&self, principal: &Principal) -> anyhow::Result<Principal> {
            self.upserted.lock().expect("stub lock").push(principal.clone());
            Ok(principal.clone())
        }

        async fn get(&self, _id: &str) -> anyhow::Result<Option<Principal>> {
            Ok(None)
        }

        async fn find_by_external_key(
            &self,
            _issuer: &str,
            _external_id: &str,
        ) -> anyhow::Result<Option<Principal>> {
            Ok(None)
        }

        async fn find_by_external_keys(
            &self,
            _issuer: &str,
            _external_ids: &[String],
        ) -> anyhow::Result<Vec<Principal>> {
            Ok(Vec::new())
        }

        async fn list(
            &self,
            _query: &str,
            _after_id: Option<&str>,
            _limit: u32,
        ) -> anyhow::Result<Vec<Principal>> {
            Ok(Vec::new())
        }

        async fn update_status(
            &self,
            _id: &str,
            _status: PrincipalStatus,
        ) -> anyhow::Result<Option<Principal>> {
            Ok(None)
        }

        async fn delete(&self, _id: &str) -> anyhow::Result<bool> {
            Ok(false)
        }
    }

    #[test]
    fn stable_ids_are_issuer_scoped() {
        let first = PrincipalHandler::stable_principal_id("https://id.example/realm-a", "user-1");
        assert_eq!(
            first,
            PrincipalHandler::stable_principal_id("https://id.example/realm-a", "user-1",)
        );
        assert_ne!(
            first,
            PrincipalHandler::stable_principal_id("https://id.example/realm-b", "user-1",)
        );
    }

    #[test]
    fn group_external_ids_use_a_separate_namespace() {
        assert_eq!(PrincipalHandler::namespaced_group_external_id("analysts"), "group:analysts");
        assert_eq!(
            PrincipalHandler::namespaced_group_external_id("group:analysts"),
            "group:analysts"
        );
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
        let federated = vec![Arc::new(StubProvider)
            as Arc<dyn IPrincipalDiscovery<PrincipalSearchQuery, Output = PrincipalSearchPage>>];
        let handler = PrincipalHandler::new(repository.clone(), None, federated, None);
        let reference = ExternalPrincipalRef {
            provider_id: "corporate-ldap".to_string(),
            issuer: "https://ldap.example.com".to_string(),
            external_id: "jdoe".to_string(),
        };
        let materialized = handler.materialize(&reference).await.expect("materialize");
        assert_eq!(materialized.external_id, "jdoe");
        assert_eq!(materialized.attributes["provider_id"], "corporate-ldap");
        {
            let upserted = repository.upserted.lock().expect("stub lock");
            assert_eq!(upserted.len(), 1);
        }
        assert!(handler
            .materialize(&ExternalPrincipalRef { provider_id: "FED_LDAP".to_string(), ..reference })
            .await
            .is_err());
    }
}
