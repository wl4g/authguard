//! Federated Principal search across protocol-specific identity sources.

mod keycloak;
mod ldap;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::task::JoinSet;

pub use keycloak::KeycloakPrincipalDiscovery;
pub use ldap::LdapPrincipalDiscovery;

use super::{
    ExternalPrincipalRef, IPrincipalDiscovery, IPrincipalResolver, IPrincipalSearchDiscovery,
    PrincipalDiscoveryError, PrincipalProjection, PrincipalSearchPage, PrincipalSearchQuery,
};

/// Bounded concurrent fan-out over configured identity providers.
///
/// Results are deterministically merged by the stable external identity key
/// `(issuer, external_id)`. Providers may expose Keycloak Admin REST, LDAP
/// (RFC 4511), cloud IAM, or an equivalent enterprise identity API.
/// <https://www.rfc-editor.org/rfc/rfc4511.html>
#[derive(Clone)]
pub struct FederatedPrincipalDiscovery {
    sources: Arc<BTreeMap<String, Arc<dyn IPrincipalSearchDiscovery>>>,
}

impl FederatedPrincipalDiscovery {
    /// Builds an aggregate and rejects empty or duplicate provider IDs.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalDiscoveryError::InvalidConfiguration`] for invalid
    /// provider composition.
    pub fn new(
        sources: impl IntoIterator<Item = Arc<dyn IPrincipalSearchDiscovery>>,
    ) -> Result<Self, PrincipalDiscoveryError> {
        let mut by_id = BTreeMap::new();
        for source in sources {
            let id = IPrincipalDiscovery::id(source.as_ref()).trim().to_owned();
            if id.is_empty() || id != IPrincipalDiscovery::id(source.as_ref()) {
                return Err(PrincipalDiscoveryError::InvalidConfiguration(
                    "provider id must be non-empty and have no surrounding whitespace".to_string(),
                ));
            }
            if by_id.insert(id.clone(), source).is_some() {
                return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
                    "duplicate provider id `{id}`"
                )));
            }
        }
        if by_id.is_empty() {
            return Err(PrincipalDiscoveryError::InvalidConfiguration(
                "at least one principal provider is required".to_string(),
            ));
        }
        Ok(Self { sources: Arc::new(by_id) })
    }

    #[must_use]
    pub fn provider_ids(&self) -> BTreeSet<String> {
        self.sources.keys().cloned().collect()
    }

    fn validate_query(query: &PrincipalSearchQuery) -> Result<(), PrincipalDiscoveryError> {
        if query.text.trim().is_empty() {
            return Err(PrincipalDiscoveryError::InvalidQuery(
                "search text must not be empty".to_string(),
            ));
        }
        if query.text.len() > PrincipalSearchQuery::MAX_TEXT_BYTES {
            return Err(PrincipalDiscoveryError::InvalidQuery(format!(
                "search text must not exceed {} bytes",
                PrincipalSearchQuery::MAX_TEXT_BYTES
            )));
        }
        if !(1..=PrincipalSearchQuery::MAX_PAGE_SIZE).contains(&query.per_provider_limit) {
            return Err(PrincipalDiscoveryError::InvalidQuery(format!(
                "per_provider_limit must be between 1 and {}",
                PrincipalSearchQuery::MAX_PAGE_SIZE
            )));
        }
        Ok(())
    }

    fn selected_sources(
        &self,
        ids: &BTreeSet<String>,
    ) -> Result<Vec<Arc<dyn IPrincipalSearchDiscovery>>, PrincipalDiscoveryError> {
        if ids.is_empty() {
            return Ok(self.sources.values().cloned().collect());
        }
        ids.iter()
            .map(|id| {
                self.sources
                    .get(id)
                    .cloned()
                    .ok_or_else(|| PrincipalDiscoveryError::UnknownProvider(id.clone()))
            })
            .collect()
    }
}

#[async_trait]
impl IPrincipalDiscovery<PrincipalSearchQuery> for FederatedPrincipalDiscovery {
    type Output = PrincipalSearchPage;

    fn id(&self) -> &'static str {
        "federated"
    }

    async fn discover(
        &self,
        query: PrincipalSearchQuery,
    ) -> Result<Self::Output, PrincipalDiscoveryError> {
        Self::validate_query(&query)?;
        let selected = self.selected_sources(&query.provider_ids)?;
        let mut tasks = JoinSet::new();
        for provider in selected {
            let query = query.clone();
            let id = IPrincipalDiscovery::id(provider.as_ref()).to_string();
            tasks.spawn(async move { provider.discover(query).await.map(|page| (id, page)) });
        }

        let mut pages = BTreeMap::new();
        while let Some(result) = tasks.join_next().await {
            let (id, page) =
                result.map_err(|error| PrincipalDiscoveryError::Task(error.to_string()))??;
            pages.insert(id, page);
        }

        let mut aggregate = PrincipalSearchPage::default();
        for page in pages.into_values() {
            aggregate.principals.extend(page.principals);
            aggregate.next_cursors.extend(page.next_cursors);
        }

        let mut unique = BTreeMap::new();
        for principal in aggregate.principals {
            unique
                .entry((
                    principal.reference.issuer.clone(),
                    principal.reference.external_id.clone(),
                ))
                .or_insert(principal);
        }
        aggregate.principals = unique.into_values().collect();
        Ok(aggregate)
    }
}

#[async_trait]
impl IPrincipalResolver for FederatedPrincipalDiscovery {
    async fn resolve_principal(
        &self,
        reference: &ExternalPrincipalRef,
    ) -> Result<Option<PrincipalProjection>, PrincipalDiscoveryError> {
        self.sources
            .get(&reference.provider_id)
            .ok_or_else(|| PrincipalDiscoveryError::UnknownProvider(reference.provider_id.clone()))?
            .resolve_principal(reference)
            .await
    }
}
