use std::sync::Arc;

use crate::sdk::{
    access::{AccessError, AccessRequest, HeaderAccessContextResolver, IAccessContextResolver},
    model::RequestAccess,
    util::{ACCESS_CONTEXT_HEADER, REQUEST_ID_HEADER, SCOPE_TOKEN_HEADER},
};

#[derive(Clone)]
pub struct AccessFilter {
    resolvers: Vec<Arc<dyn IAccessContextResolver>>,
}

impl std::fmt::Debug for AccessFilter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccessFilter")
            .field("resolver_count", &self.resolvers.len())
            .finish()
    }
}

impl AccessFilter {
    /// Creates a direct-header filter from the standard HMAC-key environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error when the signing key is absent or invalid.
    pub fn trusted_context_only() -> Result<Self, AccessError> {
        Ok(Self::new(vec![Arc::new(HeaderAccessContextResolver::from_env()?)]))
    }

    #[must_use]
    pub fn new(resolvers: Vec<Arc<dyn IAccessContextResolver>>) -> Self {
        Self { resolvers }
    }

    /// Resolves request access through the configured framework-neutral resolver chain.
    ///
    /// # Errors
    ///
    /// Returns an error for conflicting headers, invalid contexts, or failed token resolution.
    pub async fn enter(
        &self,
        request: &(dyn AccessRequest + Send + Sync),
    ) -> Result<AccessScope, AccessError> {
        let direct = request.header(ACCESS_CONTEXT_HEADER).filter(|value| !value.is_empty());
        let token = request.header(SCOPE_TOKEN_HEADER).filter(|value| !value.is_empty());
        let request_id = request.header(REQUEST_ID_HEADER).unwrap_or("none");
        tracing::debug!(
            event = "authguard.access_filter.started",
            request_id,
            direct_context_present = direct.is_some(),
            scope_token_present = token.is_some(),
            resolver_count = self.resolvers.len(),
        );
        if direct.is_some() && token.is_some() {
            tracing::debug!(
                event = "authguard.access_filter.rejected",
                request_id,
                reason = "conflicting_headers",
            );
            return Err(AccessError::InvalidContext(
                "both Authguard context and scope token headers are present".to_string(),
            ));
        }
        for resolver in &self.resolvers {
            match resolver.resolve(request).await {
                Ok(Some(request_access)) => {
                    tracing::debug!(
                        event = "authguard.access_filter.authenticated",
                        request_id,
                        resolver_mode = resolver.mode(),
                        principal_id = %request_access.principal_id,
                        action = %request_access.action,
                        allow_count = request_access.grants.allow_resource_urns.len(),
                        deny_count = request_access.grants.deny_resource_urns.len(),
                    );
                    return Ok(AccessScope::with_access(request_access));
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::debug!(
                        event = "authguard.access_filter.rejected",
                        request_id,
                        resolver_mode = resolver.mode(),
                        reason = "resolver_error",
                        error_category = error.category(),
                    );
                    return Err(error);
                }
            }
        }
        if token.is_some() {
            tracing::debug!(
                event = "authguard.access_filter.rejected",
                request_id,
                reason = "scope_resolver_unavailable",
            );
            return Err(AccessError::Resolver(
                "no resolver is configured for the Authguard scope token".to_string(),
            ));
        }
        tracing::debug!(event = "authguard.access_filter.unauthenticated", request_id);
        Ok(AccessScope::empty())
    }
}

#[derive(Debug, Clone)]
pub struct AccessScope {
    request_access: Option<RequestAccess>,
}

impl AccessScope {
    fn with_access(request_access: RequestAccess) -> Self {
        Self { request_access: Some(request_access) }
    }

    fn empty() -> Self {
        Self { request_access: None }
    }

    #[must_use]
    pub fn authenticated(&self) -> bool {
        self.request_access.is_some()
    }

    #[must_use]
    pub fn request_access(&self) -> Option<&RequestAccess> {
        self.request_access.as_ref()
    }

    #[must_use]
    pub fn grants(&self) -> Option<&crate::sdk::model::AccessGrantSet> {
        self.request_access.as_ref().map(|access| &access.grants)
    }
}

#[derive(Debug, Clone)]
pub struct HttpHeaderAccessFilter {
    access_filter: AccessFilter,
}

impl HttpHeaderAccessFilter {
    /// Creates a direct-header filter from the standard HMAC-key environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error when the signing key is absent or invalid.
    pub fn trusted_context_only() -> Result<Self, AccessError> {
        Ok(Self { access_filter: AccessFilter::trusted_context_only()? })
    }

    #[must_use]
    pub fn new(resolvers: Vec<Arc<dyn IAccessContextResolver>>) -> Self {
        Self { access_filter: AccessFilter::new(resolvers) }
    }

    /// Resolves access from an `http::HeaderMap`.
    ///
    /// # Errors
    ///
    /// Returns an access-context resolution error and never falls back to JWT parsing.
    pub async fn enter_headers(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<AccessScope, AccessError> {
        self.access_filter.enter(&HttpHeaderAccessRequest { headers }).await
    }
}

struct HttpHeaderAccessRequest<'a> {
    headers: &'a http::HeaderMap,
}

impl AccessRequest for HttpHeaderAccessRequest<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }
}
