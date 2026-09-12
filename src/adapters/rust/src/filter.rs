use std::sync::Arc;

use crate::{
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
    pub fn grants(&self) -> Option<&crate::model::AccessGrantSet> {
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

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    use async_trait::async_trait;

    use super::{AccessFilter, HttpHeaderAccessFilter};
    use crate::{
        access::{
            AccessError, AccessRequest, GrpcAccessContextResolver, GrpcScopeTokenClient,
            HeaderAccessContextResolver, ScopeTokenClient, GRPC_TARGET_ENV, GRPC_TLS_ENV,
        },
        model::AccessContext,
        util::{self, ACCESS_CONTEXT_HEADER, SCOPE_TOKEN_HEADER},
    };

    const TEST_SIGNING_KEY: &[u8] = b"test-access-context-hmac-key-32-bytes-minimum";

    struct StaticScopeClient {
        encoded: String,
        called: Arc<AtomicBool>,
        fail: bool,
    }

    #[async_trait]
    impl ScopeTokenClient for StaticScopeClient {
        async fn resolve_scope(&self, token: &str) -> Result<String, AccessError> {
            self.called.store(true, Ordering::SeqCst);
            if self.fail {
                return Err(AccessError::Resolver("scope service unavailable".to_string()));
            }
            assert_eq!(token, "ags_scope");
            Ok(self.encoded.clone())
        }
    }

    #[tokio::test]
    async fn header_context_resolver_sets_request_access() {
        let scope = direct_filter().enter(&headers(Some(signed_context()), None)).await.unwrap();
        assert_authenticated(&scope);
    }

    #[tokio::test]
    async fn grpc_context_resolver_resolves_opaque_token() {
        let resolver = token_resolver(encoded_context(), false).0;
        let scope = AccessFilter::new(vec![Arc::new(resolver)])
            .enter(&headers(None, Some("ags_scope".to_string())))
            .await
            .unwrap();
        assert_authenticated(&scope);
    }

    #[tokio::test]
    async fn missing_access_headers_remain_unauthenticated() {
        let scope = direct_filter().enter(&headers(None, None)).await.unwrap();
        assert!(!scope.authenticated());
    }

    #[tokio::test]
    async fn malformed_direct_context_fails_closed() {
        assert!(direct_filter()
            .enter(&headers(Some("not-base64!".to_string()), None))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn unsupported_direct_context_version_fails_closed() {
        let mut context = test_context();
        context.version = 1;
        assert!(direct_filter()
            .enter(&headers(Some(sign_encoded_context(&context)), None))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn expired_direct_context_fails_closed() {
        let mut context = test_context();
        context.issued_at_epoch_seconds = 1;
        context.expires_at_epoch_seconds = 2;
        assert!(direct_filter()
            .enter(&headers(Some(sign_encoded_context(&context)), None))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn conflicting_context_and_token_headers_fail_closed() {
        assert!(direct_filter()
            .enter(&headers(Some(signed_context()), Some("ags_scope".to_string())))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn scope_resolver_failure_fails_closed() {
        let resolver = token_resolver(encoded_context(), true).0;
        assert!(AccessFilter::new(vec![Arc::new(resolver)])
            .enter(&headers(None, Some("ags_scope".to_string())))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn scope_token_without_request_resolver_fails_closed() {
        assert!(direct_filter()
            .enter(&headers(None, Some("ags_scope".to_string())))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn malformed_resolved_context_fails_closed() {
        let resolver = token_resolver("not-base64!".to_string(), false).0;
        assert!(AccessFilter::new(vec![Arc::new(resolver)])
            .enter(&headers(None, Some("ags_scope".to_string())))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn direct_context_does_not_call_scope_service() {
        let (resolver, called) = token_resolver(encoded_context(), false);
        let scope = AccessFilter::new(vec![Arc::new(direct_resolver()), Arc::new(resolver)])
            .enter(&headers(Some(signed_context()), None))
            .await
            .unwrap();
        assert_authenticated(&scope);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn second_entry_does_not_reuse_previous_request_access() {
        let filter = direct_filter();
        assert!(filter
            .enter(&headers(Some(signed_context()), None))
            .await
            .unwrap()
            .authenticated());
        assert!(!filter.enter(&headers(None, None)).await.unwrap().authenticated());
    }

    #[tokio::test]
    async fn framework_adapter_scopes_direct_context_to_request() {
        let mut headers = http::HeaderMap::new();
        headers.insert(ACCESS_CONTEXT_HEADER, signed_context().parse().unwrap());
        let scope = direct_http_filter().enter_headers(&headers).await.unwrap();
        assert_authenticated(&scope);
    }

    #[tokio::test]
    async fn framework_adapter_rejects_missing_access_context() {
        let scope = direct_http_filter().enter_headers(&http::HeaderMap::new()).await.unwrap();
        assert!(!scope.authenticated());
    }

    #[tokio::test]
    async fn framework_adapter_resolves_scope_token() {
        let resolver = token_resolver(encoded_context(), false).0;
        let filter = HttpHeaderAccessFilter::new(vec![Arc::new(resolver)]);
        let mut headers = http::HeaderMap::new();
        headers.insert(SCOPE_TOKEN_HEADER, "ags_scope".parse().unwrap());
        let scope = filter.enter_headers(&headers).await.unwrap();
        assert_authenticated(&scope);
    }

    #[test]
    fn grpc_target_configuration_uses_standard_environment_names() {
        assert_eq!(GRPC_TARGET_ENV, "AUTHGUARD_GRPC_TARGET");
        assert_eq!(GRPC_TLS_ENV, "AUTHGUARD_GRPC_TLS");
    }

    #[tokio::test]
    async fn grpc_client_accepts_explicit_internal_target_without_connecting() {
        GrpcScopeTokenClient::new("authguard.authguard.svc.cluster.local:8080", false).unwrap();
    }

    #[tokio::test]
    async fn grpc_client_initializes_from_environment_without_connecting() {
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        let previous_target = std::env::var_os(GRPC_TARGET_ENV);
        let previous_tls = std::env::var_os(GRPC_TLS_ENV);
        std::env::set_var(GRPC_TARGET_ENV, "authguard.internal:8080");
        std::env::set_var(GRPC_TLS_ENV, "false");

        let client = GrpcScopeTokenClient::from_env();

        restore_environment(GRPC_TARGET_ENV, previous_target);
        restore_environment(GRPC_TLS_ENV, previous_tls);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn unsigned_direct_context_fails_closed() {
        assert!(direct_filter().enter(&headers(Some(encoded_context()), None)).await.is_err());
    }

    #[tokio::test]
    async fn tampered_direct_context_fails_closed() {
        let signed = signed_context();
        let tampered = signed.replacen("agctx1.", "agctx1.A", 1);
        assert!(direct_filter().enter(&headers(Some(tampered), None)).await.is_err());
    }

    #[tokio::test]
    async fn direct_context_signed_with_different_key_fails_closed() {
        let other = util::sign_access_context(
            &test_context(),
            b"different-access-context-hmac-key-32-bytes-minimum",
        )
        .unwrap();
        assert!(direct_filter().enter(&headers(Some(other), None)).await.is_err());
    }

    #[test]
    fn signing_key_configuration_uses_standard_environment_name() {
        assert_eq!(crate::access::ACCESS_CONTEXT_HMAC_KEY_ENV, "AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY");
    }

    fn restore_environment(name: &str, value: Option<std::ffi::OsString>) {
        if let Some(value) = value {
            std::env::set_var(name, value);
        } else {
            std::env::remove_var(name);
        }
    }

    fn headers(direct: Option<String>, token: Option<String>) -> TestHeaders {
        TestHeaders { direct, token }
    }

    struct TestHeaders {
        direct: Option<String>,
        token: Option<String>,
    }

    impl AccessRequest for TestHeaders {
        fn header(&self, name: &str) -> Option<&str> {
            match name {
                ACCESS_CONTEXT_HEADER => self.direct.as_deref(),
                SCOPE_TOKEN_HEADER => self.token.as_deref(),
                _ => None,
            }
        }
    }

    fn token_resolver(encoded: String, fail: bool) -> (GrpcAccessContextResolver, Arc<AtomicBool>) {
        let called = Arc::new(AtomicBool::new(false));
        let client = StaticScopeClient { encoded, called: Arc::clone(&called), fail };
        (GrpcAccessContextResolver::new(Arc::new(client)), called)
    }

    fn assert_authenticated(scope: &super::AccessScope) {
        assert!(scope.authenticated());
        assert_eq!(scope.request_access().unwrap().principal_id, "revenue-analyst");
        assert_eq!(scope.request_access().unwrap().action, "customer-growth.job.read");
    }

    fn encoded_context() -> String {
        util::encode_access_context(&test_context()).unwrap()
    }

    fn signed_context() -> String {
        util::sign_access_context(&test_context(), TEST_SIGNING_KEY).unwrap()
    }

    fn sign_encoded_context(context: &AccessContext) -> String {
        let encoded = context.encode().unwrap();
        authguard_common::AccessContextSigner::new(TEST_SIGNING_KEY)
            .unwrap()
            .sign_encoded(&encoded)
            .unwrap()
    }

    fn direct_resolver() -> HeaderAccessContextResolver {
        HeaderAccessContextResolver::new(TEST_SIGNING_KEY).unwrap()
    }

    fn direct_filter() -> AccessFilter {
        AccessFilter::new(vec![Arc::new(direct_resolver())])
    }

    fn direct_http_filter() -> HttpHeaderAccessFilter {
        HttpHeaderAccessFilter::new(vec![Arc::new(direct_resolver())])
    }

    fn test_context() -> AccessContext {
        AccessContext::new(
            crate::model::AccessContextInput {
                principal_id: "revenue-analyst".to_string(),
                action: "customer-growth.job.read".to_string(),
                resource_urn: "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score".to_string(),
                allow_resource_urns: vec!["urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*".to_string()],
                deny_resource_urns: vec!["urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit".to_string()],
                policy_revision: 1,
            },
            authguard_common::epoch_seconds(),
            std::time::Duration::from_secs(30),
        )
    }
}
