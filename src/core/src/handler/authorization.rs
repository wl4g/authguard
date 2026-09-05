use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use envoy_types::ext_authz::v3::pb::{
    Authorization, CheckRequest, CheckResponse, HeaderAppendAction, HttpStatusCode,
};
use envoy_types::ext_authz::v3::{
    CheckResponseExt as _, DeniedHttpResponseBuilder, OkHttpResponseBuilder,
};
use opentelemetry::global;
use opentelemetry::propagation::{Extractor, TextMapPropagator};
use opentelemetry::Context;
use opentelemetry_http::HeaderExtractor;
use rand::RngCore as _;
use serde_json::json;
use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

use super::{PolicyHandler, PrincipalHandler, PrincipalHandlerError};
use crate::apm::MetricsRegistry;
use crate::cache::IAuthorizationCache;
use crate::config::{IdentityConfig, ScopeDeliveryConfig};
use crate::model::access_context_v1::access_context_service_server::AccessContextService;
use crate::model::{
    epoch_seconds, AccessContext, AccessContextInput, AccessContextSigner, BusinessTokenSigner,
    ACCESS_CONTEXT_HEADER, SCOPE_TOKEN_HEADER,
};
use crate::model::{
    AuthorizationConditions, AuthorizationDecision, AuthorizationRequest, AuthorizationScope,
    Effect, EvaluationContext, Role, UrnPattern,
};
use crate::utils::{HttpMappingError, IdentityError, RequestIdentity, ResolvedHttpRoute};

const CHECK_ROUTE: &str = "envoy.service.auth.v3.Authorization/Check";
const RESOLVE_SCOPE_ROUTE: &str = "authguard.access.v1.AccessContextService/ResolveScope";
const SCOPE_TOKEN_PREFIX: &str = "ags_";
const SCOPE_TOKEN_BYTES: usize = 32;
const MAX_REQUEST_ID_BYTES: usize = 128;
const LEGACY_ACCESS_HEADERS: [&str; 3] =
    ["x-authguard-subject-id", "x-authguard-action", "x-authguard-resource-urn"];
const UNTRUSTED_IDENTITY_HEADERS: [&str; 5] = [
    "x-authguard-id-token",
    "x-authguard-issuer",
    "x-authguard-external-id",
    "x-authguard-groups",
    "x-authguard-claim-tenant-id",
];

#[derive(Debug, Clone)]
pub(super) struct CompiledRoleBinding {
    pub(super) id: String,
    pub(super) principal_id: String,
    pub(super) role_id: String,
    pub(super) effect: Effect,
    pub(super) resource_urn: UrnPattern,
    pub(super) conditions: AuthorizationConditions,
}

/// Immutable evaluator built from the active Role and `RoleBinding` catalog.
#[derive(Debug, Clone, Default)]
pub(super) struct AuthorizationEvaluator {
    roles: HashMap<String, Role>,
    role_bindings: Vec<CompiledRoleBinding>,
}

impl AuthorizationEvaluator {
    pub(super) fn new(roles: Vec<Role>, role_bindings: Vec<CompiledRoleBinding>) -> Self {
        Self {
            roles: roles.into_iter().map(|role| (role.id.clone(), role)).collect(),
            role_bindings,
        }
    }

    #[must_use]
    pub(super) fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        let groups = request.group_principal_ids.iter().cloned().collect::<HashSet<_>>();
        let mut all_urns = Vec::with_capacity(1 + request.parent_urns.len());
        all_urns.push(&request.resource_urn);
        all_urns.extend(request.parent_urns.iter());

        let mut allow = None;
        for binding in &self.role_bindings {
            if !Self::principal_matches(binding, &request.principal_id, &groups)
                || !binding.resource_urn.matches_any(all_urns.iter().copied())
                || !self.binding_contains_action(binding, &request.action)
                || !binding.conditions.matches(&request.context)
            {
                continue;
            }
            if binding.effect == Effect::Deny {
                return AuthorizationDecision {
                    allowed: false,
                    reason: "explicit deny".to_string(),
                    role_binding_id: Some(binding.id.clone()),
                };
            }
            allow = Some(binding.id.clone());
        }

        allow.map_or_else(
            || AuthorizationDecision {
                allowed: false,
                reason: "default deny".to_string(),
                role_binding_id: None,
            },
            |role_binding_id| AuthorizationDecision {
                allowed: true,
                reason: "matched role binding".to_string(),
                role_binding_id: Some(role_binding_id),
            },
        )
    }

    #[must_use]
    pub(super) fn authorization_scope(
        &self,
        principal_id: &str,
        group_principal_ids: &[String],
        action: &str,
        context: &EvaluationContext,
    ) -> AuthorizationScope {
        let groups = group_principal_ids.iter().cloned().collect::<HashSet<_>>();
        let mut allow_resource_urns = Vec::new();
        let mut deny_resource_urns = Vec::new();
        for binding in &self.role_bindings {
            if !Self::principal_matches(binding, principal_id, &groups)
                || !self.binding_contains_action(binding, action)
                || !binding.conditions.matches(context)
            {
                continue;
            }
            let target = binding.resource_urn.to_string();
            match binding.effect {
                Effect::Allow => allow_resource_urns.push(target),
                Effect::Deny => deny_resource_urns.push(target),
            }
        }
        allow_resource_urns.sort();
        allow_resource_urns.dedup();
        deny_resource_urns.sort();
        deny_resource_urns.dedup();
        AuthorizationScope { allow_resource_urns, deny_resource_urns }
    }

    fn binding_contains_action(&self, binding: &CompiledRoleBinding, action: &str) -> bool {
        self.roles
            .get(&binding.role_id)
            .is_some_and(|role| role.action_ids.iter().any(|candidate| candidate == action))
    }

    fn principal_matches(
        binding: &CompiledRoleBinding,
        principal_id: &str,
        group_principal_ids: &HashSet<String>,
    ) -> bool {
        binding.principal_id == principal_id || group_principal_ids.contains(&binding.principal_id)
    }
}

/// Contract required by the authorization transport routes.
pub trait IAuthorizationHandler:
    Authorization + AccessContextService + Clone + Send + Sync + 'static
{
}

#[derive(Clone)]
pub struct DefaultAuthorizationHandler {
    policy: PolicyHandler,
    principals: PrincipalHandler,
    cache: Arc<dyn IAuthorizationCache>,
    metrics: MetricsRegistry,
    identity: IdentityConfig,
    scope_delivery: ScopeDeliveryConfig,
    direct_context_signer: AccessContextSigner,
    /// Re-signs the internal business JWT when enabled; `None` strips the
    /// original token header without replacement.
    business_token_signer: Option<BusinessTokenSigner>,
}

impl DefaultAuthorizationHandler {
    #[must_use]
    // The handler's startup wiring is one cohesive dependency set; a builder
    // or parameter struct would only relocate the same fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: PolicyHandler,
        principals: PrincipalHandler,
        cache: Arc<dyn IAuthorizationCache>,
        metrics: MetricsRegistry,
        identity: IdentityConfig,
        scope_delivery: ScopeDeliveryConfig,
        direct_context_signer: AccessContextSigner,
        business_token_signer: Option<BusinessTokenSigner>,
    ) -> Self {
        Self {
            policy,
            principals,
            cache,
            metrics,
            identity,
            scope_delivery,
            direct_context_signer,
            business_token_signer,
        }
    }
}

#[tonic::async_trait]
impl Authorization for DefaultAuthorizationHandler {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let started = Instant::now();
        let grpc_trace_context = GrpcTraceContext::from_metadata(request.metadata());
        let input = match WorkloadRequest::try_from(request.into_inner()) {
            Ok(input) => input,
            Err(message) => {
                let response = self.denied(
                    started,
                    HttpStatusCode::BadRequest,
                    "invalid request",
                    "invalid_request",
                    message,
                );
                tracing::info!(
                    http.request.id = "",
                    authguard.policy_revision = self.policy.compiled_snapshot().policy().revision,
                    authguard.decision = "deny",
                    rpc.grpc.status_code = response.status.as_ref().map_or(0, |status| status.code),
                    duration_seconds = started.elapsed().as_secs_f64(),
                    "Envoy ext_authz authorization check completed"
                );
                return Ok(Response::new(response));
            }
        };
        let request_id = input.request_id().unwrap_or("").to_string();
        let (parent, parent_source) = global::get_text_map_propagator(|propagator| {
            Self::extract_parent_context(propagator, grpc_trace_context.as_ref(), &input.headers)
        });
        let span = tracing::info_span!(
            "envoy.ext_authz.check",
            otel.kind = "server",
            rpc.system = "grpc",
            rpc.service = "envoy.service.auth.v3.Authorization",
            rpc.method = "Check",
            authguard.trace.parent_source = parent_source,
            http.request.method = %input.method,
            http.request.id = %input.request_id().unwrap_or(""),
            url.path = %input.path,
            authguard.decision = tracing::field::Empty,
            authguard.decision.reason = tracing::field::Empty,
            authguard.identity.issuer = tracing::field::Empty,
            authguard.principal.id = tracing::field::Empty,
            authguard.principal.group_count = tracing::field::Empty,
            authguard.route.id = tracing::field::Empty,
            authguard.action = tracing::field::Empty,
            authguard.resource.service = tracing::field::Empty,
            authguard.policy.revision = tracing::field::Empty,
            authguard.role_binding.id = tracing::field::Empty,
            authguard.scope.allow_count = tracing::field::Empty,
            authguard.scope.deny_count = tracing::field::Empty,
        );
        let _ = span.set_parent(parent);
        let response = async {
            let (response, policy_revision) = match self.evaluate_request(&input).await {
                Ok(evaluation) if evaluation.decision.allowed => {
                    let revision = evaluation.policy_revision;
                    (self.allowed(started, evaluation).await, revision)
                }
                Ok(evaluation) => {
                    let revision = evaluation.policy_revision;
                    (
                        self.denied(
                            started,
                            HttpStatusCode::Forbidden,
                            &evaluation.decision.reason,
                            "authorization_denied",
                            "request is not authorized",
                        ),
                        revision,
                    )
                }
                Err(failure) => (
                    self.denied(
                        started,
                        failure.status,
                        failure.metric_reason,
                        failure.code,
                        failure.message,
                    ),
                    self.policy.compiled_snapshot().policy().revision,
                ),
            };
            let allowed = response.status.as_ref().is_some_and(|status| status.code == 0);
            let decision = if allowed { "allow" } else { "deny" };
            tracing::Span::current().record("authguard.decision", decision);
            tracing::info!(
                http.request.id = %request_id,
                authguard.policy_revision = policy_revision,
                authguard.decision = decision,
                rpc.grpc.status_code = response.status.as_ref().map_or(0, |status| status.code),
                duration_seconds = started.elapsed().as_secs_f64(),
                "Envoy ext_authz authorization check completed"
            );
            response
        }
        .instrument(span.clone())
        .await;
        Ok(Response::new(response))
    }
}

impl DefaultAuthorizationHandler {
    fn extract_parent_context(
        propagator: &dyn TextMapPropagator,
        grpc_trace_context: Option<&GrpcTraceContext>,
        http_headers: &HeaderMap,
    ) -> (Context, &'static str) {
        grpc_trace_context.map_or_else(
            || (propagator.extract(&HeaderExtractor(http_headers)), "http_attributes"),
            |metadata| (propagator.extract(metadata), "grpc_metadata"),
        )
    }

    async fn allowed(&self, started: Instant, evaluation: RequestEvaluation) -> CheckResponse {
        let RequestEvaluation {
            principal_id,
            route,
            decision,
            authorization_scope,
            policy_revision,
            identity,
        } = evaluation;
        let Some(scoped) = authorization_scope else {
            tracing::error!("allowed authorization evaluation omitted its resource scope");
            return self.denied(
                started,
                HttpStatusCode::InternalServerError,
                "invalid authorization result",
                "invalid_authorization_result",
                "authorization result did not contain a resource scope",
            );
        };
        let allow_urn_count = scoped.allow_resource_urns.len();
        let deny_urn_count = scoped.deny_resource_urns.len();
        let urn_count = allow_urn_count + deny_urn_count;
        let now = epoch_seconds();
        let business_token = self.business_token(&identity, &principal_id);
        let direct_context = AccessContext::new(
            AccessContextInput {
                principal_id,
                action: route.action.clone(),
                resource_urn: route.resource_urn.to_string(),
                allow_resource_urns: scoped.allow_resource_urns,
                deny_resource_urns: scoped.deny_resource_urns,
                policy_revision,
            },
            now,
            self.scope_delivery.context_ttl,
        );
        let delivery = match self.prepare_delivery(direct_context, urn_count, now).await {
            Ok(delivery) => delivery,
            Err(failure) => {
                return self.denied(
                    started,
                    failure.status,
                    failure.metric_reason,
                    failure.code,
                    failure.message,
                );
            }
        };
        self.metrics.record_authorization(true, &decision.reason, started.elapsed().as_secs_f64());
        self.metrics.record_http(CHECK_ROUTE, "gRPC", 200);
        let ok = self.allowed_http_response(&delivery, business_token.as_deref());
        self.metrics.record_scope_delivery(delivery.name());
        tracing::debug!(
            authguard.decision = "allow",
            authguard.route_id = %route.route_id,
            authguard.action = %route.action,
            authguard.resource_service = %route.resource_urn.service,
            authguard.policy_revision = policy_revision,
            authguard.role_binding_id = decision.role_binding_id.as_deref().unwrap_or("none"),
            authguard.scope_delivery = delivery.name(),
            authguard.scope_allow_count = allow_urn_count,
            authguard.scope_deny_count = deny_urn_count,
            "authorization request allowed"
        );
        let mut response = CheckResponse::with_status(Status::ok("request authorized"));
        response.set_http_response(ok);
        response
    }

    async fn prepare_delivery(
        &self,
        direct_context: AccessContext,
        urn_count: usize,
        now: u64,
    ) -> Result<AccessDelivery, CheckFailure> {
        let encoded_payload = direct_context.encode().map_err(|error| {
            tracing::error!(%error, "failed to encode access context");
            CheckFailure::context_encoding()
        })?;
        let direct_encoded =
            self.direct_context_signer.sign_encoded(&encoded_payload).map_err(|error| {
                tracing::error!(%error, "failed to sign direct access context");
                CheckFailure::context_encoding()
            })?;
        if urn_count <= self.scope_delivery.direct_urn_limit
            && direct_encoded.len() <= self.scope_delivery.max_direct_header_bytes
        {
            tracing::debug!(
                authguard.scope.delivery = "direct",
                authguard.scope.urn_count = urn_count,
                authguard.scope.encoded_bytes = direct_encoded.len(),
                "prepared signed direct access context"
            );
            return Ok(AccessDelivery::Direct(direct_encoded));
        }

        let token_context = AccessContext::new(
            AccessContextInput {
                principal_id: direct_context.principal_id,
                action: direct_context.action,
                resource_urn: direct_context.resource_urn,
                allow_resource_urns: direct_context.allow_resource_urns,
                deny_resource_urns: direct_context.deny_resource_urns,
                policy_revision: direct_context.policy_revision,
            },
            now,
            self.scope_delivery.scope_token_ttl,
        );
        let encoded = token_context.encode().map_err(|error| {
            tracing::error!(%error, "failed to encode token-backed access context");
            CheckFailure::context_encoding()
        })?;
        let token = Self::new_scope_token();
        self.cache
            .store_scope(&token, &encoded, self.scope_delivery.scope_token_ttl)
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to store token-backed access context");
                CheckFailure::scope_cache_unavailable()
            })?;
        tracing::debug!(
            authguard.scope.delivery = "token",
            authguard.scope.urn_count = urn_count,
            authguard.scope.encoded_bytes = encoded.len(),
            authguard.scope.ttl_seconds = self.scope_delivery.scope_token_ttl.as_secs(),
            "stored token-backed access context"
        );
        Ok(AccessDelivery::Token(token))
    }

    fn allowed_http_response(
        &self,
        delivery: &AccessDelivery,
        business_token: Option<&str>,
    ) -> OkHttpResponseBuilder {
        let overwrite = Some(HeaderAppendAction::OverwriteIfExistsOrAdd);
        let mut response = OkHttpResponseBuilder::new();
        response.remove_header("authorization");
        for header in LEGACY_ACCESS_HEADERS {
            response.remove_header(header);
        }
        for header in UNTRUSTED_IDENTITY_HEADERS {
            response.remove_header(header);
        }
        response.remove_header(&self.identity.token_header);
        match delivery {
            AccessDelivery::Direct(encoded) => {
                // Envoy applies headers_to_set before headers_to_remove. The trusted value
                // therefore overwrites any client-supplied context, while only the alternate
                // delivery header must be removed.
                response.remove_header(SCOPE_TOKEN_HEADER);
                response.add_header(ACCESS_CONTEXT_HEADER, encoded, overwrite, false);
            }
            AccessDelivery::Token(token) => {
                response.remove_header(ACCESS_CONTEXT_HEADER);
                response.add_header(SCOPE_TOKEN_HEADER, token, overwrite, false);
            }
        }
        if let Some(token) = business_token {
            // The re-signed business JWT replaces the original IdP token so
            // the upstream microservice receives only Authguard-issued
            // identity (authguardOrigin: true) plus the access context.
            response.add_header("authorization", format!("Bearer {token}"), overwrite, false);
        }
        response
    }

    fn denied(
        &self,
        started: Instant,
        status: HttpStatusCode,
        metric_reason: &str,
        code: &str,
        message: &str,
    ) -> CheckResponse {
        self.metrics.record_authorization(false, metric_reason, started.elapsed().as_secs_f64());
        self.metrics.record_http(CHECK_ROUTE, "gRPC", status as u16);
        let grpc_status = match status {
            HttpStatusCode::Unauthorized => Status::unauthenticated(message),
            HttpStatusCode::BadRequest => Status::invalid_argument(message),
            HttpStatusCode::InternalServerError => Status::internal(message),
            _ => Status::permission_denied(message),
        };
        let mut denied = DeniedHttpResponseBuilder::new();
        denied
            .set_http_status(status)
            .add_header("content-type", "application/json", None, false)
            .set_body(json!({ "code": code, "message": message }).to_string());
        if status == HttpStatusCode::Unauthorized {
            denied.add_header("www-authenticate", "Bearer realm=\"authguard\"", None, false);
        }
        tracing::debug!(
            authguard.decision = "deny",
            authguard.reason = code,
            "authorization request denied"
        );
        let mut response = CheckResponse::with_status(grpc_status);
        response.set_http_response(denied);
        response
    }
}

/// Trace propagation fields copied from the trusted Envoy-to-Authguard gRPC transport.
///
/// Only W3C trace context is retained. Other gRPC metadata can contain credentials and must not be
/// copied into telemetry or logs.
struct GrpcTraceContext {
    traceparent: Option<String>,
    tracestate: Option<String>,
}

impl GrpcTraceContext {
    fn from_metadata(metadata: &MetadataMap) -> Option<Self> {
        metadata.contains_key("traceparent").then(|| Self {
            traceparent: metadata
                .get("traceparent")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            tracestate: metadata
                .get("tracestate")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        })
    }
}

impl Extractor for GrpcTraceContext {
    fn get(&self, key: &str) -> Option<&str> {
        match key {
            "traceparent" => self.traceparent.as_deref(),
            "tracestate" => self.tracestate.as_deref(),
            _ => None,
        }
    }

    fn keys(&self) -> Vec<&str> {
        let mut keys = Vec::with_capacity(2);
        if self.traceparent.is_some() {
            keys.push("traceparent");
        }
        if self.tracestate.is_some() {
            keys.push("tracestate");
        }
        keys
    }
}

struct WorkloadRequest {
    method: String,
    host: String,
    path: String,
    headers: HeaderMap,
    source_ip: Option<IpAddr>,
    secure_transport: bool,
}

impl TryFrom<CheckRequest> for WorkloadRequest {
    type Error = &'static str;

    fn try_from(request: CheckRequest) -> Result<Self, Self::Error> {
        let attributes = request.attributes.ok_or("Envoy CheckRequest is missing attributes")?;
        let source_ip = attributes.source.as_ref().and_then(Self::peer_ip);
        let http = attributes
            .request
            .and_then(|request| request.http)
            .ok_or("Envoy CheckRequest is missing HTTP attributes")?;
        if http.method.is_empty() || http.path.is_empty() {
            return Err("Envoy CheckRequest method and path are required");
        }
        let headers = Self::header_map(&http.headers);
        let host = if http.host.is_empty() {
            http.headers.get("host").cloned().unwrap_or_default()
        } else {
            http.host
        };
        let secure_transport = http.scheme.eq_ignore_ascii_case("https");
        let path = http.path.split('?').next().unwrap_or("/").to_string();
        Ok(Self { method: http.method, host, path, headers, source_ip, secure_transport })
    }
}

impl WorkloadRequest {
    fn request_id(&self) -> Option<&str> {
        self.headers.get("x-request-id").and_then(|value| value.to_str().ok()).filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_REQUEST_ID_BYTES
                && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
    }

    fn peer_ip(
        peer: &envoy_types::pb::envoy::service::auth::v3::attribute_context::Peer,
    ) -> Option<IpAddr> {
        use envoy_types::pb::envoy::config::core::v3::address::Address;

        match peer.address.as_ref()?.address.as_ref()? {
            Address::SocketAddress(socket) => socket.address.parse().ok(),
            Address::Pipe(_) | Address::EnvoyInternalAddress(_) => None,
        }
    }

    fn header_map(headers: &HashMap<String, String>) -> HeaderMap {
        let mut result = HeaderMap::with_capacity(headers.len());
        for (name, value) in headers {
            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            let Ok(value) = HeaderValue::from_str(value) else {
                continue;
            };
            result.insert(name, value);
        }
        result
    }
}

struct RequestEvaluation {
    principal_id: String,
    route: ResolvedHttpRoute,
    decision: AuthorizationDecision,
    authorization_scope: Option<AuthorizationScope>,
    policy_revision: u64,
    identity: RequestIdentity,
}

enum AccessDelivery {
    Direct(String),
    Token(String),
}

impl AccessDelivery {
    const fn name(&self) -> &'static str {
        match self {
            Self::Direct(_) => "direct",
            Self::Token(_) => "token",
        }
    }
}

struct CheckFailure {
    status: HttpStatusCode,
    metric_reason: &'static str,
    code: &'static str,
    message: &'static str,
}

impl CheckFailure {
    const fn context_encoding() -> Self {
        Self {
            status: HttpStatusCode::InternalServerError,
            metric_reason: "invalid request",
            code: "context_encoding_failed",
            message: "failed to create trusted access context",
        }
    }

    const fn scope_cache_unavailable() -> Self {
        Self {
            status: HttpStatusCode::ServiceUnavailable,
            metric_reason: "scope cache unavailable",
            code: "scope_cache_unavailable",
            message: "authorization scope is temporarily unavailable",
        }
    }

    fn principal(error: &PrincipalHandlerError) -> Self {
        tracing::warn!(%error, "principal resolution failed closed");
        match error {
            PrincipalHandlerError::Disabled(_) => Self {
                status: HttpStatusCode::Forbidden,
                metric_reason: "principal disabled",
                code: "principal_disabled",
                message: "the authenticated principal is disabled",
            },
            PrincipalHandlerError::NotFound(_) | PrincipalHandlerError::ProviderUnavailable => {
                Self {
                    status: HttpStatusCode::Unauthorized,
                    metric_reason: "unknown principal",
                    code: "unknown_principal",
                    message: "the authenticated principal is not registered",
                }
            }
            PrincipalHandlerError::Referenced(_)
            | PrincipalHandlerError::Discovery(_)
            | PrincipalHandlerError::Storage(_) => Self {
                status: HttpStatusCode::ServiceUnavailable,
                metric_reason: "principal resolution unavailable",
                code: "principal_resolution_unavailable",
                message: "principal resolution is temporarily unavailable",
            },
        }
    }
}

impl DefaultAuthorizationHandler {
    fn request_identity(&self, request: &WorkloadRequest) -> Result<RequestIdentity, CheckFailure> {
        let identity = match RequestIdentity::from_gateway_headers(
            &request.headers,
            &self.identity.token_header,
            &self.identity.issuer_claim,
            &self.identity.external_id_claim,
            &self.identity.groups_claim,
        ) {
            Ok(identity) => identity,
            Err(IdentityError::Missing) => {
                return Err(CheckFailure {
                    status: HttpStatusCode::Unauthorized,
                    metric_reason: "missing identity",
                    code: "missing_identity",
                    message: "trusted identity token is required",
                });
            }
            Err(error) => {
                tracing::warn!(error = %error, "rejected malformed trusted identity token");
                return Err(CheckFailure {
                    status: HttpStatusCode::Unauthorized,
                    metric_reason: "invalid identity",
                    code: "invalid_identity",
                    message: "trusted identity token is invalid",
                });
            }
        };
        let span = tracing::Span::current();
        span.record("authguard.identity.issuer", identity.issuer.as_str());
        tracing::debug!(
            authguard.identity.issuer = %identity.issuer,
            authguard.identity.group_claim_count = identity.group_external_ids.len(),
            authguard.identity.scalar_claim_count = identity.claims.len(),
            "parsed gateway-verified request identity"
        );
        Ok(identity)
    }

    async fn evaluate_request(
        &self,
        request: &WorkloadRequest,
    ) -> Result<RequestEvaluation, CheckFailure> {
        let identity = self.request_identity(request)?;
        let span = tracing::Span::current();
        let resolved = self
            .principals
            .resolve_request(&identity)
            .await
            .map_err(|error| CheckFailure::principal(&error))?;
        span.record("authguard.principal.id", resolved.principal_id.as_str());
        span.record("authguard.principal.group_count", resolved.group_principal_ids.len());
        tracing::debug!(
            authguard.principal_id = %resolved.principal_id,
            authguard.principal_group_count = resolved.group_principal_ids.len(),
            "resolved request identity to authorization principals"
        );
        let snapshot = self.policy.compiled_snapshot();
        span.record("authguard.policy.revision", snapshot.policy().revision);
        let route = match snapshot.resolve_http_route(
            &request.method,
            &request.host,
            &request.path,
            &identity.claims,
        ) {
            Ok(route) => route,
            Err(HttpMappingError::NotMapped) => {
                return Err(CheckFailure {
                    status: HttpStatusCode::Forbidden,
                    metric_reason: "route not mapped",
                    code: "route_not_mapped",
                    message: "request route has no authorization mapping",
                });
            }
            Err(error) => {
                tracing::warn!(error = %error, "failed to resolve HTTP authorization route");
                return Err(CheckFailure {
                    status: HttpStatusCode::Forbidden,
                    metric_reason: "invalid request",
                    code: "invalid_route_mapping",
                    message: "request route mapping is invalid",
                });
            }
        };
        span.record("authguard.route.id", route.route_id.as_str());
        span.record("authguard.action", route.action.as_str());
        span.record("authguard.resource.service", route.resource_urn.service.as_str());
        tracing::debug!(
            authguard.route_id = %route.route_id,
            authguard.action = %route.action,
            authguard.resource_service = %route.resource_urn.service,
            authguard.policy_revision = snapshot.policy().revision,
            "resolved HTTP request to authorization resource"
        );
        let evaluator = snapshot.evaluator();
        let context = EvaluationContext {
            source_ip: request.source_ip,
            request_method: Some(request.method.clone()),
            secure_transport: Some(request.secure_transport),
            claims: identity.claims.clone().into_iter().collect(),
        };
        let decision = evaluator.authorize(&AuthorizationRequest {
            principal_id: resolved.principal_id.clone(),
            group_principal_ids: resolved.group_principal_ids.clone(),
            action: route.action.clone(),
            resource_urn: route.resource_urn.clone(),
            parent_urns: route.parent_urns.clone(),
            context: context.clone(),
        });
        span.record("authguard.decision", if decision.allowed { "allow" } else { "deny" });
        span.record("authguard.decision.reason", decision.reason.as_str());
        if let Some(role_binding_id) = decision.role_binding_id.as_deref() {
            span.record("authguard.role_binding.id", role_binding_id);
        }
        let authorization_scope = decision.allowed.then(|| {
            evaluator.authorization_scope(
                &resolved.principal_id,
                &resolved.group_principal_ids,
                &route.action,
                &context,
            )
        });
        if let Some(scope) = authorization_scope.as_ref() {
            span.record("authguard.scope.allow_count", scope.allow_resource_urns.len());
            span.record("authguard.scope.deny_count", scope.deny_resource_urns.len());
        }
        Ok(RequestEvaluation {
            principal_id: resolved.principal_id,
            route,
            decision,
            authorization_scope,
            policy_revision: snapshot.policy().revision,
            identity,
        })
    }

    /// Re-signs the internal business JWT for the upstream microservice.
    ///
    /// The token carries `authguardOrigin: true`, the verified identity, and
    /// the materialized principal id. It is signed with Authguard's RSA
    /// private key (RS256), so the microservice verifies it with the paired
    /// public key without calling back into Authguard.
    fn business_token(&self, identity: &RequestIdentity, principal_id: &str) -> Option<String> {
        let signer = self.business_token_signer.as_ref()?;
        let now = epoch_seconds();
        let claims = Self::business_token_claims(identity, principal_id, now, &self.scope_delivery);
        let payload = serde_json::to_vec(&claims)
            .map_err(|error| tracing::error!(%error, "failed to encode business token claims"))
            .ok()?;
        let token = signer
            .sign(&payload)
            .map_err(|error| tracing::error!(%error, "failed to sign business token"))
            .ok()?;
        tracing::debug!(
            authguard.principal_id = principal_id,
            authguard.business_token.ttl_seconds = self.scope_delivery.scope_token_ttl.as_secs(),
            "re-signed internal business JWT"
        );
        Some(token)
    }

    /// Assembles the business JWT claims shared between the runtime and tests.
    #[must_use]
    pub(crate) fn business_token_claims(
        identity: &RequestIdentity,
        principal_id: &str,
        now_epoch_seconds: u64,
        scope_delivery: &ScopeDeliveryConfig,
    ) -> serde_json::Value {
        let mut claims = serde_json::Map::new();
        claims.insert("iss".to_string(), json!("authguard"));
        claims.insert("sub".to_string(), json!(identity.external_id));
        claims.insert("principal_id".to_string(), json!(principal_id));
        claims.insert("authguard_group_ids".to_string(), json!(identity.group_external_ids));
        // Marker claim: this JWT was re-signed by Authguard, never the IdP.
        claims.insert("authguardOrigin".to_string(), json!(true));
        claims.insert("iat".to_string(), json!(now_epoch_seconds));
        claims.insert(
            "exp".to_string(),
            json!(now_epoch_seconds.saturating_add(scope_delivery.scope_token_ttl.as_secs())),
        );
        for (name, value) in &identity.claims {
            if matches!(name.as_str(), "iss" | "sub" | "authguard_group_ids") {
                continue;
            }
            claims.insert(name.clone(), json!(value));
        }
        serde_json::Value::Object(claims)
    }

    fn new_scope_token() -> String {
        let mut bytes = [0_u8; SCOPE_TOKEN_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        format!("{SCOPE_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
    }

    fn valid_scope_token(token: &str) -> bool {
        token.len() == SCOPE_TOKEN_PREFIX.len() + 43
            && token.starts_with(SCOPE_TOKEN_PREFIX)
            && token[SCOPE_TOKEN_PREFIX.len()..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }
}

#[tonic::async_trait]
impl AccessContextService for DefaultAuthorizationHandler {
    async fn resolve_scope(&self, request: Request<String>) -> Result<Response<String>, Status> {
        let started = Instant::now();
        let token = request.into_inner();
        if !Self::valid_scope_token(&token) {
            tracing::warn!("rejected malformed authorization scope token");
            self.metrics.record_scope_resolution("invalid", started.elapsed().as_secs_f64());
            self.metrics.record_http(RESOLVE_SCOPE_ROUTE, "gRPC", 400);
            return Err(Status::invalid_argument("invalid scope token"));
        }
        let encoded = match self.cache.load_scope(&token).await {
            Ok(Some(encoded)) => encoded,
            Ok(None) => {
                tracing::debug!("authorization scope token was not found or has expired");
                self.metrics.record_scope_resolution("miss", started.elapsed().as_secs_f64());
                self.metrics.record_http(RESOLVE_SCOPE_ROUTE, "gRPC", 401);
                return Err(Status::unauthenticated("scope token is unknown or expired"));
            }
            Err(error) => {
                tracing::error!(%error, "failed to load token-backed access context");
                self.metrics.record_scope_resolution("error", started.elapsed().as_secs_f64());
                self.metrics.record_http(RESOLVE_SCOPE_ROUTE, "gRPC", 503);
                return Err(Status::unavailable("authorization scope is temporarily unavailable"));
            }
        };
        let context = AccessContext::decode(&encoded).map_err(|error| {
            tracing::warn!(%error, "rejected invalid cached access context");
            self.metrics.record_scope_resolution("invalid", started.elapsed().as_secs_f64());
            self.metrics.record_http(RESOLVE_SCOPE_ROUTE, "gRPC", 401);
            Status::unauthenticated("scope token is unknown or expired")
        })?;
        self.metrics.record_scope_resolution("hit", started.elapsed().as_secs_f64());
        self.metrics.record_http(RESOLVE_SCOPE_ROUTE, "gRPC", 200);
        tracing::debug!(
            authguard.principal_id = %context.principal_id,
            authguard.action = %context.action,
            authguard.policy_revision = context.policy_revision,
            authguard.scope_allow_count = context.allow_resource_urns.len(),
            authguard.scope_deny_count = context.deny_resource_urns.len(),
            duration_seconds = started.elapsed().as_secs_f64(),
            "authorization scope token resolved"
        );
        Ok(Response::new(encoded))
    }
}

impl IAuthorizationHandler for DefaultAuthorizationHandler {}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};
    use opentelemetry::trace::TraceContextExt as _;
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use tonic::metadata::MetadataMap;

    use super::{DefaultAuthorizationHandler, GrpcTraceContext};
    use crate::config::ScopeDeliveryConfig;
    use crate::utils::RequestIdentity;

    const GRPC_TRACE_ID: &str = "11111111111111111111111111111111";
    const HTTP_TRACE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn prefers_trusted_grpc_trace_context_over_http_attributes() {
        let metadata =
            SelfTestData::grpc_metadata(&format!("00-{GRPC_TRACE_ID}-2222222222222222-01"));
        let grpc = GrpcTraceContext::from_metadata(&metadata);
        let headers =
            SelfTestData::http_headers(&format!("00-{HTTP_TRACE_ID}-bbbbbbbbbbbbbbbb-01"));

        let (parent, source) = DefaultAuthorizationHandler::extract_parent_context(
            &TraceContextPropagator::new(),
            grpc.as_ref(),
            &headers,
        );
        let span = parent.span();

        assert_eq!(source, "grpc_metadata");
        assert_eq!(span.span_context().trace_id().to_string(), GRPC_TRACE_ID);
        assert_eq!(span.span_context().trace_state().header(), "vendor=grpc");
    }

    #[test]
    fn falls_back_to_envoy_http_attributes_without_grpc_traceparent() {
        let metadata = MetadataMap::new();
        let grpc = GrpcTraceContext::from_metadata(&metadata);
        let headers =
            SelfTestData::http_headers(&format!("00-{HTTP_TRACE_ID}-bbbbbbbbbbbbbbbb-01"));

        let (parent, source) = DefaultAuthorizationHandler::extract_parent_context(
            &TraceContextPropagator::new(),
            grpc.as_ref(),
            &headers,
        );
        let span = parent.span();

        assert_eq!(source, "http_attributes");
        assert_eq!(span.span_context().trace_id().to_string(), HTTP_TRACE_ID);
        assert_eq!(span.span_context().trace_state().header(), "vendor=http");
    }

    #[test]
    fn malformed_grpc_traceparent_does_not_downgrade_to_http_attributes() {
        let metadata = SelfTestData::grpc_metadata("malformed");
        let grpc = GrpcTraceContext::from_metadata(&metadata);
        let headers =
            SelfTestData::http_headers(&format!("00-{HTTP_TRACE_ID}-bbbbbbbbbbbbbbbb-01"));

        let (parent, source) = DefaultAuthorizationHandler::extract_parent_context(
            &TraceContextPropagator::new(),
            grpc.as_ref(),
            &headers,
        );
        let span = parent.span();

        assert_eq!(source, "grpc_metadata");
        assert!(!span.span_context().is_valid());
    }

    #[test]
    fn business_token_claims_mark_authguard_origin_and_keep_scalar_claims() {
        let identity = RequestIdentity {
            issuer: "https://id.example/realms/company".to_string(),
            external_id: "user-1".to_string(),
            group_external_ids: vec!["group-7".to_string()],
            claims: std::collections::HashMap::from([
                ("tenant_id".to_string(), "mycompany".to_string()),
                ("mfa".to_string(), "true".to_string()),
            ]),
        };
        let claims = DefaultAuthorizationHandler::business_token_claims(
            &identity,
            "principal-1",
            1_700_000_000,
            &ScopeDeliveryConfig::default(),
        );

        assert_eq!(claims["iss"], "authguard");
        assert_eq!(claims["sub"], "user-1");
        assert_eq!(claims["principal_id"], "principal-1");
        assert_eq!(claims["authguard_group_ids"], serde_json::json!(["group-7"]));
        assert_eq!(claims["authguardOrigin"], serde_json::json!(true));
        assert_eq!(claims["iat"], serde_json::json!(1_700_000_000));
        assert_eq!(claims["tenant_id"], "mycompany", "scalar claims are preserved");
        assert_eq!(claims["mfa"], "true");
        assert!(
            claims.as_object().is_some_and(|object| object.contains_key("exp")),
            "expiry claim present"
        );
    }

    struct SelfTestData;

    impl SelfTestData {
        fn grpc_metadata(traceparent: &str) -> MetadataMap {
            let mut metadata = MetadataMap::new();
            metadata.insert("traceparent", traceparent.parse().expect("valid metadata value"));
            metadata.insert("tracestate", "vendor=grpc".parse().expect("valid metadata value"));
            metadata
        }

        fn http_headers(traceparent: &str) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert("traceparent", HeaderValue::from_str(traceparent).unwrap());
            headers.insert("tracestate", HeaderValue::from_static("vendor=http"));
            headers
        }
    }
}
