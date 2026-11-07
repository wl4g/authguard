use axum::http::{HeaderMap, HeaderValue};
use opentelemetry::trace::TraceContextExt as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tonic::metadata::MetadataMap;

use super::{DefaultAuthorizationHandler, GrpcTraceContext};
use authguard_common::AuthenticatedPrincipalContext;

const GRPC_TRACE_ID: &str = "11111111111111111111111111111111";
const HTTP_TRACE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn prefers_trusted_grpc_trace_context_over_http_attributes() {
    let metadata = SelfTestData::grpc_metadata(&format!("00-{GRPC_TRACE_ID}-2222222222222222-01"));
    let grpc = GrpcTraceContext::from_metadata(&metadata);
    let headers = SelfTestData::http_headers(&format!("00-{HTTP_TRACE_ID}-bbbbbbbbbbbbbbbb-01"));

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
    let headers = SelfTestData::http_headers(&format!("00-{HTTP_TRACE_ID}-bbbbbbbbbbbbbbbb-01"));

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
    let headers = SelfTestData::http_headers(&format!("00-{HTTP_TRACE_ID}-bbbbbbbbbbbbbbbb-01"));

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
fn resign_token_claims_mark_authguard_origin_and_keep_scalar_claims() {
    let identity = AuthenticatedPrincipalContext {
        principal_id: "principal-1".to_string(),
        kind: crate::model::PrincipalKind::User,
        stable_group_ids: vec!["principal-group-7".to_string()],
        trusted_claims: std::collections::HashMap::from([
            ("tenant_id".to_string(), "mycompany".to_string()),
            ("mfa".to_string(), "true".to_string()),
        ]),
        acr: Some("urn:mfa".to_string()),
        amr: vec!["pwd".to_string(), "mfa".to_string()],
    };
    let claims = DefaultAuthorizationHandler::resign_token_claims(
        &identity,
        "principal-1",
        1_700_000_000,
        std::time::Duration::from_secs(30),
    );

    assert_eq!(claims["iss"], "authguard-authz");
    assert_eq!(claims["sub"], "principal-1");
    assert_eq!(claims["principal_id"], "principal-1");
    assert_eq!(claims["principal_kind"], "USER");
    assert_eq!(claims["authguard_group_ids"], serde_json::json!(["principal-group-7"]));
    assert_eq!(claims["authguardOrigin"], serde_json::json!(true));
    assert_eq!(claims["iat"], serde_json::json!(1_700_000_000));
    assert_eq!(claims["exp"], serde_json::json!(1_700_000_030));
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
