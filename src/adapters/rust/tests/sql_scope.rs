use authguard_adapter_rust::{
    access,
    model::{PathMap, PathPattern, ResourceSqlMapping, SegmentMap, SegmentPattern, SqlScope},
    util::{self, CurrentScopeError},
    AccessContext, AccessGrantSet,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

const EXACT_JOB: &str = "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score";
const JOB_WILDCARD: &str = "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*";

#[test]
fn compiles_exact_job_resource_to_sql_scope() {
    let scope =
        util::compile_scope(&customer_growth_job_mapping(), [EXACT_JOB], [] as [&str; 0]).unwrap();

    assert_scope(
        &scope,
        "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?",
        &[
            "global",
            "example-corp",
            "customer-insights",
            "retention-analytics",
            "daily-churn-risk-score",
        ],
    );
}

#[test]
fn compiles_single_segment_job_wildcard_without_job_predicate() {
    let scope =
        util::compile_scope(&customer_growth_job_mapping(), [JOB_WILDCARD], [] as [&str; 0])
            .unwrap();

    assert_scope(
        &scope,
        "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?",
        &["global", "example-corp", "customer-insights", "retention-analytics"],
    );
}

#[test]
fn combines_multiple_allow_scopes_before_explicit_deny() {
    let scope = util::compile_scope(
        &customer_growth_job_mapping(),
        [
            JOB_WILDCARD,
            "urn:iam:prod:customer-growth:global:example-corp:workspace/campaign-analytics/project/campaign-attribution/job/daily-channel-attribution",
        ],
        ["urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit"],
    )
    .unwrap();

    assert_scope(
        &scope,
        "((region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?) OR \
         (region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?)) \
         AND NOT (region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?)",
        &[
            "global",
            "example-corp",
            "customer-insights",
            "retention-analytics",
            "global",
            "example-corp",
            "campaign-analytics",
            "campaign-attribution",
            "daily-channel-attribution",
            "global",
            "example-corp",
            "customer-insights",
            "retention-analytics",
            "vip-retention-risk-audit",
        ],
    );
}

#[test]
fn returns_deny_all_when_allow_list_is_empty() {
    let scope = util::compile_scope(
        &customer_growth_job_mapping(),
        [] as [&str; 0],
        ["urn:iam:prod:customer-growth:global:example-corp:**"],
    )
    .unwrap();

    assert_scope(&scope, "0=1", &[]);
}

#[test]
fn compiles_object_key_globstar_to_boundary_safe_prefix() {
    let scope = util::compile_scope(
        &object_mapping(),
        ["urn:iam:prod:object-store:us-west-2:example-corp:bucket/audit-exports/object/2026/08/**"],
        [] as [&str; 0],
    )
    .unwrap();

    assert_scope(
        &scope,
        "region = ? AND account_id = ? AND bucket = ? AND (object_key = ? OR object_key LIKE ?)",
        &["us-west-2", "example-corp", "audit-exports", "2026/08", "2026/08/%"],
    );
}

#[test]
fn rejects_single_segment_wildcard_inside_remainder_column() {
    let error = util::compile_scope(
        &object_mapping(),
        ["urn:iam:prod:object-store:us-west-2:example-corp:bucket/audit-exports/object/*/report.json"],
        [] as [&str; 0],
    )
    .unwrap_err();

    assert!(error.to_string().contains("remainder column"));
}

#[test]
fn access_context_codec_round_trips() {
    let expected = test_context();

    let encoded = util::encode_access_context(&expected).unwrap();

    assert!(!encoded.contains('='));
    assert_eq!(util::decode_access_context(&encoded).unwrap(), expected);
}

#[test]
fn access_context_codec_emits_v3_canonical_fields() {
    let encoded = util::encode_access_context(&test_context()).unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();

    assert_eq!(json["version"], 3);
    assert_eq!(json["principal_id"], "revenue-analyst");
    assert_eq!(json["policy_revision"], 1);
    assert!(json.get("subject_id").is_none());
    assert!(json.get("policy_version").is_none());
}

#[test]
fn access_context_codec_accepts_v3_legacy_field_aliases() {
    let now = authguard_core::model::epoch_seconds();
    let legacy_json = serde_json::json!({
        "version": 3,
        "subject_id": "legacy-revenue-analyst",
        "action": "customer-growth.job.read",
        "resource_urn": EXACT_JOB,
        "allow_resource_urns": [JOB_WILDCARD],
        "deny_resource_urns": [],
        "policy_version": 17,
        "issued_at_epoch_seconds": now,
        "expires_at_epoch_seconds": now + 30,
    });
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&legacy_json).unwrap());

    let decoded = util::decode_access_context(&encoded).unwrap();

    assert_eq!(decoded.version, 3);
    assert_eq!(decoded.principal_id, "legacy-revenue-analyst");
    assert_eq!(decoded.policy_revision, 17);
}

#[test]
fn current_context_compiles_sql_scope() {
    access::set_current(AccessGrantSet::new(vec![JOB_WILDCARD.to_string()], Vec::new()));

    let scope = util::current_scope(&customer_growth_job_mapping()).unwrap();
    access::clear_current();

    assert_scope(
        &scope,
        "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?",
        &["global", "example-corp", "customer-insights", "retention-analytics"],
    );
}

#[test]
fn current_action_scope_compiles_for_matching_action() {
    let context = AccessContext { deny_resource_urns: Vec::new(), ..test_context() };
    access::set_current_access(authguard_adapter_rust::RequestAccess::from_context(&context));

    let scope =
        util::current_scope_for_action("customer-growth.job.read", &customer_growth_job_mapping())
            .unwrap();
    access::clear_current();

    assert_scope(
        &scope,
        "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?",
        &["global", "example-corp", "customer-insights", "retention-analytics"],
    );
}

#[test]
fn current_action_scope_rejects_action_mismatch() {
    access::set_current_access(
        authguard_adapter_rust::RequestAccess::from_context(&test_context()),
    );

    let error = util::current_scope_for_action(
        "customer-growth.job.update",
        &customer_growth_job_mapping(),
    )
    .unwrap_err();
    access::clear_current();

    assert!(error.to_string().contains("action mismatch"));
}

#[test]
fn parses_descriptive_resource_urn_components() {
    let pattern = util::parse_urn_pattern(EXACT_JOB).unwrap();

    assert_eq!(pattern.partition, SegmentPattern::Exact("prod".to_string()));
    assert_eq!(pattern.service, SegmentPattern::Exact("customer-growth".to_string()));
    assert_eq!(pattern.region, SegmentPattern::Exact("global".to_string()));
    assert_eq!(pattern.tenant, SegmentPattern::Exact("example-corp".to_string()));
    assert_eq!(
        pattern.path,
        [
            "workspace",
            "customer-insights",
            "project",
            "retention-analytics",
            "job",
            "daily-churn-risk-score",
        ]
        .into_iter()
        .map(|value| PathPattern::Exact(value.to_string()))
        .collect::<Vec<_>>()
    );
}

#[test]
fn rejects_non_iam_urn_namespace() {
    assert!(util::parse_urn_pattern(
        "urn:other:prod:customer-growth:global:example-corp:workspace/customer-insights"
    )
    .is_err());
}

#[test]
fn rejects_urn_without_resource_path() {
    assert!(util::parse_urn_pattern("urn:iam:prod:customer-growth:global:example-corp:").is_err());
}

#[test]
fn rejects_empty_resource_path_segment() {
    assert!(util::parse_urn_pattern(
        "urn:iam:prod:customer-growth:global:example-corp:workspace//project/retention-analytics"
    )
    .is_err());
}

#[test]
fn rejects_partial_segment_wildcard() {
    assert!(util::parse_urn_pattern(
        "urn:iam:prod:customer-growth:global:example-corp:workspace/revenue-*/project/retention-analytics"
    )
    .is_err());
}

#[test]
fn rejects_non_terminal_globstar() {
    assert!(util::parse_urn_pattern(
        "urn:iam:prod:customer-growth:global:example-corp:workspace/**/job/daily-churn-risk-score"
    )
    .is_err());
}

#[test]
fn ignores_allow_for_different_service() {
    let scope = util::compile_scope(
        &customer_growth_job_mapping(),
        ["urn:iam:prod:billing:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score"],
        [] as [&str; 0],
    )
    .unwrap();

    assert_scope(&scope, "0=1", &[]);
}

#[test]
fn ignores_deny_for_different_service() {
    let scope = util::compile_scope(
        &customer_growth_job_mapping(),
        [EXACT_JOB],
        ["urn:iam:prod:billing:global:example-corp:**"],
    )
    .unwrap();

    assert_scope(
        &scope,
        "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?",
        &[
            "global",
            "example-corp",
            "customer-insights",
            "retention-analytics",
            "daily-churn-risk-score",
        ],
    );
}

#[test]
fn compiles_all_segment_wildcards_to_allow_all() {
    let scope = util::compile_scope(
        &customer_growth_job_mapping(),
        ["urn:iam:*:*:*:*:**"],
        [] as [&str; 0],
    )
    .unwrap();

    assert_scope(&scope, "1=1", &[]);
}

#[test]
fn global_deny_wildcard_collapses_scope_to_deny_all() {
    let scope =
        util::compile_scope(&customer_growth_job_mapping(), [EXACT_JOB], ["urn:iam:*:*:*:*:**"])
            .unwrap();

    assert_scope(&scope, "0=1", &[]);
}

#[test]
fn compiles_exact_object_key_into_single_equality() {
    let scope = util::compile_scope(
        &object_mapping(),
        ["urn:iam:prod:object-store:us-west-2:example-corp:bucket/audit-exports/object/2026/08/report.json"],
        [] as [&str; 0],
    )
    .unwrap();

    assert_scope(
        &scope,
        "region = ? AND account_id = ? AND bucket = ? AND object_key = ?",
        &["us-west-2", "example-corp", "audit-exports", "2026/08/report.json"],
    );
}

#[test]
fn current_scope_without_access_context_fails_closed() {
    access::clear_current();

    let error = util::current_scope(&customer_growth_job_mapping()).unwrap_err();

    assert!(matches!(error, CurrentScopeError::Access(_)));
}

fn test_context() -> AccessContext {
    AccessContext::new(
        authguard_adapter_rust::model::AccessContextInput {
            principal_id: "revenue-analyst".to_string(),
            action: "customer-growth.job.read".to_string(),
            resource_urn: EXACT_JOB.to_string(),
            allow_resource_urns: vec![JOB_WILDCARD.to_string()],
            deny_resource_urns: vec!["urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit".to_string()],
            policy_revision: 1,
        },
        authguard_core::model::epoch_seconds(),
        std::time::Duration::from_secs(30),
    )
}

fn customer_growth_job_mapping() -> ResourceSqlMapping {
    ResourceSqlMapping {
        partition: SegmentMap::constant("prod"),
        service: SegmentMap::constant("customer-growth"),
        region: SegmentMap::column("region"),
        tenant: SegmentMap::column("tenant_id"),
        path: vec![
            PathMap::literal("workspace"),
            PathMap::column("workspace_id"),
            PathMap::literal("project"),
            PathMap::column("project_id"),
            PathMap::literal("job"),
            PathMap::column("job_id"),
        ],
    }
}

fn object_mapping() -> ResourceSqlMapping {
    ResourceSqlMapping {
        partition: SegmentMap::constant("prod"),
        service: SegmentMap::constant("object-store"),
        region: SegmentMap::column("region"),
        tenant: SegmentMap::column("account_id"),
        path: vec![
            PathMap::literal("bucket"),
            PathMap::column("bucket"),
            PathMap::literal("object"),
            PathMap::remainder_column("object_key"),
        ],
    }
}

fn assert_scope(scope: &SqlScope, where_clause: &str, params: &[&str]) {
    assert_eq!(scope.where_clause, where_clause);
    let expected = params.iter().map(|value| (*value).to_string()).collect::<Vec<_>>();
    assert_eq!(scope.params, expected);
}
