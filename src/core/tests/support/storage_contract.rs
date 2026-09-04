use std::collections::BTreeMap;
use std::str::FromStr as _;

use authguard_core::model::{RequestConditionSpec, SourceIpConditionSpec};
use authguard_core::storage::{
    PolicyRepository, PolicyRevisionConflict, PrincipalReferenced, PrincipalRepository,
};
use authguard_core::{
    Action, AuthorizationConditionSpec, AuthorizationRequest, Effect, EvaluationContext,
    HttpRouteMatcher, Policy, PolicyRuntime, Principal, PrincipalKind, PrincipalStatus,
    ResourceUrn, Role, RoleBinding,
};
use serde_json::json;

const ISSUER: &str = "https://identity.example.com/realms/customer-growth";
const PARTNER_ISSUER: &str = "https://partners.example.com/oidc";
const USER_ID: &str = "principal-growth-analyst";
const GROUP_ID: &str = "principal-growth-team";
const WORKLOAD_ID: &str = "principal-growth-scheduler";
const ALLOWED_JOB: &str = "urn:iam:prod:customer-growth:global:example-corp:workspace/growth/project/acquisition/job/daily-acquisition-score";
const DENIED_JOB: &str = "urn:iam:prod:customer-growth:global:example-corp:workspace/growth/project/acquisition/job/executive-audience-export";

/// Exercises the externally observable contract shared by the `SQLite` and
/// `PostgreSQL` implementations. The policy fixture touches every normalized
/// authorization table: policy, action, role, role-action, role-binding, and
/// principal.
pub async fn assert_repository_contract<R>(repository: &R)
where
    R: PolicyRepository + PrincipalRepository + Sync,
{
    repository.ping().await.expect("repository ping");
    let initial = repository.load().await.expect("initial policy");
    assert_eq!(initial, Policy::default());

    let principals = assert_principal_projection_contract(repository).await;
    assert_policy_aggregate_contract(repository, &principals).await;
    assert_principal_lifecycle_after_policy_reset(repository, &principals).await;
}

struct ContractPrincipals {
    user: Principal,
    group: Principal,
    workload: Principal,
    partner: Principal,
}

async fn assert_principal_projection_contract<R>(repository: &R) -> ContractPrincipals
where
    R: PrincipalRepository + Sync,
{
    let user = principal(USER_ID, ISSUER, "growth-analyst-42", PrincipalKind::User);
    let group = principal(GROUP_ID, ISSUER, "group:growth-team", PrincipalKind::Group);
    let workload =
        principal(WORKLOAD_ID, ISSUER, "service-account:growth-scheduler", PrincipalKind::Workload);
    for principal in [&user, &group, &workload] {
        assert_eq!(repository.upsert(principal).await.expect("project principal"), *principal);
    }

    let mut refreshed = user.clone();
    refreshed.id = "must-not-replace-authguard-id".to_string();
    refreshed.display_name = "Growth Analyst 42".to_string();
    let refreshed = repository.upsert(&refreshed).await.expect("refresh projection");
    assert_eq!(refreshed.id, USER_ID);
    assert_eq!(refreshed.display_name, "Growth Analyst 42");

    let partner = principal(
        "principal-partner-growth-analyst",
        PARTNER_ISSUER,
        "growth-analyst-42",
        PrincipalKind::User,
    );
    repository.upsert(&partner).await.expect("project partner principal");
    assert_eq!(
        repository
            .find_by_external_key(ISSUER, "growth-analyst-42")
            .await
            .expect("find workforce principal")
            .expect("workforce principal")
            .id,
        USER_ID
    );
    assert_eq!(
        repository
            .find_by_external_key(PARTNER_ISSUER, "growth-analyst-42")
            .await
            .expect("find partner principal")
            .expect("partner principal")
            .id,
        partner.id
    );

    let external_ids =
        vec![workload.external_id.clone(), "missing".to_string(), group.external_id.clone()];
    let projected = repository
        .find_by_external_keys(ISSUER, &external_ids)
        .await
        .expect("batch issuer-scoped lookup");
    assert_eq!(
        projected.iter().map(|principal| principal.id.as_str()).collect::<Vec<_>>(),
        vec![GROUP_ID, WORKLOAD_ID]
    );

    ContractPrincipals { user: refreshed, group, workload, partner }
}

async fn assert_policy_aggregate_contract<R>(repository: &R, principals: &ContractPrincipals)
where
    R: PolicyRepository + PrincipalRepository + Sync,
{
    let expected = policy();
    repository.compare_and_replace(0, &expected).await.expect("persist normalized policy");
    let loaded = repository.load().await.expect("load normalized policy");
    assert_eq!(loaded, expected);

    let runtime = PolicyRuntime::new(loaded.clone()).expect("compile persisted policy");
    let allowed = runtime.authorize(&request(ALLOWED_JOB, USER_ID, &[GROUP_ID], "read"));
    assert!(allowed.allowed);
    assert_eq!(allowed.role_binding_id.as_deref(), Some("02-growth-team-reader"));

    let denied = runtime.authorize(&request(DENIED_JOB, USER_ID, &[GROUP_ID], "read"));
    assert!(!denied.allowed);
    assert_eq!(denied.reason, "explicit deny");
    assert_eq!(denied.role_binding_id.as_deref(), Some("01-sensitive-export-deny"));

    let execution = runtime.authorize(&AuthorizationRequest {
        context: EvaluationContext {
            source_ip: Some("10.20.1.8".parse().expect("source IP")),
            request_method: Some("POST".to_string()),
            secure_transport: Some(true),
            ..EvaluationContext::default()
        },
        ..request(ALLOWED_JOB, WORKLOAD_ID, &[], "run")
    });
    assert!(execution.allowed);
    assert_eq!(execution.role_binding_id.as_deref(), Some("03-growth-scheduler-runner"));

    let stale = Policy { revision: 2, ..Policy::default() };
    let error =
        repository.compare_and_replace(0, &stale).await.expect_err("stale policy writer must fail");
    assert_eq!(
        error.downcast_ref::<PolicyRevisionConflict>(),
        Some(&PolicyRevisionConflict { expected: 0, actual: 1 })
    );

    let mut invalid = expected.clone();
    invalid.revision = 2;
    invalid.role_bindings.push(RoleBinding {
        id: "04-unknown-principal".to_string(),
        principal_id: "principal-not-projected".to_string(),
        role_id: "customer-growth-reader".to_string(),
        effect: Effect::Allow,
        resource_urn: ALLOWED_JOB.to_string(),
        conditions: AuthorizationConditionSpec::default(),
    });
    assert!(repository.compare_and_replace(1, &invalid).await.is_err());
    assert_eq!(repository.load().await.expect("failed write is atomic"), expected);

    let disabled = repository
        .update_status(GROUP_ID, PrincipalStatus::Disabled)
        .await
        .expect("disable referenced principal")
        .expect("referenced principal exists");
    assert_eq!(disabled.status, PrincipalStatus::Disabled);
    let referenced =
        repository.delete(GROUP_ID).await.expect_err("role binding protects principal projection");
    assert_eq!(
        referenced.downcast_ref::<PrincipalReferenced>(),
        Some(&PrincipalReferenced { id: GROUP_ID.to_string() })
    );
    assert_eq!(
        repository.get(&principals.group.id).await.expect("reload referenced principal"),
        Some(disabled)
    );
}

async fn assert_principal_lifecycle_after_policy_reset<R>(
    repository: &R,
    principals: &ContractPrincipals,
) where
    R: PolicyRepository + PrincipalRepository + Sync,
{
    let reset = Policy { revision: 2, ..Policy::default() };
    repository.compare_and_replace(1, &reset).await.expect("reset policy aggregate");
    assert_eq!(repository.load().await.expect("load reset policy"), reset);
    assert!(repository.delete(&principals.group.id).await.expect("delete unbound group"));
    assert!(repository.delete(&principals.user.id).await.expect("delete unbound user"));
    assert!(repository.delete(&principals.workload.id).await.expect("delete unbound workload"));
    assert!(repository.delete(&principals.partner.id).await.expect("delete partner"));
    assert!(!repository.delete(&principals.partner.id).await.expect("idempotent absent delete"));
}

fn principal(id: &str, issuer: &str, external_id: &str, kind: PrincipalKind) -> Principal {
    Principal {
        id: id.to_string(),
        issuer: issuer.to_string(),
        external_id: external_id.to_string(),
        kind,
        display_name: external_id.to_string(),
        status: PrincipalStatus::Active,
        attributes: BTreeMap::from([("department".to_string(), json!("customer-growth"))]),
    }
}

fn policy() -> Policy {
    Policy {
        id: "default".to_string(),
        revision: 1,
        name: "Customer growth authorization".to_string(),
        description: "Cross-backend normalized IAM contract".to_string(),
        actions: vec![
            Action {
                identifier: "customer-growth.job.read".to_string(),
                description: "Read customer growth jobs".to_string(),
                route_matchers: vec![HttpRouteMatcher {
                    id: "customer-growth-job-read".to_string(),
                    methods: vec!["GET".to_string()],
                    hosts: vec!["growth.example.com".to_string()],
                    path: "/customer-growth/jobs/{job_id}".to_string(),
                    resource_urn: "urn:iam:prod:customer-growth:global:{tenant_id}:workspace/growth/project/acquisition/job/{job_id}".to_string(),
                    parent_urns: Vec::new(),
                }],
            },
            Action {
                identifier: "customer-growth.job.run".to_string(),
                description: "Run customer growth jobs".to_string(),
                route_matchers: Vec::new(),
            },
        ],
        roles: vec![
            Role {
                id: "customer-growth-reader".to_string(),
                name: "Customer Growth Reader".to_string(),
                description: String::new(),
                action_ids: vec!["customer-growth.job.read".to_string()],
            },
            Role {
                id: "customer-growth-runner".to_string(),
                name: "Customer Growth Runner".to_string(),
                description: String::new(),
                action_ids: vec!["customer-growth.job.read".to_string(), "customer-growth.job.run".to_string()],
            },
        ],
        role_bindings: vec![
            RoleBinding {
                id: "01-sensitive-export-deny".to_string(),
                principal_id: USER_ID.to_string(),
                role_id: "customer-growth-reader".to_string(),
                effect: Effect::Deny,
                resource_urn: DENIED_JOB.to_string(),
                conditions: AuthorizationConditionSpec::default(),
            },
            RoleBinding {
                id: "02-growth-team-reader".to_string(),
                principal_id: GROUP_ID.to_string(),
                role_id: "customer-growth-reader".to_string(),
                effect: Effect::Allow,
                resource_urn: "urn:iam:prod:customer-growth:global:example-corp:workspace/growth/project/acquisition/job/*".to_string(),
                conditions: AuthorizationConditionSpec::default(),
            },
            RoleBinding {
                id: "03-growth-scheduler-runner".to_string(),
                principal_id: WORKLOAD_ID.to_string(),
                role_id: "customer-growth-runner".to_string(),
                effect: Effect::Allow,
                resource_urn: ALLOWED_JOB.to_string(),
                conditions: AuthorizationConditionSpec {
                    source_ip: Some(SourceIpConditionSpec {
                        in_cidr: vec!["10.0.0.0/8".to_string()],
                        not_in_cidr: Vec::new(),
                    }),
                    request: RequestConditionSpec {
                        methods: vec!["POST".to_string()],
                        secure_transport: Some(true),
                    },
                    ..AuthorizationConditionSpec::default()
                },
            },
        ],
    }
}

fn request(
    resource_urn: &str,
    principal_id: &str,
    group_principal_ids: &[&str],
    operation: &str,
) -> AuthorizationRequest {
    AuthorizationRequest {
        principal_id: principal_id.to_string(),
        group_principal_ids: group_principal_ids.iter().map(ToString::to_string).collect(),
        action: format!("customer-growth.job.{operation}"),
        resource_urn: ResourceUrn::from_str(resource_urn).expect("resource URN"),
        parent_urns: Vec::new(),
        context: EvaluationContext::default(),
    }
}
