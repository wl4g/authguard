use std::str::FromStr;

use authguard_authz::model::SourceIpConditionSpec;
use authguard_authz::{
    AuthorizationConditionSpec, AuthorizationRequest, Effect, EvaluationContext, IamActionInfo,
    IamPolicyInfo, IamRoleBindingInfo, IamRoleInfo, PolicyRuntime, ResourceUrn,
};
use serde::Deserialize;

const BUSINESS_SCENARIOS: &str = include_str!(
    "../../../use-cases/customer-growth-job-service/e2e/config/authguard-e2e-scenarios.json"
);

#[derive(Debug, Deserialize)]
struct Fixture {
    authz: AuthorizationFixture,
}

#[derive(Debug, Deserialize)]
struct AuthorizationFixture {
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    id: String,
    principal_id: String,
    action: String,
    resource_urn: String,
    conditions: Option<AuthorizationConditionSpec>,
    #[serde(default)]
    evaluation_context: EvaluationContext,
    gateway_allowed: bool,
}

#[test]
fn shared_business_condition_scenarios_match_gateway_decisions() {
    let fixture: Fixture = serde_json::from_str(BUSINESS_SCENARIOS).expect("business fixture");
    let condition_scenarios = fixture
        .authz
        .scenarios
        .into_iter()
        .filter(|scenario| scenario.conditions.is_some())
        .collect::<Vec<_>>();
    assert!(condition_scenarios.len() >= 10, "condition matrix must remain substantial");

    for scenario in condition_scenarios {
        let role_id = format!("role-{}", scenario.id);
        let policy = IamPolicyInfo {
            actions: vec![IamActionInfo {
                identifier: scenario.action.clone(),
                description: String::new(),
                route_matchers: Vec::new(),
            }],
            roles: vec![IamRoleInfo {
                id: role_id.clone(),
                name: role_id.clone(),
                description: String::new(),
                action_ids: vec![scenario.action.clone()],
            }],
            role_bindings: vec![IamRoleBindingInfo {
                id: format!("binding-{}", scenario.id),
                principal_id: scenario.principal_id.clone(),
                role_id,
                effect: Effect::Allow,
                resource_urn: scenario.resource_urn.clone(),
                conditions: scenario.conditions.expect("filtered condition"),
            }],
            ..IamPolicyInfo::default()
        };
        let decision = PolicyRuntime::new(policy).expect("compiled condition policy").authorize(
            &AuthorizationRequest {
                principal_id: scenario.principal_id,
                group_principal_ids: Vec::new(),
                action: scenario.action,
                resource_urn: ResourceUrn::from_str(&scenario.resource_urn).expect("resource URN"),
                parent_urns: Vec::new(),
                context: scenario.evaluation_context,
            },
        );
        assert_eq!(decision.allowed, scenario.gateway_allowed, "scenario {}", scenario.id);
    }
}

#[test]
fn invalid_cidr_is_rejected_when_policy_is_compiled() {
    let policy = condition_policy(vec![IamRoleBindingInfo {
        id: "invalid-network".to_string(),
        principal_id: "analyst".to_string(),
        role_id: "reader".to_string(),
        effect: Effect::Allow,
        resource_urn: "urn:iam:prod:customer-growth:global:example-corp:**".to_string(),
        conditions: AuthorizationConditionSpec {
            source_ip: Some(SourceIpConditionSpec {
                in_cidr: vec!["10.0.0.0/99".to_string()],
                not_in_cidr: Vec::new(),
            }),
            ..AuthorizationConditionSpec::default()
        },
    }]);

    assert!(PolicyRuntime::new(policy).is_err());
}

#[test]
fn conditional_explicit_deny_only_wins_when_its_network_matches() {
    let urn = "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights";
    let policy = condition_policy(vec![
        IamRoleBindingInfo {
            id: "allow-office".to_string(),
            principal_id: "analyst".to_string(),
            role_id: "reader".to_string(),
            effect: Effect::Allow,
            resource_urn: urn.to_string(),
            conditions: AuthorizationConditionSpec::default(),
        },
        IamRoleBindingInfo {
            id: "deny-quarantined-network".to_string(),
            principal_id: "analyst".to_string(),
            role_id: "reader".to_string(),
            effect: Effect::Deny,
            resource_urn: urn.to_string(),
            conditions: AuthorizationConditionSpec {
                source_ip: Some(SourceIpConditionSpec {
                    in_cidr: vec!["10.99.0.0/16".to_string()],
                    not_in_cidr: Vec::new(),
                }),
                ..AuthorizationConditionSpec::default()
            },
        },
    ]);
    let runtime = PolicyRuntime::new(policy).expect("policy");

    assert!(authorize_from_ip(&runtime, urn, "10.20.1.8").allowed);
    let denied = authorize_from_ip(&runtime, urn, "10.99.1.8");
    assert!(!denied.allowed);
    assert_eq!(denied.reason, "explicit deny");
}

fn condition_policy(role_bindings: Vec<IamRoleBindingInfo>) -> IamPolicyInfo {
    IamPolicyInfo {
        actions: vec![IamActionInfo {
            identifier: "customer-growth.job.read".to_string(),
            description: String::new(),
            route_matchers: Vec::new(),
        }],
        roles: vec![IamRoleInfo {
            id: "reader".to_string(),
            name: "Reader".to_string(),
            description: String::new(),
            action_ids: vec!["customer-growth.job.read".to_string()],
        }],
        role_bindings,
        ..IamPolicyInfo::default()
    }
}

fn authorize_from_ip(
    runtime: &PolicyRuntime,
    resource_urn: &str,
    source_ip: &str,
) -> authguard_authz::AuthorizationDecision {
    runtime.authorize(&AuthorizationRequest {
        principal_id: "analyst".to_string(),
        group_principal_ids: Vec::new(),
        action: "customer-growth.job.read".to_string(),
        resource_urn: ResourceUrn::from_str(resource_urn).expect("resource URN"),
        parent_urns: Vec::new(),
        context: EvaluationContext {
            source_ip: Some(source_ip.parse().expect("source IP")),
            ..EvaluationContext::default()
        },
    })
}
