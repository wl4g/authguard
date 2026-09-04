use std::str::FromStr;

use authguard_core::model::SourceIpConditionSpec;
use authguard_core::{
    Action, AuthorizationConditionSpec, AuthorizationRequest, Effect, EvaluationContext, Policy,
    PolicyRuntime, ResourceUrn, Role, RoleBinding,
};
use serde::Deserialize;

const BUSINESS_SCENARIOS: &str = include_str!(
    "../../../use-cases/customer-growth-job-service/config/authorization-scenarios.json"
);

#[derive(Debug, Deserialize)]
struct Fixture {
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
        .scenarios
        .into_iter()
        .filter(|scenario| scenario.conditions.is_some())
        .collect::<Vec<_>>();
    assert!(condition_scenarios.len() >= 10, "condition matrix must remain substantial");

    for scenario in condition_scenarios {
        let role_id = format!("role-{}", scenario.id);
        let policy = Policy {
            actions: vec![Action {
                identifier: scenario.action.clone(),
                description: String::new(),
                route_matchers: Vec::new(),
            }],
            roles: vec![Role {
                id: role_id.clone(),
                name: role_id.clone(),
                description: String::new(),
                action_ids: vec![scenario.action.clone()],
            }],
            role_bindings: vec![RoleBinding {
                id: format!("binding-{}", scenario.id),
                principal_id: scenario.principal_id.clone(),
                role_id,
                effect: Effect::Allow,
                resource_urn: scenario.resource_urn.clone(),
                conditions: scenario.conditions.expect("filtered condition"),
            }],
            ..Policy::default()
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
    let policy = condition_policy(vec![RoleBinding {
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
        RoleBinding {
            id: "allow-office".to_string(),
            principal_id: "analyst".to_string(),
            role_id: "reader".to_string(),
            effect: Effect::Allow,
            resource_urn: urn.to_string(),
            conditions: AuthorizationConditionSpec::default(),
        },
        RoleBinding {
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

fn condition_policy(role_bindings: Vec<RoleBinding>) -> Policy {
    Policy {
        actions: vec![Action {
            identifier: "customer-growth.job.read".to_string(),
            description: String::new(),
            route_matchers: Vec::new(),
        }],
        roles: vec![Role {
            id: "reader".to_string(),
            name: "Reader".to_string(),
            description: String::new(),
            action_ids: vec!["customer-growth.job.read".to_string()],
        }],
        role_bindings,
        ..Policy::default()
    }
}

fn authorize_from_ip(
    runtime: &PolicyRuntime,
    resource_urn: &str,
    source_ip: &str,
) -> authguard_core::AuthorizationDecision {
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
