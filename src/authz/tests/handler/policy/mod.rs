use super::*;
use crate::model::{AuthorizationConditionSpec, IamActionInfo, IamRoleBindingInfo};

#[test]
fn rejected_replacement_keeps_previous_policy() {
    let runtime = PolicyRuntime::new(IamPolicyInfo::default()).expect("runtime");
    let invalid = IamPolicyInfo {
        actions: vec![IamActionInfo {
            identifier: "job.read".to_string(),
            description: String::new(),
            route_matchers: Vec::new(),
        }],
        roles: vec![IamRoleInfo {
            id: "reader".to_string(),
            name: "Reader".to_string(),
            description: String::new(),
            action_ids: vec!["job.read".to_string()],
        }],
        role_bindings: vec![IamRoleBindingInfo {
            id: "binding-1".to_string(),
            principal_id: "principal-1".to_string(),
            role_id: "reader".to_string(),
            effect: Effect::Allow,
            resource_urn: "invalid".to_string(),
            conditions: AuthorizationConditionSpec::default(),
        }],
        ..IamPolicyInfo::default()
    };
    assert!(PolicyRuntime::prepare_replacement(invalid, 2).is_err());
    assert_eq!(runtime.catalog().policy().revision, 1);
}
