//! Validated, immutable authorization-policy compilation and evaluation.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use thiserror::Error;

use crate::model::{
    AuthorizationConditions, AuthorizationDecision, AuthorizationRequest, AuthorizationScope,
    Effect, EvaluationContext, IamPolicyInfo, IamRoleBindingInfo, IamRoleInfo, UrnPattern,
};
use authguard_common::utils::{
    resolve_route, CompiledHttpRoute, HttpMappingError, ResolvedHttpRoute,
};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("duplicate action identifier `{0}`")]
    DuplicateAction(String),
    #[error("duplicate role id `{0}`")]
    DuplicateRole(String),
    #[error("duplicate role binding id `{0}`")]
    DuplicateRoleBinding(String),
    #[error("duplicate HTTP route matcher id `{0}`")]
    DuplicateRouteMatcher(String),
    #[error("role `{role_id}` references unknown action `{action_id}`")]
    UnknownAction { role_id: String, action_id: String },
    #[error("role binding `{binding_id}` references unknown role `{role_id}`")]
    UnknownRole { binding_id: String, role_id: String },
    #[error("role binding `{0}` has an empty principal id")]
    InvalidPrincipal(String),
    #[error("role binding `{binding_id}` has invalid Resource URN: {message}")]
    InvalidBindingUrn { binding_id: String, message: String },
    #[error("role binding `{binding_id}` has invalid conditions: {message}")]
    InvalidBindingCondition { binding_id: String, message: String },
    #[error("invalid HTTP route matcher: {0}")]
    InvalidHttpRoute(#[from] HttpMappingError),
}

#[derive(Debug, Clone)]
struct CompiledRoleBinding {
    id: String,
    principal_id: String,
    action_ids: HashSet<String>,
    effect: Effect,
    resource_urn: UrnPattern,
    conditions: AuthorizationConditions,
}

#[derive(Debug, Clone, Default)]
struct AuthorizationEvaluator {
    role_bindings: Vec<CompiledRoleBinding>,
}

impl AuthorizationEvaluator {
    fn new(role_bindings: Vec<CompiledRoleBinding>) -> Self {
        Self { role_bindings }
    }

    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        let groups = request.group_principal_ids.iter().cloned().collect::<HashSet<_>>();
        let mut urns = Vec::with_capacity(1 + request.parent_urns.len());
        urns.push(&request.resource_urn);
        urns.extend(request.parent_urns.iter());

        let mut allow = None;
        for binding in &self.role_bindings {
            if !Self::principal_matches(binding, &request.principal_id, &groups)
                || !binding.resource_urn.matches_any(urns.iter().copied())
                || !binding.action_ids.contains(&request.action)
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

    fn authorization_scope(
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
                || !binding.action_ids.contains(action)
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

    fn principal_matches(
        binding: &CompiledRoleBinding,
        principal_id: &str,
        group_principal_ids: &HashSet<String>,
    ) -> bool {
        binding.principal_id == principal_id || group_principal_ids.contains(&binding.principal_id)
    }
}

#[derive(Debug)]
pub(crate) struct CompiledPolicy {
    policy: IamPolicyInfo,
    evaluator: AuthorizationEvaluator,
    routes: Vec<CompiledHttpRoute>,
}

impl CompiledPolicy {
    fn compile(mut policy: IamPolicyInfo, revision: u64) -> Result<Self, PolicyError> {
        policy.revision = revision;
        Self::validate_unique(
            policy.actions.iter().map(|action| action.identifier.as_str()),
            |id| PolicyError::DuplicateAction(id.to_string()),
        )?;
        Self::validate_unique(policy.roles.iter().map(|role| role.id.as_str()), |id| {
            PolicyError::DuplicateRole(id.to_string())
        })?;
        Self::validate_unique(
            policy.role_bindings.iter().map(|binding| binding.id.as_str()),
            |id| PolicyError::DuplicateRoleBinding(id.to_string()),
        )?;
        Self::validate_unique(
            policy
                .actions
                .iter()
                .flat_map(|action| action.route_matchers.iter())
                .map(|matcher| matcher.id.as_str()),
            |id| PolicyError::DuplicateRouteMatcher(id.to_string()),
        )?;

        let action_ids =
            policy.actions.iter().map(|action| action.identifier.as_str()).collect::<HashSet<_>>();
        for role in &policy.roles {
            for action_id in &role.action_ids {
                if !action_ids.contains(action_id.as_str()) {
                    return Err(PolicyError::UnknownAction {
                        role_id: role.id.clone(),
                        action_id: action_id.clone(),
                    });
                }
            }
        }

        let roles =
            policy.roles.iter().map(|role| (role.id.as_str(), role)).collect::<HashMap<_, _>>();
        let bindings = policy
            .role_bindings
            .iter()
            .map(|binding| compile_role_binding(binding, &roles))
            .collect::<Result<Vec<_>, _>>()?;
        let routes =
            policy
                .actions
                .iter()
                .flat_map(|action| {
                    action.route_matchers.iter().cloned().map(|matcher| {
                        CompiledHttpRoute::compile(action.identifier.clone(), matcher)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
        let evaluator = AuthorizationEvaluator::new(bindings);
        Ok(Self { policy, evaluator, routes })
    }

    fn validate_unique<'a>(
        values: impl IntoIterator<Item = &'a str>,
        error: impl Fn(&str) -> PolicyError,
    ) -> Result<(), PolicyError> {
        let mut seen = HashSet::new();
        for value in values {
            if value.trim().is_empty() || !seen.insert(value) {
                return Err(error(value));
            }
        }
        Ok(())
    }

    #[must_use]
    pub(crate) fn policy(&self) -> &IamPolicyInfo {
        &self.policy
    }

    pub(crate) fn resolve_http_route(
        &self,
        method: &str,
        host: &str,
        path: &str,
        claims: &HashMap<String, String>,
    ) -> Result<ResolvedHttpRoute, HttpMappingError> {
        resolve_route(&self.routes, method, host, path, claims)
    }

    pub(crate) fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self.evaluator.authorize(request)
    }

    pub(crate) fn authorization_scope(
        &self,
        principal_id: &str,
        group_principal_ids: &[String],
        action: &str,
        context: &EvaluationContext,
    ) -> AuthorizationScope {
        self.evaluator.authorization_scope(principal_id, group_principal_ids, action, context)
    }
}

fn compile_role_binding(
    binding: &IamRoleBindingInfo,
    roles: &HashMap<&str, &IamRoleInfo>,
) -> Result<CompiledRoleBinding, PolicyError> {
    if binding.principal_id.trim().is_empty() {
        return Err(PolicyError::InvalidPrincipal(binding.id.clone()));
    }
    let role = roles.get(binding.role_id.as_str()).ok_or_else(|| PolicyError::UnknownRole {
        binding_id: binding.id.clone(),
        role_id: binding.role_id.clone(),
    })?;
    let resource_urn = UrnPattern::from_str(&binding.resource_urn).map_err(|error| {
        PolicyError::InvalidBindingUrn {
            binding_id: binding.id.clone(),
            message: error.to_string(),
        }
    })?;
    let conditions = binding.conditions.compile().map_err(|message| {
        PolicyError::InvalidBindingCondition { binding_id: binding.id.clone(), message }
    })?;
    Ok(CompiledRoleBinding {
        id: binding.id.clone(),
        principal_id: binding.principal_id.clone(),
        action_ids: role.action_ids.iter().cloned().collect(),
        effect: binding.effect,
        resource_urn,
        conditions,
    })
}

/// Atomically readable, validated authorization policy runtime.
#[derive(Debug, Clone)]
pub struct PolicyRuntime {
    current: Arc<RwLock<Arc<CompiledPolicy>>>,
}

impl PolicyRuntime {
    /// Compiles the initial policy into an immutable runtime catalog.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy is invalid.
    pub fn new(policy: IamPolicyInfo) -> Result<Self, PolicyError> {
        let revision = policy.revision.max(1);
        let compiled = Arc::new(CompiledPolicy::compile(policy, revision)?);
        Ok(Self { current: Arc::new(RwLock::new(compiled)) })
    }

    #[must_use]
    pub fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self.catalog().authorize(request)
    }

    #[must_use]
    pub(crate) fn catalog(&self) -> Arc<CompiledPolicy> {
        self.current.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }

    pub(super) fn prepare_replacement(
        policy: IamPolicyInfo,
        revision: u64,
    ) -> Result<Arc<CompiledPolicy>, PolicyError> {
        CompiledPolicy::compile(policy, revision).map(Arc::new)
    }

    pub(super) fn install(&self, compiled: Arc<CompiledPolicy>) {
        *self.current.write().unwrap_or_else(std::sync::PoisonError::into_inner) = compiled;
    }
}

#[cfg(test)]
mod tests {
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
}
