//! `AuthGuard` control-plane authorization catalog handlers.
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AuthorizationDecision, AuthorizationRequest, EvaluationContext, IamActionInfo, IamPolicyInfo,
    IamRoleBindingInfo, IamRoleInfo, PrincipalStatus, ResourceUrn, UrnPattern,
};
use crate::storage::{PolicyRepository, PrincipalRepository};
use authguard_common::apm::metrics::AuthzMetrics;
use authguard_common::utils::{
    resolve_route, CompiledHttpRoute, HttpMappingError, ResolvedHttpRoute,
};

use crate::handler::envoy_authz::{AuthorizationEvaluator, CompiledRoleBinding};

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

        let role_ids = policy.roles.iter().map(|role| role.id.as_str()).collect::<HashSet<_>>();
        let bindings = policy
            .role_bindings
            .iter()
            .map(|binding| compile_role_binding(binding, &role_ids))
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
        let evaluator = AuthorizationEvaluator::new(policy.roles.clone(), bindings);
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

    #[must_use]
    pub(crate) fn evaluator(&self) -> &AuthorizationEvaluator {
        &self.evaluator
    }

    pub(crate) fn resolve_http_route(
        &self,
        method: &str,
        host: &str,
        path: &str,
        claims: &std::collections::HashMap<String, String>,
    ) -> Result<ResolvedHttpRoute, HttpMappingError> {
        resolve_route(&self.routes, method, host, path, claims)
    }
}

fn compile_role_binding(
    binding: &IamRoleBindingInfo,
    roles: &HashSet<&str>,
) -> Result<CompiledRoleBinding, PolicyError> {
    if binding.principal_id.trim().is_empty() {
        return Err(PolicyError::InvalidPrincipal(binding.id.clone()));
    }
    if !roles.contains(binding.role_id.as_str()) {
        return Err(PolicyError::UnknownRole {
            binding_id: binding.id.clone(),
            role_id: binding.role_id.clone(),
        });
    }
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
        role_id: binding.role_id.clone(),
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
        self.catalog().evaluator().authorize(request)
    }

    #[must_use]
    pub(crate) fn catalog(&self) -> Arc<CompiledPolicy> {
        self.current.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }

    fn prepare_replacement(
        policy: IamPolicyInfo,
        revision: u64,
    ) -> Result<Arc<CompiledPolicy>, PolicyError> {
        CompiledPolicy::compile(policy, revision).map(Arc::new)
    }

    fn install(&self, compiled: Arc<CompiledPolicy>) {
        *self.current.write().unwrap_or_else(std::sync::PoisonError::into_inner) = compiled;
    }
}

#[derive(Clone)]
pub struct PolicyHandler {
    runtime: PolicyRuntime,
    repository: Arc<dyn PolicyRepository>,
    principals: Arc<dyn PrincipalRepository>,
    metrics: AuthzMetrics,
    write_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub principal_id: String,
    #[serde(default)]
    pub group_principal_ids: Vec<String>,
    pub action: String,
    pub resource_urn: String,
    #[serde(default)]
    pub parent_urns: Vec<String>,
    #[serde(default)]
    pub context: EvaluationContext,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizeResponse {
    pub allowed: bool,
    pub reason: String,
    pub role_binding_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationStatus {
    pub status: &'static str,
    pub policy_revision: u64,
    pub actions: usize,
    pub roles: usize,
    pub role_bindings: usize,
    pub route_matchers: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceCollection<T> {
    pub policy_revision: u64,
    pub total: usize,
    pub items: Vec<T>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceItem<T> {
    pub policy_revision: u64,
    pub resource: T,
}

#[derive(Debug, Error)]
pub enum PolicyHandlerError {
    #[error("{resource} `{id}` already exists")]
    AlreadyExists { resource: &'static str, id: String },
    #[error("{resource} `{id}` was not found")]
    NotFound { resource: &'static str, id: String },
    #[error("path {resource} id `{path_id}` does not match body id `{body_id}`")]
    IdMismatch { resource: &'static str, path_id: String, body_id: String },
    #[error("principal `{0}` is disabled")]
    PrincipalDisabled(String),
    #[error("{resource} `{id}` is still referenced by {referenced_by}")]
    Referenced { resource: &'static str, id: String, referenced_by: &'static str },
    #[error("policy revision conflict: expected {expected}, persisted revision is {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("invalid authorization request: {0}")]
    InvalidRequest(String),
    #[error("principal `{0}` is not active")]
    AuthorizationPrincipalInactive(String),
    #[error("invalid authorization policy: {0}")]
    InvalidPolicy(#[from] PolicyError),
    #[error("authorization storage unavailable: {0}")]
    Storage(#[source] anyhow::Error),
}

impl PolicyHandler {
    #[must_use]
    pub fn new(
        runtime: PolicyRuntime,
        repository: Arc<dyn PolicyRepository>,
        principals: Arc<dyn PrincipalRepository>,
        metrics: AuthzMetrics,
    ) -> Self {
        Self {
            runtime,
            repository,
            principals,
            metrics,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Loads the active policy and initializes the immutable runtime catalog.
    ///
    /// # Errors
    ///
    /// Returns a storage or policy-validation error.
    pub async fn open(
        repository: Arc<dyn PolicyRepository>,
        principals: Arc<dyn PrincipalRepository>,
        metrics: AuthzMetrics,
        bootstrap_policy: Option<IamPolicyInfo>,
    ) -> Result<Self, PolicyHandlerError> {
        let stored = repository.load().await.map_err(PolicyHandlerError::Storage)?;
        let initialize = stored.actions.is_empty()
            && stored.roles.is_empty()
            && stored.role_bindings.is_empty()
            && bootstrap_policy.is_some();
        let policy = match (initialize, bootstrap_policy) {
            (true, Some(policy)) => policy,
            _ => stored,
        };
        let runtime = PolicyRuntime::new(policy)?;
        let normalized = runtime.catalog();
        if initialize {
            repository.replace(normalized.policy()).await.map_err(PolicyHandlerError::Storage)?;
        }
        metrics.set_policy_revision(normalized.policy().revision);
        tracing::debug!(
            authguard.policy.revision = normalized.policy().revision,
            authguard.policy.bootstrap_applied = initialize,
            authguard.policy.action_count = normalized.policy().actions.len(),
            authguard.policy.role_count = normalized.policy().roles.len(),
            authguard.policy.role_binding_count = normalized.policy().role_bindings.len(),
            "authorization policy catalog loaded from storage"
        );
        Ok(Self::new(runtime, repository, principals, metrics))
    }

    #[must_use]
    pub fn catalog(&self) -> IamPolicyInfo {
        self.runtime.catalog().policy().clone()
    }

    #[must_use]
    pub fn actions(&self) -> ResourceCollection<IamActionInfo> {
        let catalog = self.catalog();
        ResourceCollection {
            policy_revision: catalog.revision,
            total: catalog.actions.len(),
            items: catalog.actions,
        }
    }

    #[must_use]
    pub fn roles(&self) -> ResourceCollection<IamRoleInfo> {
        let catalog = self.catalog();
        ResourceCollection {
            policy_revision: catalog.revision,
            total: catalog.roles.len(),
            items: catalog.roles,
        }
    }

    #[must_use]
    pub fn role_bindings(&self) -> ResourceCollection<IamRoleBindingInfo> {
        let catalog = self.catalog();
        ResourceCollection {
            policy_revision: catalog.revision,
            total: catalog.role_bindings.len(),
            items: catalog.role_bindings,
        }
    }

    #[must_use]
    pub fn role_binding(&self, id: &str) -> Option<IamRoleBindingInfo> {
        self.catalog().role_bindings.into_iter().find(|binding| binding.id == id)
    }

    #[must_use]
    pub fn action(&self, id: &str) -> Option<IamActionInfo> {
        self.catalog().actions.into_iter().find(|action| action.identifier == id)
    }

    #[must_use]
    pub fn role(&self, id: &str) -> Option<IamRoleInfo> {
        self.catalog().roles.into_iter().find(|role| role.id == id)
    }

    /// Returns one action and the current catalog revision.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyHandlerError::NotFound`] when the action does not exist.
    pub fn action_item(&self, id: &str) -> Result<ResourceItem<IamActionInfo>, PolicyHandlerError> {
        let catalog = self.catalog();
        let resource = catalog
            .actions
            .into_iter()
            .find(|action| action.identifier == id)
            .ok_or_else(|| Self::not_found("action", id))?;
        Ok(ResourceItem { policy_revision: catalog.revision, resource })
    }

    /// Returns one role and the current catalog revision.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyHandlerError::NotFound`] when the role does not exist.
    pub fn role_item(&self, id: &str) -> Result<ResourceItem<IamRoleInfo>, PolicyHandlerError> {
        let catalog = self.catalog();
        let resource = catalog
            .roles
            .into_iter()
            .find(|role| role.id == id)
            .ok_or_else(|| Self::not_found("role", id))?;
        Ok(ResourceItem { policy_revision: catalog.revision, resource })
    }

    /// Returns one role binding and the current catalog revision.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyHandlerError::NotFound`] when the binding does not exist.
    pub fn role_binding_item(
        &self,
        id: &str,
    ) -> Result<ResourceItem<IamRoleBindingInfo>, PolicyHandlerError> {
        let catalog = self.catalog();
        let resource = catalog
            .role_bindings
            .into_iter()
            .find(|binding| binding.id == id)
            .ok_or_else(|| Self::not_found("role binding", id))?;
        Ok(ResourceItem { policy_revision: catalog.revision, resource })
    }

    #[must_use]
    pub fn status(&self) -> AuthorizationStatus {
        let catalog = self.catalog();
        AuthorizationStatus {
            status: "ok",
            policy_revision: catalog.revision,
            actions: catalog.actions.len(),
            roles: catalog.roles.len(),
            role_bindings: catalog.role_bindings.len(),
            route_matchers: catalog.actions.iter().map(|action| action.route_matchers.len()).sum(),
        }
    }

    /// Validates and evaluates one control-plane authorization request.
    ///
    /// # Errors
    ///
    /// Returns a validation, inactive-principal, or storage error.
    pub async fn authorize_request(
        &self,
        request: AuthorizeRequest,
    ) -> Result<AuthorizeResponse, PolicyHandlerError> {
        let started = Instant::now();
        if request.principal_id.trim().is_empty()
            || request.action.trim().is_empty()
            || request.resource_urn.trim().is_empty()
        {
            return Err(PolicyHandlerError::InvalidRequest(
                "principal_id, action, and resource_urn are required".to_string(),
            ));
        }
        let resource_urn = ResourceUrn::from_str(&request.resource_urn)
            .map_err(|error| PolicyHandlerError::InvalidRequest(error.to_string()))?;
        let parent_urns = request
            .parent_urns
            .iter()
            .map(|urn| ResourceUrn::from_str(urn))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| PolicyHandlerError::InvalidRequest(error.to_string()))?;
        let principal = self
            .principals
            .get(&request.principal_id)
            .await
            .map_err(PolicyHandlerError::Storage)?;
        if !principal.is_some_and(|principal| principal.status == PrincipalStatus::Active) {
            return Err(PolicyHandlerError::AuthorizationPrincipalInactive(request.principal_id));
        }
        let request = AuthorizationRequest {
            principal_id: request.principal_id,
            group_principal_ids: request.group_principal_ids,
            action: request.action,
            resource_urn,
            parent_urns,
            context: request.context,
        };
        let decision = self.authorize(&request);
        self.metrics.record_authorization(
            decision.allowed,
            &decision.reason,
            started.elapsed().as_secs_f64(),
        );
        tracing::info!(
            authguard.decision = if decision.allowed { "allow" } else { "deny" },
            authguard.reason = %decision.reason,
            authguard.principal_id = %request.principal_id,
            authguard.principal_group_count = request.group_principal_ids.len(),
            authguard.action = %request.action,
            authguard.resource_service = %request.resource_urn.service,
            authguard.role_binding_id = decision.role_binding_id.as_deref().unwrap_or("none"),
            duration_seconds = started.elapsed().as_secs_f64(),
            "control-plane authorization evaluation completed"
        );
        Ok(AuthorizeResponse {
            allowed: decision.allowed,
            reason: decision.reason,
            role_binding_id: decision.role_binding_id,
        })
    }

    /// Creates one role binding after validating its Principal reference.
    ///
    /// # Errors
    ///
    /// Returns a conflict, validation, or storage error without partial publication.
    pub async fn create_role_binding(
        &self,
        expected_revision: u64,
        binding: IamRoleBindingInfo,
    ) -> Result<(u64, IamRoleBindingInfo), PolicyHandlerError> {
        self.require_active_principal(&binding.principal_id).await?;
        let response = binding.clone();
        let revision = self
            .mutate(expected_revision, move |policy| {
                Self::ensure_absent(
                    policy.role_bindings.iter().map(|item| item.id.as_str()),
                    "role binding",
                    &binding.id,
                )?;
                policy.role_bindings.push(binding);
                Ok(())
            })
            .await?
            .revision;
        Ok((revision, response))
    }

    /// Replaces one role binding.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, not-found, validation, or storage error.
    pub async fn update_role_binding(
        &self,
        expected_revision: u64,
        id: &str,
        binding: IamRoleBindingInfo,
    ) -> Result<(u64, IamRoleBindingInfo), PolicyHandlerError> {
        Self::ensure_matching_id("role binding", id, &binding.id)?;
        self.require_active_principal(&binding.principal_id).await?;
        let id = id.to_string();
        let response = binding.clone();
        let revision = self
            .mutate(expected_revision, move |policy| {
                let current = policy
                    .role_bindings
                    .iter_mut()
                    .find(|candidate| candidate.id == id)
                    .ok_or_else(|| Self::not_found("role binding", &id))?;
                *current = binding;
                Ok(())
            })
            .await?
            .revision;
        Ok((revision, response))
    }

    /// Deletes one role binding.
    ///
    /// # Errors
    ///
    /// Returns not-found or storage errors.
    pub async fn delete_role_binding(
        &self,
        expected_revision: u64,
        id: &str,
    ) -> Result<u64, PolicyHandlerError> {
        let id = id.to_string();
        Ok(self
            .mutate(expected_revision, move |policy| {
                Self::remove_by_id("role binding", &mut policy.role_bindings, &id, |item| &item.id)
            })
            .await?
            .revision)
    }

    /// Creates one action definition.
    ///
    /// # Errors
    ///
    /// Returns a conflict, validation, or storage error.
    pub async fn create_action(
        &self,
        expected_revision: u64,
        action: IamActionInfo,
    ) -> Result<(u64, IamActionInfo), PolicyHandlerError> {
        let response = action.clone();
        let revision = self
            .mutate(expected_revision, move |policy| {
                Self::ensure_absent(
                    policy.actions.iter().map(|item| item.identifier.as_str()),
                    "action",
                    &action.identifier,
                )?;
                policy.actions.push(action);
                Ok(())
            })
            .await?
            .revision;
        Ok((revision, response))
    }

    /// Replaces one action definition.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, not-found, validation, or storage error.
    pub async fn update_action(
        &self,
        expected_revision: u64,
        id: &str,
        action: IamActionInfo,
    ) -> Result<(u64, IamActionInfo), PolicyHandlerError> {
        Self::ensure_matching_id("action", id, &action.identifier)?;
        let id = id.to_string();
        let response = action.clone();
        let revision = self
            .mutate(expected_revision, move |policy| {
                let current = policy
                    .actions
                    .iter_mut()
                    .find(|candidate| candidate.identifier == id)
                    .ok_or_else(|| Self::not_found("action", &id))?;
                *current = action;
                Ok(())
            })
            .await?
            .revision;
        Ok((revision, response))
    }

    /// Deletes one unreferenced action definition.
    ///
    /// # Errors
    ///
    /// Returns not-found, validation, or storage errors. A referenced action is rejected.
    pub async fn delete_action(
        &self,
        expected_revision: u64,
        id: &str,
    ) -> Result<u64, PolicyHandlerError> {
        let id = id.to_string();
        Ok(self
            .mutate(expected_revision, move |policy| {
                if policy.roles.iter().any(|role| role.action_ids.contains(&id)) {
                    return Err(PolicyHandlerError::Referenced {
                        resource: "action",
                        id,
                        referenced_by: "a role",
                    });
                }
                Self::remove_by_id("action", &mut policy.actions, &id, |item| &item.identifier)
            })
            .await?
            .revision)
    }

    /// Creates one role.
    ///
    /// # Errors
    ///
    /// Returns a conflict, validation, or storage error.
    pub async fn create_role(
        &self,
        expected_revision: u64,
        role: IamRoleInfo,
    ) -> Result<(u64, IamRoleInfo), PolicyHandlerError> {
        let response = role.clone();
        let revision = self
            .mutate(expected_revision, move |policy| {
                Self::ensure_absent(
                    policy.roles.iter().map(|item| item.id.as_str()),
                    "role",
                    &role.id,
                )?;
                policy.roles.push(role);
                Ok(())
            })
            .await?
            .revision;
        Ok((revision, response))
    }

    /// Replaces one role.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, not-found, validation, or storage error.
    pub async fn update_role(
        &self,
        expected_revision: u64,
        id: &str,
        role: IamRoleInfo,
    ) -> Result<(u64, IamRoleInfo), PolicyHandlerError> {
        Self::ensure_matching_id("role", id, &role.id)?;
        let id = id.to_string();
        let response = role.clone();
        let revision = self
            .mutate(expected_revision, move |policy| {
                let current = policy
                    .roles
                    .iter_mut()
                    .find(|candidate| candidate.id == id)
                    .ok_or_else(|| Self::not_found("role", &id))?;
                *current = role;
                Ok(())
            })
            .await?
            .revision;
        Ok((revision, response))
    }

    /// Deletes one unreferenced role.
    ///
    /// # Errors
    ///
    /// Returns not-found, validation, or storage errors. A referenced role is rejected.
    pub async fn delete_role(
        &self,
        expected_revision: u64,
        id: &str,
    ) -> Result<u64, PolicyHandlerError> {
        let id = id.to_string();
        Ok(self
            .mutate(expected_revision, move |policy| {
                if policy.role_bindings.iter().any(|binding| binding.role_id == id) {
                    return Err(PolicyHandlerError::Referenced {
                        resource: "role",
                        id,
                        referenced_by: "a role binding",
                    });
                }
                Self::remove_by_id("role", &mut policy.roles, &id, |item| &item.id)
            })
            .await?
            .revision)
    }

    /// Atomically validates and replaces the complete policy using revision CAS.
    ///
    /// # Errors
    ///
    /// Returns validation, revision-conflict, or storage errors.
    pub async fn replace(
        &self,
        expected_revision: u64,
        policy: IamPolicyInfo,
    ) -> Result<IamPolicyInfo, PolicyHandlerError> {
        if expected_revision != policy.revision {
            return Err(PolicyHandlerError::InvalidRequest(
                "If-Match must equal the policy revision in the request body".to_string(),
            ));
        }
        let _guard = self.write_lock.lock().await;
        self.require_revision(expected_revision)?;
        self.require_active_binding_principals(&policy).await?;
        self.persist_and_publish(expected_revision, policy).await
    }

    /// Clears every action, role, and role binding in one transaction.
    ///
    /// # Errors
    ///
    /// Returns a revision-conflict or storage error without publishing a partial catalog.
    pub async fn reset(&self, expected_revision: u64) -> Result<u64, PolicyHandlerError> {
        let replacement = self
            .mutate(expected_revision, |policy| {
                policy.actions.clear();
                policy.roles.clear();
                policy.role_bindings.clear();
                Ok(())
            })
            .await?;
        Ok(replacement.revision)
    }

    #[must_use]
    pub fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self.runtime.authorize(request)
    }

    #[must_use]
    pub(crate) fn compiled_catalog(&self) -> Arc<CompiledPolicy> {
        self.runtime.catalog()
    }

    /// Verifies durable authorization storage connectivity.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository cannot be reached.
    pub async fn readiness(&self) -> anyhow::Result<()> {
        self.repository.ping().await?;
        Ok(())
    }

    async fn require_active_principal(&self, id: &str) -> Result<(), PolicyHandlerError> {
        let principal = self
            .principals
            .get(id)
            .await
            .map_err(PolicyHandlerError::Storage)?
            .ok_or_else(|| Self::not_found("principal", id))?;
        if principal.status == PrincipalStatus::Disabled {
            return Err(PolicyHandlerError::PrincipalDisabled(id.to_string()));
        }
        Ok(())
    }

    async fn require_active_binding_principals(
        &self,
        policy: &IamPolicyInfo,
    ) -> Result<(), PolicyHandlerError> {
        let mut principal_ids = policy
            .role_bindings
            .iter()
            .map(|binding| binding.principal_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        while let Some(principal_id) = principal_ids.pop_first() {
            self.require_active_principal(principal_id).await?;
        }
        Ok(())
    }

    async fn mutate(
        &self,
        expected_revision: u64,
        mutation: impl FnOnce(&mut IamPolicyInfo) -> Result<(), PolicyHandlerError>,
    ) -> Result<IamPolicyInfo, PolicyHandlerError> {
        let _guard = self.write_lock.lock().await;
        let current = self.require_revision(expected_revision)?;
        let mut replacement = current;
        mutation(&mut replacement)?;
        self.persist_and_publish(expected_revision, replacement).await
    }

    async fn persist_and_publish(
        &self,
        expected_revision: u64,
        policy: IamPolicyInfo,
    ) -> Result<IamPolicyInfo, PolicyHandlerError> {
        let replacement_revision = expected_revision.checked_add(1).ok_or_else(|| {
            PolicyHandlerError::Storage(anyhow::anyhow!("policy revision overflow"))
        })?;
        let catalog =
            PolicyRuntime::prepare_replacement(policy, replacement_revision).map_err(|error| {
                self.metrics.record_policy_reload(false);
                tracing::warn!(
                    authguard.policy.expected_revision = expected_revision,
                    authguard.policy.replacement_revision = replacement_revision,
                    %error,
                    "rejected invalid authorization policy mutation"
                );
                PolicyHandlerError::InvalidPolicy(error)
            })?;
        self.repository.replace(catalog.policy()).await.map_err(|error| {
            tracing::error!(
                authguard.policy.expected_revision = expected_revision,
                %error,
                "failed to persist authorization catalog mutation"
            );
            PolicyHandlerError::Storage(error)
        })?;
        self.runtime.install(catalog.clone());
        self.metrics.record_policy_reload(true);
        self.metrics.set_policy_revision(catalog.policy().revision);
        tracing::info!(
            authguard.policy.previous_revision = expected_revision,
            authguard.policy.revision = catalog.policy().revision,
            authguard.policy.action_count = catalog.policy().actions.len(),
            authguard.policy.role_count = catalog.policy().roles.len(),
            authguard.policy.role_binding_count = catalog.policy().role_bindings.len(),
            "authorization policy mutation persisted and published"
        );
        Ok(catalog.policy().clone())
    }

    fn require_revision(
        &self,
        expected_revision: u64,
    ) -> Result<IamPolicyInfo, PolicyHandlerError> {
        let current = self.catalog();
        if current.revision != expected_revision {
            tracing::warn!(
                authguard.policy.expected_revision = expected_revision,
                authguard.policy.runtime_revision = current.revision,
                "rejected stale authorization policy mutation"
            );
            return Err(PolicyHandlerError::RevisionConflict {
                expected: expected_revision,
                actual: current.revision,
            });
        }
        Ok(current)
    }

    fn ensure_absent<'a>(
        ids: impl IntoIterator<Item = &'a str>,
        resource: &'static str,
        id: &str,
    ) -> Result<(), PolicyHandlerError> {
        if ids.into_iter().any(|candidate| candidate == id) {
            return Err(PolicyHandlerError::AlreadyExists { resource, id: id.to_string() });
        }
        Ok(())
    }

    fn ensure_matching_id(
        resource: &'static str,
        path_id: &str,
        body_id: &str,
    ) -> Result<(), PolicyHandlerError> {
        if path_id == body_id {
            return Ok(());
        }
        Err(PolicyHandlerError::IdMismatch {
            resource,
            path_id: path_id.to_string(),
            body_id: body_id.to_string(),
        })
    }

    fn not_found(resource: &'static str, id: &str) -> PolicyHandlerError {
        PolicyHandlerError::NotFound { resource, id: id.to_string() }
    }

    fn remove_by_id<T>(
        resource: &'static str,
        values: &mut Vec<T>,
        id: &str,
        value_id: impl Fn(&T) -> &str,
    ) -> Result<(), PolicyHandlerError> {
        let previous_len = values.len();
        values.retain(|value| value_id(value) != id);
        if values.len() == previous_len {
            return Err(Self::not_found(resource, id));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AuthorizationConditionSpec, Effect};

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
