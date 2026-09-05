use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::apm::MetricsRegistry;
use crate::model::{
    Action, AuthorizationDecision, AuthorizationRequest, Policy, PrincipalStatus, Role,
    RoleBinding, UrnPattern,
};
use crate::storage::{PolicyRepository, PolicyRevisionConflict, PrincipalRepository};
use crate::utils::{resolve_route, CompiledHttpRoute, HttpMappingError, ResolvedHttpRoute};

use super::authorization::{AuthorizationEvaluator, CompiledRoleBinding};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy id and name must not be empty")]
    InvalidPolicyIdentity,
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
pub(super) struct CompiledPolicy {
    policy: Policy,
    evaluator: AuthorizationEvaluator,
    routes: Vec<CompiledHttpRoute>,
}

impl CompiledPolicy {
    fn compile(mut policy: Policy, revision: u64) -> Result<Self, PolicyError> {
        policy.revision = revision;
        if policy.id.trim().is_empty() || policy.name.trim().is_empty() {
            return Err(PolicyError::InvalidPolicyIdentity);
        }
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
            .map(|binding| binding.compile(&role_ids))
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
    pub(super) fn policy(&self) -> &Policy {
        &self.policy
    }

    #[must_use]
    pub(super) fn evaluator(&self) -> &AuthorizationEvaluator {
        &self.evaluator
    }

    pub(super) fn resolve_http_route(
        &self,
        method: &str,
        host: &str,
        path: &str,
        claims: &std::collections::HashMap<String, String>,
    ) -> Result<ResolvedHttpRoute, HttpMappingError> {
        resolve_route(&self.routes, method, host, path, claims)
    }
}

impl RoleBinding {
    fn compile(&self, roles: &HashSet<&str>) -> Result<CompiledRoleBinding, PolicyError> {
        if self.principal_id.trim().is_empty() {
            return Err(PolicyError::InvalidPrincipal(self.id.clone()));
        }
        if !roles.contains(self.role_id.as_str()) {
            return Err(PolicyError::UnknownRole {
                binding_id: self.id.clone(),
                role_id: self.role_id.clone(),
            });
        }
        let resource_urn = UrnPattern::from_str(&self.resource_urn).map_err(|error| {
            PolicyError::InvalidBindingUrn {
                binding_id: self.id.clone(),
                message: error.to_string(),
            }
        })?;
        let conditions = self.conditions.compile().map_err(|message| {
            PolicyError::InvalidBindingCondition { binding_id: self.id.clone(), message }
        })?;
        Ok(CompiledRoleBinding {
            id: self.id.clone(),
            principal_id: self.principal_id.clone(),
            role_id: self.role_id.clone(),
            effect: self.effect,
            resource_urn,
            conditions,
        })
    }
}

/// Atomically readable, validated authorization policy runtime.
#[derive(Debug, Clone)]
pub struct PolicyRuntime {
    current: Arc<RwLock<Arc<CompiledPolicy>>>,
}

impl PolicyRuntime {
    /// Compiles the initial policy into an immutable runtime snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy is invalid.
    pub fn new(policy: Policy) -> Result<Self, PolicyError> {
        let revision = policy.revision.max(1);
        let compiled = Arc::new(CompiledPolicy::compile(policy, revision)?);
        Ok(Self { current: Arc::new(RwLock::new(compiled)) })
    }

    #[must_use]
    pub fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self.snapshot().evaluator().authorize(request)
    }

    #[must_use]
    pub(super) fn snapshot(&self) -> Arc<CompiledPolicy> {
        self.current.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }

    fn prepare_replacement(
        policy: Policy,
        revision: u64,
    ) -> Result<Arc<CompiledPolicy>, PolicyError> {
        CompiledPolicy::compile(policy, revision).map(Arc::new)
    }

    fn prepare_stored(policy: Policy) -> Result<Arc<CompiledPolicy>, PolicyError> {
        let revision = policy.revision.max(1);
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
    metrics: MetricsRegistry,
    write_lock: Arc<tokio::sync::Mutex<()>>,
    last_storage_sync: Arc<Mutex<Instant>>,
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
        metrics: MetricsRegistry,
    ) -> Self {
        Self {
            runtime,
            repository,
            principals,
            metrics,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            last_storage_sync: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Loads the active policy and initializes the immutable runtime snapshot.
    ///
    /// # Errors
    ///
    /// Returns a storage or policy-validation error.
    pub async fn open(
        repository: Arc<dyn PolicyRepository>,
        principals: Arc<dyn PrincipalRepository>,
        metrics: MetricsRegistry,
        bootstrap_policy: Option<Policy>,
    ) -> Result<Self, PolicyHandlerError> {
        let stored = repository.load().await.map_err(PolicyHandlerError::Storage)?;
        let initialize = stored.revision == 0;
        let mut policy = stored;
        if initialize {
            policy = bootstrap_policy.unwrap_or(policy);
        }
        let runtime = PolicyRuntime::new(policy)?;
        let normalized = runtime.snapshot();
        if initialize {
            repository
                .compare_and_replace(0, normalized.policy())
                .await
                .map_err(Self::map_storage_error)?;
        }
        metrics.set_policy_revision(normalized.policy().revision);
        tracing::debug!(
            authguard.policy.revision = normalized.policy().revision,
            authguard.policy.bootstrap_applied = initialize,
            authguard.policy.action_count = normalized.policy().actions.len(),
            authguard.policy.role_count = normalized.policy().roles.len(),
            authguard.policy.role_binding_count = normalized.policy().role_bindings.len(),
            "authorization policy snapshot loaded from storage"
        );
        Ok(Self::new(runtime, repository, principals, metrics))
    }

    #[must_use]
    pub fn snapshot(&self) -> Policy {
        self.runtime.snapshot().policy().clone()
    }

    #[must_use]
    pub fn role_binding(&self, id: &str) -> Option<RoleBinding> {
        self.snapshot().role_bindings.into_iter().find(|binding| binding.id == id)
    }

    #[must_use]
    pub fn action(&self, id: &str) -> Option<Action> {
        self.snapshot().actions.into_iter().find(|action| action.identifier == id)
    }

    #[must_use]
    pub fn role(&self, id: &str) -> Option<Role> {
        self.snapshot().roles.into_iter().find(|role| role.id == id)
    }

    /// Creates one role binding after validating its Principal reference.
    ///
    /// # Errors
    ///
    /// Returns a conflict, validation, or storage error without partial publication.
    pub async fn create_role_binding(
        &self,
        expected_revision: u64,
        binding: RoleBinding,
    ) -> Result<(u64, RoleBinding), PolicyHandlerError> {
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
        binding: RoleBinding,
    ) -> Result<(u64, RoleBinding), PolicyHandlerError> {
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
        action: Action,
    ) -> Result<(u64, Action), PolicyHandlerError> {
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
        action: Action,
    ) -> Result<(u64, Action), PolicyHandlerError> {
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
        role: Role,
    ) -> Result<(u64, Role), PolicyHandlerError> {
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
        role: Role,
    ) -> Result<(u64, Role), PolicyHandlerError> {
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
        policy: Policy,
    ) -> Result<Policy, PolicyHandlerError> {
        let _guard = self.write_lock.lock().await;
        self.require_persisted_revision(expected_revision).await?;
        self.require_active_binding_principals(&policy).await?;
        self.persist_and_publish(expected_revision, policy).await
    }

    /// Clears the singleton policy aggregate using revision CAS.
    ///
    /// The durable singleton row remains present so a subsequent policy can be
    /// created with the same immutable aggregate identifier.
    ///
    /// # Errors
    ///
    /// Returns a revision-conflict or storage error without publishing a partial reset.
    pub async fn reset(&self, expected_revision: u64) -> Result<u64, PolicyHandlerError> {
        let replacement = self
            .mutate(expected_revision, |policy| {
                policy.name = Policy::default().name;
                policy.description.clear();
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
    pub(super) fn compiled_snapshot(&self) -> Arc<CompiledPolicy> {
        self.runtime.snapshot()
    }

    /// Refreshes the active snapshot when storage contains a newer revision.
    ///
    /// # Errors
    ///
    /// Returns storage or validation errors without publishing an invalid policy.
    pub async fn refresh_if_newer(&self) -> Result<bool, PolicyHandlerError> {
        let _guard = self.write_lock.lock().await;
        let policy = self.repository.load().await.map_err(PolicyHandlerError::Storage)?;
        let current_revision = self.snapshot().revision;
        if policy.revision <= current_revision {
            self.mark_storage_sync();
            tracing::debug!(
                authguard.policy.runtime_revision = current_revision,
                authguard.policy.storage_revision = policy.revision,
                "policy refresh found no newer storage revision"
            );
            return Ok(false);
        }
        let snapshot = PolicyRuntime::prepare_stored(policy).map_err(|error| {
            self.metrics.record_policy_reload(false);
            PolicyHandlerError::InvalidPolicy(error)
        })?;
        self.runtime.install(snapshot.clone());
        self.metrics.record_policy_reload(true);
        self.metrics.set_policy_revision(snapshot.policy().revision);
        self.mark_storage_sync();
        tracing::info!(
            authguard.policy.previous_revision = current_revision,
            authguard.policy.revision = snapshot.policy().revision,
            authguard.policy.action_count = snapshot.policy().actions.len(),
            authguard.policy.role_count = snapshot.policy().roles.len(),
            authguard.policy.role_binding_count = snapshot.policy().role_bindings.len(),
            "new authorization policy snapshot installed from storage"
        );
        Ok(true)
    }

    /// Verifies durable storage connectivity and policy snapshot freshness.
    ///
    /// # Errors
    ///
    /// Returns an error when storage is unavailable or the refresh loop has not
    /// completed successfully within `max_staleness`.
    pub async fn readiness(&self, max_staleness: Duration) -> anyhow::Result<()> {
        self.repository.ping().await?;
        let age = self.storage_sync_age();
        anyhow::ensure!(
            age <= max_staleness,
            "policy snapshot storage sync is stale: age {:.3}s exceeds {:.3}s",
            age.as_secs_f64(),
            max_staleness.as_secs_f64()
        );
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
        policy: &Policy,
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
        mutation: impl FnOnce(&mut Policy) -> Result<(), PolicyHandlerError>,
    ) -> Result<Policy, PolicyHandlerError> {
        let _guard = self.write_lock.lock().await;
        let current = self.require_persisted_revision(expected_revision).await?;
        let mut replacement = current;
        mutation(&mut replacement)?;
        self.persist_and_publish(expected_revision, replacement).await
    }

    async fn persist_and_publish(
        &self,
        expected_revision: u64,
        policy: Policy,
    ) -> Result<Policy, PolicyHandlerError> {
        let replacement_revision = expected_revision.checked_add(1).ok_or_else(|| {
            PolicyHandlerError::Storage(anyhow::anyhow!("policy revision overflow"))
        })?;
        let snapshot =
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
        self.repository.compare_and_replace(expected_revision, snapshot.policy()).await.map_err(
            |error| {
                let mapped = Self::map_storage_error(error);
                if let PolicyHandlerError::RevisionConflict { expected, actual } = &mapped {
                    tracing::warn!(
                        authguard.policy.expected_revision = expected,
                        authguard.policy.storage_revision = actual,
                        "authorization policy mutation lost its revision race"
                    );
                } else {
                    tracing::error!(
                        authguard.policy.expected_revision = expected_revision,
                        error = %mapped,
                        "failed to persist authorization policy mutation"
                    );
                }
                mapped
            },
        )?;
        self.runtime.install(snapshot.clone());
        self.metrics.record_policy_reload(true);
        self.metrics.set_policy_revision(snapshot.policy().revision);
        self.mark_storage_sync();
        tracing::info!(
            authguard.policy.previous_revision = expected_revision,
            authguard.policy.revision = snapshot.policy().revision,
            authguard.policy.action_count = snapshot.policy().actions.len(),
            authguard.policy.role_count = snapshot.policy().roles.len(),
            authguard.policy.role_binding_count = snapshot.policy().role_bindings.len(),
            "authorization policy mutation persisted and published"
        );
        Ok(snapshot.policy().clone())
    }

    async fn require_persisted_revision(
        &self,
        expected_revision: u64,
    ) -> Result<Policy, PolicyHandlerError> {
        let persisted = self.repository.load().await.map_err(PolicyHandlerError::Storage)?;
        if persisted.revision != expected_revision {
            tracing::warn!(
                authguard.policy.expected_revision = expected_revision,
                authguard.policy.storage_revision = persisted.revision,
                "rejected stale authorization policy mutation"
            );
            return Err(PolicyHandlerError::RevisionConflict {
                expected: expected_revision,
                actual: persisted.revision,
            });
        }
        Ok(persisted)
    }

    fn mark_storage_sync(&self) {
        let mut last_sync =
            self.last_storage_sync.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *last_sync = Instant::now();
    }

    fn storage_sync_age(&self) -> Duration {
        self.last_storage_sync.lock().unwrap_or_else(std::sync::PoisonError::into_inner).elapsed()
    }

    fn map_storage_error(error: anyhow::Error) -> PolicyHandlerError {
        if let Some(conflict) = error.downcast_ref::<PolicyRevisionConflict>() {
            return PolicyHandlerError::RevisionConflict {
                expected: conflict.expected,
                actual: conflict.actual,
            };
        }
        PolicyHandlerError::Storage(error)
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
        let runtime = PolicyRuntime::new(Policy::default()).expect("runtime");
        let invalid = Policy {
            actions: vec![Action {
                identifier: "job.read".to_string(),
                description: String::new(),
                route_matchers: Vec::new(),
            }],
            roles: vec![Role {
                id: "reader".to_string(),
                name: "Reader".to_string(),
                description: String::new(),
                action_ids: vec!["job.read".to_string()],
            }],
            role_bindings: vec![RoleBinding {
                id: "binding-1".to_string(),
                principal_id: "principal-1".to_string(),
                role_id: "reader".to_string(),
                effect: Effect::Allow,
                resource_urn: "invalid".to_string(),
                conditions: AuthorizationConditionSpec::default(),
            }],
            ..Policy::default()
        };
        assert!(PolicyRuntime::prepare_replacement(invalid, 2).is_err());
        assert_eq!(runtime.snapshot().policy().revision, 1);
    }
}
