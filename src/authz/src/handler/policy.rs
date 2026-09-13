//! `AuthGuard` control-plane authorization catalog CRUD handlers.
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AuthorizationDecision, AuthorizationRequest, EvaluationContext, IamActionInfo, IamPolicyInfo,
    IamRoleBindingInfo, IamRoleInfo, PrincipalStatus, ResourceUrn,
};
use crate::storage::{PolicyRepository, PrincipalRepository};
use authguard_common::apm::metrics::AuthzMetrics;

mod runtime;

use runtime::CompiledPolicy;
pub use runtime::{PolicyError, PolicyRuntime};

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

impl<T> ResourceCollection<T> {
    fn new(policy_revision: u64, items: Vec<T>) -> Self {
        Self { policy_revision, total: items.len(), items }
    }
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
        ResourceCollection::new(catalog.revision, catalog.actions)
    }

    #[must_use]
    pub fn roles(&self) -> ResourceCollection<IamRoleInfo> {
        let catalog = self.catalog();
        ResourceCollection::new(catalog.revision, catalog.roles)
    }

    #[must_use]
    pub fn role_bindings(&self) -> ResourceCollection<IamRoleBindingInfo> {
        let catalog = self.catalog();
        ResourceCollection::new(catalog.revision, catalog.role_bindings)
    }

    /// Returns one action and the current catalog revision.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyHandlerError::NotFound`] when the action does not exist.
    pub fn action_item(&self, id: &str) -> Result<ResourceItem<IamActionInfo>, PolicyHandlerError> {
        let catalog = self.catalog();
        Self::find_item(catalog.revision, catalog.actions, "action", id, |item| &item.identifier)
    }

    /// Returns one role and the current catalog revision.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyHandlerError::NotFound`] when the role does not exist.
    pub fn role_item(&self, id: &str) -> Result<ResourceItem<IamRoleInfo>, PolicyHandlerError> {
        let catalog = self.catalog();
        Self::find_item(catalog.revision, catalog.roles, "role", id, |item| &item.id)
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
        Self::find_item(catalog.revision, catalog.role_bindings, "role binding", id, |item| {
            &item.id
        })
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

    fn find_item<T>(
        policy_revision: u64,
        items: Vec<T>,
        resource: &'static str,
        id: &str,
        item_id: impl Fn(&T) -> &str,
    ) -> Result<ResourceItem<T>, PolicyHandlerError> {
        items
            .into_iter()
            .find(|item| item_id(item) == id)
            .map(|resource| ResourceItem { policy_revision, resource })
            .ok_or_else(|| Self::not_found(resource, id))
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
