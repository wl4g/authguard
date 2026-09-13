use std::time::Instant;

use crate::model::{IamPrincipalInfo, PrincipalKind, PrincipalStatus};
use crate::principal::{
    IPrincipalDiscovery, ScimListQuery, ScimListResponse, ScimPatchRequest, ScimProjectionEvent,
    ScimProvisioningRequest, ScimResource, ScimStoredResource,
};

use super::principal::{PrincipalHandler, PrincipalHandlerError};

impl PrincipalHandler {
    async fn apply_scim_projection(
        &self,
        event: ScimProjectionEvent,
    ) -> Result<Option<IamPrincipalInfo>, PrincipalHandlerError> {
        match event {
            ScimProjectionEvent::Upsert { principal_id, projection } => {
                self.upsert_external(&principal_id, projection, "SCIM").await.map(Some)
            }
            ScimProjectionEvent::Delete { principal_id } => {
                let Some(mut principal) = self.get(&principal_id).await? else {
                    tracing::debug!(
                        authguard.principal.provisioning = "SCIM",
                        authguard.principal.operation = "disable",
                        "SCIM deletion referenced an unknown canonical Principal"
                    );
                    return Ok(None);
                };
                principal.status = PrincipalStatus::Disabled;
                principal
                    .authorization_state
                    .insert("scimDeleted".to_string(), serde_json::Value::Bool(true));
                self.repository
                    .upsert(&principal)
                    .await
                    .map(Some)
                    .map_err(PrincipalHandlerError::Storage)
            }
        }
    }

    /// Normalizes and applies one SCIM provisioning change.
    ///
    /// # Errors
    ///
    /// Returns an error when SCIM is disabled or normalization/persistence fails.
    async fn provision_scim(
        &self,
        mut request: ScimProvisioningRequest,
    ) -> Result<Option<IamPrincipalInfo>, PrincipalHandlerError> {
        let started = Instant::now();
        let discovery = self.scim.as_ref().ok_or(PrincipalHandlerError::ProviderUnavailable)?;
        let principal_id_missing = match &request {
            ScimProvisioningRequest::UpsertUser { principal_id, .. }
            | ScimProvisioningRequest::UpsertGroup { principal_id, .. } => principal_id.is_empty(),
            ScimProvisioningRequest::Delete { .. } => false,
        };
        if principal_id_missing {
            let identity = discovery.upsert_identity_key(&request)?;
            if let Some(principal) = self
                .repository
                .find_by_identity(&identity)
                .await
                .map_err(PrincipalHandlerError::Storage)?
            {
                let already_scim_managed = self
                    .repository
                    .get_identity(&principal.id, &identity.provider)
                    .await
                    .map_err(PrincipalHandlerError::Storage)?
                    .is_some_and(|binding| binding.claims.get("schemas").is_some());
                let is_deleted = principal.authorization_state.get("scimDeleted")
                    == Some(&serde_json::Value::Bool(true));
                if already_scim_managed && !is_deleted {
                    return Err(PrincipalHandlerError::IdentityConflict);
                }
                match &mut request {
                    ScimProvisioningRequest::UpsertUser { principal_id, .. }
                    | ScimProvisioningRequest::UpsertGroup { principal_id, .. } => {
                        principal_id.clone_from(&principal.id);
                    }
                    ScimProvisioningRequest::Delete { .. } => {}
                }
            }
        }
        let (operation, requested_id) = match &request {
            ScimProvisioningRequest::UpsertUser { principal_id, .. } => {
                ("upsert_user", principal_id.clone())
            }
            ScimProvisioningRequest::UpsertGroup { principal_id, .. } => {
                ("upsert_group", principal_id.clone())
            }
            ScimProvisioningRequest::Delete { principal_id } => ("delete", principal_id.clone()),
        };
        tracing::info!(
            event = "authguard.authz.scim_provisioning.started",
            authguard.principal.provisioning = "SCIM",
            authguard.principal.operation = operation,
            authguard.principal_id = %requested_id,
            "SCIM Principal provisioning started"
        );
        let event = discovery.discover(request).await?;
        let principal = self.apply_scim_projection(event).await?;
        let result_id = principal.as_ref().map_or(requested_id.as_str(), |value| value.id.as_str());
        tracing::info!(
            event = "authguard.authz.scim_provisioning.succeeded",
            authguard.principal.provisioning = "SCIM",
            authguard.principal.operation = operation,
            authguard.principal_id = %result_id,
            duration_seconds = started.elapsed().as_secs_f64(),
            "SCIM Principal provisioning completed"
        );
        Ok(principal)
    }

    /// Creates or replaces one SCIM resource and returns its canonical wire projection.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid resource, missing replacement, or storage failure.
    pub(crate) async fn upsert_scim(
        &self,
        principal_id: String,
        resource: ScimResource,
        replace: bool,
    ) -> Result<ScimResource, PrincipalHandlerError> {
        let kind = resource.kind();
        if replace {
            self.get_scim(&principal_id, kind).await?;
        }
        let principal = self
            .provision_scim(resource.into_upsert(principal_id))
            .await?
            .ok_or_else(|| PrincipalHandlerError::NotFound("SCIM resource".to_string()))?;
        self.get_scim(&principal.id, kind).await
    }

    /// Disables one SCIM resource after validating its collection kind.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown resource, kind mismatch, or storage failure.
    pub(crate) async fn delete_scim(
        &self,
        principal_id: &str,
        kind: PrincipalKind,
    ) -> Result<(), PrincipalHandlerError> {
        self.get_scim(principal_id, kind).await?;
        self.provision_scim(ScimProvisioningRequest::Delete {
            principal_id: principal_id.to_string(),
        })
        .await?;
        Ok(())
    }

    /// Reads one SCIM-backed User or Group projection.
    ///
    /// # Errors
    ///
    /// Returns not-found, disabled-provider, corrupt-claim, or storage errors.
    pub(crate) async fn get_scim(
        &self,
        principal_id: &str,
        expected_kind: PrincipalKind,
    ) -> Result<ScimResource, PrincipalHandlerError> {
        let discovery = self.scim.as_ref().ok_or(PrincipalHandlerError::ProviderUnavailable)?;
        let principal = self
            .get(principal_id)
            .await?
            .ok_or_else(|| PrincipalHandlerError::NotFound(principal_id.to_string()))?;
        if principal.authorization_state.get("scimDeleted") == Some(&serde_json::Value::Bool(true))
            || principal.kind != expected_kind
        {
            return Err(PrincipalHandlerError::NotFound(principal_id.to_string()));
        }
        let identity = self
            .repository
            .get_identity(principal_id, discovery.provider_id())
            .await
            .map_err(PrincipalHandlerError::Storage)?
            .ok_or_else(|| PrincipalHandlerError::NotFound(principal_id.to_string()))?;
        discovery
            .restore_resource(ScimStoredResource { principal, claims: identity.claims })
            .map_err(PrincipalHandlerError::Discovery)
    }

    /// Lists all SCIM-backed projections of one resource kind.
    ///
    /// # Errors
    ///
    /// Returns an error when storage is unavailable or persisted claims are invalid.
    pub(crate) async fn list_scim(
        &self,
        expected_kind: PrincipalKind,
        query: &ScimListQuery,
    ) -> Result<ScimListResponse<ScimResource>, PrincipalHandlerError> {
        let discovery = self.scim.as_ref().ok_or(PrincipalHandlerError::ProviderUnavailable)?;
        let mut resources = Vec::new();
        let mut after_id = None;
        loop {
            let page = self
                .repository
                .list("", after_id.as_deref(), 100)
                .await
                .map_err(PrincipalHandlerError::Storage)?;
            if page.is_empty() {
                break;
            }
            after_id = page.last().map(|principal| principal.id.clone());
            let page_len = page.len();
            for principal in page {
                if principal.kind == expected_kind {
                    match self.get_scim(&principal.id, expected_kind).await {
                        Ok(resource) => resources.push(resource),
                        Err(PrincipalHandlerError::NotFound(_)) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            if page_len < 100 {
                break;
            }
        }
        discovery.list_page(resources, query).map_err(PrincipalHandlerError::Discovery)
    }

    /// Applies a supported RFC 7644 PATCH operation and persists the result.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown resource, invalid operation, or storage failure.
    pub(crate) async fn patch_scim(
        &self,
        principal_id: &str,
        expected_kind: PrincipalKind,
        patch: &ScimPatchRequest,
    ) -> Result<ScimResource, PrincipalHandlerError> {
        let discovery = self.scim.as_ref().ok_or(PrincipalHandlerError::ProviderUnavailable)?;
        let current = self.get_scim(principal_id, expected_kind).await?;
        let patched = discovery.patch(&current, patch)?;
        self.provision_scim(patched.into_upsert(principal_id.to_string())).await?;
        self.get_scim(principal_id, expected_kind).await
    }
}
