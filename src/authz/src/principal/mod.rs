//! Optional `AuthZ` control-plane Principal federation and materialization.

mod keycloak;
mod ldap;
mod scim;

use anyhow::Context;
use std::sync::Arc;

use crate::handler::PrincipalHandler;
pub use authguard_common::principal::*;
pub use keycloak::KeycloakPrincipalDiscovery;
pub use ldap::LdapPrincipalDiscovery;
pub use scim::{
    ScimGroupResource, ScimPrincipalDiscovery, ScimProjectionEvent, ScimProvisioningRequest,
    ScimUserResource,
};

pub struct PrincipalDiscoveryComponent {
    handler: PrincipalHandler,
}

impl PrincipalDiscoveryComponent {
    /// Opens enabled control-plane federation connectors and optional SCIM
    /// projection into a ready [`PrincipalHandler`].
    ///
    /// # Errors
    ///
    /// Returns a configuration or credential-file error.
    pub fn new(repository: Arc<dyn crate::storage::PrincipalRepository>) -> anyhow::Result<Self> {
        let app_config = crate::config::AppConfig::get();
        let config = &app_config.get_authz().principal_discovery;
        let mut federated: Vec<Arc<dyn IPrincipalSearchDiscovery>> = Vec::new();
        for keycloak in config.keycloak.iter().filter(|entry| entry.enabled) {
            let secret = Self::credential(
                &keycloak.auth.client_secret,
                &keycloak.auth.client_secret_file,
                "Keycloak client secret",
            )?;
            let provider = KeycloakPrincipalDiscovery::with_client_credentials(
                keycloak,
                &keycloak.auth.client_id,
                secret,
            )
            .context("configure Keycloak IamPrincipalInfo discovery")?;
            Self::add_search_provider(&mut federated, provider)?;
        }
        for ldap in config.ldap.iter().filter(|entry| entry.enabled) {
            let password = Self::credential(
                &ldap.auth.bind_password,
                &ldap.auth.bind_password_file,
                "LDAP bind password",
            )?;
            let mut resolved = ldap.clone();
            resolved.auth.bind_password = password;
            let provider = LdapPrincipalDiscovery::new(&resolved)
                .context("configure LDAP IamPrincipalInfo discovery")?;
            Self::add_search_provider(&mut federated, provider)?;
        }
        for custom in config.custom.iter().filter(|entry| entry.enabled) {
            let token =
                Self::credential(&custom.jwt_token, &custom.jwt_token_file, "custom JWT token")?;
            let mut resolved = custom.clone();
            resolved.jwt_token = token;
            let provider = CustomPrincipalDiscovery::new(&resolved)
                .context("configure HTTP IamPrincipalInfo discovery")?;
            Self::add_search_provider(&mut federated, provider)?;
        }
        let scim = config
            .scim
            .enabled
            .then(|| {
                ScimPrincipalDiscovery::new(
                    config.scim.discovery_id.clone(),
                    config.scim.issuer.clone(),
                )
            })
            .transpose()
            .context("configure SCIM IamPrincipalInfo discovery")?;
        let federated_provider_count = federated.len();
        let handler = PrincipalHandler::new(repository, federated, scim);
        tracing::info!(
            authguard.principal.federated_provider_count = federated_provider_count,
            authguard.principal.scim_enabled = config.scim.enabled,
            "principal discovery providers configured"
        );
        Ok(Self { handler })
    }

    #[must_use]
    pub fn handler(&self) -> PrincipalHandler {
        self.handler.clone()
    }

    /// Adds one search provider, rejecting duplicate protocol identifiers.
    ///
    /// Each `FED_KEYCLOAK`/`FED_LDAP`/`FED_CUSTOM` protocol may be configured
    /// at most once, because search filtering and resolution dispatch on the
    /// protocol identifier.
    fn add_search_provider<T>(
        providers: &mut Vec<Arc<dyn IPrincipalSearchDiscovery>>,
        provider: T,
    ) -> anyhow::Result<()>
    where
        T: IPrincipalDiscovery<PrincipalSearchQuery, Output = PrincipalSearchPage>,
    {
        let protocol = provider.provider();
        if providers.iter().any(|existing| existing.provider() == protocol) {
            anyhow::bail!(PrincipalDiscoveryError::InvalidConfiguration(format!(
                "search provider protocol `{protocol}` is already configured"
            )));
        }
        providers.push(Arc::new(provider));
        Ok(())
    }

    /// Resolves one file-or-inline credential value.
    pub(crate) fn credential(value: &str, file: &str, name: &str) -> anyhow::Result<String> {
        if !value.is_empty() {
            return Ok(value.to_string());
        }
        let value = std::fs::read_to_string(file)
            .with_context(|| format!("read {name} file"))?
            .trim_end_matches(['\r', '\n'])
            .to_string();
        if value.is_empty() {
            return Err(anyhow::anyhow!("{name} file is empty"));
        }
        Ok(value)
    }
}
