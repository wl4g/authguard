//! Shared `AuthN` runtime composition without protocol logic.

use std::sync::Arc;

use authguard_common::config::AppConfig;
use authguard_common::storage::{IdentityBindingRepository, StandaloneCredentialRepository};

use crate::challenge::{ChallengeStore, RedisChallengeStore};
use crate::pipeline::AuthenticationPipeline;
use crate::session::SessionIssuer;

#[derive(Clone)]
pub struct AuthnRuntime {
    pub pipeline: Arc<AuthenticationPipeline>,
    pub credentials: Arc<dyn StandaloneCredentialRepository>,
    pub challenges: Option<Arc<dyn ChallengeStore>>,
}

impl AuthnRuntime {
    /// Opens protocol-neutral persistence, challenges, linking, and sessions.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid storage, Redis, or session-key setup.
    pub async fn open() -> anyhow::Result<Self> {
        let config = AppConfig::get();
        let storage = config.get_storage();
        let (identities, credentials): (
            Arc<dyn IdentityBindingRepository>,
            Arc<dyn StandaloneCredentialRepository>,
        ) = match storage.provider.to_ascii_lowercase().as_str() {
            "sqlite" => {
                let repository = Arc::new(
                    authguard_common::storage::AuthnSqliteRepository::connect(&storage.sqlite)
                        .await?,
                );
                (repository.clone(), repository)
            }
            "postgres" => {
                let repository = Arc::new(
                    authguard_common::storage::AuthnPostgresRepository::connect(&storage.postgres)
                        .await?,
                );
                (repository.clone(), repository)
            }
            provider => anyhow::bail!("unsupported IAM storage provider `{provider}`"),
        };
        let authn = config.get_authn();
        let challenge_required = !authn.providers.is_empty()
            || authn.wallet.enabled
            || authn.standalone.enabled
                && (authn.standalone.totp.enabled || authn.standalone.webauthn.enabled);
        let challenges = if challenge_required {
            Some(Arc::new(RedisChallengeStore::connect(&config.cache.redis).await?)
                as Arc<dyn ChallengeStore>)
        } else {
            None
        };
        let sessions = SessionIssuer::from_config(authn)?;
        let pipeline = Arc::new(AuthenticationPipeline::new(
            authn.account_linking.clone(),
            identities,
            sessions,
        ));
        Ok(Self { pipeline, credentials, challenges })
    }
}
