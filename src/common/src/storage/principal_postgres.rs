//! `PostgreSQL` persistence for the shared canonical Principal aggregate.

use std::ops::Deref;

use anyhow::{bail, Context as _};
use async_trait::async_trait;

use super::authn::{IdentityBindingRepository, IdentityRepositoryError};
use super::authz::{
    AuthzPostgresRepository, PrincipalIdentityConflict, PrincipalReferenced, PrincipalRepository,
};
use super::base_postgres::{
    postgres_delete, postgres_insert, postgres_select, postgres_update, postgres_upsert,
};
use super::PostgresRepository;
use crate::model::{
    ExternalIdentity, ExternalIdentityKey, IamPrincipalIdentityInfo, IamPrincipalInfo,
    PrincipalStatus,
};

#[derive(Debug)]
pub struct AuthnPostgresRepository {
    inner: PostgresRepository,
}

impl AuthnPostgresRepository {
    /// Opens the `PostgreSQL`-backed `AuthN` repository.
    ///
    /// # Errors
    ///
    /// Returns an error when connection or schema initialization fails.
    pub async fn connect(config: &crate::config::PostgresProperties) -> anyhow::Result<Self> {
        Ok(Self { inner: PostgresRepository::connect(config).await? })
    }
}

impl Deref for AuthnPostgresRepository {
    type Target = PostgresRepository;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[async_trait]
impl IdentityBindingRepository for AuthnPostgresRepository {
    async fn find_principal_by_identity(
        &self,
        identity: &ExternalIdentityKey,
    ) -> Result<Option<IamPrincipalInfo>, IdentityRepositoryError> {
        postgres_select!(
            optional & self.pool,
            IamPrincipalInfo,
            "SELECT p.id, p.kind, p.display_name, p.status, p.authorization_state \
             FROM iam_principal p \
             JOIN iam_principal_identity i ON i.principal_id = p.id \
             WHERE i.provider = $1 AND i.issuer = $2 AND i.subject = $3",
            &identity.provider,
            &identity.issuer,
            &identity.subject,
        )
        .map_err(map_identity_error)
    }

    async fn create_principal_and_bind(
        &self,
        principal: &IamPrincipalInfo,
        identity: &ExternalIdentity,
    ) -> Result<IamPrincipalInfo, IdentityRepositoryError> {
        let claims = serde_json::to_value(&identity.claims)
            .map_err(|error| IdentityRepositoryError::Backend(error.to_string()))?;
        let authorization_state = serde_json::to_value(&principal.authorization_state)
            .map_err(|error| IdentityRepositoryError::Backend(error.to_string()))?;
        let mut transaction = self.pool.begin().await.map_err(map_identity_error)?;
        postgres_insert!(
            &mut *transaction,
            "INSERT INTO iam_principal(id, kind, display_name, status, authorization_state) \
             VALUES ($1, $2, $3, $4, $5)",
            &principal.id,
            principal.kind.as_str(),
            &principal.display_name,
            principal.status.as_str(),
            authorization_state,
        )
        .map_err(map_identity_error)?;
        postgres_insert!(
            &mut *transaction,
            "INSERT INTO iam_principal_identity(\
                principal_id, provider, issuer, subject, claims, last_authenticated_at\
             ) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)",
            &principal.id,
            &identity.provider,
            &identity.issuer,
            &identity.subject,
            claims,
        )
        .map_err(map_identity_error)?;
        transaction.commit().await.map_err(map_identity_error)?;
        Ok(principal.clone())
    }

    async fn bind_identity(
        &self,
        principal_id: &str,
        identity: &ExternalIdentity,
    ) -> Result<IamPrincipalInfo, IdentityRepositoryError> {
        let claims = serde_json::to_value(&identity.claims)
            .map_err(|error| IdentityRepositoryError::Backend(error.to_string()))?;
        let mut transaction = self.pool.begin().await.map_err(map_identity_error)?;
        let principal = postgres_select!(
            optional &mut *transaction,
            IamPrincipalInfo,
            "SELECT id, kind, display_name, status, authorization_state \
             FROM iam_principal WHERE id = $1",
            principal_id,
        )
        .map_err(map_identity_error)?
        .ok_or_else(|| IdentityRepositoryError::Backend("missing principal".to_string()))?;
        postgres_insert!(
            &mut *transaction,
            "INSERT INTO iam_principal_identity(\
                principal_id, provider, issuer, subject, claims, last_authenticated_at\
             ) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)",
            principal_id,
            &identity.provider,
            &identity.issuer,
            &identity.subject,
            claims,
        )
        .map_err(map_identity_error)?;
        transaction.commit().await.map_err(map_identity_error)?;
        Ok(principal)
    }

    async fn principal_has_provider(
        &self,
        principal_id: &str,
        provider: &str,
    ) -> Result<bool, IdentityRepositoryError> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(\
                SELECT 1 FROM iam_principal_identity \
                WHERE principal_id = $1 AND provider = $2\
             )",
        )
        .bind(principal_id)
        .bind(provider)
        .fetch_one(&self.pool)
        .await
        .map_err(map_identity_error)
    }
}

#[async_trait]
impl PrincipalRepository for AuthzPostgresRepository {
    async fn upsert(&self, principal: &IamPrincipalInfo) -> anyhow::Result<IamPrincipalInfo> {
        validate_principal(principal)?;
        postgres_upsert!(
            &self.pool,
            IamPrincipalInfo,
            "INSERT INTO iam_principal(\
                id, kind, display_name, status, authorization_state, last_seen_at\
             ) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP) \
             ON CONFLICT(id) DO UPDATE SET \
                kind = EXCLUDED.kind, display_name = EXCLUDED.display_name, \
                status = EXCLUDED.status, authorization_state = EXCLUDED.authorization_state, \
                last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP \
             RETURNING id, kind, display_name, status, authorization_state",
            &principal.id,
            principal.kind.as_str(),
            &principal.display_name,
            principal.status.as_str(),
            serde_json::to_value(&principal.authorization_state)?,
        )
        .context("upsert IAM principal projection")
    }

    async fn upsert_with_identity(
        &self,
        principal: &IamPrincipalInfo,
        identity: &IamPrincipalIdentityInfo,
    ) -> anyhow::Result<IamPrincipalInfo> {
        validate_principal(principal)?;
        let mut transaction = self.pool.begin().await?;
        let projected = sqlx::query_as::<_, IamPrincipalInfo>(
            "INSERT INTO iam_principal(\
                id, kind, display_name, status, authorization_state, last_seen_at\
             ) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP) \
             ON CONFLICT(id) DO UPDATE SET \
                kind = EXCLUDED.kind, display_name = EXCLUDED.display_name, \
                status = EXCLUDED.status, authorization_state = EXCLUDED.authorization_state, \
                last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP \
             RETURNING id, kind, display_name, status, authorization_state",
        )
        .bind(&principal.id)
        .bind(principal.kind.as_str())
        .bind(&principal.display_name)
        .bind(principal.status.as_str())
        .bind(serde_json::to_value(&principal.authorization_state)?)
        .fetch_one(&mut *transaction)
        .await?;
        let bound = sqlx::query(
            "INSERT INTO iam_principal_identity(\
                principal_id, provider, issuer, subject, claims, last_authenticated_at\
             ) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP) \
             ON CONFLICT(provider, issuer, subject) DO UPDATE SET \
                claims = EXCLUDED.claims, last_authenticated_at = CURRENT_TIMESTAMP \
             WHERE iam_principal_identity.principal_id = EXCLUDED.principal_id",
        )
        .bind(&identity.principal_id)
        .bind(&identity.provider)
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .bind(&identity.claims)
        .execute(&mut *transaction)
        .await?;
        if bound.rows_affected() != 1 {
            return Err(PrincipalIdentityConflict.into());
        }
        transaction.commit().await?;
        Ok(projected)
    }

    async fn get(&self, id: &str) -> anyhow::Result<Option<IamPrincipalInfo>> {
        Ok(postgres_select!(
            optional & self.pool,
            IamPrincipalInfo,
            "SELECT id, kind, display_name, status, authorization_state \
             FROM iam_principal WHERE id = $1",
            id,
        )?)
    }

    async fn find_by_identity(
        &self,
        identity: &ExternalIdentityKey,
    ) -> anyhow::Result<Option<IamPrincipalInfo>> {
        Ok(postgres_select!(
            optional & self.pool,
            IamPrincipalInfo,
            "SELECT p.id, p.kind, p.display_name, p.status, p.authorization_state \
             FROM iam_principal p \
             JOIN iam_principal_identity i ON i.principal_id = p.id \
             WHERE i.provider = $1 AND i.issuer = $2 AND i.subject = $3",
            &identity.provider,
            &identity.issuer,
            &identity.subject,
        )?)
    }

    async fn get_identity(
        &self,
        principal_id: &str,
        provider: &str,
    ) -> anyhow::Result<Option<IamPrincipalIdentityInfo>> {
        Ok(postgres_select!(
            optional & self.pool,
            IamPrincipalIdentityInfo,
            "SELECT principal_id, provider, issuer, subject, claims \
             FROM iam_principal_identity \
             WHERE principal_id = $1 AND provider = $2",
            principal_id,
            provider,
        )?)
    }

    async fn find_by_ids(&self, ids: &[String]) -> anyhow::Result<Vec<IamPrincipalInfo>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        Ok(sqlx::query_as::<_, IamPrincipalInfo>(
            "SELECT id, kind, display_name, status, authorization_state \
             FROM iam_principal WHERE id = ANY($1) ORDER BY id",
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn list(
        &self,
        query: &str,
        after_id: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<IamPrincipalInfo>> {
        let pattern = principal_prefix_pattern(query);
        postgres_select!(
            all & self.pool,
            IamPrincipalInfo,
            "SELECT id, kind, display_name, status, authorization_state \
             FROM iam_principal \
             WHERE id > $1 \
               AND ($2 = '%' OR LOWER(display_name) LIKE LOWER($2) ESCAPE '\\' \
                            OR LOWER(id) LIKE LOWER($2) ESCAPE '\\') \
             ORDER BY id LIMIT $3",
            after_id.unwrap_or(""),
            pattern,
            i64::from(limit.clamp(1, 100)),
        )
        .context("list IAM principal projections")
    }

    async fn update_status(
        &self,
        id: &str,
        status: PrincipalStatus,
    ) -> anyhow::Result<Option<IamPrincipalInfo>> {
        Ok(postgres_update!(
            &self.pool,
            IamPrincipalInfo,
            "UPDATE iam_principal SET status = $1, updated_at = CURRENT_TIMESTAMP \
             WHERE id = $2 \
             RETURNING id, kind, display_name, status, authorization_state",
            status.as_str(),
            id,
        )?)
    }

    async fn delete(&self, id: &str) -> anyhow::Result<bool> {
        match postgres_delete!(&self.pool, "DELETE FROM iam_principal WHERE id = $1", id) {
            Ok(result) => Ok(result.rows_affected() == 1),
            Err(sqlx::Error::Database(error))
                if error.is_foreign_key_violation() || error.code().as_deref() == Some("23001") =>
            {
                Err(PrincipalReferenced { id: id.to_string() }.into())
            }
            Err(error) => Err(error).context("delete IAM principal projection"),
        }
    }
}

fn validate_principal(principal: &IamPrincipalInfo) -> anyhow::Result<()> {
    if principal.id.trim().is_empty() || principal.display_name.trim().is_empty() {
        bail!("IAM principal ID and display name must not be empty");
    }
    Ok(())
}

fn principal_prefix_pattern(input: &str) -> String {
    if input.is_empty() {
        return "%".to_string();
    }
    let escaped = input.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
    format!("{escaped}%")
}

fn map_identity_error(error: sqlx::Error) -> IdentityRepositoryError {
    let message = error.to_string();
    if error.into_database_error().is_some_and(|error| error.is_unique_violation()) {
        IdentityRepositoryError::IdentityAlreadyBound
    } else {
        IdentityRepositoryError::Backend(message)
    }
}
