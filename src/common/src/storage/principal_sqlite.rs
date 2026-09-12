//! `SQLite` persistence for the shared canonical Principal aggregate.

use std::ops::Deref;

use anyhow::{bail, Context as _};
use async_trait::async_trait;
use sqlx::QueryBuilder;

use super::authn::{IdentityBindingRepository, IdentityRepositoryError};
use super::authz::{AuthzSqliteRepository, PrincipalReferenced, PrincipalRepository};
use super::base_sqlite::{
    sqlite_delete, sqlite_insert, sqlite_select, sqlite_update, sqlite_upsert,
};
use super::SqliteRepository;
use crate::model::{ExternalIdentity, ExternalIdentityKey, IamPrincipalInfo, PrincipalStatus};

#[derive(Debug)]
pub struct AuthnSqliteRepository {
    inner: SqliteRepository,
}

impl AuthnSqliteRepository {
    /// Opens the `SQLite`-backed `AuthN` repository.
    ///
    /// # Errors
    ///
    /// Returns an error when connection or schema initialization fails.
    pub async fn connect(config: &crate::config::SqliteProperties) -> anyhow::Result<Self> {
        Ok(Self { inner: SqliteRepository::connect(config).await? })
    }
}

impl Deref for AuthnSqliteRepository {
    type Target = SqliteRepository;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[async_trait]
impl IdentityBindingRepository for AuthnSqliteRepository {
    async fn find_principal_by_identity(
        &self,
        identity: &ExternalIdentityKey,
    ) -> Result<Option<IamPrincipalInfo>, IdentityRepositoryError> {
        sqlite_select!(
            optional & self.pool,
            IamPrincipalInfo,
            "SELECT p.id, p.kind, p.display_name, p.status, \
                    JSON(p.authorization_state) AS authorization_state \
             FROM iam_principal p \
             JOIN iam_principal_identity i ON i.principal_id = p.id \
             WHERE i.provider = ? AND i.issuer = ? AND i.subject = ?",
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
        let claims = serde_json::to_string(&identity.claims)
            .map_err(|error| IdentityRepositoryError::Backend(error.to_string()))?;
        let authorization_state = serde_json::to_string(&principal.authorization_state)
            .map_err(|error| IdentityRepositoryError::Backend(error.to_string()))?;
        let mut transaction = self.pool.begin().await.map_err(map_identity_error)?;
        sqlite_insert!(
            &mut *transaction,
            "INSERT INTO iam_principal(id, kind, display_name, status, authorization_state) \
             VALUES (?, ?, ?, ?, JSON(?))",
            &principal.id,
            principal.kind.as_str(),
            &principal.display_name,
            principal.status.as_str(),
            authorization_state,
        )
        .map_err(map_identity_error)?;
        sqlite_insert!(
            &mut *transaction,
            "INSERT INTO iam_principal_identity(\
                principal_id, provider, issuer, subject, claims, last_authenticated_at\
             ) VALUES (?, ?, ?, ?, JSON(?), CURRENT_TIMESTAMP)",
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
        let claims = serde_json::to_string(&identity.claims)
            .map_err(|error| IdentityRepositoryError::Backend(error.to_string()))?;
        let mut transaction = self.pool.begin().await.map_err(map_identity_error)?;
        let principal = sqlite_select!(
            optional &mut *transaction,
            IamPrincipalInfo,
            "SELECT id, kind, display_name, status, \
                    JSON(authorization_state) AS authorization_state \
             FROM iam_principal WHERE id = ?",
            principal_id,
        )
        .map_err(map_identity_error)?
        .ok_or_else(|| IdentityRepositoryError::Backend("missing principal".to_string()))?;
        sqlite_insert!(
            &mut *transaction,
            "INSERT INTO iam_principal_identity(\
                principal_id, provider, issuer, subject, claims, last_authenticated_at\
             ) VALUES (?, ?, ?, ?, JSON(?), CURRENT_TIMESTAMP)",
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
        let exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(\
                SELECT 1 FROM iam_principal_identity \
                WHERE principal_id = ? AND provider = ?\
             )",
        )
        .bind(principal_id)
        .bind(provider)
        .fetch_one(&self.pool)
        .await
        .map_err(map_identity_error)?;
        Ok(exists != 0)
    }
}

#[async_trait]
impl PrincipalRepository for AuthzSqliteRepository {
    async fn upsert(&self, principal: &IamPrincipalInfo) -> anyhow::Result<IamPrincipalInfo> {
        validate_principal(principal)?;
        sqlite_upsert!(
            &self.pool,
            "INSERT INTO iam_principal(\
                id, kind, display_name, status, authorization_state, last_seen_at\
             ) VALUES (?, ?, ?, ?, JSON(?), CURRENT_TIMESTAMP) \
             ON CONFLICT(id) DO UPDATE SET \
                kind = excluded.kind, display_name = excluded.display_name, \
                status = excluded.status, authorization_state = excluded.authorization_state, \
                last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP",
            &principal.id,
            principal.kind.as_str(),
            &principal.display_name,
            principal.status.as_str(),
            serde_json::to_string(&principal.authorization_state)?,
        )
        .context("upsert IAM principal")?;
        self.get(&principal.id).await?.context("upserted IAM principal is missing")
    }

    async fn get(&self, id: &str) -> anyhow::Result<Option<IamPrincipalInfo>> {
        Ok(sqlite_select!(
            optional & self.pool,
            IamPrincipalInfo,
            "SELECT id, kind, display_name, status, \
                    JSON(authorization_state) AS authorization_state \
             FROM iam_principal WHERE id = ?",
            id,
        )?)
    }

    async fn find_by_ids(&self, ids: &[String]) -> anyhow::Result<Vec<IamPrincipalInfo>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut query = QueryBuilder::new(
            "SELECT id, kind, display_name, status, \
                    JSON(authorization_state) AS authorization_state \
             FROM iam_principal WHERE id IN (",
        );
        let mut values = query.separated(", ");
        for id in ids {
            values.push_bind(id);
        }
        values.push_unseparated(") ORDER BY id");
        Ok(query.build_query_as::<IamPrincipalInfo>().fetch_all(&self.pool).await?)
    }

    async fn list(
        &self,
        query: &str,
        after_id: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<IamPrincipalInfo>> {
        let pattern = principal_prefix_pattern(query);
        sqlite_select!(
            all & self.pool,
            IamPrincipalInfo,
            "SELECT id, kind, display_name, status, \
                    JSON(authorization_state) AS authorization_state \
             FROM iam_principal \
             WHERE id > ? \
               AND (? = '%' OR LOWER(display_name) LIKE LOWER(?) ESCAPE '\\' \
                             OR LOWER(id) LIKE LOWER(?) ESCAPE '\\') \
             ORDER BY id LIMIT ?",
            after_id.unwrap_or(""),
            &pattern,
            &pattern,
            &pattern,
            i64::from(limit.clamp(1, 100)),
        )
        .context("list IAM principal projections")
    }

    async fn update_status(
        &self,
        id: &str,
        status: PrincipalStatus,
    ) -> anyhow::Result<Option<IamPrincipalInfo>> {
        Ok(sqlite_update!(
            &self.pool,
            IamPrincipalInfo,
            "UPDATE iam_principal SET status = ?, updated_at = CURRENT_TIMESTAMP \
             WHERE id = ? \
             RETURNING id, kind, display_name, status, \
                       JSON(authorization_state) AS authorization_state",
            status.as_str(),
            id,
        )?)
    }

    async fn delete(&self, id: &str) -> anyhow::Result<bool> {
        match sqlite_delete!(&self.pool, "DELETE FROM iam_principal WHERE id = ?", id) {
            Ok(result) => Ok(result.rows_affected() == 1),
            Err(sqlx::Error::Database(error))
                if error.is_foreign_key_violation()
                    || error.message() == "FOREIGN KEY constraint failed" =>
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
