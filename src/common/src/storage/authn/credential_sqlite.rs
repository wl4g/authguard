use async_trait::async_trait;
use sqlx::sqlite::SqliteRow;
use sqlx::Row as _;

use super::{AuthnSqliteRepository, CredentialRepositoryError, StandaloneCredentialRepository};
use crate::model::{
    ExternalIdentity, ExternalIdentityKey, IamStandaloneCredential, StandaloneCredentialIdentity,
    StandaloneCredentialKind,
};

#[async_trait]
impl StandaloneCredentialRepository for AuthnSqliteRepository {
    async fn find_by_key(
        &self,
        issuer: &str,
        kind: StandaloneCredentialKind,
        credential_key: &str,
    ) -> Result<Option<StandaloneCredentialIdentity>, CredentialRepositoryError> {
        let row = sqlx::query(
            "SELECT i.provider, i.issuer, i.subject, JSON(i.claims) AS claims, \
                    c.id, c.kind, c.credential_key, c.secret_data, \
                    JSON(c.credential_data) AS credential_data \
             FROM iam_standalone_credential c \
             JOIN iam_principal_identity i \
               ON i.provider = c.identity_provider \
              AND i.issuer = c.identity_issuer \
              AND i.subject = c.identity_subject \
             WHERE c.identity_provider = 'standalone' AND c.identity_issuer = ? \
               AND c.kind = ? AND c.credential_key = ? AND c.revoked_at IS NULL",
        )
        .bind(issuer)
        .bind(kind.as_str())
        .bind(credential_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_error)?;
        row.as_ref().map(decode_identity_credential).transpose()
    }

    async fn list_by_identity(
        &self,
        identity: &ExternalIdentityKey,
        kind: StandaloneCredentialKind,
    ) -> Result<Vec<IamStandaloneCredential>, CredentialRepositoryError> {
        let rows = sqlx::query(
            "SELECT id, identity_provider, identity_issuer, identity_subject, kind, \
                    credential_key, secret_data, JSON(credential_data) AS credential_data \
             FROM iam_standalone_credential \
             WHERE identity_provider = ? AND identity_issuer = ? AND identity_subject = ? \
               AND kind = ? AND revoked_at IS NULL ORDER BY created_at, id",
        )
        .bind(&identity.provider)
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .bind(kind.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(map_error)?;
        rows.iter().map(decode_credential).collect()
    }

    async fn create_credential(
        &self,
        credential: &IamStandaloneCredential,
    ) -> Result<(), CredentialRepositoryError> {
        let data = credential
            .credential_data
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| CredentialRepositoryError::Backend(error.to_string()))?;
        sqlx::query(
            "INSERT INTO iam_standalone_credential(\
                id, identity_provider, identity_issuer, identity_subject, kind, \
                credential_key, secret_data, credential_data\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, JSON(?))",
        )
        .bind(&credential.id)
        .bind(&credential.identity.provider)
        .bind(&credential.identity.issuer)
        .bind(&credential.identity.subject)
        .bind(credential.kind.as_str())
        .bind(&credential.credential_key)
        .bind(&credential.secret_data)
        .bind(data)
        .execute(&self.pool)
        .await
        .map_err(map_error)?;
        Ok(())
    }

    async fn compare_and_swap_credential_data(
        &self,
        credential_id: &str,
        current_data: &serde_json::Value,
        credential_data: &serde_json::Value,
    ) -> Result<bool, CredentialRepositoryError> {
        let data = serde_json::to_string(credential_data)
            .map_err(|error| CredentialRepositoryError::Backend(error.to_string()))?;
        let current = serde_json::to_string(current_data)
            .map_err(|error| CredentialRepositoryError::Backend(error.to_string()))?;
        let result = sqlx::query(
            "UPDATE iam_standalone_credential \
             SET credential_data = JSON(?), updated_at = CURRENT_TIMESTAMP \
             WHERE id = ? AND revoked_at IS NULL \
               AND JSON(credential_data) = JSON(?)",
        )
        .bind(data)
        .bind(credential_id)
        .bind(current)
        .execute(&self.pool)
        .await
        .map_err(map_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn advance_totp_counter(
        &self,
        credential_id: &str,
        counter: u64,
    ) -> Result<bool, CredentialRepositoryError> {
        let counter = i64::try_from(counter).map_err(|_| {
            CredentialRepositoryError::Backend("TOTP counter is out of range".into())
        })?;
        let result = sqlx::query(
            "UPDATE iam_standalone_credential \
             SET credential_data = JSON_SET(COALESCE(credential_data, '{}'), '$.lastCounter', ?), \
                 updated_at = CURRENT_TIMESTAMP \
             WHERE id = ? AND kind = 'totp' AND revoked_at IS NULL \
               AND COALESCE(CAST(JSON_EXTRACT(credential_data, '$.lastCounter') AS INTEGER), -1) < ?",
        )
        .bind(counter)
        .bind(credential_id)
        .bind(counter)
        .execute(&self.pool)
        .await
        .map_err(map_error)?;
        Ok(result.rows_affected() == 1)
    }
}

fn decode_identity_credential(
    row: &SqliteRow,
) -> Result<StandaloneCredentialIdentity, CredentialRepositoryError> {
    let provider = row.try_get("provider").map_err(map_error)?;
    let issuer = row.try_get("issuer").map_err(map_error)?;
    let subject = row.try_get("subject").map_err(map_error)?;
    let claims = serde_json::from_str(&row.try_get::<String, _>("claims").map_err(map_error)?)
        .map_err(|error| CredentialRepositoryError::Backend(error.to_string()))?;
    let external_identity = ExternalIdentity { provider, issuer, subject, claims };
    let credential = decode_credential_with_identity(
        row,
        external_identity
            .key()
            .map_err(|error| CredentialRepositoryError::Backend(error.to_string()))?,
    )?;
    Ok(StandaloneCredentialIdentity { external_identity, credential })
}

fn decode_credential(
    row: &SqliteRow,
) -> Result<IamStandaloneCredential, CredentialRepositoryError> {
    let identity = ExternalIdentityKey::new(
        row.try_get::<String, _>("identity_provider").map_err(map_error)?,
        row.try_get::<String, _>("identity_issuer").map_err(map_error)?,
        row.try_get::<String, _>("identity_subject").map_err(map_error)?,
    )
    .map_err(|error| CredentialRepositoryError::Backend(error.to_string()))?;
    decode_credential_with_identity(row, identity)
}

fn decode_credential_with_identity(
    row: &SqliteRow,
    identity: ExternalIdentityKey,
) -> Result<IamStandaloneCredential, CredentialRepositoryError> {
    let kind =
        StandaloneCredentialKind::try_from(row.try_get::<String, _>("kind").map_err(map_error)?)
            .map_err(|error| CredentialRepositoryError::Backend(error.to_string()))?;
    let data = row
        .try_get::<Option<String>, _>("credential_data")
        .map_err(map_error)?
        .map(|value| serde_json::from_str(&value))
        .transpose()
        .map_err(|error| CredentialRepositoryError::Backend(error.to_string()))?;
    Ok(IamStandaloneCredential {
        id: row.try_get("id").map_err(map_error)?,
        identity,
        kind,
        credential_key: row.try_get("credential_key").map_err(map_error)?,
        secret_data: row.try_get("secret_data").map_err(map_error)?,
        credential_data: data,
    })
}

fn map_error(error: sqlx::Error) -> CredentialRepositoryError {
    let unique =
        error.as_database_error().is_some_and(sqlx::error::DatabaseError::is_unique_violation);
    let message = error.to_string();
    drop(error);
    if unique {
        CredentialRepositoryError::KeyConflict
    } else {
        CredentialRepositoryError::Backend(message)
    }
}
