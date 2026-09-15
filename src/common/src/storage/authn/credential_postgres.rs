use async_trait::async_trait;
use sqlx::postgres::PgRow;
use sqlx::Row as _;

use super::{AuthnPostgresRepository, CredentialRepositoryError, StandaloneCredentialRepository};
use crate::model::{
    ExternalIdentity, ExternalIdentityKey, IamStandaloneCredential, StandaloneCredentialIdentity,
    StandaloneCredentialKind,
};

#[async_trait]
impl StandaloneCredentialRepository for AuthnPostgresRepository {
    async fn find_by_key(
        &self,
        issuer: &str,
        kind: StandaloneCredentialKind,
        credential_key: &str,
    ) -> Result<Option<StandaloneCredentialIdentity>, CredentialRepositoryError> {
        let row = sqlx::query(
            "SELECT i.provider, i.issuer, i.subject, i.claims, c.id, c.kind, \
                    c.credential_key, c.secret_data, c.credential_data \
             FROM iam_standalone_credential c \
             JOIN iam_principal_identity i \
               ON i.provider = c.identity_provider \
              AND i.issuer = c.identity_issuer \
              AND i.subject = c.identity_subject \
             WHERE c.identity_provider = 'standalone' AND c.identity_issuer = $1 \
               AND c.kind = $2 AND c.credential_key = $3 AND c.revoked_at IS NULL",
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
                    credential_key, secret_data, credential_data \
             FROM iam_standalone_credential \
             WHERE identity_provider = $1 AND identity_issuer = $2 AND identity_subject = $3 \
               AND kind = $4 AND revoked_at IS NULL ORDER BY created_at, id",
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
        sqlx::query(
            "INSERT INTO iam_standalone_credential(\
                id, identity_provider, identity_issuer, identity_subject, kind, \
                credential_key, secret_data, credential_data\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&credential.id)
        .bind(&credential.identity.provider)
        .bind(&credential.identity.issuer)
        .bind(&credential.identity.subject)
        .bind(credential.kind.as_str())
        .bind(&credential.credential_key)
        .bind(&credential.secret_data)
        .bind(&credential.credential_data)
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
        let result = sqlx::query(
            "UPDATE iam_standalone_credential \
             SET credential_data = $1, updated_at = CURRENT_TIMESTAMP \
             WHERE id = $3 AND revoked_at IS NULL \
               AND credential_data::jsonb = $2::jsonb",
        )
        .bind(credential_data)
        .bind(current_data)
        .bind(credential_id)
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
             SET credential_data = JSONB_SET(COALESCE(credential_data, '{}')::jsonb, \
                                              '{lastCounter}', TO_JSONB($1::bigint))::json, \
                 updated_at = CURRENT_TIMESTAMP \
             WHERE id = $2 AND kind = 'totp' AND revoked_at IS NULL \
               AND COALESCE((credential_data->>'lastCounter')::bigint, -1) < $1",
        )
        .bind(counter)
        .bind(credential_id)
        .execute(&self.pool)
        .await
        .map_err(map_error)?;
        Ok(result.rows_affected() == 1)
    }
}

fn decode_identity_credential(
    row: &PgRow,
) -> Result<StandaloneCredentialIdentity, CredentialRepositoryError> {
    let external_identity = ExternalIdentity {
        provider: row.try_get("provider").map_err(map_error)?,
        issuer: row.try_get("issuer").map_err(map_error)?,
        subject: row.try_get("subject").map_err(map_error)?,
        claims: serde_json::from_value(row.try_get("claims").map_err(map_error)?)
            .map_err(|error| CredentialRepositoryError::Backend(error.to_string()))?,
    };
    let credential = decode_credential_with_identity(
        row,
        external_identity
            .key()
            .map_err(|error| CredentialRepositoryError::Backend(error.to_string()))?,
    )?;
    Ok(StandaloneCredentialIdentity { external_identity, credential })
}

fn decode_credential(row: &PgRow) -> Result<IamStandaloneCredential, CredentialRepositoryError> {
    let identity = ExternalIdentityKey::new(
        row.try_get::<String, _>("identity_provider").map_err(map_error)?,
        row.try_get::<String, _>("identity_issuer").map_err(map_error)?,
        row.try_get::<String, _>("identity_subject").map_err(map_error)?,
    )
    .map_err(|error| CredentialRepositoryError::Backend(error.to_string()))?;
    decode_credential_with_identity(row, identity)
}

fn decode_credential_with_identity(
    row: &PgRow,
    identity: ExternalIdentityKey,
) -> Result<IamStandaloneCredential, CredentialRepositoryError> {
    let kind =
        StandaloneCredentialKind::try_from(row.try_get::<String, _>("kind").map_err(map_error)?)
            .map_err(|error| CredentialRepositoryError::Backend(error.to_string()))?;
    Ok(IamStandaloneCredential {
        id: row.try_get("id").map_err(map_error)?,
        identity,
        kind,
        credential_key: row.try_get("credential_key").map_err(map_error)?,
        secret_data: row.try_get("secret_data").map_err(map_error)?,
        credential_data: row.try_get("credential_data").map_err(map_error)?,
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
