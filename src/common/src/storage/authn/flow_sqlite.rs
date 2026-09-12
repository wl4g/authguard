use super::{AuthnFlowRepository, AuthnFlowRepositoryError, AuthnSqliteRepository};
use crate::model::IamAuthFlowInfo;
use async_trait::async_trait;
use sqlx::Row as _;

#[async_trait]
impl AuthnFlowRepository for AuthnSqliteRepository {
    async fn create(
        &self,
        state_hash: &str,
        flow: &IamAuthFlowInfo,
    ) -> Result<(), AuthnFlowRepositoryError> {
        let expires = i64::try_from(flow.expires_at_epoch_seconds)
            .map_err(|_| AuthnFlowRepositoryError("flow expiry is out of range".into()))?;
        sqlx::query(
            "INSERT INTO iam_authn_flow(state_hash, provider, return_uri, expires_at_epoch_seconds) VALUES (?, ?, ?, ?)",
        )
        .bind(state_hash)
        .bind(&flow.provider)
        .bind(&flow.return_uri)
        .bind(expires)
        .execute(&self.pool)
        .await
        .map_err(map_flow_error)?;
        Ok(())
    }

    async fn consume(
        &self,
        state_hash: &str,
    ) -> Result<Option<IamAuthFlowInfo>, AuthnFlowRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(map_flow_error)?;
        let row = sqlx::query(
            "SELECT provider, return_uri, expires_at_epoch_seconds FROM iam_authn_flow WHERE state_hash = ?",
        )
        .bind(state_hash)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_flow_error)?;
        sqlx::query("DELETE FROM iam_authn_flow WHERE state_hash = ?")
            .bind(state_hash)
            .execute(&mut *transaction)
            .await
            .map_err(map_flow_error)?;
        transaction.commit().await.map_err(map_flow_error)?;
        row.map(|row| {
            decode_flow(
                row.get("provider"),
                row.get("return_uri"),
                row.get("expires_at_epoch_seconds"),
            )
        })
        .transpose()
    }
}

fn decode_flow(
    provider: String,
    return_uri: String,
    expires: i64,
) -> Result<IamAuthFlowInfo, AuthnFlowRepositoryError> {
    Ok(IamAuthFlowInfo {
        provider,
        return_uri,
        expires_at_epoch_seconds: u64::try_from(expires)
            .map_err(|_| AuthnFlowRepositoryError("flow expiry is out of range".into()))?,
    })
}

fn map_flow_error(error: sqlx::Error) -> AuthnFlowRepositoryError {
    let message = error.to_string();
    drop(error);
    AuthnFlowRepositoryError(message)
}
