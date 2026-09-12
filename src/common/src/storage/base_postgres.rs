use std::str::FromStr as _;

use anyhow::Context as _;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::Postgres;

use super::{IAM_BOOTSTRAP_DML, IAM_SCHEMA_DDL, IAM_SCHEMA_LOCK};
use crate::config::PostgresProperties;

/// Shared `PostgreSQL` infrastructure used by entity-specific repositories.
#[derive(Debug)]
pub struct PostgresRepository {
    pub(crate) pool: PgPool,
}

/// Executes a typed `SELECT` from a fixed SQL literal.
macro_rules! postgres_select {
    (optional $executor:expr, $entity:ty, $sql:literal $(, $bind:expr)* $(,)?) => {{
        let query = sqlx::query_as::<_, $entity>($sql);
        $(let query = query.bind($bind);)*
        query.fetch_optional($executor).await
    }};
    (all $executor:expr, $entity:ty, $sql:literal $(, $bind:expr)* $(,)?) => {{
        let query = sqlx::query_as::<_, $entity>($sql);
        $(let query = query.bind($bind);)*
        query.fetch_all($executor).await
    }};
}

/// Executes a fixed `INSERT` statement.
macro_rules! postgres_insert {
    ($executor:expr, $sql:literal $(, $bind:expr)* $(,)?) => {{
        let query = sqlx::query($sql);
        $(let query = query.bind($bind);)*
        query.execute($executor).await
    }};
}

/// Executes an `INSERT .. ON CONFLICT` and returns its typed row.
macro_rules! postgres_upsert {
    ($executor:expr, $entity:ty, $sql:literal $(, $bind:expr)* $(,)?) => {{
        let query = sqlx::query_as::<_, $entity>($sql);
        $(let query = query.bind($bind);)*
        query.fetch_one($executor).await
    }};
}

/// Executes an `UPDATE .. RETURNING` and returns its optional typed row.
macro_rules! postgres_update {
    ($executor:expr, $entity:ty, $sql:literal $(, $bind:expr)* $(,)?) => {{
        let query = sqlx::query_as::<_, $entity>($sql);
        $(let query = query.bind($bind);)*
        query.fetch_optional($executor).await
    }};
}

/// Executes a fixed `DELETE` statement.
macro_rules! postgres_delete {
    ($executor:expr, $sql:literal $(, $bind:expr)* $(,)?) => {{
        let query = sqlx::query($sql);
        $(let query = query.bind($bind);)*
        query.execute($executor).await
    }};
}

pub(crate) use {
    postgres_delete, postgres_insert, postgres_select, postgres_update, postgres_upsert,
};

impl PostgresRepository {
    /// Opens `PostgreSQL` and initializes the canonical IAM schema under an
    /// advisory transaction lock shared by `AuthN` and `AuthZ` processes.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, connection, or migration failure.
    pub async fn connect(config: &PostgresProperties) -> anyhow::Result<Self> {
        let mut options =
            PgConnectOptions::from_str(&config.url).context("parse PostgreSQL URL")?;
        if !config.username.is_empty() {
            options = options.username(&config.username);
        }
        if !config.password.is_empty() {
            options = options.password(&config.password);
        }
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(config.connect_timeout)
            .idle_timeout(config.idle_timeout)
            .test_before_acquire(config.validate_on_acquire)
            .connect_with(options)
            .await
            .context("connect to IAM database")?;
        let mut initialization =
            pool.begin().await.context("begin PostgreSQL IAM initialization")?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(IAM_SCHEMA_LOCK)
            .execute(&mut *initialization)
            .await
            .context("serialize PostgreSQL IAM initialization")?;
        sqlx::raw_sql(IAM_SCHEMA_DDL)
            .execute(&mut *initialization)
            .await
            .context("initialize PostgreSQL IAM schema")?;
        sqlx::raw_sql(IAM_BOOTSTRAP_DML)
            .execute(&mut *initialization)
            .await
            .context("initialize PostgreSQL IAM bootstrap data")?;
        initialization.commit().await.context("commit PostgreSQL IAM initialization")?;
        Ok(Self { pool })
    }
}

impl super::IAsyncRepository for PostgresRepository {
    type Database = Postgres;
    fn pool(&self) -> &PgPool {
        &self.pool
    }
}
