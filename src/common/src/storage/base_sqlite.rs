use std::str::FromStr as _;

use anyhow::Context as _;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::Sqlite;

use super::{IAM_BOOTSTRAP_DML, IAM_SCHEMA_DDL};
use crate::config::SqliteProperties;

/// Shared `SQLite` infrastructure used by entity-specific repositories.
#[derive(Debug)]
pub struct SqliteRepository {
    pub(crate) pool: SqlitePool,
}

/// Executes a typed `SELECT` from a fixed SQL literal.
macro_rules! sqlite_select {
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
macro_rules! sqlite_insert {
    ($executor:expr, $sql:literal $(, $bind:expr)* $(,)?) => {{
        let query = sqlx::query($sql);
        $(let query = query.bind($bind);)*
        query.execute($executor).await
    }};
}

/// Executes a fixed `INSERT .. ON CONFLICT` statement.
macro_rules! sqlite_upsert {
    ($executor:expr, $sql:literal $(, $bind:expr)* $(,)?) => {{
        let query = sqlx::query($sql);
        $(let query = query.bind($bind);)*
        query.execute($executor).await
    }};
}

/// Executes an `UPDATE .. RETURNING` and returns its optional typed row.
macro_rules! sqlite_update {
    ($executor:expr, $entity:ty, $sql:literal $(, $bind:expr)* $(,)?) => {{
        let query = sqlx::query_as::<_, $entity>($sql);
        $(let query = query.bind($bind);)*
        query.fetch_optional($executor).await
    }};
}

/// Executes a fixed `DELETE` statement.
macro_rules! sqlite_delete {
    ($executor:expr, $sql:literal $(, $bind:expr)* $(,)?) => {{
        let query = sqlx::query($sql);
        $(let query = query.bind($bind);)*
        query.execute($executor).await
    }};
}

pub(crate) use {sqlite_delete, sqlite_insert, sqlite_select, sqlite_update, sqlite_upsert};

impl SqliteRepository {
    /// Opens `SQLite` and initializes the canonical IAM schema under a serialized
    /// write transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, connection, or migration failure.
    pub async fn connect(config: &SqliteProperties) -> anyhow::Result<Self> {
        let options = SqliteConnectOptions::from_str(&config.url)
            .context("parse SQLite IAM database URL")?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(config.connect_timeout);
        let pool = SqlitePoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.connect_timeout)
            .connect_with(options)
            .await
            .context("connect to SQLite IAM database")?;
        let mut initialization = pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .context("begin serialized SQLite IAM initialization")?;
        sqlx::raw_sql(IAM_SCHEMA_DDL)
            .execute(&mut *initialization)
            .await
            .context("initialize SQLite IAM schema")?;
        sqlx::raw_sql(IAM_BOOTSTRAP_DML)
            .execute(&mut *initialization)
            .await
            .context("initialize SQLite IAM bootstrap data")?;
        initialization.commit().await.context("commit SQLite IAM initialization")?;
        Ok(Self { pool })
    }
}

impl super::IAsyncRepository for SqliteRepository {
    type Database = Sqlite;
    fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}
