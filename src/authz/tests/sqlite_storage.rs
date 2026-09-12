mod support;

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use authguard_authz::config::SqliteProperties;
use authguard_authz::storage::{AuthzSqliteRepository, PolicyRepository};
use rusqlite::Connection;

use support::storage_contract::assert_repository_contract;

#[tokio::test]
async fn sqlite_implements_the_normalized_authorization_repository_contract() {
    let repository = AuthzSqliteRepository::connect(&SqliteProperties {
        url: "sqlite::memory:".to_string(),
        max_connections: 1,
        connect_timeout: Duration::from_secs(2),
    })
    .await
    .expect("connect SQLite authorization repository");

    assert_repository_contract(&repository).await;
}

#[tokio::test]
async fn concurrent_sqlite_connections_serialize_initialization() {
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("authguard-storage-{unique}.db"));
    let config = SqliteProperties {
        url: format!("sqlite://{}", path.display()),
        max_connections: 1,
        connect_timeout: Duration::from_secs(2),
    };

    let (first, second) = tokio::join!(
        AuthzSqliteRepository::connect(&config),
        AuthzSqliteRepository::connect(&config),
    );
    let first = first.expect("initialize first SQLite repository concurrently");
    let second = second.expect("initialize second SQLite repository concurrently");
    assert!(first.load().await.expect("load first initialized catalog").actions.is_empty());
    assert!(second.load().await.expect("load second initialized catalog").actions.is_empty());

    drop((first, second));
    for suffix in ["", "-shm", "-wal"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[test]
fn sqlite_schema_contains_the_unified_iam_tables() {
    let connection = Connection::open_in_memory().expect("open SQLite");
    connection
        .execute_batch(authguard_common::storage::IAM_SCHEMA_DDL)
        .expect("apply shared authorization DDL");
    connection
        .execute_batch(authguard_common::storage::IAM_BOOTSTRAP_DML)
        .expect("apply shared authorization DML");
    let mut statement = connection
        .prepare(
            "SELECT name FROM sqlite_master \
             WHERE type = 'table' AND name LIKE 'iam_%' ORDER BY name",
        )
        .expect("query SQLite schema");
    let tables = statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("list IAM tables")
        .collect::<Result<BTreeSet<_>, _>>()
        .expect("decode IAM table names");

    assert_eq!(
        tables,
        BTreeSet::from([
            "iam_action".to_string(),
            "iam_authn_flow".to_string(),
            "iam_principal".to_string(),
            "iam_principal_identity".to_string(),
            "iam_role".to_string(),
            "iam_role_action".to_string(),
            "iam_role_binding".to_string(),
        ])
    );
}

#[test]
fn shared_initialization_scripts_are_idempotent_on_sqlite() {
    let connection = Connection::open_in_memory().expect("open SQLite");
    for _ in 0..2 {
        connection
            .execute_batch(authguard_common::storage::IAM_SCHEMA_DDL)
            .expect("apply shared authorization DDL");
        connection
            .execute_batch(authguard_common::storage::IAM_BOOTSTRAP_DML)
            .expect("apply shared authorization DML");
    }
}
