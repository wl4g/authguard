use authguard_authz::config::PostgresProperties;
use authguard_authz::storage::{AuthzPostgresRepository, PolicyRepository};
use sqlx::PgPool;

mod support;

use support::storage_contract::assert_repository_contract;

#[tokio::test]
#[ignore = "requires a disposable AUTHGUARD_TEST_POSTGRES_URL database"]
async fn postgres_implements_the_normalized_authorization_repository_contract() {
    let url = std::env::var("AUTHGUARD_TEST_POSTGRES_URL").expect("test database URL");
    let config = PostgresProperties {
        url: url.clone(),
        max_connections: 2,
        connect_timeout: std::time::Duration::from_secs(5),
        ..PostgresProperties::default()
    };
    let pool = PgPool::connect(&url).await.expect("connect PostgreSQL schema inspector");
    sqlx::raw_sql(
        "DROP TABLE IF EXISTS iam_authn_flow, iam_principal_identity, iam_role_binding, \
         iam_role_action, iam_role, iam_action, iam_principal CASCADE",
    )
    .execute(&pool)
    .await
    .expect("reset disposable PostgreSQL test database");

    let (first, second) = tokio::join!(
        AuthzPostgresRepository::connect(&config),
        AuthzPostgresRepository::connect(&config),
    );
    let repository = first.expect("initialize first repository concurrently");
    let second = second.expect("initialize second repository concurrently");
    second.ping().await.expect("ping second initialized repository");

    let tables = sqlx::query_scalar::<_, String>(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name LIKE 'iam_%' \
         ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await
    .expect("list PostgreSQL IAM tables");
    assert_eq!(
        tables,
        vec![
            "iam_action",
            "iam_authn_flow",
            "iam_principal",
            "iam_principal_identity",
            "iam_role",
            "iam_role_action",
            "iam_role_binding",
        ]
    );

    assert_repository_contract(&repository).await;
}
