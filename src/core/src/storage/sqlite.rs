use std::str::FromStr as _;

use super::record::{
    ActionRecord, PolicyRecord, PrincipalRecord, RoleActionRecord, RoleBindingRecord,
};
use super::{PolicyRepository, PolicyRevisionConflict, PrincipalReferenced, PrincipalRepository};
use crate::config::SqliteConfig;
use crate::model::{Action, Policy, Principal, PrincipalStatus, Role, RoleBinding};
use anyhow::{bail, Context as _};
use async_trait::async_trait;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool, SqlitePoolOptions,
    SqliteSynchronous,
};
use sqlx::QueryBuilder;

#[derive(Debug)]
pub struct SqliteAuthorizationRepository {
    pool: SqlitePool,
}

impl SqliteAuthorizationRepository {
    /// Opens `SQLite` and creates the normalized IAM schema when it is absent.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is invalid or the database cannot be opened or initialized.
    pub async fn connect(config: &SqliteConfig) -> anyhow::Result<Self> {
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
            .context("begin serialized SQLite authorization initialization")?;
        sqlx::raw_sql(include_str!("../../migrations/001_init.ddl.sql"))
            .execute(&mut *initialization)
            .await
            .context("initialize SQLite authorization schema")?;
        sqlx::raw_sql(include_str!("../../migrations/001_init.dml.sql"))
            .execute(&mut *initialization)
            .await
            .context("initialize SQLite authorization data")?;
        initialization.commit().await.context("commit SQLite authorization initialization")?;
        Ok(Self { pool })
    }

    async fn policy_record(connection: &mut SqliteConnection) -> anyhow::Result<PolicyRecord> {
        let records = sqlx::query_as::<_, PolicyRecord>(
            "SELECT id, revision, name, description FROM iam_policy ORDER BY id LIMIT 2",
        )
        .fetch_all(connection)
        .await
        .context("query IAM policy aggregate")?;
        match records.as_slice() {
            [] => bail!("IAM policy aggregate is missing"),
            [_] => Ok(records.into_iter().next().expect("one policy record")),
            _ => bail!("multiple IAM policy aggregates are not supported"),
        }
    }

    async fn load_actions(
        connection: &mut SqliteConnection,
        policy_id: &str,
    ) -> anyhow::Result<Vec<Action>> {
        sqlx::query_as::<_, ActionRecord>(
            "SELECT identifier, description, JSON(route_matchers) AS route_matchers \
             FROM iam_action WHERE policy_id = ? ORDER BY identifier",
        )
        .bind(policy_id)
        .fetch_all(connection)
        .await
        .context("query IAM actions")?
        .into_iter()
        .map(ActionRecord::try_into_model)
        .collect()
    }

    async fn load_roles(
        connection: &mut SqliteConnection,
        policy_id: &str,
    ) -> anyhow::Result<Vec<Role>> {
        let records = sqlx::query_as::<_, RoleActionRecord>(
            "SELECT r.id AS role_id, r.name AS role_name, \
                    r.description AS role_description, ra.action_identifier \
             FROM iam_role r \
             LEFT JOIN iam_role_action ra \
               ON ra.policy_id = r.policy_id AND ra.role_id = r.id \
             WHERE r.policy_id = ? \
             ORDER BY r.id, ra.action_identifier",
        )
        .bind(policy_id)
        .fetch_all(connection)
        .await
        .context("query IAM roles")?;
        let mut roles = Vec::<Role>::new();
        for record in records {
            if roles.last().is_none_or(|role| role.id != record.role_id) {
                roles.push(Role {
                    id: record.role_id,
                    name: record.role_name,
                    description: record.role_description,
                    action_ids: Vec::new(),
                });
            }
            if let Some(identifier) = record.action_identifier {
                roles.last_mut().expect("role was inserted").action_ids.push(identifier);
            }
        }
        Ok(roles)
    }

    async fn load_bindings(
        connection: &mut SqliteConnection,
        policy_id: &str,
    ) -> anyhow::Result<Vec<RoleBinding>> {
        sqlx::query_as::<_, RoleBindingRecord>(
            "SELECT id AS binding_id, principal_id, effect, resource_urn, \
                    JSON(conditions) AS conditions, role_id \
             FROM iam_role_binding WHERE policy_id = ? ORDER BY id",
        )
        .bind(policy_id)
        .fetch_all(connection)
        .await
        .context("query IAM role bindings")?
        .into_iter()
        .map(RoleBindingRecord::try_into_model)
        .collect()
    }

    async fn insert_actions(
        connection: &mut SqliteConnection,
        policy_id: &str,
        actions: &[Action],
    ) -> anyhow::Result<()> {
        for action in actions {
            sqlx::query(
                "INSERT INTO iam_action(\
                    policy_id, identifier, description, route_matchers\
                 ) VALUES (?, ?, ?, ?)",
            )
            .bind(policy_id)
            .bind(&action.identifier)
            .bind(&action.description)
            .bind(serde_json::to_string(&action.route_matchers)?)
            .execute(&mut *connection)
            .await?;
        }
        Ok(())
    }

    async fn insert_roles(
        connection: &mut SqliteConnection,
        policy_id: &str,
        roles: &[Role],
    ) -> anyhow::Result<()> {
        for role in roles {
            sqlx::query(
                "INSERT INTO iam_role(\
                    policy_id, id, name, description\
                 ) VALUES (?, ?, ?, ?)",
            )
            .bind(policy_id)
            .bind(&role.id)
            .bind(&role.name)
            .bind(&role.description)
            .execute(&mut *connection)
            .await?;
            for identifier in &role.action_ids {
                sqlx::query(
                    "INSERT INTO iam_role_action(\
                        policy_id, role_id, action_identifier\
                     ) \
                     VALUES (?, ?, ?)",
                )
                .bind(policy_id)
                .bind(&role.id)
                .bind(identifier)
                .execute(&mut *connection)
                .await?;
            }
        }
        Ok(())
    }

    async fn insert_bindings(
        connection: &mut SqliteConnection,
        policy_id: &str,
        bindings: &[RoleBinding],
    ) -> anyhow::Result<()> {
        for binding in bindings {
            sqlx::query(
                "INSERT INTO iam_role_binding(\
                    policy_id, id, principal_id, role_id, effect, resource_urn, conditions\
                 ) VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(policy_id)
            .bind(&binding.id)
            .bind(&binding.principal_id)
            .bind(&binding.role_id)
            .bind(binding.effect.as_str())
            .bind(&binding.resource_urn)
            .bind(serde_json::to_string(&binding.conditions)?)
            .execute(&mut *connection)
            .await
            .with_context(|| {
                format!(
                    "insert IAM role binding `{}`; principal `{}` must already be projected",
                    binding.id, binding.principal_id
                )
            })?;
        }
        Ok(())
    }

    async fn optional_principal<'q>(
        &self,
        query: sqlx::query::QueryAs<
            'q,
            sqlx::Sqlite,
            PrincipalRecord,
            sqlx::sqlite::SqliteArguments<'q>,
        >,
    ) -> anyhow::Result<Option<Principal>> {
        query.fetch_optional(&self.pool).await?.map(PrincipalRecord::try_into_model).transpose()
    }

    fn validate_principal(principal: &Principal) -> anyhow::Result<()> {
        if principal.id.trim().is_empty()
            || principal.issuer.trim().is_empty()
            || principal.external_id.trim().is_empty()
            || principal.display_name.trim().is_empty()
        {
            bail!("IAM principal identifiers and display name must not be empty");
        }
        Ok(())
    }

    fn prefix_pattern(input: &str) -> String {
        if input.is_empty() {
            return "%".to_string();
        }
        let escaped = input.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        format!("{escaped}%")
    }
}

#[async_trait]
impl PolicyRepository for SqliteAuthorizationRepository {
    async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("ping SQLite authorization storage")?;
        Ok(())
    }

    async fn load(&self) -> anyhow::Result<Policy> {
        let mut transaction = self.pool.begin().await.context("begin SQLite policy read")?;
        let record = Self::policy_record(&mut transaction).await?;
        let revision = u64::try_from(record.revision).context("IAM policy revision is negative")?;
        let actions = Self::load_actions(&mut transaction, &record.id).await?;
        let roles = Self::load_roles(&mut transaction, &record.id).await?;
        let role_bindings = Self::load_bindings(&mut transaction, &record.id).await?;
        transaction.commit().await.context("commit SQLite policy read")?;
        Ok(Policy {
            id: record.id,
            revision,
            name: record.name,
            description: record.description,
            actions,
            roles,
            role_bindings,
        })
    }

    async fn compare_and_replace(
        &self,
        expected_revision: u64,
        policy: &Policy,
    ) -> anyhow::Result<()> {
        if policy.revision <= expected_revision {
            bail!(
                "replacement policy revision {} must be greater than persisted revision {expected_revision}",
                policy.revision
            );
        }
        let revision = i64::try_from(policy.revision).context("policy revision exceeds INTEGER")?;
        let expected =
            i64::try_from(expected_revision).context("expected revision exceeds INTEGER")?;
        // Acquire SQLite's write reservation before reading the revision. This
        // gives the same compare-and-swap semantics as PostgreSQL's row lock
        // instead of allowing two deferred transactions to observe one value.
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .context("begin serialized SQLite policy replacement")?;
        let persisted = Self::policy_record(&mut transaction).await?;
        let actual =
            u64::try_from(persisted.revision).context("IAM policy revision is negative")?;
        if actual != expected_revision {
            return Err(PolicyRevisionConflict { expected: expected_revision, actual }.into());
        }
        if persisted.id != policy.id {
            bail!(
                "policy identifier is immutable: persisted `{}`, replacement `{}`",
                persisted.id,
                policy.id
            );
        }

        let updated = sqlx::query(
            "UPDATE iam_policy SET name = ?, description = ?, revision = ?, \
                    updated_at = CURRENT_TIMESTAMP \
             WHERE id = ? AND revision = ?",
        )
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(revision)
        .bind(&policy.id)
        .bind(expected)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            bail!("IAM policy changed while holding its update transaction");
        }
        for statement in [
            "DELETE FROM iam_role_binding WHERE policy_id = ?",
            "DELETE FROM iam_role_action WHERE policy_id = ?",
            "DELETE FROM iam_role WHERE policy_id = ?",
            "DELETE FROM iam_action WHERE policy_id = ?",
        ] {
            sqlx::query(statement).bind(&policy.id).execute(&mut *transaction).await?;
        }
        Self::insert_actions(&mut transaction, &policy.id, &policy.actions).await?;
        Self::insert_roles(&mut transaction, &policy.id, &policy.roles).await?;
        Self::insert_bindings(&mut transaction, &policy.id, &policy.role_bindings).await?;
        transaction.commit().await.context("commit SQLite policy replacement")
    }
}

#[async_trait]
impl PrincipalRepository for SqliteAuthorizationRepository {
    async fn upsert(&self, principal: &Principal) -> anyhow::Result<Principal> {
        Self::validate_principal(principal)?;
        sqlx::query(
            "INSERT INTO iam_principal(\
                id, issuer, external_id, kind, display_name, status, attributes, last_seen_at\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) \
             ON CONFLICT(issuer, external_id) DO UPDATE SET \
                kind = excluded.kind, display_name = excluded.display_name, \
                status = excluded.status, attributes = excluded.attributes, \
                last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP",
        )
        .bind(&principal.id)
        .bind(&principal.issuer)
        .bind(&principal.external_id)
        .bind(principal.kind.as_str())
        .bind(&principal.display_name)
        .bind(principal.status.as_str())
        .bind(serde_json::to_string(&principal.attributes)?)
        .execute(&self.pool)
        .await
        .context("upsert IAM principal projection")?;
        self.find_by_external_key(&principal.issuer, &principal.external_id)
            .await?
            .context("upserted IAM principal projection is missing")
    }

    async fn get(&self, id: &str) -> anyhow::Result<Option<Principal>> {
        self.optional_principal(
            sqlx::query_as::<_, PrincipalRecord>(
                "SELECT id, issuer, external_id, kind, display_name, status, \
                        JSON(attributes) AS attributes \
                 FROM iam_principal WHERE id = ?",
            )
            .bind(id),
        )
        .await
    }

    async fn find_by_external_key(
        &self,
        issuer: &str,
        external_id: &str,
    ) -> anyhow::Result<Option<Principal>> {
        self.optional_principal(
            sqlx::query_as::<_, PrincipalRecord>(
                "SELECT id, issuer, external_id, kind, display_name, status, \
                        JSON(attributes) AS attributes \
                 FROM iam_principal WHERE issuer = ? AND external_id = ?",
            )
            .bind(issuer)
            .bind(external_id),
        )
        .await
    }

    async fn find_by_external_keys(
        &self,
        issuer: &str,
        external_ids: &[String],
    ) -> anyhow::Result<Vec<Principal>> {
        if external_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut query = QueryBuilder::new(
            "SELECT id, issuer, external_id, kind, display_name, status, \
                    JSON(attributes) AS attributes \
             FROM iam_principal WHERE issuer = ",
        );
        query.push_bind(issuer).push(" AND external_id IN (");
        let mut values = query.separated(", ");
        for external_id in external_ids {
            values.push_bind(external_id);
        }
        values.push_unseparated(") ORDER BY external_id");
        query
            .build_query_as::<PrincipalRecord>()
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(PrincipalRecord::try_into_model)
            .collect()
    }

    async fn list(
        &self,
        query: &str,
        after_id: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<Principal>> {
        let pattern = Self::prefix_pattern(query);
        sqlx::query_as::<_, PrincipalRecord>(
            "SELECT id, issuer, external_id, kind, display_name, status, \
                    JSON(attributes) AS attributes \
             FROM iam_principal \
             WHERE id > ? \
               AND (? = '%' OR LOWER(display_name) LIKE LOWER(?) ESCAPE '\\' \
                             OR LOWER(external_id) LIKE LOWER(?) ESCAPE '\\') \
             ORDER BY id LIMIT ?",
        )
        .bind(after_id.unwrap_or(""))
        .bind(&pattern)
        .bind(&pattern)
        .bind(&pattern)
        .bind(i64::from(limit.clamp(1, 100)))
        .fetch_all(&self.pool)
        .await
        .context("list IAM principal projections")?
        .into_iter()
        .map(PrincipalRecord::try_into_model)
        .collect()
    }

    async fn update_status(
        &self,
        id: &str,
        status: PrincipalStatus,
    ) -> anyhow::Result<Option<Principal>> {
        self.optional_principal(
            sqlx::query_as::<_, PrincipalRecord>(
                "UPDATE iam_principal SET status = ?, updated_at = CURRENT_TIMESTAMP \
                 WHERE id = ? \
                 RETURNING id, issuer, external_id, kind, display_name, status, \
                           JSON(attributes) AS attributes",
            )
            .bind(status.as_str())
            .bind(id),
        )
        .await
    }

    async fn delete(&self, id: &str) -> anyhow::Result<bool> {
        match sqlx::query("DELETE FROM iam_principal WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
        {
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::model::{
        AuthorizationConditionSpec, Effect, HttpRouteMatcher, PrincipalKind, PrincipalStatus,
    };

    async fn repository() -> SqliteAuthorizationRepository {
        SqliteAuthorizationRepository::connect(&SqliteConfig {
            url: "sqlite::memory:".to_string(),
            max_connections: 1,
            connect_timeout: Duration::from_secs(2),
        })
        .await
        .expect("connect")
    }

    fn principal(id: &str, issuer: &str, external_id: &str) -> Principal {
        Principal {
            id: id.to_string(),
            issuer: issuer.to_string(),
            external_id: external_id.to_string(),
            kind: PrincipalKind::User,
            display_name: "Alice Analyst".to_string(),
            status: PrincipalStatus::Active,
            attributes: BTreeMap::from([("department".to_string(), json!("growth"))]),
        }
    }

    fn policy(principal_id: &str, revision: u64) -> Policy {
        let action_id = "customer-growth.job.read".to_string();
        Policy {
            id: "default".to_string(),
            revision,
            name: "Customer growth authorization".to_string(),
            description: "Customer growth job access".to_string(),
            actions: vec![Action {
                identifier: action_id.clone(),
                description: "Read one growth job".to_string(),
                route_matchers: vec![HttpRouteMatcher {
                    id: "customer-growth-job-read".to_string(),
                    methods: vec!["GET".to_string()],
                    hosts: vec!["growth.example.com".to_string()],
                    path: "/jobs/{job_id}".to_string(),
                    resource_urn: "urn:iam:prod:customer-growth:global:{tenant_id}:workspace/growth/job/{job_id}".to_string(),
                    parent_urns: Vec::new(),
                }],
            }],
            roles: vec![Role {
                id: "customer-growth.viewer".to_string(),
                name: "Customer growth viewer".to_string(),
                description: String::new(),
                action_ids: vec![action_id],
            }],
            role_bindings: vec![RoleBinding {
                id: "customer-growth-viewer-binding".to_string(),
                principal_id: principal_id.to_string(),
                role_id: "customer-growth.viewer".to_string(),
                effect: Effect::Allow,
                resource_urn:
                    "urn:iam:prod:customer-growth:global:example-corp:workspace/growth/job/**"
                        .to_string(),
                conditions: AuthorizationConditionSpec::default(),
            }],
        }
    }

    #[tokio::test]
    async fn external_identity_is_unique_by_issuer_and_external_id() {
        let repository = repository().await;
        let original = principal("principal-1", "https://id.example/realms/main", "user-42");
        assert_eq!(repository.upsert(&original).await.unwrap(), original);

        let mut refreshed = principal("ignored-new-id", &original.issuer, &original.external_id);
        refreshed.display_name = "Alice Growth Analyst".to_string();
        let stored = repository.upsert(&refreshed).await.unwrap();
        assert_eq!(stored.id, original.id);
        assert_eq!(stored.display_name, refreshed.display_name);
        assert_eq!(
            repository.find_by_external_key(&original.issuer, &original.external_id).await.unwrap(),
            Some(stored)
        );
    }

    #[tokio::test]
    async fn same_external_id_from_different_issuers_remains_distinct() {
        let repository = repository().await;
        let first = principal("principal-1", "https://id.example/realms/one", "same-sub");
        let second = principal("principal-2", "https://id.example/realms/two", "same-sub");
        repository.upsert(&first).await.unwrap();
        repository.upsert(&second).await.unwrap();

        assert_eq!(repository.get(&first.id).await.unwrap(), Some(first));
        assert_eq!(repository.get(&second.id).await.unwrap(), Some(second));
    }

    #[tokio::test]
    async fn batch_identity_lookup_is_issuer_scoped_and_deterministic() {
        let repository = repository().await;
        let issuer = "https://id.example/realms/main";
        let user = principal("principal-user", issuer, "user-42");
        let group = principal("principal-group", issuer, "group:team-7");
        let other_issuer =
            principal("principal-other", "https://id.example/realms/other", "group:team-7");
        repository.upsert(&user).await.unwrap();
        repository.upsert(&group).await.unwrap();
        repository.upsert(&other_issuer).await.unwrap();

        let found = repository
            .find_by_external_keys(
                issuer,
                &["user-42".to_string(), "missing".to_string(), "group:team-7".to_string()],
            )
            .await
            .unwrap();

        assert_eq!(found, vec![group, user]);
    }

    #[tokio::test]
    async fn normalized_schema_round_trips_policy_with_projected_principal() {
        let repository = repository().await;
        let principal = principal("principal-1", "https://id.example/realms/main", "user-42");
        repository.upsert(&principal).await.unwrap();
        let expected = policy(&principal.id, 1);

        repository.compare_and_replace(0, &expected).await.unwrap();

        assert_eq!(repository.load().await.unwrap(), expected);
    }

    #[tokio::test]
    async fn missing_principal_rolls_back_complete_policy_replacement() {
        let repository = repository().await;
        let principal = principal("principal-1", "https://id.example/realms/main", "user-42");
        repository.upsert(&principal).await.unwrap();
        let original = policy(&principal.id, 1);
        repository.compare_and_replace(0, &original).await.unwrap();

        let replacement = policy("not-projected", 2);
        assert!(repository.compare_and_replace(1, &replacement).await.is_err());
        assert_eq!(repository.load().await.unwrap(), original);
    }

    #[tokio::test]
    async fn policy_compare_and_swap_rejects_a_stale_writer() {
        let repository = repository().await;
        repository
            .compare_and_replace(0, &Policy { revision: 1, ..Policy::default() })
            .await
            .unwrap();
        let error = repository
            .compare_and_replace(0, &Policy { revision: 2, ..Policy::default() })
            .await
            .expect_err("stale write must fail");
        assert_eq!(
            error.downcast_ref::<PolicyRevisionConflict>(),
            Some(&PolicyRevisionConflict { expected: 0, actual: 1 })
        );
        assert_eq!(repository.load().await.unwrap().revision, 1);
    }

    #[tokio::test]
    async fn concurrent_policy_writers_cannot_lose_an_update() {
        let repository = Arc::new(repository().await);
        let first_repository = Arc::clone(&repository);
        let second_repository = Arc::clone(&repository);
        let first = Policy { revision: 1, name: "First writer".to_string(), ..Policy::default() };
        let second = Policy { revision: 2, name: "Second writer".to_string(), ..Policy::default() };

        let (first_result, second_result) = tokio::join!(
            first_repository.compare_and_replace(0, &first),
            second_repository.compare_and_replace(0, &second),
        );

        assert_ne!(first_result.is_ok(), second_result.is_ok());
        let persisted = repository.load().await.unwrap();
        assert!(
            (persisted.revision == 1 && persisted.name == "First writer")
                || (persisted.revision == 2 && persisted.name == "Second writer")
        );
    }

    #[tokio::test]
    async fn policy_collections_load_in_deterministic_identifier_order() {
        let repository = repository().await;
        let policy = Policy {
            revision: 1,
            actions: vec![
                Action {
                    identifier: "z.action".to_string(),
                    description: String::new(),
                    route_matchers: Vec::new(),
                },
                Action {
                    identifier: "a.action".to_string(),
                    description: String::new(),
                    route_matchers: Vec::new(),
                },
            ],
            roles: vec![
                Role {
                    id: "z.role".to_string(),
                    name: "Z role".to_string(),
                    description: String::new(),
                    action_ids: vec!["z.action".to_string()],
                },
                Role {
                    id: "a.role".to_string(),
                    name: "A role".to_string(),
                    description: String::new(),
                    action_ids: vec!["a.action".to_string()],
                },
            ],
            ..Policy::default()
        };
        repository.compare_and_replace(0, &policy).await.unwrap();

        let loaded = repository.load().await.unwrap();
        assert_eq!(
            loaded.actions.iter().map(|action| action.identifier.as_str()).collect::<Vec<_>>(),
            vec!["a.action", "z.action"]
        );
        assert_eq!(
            loaded.roles.iter().map(|role| role.id.as_str()).collect::<Vec<_>>(),
            vec!["a.role", "z.role"]
        );
    }

    #[tokio::test]
    async fn principal_lifecycle_preserves_binding_referential_integrity() {
        let repository = repository().await;
        let principal = principal("principal-1", "https://id.example/realms/main", "user-42");
        repository.upsert(&principal).await.unwrap();
        repository.compare_and_replace(0, &policy(&principal.id, 1)).await.unwrap();

        let disabled = repository
            .update_status(&principal.id, PrincipalStatus::Disabled)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(disabled.status, PrincipalStatus::Disabled);
        let error = repository.delete(&principal.id).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<PrincipalReferenced>(),
            Some(&PrincipalReferenced { id: principal.id.clone() })
        );
        assert_eq!(repository.get(&principal.id).await.unwrap(), Some(disabled));
    }

    #[tokio::test]
    async fn unreferenced_principal_can_be_deleted() {
        let repository = repository().await;
        let principal = principal("principal-1", "https://id.example/realms/main", "user-42");
        repository.upsert(&principal).await.unwrap();

        assert!(repository.delete(&principal.id).await.unwrap());
        assert!(!repository.delete(&principal.id).await.unwrap());
        assert!(repository.get(&principal.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn principal_list_uses_literal_prefix_and_id_cursor() {
        let repository = repository().await;
        let mut percent = principal("principal-1", "https://id.example", "user-percent");
        percent.display_name = "Growth 100% Analyst".to_string();
        let ordinary = principal("principal-2", "https://id.example", "user-ordinary");
        repository.upsert(&percent).await.unwrap();
        repository.upsert(&ordinary).await.unwrap();

        assert_eq!(repository.list("Growth 100%", None, 10).await.unwrap(), vec![percent]);
        assert!(repository.list("_", None, 10).await.unwrap().is_empty());
        assert_eq!(repository.list("", Some("principal-1"), 10).await.unwrap(), vec![ordinary]);
    }
}
