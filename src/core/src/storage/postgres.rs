use anyhow::{bail, Context as _};
use async_trait::async_trait;
use sqlx::postgres::{PgConnection, PgPool, PgPoolOptions};
use sqlx::Executor as _;

use super::record::{
    ActionRecord, PolicyRecord, PrincipalRecord, RoleActionRecord, RoleBindingRecord,
};
use super::{PolicyRepository, PolicyRevisionConflict, PrincipalReferenced, PrincipalRepository};
use crate::config::PostgresConfig;
use crate::model::{Action, Policy, Principal, PrincipalStatus, Role, RoleBinding};

const AUTHORIZATION_SCHEMA_LOCK: i64 = 0x4155_5448_4755_4152;

#[derive(Debug)]
pub struct PostgresAuthorizationRepository {
    pool: PgPool,
}

impl PostgresAuthorizationRepository {
    /// Opens the connection pool and initializes the authorization schema.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be reached or migrated.
    pub async fn connect(config: &PostgresConfig) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.connect_timeout)
            .connect(&config.url)
            .await
            .context("connect to IAM database")?;
        let mut initialization =
            pool.begin().await.context("begin PostgreSQL authorization initialization")?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(AUTHORIZATION_SCHEMA_LOCK)
            .execute(&mut *initialization)
            .await
            .context("serialize PostgreSQL authorization initialization")?;
        sqlx::raw_sql(include_str!("../../migrations/001_init.ddl.sql"))
            .execute(&mut *initialization)
            .await
            .context("initialize PostgreSQL authorization schema")?;
        sqlx::raw_sql(include_str!("../../migrations/001_init.dml.sql"))
            .execute(&mut *initialization)
            .await
            .context("initialize PostgreSQL authorization data")?;
        initialization.commit().await.context("commit PostgreSQL authorization initialization")?;
        Ok(Self { pool })
    }

    async fn policy_record(
        connection: &mut PgConnection,
        for_update: bool,
    ) -> anyhow::Result<PolicyRecord> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let records = sqlx::query_as::<_, PolicyRecord>(&format!(
            "SELECT id, revision, name, description FROM iam_policy ORDER BY id LIMIT 2{suffix}"
        ))
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
        connection: &mut PgConnection,
        policy_id: &str,
    ) -> anyhow::Result<Vec<Action>> {
        sqlx::query_as::<_, ActionRecord>(
            "SELECT identifier, description, route_matchers \
             FROM iam_action WHERE policy_id = $1 ORDER BY identifier",
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
        connection: &mut PgConnection,
        policy_id: &str,
    ) -> anyhow::Result<Vec<Role>> {
        let records = sqlx::query_as::<_, RoleActionRecord>(
            "SELECT r.id AS role_id, r.name AS role_name, \
                    r.description AS role_description, ra.action_identifier \
             FROM iam_role r \
             LEFT JOIN iam_role_action ra \
               ON ra.policy_id = r.policy_id AND ra.role_id = r.id \
             WHERE r.policy_id = $1 \
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
        connection: &mut PgConnection,
        policy_id: &str,
    ) -> anyhow::Result<Vec<RoleBinding>> {
        sqlx::query_as::<_, RoleBindingRecord>(
            "SELECT id AS binding_id, principal_id, effect, resource_urn, conditions, role_id \
             FROM iam_role_binding WHERE policy_id = $1 ORDER BY id",
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
        connection: &mut PgConnection,
        policy_id: &str,
        actions: &[Action],
    ) -> anyhow::Result<()> {
        for action in actions {
            sqlx::query(
                "INSERT INTO iam_action(\
                    policy_id, identifier, description, route_matchers\
                 ) VALUES ($1, $2, $3, $4)",
            )
            .bind(policy_id)
            .bind(&action.identifier)
            .bind(&action.description)
            .bind(serde_json::to_value(&action.route_matchers)?)
            .execute(&mut *connection)
            .await?;
        }
        Ok(())
    }

    async fn insert_roles(
        connection: &mut PgConnection,
        policy_id: &str,
        roles: &[Role],
    ) -> anyhow::Result<()> {
        for role in roles {
            sqlx::query(
                "INSERT INTO iam_role(\
                    policy_id, id, name, description\
                 ) VALUES ($1, $2, $3, $4)",
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
                     VALUES ($1, $2, $3)",
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
        connection: &mut PgConnection,
        policy_id: &str,
        bindings: &[RoleBinding],
    ) -> anyhow::Result<()> {
        for binding in bindings {
            sqlx::query(
                "INSERT INTO iam_role_binding(\
                    policy_id, id, principal_id, role_id, effect, resource_urn, conditions\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(policy_id)
            .bind(&binding.id)
            .bind(&binding.principal_id)
            .bind(&binding.role_id)
            .bind(binding.effect.as_str())
            .bind(&binding.resource_urn)
            .bind(serde_json::to_value(&binding.conditions)?)
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

    async fn optional_principal(
        &self,
        query: sqlx::query::QueryAs<
            '_,
            sqlx::Postgres,
            PrincipalRecord,
            sqlx::postgres::PgArguments,
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
impl PolicyRepository for PostgresAuthorizationRepository {
    async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("ping PostgreSQL authorization storage")?;
        Ok(())
    }

    async fn load(&self) -> anyhow::Result<Policy> {
        let mut transaction = self.pool.begin().await.context("begin policy read")?;
        transaction
            .execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .await
            .context("configure consistent policy read")?;
        let record = Self::policy_record(&mut transaction, false).await?;
        let revision = u64::try_from(record.revision).context("IAM policy revision is negative")?;
        let actions = Self::load_actions(&mut transaction, &record.id).await?;
        let roles = Self::load_roles(&mut transaction, &record.id).await?;
        let role_bindings = Self::load_bindings(&mut transaction, &record.id).await?;
        transaction.commit().await.context("commit policy read")?;
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
        let revision = i64::try_from(policy.revision).context("policy revision exceeds BIGINT")?;
        let mut transaction = self.pool.begin().await.context("begin policy replacement")?;
        let persisted = Self::policy_record(&mut transaction, true).await?;
        let policy_id = persisted.id;
        let actual_revision =
            u64::try_from(persisted.revision).context("IAM policy revision is negative")?;
        if actual_revision != expected_revision {
            return Err(PolicyRevisionConflict {
                expected: expected_revision,
                actual: actual_revision,
            }
            .into());
        }
        if policy.id != policy_id {
            bail!("active policy id `{policy_id}` cannot be replaced by `{}`", policy.id);
        }
        if policy.revision <= expected_revision {
            bail!(
                "replacement policy revision {} must be greater than persisted revision {expected_revision}",
                policy.revision
            );
        }

        for statement in [
            "DELETE FROM iam_role_binding WHERE policy_id = $1",
            "DELETE FROM iam_role_action WHERE policy_id = $1",
            "DELETE FROM iam_role WHERE policy_id = $1",
            "DELETE FROM iam_action WHERE policy_id = $1",
        ] {
            sqlx::query(statement).bind(&policy_id).execute(&mut *transaction).await?;
        }
        Self::insert_actions(&mut transaction, &policy_id, &policy.actions).await?;
        Self::insert_roles(&mut transaction, &policy_id, &policy.roles).await?;
        Self::insert_bindings(&mut transaction, &policy_id, &policy.role_bindings).await?;

        let updated = sqlx::query(
            "UPDATE iam_policy SET name = $1, description = $2, revision = $3, \
                    updated_at = CURRENT_TIMESTAMP \
             WHERE id = $4 AND revision = $5",
        )
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(revision)
        .bind(&policy_id)
        .bind(i64::try_from(expected_revision).context("expected revision exceeds BIGINT")?)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            bail!("active IAM policy changed while holding its update lock");
        }
        transaction.commit().await.context("commit policy replacement")
    }
}

#[async_trait]
impl PrincipalRepository for PostgresAuthorizationRepository {
    async fn upsert(&self, principal: &Principal) -> anyhow::Result<Principal> {
        Self::validate_principal(principal)?;
        let record = sqlx::query_as::<_, PrincipalRecord>(
            "INSERT INTO iam_principal(\
                id, issuer, external_id, kind, display_name, status, attributes, last_seen_at\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP) \
             ON CONFLICT(issuer, external_id) DO UPDATE SET \
                kind = EXCLUDED.kind, display_name = EXCLUDED.display_name, \
                status = EXCLUDED.status, attributes = EXCLUDED.attributes, \
                last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP \
             RETURNING id, issuer, external_id, kind, display_name, status, attributes",
        )
        .bind(&principal.id)
        .bind(&principal.issuer)
        .bind(&principal.external_id)
        .bind(principal.kind.as_str())
        .bind(&principal.display_name)
        .bind(principal.status.as_str())
        .bind(serde_json::to_value(&principal.attributes)?)
        .fetch_one(&self.pool)
        .await
        .context("upsert IAM principal projection")?;
        record.try_into_model()
    }

    async fn get(&self, id: &str) -> anyhow::Result<Option<Principal>> {
        self.optional_principal(
            sqlx::query_as::<_, PrincipalRecord>(
                "SELECT id, issuer, external_id, kind, display_name, status, attributes \
                 FROM iam_principal WHERE id = $1",
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
                "SELECT id, issuer, external_id, kind, display_name, status, attributes \
                 FROM iam_principal WHERE issuer = $1 AND external_id = $2",
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
        sqlx::query_as::<_, PrincipalRecord>(
            "SELECT id, issuer, external_id, kind, display_name, status, attributes \
             FROM iam_principal \
             WHERE issuer = $1 AND external_id = ANY($2) \
             ORDER BY external_id",
        )
        .bind(issuer)
        .bind(external_ids)
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
            "SELECT id, issuer, external_id, kind, display_name, status, attributes \
             FROM iam_principal \
             WHERE id > $1 \
               AND ($2 = '%' OR LOWER(display_name) LIKE LOWER($2) ESCAPE '\\' \
                            OR LOWER(external_id) LIKE LOWER($2) ESCAPE '\\') \
             ORDER BY id LIMIT $3",
        )
        .bind(after_id.unwrap_or(""))
        .bind(pattern)
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
                "UPDATE iam_principal SET status = $1, updated_at = CURRENT_TIMESTAMP \
                 WHERE id = $2 \
                 RETURNING id, issuer, external_id, kind, display_name, status, attributes",
            )
            .bind(status.as_str())
            .bind(id),
        )
        .await
    }

    async fn delete(&self, id: &str) -> anyhow::Result<bool> {
        match sqlx::query("DELETE FROM iam_principal WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
        {
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
