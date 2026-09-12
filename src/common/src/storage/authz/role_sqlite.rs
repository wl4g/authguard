use super::PolicyRepository;
use crate::model::{
    AuthorizationConditionSpec, Effect, HttpRouteMatcher, IamActionInfo, IamPolicyInfo,
    IamRoleBindingInfo, IamRoleInfo,
};
use crate::storage::SqliteRepository;
use anyhow::{bail, Context as _};
use async_trait::async_trait;
use serde_json::Value;
use sqlx::sqlite::SqliteConnection;
use sqlx::FromRow;
use std::ops::Deref;

#[derive(Debug)]
pub struct AuthzSqliteRepository {
    inner: SqliteRepository,
}

#[derive(Debug, FromRow)]
struct StoredAction {
    identifier: String,
    description: String,
    route_matchers: Value,
}

impl StoredAction {
    fn try_into_model(self) -> anyhow::Result<IamActionInfo> {
        Ok(IamActionInfo {
            identifier: self.identifier,
            description: self.description,
            route_matchers: serde_json::from_value::<Vec<HttpRouteMatcher>>(self.route_matchers)
                .context("decode IAM action route matchers")?,
        })
    }
}

#[derive(Debug, FromRow)]
struct RoleWithAction {
    role_id: String,
    role_name: String,
    role_description: String,
    action_identifier: Option<String>,
}

#[derive(Debug, FromRow)]
struct StoredRoleBinding {
    binding_id: String,
    principal_id: String,
    role_id: String,
    effect: String,
    resource_urn: String,
    conditions: Value,
}

impl StoredRoleBinding {
    fn try_into_model(self) -> anyhow::Result<IamRoleBindingInfo> {
        let effect = match self.effect.as_str() {
            "ALLOW" => Effect::Allow,
            "DENY" => Effect::Deny,
            value => bail!("unsupported IAM role binding effect `{value}`"),
        };
        Ok(IamRoleBindingInfo {
            id: self.binding_id,
            principal_id: self.principal_id,
            role_id: self.role_id,
            effect,
            resource_urn: self.resource_urn,
            conditions: serde_json::from_value::<AuthorizationConditionSpec>(self.conditions)
                .context("decode IAM role binding conditions")?,
        })
    }
}

impl AuthzSqliteRepository {
    /// Opens the SQLite-backed `AuthZ` aggregate repository.
    ///
    /// # Errors
    ///
    /// Returns an error when connection or schema initialization fails.
    pub async fn connect(config: &crate::config::SqliteProperties) -> anyhow::Result<Self> {
        Ok(Self { inner: SqliteRepository::connect(config).await? })
    }
}

impl Deref for AuthzSqliteRepository {
    type Target = SqliteRepository;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AuthzSqliteRepository {
    async fn load_actions(connection: &mut SqliteConnection) -> anyhow::Result<Vec<IamActionInfo>> {
        sqlx::query_as::<_, StoredAction>(
            "SELECT identifier, description, JSON(route_matchers) AS route_matchers \
             FROM iam_action ORDER BY identifier",
        )
        .fetch_all(connection)
        .await
        .context("query IAM actions")?
        .into_iter()
        .map(StoredAction::try_into_model)
        .collect()
    }

    async fn load_roles(connection: &mut SqliteConnection) -> anyhow::Result<Vec<IamRoleInfo>> {
        let records = sqlx::query_as::<_, RoleWithAction>(
            "SELECT r.id AS role_id, r.name AS role_name, \
                    r.description AS role_description, ra.action_identifier \
             FROM iam_role r \
             LEFT JOIN iam_role_action ra ON ra.role_id = r.id \
             ORDER BY r.id, ra.action_identifier",
        )
        .fetch_all(connection)
        .await
        .context("query IAM roles")?;
        let mut roles = Vec::<IamRoleInfo>::new();
        for record in records {
            if roles.last().is_none_or(|role| role.id != record.role_id) {
                roles.push(IamRoleInfo {
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
    ) -> anyhow::Result<Vec<IamRoleBindingInfo>> {
        sqlx::query_as::<_, StoredRoleBinding>(
            "SELECT id AS binding_id, principal_id, effect, resource_urn, \
                    JSON(conditions) AS conditions, role_id \
             FROM iam_role_binding ORDER BY id",
        )
        .fetch_all(connection)
        .await
        .context("query IAM role bindings")?
        .into_iter()
        .map(StoredRoleBinding::try_into_model)
        .collect()
    }

    async fn insert_actions(
        connection: &mut SqliteConnection,
        actions: &[IamActionInfo],
    ) -> anyhow::Result<()> {
        for action in actions {
            sqlx::query(
                "INSERT INTO iam_action(\
                    identifier, description, route_matchers\
                 ) VALUES (?, ?, ?)",
            )
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
        roles: &[IamRoleInfo],
    ) -> anyhow::Result<()> {
        for role in roles {
            sqlx::query(
                "INSERT INTO iam_role(\
                    id, name, description\
                 ) VALUES (?, ?, ?)",
            )
            .bind(&role.id)
            .bind(&role.name)
            .bind(&role.description)
            .execute(&mut *connection)
            .await?;
            for identifier in &role.action_ids {
                sqlx::query(
                    "INSERT INTO iam_role_action(\
                        role_id, action_identifier\
                     ) \
                     VALUES (?, ?)",
                )
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
        bindings: &[IamRoleBindingInfo],
    ) -> anyhow::Result<()> {
        for binding in bindings {
            sqlx::query(
                "INSERT INTO iam_role_binding(\
                    id, principal_id, role_id, effect, resource_urn, conditions\
                 ) VALUES (?, ?, ?, ?, ?, ?)",
            )
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
}

#[async_trait]
impl PolicyRepository for AuthzSqliteRepository {
    async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("ping SQLite authorization storage")?;
        Ok(())
    }

    async fn load(&self) -> anyhow::Result<IamPolicyInfo> {
        let mut transaction = self.pool.begin().await.context("begin SQLite policy read")?;
        let actions = Self::load_actions(&mut transaction).await?;
        let roles = Self::load_roles(&mut transaction).await?;
        let role_bindings = Self::load_bindings(&mut transaction).await?;
        transaction.commit().await.context("commit SQLite policy read")?;
        Ok(IamPolicyInfo { revision: 1, actions, roles, role_bindings })
    }

    async fn replace(&self, policy: &IamPolicyInfo) -> anyhow::Result<()> {
        // Serialize the aggregate replacement so readers never observe a
        // partially rewritten authorization catalog.
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .context("begin serialized SQLite policy replacement")?;
        for statement in [
            "DELETE FROM iam_role_binding",
            "DELETE FROM iam_role_action",
            "DELETE FROM iam_role",
            "DELETE FROM iam_action",
        ] {
            sqlx::query(statement).execute(&mut *transaction).await?;
        }
        Self::insert_actions(&mut transaction, &policy.actions).await?;
        Self::insert_roles(&mut transaction, &policy.roles).await?;
        Self::insert_bindings(&mut transaction, &policy.role_bindings).await?;
        transaction.commit().await.context("commit SQLite policy replacement")
    }
}
