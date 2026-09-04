use std::collections::BTreeMap;

use anyhow::{bail, Context as _};
use serde_json::Value;
use sqlx::FromRow;

use crate::model::{
    Action, AuthorizationConditionSpec, Effect, HttpRouteMatcher, Principal, PrincipalKind,
    PrincipalStatus, RoleBinding,
};

#[derive(Debug, FromRow)]
pub(super) struct PolicyRecord {
    pub(super) id: String,
    pub(super) revision: i64,
    pub(super) name: String,
    pub(super) description: String,
}

#[derive(Debug, FromRow)]
pub(super) struct PrincipalRecord {
    pub(super) id: String,
    pub(super) issuer: String,
    pub(super) external_id: String,
    pub(super) kind: String,
    pub(super) display_name: String,
    pub(super) status: String,
    pub(super) attributes: Value,
}

impl PrincipalRecord {
    pub(super) fn try_into_model(self) -> anyhow::Result<Principal> {
        let kind = match self.kind.as_str() {
            "USER" => PrincipalKind::User,
            "WORKLOAD" => PrincipalKind::Workload,
            "GROUP" => PrincipalKind::Group,
            value => bail!("unsupported IAM principal kind `{value}`"),
        };
        let status = match self.status.as_str() {
            "ACTIVE" => PrincipalStatus::Active,
            "DISABLED" => PrincipalStatus::Disabled,
            value => bail!("unsupported IAM principal status `{value}`"),
        };
        let attributes = serde_json::from_value::<BTreeMap<String, Value>>(self.attributes)
            .context("decode IAM principal attributes")?;
        Ok(Principal {
            id: self.id,
            issuer: self.issuer,
            external_id: self.external_id,
            kind,
            display_name: self.display_name,
            status,
            attributes,
        })
    }
}

#[derive(Debug, FromRow)]
pub(super) struct ActionRecord {
    pub(super) identifier: String,
    pub(super) description: String,
    pub(super) route_matchers: Value,
}

impl ActionRecord {
    pub(super) fn try_into_model(self) -> anyhow::Result<Action> {
        let route_matchers = serde_json::from_value::<Vec<HttpRouteMatcher>>(self.route_matchers)
            .with_context(|| {
            format!("decode route matchers for IAM action `{}`", self.identifier)
        })?;
        Ok(Action { identifier: self.identifier, description: self.description, route_matchers })
    }
}

#[derive(Debug, FromRow)]
pub(super) struct RoleActionRecord {
    pub(super) role_id: String,
    pub(super) role_name: String,
    pub(super) role_description: String,
    pub(super) action_identifier: Option<String>,
}

#[derive(Debug, FromRow)]
pub(super) struct RoleBindingRecord {
    pub(super) binding_id: String,
    pub(super) principal_id: String,
    pub(super) role_id: String,
    pub(super) effect: String,
    pub(super) resource_urn: String,
    pub(super) conditions: Value,
}

impl RoleBindingRecord {
    pub(super) fn try_into_model(self) -> anyhow::Result<RoleBinding> {
        let effect = match self.effect.as_str() {
            "ALLOW" => Effect::Allow,
            "DENY" => Effect::Deny,
            value => bail!("unsupported IAM role binding effect `{value}`"),
        };
        let conditions = serde_json::from_value::<AuthorizationConditionSpec>(self.conditions)
            .context("decode IAM role binding conditions")?;
        Ok(RoleBinding {
            id: self.binding_id,
            principal_id: self.principal_id,
            role_id: self.role_id,
            effect,
            resource_urn: self.resource_urn,
            conditions,
        })
    }
}
