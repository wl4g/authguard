//! Persisted authorization catalog data. Evaluation lives in `utils`.

use crate::model::{IamActionInfo, IamRoleBindingInfo, IamRoleInfo};
use serde::{Deserialize, Serialize};

/// Active authorization policy aggregate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IamPolicyInfo {
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub actions: Vec<IamActionInfo>,
    #[serde(default)]
    pub roles: Vec<IamRoleInfo>,
    #[serde(default)]
    pub role_bindings: Vec<IamRoleBindingInfo>,
}
