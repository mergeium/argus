use serde::{Deserialize, Serialize};

use crate::id::TenantId;

/// A ReBAC relationship tuple (Zanzibar model).
/// Encodes: `user_ref` has `relation` on `object_type:object_id`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationTuple {
    pub tenant_id: TenantId,
    pub user_ref: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCheck {
    pub user_ref: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub resolution_path: Vec<String>,
    pub duration_us: u64,
}
