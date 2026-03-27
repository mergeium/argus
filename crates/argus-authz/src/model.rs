use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A ReBAC relationship tuple (Zanzibar / OpenFGA model).
///
/// Encodes: `user_ref` has `relation` on `object_type:object_id`
///
/// Examples from the spec:
/// - (user:alice, owner, document:design-spec)
/// - (group:engineering, viewer, folder:projects)
/// - (user:charlie, member, group:engineering)
/// - (role:admin, assignee, user:eve)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationTuple {
    pub store_id: Uuid,
    pub user_ref: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
    pub created_at: DateTime<Utc>,
}

/// Request to write (add or delete) tuples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    pub store_id: Uuid,
    pub writes: Vec<TupleKey>,
    pub deletes: Vec<TupleKey>,
}

/// A tuple key without timestamps (used in write/delete/check requests).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TupleKey {
    pub user_ref: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}

/// Request to check if a user has a relation on an object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRequest {
    pub store_id: Uuid,
    pub user_ref: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}

/// Result of an authorization check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResponse {
    pub allowed: bool,
    pub resolution_path: Vec<String>,
    pub duration_us: u64,
}

/// Request to list all objects a user can access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListObjectsRequest {
    pub store_id: Uuid,
    pub user_ref: String,
    pub relation: String,
    pub object_type: String,
}

/// Request to expand: who has access to an object?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpandRequest {
    pub store_id: Uuid,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}
