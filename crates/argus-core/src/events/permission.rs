use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum PermissionEvent {
    TupleWritten {
        user_ref: String,
        relation: String,
        object_type: String,
        object_id: String,
    },
    TupleDeleted {
        user_ref: String,
        relation: String,
        object_type: String,
        object_id: String,
    },
    AuthorizationModelUpdated {
        model: serde_json::Value,
    },
    PolicyDeployed {
        policy_id: String,
        version: String,
    },
    AuditLogEntry {
        decision: String,
        reason: String,
    },
}
