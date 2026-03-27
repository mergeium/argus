use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum AuditEvent {
    AuthEvent {
        user_id: String,
        action: String,
        success: bool,
        ip: String,
        user_agent: String,
    },
    AuthzDecision {
        subject: String,
        resource: String,
        action: String,
        allowed: bool,
        reason: String,
    },
}
