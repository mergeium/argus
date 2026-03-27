use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum InvitationEvent {
    InvitationCreated {
        email: String,
        role: String,
        invited_by: String,
    },
    InvitationAccepted {
        user_id: String,
    },
    InvitationRevoked {
        revoked_by: String,
    },
    InvitationExpired,
}
