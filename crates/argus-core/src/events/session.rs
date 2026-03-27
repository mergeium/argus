use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum SessionEvent {
    SessionCreated {
        user_id: String,
        client_id: Option<String>,
        ip: String,
        user_agent: String,
    },
    SessionExtended {
        new_expires_at: DateTime<Utc>,
    },
    SessionStepUpCompleted {
        mfa_method: String,
    },
    SessionDeviceTrusted {
        device_id: String,
    },
    SessionTerminated {
        reason: String,
    },
    SessionExpired,
}
