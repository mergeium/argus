use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum LifecycleEvent {
    DeprovisioningStarted {
        user_id: String,
        initiated_by: String,
    },
    SessionsRevoked {
        user_id: String,
        count: u64,
    },
    TokensRevoked {
        user_id: String,
        count: u64,
    },
    SCIMPushSent {
        user_id: String,
        target: String,
    },
    DeprovisioningCompleted {
        user_id: String,
    },
}
