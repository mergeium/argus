use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum DeviceEvent {
    DeviceRegistered {
        user_id: String,
        name: String,
        fingerprint: String,
    },
    DeviceTrusted {
        trusted_by: String,
    },
    DeviceRevoked {
        reason: String,
    },
    DeviceLastSeen {
        ip: String,
        seen_at: DateTime<Utc>,
    },
}
