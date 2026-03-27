use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::id::{DeviceId, TenantId, UserId};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Trusted,
    Untrusted,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub name: String,
    pub fingerprint: String,
    pub status: DeviceStatus,
    pub last_seen_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
