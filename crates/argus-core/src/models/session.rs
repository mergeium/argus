use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::id::{ClientId, DeviceId, SessionId, TenantId, UserId};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MfaLevel {
    None,
    SingleFactor,
    MultiFactor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub client_id: Option<ClientId>,
    pub device_id: Option<DeviceId>,
    pub ip: String,
    pub user_agent: String,
    pub mfa_level: MfaLevel,
    pub risk_score: f64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
}
