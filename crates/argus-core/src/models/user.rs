use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::id::{OrgId, TenantId, UserId};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Locked,
    Suspended,
    PendingVerification,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub tenant_id: TenantId,
    pub org_id: Option<OrgId>,
    pub email: String,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub display_name: Option<String>,
    pub status: UserStatus,
    pub metadata: serde_json::Value,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
