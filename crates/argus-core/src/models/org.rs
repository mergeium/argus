use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::id::{OrgId, TenantId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: OrgId,
    pub tenant_id: TenantId,
    pub name: String,
    pub slug: String,
    pub logo_url: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
