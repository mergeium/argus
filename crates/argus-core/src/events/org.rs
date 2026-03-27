use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum OrgEvent {
    OrgCreated { name: String, slug: String },
    OrgNameChanged { old_name: String, new_name: String },
    OrgLogoSet { logo_url: String },
    OrgDomainAdded { domain: String },
    OrgDomainVerified { domain: String },
    OrgBrandingSet { branding: serde_json::Value },
    OrgPolicySet { policy: serde_json::Value },
    OrgDeleted,
}
