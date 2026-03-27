use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum TenantPolicyEvent {
    PasswordPolicySet {
        min_length: u32,
        require_uppercase: bool,
        require_number: bool,
        require_special: bool,
    },
    MFAPolicySet {
        required: bool,
        allowed_methods: Vec<String>,
    },
    SessionPolicySet {
        max_lifetime_secs: u64,
        idle_timeout_secs: u64,
    },
    BrandingSet {
        branding: serde_json::Value,
    },
    SMTPConfigured {
        host: String,
        port: u16,
        from_address: String,
    },
    IPAllowlistSet {
        allowed_ips: Vec<String>,
    },
}
