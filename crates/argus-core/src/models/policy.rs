use serde::{Deserialize, Serialize};

use crate::id::TenantId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub tenant_id: TenantId,
    pub min_length: u8,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub max_age_days: Option<u32>,
    pub hibp_check: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            tenant_id: TenantId::new(),
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
            max_age_days: None,
            hibp_check: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPolicy {
    pub tenant_id: TenantId,
    pub max_lifetime_hours: u32,
    pub idle_timeout_minutes: u32,
    pub max_concurrent_sessions: u32,
    pub require_mfa_after_hours: Option<u32>,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            tenant_id: TenantId::new(),
            max_lifetime_hours: 24,
            idle_timeout_minutes: 30,
            max_concurrent_sessions: 5,
            require_mfa_after_hours: Some(12),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaPolicy {
    pub tenant_id: TenantId,
    pub required: bool,
    pub allowed_factors: Vec<MfaFactor>,
    pub grace_period_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MfaFactor {
    Totp,
    Passkey,
    Email,
    Sms,
    RecoveryCode,
}
