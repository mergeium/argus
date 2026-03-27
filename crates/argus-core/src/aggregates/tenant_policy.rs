use uuid::Uuid;

use crate::events::tenant_policy::TenantPolicyEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub require_uppercase: bool,
    pub require_number: bool,
    pub require_special: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: false,
            require_number: false,
            require_special: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MfaPolicy {
    pub required: bool,
    pub allowed_methods: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SessionPolicy {
    pub max_lifetime_secs: u64,
    pub idle_timeout_secs: u64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            max_lifetime_secs: 86400,
            idle_timeout_secs: 3600,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub from_address: String,
}

#[derive(Debug, Clone)]
pub struct TenantPolicyAggregate {
    pub id: Uuid,
    pub version: i64,
    pub password_policy: PasswordPolicy,
    pub mfa_policy: MfaPolicy,
    pub session_policy: SessionPolicy,
    pub branding: serde_json::Value,
    pub smtp_config: Option<SmtpConfig>,
    pub ip_allowlist: Vec<String>,
}

impl Default for TenantPolicyAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            password_policy: PasswordPolicy::default(),
            mfa_policy: MfaPolicy::default(),
            session_policy: SessionPolicy::default(),
            branding: serde_json::Value::Null,
            smtp_config: None,
            ip_allowlist: Vec::new(),
        }
    }
}

impl Aggregate for TenantPolicyAggregate {
    const AGGREGATE_TYPE: &'static str = "TenantPolicy";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(policy_event) = serde_json::from_value::<TenantPolicyEvent>(event.payload.clone())
        else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize TenantPolicyEvent payload"
            );
            return;
        };

        match policy_event {
            TenantPolicyEvent::PasswordPolicySet {
                min_length,
                require_uppercase,
                require_number,
                require_special,
            } => {
                self.password_policy = PasswordPolicy {
                    min_length,
                    require_uppercase,
                    require_number,
                    require_special,
                };
            }
            TenantPolicyEvent::MFAPolicySet {
                required,
                allowed_methods,
            } => {
                self.mfa_policy = MfaPolicy {
                    required,
                    allowed_methods,
                };
            }
            TenantPolicyEvent::SessionPolicySet {
                max_lifetime_secs,
                idle_timeout_secs,
            } => {
                self.session_policy = SessionPolicy {
                    max_lifetime_secs,
                    idle_timeout_secs,
                };
            }
            TenantPolicyEvent::BrandingSet { branding } => {
                self.branding = branding;
            }
            TenantPolicyEvent::SMTPConfigured {
                host,
                port,
                from_address,
            } => {
                self.smtp_config = Some(SmtpConfig {
                    host,
                    port,
                    from_address,
                });
            }
            TenantPolicyEvent::IPAllowlistSet { allowed_ips } => {
                self.ip_allowlist = allowed_ips;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventMetadata, StoredEvent};
    use crate::id::TenantId;
    use chrono::Utc;

    fn make_stored_event(
        aggregate_id: Uuid,
        version: i64,
        event_type: &str,
        payload: serde_json::Value,
    ) -> StoredEvent {
        StoredEvent {
            id: version,
            aggregate_type: "TenantPolicy".to_string(),
            aggregate_id,
            aggregate_version: version,
            event_type: event_type.to_string(),
            payload,
            metadata: EventMetadata::default(),
            tenant_id: TenantId::new(),
            schema_version: 1,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_password_policy_set() {
        let mut agg = TenantPolicyAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "PasswordPolicySet",
            serde_json::json!({
                "type": "PasswordPolicySet",
                "data": {
                    "min_length": 12,
                    "require_uppercase": true,
                    "require_number": true,
                    "require_special": false
                }
            }),
        ));

        assert_eq!(agg.password_policy.min_length, 12);
        assert!(agg.password_policy.require_uppercase);
        assert!(agg.password_policy.require_number);
        assert!(!agg.password_policy.require_special);
    }

    #[test]
    fn test_full_policy_replay() {
        let mut agg = TenantPolicyAggregate::default();
        let id = Uuid::now_v7();

        let events = vec![
            make_stored_event(
                id,
                1,
                "PasswordPolicySet",
                serde_json::json!({
                    "type": "PasswordPolicySet",
                    "data": {
                        "min_length": 10,
                        "require_uppercase": true,
                        "require_number": true,
                        "require_special": true
                    }
                }),
            ),
            make_stored_event(
                id,
                2,
                "MFAPolicySet",
                serde_json::json!({
                    "type": "MFAPolicySet",
                    "data": {
                        "required": true,
                        "allowed_methods": ["totp", "passkey"]
                    }
                }),
            ),
            make_stored_event(
                id,
                3,
                "SessionPolicySet",
                serde_json::json!({
                    "type": "SessionPolicySet",
                    "data": {
                        "max_lifetime_secs": 43200,
                        "idle_timeout_secs": 1800
                    }
                }),
            ),
            make_stored_event(
                id,
                4,
                "BrandingSet",
                serde_json::json!({
                    "type": "BrandingSet",
                    "data": { "branding": {"logo": "https://example.com/logo.png"} }
                }),
            ),
            make_stored_event(
                id,
                5,
                "SMTPConfigured",
                serde_json::json!({
                    "type": "SMTPConfigured",
                    "data": {
                        "host": "smtp.example.com",
                        "port": 587,
                        "from_address": "noreply@example.com"
                    }
                }),
            ),
            make_stored_event(
                id,
                6,
                "IPAllowlistSet",
                serde_json::json!({
                    "type": "IPAllowlistSet",
                    "data": { "allowed_ips": ["10.0.0.0/8", "192.168.1.0/24"] }
                }),
            ),
        ];

        for event in &events {
            agg.apply(event);
        }

        assert_eq!(agg.version(), 6);
        assert_eq!(agg.password_policy.min_length, 10);
        assert!(agg.mfa_policy.required);
        assert_eq!(agg.mfa_policy.allowed_methods, vec!["totp", "passkey"]);
        assert_eq!(agg.session_policy.max_lifetime_secs, 43200);
        assert_eq!(agg.session_policy.idle_timeout_secs, 1800);
        assert_eq!(
            agg.branding,
            serde_json::json!({"logo": "https://example.com/logo.png"})
        );
        let smtp = agg.smtp_config.unwrap();
        assert_eq!(smtp.host, "smtp.example.com");
        assert_eq!(smtp.port, 587);
        assert_eq!(smtp.from_address, "noreply@example.com");
        assert_eq!(agg.ip_allowlist, vec!["10.0.0.0/8", "192.168.1.0/24"]);
    }
}
