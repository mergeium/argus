use uuid::Uuid;

use crate::events::mfa::MfaEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone)]
pub struct MfaAggregate {
    pub id: Uuid,
    pub version: i64,
    pub user_id: String,
    pub totp_enrolled: bool,
    pub totp_verified: bool,
    pub totp_secret_hash: String,
    pub passkeys: Vec<String>,
    pub recovery_code_count: u32,
    pub recovery_codes_used: Vec<u32>,
}

impl Default for MfaAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            user_id: String::new(),
            totp_enrolled: false,
            totp_verified: false,
            totp_secret_hash: String::new(),
            passkeys: Vec::new(),
            recovery_code_count: 0,
            recovery_codes_used: Vec::new(),
        }
    }
}

impl Aggregate for MfaAggregate {
    const AGGREGATE_TYPE: &'static str = "Mfa";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(mfa_event) = serde_json::from_value::<MfaEvent>(event.payload.clone()) else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize MfaEvent payload"
            );
            return;
        };

        match mfa_event {
            MfaEvent::TOTPEnrolled {
                user_id,
                secret_hash,
            } => {
                self.user_id = user_id;
                self.totp_enrolled = true;
                self.totp_verified = false;
                self.totp_secret_hash = secret_hash;
            }
            MfaEvent::TOTPVerified { user_id } => {
                self.user_id = user_id;
                self.totp_verified = true;
            }
            MfaEvent::TOTPRemoved { user_id } => {
                self.user_id = user_id;
                self.totp_enrolled = false;
                self.totp_verified = false;
                self.totp_secret_hash = String::new();
            }
            MfaEvent::PasskeyRegistered {
                user_id,
                credential_id,
            } => {
                self.user_id = user_id;
                if !self.passkeys.contains(&credential_id) {
                    self.passkeys.push(credential_id);
                }
            }
            MfaEvent::PasskeyUsed {
                user_id,
                credential_id: _,
            } => {
                self.user_id = user_id;
            }
            MfaEvent::PasskeyRemoved {
                user_id,
                credential_id,
            } => {
                self.user_id = user_id;
                self.passkeys.retain(|c| c != &credential_id);
            }
            MfaEvent::RecoveryCodesGenerated {
                user_id,
                code_count,
            } => {
                self.user_id = user_id;
                self.recovery_code_count = code_count;
                self.recovery_codes_used.clear();
            }
            MfaEvent::RecoveryCodeUsed {
                user_id,
                code_index,
            } => {
                self.user_id = user_id;
                if !self.recovery_codes_used.contains(&code_index) {
                    self.recovery_codes_used.push(code_index);
                }
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
            aggregate_type: "Mfa".to_string(),
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
    fn test_totp_enroll_verify_remove() {
        let mut agg = MfaAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "TOTPEnrolled",
            serde_json::json!({
                "type": "TOTPEnrolled",
                "data": { "user_id": "usr_1", "secret_hash": "sec_hash" }
            }),
        ));

        assert_eq!(agg.user_id, "usr_1");
        assert!(agg.totp_enrolled);
        assert!(!agg.totp_verified);
        assert_eq!(agg.totp_secret_hash, "sec_hash");

        agg.apply(&make_stored_event(
            id,
            2,
            "TOTPVerified",
            serde_json::json!({
                "type": "TOTPVerified",
                "data": { "user_id": "usr_1" }
            }),
        ));
        assert!(agg.totp_verified);

        agg.apply(&make_stored_event(
            id,
            3,
            "TOTPRemoved",
            serde_json::json!({
                "type": "TOTPRemoved",
                "data": { "user_id": "usr_1" }
            }),
        ));
        assert!(!agg.totp_enrolled);
        assert!(!agg.totp_verified);
        assert!(agg.totp_secret_hash.is_empty());
    }

    #[test]
    fn test_passkey_and_recovery_codes() {
        let mut agg = MfaAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "PasskeyRegistered",
            serde_json::json!({
                "type": "PasskeyRegistered",
                "data": { "user_id": "usr_1", "credential_id": "cred_abc" }
            }),
        ));
        assert_eq!(agg.passkeys, vec!["cred_abc"]);

        agg.apply(&make_stored_event(
            id,
            2,
            "RecoveryCodesGenerated",
            serde_json::json!({
                "type": "RecoveryCodesGenerated",
                "data": { "user_id": "usr_1", "code_count": 10 }
            }),
        ));
        assert_eq!(agg.recovery_code_count, 10);

        agg.apply(&make_stored_event(
            id,
            3,
            "RecoveryCodeUsed",
            serde_json::json!({
                "type": "RecoveryCodeUsed",
                "data": { "user_id": "usr_1", "code_index": 3 }
            }),
        ));
        assert_eq!(agg.recovery_codes_used, vec![3]);

        agg.apply(&make_stored_event(
            id,
            4,
            "PasskeyRemoved",
            serde_json::json!({
                "type": "PasskeyRemoved",
                "data": { "user_id": "usr_1", "credential_id": "cred_abc" }
            }),
        ));
        assert!(agg.passkeys.is_empty());
        assert_eq!(agg.version(), 4);
    }
}
