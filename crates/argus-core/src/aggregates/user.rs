use uuid::Uuid;

use crate::events::user::UserEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone)]
pub struct UserAggregate {
    pub id: Uuid,
    pub version: i64,
    pub email: String,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub password_hash: String,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub locked: bool,
    pub lock_reason: Option<String>,
    pub deleted: bool,
    pub metadata: serde_json::Value,
    pub mfa_factors: Vec<String>,
}

impl Default for UserAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            email: String::new(),
            email_verified: false,
            display_name: None,
            password_hash: String::new(),
            phone: None,
            phone_verified: false,
            locked: false,
            lock_reason: None,
            deleted: false,
            metadata: serde_json::Value::Null,
            mfa_factors: Vec::new(),
        }
    }
}

impl Aggregate for UserAggregate {
    const AGGREGATE_TYPE: &'static str = "User";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(user_event) = serde_json::from_value::<UserEvent>(event.payload.clone()) else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize UserEvent payload"
            );
            return;
        };

        match user_event {
            UserEvent::UserCreated {
                email,
                display_name,
                password_hash,
            } => {
                self.email = email;
                self.display_name = display_name;
                self.password_hash = password_hash;
                self.deleted = false;
                self.locked = false;
            }
            UserEvent::UserEmailChanged { new_email, .. } => {
                self.email = new_email;
                self.email_verified = false;
            }
            UserEvent::UserEmailVerified => {
                self.email_verified = true;
            }
            UserEvent::UserPasswordChanged { password_hash } => {
                self.password_hash = password_hash;
            }
            UserEvent::UserMfaEnabled { factor } => {
                if !self.mfa_factors.contains(&factor) {
                    self.mfa_factors.push(factor);
                }
            }
            UserEvent::UserMfaDisabled { factor } => {
                self.mfa_factors.retain(|f| f != &factor);
            }
            UserEvent::UserLocked { reason } => {
                self.locked = true;
                self.lock_reason = Some(reason);
            }
            UserEvent::UserUnlocked => {
                self.locked = false;
                self.lock_reason = None;
            }
            UserEvent::UserMetadataSet { metadata } => {
                self.metadata = metadata;
            }
            UserEvent::UserPhoneAdded { phone } => {
                self.phone = Some(phone);
                self.phone_verified = false;
            }
            UserEvent::UserPhoneVerified => {
                self.phone_verified = true;
            }
            UserEvent::UserDeleted => {
                self.deleted = true;
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
            aggregate_type: "User".to_string(),
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
    fn test_user_created_sets_initial_state() {
        let mut agg = UserAggregate::default();
        let id = Uuid::now_v7();

        let event = make_stored_event(
            id,
            1,
            "UserCreated",
            serde_json::json!({
                "type": "UserCreated",
                "data": {
                    "email": "alice@example.com",
                    "display_name": "Alice",
                    "password_hash": "hash123"
                }
            }),
        );

        agg.apply(&event);

        assert_eq!(agg.id, id);
        assert_eq!(agg.version, 1);
        assert_eq!(agg.email, "alice@example.com");
        assert_eq!(agg.display_name, Some("Alice".to_string()));
        assert_eq!(agg.password_hash, "hash123");
        assert!(!agg.deleted);
        assert!(!agg.locked);
    }

    #[test]
    fn test_email_change_and_verify_flow() {
        let mut agg = UserAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "UserCreated",
            serde_json::json!({
                "type": "UserCreated",
                "data": {
                    "email": "alice@example.com",
                    "display_name": null,
                    "password_hash": "hash123"
                }
            }),
        ));

        // Verify email
        agg.apply(&make_stored_event(
            id,
            2,
            "UserEmailVerified",
            serde_json::json!({"type": "UserEmailVerified"}),
        ));
        assert!(agg.email_verified);

        // Change email resets verified
        agg.apply(&make_stored_event(
            id,
            3,
            "UserEmailChanged",
            serde_json::json!({
                "type": "UserEmailChanged",
                "data": {
                    "old_email": "alice@example.com",
                    "new_email": "alice2@example.com"
                }
            }),
        ));
        assert_eq!(agg.email, "alice2@example.com");
        assert!(!agg.email_verified);
        assert_eq!(agg.version, 3);
    }

    #[test]
    fn test_lock_unlock_flow() {
        let mut agg = UserAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "UserCreated",
            serde_json::json!({
                "type": "UserCreated",
                "data": {
                    "email": "bob@example.com",
                    "display_name": null,
                    "password_hash": "hash"
                }
            }),
        ));

        agg.apply(&make_stored_event(
            id,
            2,
            "UserLocked",
            serde_json::json!({
                "type": "UserLocked",
                "data": { "reason": "too many failed attempts" }
            }),
        ));
        assert!(agg.locked);
        assert_eq!(
            agg.lock_reason,
            Some("too many failed attempts".to_string())
        );

        agg.apply(&make_stored_event(
            id,
            3,
            "UserUnlocked",
            serde_json::json!({"type": "UserUnlocked"}),
        ));
        assert!(!agg.locked);
        assert!(agg.lock_reason.is_none());
    }

    #[test]
    fn test_optimistic_versioning() {
        let mut agg = UserAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "UserCreated",
            serde_json::json!({
                "type": "UserCreated",
                "data": {
                    "email": "v@example.com",
                    "display_name": null,
                    "password_hash": "hash"
                }
            }),
        ));
        assert_eq!(agg.version(), 1);

        agg.apply(&make_stored_event(
            id,
            2,
            "UserEmailVerified",
            serde_json::json!({"type": "UserEmailVerified"}),
        ));
        assert_eq!(agg.version(), 2);

        agg.apply(&make_stored_event(
            id,
            3,
            "UserPasswordChanged",
            serde_json::json!({
                "type": "UserPasswordChanged",
                "data": { "password_hash": "newhash" }
            }),
        ));
        assert_eq!(agg.version(), 3);
    }

    #[test]
    fn test_full_event_replay() {
        let mut agg = UserAggregate::default();
        let id = Uuid::now_v7();

        let events = vec![
            make_stored_event(
                id,
                1,
                "UserCreated",
                serde_json::json!({
                    "type": "UserCreated",
                    "data": {
                        "email": "replay@example.com",
                        "display_name": "Replay User",
                        "password_hash": "hash1"
                    }
                }),
            ),
            make_stored_event(
                id,
                2,
                "UserEmailVerified",
                serde_json::json!({"type": "UserEmailVerified"}),
            ),
            make_stored_event(
                id,
                3,
                "UserPhoneAdded",
                serde_json::json!({
                    "type": "UserPhoneAdded",
                    "data": { "phone": "+1234567890" }
                }),
            ),
            make_stored_event(
                id,
                4,
                "UserPhoneVerified",
                serde_json::json!({"type": "UserPhoneVerified"}),
            ),
            make_stored_event(
                id,
                5,
                "UserMetadataSet",
                serde_json::json!({
                    "type": "UserMetadataSet",
                    "data": { "metadata": {"role": "admin"} }
                }),
            ),
            make_stored_event(
                id,
                6,
                "UserPasswordChanged",
                serde_json::json!({
                    "type": "UserPasswordChanged",
                    "data": { "password_hash": "hash2" }
                }),
            ),
            make_stored_event(
                id,
                7,
                "UserLocked",
                serde_json::json!({
                    "type": "UserLocked",
                    "data": { "reason": "suspicious" }
                }),
            ),
            make_stored_event(
                id,
                8,
                "UserUnlocked",
                serde_json::json!({"type": "UserUnlocked"}),
            ),
            make_stored_event(
                id,
                9,
                "UserDeleted",
                serde_json::json!({"type": "UserDeleted"}),
            ),
        ];

        for event in &events {
            agg.apply(event);
        }

        assert_eq!(agg.id, id);
        assert_eq!(agg.version(), 9);
        assert_eq!(agg.email, "replay@example.com");
        assert!(agg.email_verified);
        assert_eq!(agg.phone, Some("+1234567890".to_string()));
        assert!(agg.phone_verified);
        assert_eq!(agg.password_hash, "hash2");
        assert!(!agg.locked);
        assert!(agg.deleted);
        assert_eq!(agg.metadata, serde_json::json!({"role": "admin"}));
    }

    #[test]
    fn test_mfa_enable_disable() {
        let mut agg = UserAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "UserCreated",
            serde_json::json!({
                "type": "UserCreated",
                "data": {
                    "email": "mfa@example.com",
                    "display_name": null,
                    "password_hash": "hash"
                }
            }),
        ));

        agg.apply(&make_stored_event(
            id,
            2,
            "UserMfaEnabled",
            serde_json::json!({
                "type": "UserMfaEnabled",
                "data": { "factor": "totp" }
            }),
        ));
        assert_eq!(agg.mfa_factors, vec!["totp"]);

        // Duplicate enable should not add twice
        agg.apply(&make_stored_event(
            id,
            3,
            "UserMfaEnabled",
            serde_json::json!({
                "type": "UserMfaEnabled",
                "data": { "factor": "totp" }
            }),
        ));
        assert_eq!(agg.mfa_factors, vec!["totp"]);

        agg.apply(&make_stored_event(
            id,
            4,
            "UserMfaDisabled",
            serde_json::json!({
                "type": "UserMfaDisabled",
                "data": { "factor": "totp" }
            }),
        ));
        assert!(agg.mfa_factors.is_empty());
    }
}
