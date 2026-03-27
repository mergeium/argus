use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::events::session::SessionEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Terminated,
    Expired,
}

impl Default for SessionStatus {
    fn default() -> Self {
        Self::Active
    }
}

#[derive(Debug, Clone)]
pub struct SessionAggregate {
    pub id: Uuid,
    pub version: i64,
    pub user_id: String,
    pub client_id: Option<String>,
    pub ip: String,
    pub user_agent: String,
    pub device_id: Option<String>,
    pub mfa_method: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: SessionStatus,
    pub terminated_reason: Option<String>,
}

impl Default for SessionAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            user_id: String::new(),
            client_id: None,
            ip: String::new(),
            user_agent: String::new(),
            device_id: None,
            mfa_method: None,
            expires_at: None,
            status: SessionStatus::Active,
            terminated_reason: None,
        }
    }
}

impl Aggregate for SessionAggregate {
    const AGGREGATE_TYPE: &'static str = "Session";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(session_event) = serde_json::from_value::<SessionEvent>(event.payload.clone())
        else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize SessionEvent payload"
            );
            return;
        };

        match session_event {
            SessionEvent::SessionCreated {
                user_id,
                client_id,
                ip,
                user_agent,
            } => {
                self.user_id = user_id;
                self.client_id = client_id;
                self.ip = ip;
                self.user_agent = user_agent;
                self.status = SessionStatus::Active;
            }
            SessionEvent::SessionExtended { new_expires_at } => {
                self.expires_at = Some(new_expires_at);
            }
            SessionEvent::SessionStepUpCompleted { mfa_method } => {
                self.mfa_method = Some(mfa_method);
            }
            SessionEvent::SessionDeviceTrusted { device_id } => {
                self.device_id = Some(device_id);
            }
            SessionEvent::SessionTerminated { reason } => {
                self.status = SessionStatus::Terminated;
                self.terminated_reason = Some(reason);
            }
            SessionEvent::SessionExpired => {
                self.status = SessionStatus::Expired;
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
            aggregate_type: "Session".to_string(),
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
    fn test_session_created() {
        let mut agg = SessionAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "SessionCreated",
            serde_json::json!({
                "type": "SessionCreated",
                "data": {
                    "user_id": "usr_123",
                    "client_id": "cli_456",
                    "ip": "192.168.1.1",
                    "user_agent": "Mozilla/5.0"
                }
            }),
        ));

        assert_eq!(agg.id, id);
        assert_eq!(agg.version(), 1);
        assert_eq!(agg.user_id, "usr_123");
        assert_eq!(agg.client_id, Some("cli_456".to_string()));
        assert_eq!(agg.ip, "192.168.1.1");
        assert_eq!(agg.status, SessionStatus::Active);
    }

    #[test]
    fn test_session_full_lifecycle() {
        let mut agg = SessionAggregate::default();
        let id = Uuid::now_v7();
        let future = Utc::now() + chrono::Duration::hours(2);

        let events = vec![
            make_stored_event(
                id,
                1,
                "SessionCreated",
                serde_json::json!({
                    "type": "SessionCreated",
                    "data": {
                        "user_id": "usr_abc",
                        "client_id": null,
                        "ip": "10.0.0.1",
                        "user_agent": "curl"
                    }
                }),
            ),
            make_stored_event(
                id,
                2,
                "SessionExtended",
                serde_json::json!({
                    "type": "SessionExtended",
                    "data": { "new_expires_at": future.to_rfc3339() }
                }),
            ),
            make_stored_event(
                id,
                3,
                "SessionStepUpCompleted",
                serde_json::json!({
                    "type": "SessionStepUpCompleted",
                    "data": { "mfa_method": "totp" }
                }),
            ),
            make_stored_event(
                id,
                4,
                "SessionDeviceTrusted",
                serde_json::json!({
                    "type": "SessionDeviceTrusted",
                    "data": { "device_id": "dev_xyz" }
                }),
            ),
            make_stored_event(
                id,
                5,
                "SessionTerminated",
                serde_json::json!({
                    "type": "SessionTerminated",
                    "data": { "reason": "user logout" }
                }),
            ),
        ];

        for event in &events {
            agg.apply(event);
        }

        assert_eq!(agg.version(), 5);
        assert_eq!(agg.user_id, "usr_abc");
        assert!(agg.client_id.is_none());
        assert_eq!(agg.mfa_method, Some("totp".to_string()));
        assert_eq!(agg.device_id, Some("dev_xyz".to_string()));
        assert!(agg.expires_at.is_some());
        assert_eq!(agg.status, SessionStatus::Terminated);
        assert_eq!(agg.terminated_reason, Some("user logout".to_string()));
    }

    #[test]
    fn test_session_expired() {
        let mut agg = SessionAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "SessionCreated",
            serde_json::json!({
                "type": "SessionCreated",
                "data": {
                    "user_id": "usr_exp",
                    "client_id": null,
                    "ip": "1.2.3.4",
                    "user_agent": "test"
                }
            }),
        ));
        agg.apply(&make_stored_event(
            id,
            2,
            "SessionExpired",
            serde_json::json!({"type": "SessionExpired"}),
        ));

        assert_eq!(agg.status, SessionStatus::Expired);
        assert_eq!(agg.version(), 2);
    }

    #[test]
    fn test_optimistic_versioning() {
        let mut agg = SessionAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "SessionCreated",
            serde_json::json!({
                "type": "SessionCreated",
                "data": {
                    "user_id": "usr_v",
                    "client_id": null,
                    "ip": "1.1.1.1",
                    "user_agent": "test"
                }
            }),
        ));
        assert_eq!(agg.version(), 1);

        agg.apply(&make_stored_event(
            id,
            2,
            "SessionStepUpCompleted",
            serde_json::json!({
                "type": "SessionStepUpCompleted",
                "data": { "mfa_method": "passkey" }
            }),
        ));
        assert_eq!(agg.version(), 2);
    }
}
