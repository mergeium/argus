use uuid::Uuid;

use crate::events::webhook::WebhookEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone)]
pub struct WebhookAggregate {
    pub id: Uuid,
    pub version: i64,
    pub url: String,
    pub event_types: Vec<String>,
    pub secret_hash: String,
    pub total_fired: u64,
    pub total_delivered: u64,
    pub total_failed: u64,
    pub last_status_code: Option<u16>,
    pub last_error: Option<String>,
    pub last_attempt: u32,
    pub deleted: bool,
}

impl Default for WebhookAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            url: String::new(),
            event_types: Vec::new(),
            secret_hash: String::new(),
            total_fired: 0,
            total_delivered: 0,
            total_failed: 0,
            last_status_code: None,
            last_error: None,
            last_attempt: 0,
            deleted: false,
        }
    }
}

impl Aggregate for WebhookAggregate {
    const AGGREGATE_TYPE: &'static str = "Webhook";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(wh_event) = serde_json::from_value::<WebhookEvent>(event.payload.clone()) else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize WebhookEvent payload"
            );
            return;
        };

        match wh_event {
            WebhookEvent::WebhookCreated {
                url,
                event_types,
                secret_hash,
            } => {
                self.url = url;
                self.event_types = event_types;
                self.secret_hash = secret_hash;
                self.deleted = false;
            }
            WebhookEvent::WebhookFired {
                webhook_id: _,
                event_type: _,
            } => {
                self.total_fired += 1;
            }
            WebhookEvent::WebhookDelivered {
                webhook_id: _,
                status_code,
            } => {
                self.total_delivered += 1;
                self.last_status_code = Some(status_code);
                self.last_error = None;
            }
            WebhookEvent::WebhookFailed {
                webhook_id: _,
                error,
                attempt,
            } => {
                self.total_failed += 1;
                self.last_error = Some(error);
                self.last_attempt = attempt;
            }
            WebhookEvent::WebhookDeleted => {
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
            aggregate_type: "Webhook".to_string(),
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
    fn test_webhook_lifecycle() {
        let mut agg = WebhookAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "WebhookCreated",
            serde_json::json!({
                "type": "WebhookCreated",
                "data": {
                    "url": "https://hooks.example.com/events",
                    "event_types": ["user.created", "user.deleted"],
                    "secret_hash": "whsec_hash"
                }
            }),
        ));

        assert_eq!(agg.url, "https://hooks.example.com/events");
        assert_eq!(agg.event_types, vec!["user.created", "user.deleted"]);
        assert!(!agg.deleted);

        agg.apply(&make_stored_event(
            id,
            2,
            "WebhookFired",
            serde_json::json!({
                "type": "WebhookFired",
                "data": { "webhook_id": "wh_1", "event_type": "user.created" }
            }),
        ));
        assert_eq!(agg.total_fired, 1);

        agg.apply(&make_stored_event(
            id,
            3,
            "WebhookDelivered",
            serde_json::json!({
                "type": "WebhookDelivered",
                "data": { "webhook_id": "wh_1", "status_code": 200 }
            }),
        ));
        assert_eq!(agg.total_delivered, 1);
        assert_eq!(agg.last_status_code, Some(200));

        agg.apply(&make_stored_event(
            id,
            4,
            "WebhookFired",
            serde_json::json!({
                "type": "WebhookFired",
                "data": { "webhook_id": "wh_1", "event_type": "user.deleted" }
            }),
        ));

        agg.apply(&make_stored_event(
            id,
            5,
            "WebhookFailed",
            serde_json::json!({
                "type": "WebhookFailed",
                "data": { "webhook_id": "wh_1", "error": "timeout", "attempt": 3 }
            }),
        ));
        assert_eq!(agg.total_fired, 2);
        assert_eq!(agg.total_failed, 1);
        assert_eq!(agg.last_error, Some("timeout".to_string()));
        assert_eq!(agg.last_attempt, 3);

        agg.apply(&make_stored_event(
            id,
            6,
            "WebhookDeleted",
            serde_json::json!({"type": "WebhookDeleted"}),
        ));
        assert!(agg.deleted);
        assert_eq!(agg.version(), 6);
    }
}
