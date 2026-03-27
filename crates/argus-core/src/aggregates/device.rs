use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::events::device::DeviceEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStatus {
    Registered,
    Trusted,
    Revoked,
}

impl Default for DeviceStatus {
    fn default() -> Self {
        Self::Registered
    }
}

#[derive(Debug, Clone)]
pub struct DeviceAggregate {
    pub id: Uuid,
    pub version: i64,
    pub user_id: String,
    pub name: String,
    pub fingerprint: String,
    pub status: DeviceStatus,
    pub trusted_by: Option<String>,
    pub revoke_reason: Option<String>,
    pub last_seen_ip: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

impl Default for DeviceAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            user_id: String::new(),
            name: String::new(),
            fingerprint: String::new(),
            status: DeviceStatus::Registered,
            trusted_by: None,
            revoke_reason: None,
            last_seen_ip: None,
            last_seen_at: None,
        }
    }
}

impl Aggregate for DeviceAggregate {
    const AGGREGATE_TYPE: &'static str = "Device";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(device_event) = serde_json::from_value::<DeviceEvent>(event.payload.clone()) else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize DeviceEvent payload"
            );
            return;
        };

        match device_event {
            DeviceEvent::DeviceRegistered {
                user_id,
                name,
                fingerprint,
            } => {
                self.user_id = user_id;
                self.name = name;
                self.fingerprint = fingerprint;
                self.status = DeviceStatus::Registered;
            }
            DeviceEvent::DeviceTrusted { trusted_by } => {
                self.status = DeviceStatus::Trusted;
                self.trusted_by = Some(trusted_by);
            }
            DeviceEvent::DeviceRevoked { reason } => {
                self.status = DeviceStatus::Revoked;
                self.revoke_reason = Some(reason);
            }
            DeviceEvent::DeviceLastSeen { ip, seen_at } => {
                self.last_seen_ip = Some(ip);
                self.last_seen_at = Some(seen_at);
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
            aggregate_type: "Device".to_string(),
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
    fn test_device_register_trust_revoke() {
        let mut agg = DeviceAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "DeviceRegistered",
            serde_json::json!({
                "type": "DeviceRegistered",
                "data": {
                    "user_id": "usr_1",
                    "name": "iPhone 15",
                    "fingerprint": "fp_abc123"
                }
            }),
        ));

        assert_eq!(agg.user_id, "usr_1");
        assert_eq!(agg.name, "iPhone 15");
        assert_eq!(agg.fingerprint, "fp_abc123");
        assert_eq!(agg.status, DeviceStatus::Registered);

        agg.apply(&make_stored_event(
            id,
            2,
            "DeviceTrusted",
            serde_json::json!({
                "type": "DeviceTrusted",
                "data": { "trusted_by": "admin_1" }
            }),
        ));
        assert_eq!(agg.status, DeviceStatus::Trusted);
        assert_eq!(agg.trusted_by, Some("admin_1".to_string()));

        agg.apply(&make_stored_event(
            id,
            3,
            "DeviceRevoked",
            serde_json::json!({
                "type": "DeviceRevoked",
                "data": { "reason": "lost device" }
            }),
        ));
        assert_eq!(agg.status, DeviceStatus::Revoked);
        assert_eq!(agg.revoke_reason, Some("lost device".to_string()));
        assert_eq!(agg.version(), 3);
    }

    #[test]
    fn test_device_last_seen() {
        let mut agg = DeviceAggregate::default();
        let id = Uuid::now_v7();
        let now = Utc::now();

        agg.apply(&make_stored_event(
            id,
            1,
            "DeviceRegistered",
            serde_json::json!({
                "type": "DeviceRegistered",
                "data": {
                    "user_id": "usr_2",
                    "name": "Laptop",
                    "fingerprint": "fp_xyz"
                }
            }),
        ));

        agg.apply(&make_stored_event(
            id,
            2,
            "DeviceLastSeen",
            serde_json::json!({
                "type": "DeviceLastSeen",
                "data": { "ip": "10.0.0.5", "seen_at": now.to_rfc3339() }
            }),
        ));

        assert_eq!(agg.last_seen_ip, Some("10.0.0.5".to_string()));
        assert!(agg.last_seen_at.is_some());
        assert_eq!(agg.version(), 2);
    }
}
