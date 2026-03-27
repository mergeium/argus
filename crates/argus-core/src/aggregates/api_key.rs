use uuid::Uuid;

use crate::events::api_key::ApiKeyEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone)]
pub struct ApiKeyAggregate {
    pub id: Uuid,
    pub version: i64,
    pub name: String,
    pub key_hash: String,
    pub scopes: Vec<String>,
    pub active: bool,
    pub deleted: bool,
}

impl Default for ApiKeyAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            name: String::new(),
            key_hash: String::new(),
            scopes: Vec::new(),
            active: true,
            deleted: false,
        }
    }
}

impl Aggregate for ApiKeyAggregate {
    const AGGREGATE_TYPE: &'static str = "ApiKey";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(api_event) = serde_json::from_value::<ApiKeyEvent>(event.payload.clone()) else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize ApiKeyEvent payload"
            );
            return;
        };

        match api_event {
            ApiKeyEvent::APIKeyCreated {
                name,
                key_hash,
                scopes,
            } => {
                self.name = name;
                self.key_hash = key_hash;
                self.scopes = scopes;
                self.active = true;
                self.deleted = false;
            }
            ApiKeyEvent::APIKeyRotated { new_key_hash } => {
                self.key_hash = new_key_hash;
            }
            ApiKeyEvent::APIKeyScopeChanged { new_scopes, .. } => {
                self.scopes = new_scopes;
            }
            ApiKeyEvent::APIKeyDeactivated => {
                self.active = false;
            }
            ApiKeyEvent::APIKeyDeleted => {
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
            aggregate_type: "ApiKey".to_string(),
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
    fn test_api_key_lifecycle() {
        let mut agg = ApiKeyAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "APIKeyCreated",
            serde_json::json!({
                "type": "APIKeyCreated",
                "data": {
                    "name": "My Key",
                    "key_hash": "hash_1",
                    "scopes": ["read", "write"]
                }
            }),
        ));

        assert_eq!(agg.name, "My Key");
        assert_eq!(agg.key_hash, "hash_1");
        assert_eq!(agg.scopes, vec!["read", "write"]);
        assert!(agg.active);

        agg.apply(&make_stored_event(
            id,
            2,
            "APIKeyRotated",
            serde_json::json!({
                "type": "APIKeyRotated",
                "data": { "new_key_hash": "hash_2" }
            }),
        ));
        assert_eq!(agg.key_hash, "hash_2");

        agg.apply(&make_stored_event(
            id,
            3,
            "APIKeyScopeChanged",
            serde_json::json!({
                "type": "APIKeyScopeChanged",
                "data": { "old_scopes": ["read", "write"], "new_scopes": ["read"] }
            }),
        ));
        assert_eq!(agg.scopes, vec!["read"]);

        agg.apply(&make_stored_event(
            id,
            4,
            "APIKeyDeactivated",
            serde_json::json!({"type": "APIKeyDeactivated"}),
        ));
        assert!(!agg.active);

        agg.apply(&make_stored_event(
            id,
            5,
            "APIKeyDeleted",
            serde_json::json!({"type": "APIKeyDeleted"}),
        ));
        assert!(agg.deleted);
        assert_eq!(agg.version(), 5);
    }
}
