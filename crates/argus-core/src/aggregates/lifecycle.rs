use uuid::Uuid;

use crate::events::lifecycle::LifecycleEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeprovisioningStatus {
    NotStarted,
    InProgress,
    Completed,
}

impl Default for DeprovisioningStatus {
    fn default() -> Self {
        Self::NotStarted
    }
}

#[derive(Debug, Clone)]
pub struct LifecycleAggregate {
    pub id: Uuid,
    pub version: i64,
    pub user_id: String,
    pub initiated_by: String,
    pub status: DeprovisioningStatus,
    pub sessions_revoked: u64,
    pub tokens_revoked: u64,
    pub scim_targets: Vec<String>,
}

impl Default for LifecycleAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            user_id: String::new(),
            initiated_by: String::new(),
            status: DeprovisioningStatus::NotStarted,
            sessions_revoked: 0,
            tokens_revoked: 0,
            scim_targets: Vec::new(),
        }
    }
}

impl Aggregate for LifecycleAggregate {
    const AGGREGATE_TYPE: &'static str = "Lifecycle";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(lc_event) = serde_json::from_value::<LifecycleEvent>(event.payload.clone()) else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize LifecycleEvent payload"
            );
            return;
        };

        match lc_event {
            LifecycleEvent::DeprovisioningStarted {
                user_id,
                initiated_by,
            } => {
                self.user_id = user_id;
                self.initiated_by = initiated_by;
                self.status = DeprovisioningStatus::InProgress;
                self.sessions_revoked = 0;
                self.tokens_revoked = 0;
                self.scim_targets.clear();
            }
            LifecycleEvent::SessionsRevoked { user_id, count } => {
                self.user_id = user_id;
                self.sessions_revoked = count;
            }
            LifecycleEvent::TokensRevoked { user_id, count } => {
                self.user_id = user_id;
                self.tokens_revoked = count;
            }
            LifecycleEvent::SCIMPushSent { user_id, target } => {
                self.user_id = user_id;
                if !self.scim_targets.contains(&target) {
                    self.scim_targets.push(target);
                }
            }
            LifecycleEvent::DeprovisioningCompleted { user_id } => {
                self.user_id = user_id;
                self.status = DeprovisioningStatus::Completed;
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
            aggregate_type: "Lifecycle".to_string(),
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
    fn test_full_deprovisioning_flow() {
        let mut agg = LifecycleAggregate::default();
        let id = Uuid::now_v7();

        let events = vec![
            make_stored_event(
                id,
                1,
                "DeprovisioningStarted",
                serde_json::json!({
                    "type": "DeprovisioningStarted",
                    "data": { "user_id": "usr_1", "initiated_by": "admin_1" }
                }),
            ),
            make_stored_event(
                id,
                2,
                "SessionsRevoked",
                serde_json::json!({
                    "type": "SessionsRevoked",
                    "data": { "user_id": "usr_1", "count": 5 }
                }),
            ),
            make_stored_event(
                id,
                3,
                "TokensRevoked",
                serde_json::json!({
                    "type": "TokensRevoked",
                    "data": { "user_id": "usr_1", "count": 12 }
                }),
            ),
            make_stored_event(
                id,
                4,
                "SCIMPushSent",
                serde_json::json!({
                    "type": "SCIMPushSent",
                    "data": { "user_id": "usr_1", "target": "okta" }
                }),
            ),
            make_stored_event(
                id,
                5,
                "DeprovisioningCompleted",
                serde_json::json!({
                    "type": "DeprovisioningCompleted",
                    "data": { "user_id": "usr_1" }
                }),
            ),
        ];

        for event in &events {
            agg.apply(event);
        }

        assert_eq!(agg.version(), 5);
        assert_eq!(agg.user_id, "usr_1");
        assert_eq!(agg.initiated_by, "admin_1");
        assert_eq!(agg.status, DeprovisioningStatus::Completed);
        assert_eq!(agg.sessions_revoked, 5);
        assert_eq!(agg.tokens_revoked, 12);
        assert_eq!(agg.scim_targets, vec!["okta"]);
    }

    #[test]
    fn test_deprovisioning_started() {
        let mut agg = LifecycleAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "DeprovisioningStarted",
            serde_json::json!({
                "type": "DeprovisioningStarted",
                "data": { "user_id": "usr_2", "initiated_by": "system" }
            }),
        ));

        assert_eq!(agg.status, DeprovisioningStatus::InProgress);
        assert_eq!(agg.user_id, "usr_2");
        assert_eq!(agg.initiated_by, "system");
        assert_eq!(agg.version(), 1);
    }
}
