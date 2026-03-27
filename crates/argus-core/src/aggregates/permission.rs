use uuid::Uuid;

use crate::events::permission::PermissionEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone, PartialEq)]
pub struct PermissionTuple {
    pub user_ref: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}

#[derive(Debug, Clone)]
pub struct PermissionAggregate {
    pub id: Uuid,
    pub version: i64,
    pub tuples: Vec<PermissionTuple>,
    pub authorization_model: serde_json::Value,
    pub deployed_policy_id: Option<String>,
    pub deployed_policy_version: Option<String>,
    pub audit_entries: Vec<(String, String)>,
}

impl Default for PermissionAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            tuples: Vec::new(),
            authorization_model: serde_json::Value::Null,
            deployed_policy_id: None,
            deployed_policy_version: None,
            audit_entries: Vec::new(),
        }
    }
}

impl Aggregate for PermissionAggregate {
    const AGGREGATE_TYPE: &'static str = "Permission";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(perm_event) = serde_json::from_value::<PermissionEvent>(event.payload.clone())
        else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize PermissionEvent payload"
            );
            return;
        };

        match perm_event {
            PermissionEvent::TupleWritten {
                user_ref,
                relation,
                object_type,
                object_id,
            } => {
                let tuple = PermissionTuple {
                    user_ref,
                    relation,
                    object_type,
                    object_id,
                };
                if !self.tuples.contains(&tuple) {
                    self.tuples.push(tuple);
                }
            }
            PermissionEvent::TupleDeleted {
                user_ref,
                relation,
                object_type,
                object_id,
            } => {
                self.tuples.retain(|t| {
                    !(t.user_ref == user_ref
                        && t.relation == relation
                        && t.object_type == object_type
                        && t.object_id == object_id)
                });
            }
            PermissionEvent::AuthorizationModelUpdated { model } => {
                self.authorization_model = model;
            }
            PermissionEvent::PolicyDeployed { policy_id, version } => {
                self.deployed_policy_id = Some(policy_id);
                self.deployed_policy_version = Some(version);
            }
            PermissionEvent::AuditLogEntry { decision, reason } => {
                self.audit_entries.push((decision, reason));
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
            aggregate_type: "Permission".to_string(),
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
    fn test_tuple_write_and_delete() {
        let mut agg = PermissionAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "TupleWritten",
            serde_json::json!({
                "type": "TupleWritten",
                "data": {
                    "user_ref": "user:alice",
                    "relation": "viewer",
                    "object_type": "document",
                    "object_id": "doc_1"
                }
            }),
        ));

        assert_eq!(agg.tuples.len(), 1);
        assert_eq!(agg.tuples[0].user_ref, "user:alice");
        assert_eq!(agg.tuples[0].relation, "viewer");

        agg.apply(&make_stored_event(
            id,
            2,
            "TupleDeleted",
            serde_json::json!({
                "type": "TupleDeleted",
                "data": {
                    "user_ref": "user:alice",
                    "relation": "viewer",
                    "object_type": "document",
                    "object_id": "doc_1"
                }
            }),
        ));

        assert!(agg.tuples.is_empty());
        assert_eq!(agg.version(), 2);
    }

    #[test]
    fn test_policy_deployed_and_model_updated() {
        let mut agg = PermissionAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "AuthorizationModelUpdated",
            serde_json::json!({
                "type": "AuthorizationModelUpdated",
                "data": { "model": {"version": "1.0", "types": []} }
            }),
        ));
        assert_eq!(
            agg.authorization_model,
            serde_json::json!({"version": "1.0", "types": []})
        );

        agg.apply(&make_stored_event(
            id,
            2,
            "PolicyDeployed",
            serde_json::json!({
                "type": "PolicyDeployed",
                "data": { "policy_id": "pol_1", "version": "v2" }
            }),
        ));
        assert_eq!(agg.deployed_policy_id, Some("pol_1".to_string()));
        assert_eq!(agg.deployed_policy_version, Some("v2".to_string()));
        assert_eq!(agg.version(), 2);
    }
}
