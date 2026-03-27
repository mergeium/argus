use uuid::Uuid;

use crate::events::invitation::InvitationEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Revoked,
    Expired,
}

impl Default for InvitationStatus {
    fn default() -> Self {
        Self::Pending
    }
}

#[derive(Debug, Clone)]
pub struct InvitationAggregate {
    pub id: Uuid,
    pub version: i64,
    pub email: String,
    pub role: String,
    pub invited_by: String,
    pub accepted_by_user_id: Option<String>,
    pub revoked_by: Option<String>,
    pub status: InvitationStatus,
}

impl Default for InvitationAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            email: String::new(),
            role: String::new(),
            invited_by: String::new(),
            accepted_by_user_id: None,
            revoked_by: None,
            status: InvitationStatus::Pending,
        }
    }
}

impl Aggregate for InvitationAggregate {
    const AGGREGATE_TYPE: &'static str = "Invitation";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(inv_event) = serde_json::from_value::<InvitationEvent>(event.payload.clone()) else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize InvitationEvent payload"
            );
            return;
        };

        match inv_event {
            InvitationEvent::InvitationCreated {
                email,
                role,
                invited_by,
            } => {
                self.email = email;
                self.role = role;
                self.invited_by = invited_by;
                self.status = InvitationStatus::Pending;
            }
            InvitationEvent::InvitationAccepted { user_id } => {
                self.accepted_by_user_id = Some(user_id);
                self.status = InvitationStatus::Accepted;
            }
            InvitationEvent::InvitationRevoked { revoked_by } => {
                self.revoked_by = Some(revoked_by);
                self.status = InvitationStatus::Revoked;
            }
            InvitationEvent::InvitationExpired => {
                self.status = InvitationStatus::Expired;
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
            aggregate_type: "Invitation".to_string(),
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
    fn test_invitation_accept_flow() {
        let mut agg = InvitationAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "InvitationCreated",
            serde_json::json!({
                "type": "InvitationCreated",
                "data": {
                    "email": "bob@example.com",
                    "role": "member",
                    "invited_by": "admin_1"
                }
            }),
        ));

        assert_eq!(agg.email, "bob@example.com");
        assert_eq!(agg.role, "member");
        assert_eq!(agg.status, InvitationStatus::Pending);

        agg.apply(&make_stored_event(
            id,
            2,
            "InvitationAccepted",
            serde_json::json!({
                "type": "InvitationAccepted",
                "data": { "user_id": "usr_bob" }
            }),
        ));

        assert_eq!(agg.status, InvitationStatus::Accepted);
        assert_eq!(agg.accepted_by_user_id, Some("usr_bob".to_string()));
        assert_eq!(agg.version(), 2);
    }

    #[test]
    fn test_invitation_revoke_flow() {
        let mut agg = InvitationAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "InvitationCreated",
            serde_json::json!({
                "type": "InvitationCreated",
                "data": {
                    "email": "carol@example.com",
                    "role": "admin",
                    "invited_by": "admin_2"
                }
            }),
        ));

        agg.apply(&make_stored_event(
            id,
            2,
            "InvitationRevoked",
            serde_json::json!({
                "type": "InvitationRevoked",
                "data": { "revoked_by": "admin_2" }
            }),
        ));

        assert_eq!(agg.status, InvitationStatus::Revoked);
        assert_eq!(agg.revoked_by, Some("admin_2".to_string()));
    }

    #[test]
    fn test_invitation_expired() {
        let mut agg = InvitationAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "InvitationCreated",
            serde_json::json!({
                "type": "InvitationCreated",
                "data": {
                    "email": "dave@example.com",
                    "role": "viewer",
                    "invited_by": "admin_3"
                }
            }),
        ));

        agg.apply(&make_stored_event(
            id,
            2,
            "InvitationExpired",
            serde_json::json!({"type": "InvitationExpired"}),
        ));

        assert_eq!(agg.status, InvitationStatus::Expired);
        assert_eq!(agg.version(), 2);
    }
}
