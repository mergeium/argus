use uuid::Uuid;

use crate::events::audit::AuditEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub action: String,
    pub success: bool,
    pub ip: String,
    pub user_agent: String,
}

#[derive(Debug, Clone)]
pub struct AuthzEntry {
    pub subject: String,
    pub resource: String,
    pub action: String,
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct AuditAggregate {
    pub id: Uuid,
    pub version: i64,
    pub user_id: String,
    pub auth_events: Vec<AuditEntry>,
    pub authz_decisions: Vec<AuthzEntry>,
    pub total_auth_success: u64,
    pub total_auth_failure: u64,
    pub total_authz_allowed: u64,
    pub total_authz_denied: u64,
}

impl Default for AuditAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            user_id: String::new(),
            auth_events: Vec::new(),
            authz_decisions: Vec::new(),
            total_auth_success: 0,
            total_auth_failure: 0,
            total_authz_allowed: 0,
            total_authz_denied: 0,
        }
    }
}

impl Aggregate for AuditAggregate {
    const AGGREGATE_TYPE: &'static str = "Audit";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(audit_event) = serde_json::from_value::<AuditEvent>(event.payload.clone()) else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize AuditEvent payload"
            );
            return;
        };

        match audit_event {
            AuditEvent::AuthEvent {
                user_id,
                action,
                success,
                ip,
                user_agent,
            } => {
                self.user_id = user_id;
                if success {
                    self.total_auth_success += 1;
                } else {
                    self.total_auth_failure += 1;
                }
                self.auth_events.push(AuditEntry {
                    action,
                    success,
                    ip,
                    user_agent,
                });
            }
            AuditEvent::AuthzDecision {
                subject,
                resource,
                action,
                allowed,
                reason,
            } => {
                if allowed {
                    self.total_authz_allowed += 1;
                } else {
                    self.total_authz_denied += 1;
                }
                self.authz_decisions.push(AuthzEntry {
                    subject,
                    resource,
                    action,
                    allowed,
                    reason,
                });
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
            aggregate_type: "Audit".to_string(),
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
    fn test_auth_events() {
        let mut agg = AuditAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "AuthEvent",
            serde_json::json!({
                "type": "AuthEvent",
                "data": {
                    "user_id": "usr_1",
                    "action": "login",
                    "success": true,
                    "ip": "192.168.1.1",
                    "user_agent": "Mozilla/5.0"
                }
            }),
        ));

        assert_eq!(agg.user_id, "usr_1");
        assert_eq!(agg.total_auth_success, 1);
        assert_eq!(agg.total_auth_failure, 0);
        assert_eq!(agg.auth_events.len(), 1);
        assert_eq!(agg.auth_events[0].action, "login");

        agg.apply(&make_stored_event(
            id,
            2,
            "AuthEvent",
            serde_json::json!({
                "type": "AuthEvent",
                "data": {
                    "user_id": "usr_1",
                    "action": "login",
                    "success": false,
                    "ip": "10.0.0.1",
                    "user_agent": "curl"
                }
            }),
        ));

        assert_eq!(agg.total_auth_success, 1);
        assert_eq!(agg.total_auth_failure, 1);
        assert_eq!(agg.auth_events.len(), 2);
    }

    #[test]
    fn test_authz_decisions() {
        let mut agg = AuditAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "AuthzDecision",
            serde_json::json!({
                "type": "AuthzDecision",
                "data": {
                    "subject": "user:alice",
                    "resource": "doc:123",
                    "action": "read",
                    "allowed": true,
                    "reason": "direct grant"
                }
            }),
        ));

        assert_eq!(agg.total_authz_allowed, 1);
        assert_eq!(agg.total_authz_denied, 0);

        agg.apply(&make_stored_event(
            id,
            2,
            "AuthzDecision",
            serde_json::json!({
                "type": "AuthzDecision",
                "data": {
                    "subject": "user:bob",
                    "resource": "doc:123",
                    "action": "write",
                    "allowed": false,
                    "reason": "no permission"
                }
            }),
        ));

        assert_eq!(agg.total_authz_allowed, 1);
        assert_eq!(agg.total_authz_denied, 1);
        assert_eq!(agg.authz_decisions.len(), 2);
        assert_eq!(agg.version(), 2);
    }
}
