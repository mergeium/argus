use uuid::Uuid;

use crate::events::connector::ConnectorEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorType {
    None,
    Ldap,
    SamlIdp,
    Social,
}

impl Default for ConnectorType {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    Idle,
    InProgress,
    Completed,
    Failed,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self::Idle
    }
}

#[derive(Debug, Clone)]
pub struct ConnectorAggregate {
    pub id: Uuid,
    pub version: i64,
    pub connector_type: ConnectorType,
    pub host: String,
    pub base_dn: String,
    pub entity_id: String,
    pub metadata_url: String,
    pub provider: String,
    pub client_id: String,
    pub sync_status: SyncStatus,
    pub last_sync_users: u64,
    pub last_sync_error: Option<String>,
    pub deleted: bool,
}

impl Default for ConnectorAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            connector_type: ConnectorType::None,
            host: String::new(),
            base_dn: String::new(),
            entity_id: String::new(),
            metadata_url: String::new(),
            provider: String::new(),
            client_id: String::new(),
            sync_status: SyncStatus::Idle,
            last_sync_users: 0,
            last_sync_error: None,
            deleted: false,
        }
    }
}

impl Aggregate for ConnectorAggregate {
    const AGGREGATE_TYPE: &'static str = "Connector";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(conn_event) = serde_json::from_value::<ConnectorEvent>(event.payload.clone()) else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize ConnectorEvent payload"
            );
            return;
        };

        match conn_event {
            ConnectorEvent::LDAPConnectorCreated { host, base_dn } => {
                self.connector_type = ConnectorType::Ldap;
                self.host = host;
                self.base_dn = base_dn;
                self.deleted = false;
            }
            ConnectorEvent::LDAPSyncStarted { connector_id: _ } => {
                self.sync_status = SyncStatus::InProgress;
                self.last_sync_error = None;
            }
            ConnectorEvent::LDAPSyncCompleted {
                connector_id: _,
                users_synced,
            } => {
                self.sync_status = SyncStatus::Completed;
                self.last_sync_users = users_synced;
                self.last_sync_error = None;
            }
            ConnectorEvent::LDAPSyncFailed {
                connector_id: _,
                error,
            } => {
                self.sync_status = SyncStatus::Failed;
                self.last_sync_error = Some(error);
            }
            ConnectorEvent::SAMLIdPCreated {
                entity_id,
                metadata_url,
            } => {
                self.connector_type = ConnectorType::SamlIdp;
                self.entity_id = entity_id;
                self.metadata_url = metadata_url;
                self.deleted = false;
            }
            ConnectorEvent::SocialProviderAdded {
                provider,
                client_id,
            } => {
                self.connector_type = ConnectorType::Social;
                self.provider = provider;
                self.client_id = client_id;
                self.deleted = false;
            }
            ConnectorEvent::ConnectorDeleted { connector_id: _ } => {
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
            aggregate_type: "Connector".to_string(),
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
    fn test_ldap_connector_lifecycle() {
        let mut agg = ConnectorAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "LDAPConnectorCreated",
            serde_json::json!({
                "type": "LDAPConnectorCreated",
                "data": { "host": "ldap.example.com", "base_dn": "dc=example,dc=com" }
            }),
        ));

        assert_eq!(agg.connector_type, ConnectorType::Ldap);
        assert_eq!(agg.host, "ldap.example.com");
        assert_eq!(agg.base_dn, "dc=example,dc=com");

        agg.apply(&make_stored_event(
            id,
            2,
            "LDAPSyncStarted",
            serde_json::json!({
                "type": "LDAPSyncStarted",
                "data": { "connector_id": "conn_1" }
            }),
        ));
        assert_eq!(agg.sync_status, SyncStatus::InProgress);

        agg.apply(&make_stored_event(
            id,
            3,
            "LDAPSyncCompleted",
            serde_json::json!({
                "type": "LDAPSyncCompleted",
                "data": { "connector_id": "conn_1", "users_synced": 150 }
            }),
        ));
        assert_eq!(agg.sync_status, SyncStatus::Completed);
        assert_eq!(agg.last_sync_users, 150);

        agg.apply(&make_stored_event(
            id,
            4,
            "ConnectorDeleted",
            serde_json::json!({
                "type": "ConnectorDeleted",
                "data": { "connector_id": "conn_1" }
            }),
        ));
        assert!(agg.deleted);
        assert_eq!(agg.version(), 4);
    }

    #[test]
    fn test_ldap_sync_failed() {
        let mut agg = ConnectorAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "LDAPConnectorCreated",
            serde_json::json!({
                "type": "LDAPConnectorCreated",
                "data": { "host": "ldap.test.com", "base_dn": "dc=test,dc=com" }
            }),
        ));

        agg.apply(&make_stored_event(
            id,
            2,
            "LDAPSyncStarted",
            serde_json::json!({
                "type": "LDAPSyncStarted",
                "data": { "connector_id": "conn_2" }
            }),
        ));

        agg.apply(&make_stored_event(
            id,
            3,
            "LDAPSyncFailed",
            serde_json::json!({
                "type": "LDAPSyncFailed",
                "data": { "connector_id": "conn_2", "error": "connection timeout" }
            }),
        ));

        assert_eq!(agg.sync_status, SyncStatus::Failed);
        assert_eq!(agg.last_sync_error, Some("connection timeout".to_string()));
    }

    #[test]
    fn test_saml_idp_created() {
        let mut agg = ConnectorAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "SAMLIdPCreated",
            serde_json::json!({
                "type": "SAMLIdPCreated",
                "data": {
                    "entity_id": "https://idp.example.com",
                    "metadata_url": "https://idp.example.com/metadata"
                }
            }),
        ));

        assert_eq!(agg.connector_type, ConnectorType::SamlIdp);
        assert_eq!(agg.entity_id, "https://idp.example.com");
        assert_eq!(agg.metadata_url, "https://idp.example.com/metadata");
    }
}
