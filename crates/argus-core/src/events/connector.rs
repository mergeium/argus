use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ConnectorEvent {
    LDAPConnectorCreated {
        host: String,
        base_dn: String,
    },
    LDAPSyncStarted {
        connector_id: String,
    },
    LDAPSyncCompleted {
        connector_id: String,
        users_synced: u64,
    },
    LDAPSyncFailed {
        connector_id: String,
        error: String,
    },
    SAMLIdPCreated {
        entity_id: String,
        metadata_url: String,
    },
    SocialProviderAdded {
        provider: String,
        client_id: String,
    },
    ConnectorDeleted {
        connector_id: String,
    },
}
