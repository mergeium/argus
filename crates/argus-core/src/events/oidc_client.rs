use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum OidcClientEvent {
    ClientCreated {
        client_name: String,
        redirect_uris: Vec<String>,
        grant_types: Vec<String>,
    },
    ClientSecretRotated {
        secret_hash: String,
    },
    ClientRedirectUriAdded {
        uri: String,
    },
    ClientScopeAdded {
        scope: String,
    },
    ClientGrantTypeSet {
        grant_types: Vec<String>,
    },
    ClientRateLimitSet {
        rate_limit: serde_json::Value,
    },
    ClientJwtTemplateSet {
        template: serde_json::Value,
    },
    ClientSettingsChanged {
        settings: serde_json::Value,
    },
    ClientDeactivated,
    ClientDeleted,
}
