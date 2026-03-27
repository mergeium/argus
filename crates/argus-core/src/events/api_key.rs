use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ApiKeyEvent {
    APIKeyCreated {
        name: String,
        key_hash: String,
        scopes: Vec<String>,
    },
    APIKeyRotated {
        new_key_hash: String,
    },
    APIKeyScopeChanged {
        old_scopes: Vec<String>,
        new_scopes: Vec<String>,
    },
    APIKeyDeactivated,
    APIKeyDeleted,
}
