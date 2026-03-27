use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WebhookEvent {
    WebhookCreated {
        url: String,
        event_types: Vec<String>,
        secret_hash: String,
    },
    WebhookFired {
        webhook_id: String,
        event_type: String,
    },
    WebhookDelivered {
        webhook_id: String,
        status_code: u16,
    },
    WebhookFailed {
        webhook_id: String,
        error: String,
        attempt: u32,
    },
    WebhookDeleted,
}
