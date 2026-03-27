use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum UserEvent {
    UserCreated {
        email: String,
        display_name: Option<String>,
        password_hash: String,
    },
    UserEmailChanged {
        old_email: String,
        new_email: String,
    },
    UserEmailVerified,
    UserPasswordChanged {
        password_hash: String,
    },
    UserMfaEnabled {
        factor: String,
    },
    UserMfaDisabled {
        factor: String,
    },
    UserLocked {
        reason: String,
    },
    UserUnlocked,
    UserMetadataSet {
        metadata: serde_json::Value,
    },
    UserPhoneAdded {
        phone: String,
    },
    UserPhoneVerified,
    UserDeleted,
}
