use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum MfaEvent {
    TOTPEnrolled {
        user_id: String,
        secret_hash: String,
    },
    TOTPVerified {
        user_id: String,
    },
    TOTPRemoved {
        user_id: String,
    },
    PasskeyRegistered {
        user_id: String,
        credential_id: String,
    },
    PasskeyUsed {
        user_id: String,
        credential_id: String,
    },
    PasskeyRemoved {
        user_id: String,
        credential_id: String,
    },
    RecoveryCodesGenerated {
        user_id: String,
        code_count: u32,
    },
    RecoveryCodeUsed {
        user_id: String,
        code_index: u32,
    },
}
