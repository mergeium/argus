use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArgusError {
    // --- Authentication ---
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("account locked until {0}")]
    AccountLocked(chrono::DateTime<chrono::Utc>),

    #[error("session expired")]
    SessionExpired,

    #[error("token expired")]
    TokenExpired,

    #[error("invalid token: {0}")]
    InvalidToken(String),

    #[error("mfa required")]
    MfaRequired,

    // --- Authorization ---
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("insufficient scope: required {required}, got {actual}")]
    InsufficientScope { required: String, actual: String },

    // --- Resources ---
    #[error("{resource} not found: {id}")]
    NotFound { resource: &'static str, id: String },

    #[error("{resource} already exists: {id}")]
    AlreadyExists { resource: &'static str, id: String },

    // --- Event Store ---
    #[error(
        "concurrency conflict on aggregate {aggregate_id} (expected version {expected}, got {actual})"
    )]
    ConcurrencyConflict {
        aggregate_id: String,
        expected: i64,
        actual: i64,
    },

    #[error("aggregate not found: {0}")]
    AggregateNotFound(String),

    // --- Crypto ---
    #[error("cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    // --- Validation ---
    #[error("validation error: {0}")]
    Validation(String),

    #[error("invalid configuration: {0}")]
    ConfigError(String),

    // --- Infrastructure ---
    #[error("database error: {0}")]
    Database(String),

    #[error("cache error: {0}")]
    Cache(String),

    #[error("messaging error: {0}")]
    Messaging(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type ArgusResult<T> = Result<T, ArgusError>;
