use serde::Deserialize;

/// Layered configuration: TOML file → environment variables → CLI args.
#[derive(Debug, Clone, Deserialize)]
pub struct ArgusConfig {
    #[serde(default = "default_server")]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub nats: NatsConfig,
    #[serde(default)]
    pub crypto: CryptoConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub features: FeaturesConfig,
    #[serde(default)]
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Path to TLS certificate file (PEM). If set together with `tls_key`, enables TLS 1.3 via rustls.
    #[serde(default)]
    pub tls_cert: Option<String>,
    /// Path to TLS private key file (PEM). If set together with `tls_cert`, enables TLS 1.3 via rustls.
    #[serde(default)]
    pub tls_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    /// OTel collector endpoint, e.g. http://otel:4318
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// Enable Prometheus-style metrics collection
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,
    /// Tracing level filter
    #[serde(default = "default_tracing_level")]
    pub tracing_level: String,
    /// Log format: "json" or "pretty"
    #[serde(default = "default_log_format")]
    pub log_format: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    /// Maximum authentication attempts per minute per IP/user
    #[serde(default = "default_auth_rate_limit")]
    pub auth_rate_limit_per_minute: u32,
    /// Maximum concurrent sessions per user
    #[serde(default = "default_max_sessions")]
    pub max_sessions_per_user: u32,
    /// Maximum request body size in bytes (default 1 MB)
    #[serde(default = "default_max_body_bytes")]
    pub max_request_body_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeaturesConfig {
    /// Enable OpenID Connect protocol support
    #[serde(default = "default_true")]
    pub oidc: bool,
    /// Enable SAML 2.0 protocol support
    #[serde(default)]
    pub saml: bool,
    /// Enable WebAuthn / passkey support
    #[serde(default = "default_true")]
    pub webauthn: bool,
    /// Enable LDAP directory integration
    #[serde(default)]
    pub ldap: bool,
    /// Enable SCIM provisioning
    #[serde(default)]
    pub scim: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// Signing key source: "db", "hsm", or "env" (PDF §16.2)
    #[serde(default = "default_signing_key_source")]
    pub signing_key_source: String,
    /// Whether passkey/WebAuthn is the default auth method
    #[serde(default = "default_true")]
    pub passkey_first: bool,
    /// Whether to allow password-based login (fallback)
    #[serde(default = "default_true")]
    pub password_login_enabled: bool,
    /// Maximum failed login attempts before account lockout
    #[serde(default = "default_max_failed_attempts")]
    pub max_failed_attempts: u32,
    /// Account lockout duration in seconds
    #[serde(default = "default_lockout_duration_secs")]
    pub lockout_duration_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_database_url")]
    pub url: String,
    #[serde(default = "default_pool_size")]
    pub max_connections: u32,
    #[serde(default)]
    pub migrate_on_start: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    #[serde(default = "default_redis_url")]
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NatsConfig {
    #[serde(default = "default_nats_url")]
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CryptoConfig {
    #[serde(default = "default_argon2_memory")]
    pub argon2_memory_kib: u32,
    #[serde(default = "default_argon2_iterations")]
    pub argon2_iterations: u32,
    #[serde(default = "default_argon2_parallelism")]
    pub argon2_parallelism: u32,
    #[serde(default = "default_jwt_issuer")]
    pub jwt_issuer: String,
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl_secs: u64,
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl_secs: u64,
}

// Defaults
fn default_true() -> bool {
    true
}
fn default_tracing_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "json".into()
}
fn default_auth_rate_limit() -> u32 {
    10
}
fn default_max_sessions() -> u32 {
    5
}
fn default_max_body_bytes() -> usize {
    1_048_576 // 1 MB
}
fn default_signing_key_source() -> String {
    "db".into()
}
fn default_max_failed_attempts() -> u32 {
    5
}
fn default_lockout_duration_secs() -> u64 {
    900 // 15 minutes
}

fn default_server() -> ServerConfig {
    ServerConfig {
        host: default_host(),
        port: default_port(),
        request_timeout_secs: default_request_timeout_secs(),
        tls_cert: None,
        tls_key: None,
    }
}

fn default_host() -> String {
    "0.0.0.0".into()
}
fn default_port() -> u16 {
    8080
}
fn default_request_timeout_secs() -> u64 {
    30
}
fn default_database_url() -> String {
    "postgres://argus:argus@localhost:5432/argus".into()
}
fn default_pool_size() -> u32 {
    10
}
fn default_redis_url() -> String {
    "redis://localhost:6379".into()
}
fn default_nats_url() -> String {
    "nats://localhost:4222".into()
}
fn default_argon2_memory() -> u32 {
    19456 // 19 MiB — OWASP recommended (PDF §15.2)
}
fn default_argon2_iterations() -> u32 {
    2 // OWASP minimum level 2 (PDF §15.2)
}
fn default_argon2_parallelism() -> u32 {
    1 // Minimizes server resource usage while maintaining security (PDF §15.2)
}
fn default_jwt_issuer() -> String {
    "https://auth.argus.dev".into()
}
fn default_access_token_ttl() -> u64 {
    900 // 15 minutes
}
fn default_refresh_token_ttl() -> u64 {
    2_592_000 // 30 days
}

impl Default for ArgusConfig {
    fn default() -> Self {
        Self {
            server: default_server(),
            database: DatabaseConfig::default(),
            redis: RedisConfig::default(),
            nats: NatsConfig::default(),
            crypto: CryptoConfig::default(),
            telemetry: TelemetryConfig::default(),
            limits: LimitsConfig::default(),
            features: FeaturesConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            metrics_enabled: true,
            tracing_level: default_tracing_level(),
            log_format: default_log_format(),
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            auth_rate_limit_per_minute: default_auth_rate_limit(),
            max_sessions_per_user: default_max_sessions(),
            max_request_body_bytes: default_max_body_bytes(),
        }
    }
}

impl Default for FeaturesConfig {
    fn default() -> Self {
        Self {
            oidc: true,
            saml: false,
            webauthn: true,
            ldap: false,
            scim: false,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            signing_key_source: default_signing_key_source(),
            passkey_first: true,
            password_login_enabled: true,
            max_failed_attempts: default_max_failed_attempts(),
            lockout_duration_secs: default_lockout_duration_secs(),
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: default_database_url(),
            max_connections: default_pool_size(),
            migrate_on_start: false,
        }
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: default_redis_url(),
        }
    }
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: default_nats_url(),
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            argon2_memory_kib: default_argon2_memory(),
            argon2_iterations: default_argon2_iterations(),
            argon2_parallelism: default_argon2_parallelism(),
            jwt_issuer: default_jwt_issuer(),
            access_token_ttl_secs: default_access_token_ttl(),
            refresh_token_ttl_secs: default_refresh_token_ttl(),
        }
    }
}

impl ArgusConfig {
    /// Load configuration from file + environment variables.
    /// Env vars are prefixed with `ARGUS_` and use `__` as separator.
    /// e.g. `ARGUS_SERVER__PORT=9090`
    pub fn load() -> Result<Self, config::ConfigError> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name("argus").required(false))
            .add_source(config::Environment::with_prefix("ARGUS").separator("__"))
            .build()?;

        cfg.try_deserialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = ArgusConfig::default();
        assert_eq!(config.server.port, 8080);
        assert!(config.server.tls_cert.is_none());
        assert!(config.server.tls_key.is_none());
        assert_eq!(config.crypto.argon2_memory_kib, 19456);
        assert_eq!(config.crypto.access_token_ttl_secs, 900);

        // Telemetry defaults
        assert!(config.telemetry.otlp_endpoint.is_none());
        assert!(config.telemetry.metrics_enabled);
        assert_eq!(config.telemetry.tracing_level, "info");
        assert_eq!(config.telemetry.log_format, "json");

        // Limits defaults
        assert_eq!(config.limits.auth_rate_limit_per_minute, 10);
        assert_eq!(config.limits.max_sessions_per_user, 5);
        assert_eq!(config.limits.max_request_body_bytes, 1_048_576);

        // Features defaults
        assert!(config.features.oidc);
        assert!(!config.features.saml);
        assert!(config.features.webauthn);
        assert!(!config.features.ldap);
        assert!(!config.features.scim);

        // Auth defaults (9th config group)
        assert_eq!(config.auth.signing_key_source, "db");
        assert!(config.auth.passkey_first);
        assert!(config.auth.password_login_enabled);
        assert_eq!(config.auth.max_failed_attempts, 5);
        assert_eq!(config.auth.lockout_duration_secs, 900);
    }
}
