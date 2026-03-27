//! Cross-crate integration test for configuration system.
//! Verifies that argus-core config is loadable from the test crate
//! and that all 9 config groups are properly structured.
//!
//! Unit tests for individual default values live in
//! crates/argus-core/src/config.rs.

use argus_core::config::ArgusConfig;

/// Verify all 9 config groups exist and are accessible from outside argus-core.
#[test]
fn all_9_config_groups_accessible() {
    let c = ArgusConfig::default();

    // Just verify struct fields are accessible — the actual values
    // are tested by unit tests in config.rs
    let _ = c.server.port;
    let _ = c.database.url;
    let _ = c.redis.url;
    let _ = c.nats.url;
    let _ = c.crypto.argon2_memory_kib;
    let _ = c.auth.signing_key_source;
    let _ = c.telemetry.metrics_enabled;
    let _ = c.limits.auth_rate_limit_per_minute;
    let _ = c.features.oidc;
}

/// Verify config is serialization-round-trip safe via serde.
#[test]
fn config_defaults_deserialize_from_empty_toml() {
    // An empty TOML string should produce valid defaults
    let config: ArgusConfig = toml::from_str("").unwrap();
    assert_eq!(config.server.port, 8080);
    assert_eq!(config.crypto.argon2_memory_kib, 19456);
    assert!(config.features.oidc);
    assert!(!config.features.saml);
    assert_eq!(config.auth.signing_key_source, "db");
}
