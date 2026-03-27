use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use argus_core::config::CryptoConfig;

/// Argon2id password hasher with OWASP-recommended parameters (PDF §15.2).
///
/// Parameters from spec: m=19456 KiB, t=2, p=1, output=32 bytes
/// Hash time target: ~100ms (brute-force cost vs UX balance)
pub struct PasswordHasherService {
    params: Params,
}

impl PasswordHasherService {
    pub fn new(config: &CryptoConfig) -> Self {
        let params = Params::new(
            config.argon2_memory_kib,
            config.argon2_iterations,
            config.argon2_parallelism,
            Some(32), // 256-bit output per spec
        )
        .expect("invalid Argon2 parameters");

        Self { params }
    }

    /// Hash a password with Argon2id. Returns the PHC-format string.
    /// Password is wrapped in Zeroizing to ensure memory cleanup.
    pub fn hash_password(
        &self,
        password: Zeroizing<String>,
    ) -> Result<String, argus_core::error::ArgusError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone());

        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                argus_core::error::ArgusError::CryptoError(format!("password hash failed: {e}"))
            })?
            .to_string();

        // password is Zeroizing — automatically zeroized on drop
        Ok(hash)
    }

    /// Verify a password against a stored PHC-format hash (constant-time).
    pub fn verify_password(
        &self,
        password: Zeroizing<String>,
        hash: &str,
    ) -> Result<bool, argus_core::error::ArgusError> {
        let parsed = PasswordHash::new(hash).map_err(|e| {
            argus_core::error::ArgusError::CryptoError(format!("invalid hash format: {e}"))
        })?;

        let result = Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone())
            .verify_password(password.as_bytes(), &parsed);

        // password is Zeroizing — automatically zeroized on drop
        Ok(result.is_ok())
    }

    /// Check if a hash needs rehashing (parameter upgrade strategy from PDF §15.2).
    /// On successful login, rehash with current parameters if old params differ.
    pub fn needs_rehash(&self, hash: &str) -> bool {
        let parsed = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(_) => return true,
        };

        // Check if the hash uses current parameters by inspecting the PHC params field
        let params = &parsed.params;
        let m = params.get_str("m").and_then(|v| v.parse::<u32>().ok());
        let t = params.get_str("t").and_then(|v| v.parse::<u32>().ok());
        let p = params.get_str("p").and_then(|v| v.parse::<u32>().ok());

        m != Some(self.params.m_cost())
            || t != Some(self.params.t_cost())
            || p != Some(self.params.p_cost())
    }
}

/// Constant-time comparison for tokens/secrets (PDF §15.6).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hasher() -> PasswordHasherService {
        let config = CryptoConfig {
            argon2_memory_kib: 1024,
            argon2_iterations: 1,
            argon2_parallelism: 1,
            ..CryptoConfig::default()
        };
        PasswordHasherService::new(&config)
    }

    #[test]
    fn hash_and_verify() {
        let hasher = test_hasher();
        let hash = hasher
            .hash_password(Zeroizing::new("SuperSecret123!".into()))
            .unwrap();

        assert!(hash.starts_with("$argon2id$"));
        assert!(
            hasher
                .verify_password(Zeroizing::new("SuperSecret123!".into()), &hash)
                .unwrap()
        );
        assert!(
            !hasher
                .verify_password(Zeroizing::new("WrongPassword".into()), &hash)
                .unwrap()
        );
    }

    #[test]
    fn different_salts_produce_different_hashes() {
        let hasher = test_hasher();
        let h1 = hasher
            .hash_password(Zeroizing::new("same_password".into()))
            .unwrap();
        let h2 = hasher
            .hash_password(Zeroizing::new("same_password".into()))
            .unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn constant_time_comparison() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer_string"));
    }

    #[test]
    fn needs_rehash_detects_param_change() {
        let hasher = test_hasher();
        let hash = hasher.hash_password(Zeroizing::new("test".into())).unwrap();
        assert!(!hasher.needs_rehash(&hash));

        // Different params should trigger rehash
        let config2 = CryptoConfig {
            argon2_memory_kib: 2048,
            argon2_iterations: 2,
            argon2_parallelism: 1,
            ..CryptoConfig::default()
        };
        let hasher2 = PasswordHasherService::new(&config2);
        assert!(hasher2.needs_rehash(&hash));
    }
}
