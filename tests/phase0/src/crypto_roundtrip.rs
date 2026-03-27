//! Cross-crate integration tests for the crypto module.
//! These test multiple crypto primitives working together — scenarios
//! that span hashing + JWT + encryption + HSM.
//!
//! Unit tests for individual primitives live in each module file
//! (e.g. crates/argus-crypto/src/hashing.rs).

use argus_crypto::encryption;
use argus_crypto::hashing::PasswordHasherService;
use argus_crypto::hmac_util;
use argus_crypto::hsm::{HsmProvider, KeyAlgorithm, SoftwareHsmProvider};
use argus_crypto::jwt::{self, JwtKeyManager};
use zeroize::Zeroizing;

/// End-to-end: user registers (hash password) → gets JWT → JWT verifies → key rotates → old JWT still works.
#[test]
fn user_registration_to_jwt_lifecycle() {
    let config = argus_core::config::CryptoConfig {
        argon2_memory_kib: 1024,
        argon2_iterations: 1,
        argon2_parallelism: 1,
        ..Default::default()
    };
    let hasher = PasswordHasherService::new(&config);

    // 1. User registers — password hashed
    let hash = hasher
        .hash_password(Zeroizing::new("S3cure!Pass".into()))
        .unwrap();
    assert!(hash.starts_with("$argon2id$"));

    // 2. User logs in — password verified
    assert!(
        hasher
            .verify_password(Zeroizing::new("S3cure!Pass".into()), &hash)
            .unwrap()
    );

    // 3. JWT issued
    let mut km = JwtKeyManager::new().unwrap();
    let claims =
        jwt::build_access_token_claims("usr_123", "https://auth.argus.dev", "tnt_abc", 3600);
    let token = km.sign(&claims).unwrap();

    // 4. JWT verified
    let decoded: jwt::AccessTokenClaims = km.verify(&token, "https://auth.argus.dev").unwrap();
    assert_eq!(decoded.sub, "usr_123");

    // 5. Key rotation — old token still valid
    km.rotate().unwrap();
    let _: jwt::AccessTokenClaims = km.verify(&token, "https://auth.argus.dev").unwrap();
}

/// End-to-end: encrypt sensitive data (LDAP password) with HSM → decrypt → verify HMAC webhook.
#[tokio::test]
async fn sensitive_data_encryption_with_hsm() {
    let hsm = SoftwareHsmProvider::new();

    // Generate a symmetric key for data encryption
    let dek_id = hsm.generate_key(KeyAlgorithm::Aes256).await.unwrap();

    // Encrypt an LDAP bind password
    let ldap_password = b"ldap-bind-secret-password";
    let encrypted = hsm.encrypt(&dek_id, ldap_password).await.unwrap();
    assert_ne!(&encrypted, ldap_password);

    // Decrypt it back
    let decrypted = hsm.decrypt(&dek_id, &encrypted).await.unwrap();
    assert_eq!(&decrypted, ldap_password);

    // Generate a signing key for webhook HMAC
    let _hmac_key_id = hsm.generate_key(KeyAlgorithm::HmacSha256).await.unwrap();

    // Sign a webhook payload with raw HMAC (using exported key material)
    // In production this would stay inside the HSM boundary
    let webhook_payload = b"{\"event\":\"user.created\",\"user_id\":\"usr_123\"}";
    let webhook_sig = hmac_util::sign(b"tenant-webhook-secret", webhook_payload);
    assert!(hmac_util::verify(b"tenant-webhook-secret", webhook_payload, &webhook_sig).is_ok());
}

/// End-to-end: HKDF key derivation → per-tenant encryption isolation.
#[test]
fn per_tenant_encryption_isolation() {
    let master = b"global-master-key-32-bytes-long!";

    let tenant_a_key = encryption::derive_key(master, b"tenant:acme:dek");
    let tenant_b_key = encryption::derive_key(master, b"tenant:globex:dek");

    // Same master key, different contexts → different DEKs
    assert_ne!(tenant_a_key, tenant_b_key);

    let secret = b"tenant-specific-secret-data";

    // Encrypt with tenant A's key
    let encrypted = encryption::encrypt(&tenant_a_key, secret).unwrap();

    // Tenant B cannot decrypt tenant A's data
    assert!(encryption::decrypt(&tenant_b_key, &encrypted).is_err());

    // Tenant A can decrypt their own data
    assert_eq!(
        encryption::decrypt(&tenant_a_key, &encrypted).unwrap(),
        secret
    );
}
