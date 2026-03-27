use std::collections::HashMap;
use std::sync::RwLock;

use argus_core::error::{ArgusError, ArgusResult};
use argus_core::id::KeyId;
use ed25519_dalek::{Signer, Verifier};

use crate::encryption;
use crate::keys::Ed25519KeyPair;

/// Hardware Security Module trait (PDF §15.5 — PKCS#11 abstraction).
///
/// Supported backends (Phase 2+):
/// - YubiHSM 2 (USB HID / PKCS#11)
/// - AWS CloudHSM (PKCS#11, FIPS 140-2 Level 3)
/// - Google Cloud HSM (PKCS#11 / CKM)
/// - Azure Dedicated HSM (PKCS#11)
/// - HashiCorp Vault (Transit engine)
/// - Any PKCS#11 v2.40 compatible HSM
///
/// Phase 0: Software fallback is the default provider.
pub trait HsmProvider: Send + Sync {
    /// Sign data with a named key (Ed25519).
    fn sign(
        &self,
        key_id: &str,
        data: &[u8],
    ) -> impl std::future::Future<Output = ArgusResult<Vec<u8>>> + Send;

    /// Verify a signature with a named key.
    fn verify(
        &self,
        key_id: &str,
        data: &[u8],
        signature: &[u8],
    ) -> impl std::future::Future<Output = ArgusResult<bool>> + Send;

    /// Encrypt data with ChaCha20-Poly1305 using a named key.
    fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
    ) -> impl std::future::Future<Output = ArgusResult<Vec<u8>>> + Send;

    /// Decrypt data encrypted with `encrypt`.
    fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
    ) -> impl std::future::Future<Output = ArgusResult<Vec<u8>>> + Send;

    /// Generate a new key and return its ID.
    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
    ) -> impl std::future::Future<Output = ArgusResult<String>> + Send;

    /// Export the public key bytes (32 bytes for Ed25519).
    fn export_public_key(
        &self,
        key_id: &str,
    ) -> impl std::future::Future<Output = ArgusResult<Vec<u8>>> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    HmacSha256,
    Aes256,
}

/// In-memory key material for the software provider.
enum SoftwareKey {
    Ed25519(Ed25519KeyPair),
    Symmetric([u8; 32]),
}

/// Software-only HSM provider (default fallback, no hardware required).
/// Stores keys in memory. Uses Ed25519 for signing and ChaCha20-Poly1305 for encryption.
pub struct SoftwareHsmProvider {
    keys: RwLock<HashMap<String, SoftwareKey>>,
}

impl SoftwareHsmProvider {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for SoftwareHsmProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmProvider for SoftwareHsmProvider {
    async fn sign(&self, key_id: &str, data: &[u8]) -> ArgusResult<Vec<u8>> {
        let keys = self
            .keys
            .read()
            .map_err(|e| ArgusError::Internal(format!("lock: {e}")))?;
        match keys.get(key_id) {
            Some(SoftwareKey::Ed25519(kp)) => {
                let sig = kp.signing_key().sign(data);
                Ok(sig.to_bytes().to_vec())
            }
            Some(_) => Err(ArgusError::CryptoError(format!(
                "key {key_id} is not a signing key"
            ))),
            None => Err(ArgusError::KeyNotFound(key_id.to_string())),
        }
    }

    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> ArgusResult<bool> {
        let keys = self
            .keys
            .read()
            .map_err(|e| ArgusError::Internal(format!("lock: {e}")))?;
        match keys.get(key_id) {
            Some(SoftwareKey::Ed25519(kp)) => {
                let sig = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|e| ArgusError::CryptoError(format!("invalid signature: {e}")))?;
                Ok(kp.verifying_key().verify(data, &sig).is_ok())
            }
            Some(_) => Err(ArgusError::CryptoError(format!(
                "key {key_id} is not a signing key"
            ))),
            None => Err(ArgusError::KeyNotFound(key_id.to_string())),
        }
    }

    async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> ArgusResult<Vec<u8>> {
        let keys = self
            .keys
            .read()
            .map_err(|e| ArgusError::Internal(format!("lock: {e}")))?;
        match keys.get(key_id) {
            Some(SoftwareKey::Symmetric(key)) => encryption::encrypt(key, plaintext),
            Some(_) => Err(ArgusError::CryptoError(format!(
                "key {key_id} is not a symmetric key"
            ))),
            None => Err(ArgusError::KeyNotFound(key_id.to_string())),
        }
    }

    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> ArgusResult<Vec<u8>> {
        let keys = self
            .keys
            .read()
            .map_err(|e| ArgusError::Internal(format!("lock: {e}")))?;
        match keys.get(key_id) {
            Some(SoftwareKey::Symmetric(key)) => encryption::decrypt(key, ciphertext),
            Some(_) => Err(ArgusError::CryptoError(format!(
                "key {key_id} is not a symmetric key"
            ))),
            None => Err(ArgusError::KeyNotFound(key_id.to_string())),
        }
    }

    async fn generate_key(&self, algorithm: KeyAlgorithm) -> ArgusResult<String> {
        let mut keys = self
            .keys
            .write()
            .map_err(|e| ArgusError::Internal(format!("lock: {e}")))?;
        match algorithm {
            KeyAlgorithm::Ed25519 => {
                let kp = Ed25519KeyPair::generate();
                let id = kp.key_id.to_string();
                keys.insert(id.clone(), SoftwareKey::Ed25519(kp));
                Ok(id)
            }
            KeyAlgorithm::Aes256 | KeyAlgorithm::HmacSha256 => {
                let key: [u8; 32] = rand::random();
                let id = KeyId::new().to_string();
                keys.insert(id.clone(), SoftwareKey::Symmetric(key));
                Ok(id)
            }
            KeyAlgorithm::EcdsaP256 => Err(ArgusError::CryptoError(
                "P-256 not yet supported in software HSM; use Ed25519".into(),
            )),
        }
    }

    async fn export_public_key(&self, key_id: &str) -> ArgusResult<Vec<u8>> {
        let keys = self
            .keys
            .read()
            .map_err(|e| ArgusError::Internal(format!("lock: {e}")))?;
        match keys.get(key_id) {
            Some(SoftwareKey::Ed25519(kp)) => Ok(kp.public_key_bytes.to_vec()),
            Some(_) => Err(ArgusError::CryptoError(format!(
                "key {key_id} has no public key"
            ))),
            None => Err(ArgusError::KeyNotFound(key_id.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generate_ed25519_and_sign_verify() {
        let hsm = SoftwareHsmProvider::new();
        let key_id = hsm.generate_key(KeyAlgorithm::Ed25519).await.unwrap();

        let data = b"message to sign";
        let sig = hsm.sign(&key_id, data).await.unwrap();
        assert!(hsm.verify(&key_id, data, &sig).await.unwrap());
        assert!(!hsm.verify(&key_id, b"wrong data", &sig).await.unwrap());
    }

    #[tokio::test]
    async fn generate_symmetric_and_encrypt_decrypt() {
        let hsm = SoftwareHsmProvider::new();
        let key_id = hsm.generate_key(KeyAlgorithm::Aes256).await.unwrap();

        let plaintext = b"sensitive data";
        let ciphertext = hsm.encrypt(&key_id, plaintext).await.unwrap();
        assert_ne!(&ciphertext, plaintext);

        let decrypted = hsm.decrypt(&key_id, &ciphertext).await.unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[tokio::test]
    async fn wrong_key_type_errors() {
        let hsm = SoftwareHsmProvider::new();
        let sym_key = hsm.generate_key(KeyAlgorithm::Aes256).await.unwrap();
        assert!(hsm.sign(&sym_key, b"data").await.is_err());

        let ed_key = hsm.generate_key(KeyAlgorithm::Ed25519).await.unwrap();
        assert!(hsm.encrypt(&ed_key, b"data").await.is_err());
    }

    #[tokio::test]
    async fn missing_key_errors() {
        let hsm = SoftwareHsmProvider::new();
        assert!(hsm.sign("nonexistent", b"data").await.is_err());
        assert!(hsm.encrypt("nonexistent", b"data").await.is_err());
        assert!(hsm.export_public_key("nonexistent").await.is_err());
    }

    #[tokio::test]
    async fn export_public_key_works() {
        let hsm = SoftwareHsmProvider::new();
        let key_id = hsm.generate_key(KeyAlgorithm::Ed25519).await.unwrap();
        let pk = hsm.export_public_key(&key_id).await.unwrap();
        assert_eq!(pk.len(), 32);
    }
}
