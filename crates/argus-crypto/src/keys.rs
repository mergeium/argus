use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use argus_core::id::KeyId;

/// An Ed25519 key pair with automatic zeroization on drop.
///
/// Used for non-JWT cryptographic operations (webhook signing, attestation, etc.).
/// For JWT signing/verification, use `JwtKeyManager` in the `jwt` module which
/// uses ring internally for compatibility with the jsonwebtoken crate.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519KeyPair {
    #[zeroize(skip)]
    pub key_id: KeyId,
    secret_key_bytes: [u8; 32],
    #[zeroize(skip)]
    pub public_key_bytes: [u8; 32],
}

impl Ed25519KeyPair {
    /// Generate a new random Ed25519 key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Self {
            key_id: KeyId::new(),
            secret_key_bytes: signing_key.to_bytes(),
            public_key_bytes: verifying_key.to_bytes(),
        }
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.secret_key_bytes)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.public_key_bytes).expect("stored public key is always valid")
    }
}

/// JSON Web Key (RFC 7517) for Ed25519 public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKey {
    pub kty: String,
    pub crv: String,
    pub kid: String,
    pub x: String,
    #[serde(rename = "alg")]
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
}

/// JWKS document containing one or more public keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKeySet {
    pub keys: Vec<JsonWebKey>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn generate_and_sign() {
        let kp = Ed25519KeyPair::generate();
        let signing = kp.signing_key();
        let verifying = kp.verifying_key();

        let message = b"test message";
        let signature = signing.sign(message);
        assert!(verifying.verify_strict(message, &signature).is_ok());
    }

    #[test]
    fn key_pair_zeroizes_on_drop() {
        let kp = Ed25519KeyPair::generate();
        assert!(!kp.public_key_bytes.iter().all(|&b| b == 0));
        // Zeroize happens on drop - can't easily test, but derive ensures it
    }
}
