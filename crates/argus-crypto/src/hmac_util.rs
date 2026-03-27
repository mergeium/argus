use hmac::{Hmac, Mac};
use sha2::Sha256;

use argus_core::error::ArgusError;

type HmacSha256 = Hmac<Sha256>;

/// Sign data with HMAC-SHA256. Used for CSRF tokens, cookie signing, webhook signatures.
pub fn sign(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key can be any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Verify an HMAC-SHA256 signature (constant-time comparison).
pub fn verify(key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), ArgusError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key can be any size");
    mac.update(data);
    mac.verify_slice(signature)
        .map_err(|_| ArgusError::CryptoError("HMAC verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let key = b"webhook-signing-secret";
        let data = b"POST /webhook {\"event\": \"user.created\"}";

        let sig = sign(key, data);
        assert!(verify(key, data, &sig).is_ok());
    }

    #[test]
    fn wrong_signature_rejected() {
        let key = b"secret";
        let data = b"some data";
        let mut sig = sign(key, data);
        sig[0] ^= 0xff;
        assert!(verify(key, data, &sig).is_err());
    }
}
