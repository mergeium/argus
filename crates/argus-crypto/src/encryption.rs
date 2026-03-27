use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use argus_core::error::ArgusError;

/// Derive a 256-bit encryption key from a master key using HKDF-SHA256.
pub fn derive_key(master_key: &[u8], context: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; 32];
    hk.expand(context, &mut okm)
        .expect("HKDF expand should not fail for 32-byte output");
    okm
}

/// Encrypt plaintext with ChaCha20-Poly1305 using a derived key.
/// Returns nonce || ciphertext (12 + N bytes).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, ArgusError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ArgusError::CryptoError(format!("cipher init: {e}")))?;

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| ArgusError::CryptoError(format!("encrypt: {e}")))?;

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt data produced by `encrypt`. Input is nonce || ciphertext.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, ArgusError> {
    if data.len() < 12 {
        return Err(ArgusError::CryptoError("ciphertext too short".into()));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ArgusError::CryptoError(format!("cipher init: {e}")))?;

    let nonce = Nonce::from_slice(&data[..12]);
    let plaintext = cipher.decrypt(nonce, &data[12..]).map_err(|_| {
        ArgusError::CryptoError("decryption failed (authentication tag mismatch)".into())
    })?;

    // The caller should zeroize the result when done
    Ok(plaintext)
}

/// Encrypt then zeroize the plaintext buffer.
pub fn encrypt_and_zeroize(key: &[u8; 32], plaintext: &mut Vec<u8>) -> Result<Vec<u8>, ArgusError> {
    let result = encrypt(key, plaintext)?;
    plaintext.zeroize();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_derive_key() {
        let master = b"supersecretmasterkey1234567890ab";
        let k1 = derive_key(master, b"user-encryption");
        let k2 = derive_key(master, b"session-encryption");
        assert_ne!(k1, k2); // Different contexts → different keys
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_key(b"test-master-key-that-is-32bytes!", b"test");
        let plaintext = b"sensitive user data";

        let encrypted = encrypt(&key, plaintext).unwrap();
        assert_ne!(&encrypted[12..], plaintext);

        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = derive_key(b"test-master-key-that-is-32bytes!", b"test");
        let mut encrypted = encrypt(&key, b"hello").unwrap();

        // Flip a bit in the ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;

        assert!(decrypt(&key, &encrypted).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = derive_key(b"test-master-key-that-is-32bytes!", b"key1");
        let key2 = derive_key(b"test-master-key-that-is-32bytes!", b"key2");

        let encrypted = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }
}
