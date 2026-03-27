use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use ring::signature::KeyPair;

use argus_core::error::ArgusError;
use argus_core::id::KeyId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub jti: String,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,
    pub iss: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub tenant_id: String,
    pub session_id: String,
}

/// JWT Key Manager that handles Ed25519 key pairs for signing and verification.
/// Uses ring internally (same as jsonwebtoken) for compatibility.
pub struct JwtKeyManager {
    active: JwtKeyEntry,
    retired: Vec<JwtKeyEntry>,
}

struct JwtKeyEntry {
    key_id: KeyId,
    public_key_bytes: Vec<u8>,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtKeyEntry {
    fn generate() -> Result<Self, ArgusError> {
        let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|e| ArgusError::CryptoError(format!("keygen: {e}")))?;

        let pkcs8_bytes = doc.as_ref().to_vec();
        let ring_kp = ring::signature::Ed25519KeyPair::from_pkcs8(&pkcs8_bytes)
            .map_err(|e| ArgusError::CryptoError(format!("parse: {e}")))?;

        let public_key_bytes = ring_kp.public_key().as_ref().to_vec();

        Ok(Self {
            key_id: KeyId::new(),
            encoding_key: EncodingKey::from_ed_der(&pkcs8_bytes),
            decoding_key: DecodingKey::from_ed_der(&public_key_bytes),
            public_key_bytes,
        })
    }

    fn to_jwk(&self) -> crate::keys::JsonWebKey {
        use base64::Engine;
        crate::keys::JsonWebKey {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            kid: self.key_id.to_string(),
            x: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.public_key_bytes),
            alg: "EdDSA".into(),
            use_: "sig".into(),
        }
    }
}

impl JwtKeyManager {
    pub fn new() -> Result<Self, ArgusError> {
        Ok(Self {
            active: JwtKeyEntry::generate()?,
            retired: Vec::new(),
        })
    }

    pub fn active_key_id(&self) -> &KeyId {
        &self.active.key_id
    }

    /// Sign a JWT with the active key.
    pub fn sign<T: Serialize>(&self, claims: &T) -> Result<String, ArgusError> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.active.key_id.to_string());

        encode(&header, claims, &self.active.encoding_key)
            .map_err(|e| ArgusError::CryptoError(format!("JWT sign: {e}")))
    }

    /// Verify and decode a JWT. Tries active key first, then retired keys.
    pub fn verify<T: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
        issuer: &str,
    ) -> Result<T, ArgusError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[issuer]);
        validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);

        // Try active key
        match decode::<T>(token, &self.active.decoding_key, &validation) {
            Ok(data) => return Ok(data.claims),
            Err(e) if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::InvalidSignature) => {
                // Try retired keys
            }
            Err(e) => return Err(map_jwt_error(e)),
        }

        // Try retired keys
        for entry in &self.retired {
            match decode::<T>(token, &entry.decoding_key, &validation) {
                Ok(data) => return Ok(data.claims),
                Err(e) if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::InvalidSignature) => {
                    continue;
                }
                Err(e) => return Err(map_jwt_error(e)),
            }
        }

        Err(ArgusError::InvalidToken("no matching key found".into()))
    }

    /// Rotate: current key becomes retired, new key generated.
    pub fn rotate(&mut self) -> Result<(), ArgusError> {
        let new_active = JwtKeyEntry::generate()?;
        let old = std::mem::replace(&mut self.active, new_active);
        self.retired.push(old);
        Ok(())
    }

    /// Get JWKS document (all public keys).
    pub fn jwks(&self) -> crate::keys::JsonWebKeySet {
        let mut keys = vec![self.active.to_jwk()];
        for entry in &self.retired {
            keys.push(entry.to_jwk());
        }
        crate::keys::JsonWebKeySet { keys }
    }
}

impl Default for JwtKeyManager {
    fn default() -> Self {
        Self::new().expect("key generation should not fail")
    }
}

fn map_jwt_error(e: jsonwebtoken::errors::Error) -> ArgusError {
    match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => ArgusError::TokenExpired,
        _ => ArgusError::InvalidToken(format!("{e}")),
    }
}

/// Build a standard access token claims struct.
pub fn build_access_token_claims(
    subject: &str,
    issuer: &str,
    tenant_id: &str,
    ttl_secs: u64,
) -> AccessTokenClaims {
    let now = Utc::now().timestamp();
    AccessTokenClaims {
        sub: subject.to_string(),
        iss: issuer.to_string(),
        aud: vec![issuer.to_string()],
        exp: now + ttl_secs as i64,
        iat: now,
        nbf: now,
        jti: uuid::Uuid::now_v7().to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: None,
        scopes: vec![],
        email: None,
        session_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_access_token() {
        let km = JwtKeyManager::new().unwrap();
        let claims =
            build_access_token_claims("usr_test123", "https://auth.argus.dev", "tnt_abc", 3600);

        let token = km.sign(&claims).unwrap();
        assert!(!token.is_empty());

        let decoded: AccessTokenClaims = km.verify(&token, "https://auth.argus.dev").unwrap();

        assert_eq!(decoded.sub, "usr_test123");
        assert_eq!(decoded.tenant_id, "tnt_abc");
    }

    #[test]
    fn expired_token_rejected() {
        let km = JwtKeyManager::new().unwrap();
        let mut claims =
            build_access_token_claims("usr_test", "https://auth.argus.dev", "tnt_abc", 0);
        claims.exp = Utc::now().timestamp() - 100;

        let token = km.sign(&claims).unwrap();
        let result: Result<AccessTokenClaims, _> = km.verify(&token, "https://auth.argus.dev");

        assert!(matches!(result, Err(ArgusError::TokenExpired)));
    }

    #[test]
    fn key_rotation_still_verifies() {
        let mut km = JwtKeyManager::new().unwrap();
        let claims =
            build_access_token_claims("usr_test", "https://auth.argus.dev", "tnt_abc", 3600);

        let token_before = km.sign(&claims).unwrap();
        km.rotate().unwrap();
        let token_after = km.sign(&claims).unwrap();

        // Both tokens should verify
        let _: AccessTokenClaims = km.verify(&token_before, "https://auth.argus.dev").unwrap();
        let _: AccessTokenClaims = km.verify(&token_after, "https://auth.argus.dev").unwrap();

        assert_eq!(km.jwks().keys.len(), 2);
    }
}
