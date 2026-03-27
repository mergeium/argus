use redis::AsyncCommands;
use redis::aio::ConnectionManager;

use argus_core::error::{ArgusError, ArgusResult};

/// Redis cache client with persistent connection pool (PDF §11.4).
///
/// Uses `ConnectionManager` which maintains a single multiplexed connection
/// with automatic reconnection on failure. This satisfies the "Redis bağlantı
/// havuzu" requirement from the spec.
pub struct RedisCache {
    pool: ConnectionManager,
}

impl RedisCache {
    /// Create a new Redis cache with a persistent connection pool.
    pub async fn new(url: &str) -> ArgusResult<Self> {
        let client = redis::Client::open(url)
            .map_err(|e| ArgusError::Cache(format!("redis connection failed: {e}")))?;
        let pool = ConnectionManager::new(client)
            .await
            .map_err(|e| ArgusError::Cache(format!("redis pool init failed: {e}")))?;
        Ok(Self { pool })
    }

    fn conn(&self) -> ConnectionManager {
        self.pool.clone()
    }

    // ── 1. Session Cache (TTL: 8h) ──

    pub async fn set_session(&self, session_id: &str, data: &str) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("sess:{session_id}");
        conn.set_ex::<_, _, ()>(&key, data, 28800)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    pub async fn get_session(&self, session_id: &str) -> ArgusResult<Option<String>> {
        let mut conn = self.conn();
        let key = format!("sess:{session_id}");
        conn.get(&key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    pub async fn delete_session(&self, session_id: &str) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("sess:{session_id}");
        conn.del::<_, ()>(&key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    // ── 2. Token Blacklist (TTL: token remaining TTL) ──

    pub async fn revoke_token(&self, jti: &str, ttl_secs: u64) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("revoked:jti:{jti}");
        conn.set_ex::<_, _, ()>(&key, "1", ttl_secs)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    pub async fn is_token_revoked(&self, jti: &str) -> ArgusResult<bool> {
        let mut conn = self.conn();
        let key = format!("revoked:jti:{jti}");
        let exists: bool = conn
            .exists(&key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        Ok(exists)
    }

    // ── 3. TOTP Replay Prevention (TTL: 90s) ──

    pub async fn mark_totp_used(&self, user_id: &str, code: &str) -> ArgusResult<bool> {
        let mut conn = self.conn();
        let ts = chrono::Utc::now().timestamp() / 30; // 30-second window
        let key = format!("totp:used:{user_id}:{ts}:{code}");
        let was_set: bool = conn
            .set_nx(&key, "1")
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        if was_set {
            conn.expire::<_, ()>(&key, 90)
                .await
                .map_err(|e| ArgusError::Cache(e.to_string()))?;
        }
        Ok(was_set) // true = first use, false = replay
    }

    // ── 4. Auth Rate Limit (TTL: 300s) ──

    pub async fn increment_auth_failures(&self, ip: &str) -> ArgusResult<i64> {
        let mut conn = self.conn();
        let key = format!("rl:auth:{ip}");
        let count: i64 = conn
            .incr(&key, 1)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        if count == 1 {
            conn.expire::<_, ()>(&key, 300)
                .await
                .map_err(|e| ArgusError::Cache(e.to_string()))?;
        }
        Ok(count)
    }

    // ── 9. ReBAC Check Cache (TTL: 30s) ──

    pub async fn cache_authz_check(
        &self,
        store_id: &str,
        user: &str,
        relation: &str,
        object: &str,
        allowed: bool,
    ) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("authz:{store_id}:{user}:{relation}:{object}");
        conn.set_ex::<_, _, ()>(&key, if allowed { "1" } else { "0" }, 30)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    pub async fn get_authz_check(
        &self,
        store_id: &str,
        user: &str,
        relation: &str,
        object: &str,
    ) -> ArgusResult<Option<bool>> {
        let mut conn = self.conn();
        let key = format!("authz:{store_id}:{user}:{relation}:{object}");
        let val: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        Ok(val.map(|v| v == "1"))
    }

    // ── 5. MFA Rate Limit (TTL: 300s) ──

    pub async fn increment_mfa_attempts(&self, user_id: &str) -> ArgusResult<i64> {
        let mut conn = self.conn();
        let key = format!("rl:mfa:{user_id}");
        let count: i64 = conn
            .incr(&key, 1)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        if count == 1 {
            conn.expire::<_, ()>(&key, 300)
                .await
                .map_err(|e| ArgusError::Cache(e.to_string()))?;
        }
        Ok(count)
    }

    pub async fn get_mfa_attempts(&self, user_id: &str) -> ArgusResult<i64> {
        let mut conn = self.conn();
        let key = format!("rl:mfa:{user_id}");
        let count: Option<i64> = conn
            .get(&key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        Ok(count.unwrap_or(0))
    }

    // ── 6. WebAuthn Challenge (TTL: 5min, single-use GET+DEL) ──

    pub async fn store_webauthn_challenge(
        &self,
        session_token: &str,
        challenge_json: &str,
    ) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("wn:chal:{session_token}");
        conn.set_ex::<_, _, ()>(&key, challenge_json, 300)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    /// Retrieve and delete the WebAuthn challenge (single-use).
    pub async fn consume_webauthn_challenge(
        &self,
        session_token: &str,
    ) -> ArgusResult<Option<String>> {
        let mut conn = self.conn();
        let key = format!("wn:chal:{session_token}");
        // GETDEL is atomic single-use retrieval
        let val: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        Ok(val)
    }

    // ── 7. Email OTP (TTL: 10min) ──

    pub async fn store_email_otp(
        &self,
        user: &str,
        purpose: &str,
        otp_hash: &str,
    ) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("otp:email:{user}:{purpose}");
        // Store hash and reset attempts to 0
        redis::pipe()
            .hset(&key, "hash", otp_hash)
            .hset(&key, "attempts", 0i64)
            .expire(&key, 600)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        Ok(())
    }

    /// Increment the attempt counter and return (stored_hash, attempts).
    pub async fn verify_email_otp(
        &self,
        user: &str,
        purpose: &str,
    ) -> ArgusResult<Option<(String, i64)>> {
        let mut conn = self.conn();
        let key = format!("otp:email:{user}:{purpose}");
        let hash: Option<String> = conn
            .hget(&key, "hash")
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        match hash {
            Some(h) => {
                let attempts: i64 = conn
                    .hincr(&key, "attempts", 1)
                    .await
                    .map_err(|e| ArgusError::Cache(e.to_string()))?;
                Ok(Some((h, attempts)))
            }
            None => Ok(None),
        }
    }

    pub async fn delete_email_otp(&self, user: &str, purpose: &str) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("otp:email:{user}:{purpose}");
        conn.del::<_, ()>(&key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    // ── 8. Risk Score Cache (TTL: 60s) ──

    pub async fn cache_risk_score(
        &self,
        user_id: &str,
        ip_prefix: &str,
        score: f64,
    ) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("risk:{user_id}:{ip_prefix}");
        conn.set_ex::<_, _, ()>(&key, score.to_string(), 60)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    pub async fn get_risk_score(&self, user_id: &str, ip_prefix: &str) -> ArgusResult<Option<f64>> {
        let mut conn = self.conn();
        let key = format!("risk:{user_id}:{ip_prefix}");
        let val: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        Ok(val.and_then(|v| v.parse::<f64>().ok()))
    }

    // ── 10. OAuth State / CSRF (TTL: 10min, single-use) ──

    pub async fn store_oauth_state(&self, state: &str, data_json: &str) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("oauth:state:{state}");
        conn.set_ex::<_, _, ()>(&key, data_json, 600)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    /// Consume the OAuth state (single-use CSRF protection).
    pub async fn consume_oauth_state(&self, state: &str) -> ArgusResult<Option<String>> {
        let mut conn = self.conn();
        let key = format!("oauth:state:{state}");
        let val: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        Ok(val)
    }

    // ── 11. Device Register State (TTL: 5min, single-use) ──

    pub async fn store_device_register_state(
        &self,
        token: &str,
        data_json: &str,
    ) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("dev:reg:{token}");
        conn.set_ex::<_, _, ()>(&key, data_json, 300)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    /// Consume the device registration state (single-use).
    pub async fn consume_device_register_state(&self, token: &str) -> ArgusResult<Option<String>> {
        let mut conn = self.conn();
        let key = format!("dev:reg:{token}");
        let val: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        Ok(val)
    }

    // ── 12. PAR Request (TTL: 90s, RFC 9126) ──

    pub async fn store_par_request(&self, request_uri: &str, data_json: &str) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("par:{request_uri}");
        conn.set_ex::<_, _, ()>(&key, data_json, 90)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    pub async fn get_par_request(&self, request_uri: &str) -> ArgusResult<Option<String>> {
        let mut conn = self.conn();
        let key = format!("par:{request_uri}");
        conn.get(&key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    pub async fn delete_par_request(&self, request_uri: &str) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("par:{request_uri}");
        conn.del::<_, ()>(&key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    // ── 13. LDAP Sync Lock (TTL: 10min, SETNX distributed lock) ──

    /// Try to acquire a distributed lock for LDAP sync.
    /// Returns `true` if the lock was acquired, `false` if already held.
    pub async fn try_acquire_ldap_lock(&self, tenant: &str, connector: &str) -> ArgusResult<bool> {
        let mut conn = self.conn();
        let key = format!("lock:ldap:{tenant}:{connector}");
        let acquired: bool = conn
            .set_nx(&key, "1")
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        if acquired {
            conn.expire::<_, ()>(&key, 600)
                .await
                .map_err(|e| ArgusError::Cache(e.to_string()))?;
        }
        Ok(acquired)
    }

    pub async fn release_ldap_lock(&self, tenant: &str, connector: &str) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("lock:ldap:{tenant}:{connector}");
        conn.del::<_, ()>(&key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    // ── 14. Flow State (TTL: 30min, multi-step auth state) ──

    pub async fn set_flow_state(
        &self,
        flow_session_id: &str,
        field: &str,
        value: &str,
    ) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("flow:{flow_session_id}");
        conn.hset::<_, _, _, ()>(&key, field, value)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        conn.expire::<_, ()>(&key, 1800)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))?;
        Ok(())
    }

    pub async fn get_flow_state(
        &self,
        flow_session_id: &str,
        field: &str,
    ) -> ArgusResult<Option<String>> {
        let mut conn = self.conn();
        let key = format!("flow:{flow_session_id}");
        conn.hget(&key, field)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    pub async fn get_all_flow_state(
        &self,
        flow_session_id: &str,
    ) -> ArgusResult<std::collections::HashMap<String, String>> {
        let mut conn = self.conn();
        let key = format!("flow:{flow_session_id}");
        conn.hgetall(&key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    pub async fn delete_flow_state(&self, flow_session_id: &str) -> ArgusResult<()> {
        let mut conn = self.conn();
        let key = format!("flow:{flow_session_id}");
        conn.del::<_, ()>(&key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    // ── Generic operations ──

    pub async fn set_with_ttl(&self, key: &str, value: &str, ttl_secs: u64) -> ArgusResult<()> {
        let mut conn = self.conn();
        conn.set_ex::<_, _, ()>(key, value, ttl_secs)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    pub async fn get(&self, key: &str) -> ArgusResult<Option<String>> {
        let mut conn = self.conn();
        conn.get(key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }

    pub async fn delete(&self, key: &str) -> ArgusResult<()> {
        let mut conn = self.conn();
        conn.del::<_, ()>(key)
            .await
            .map_err(|e| ArgusError::Cache(e.to_string()))
    }
}
