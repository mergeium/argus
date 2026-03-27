use std::sync::Arc;
use tokio::sync::RwLock;

use argus_core::config::ArgusConfig;
use argus_crypto::jwt::JwtKeyManager;

#[derive(Clone)]
#[allow(dead_code)] // config will be used in Phase 1 for DB/Redis/NATS connections
pub struct AppState {
    pub config: ArgusConfig,
    pub jwt_key_manager: Arc<RwLock<JwtKeyManager>>,
    pub start_time: std::time::Instant,
}

impl AppState {
    pub fn new(config: ArgusConfig) -> Self {
        Self {
            config,
            jwt_key_manager: Arc::new(RwLock::new(JwtKeyManager::default())),
            start_time: std::time::Instant::now(),
        }
    }
}
