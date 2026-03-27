use axum::{extract::State, response::Json};

use argus_crypto::keys::JsonWebKeySet;

use crate::state::AppState;

pub async fn jwks_endpoint(State(state): State<AppState>) -> Json<JsonWebKeySet> {
    let km = state.jwt_key_manager.read().await;
    Json(km.jwks())
}
