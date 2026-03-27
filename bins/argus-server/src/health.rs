use axum::{extract::State, http::StatusCode, response::Json};
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_secs: u64,
}

#[derive(Serialize)]
pub struct ReadinessResponse {
    pub status: &'static str,
    pub checks: ReadinessChecks,
}

#[derive(Serialize)]
pub struct ReadinessChecks {
    pub config: &'static str,
    pub crypto: &'static str,
}

pub async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.start_time.elapsed().as_secs(),
    })
}

pub async fn readiness_check(
    State(state): State<AppState>,
) -> (StatusCode, Json<ReadinessResponse>) {
    let km = state.jwt_key_manager.read().await;
    let crypto_ok = !km.jwks().keys.is_empty();

    let status = if crypto_ok { "ready" } else { "not_ready" };
    let code = if crypto_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        code,
        Json(ReadinessResponse {
            status,
            checks: ReadinessChecks {
                config: "ok",
                crypto: if crypto_ok { "ok" } else { "no_signing_key" },
            },
        }),
    )
}

pub async fn liveness_check() -> StatusCode {
    StatusCode::OK
}
