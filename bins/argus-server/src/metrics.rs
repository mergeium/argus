use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Global request counter (monotonically increasing).
static REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
/// Cumulative latency in microseconds (used to compute mean).
static LATENCY_SUM_US: AtomicU64 = AtomicU64::new(0);
/// Count of 2xx responses.
static SUCCESS_COUNT: AtomicU64 = AtomicU64::new(0);
/// Count of 4xx responses.
static CLIENT_ERROR_COUNT: AtomicU64 = AtomicU64::new(0);
/// Count of 5xx responses.
static SERVER_ERROR_COUNT: AtomicU64 = AtomicU64::new(0);

/// Axum middleware that tracks request count and latency.
pub async fn track_metrics(req: Request<Body>, next: Next) -> Response {
    let start = Instant::now();

    let response = next.run(req).await;

    let elapsed_us = start.elapsed().as_micros() as u64;
    REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
    LATENCY_SUM_US.fetch_add(elapsed_us, Ordering::Relaxed);

    let status = response.status().as_u16();
    match status {
        200..=299 => {
            SUCCESS_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        400..=499 => {
            CLIENT_ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        500..=599 => {
            SERVER_ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }

    response
}

/// Prometheus-compatible text format metrics endpoint.
pub async fn metrics_endpoint() -> impl IntoResponse {
    let total = REQUEST_COUNT.load(Ordering::Relaxed);
    let latency_us = LATENCY_SUM_US.load(Ordering::Relaxed);
    let success = SUCCESS_COUNT.load(Ordering::Relaxed);
    let client_err = CLIENT_ERROR_COUNT.load(Ordering::Relaxed);
    let server_err = SERVER_ERROR_COUNT.load(Ordering::Relaxed);

    let avg_latency_ms = if total > 0 {
        (latency_us as f64 / total as f64) / 1000.0
    } else {
        0.0
    };

    let body = format!(
        "# HELP argus_http_requests_total Total number of HTTP requests.\n\
         # TYPE argus_http_requests_total counter\n\
         argus_http_requests_total {total}\n\
         \n\
         # HELP argus_http_requests_success_total Total 2xx responses.\n\
         # TYPE argus_http_requests_success_total counter\n\
         argus_http_requests_success_total {success}\n\
         \n\
         # HELP argus_http_requests_client_error_total Total 4xx responses.\n\
         # TYPE argus_http_requests_client_error_total counter\n\
         argus_http_requests_client_error_total {client_err}\n\
         \n\
         # HELP argus_http_requests_server_error_total Total 5xx responses.\n\
         # TYPE argus_http_requests_server_error_total counter\n\
         argus_http_requests_server_error_total {server_err}\n\
         \n\
         # HELP argus_http_request_latency_sum_microseconds Cumulative request latency in microseconds.\n\
         # TYPE argus_http_request_latency_sum_microseconds counter\n\
         argus_http_request_latency_sum_microseconds {latency_us}\n\
         \n\
         # HELP argus_http_request_latency_avg_ms Average request latency in milliseconds.\n\
         # TYPE argus_http_request_latency_avg_ms gauge\n\
         argus_http_request_latency_avg_ms {avg_latency_ms:.3}\n",
    );

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}
