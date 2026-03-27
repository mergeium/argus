use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use tokio::signal;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use argus_core::config::ArgusConfig;

mod health;
mod jwks;
mod metrics;
mod state;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "argus_server=debug,argus_core=debug,argus_crypto=debug,argus_store=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = ArgusConfig::load().unwrap_or_else(|e| {
        tracing::warn!("failed to load config file, using defaults: {e}");
        ArgusConfig::default()
    });

    tracing::info!(
        host = %config.server.host,
        port = %config.server.port,
        tls = config.server.tls_cert.is_some(),
        "starting argus IAM server"
    );

    // Build application state
    let app_state = state::AppState::new(config.clone());

    // Build router
    let app = build_router(app_state, &config);

    // Bind and serve
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("invalid bind address");

    // Conditional TLS: if tls_cert and tls_key are both set, use rustls; otherwise plain TCP
    match (&config.server.tls_cert, &config.server.tls_key) {
        (Some(cert_path), Some(key_path)) => {
            tracing::info!("TLS enabled, loading cert={cert_path} key={key_path}");
            let tls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
                    .await
                    .expect("failed to load TLS certificate/key");

            tracing::info!("listening on {addr} (TLS)");
            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await
                .unwrap();
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            tracing::info!("listening on {addr}");

            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
                .unwrap();
        }
    }

    tracing::info!("server shutdown complete");
}

fn build_router(state: state::AppState, config: &ArgusConfig) -> Router {
    Router::new()
        // Health endpoints
        .route("/health", axum::routing::get(health::health_check))
        .route("/health/ready", axum::routing::get(health::readiness_check))
        .route("/health/live", axum::routing::get(health::liveness_check))
        // JWKS endpoint
        .route("/.well-known/jwks.json", axum::routing::get(jwks::jwks_endpoint))
        // Prometheus-compatible metrics endpoint
        .route("/metrics", axum::routing::get(metrics::metrics_endpoint))
        // Middleware stack
        .layer(axum::middleware::from_fn(metrics::track_metrics))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .layer(TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, Duration::from_secs(config.server.request_timeout_secs)))
        .with_state(state)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received, starting graceful shutdown");
}
