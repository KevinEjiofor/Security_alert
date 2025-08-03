use axum::{
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;
use tracing::{info, warn};

pub async fn security_logging(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let user_agent = req.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    // Log potentially suspicious activities
    if path.contains("admin") || path.contains("super-admin") {
        info!(
            "Admin endpoint access: {} {} from {} - User-Agent: {}",
            method, path, addr.ip(), user_agent
        );
    }

    // Log authentication attempts
    if path.contains("login") || path.contains("register") {
        info!(
            "Auth attempt: {} {} from {} - User-Agent: {}",
            method, path, addr.ip(), user_agent
        );
    }

    let response = next.run(req).await;

    // Log failed authentication attempts
    if response.status().is_client_error() && path.contains("auth") {
        warn!(
            "Failed auth attempt: {} {} from {} - Status: {}",
            method, path, addr.ip(), response.status()
        );
    }

    response
}