use axum::{
    middleware,
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    request_id::{MakeRequestUuid, SetRequestIdLayer},
};

use crate::routes::{auth_routes, admin_routes, super_admin_routes};
use crate::user_authentication::services::user_authentication_service::AuthService;
use crate::middleware::rate_limiter::RateLimiter;
use crate::middleware::{
    security_middleware,
    rate_limit_middleware,
};

pub async fn create_app(auth_service: Arc<AuthService>) -> anyhow::Result<Router> {
    let rate_limiter = Arc::new(RateLimiter::new());


    let auth_routes = auth_routes::create_auth_routes(auth_service.clone(), rate_limiter.clone());
    let admin_routes = admin_routes::create_admin_routes(auth_service.clone());
    let super_admin_routes = super_admin_routes::create_super_admin_routes(auth_service.clone());


    let health_routes = Router::new()
        .route("/health", get(health_check))
        .route("/api/health", get(health_check));


    let app = Router::new()
        .merge(auth_routes)
        .merge(admin_routes)
        .merge(super_admin_routes)
        .merge(health_routes)
  
        .layer(middleware::from_fn(security_middleware::security_logging))
        .layer(TraceLayer::new_for_http())
        .layer(SetRequestIdLayer::new(
            tower_http::request_id::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(CorsLayer::permissive());

    Ok(app)
}

async fn health_check() -> &'static str {
    "OK"
}
