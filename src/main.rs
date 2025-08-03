mod user_authentication;
mod config;
mod utils;


mod enums;
mod dtos;
mod admin_authentication;
mod super_admin_authentication;
mod routes;
mod middleware;

use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber;


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::init();
    dotenv::dotenv().ok();

    let config = Config::from_env()?;
    let database = Database::new(&config.database_url).await?;
    let email_service = EmailService::new(config.smtp.clone())?;

    let auth_service = Arc::new(AuthService::new(database.clone(), email_service));
    let auth_controller = AuthController::new(auth_service);

    let app = Router::new()
        .route("/api/auth/register", post(auth_controller.register))
        .route("/api/auth/login", post(auth_controller.login))
        .route("/api/auth/verify-email", post(auth_controller.verify_email))
        .route("/api/auth/resend-verification", post(auth_controller.resend_verification))
        .route("/api/auth/forgot-password", post(auth_controller.forgot_password))
        .route("/api/auth/reset-password", post(auth_controller.reset_password))
        .route("/api/auth/change-password", post(auth_controller.change_password))
        .route("/api/auth/refresh", post(auth_controller.refresh_token))
        .route("/health", get(|| async { "OK" }))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("Server running on http://127.0.0.1:3000");

    axum::serve(listener, app).await?;
    Ok(())
}

fn main() {}