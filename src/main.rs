mod user_authentication;
mod config;
mod utils;
mod enums;
mod dtos;
mod admin_authentication;
mod super_admin_authentication;
mod routes;

use axum::Router;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use crate::config::config::Config;
use crate::config::database::Database;
use crate::user_authentication::controllers::user_authentication_controller::AuthController;
use crate::user_authentication::services::user_authentication_service::AuthService;
use crate::utils::email::EmailService;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv().ok();

    let config = Config::from_env()?;
    let database = Database::new(&config.database_url).await?;
    let email_service = EmailService::new(config.smtp.clone())?;

    let auth_service = Arc::new(AuthService::new(database.clone(), email_service));
    let auth_controller = Arc::new(AuthController::new(auth_service));

    let app = Router::new()
        .merge(routes::user_authentication_route::routes(auth_controller))
        .merge(routes::health::routes())
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("Server running on http://127.0.0.1:3000");

    axum::serve(listener, app).await?;
    Ok(())
}