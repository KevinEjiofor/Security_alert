use axum::{routing::post, Router};
use std::sync::Arc;
use crate::user_authentication::controllers::user_authentication_controller::AuthController;

pub fn routes(auth_controller: Arc<AuthController>) -> Router {
    Router::new()
        .route("/api/auth/register", post({
            let controller = auth_controller.clone();
            move |json| async move { controller.register(json).await }
        }))
        .route("/api/auth/login", post({
            let controller = auth_controller.clone();
            move |json| async move { controller.login(json).await }
        }))
        .route("/api/auth/verify-email", post({
            let controller = auth_controller.clone();
            move |json| async move { controller.verify_email(json).await }
        }))
        .route("/api/auth/resend-verification", post({
            let controller = auth_controller.clone();
            move |json| async move { controller.resend_verification(json).await }
        }))
        .route("/api/auth/forgot-password", post({
            let controller = auth_controller.clone();
            move |json| async move { controller.forgot_password(json).await }
        }))
        .route("/api/auth/reset-password", post({
            let controller = auth_controller.clone();
            move |json| async move { controller.reset_password(json).await }
        }))
        .route("/api/auth/change-password", post({
            let controller = auth_controller.clone();
            move |headers, json| async move { controller.change_password(headers, json).await }
        }))
        .route("/api/auth/refresh", post({
            let controller = auth_controller.clone();
            move |json| async move { controller.refresh_token(json).await }
        }))
}