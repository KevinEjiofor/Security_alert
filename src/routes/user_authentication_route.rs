use axum::{routing::{get, post}, Router};
use std::sync::Arc;
use crate::user_authentication::controllers::user_authentication_controller::AuthController;

pub fn routes(auth_controller: Arc<AuthController>) -> Router {
    Router::new()
        // Authentication endpoints
        .route("/api/auth/register", post({
            let controller = auth_controller.clone();
            move |json| async move { controller.register(json).await }
        }))
        .route("/api/auth/login", post({
            let controller = auth_controller.clone();
            move |json| async move { controller.login(json).await }
        }))
        .route("/api/auth/logout", post({
            let controller = auth_controller.clone();
            move |headers| async move { controller.logout(headers).await }
        }))

        // Email verification endpoints
        .route("/api/auth/verify-email", post({
            let controller = auth_controller.clone();
            move |json| async move { controller.verify_email(json).await }
        }))
        .route("/api/auth/resend-verification", post({
            let controller = auth_controller.clone();
            move |json| async move { controller.resend_verification(json).await }
        }))

        // Password management endpoints
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

        // Token management endpoints
        .route("/api/auth/refresh", post({
            let controller = auth_controller.clone();
            move |json| async move { controller.refresh_token(json).await }
        }))
        .route("/api/auth/validate-token", get({
            let controller = auth_controller.clone();
            move |headers| async move { controller.validate_token(headers).await }
        }))
        .route("/api/auth/check-token-expiry", get({
            let controller = auth_controller.clone();
            move |headers| async move { controller.check_token_expiry(headers).await }
        }))

        // User profile management endpoints
        .route("/api/user/profile", get({
            let controller = auth_controller.clone();
            move |headers| async move { controller.get_profile(headers).await }
        }))
        .route("/api/user/profile", post({
            let controller = auth_controller.clone();
            move |headers, json| async move { controller.update_profile(headers, json).await }
        }))
        .route("/api/user/deactivate", post({
            let controller = auth_controller.clone();
            move |headers| async move { controller.deactivate_account(headers).await }
        }))
}