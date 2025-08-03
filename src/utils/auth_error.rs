use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Authentication failed")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Email not verified")]
    EmailNotVerified,

    #[error("Invalid or expired token")]
    InvalidToken,

    #[error("Account is inactive")]
    AccountInactive,

    #[error("Email service error: {0}")]
    EmailService(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Internal server error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::UserNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AuthError::UserAlreadyExists => (StatusCode::CONFLICT, self.to_string()),
            AuthError::EmailNotVerified => (StatusCode::FORBIDDEN, self.to_string()),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::AccountInactive => (StatusCode::FORBIDDEN, self.to_string()),
            AuthError::EmailService(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Email service unavailable".to_string()),
            AuthError::Database(_) | AuthError::Jwt(_) | AuthError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        let body = Json(json!({
            "error": message
        }));

        (status, body).into_response()
    }
}