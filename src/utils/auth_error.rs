use axum::{
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde_json::json;
use thiserror::Error;
use validator::ValidationErrors;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),


    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Phone number already exists")]
    PhoneAlreadyExists,

    #[error("User not found")]
    UserNotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Account inactive")]
    AccountInactive,

    #[error("Email not verified")]
    EmailNotVerified,

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("Email service error: {0}")]
    EmailService(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            AuthError::Database(ref e) => {
                tracing::error!("Database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AuthError::UserAlreadyExists => (StatusCode::CONFLICT, "User with this email already exists"),
            AuthError::PhoneAlreadyExists => (StatusCode::CONFLICT, "User with this phone number already exists"),
            AuthError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid email or password"),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid or expired token"),
            AuthError::AccountInactive => (StatusCode::FORBIDDEN, "Account is inactive"),
            AuthError::EmailNotVerified => (StatusCode::FORBIDDEN, "Email not verified"),
            AuthError::Validation(ref e) => (StatusCode::BAD_REQUEST, e.as_str()),
            AuthError::Jwt(ref e) => {
                tracing::error!("JWT error: {:?}", e);
                (StatusCode::UNAUTHORIZED, "Invalid token")
            }
            AuthError::Internal(ref e) => {
                tracing::error!("Internal error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AuthError::EmailService(ref e) => {
                tracing::error!("Email service error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send email")
            }
        };

        let body = Json(json!({
            "success": false,
            "error": error_message
        }));

        (status, body).into_response()
    }
}

impl From<ValidationErrors> for AuthError {
    fn from(errors: ValidationErrors) -> Self {
        let error_message = errors
            .field_errors()
            .into_iter()
            .map(|(field, errors)| {
                let messages: Vec<String> = errors
                    .iter()
                    .filter_map(|error| error.message.as_ref().map(|msg| msg.to_string()))
                    .collect();
                format!("{}: {}", field, messages.join(", "))
            })
            .collect::<Vec<_>>()
            .join("; ");

        AuthError::Validation(error_message)
    }
}