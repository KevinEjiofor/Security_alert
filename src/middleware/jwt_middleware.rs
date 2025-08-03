use crate::utils::auth_error::AuthError;
use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{decode, DecodingKey, Validation};

pub async fn validate_jwt_format(
    req: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let headers = req.headers();

    
    if let Some(auth_header) = headers.get("authorization") {
        let auth_str = auth_header.to_str().map_err(|_| AuthError::InvalidToken)?;

        if !auth_str.starts_with("Bearer ") {
            return Err(AuthError::InvalidToken);
        }

        let token = auth_str.strip_prefix("Bearer ").unwrap();

        // Basic JWT format validation (just check it has 3 parts)
        if token.split('.').count() != 3 {
            return Err(AuthError::InvalidToken);
        }
    }

    Ok(next.run(req).await)
}