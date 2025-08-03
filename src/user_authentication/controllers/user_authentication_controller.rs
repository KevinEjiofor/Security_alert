use crate::domain::dtos::auth_dto::*;
use crate::domain::errors::AuthError;
use crate::services::user_authentication::AuthService;
use axum::{
    extract::{Json, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct AuthController {
    auth_service: Arc<AuthService>,
}

impl AuthController {
    pub fn new(auth_service: Arc<AuthService>) -> Self {
        Self { auth_service }
    }

    pub async fn register(
        &self,
        Json(request): Json<RegisterRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.register(request).await?;
        Ok((StatusCode::CREATED, Json(response)))
    }

    pub async fn login(
        &self,
        Json(request): Json<LoginRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.login(request).await?;
        Ok((StatusCode::OK, Json(response)))
    }

    pub async fn verify_email(
        &self,
        Json(request): Json<VerifyEmailRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.verify_email(request).await?;
        Ok((StatusCode::OK, Json(response)))
    }

    pub async fn resend_verification(
        &self,
        Json(request): Json<ResendVerificationRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.resend_verification(request).await?;
        Ok((StatusCode::OK, Json(response)))
    }

    pub async fn forgot_password(
        &self,
        Json(request): Json<ForgotPasswordRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.forgot_password(request).await?;
        Ok((StatusCode::OK, Json(response)))
    }

    pub async fn reset_password(
        &self,
        Json(request): Json<ResetPasswordRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.reset_password(request).await?;
        Ok((StatusCode::OK, Json(response)))
    }

    pub async fn change_password(
        &self,
        headers: HeaderMap,
        Json(request): Json<ChangePasswordRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let user_id = self.extract_user_id_from_token(&headers).await?;
        let response = self.auth_service.change_password(user_id, request).await?;
        Ok((StatusCode::OK, Json(response)))
    }

    pub async fn refresh_token(
        &self,
        Json(request): Json<RefreshTokenRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.refresh_token(&request.refresh_token).await?;
        Ok((StatusCode::OK, Json(response)))
    }

    async fn extract_user_id_from_token(&self, headers: &HeaderMap) -> Result<Uuid, AuthError> {
        let auth_header = headers
            .get("authorization")
            .ok_or(AuthError::InvalidToken)?
            .to_str()
            .map_err(|_| AuthError::InvalidToken)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidToken)?;

        let claims = self.auth_service.decode_jwt_token(token)?;
        let user_id: Uuid = claims.sub.parse()
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(user_id)
    }
}
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}