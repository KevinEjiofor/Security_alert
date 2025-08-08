use crate::{
    dtos::user_authentication_dto::*,
    user_authentication::services::user_authentication_service::AuthService,
    utils::{api_response::ApiResponse, auth_error::AuthError},
};
use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
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

    // Authentication Endpoints
    pub async fn register(
        &self,
        Json(request): Json<RegisterRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.register(request).await?;
        Ok(ApiResponse::success_with_message(
            response,
            "User registered successfully".to_string(),
        )
            .to_response(StatusCode::CREATED))
    }

    pub async fn login(
        &self,
        Json(request): Json<LoginRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.login(request).await?;
        Ok(ApiResponse::success_with_message(response, "Login successful".to_string())
            .to_response(StatusCode::OK))
    }

    // Verification Endpoints
    pub async fn verify_email(
        &self,
        Json(request): Json<VerifyEmailRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.verify_email(request).await?;
        Ok(ApiResponse::success_with_message(
            response,
            "Email verified successfully".to_string(),
        )
            .to_response(StatusCode::OK))
    }

    pub async fn resend_verification(
        &self,
        Json(request): Json<ResendVerificationRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.resend_verification(request).await?;
        let message = if response.message == "Email is already verified." {
            response.message.clone()
        } else {
            "Verification email sent successfully".to_string()
        };
        Ok(ApiResponse::success_with_message(response, message).to_response(StatusCode::OK))
    }

    // Password Management
    pub async fn forgot_password(
        &self,
        Json(request): Json<ForgotPasswordRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.forgot_password(request).await?;
        Ok(ApiResponse::success_with_message(
            response,
            "Password reset email sent successfully".to_string(),
        )
            .to_response(StatusCode::OK))
    }

    pub async fn reset_password(
        &self,
        Json(request): Json<ResetPasswordRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.reset_password(request).await?;
        Ok(ApiResponse::success_with_message(
            response,
            "Password reset successfully".to_string(),
        )
            .to_response(StatusCode::OK))
    }

    pub async fn change_password(
        &self,
        headers: HeaderMap,
        Json(request): Json<ChangePasswordRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let user_id = self.extract_user_id_from_headers(&headers).await?;
        let response = self.auth_service.change_password(user_id, request).await?;
        Ok(ApiResponse::success_with_message(
            response,
            "Password changed successfully".to_string(),
        )
            .to_response(StatusCode::OK))
    }

    // Token Management
    pub async fn refresh_token(
        &self,
        Json(request): Json<RefreshTokenRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let response = self.auth_service.refresh_token(&request.refresh_token).await?;
        Ok(ApiResponse::success_with_message(
            response,
            "Token refreshed successfully".to_string(),
        )
            .to_response(StatusCode::OK))
    }

    pub async fn validate_token(
        &self,
        headers: HeaderMap,
    ) -> Result<impl IntoResponse, AuthError> {
        let token = self.extract_token_from_headers(&headers)?;
        let claims = self.auth_service.validate_token(token).await?;

        let response = TokenValidationResponse {
            valid: true,
            user_id: claims.sub,
            email: claims.email,
            role: claims.role,
            expires_at: claims.exp,
        };

        Ok(ApiResponse::success_with_message(response, "Token is valid".to_string())
            .to_response(StatusCode::OK))
    }

    pub async fn check_token_expiry(
        &self,
        headers: HeaderMap,
    ) -> Result<impl IntoResponse, AuthError> {
        let token = self.extract_token_from_headers(&headers)?;
        let is_valid = self.auth_service.check_token_expiry(token).await?;

        let response = TokenExpiryResponse {
            is_expired: !is_valid,
            is_valid,
        };

        let message = if is_valid {
            "Token is still valid"
        } else {
            "Token has expired"
        };

        Ok(ApiResponse::success_with_message(response, message.to_string())
            .to_response(StatusCode::OK))
    }

    // User Management
    pub async fn logout(
        &self,
        headers: HeaderMap,
    ) -> Result<impl IntoResponse, AuthError> {
        let token = self.extract_token_from_headers(&headers)?;
        let claims = self.auth_service.validate_token(token).await?;
        let user_id: Uuid = claims.sub.parse().map_err(|_| AuthError::InvalidToken)?;

        let response = self.auth_service.logout(user_id, token).await?;
        Ok(ApiResponse::success_with_message(
            response,
            "Logged out successfully".to_string(),
        )
            .to_response(StatusCode::OK))
    }

    pub async fn get_profile(
        &self,
        headers: HeaderMap,
    ) -> Result<impl IntoResponse, AuthError> {
        let user_id = self.extract_user_id_from_headers(&headers).await?;
        let user = self.auth_service.get_user_profile(user_id).await?;
        let response = UserProfileResponse::from_user(user);
        Ok(ApiResponse::success_with_message(
            response,
            "Profile retrieved successfully".to_string(),
        )
            .to_response(StatusCode::OK))
    }

    pub async fn update_profile(
        &self,
        headers: HeaderMap,
        Json(request): Json<UpdateProfileRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let user_id = self.extract_user_id_from_headers(&headers).await?;
        let response = self.auth_service.update_user_profile(user_id, request).await?;
        Ok(ApiResponse::success_with_message(
            response,
            "Profile updated successfully".to_string(),
        )
            .to_response(StatusCode::OK))
    }

    pub async fn deactivate_account(
        &self,
        headers: HeaderMap,
    ) -> Result<impl IntoResponse, AuthError> {
        let user_id = self.extract_user_id_from_headers(&headers).await?;
        let response = self.auth_service.deactivate_account(user_id).await?;
        Ok(ApiResponse::success_with_message(
            response,
            "Account deactivated successfully".to_string(),
        )
            .to_response(StatusCode::OK))
    }

    async fn extract_user_id_from_headers(&self, headers: &HeaderMap) -> Result<Uuid, AuthError> {
        let token = self.extract_token_from_headers(headers)?;
        let claims = self.auth_service.validate_token(token).await?;
        claims.sub.parse().map_err(|_| AuthError::InvalidToken)
    }

    fn extract_token_from_headers<'a>(&self, headers: &'a HeaderMap) -> Result<&'a str, AuthError> {
        headers
            .get("authorization")
            .ok_or(AuthError::InvalidToken)?
            .to_str()
            .map_err(|_| AuthError::InvalidToken)?
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidToken)
    }
}