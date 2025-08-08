use crate::enums::role::Role;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::{Validate, ValidationError};
use regex::Regex;
use crate::user_authentication::data::models::user::User;

fn validate_phone_number(phone: &str) -> Result<(), ValidationError> {
    let phone_regex = Regex::new(r"^\+?[1-9]\d{1,14}$").unwrap();

    if phone_regex.is_match(phone) {
        Ok(())
    } else {
        let mut err = ValidationError::new("phone_number");
        err.message = Some("Invalid phone number format".into());
        Err(err)
    }
}
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
    #[validate(length(min = 1, message = "First name is required"))]
    pub first_name: String,
    #[validate(length(min = 1, message = "Last name is required"))]
    pub last_name: String,
    #[validate(custom(function = "validate_phone_number"))]
    pub phone_number: String,
    pub role: Option<Role>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyEmailRequest {
    #[validate(length(min = 6, max = 6, message = "Token must be 6 digits"))]
    pub token: String,
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ResendVerificationRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ForgotPasswordRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ResetPasswordRequest {
    #[validate(length(min = 6, max = 6, message = "Token must be 6 digits"))]
    pub token: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 1, message = "Current password is required"))]
    pub current_password: String,
    #[validate(length(min = 8, message = "New password must be at least 8 characters"))]
    pub new_password: String,
}


#[derive(Debug, Deserialize, Validate)]
pub struct UpdateProfileRequest {
    #[validate(length(min = 1, message = "First name cannot be empty"))]
    pub first_name: Option<String>,
    #[validate(length(min = 1, message = "Last name cannot be empty"))]
    pub last_name: Option<String>,
    #[validate(custom(function = "validate_phone_number"))]
    pub phone_number: Option<String>,
    pub profile_picture_url: Option<String>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    #[serde(with = "uuid::serde::simple")]
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub phone_number: String,
    pub role: Role,
    pub is_email_verified: bool,
    pub is_active: bool,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, serde::Serialize)]
pub struct UserProfileResponse {
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub phone_number: String,
    pub role: crate::enums::role::Role,
    pub is_email_verified: bool,
    pub profile_picture_url: Option<String>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub two_factor_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
}
// In your dtos/user_authentication_dto.rs
impl UserProfileResponse {
    pub fn from_user(user: User) -> Self {
        UserProfileResponse {
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            phone_number: user.phone_number,
            role: user.role,
            is_email_verified: user.is_email_verified,
            profile_picture_url: user.profile_picture_url,
            timezone: user.timezone,
            locale: user.locale,
            two_factor_enabled: user.two_factor_enabled,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login: user.last_login,
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct TokenValidationResponse {
    pub valid: bool,
    pub user_id: String,
    pub email: String,
    pub role: crate::enums::role::Role,
    pub expires_at: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct TokenExpiryResponse {
    pub is_expired: bool,
    pub is_valid: bool,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}