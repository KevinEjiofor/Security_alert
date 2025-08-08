use crate::{
    config::{config::Config, database::Database},
    dtos::user_authentication_dto::*,
    enums::role::Role,
    user_authentication::{
        data::{
            models::user::{EmailVerificationToken, PasswordResetToken, User},
            repositories::user_repository::UserRepository,
        },
    },
    utils::{auth_error::AuthError, email::EmailService, crypto_service::CryptoService , crypto_service::Claims},
};
use chrono::{Duration, Utc};
use uuid::Uuid;
use validator::Validate;

pub struct AuthService {
    user_repo: UserRepository,
    email_service: EmailService,
    crypto_service: CryptoService,
}

impl AuthService {
    pub fn new(db: Database, email_service: EmailService) -> Self {
        let config = Config::from_env().expect("Failed to load config");
        let user_repo = UserRepository::new(db);
        let crypto_service = CryptoService::new(config);

        Self {
            user_repo,
            email_service,
            crypto_service,
        }
    }

    // Authentication Methods
    // ======================

    pub async fn register(&self, request: RegisterRequest) -> Result<MessageResponse, AuthError> {
        request.validate().map_err(|e| AuthError::Validation(e.to_string()))?;

        if self.user_repo.find_by_email(&request.email).await?.is_some() {
            return Err(AuthError::UserAlreadyExists);
        }

        if self.user_repo.find_by_phone(&request.phone_number).await?.is_some() {
            return Err(AuthError::PhoneAlreadyExists);
        }

        let password_hash = self.crypto_service.hash_password(&request.password)?;

        let user = User {
            id: Uuid::new_v4(),
            email: request.email.clone(),
            password_hash,
            first_name: request.first_name.clone(),
            last_name: request.last_name,
            phone_number: request.phone_number,
            role: request.role.unwrap_or(Role::User),
            is_email_verified: false,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
            profile_picture_url: None,
            timezone: None,
            locale: None,
            two_factor_enabled: false,
            two_factor_secret: None,
        };

        let created_user = self.user_repo.create_user(&user).await?;

        let token = self.crypto_service.generate_6_digit_token();
        let token_hash = self.crypto_service.hash_token(&token);
        self.create_and_send_verification_token(&created_user, &token, &token_hash).await?;

        Ok(MessageResponse {
            message: "Registration successful. Please check your email for verification code.".to_string(),
        })
    }

    pub async fn login(&self, request: LoginRequest) -> Result<AuthResponse, AuthError> {
        request.validate().map_err(|e| AuthError::Validation(e.to_string()))?;

        let user = self.user_repo.find_by_email(&request.email).await?
            .ok_or(AuthError::InvalidCredentials)?;

        if !self.crypto_service.verify_password(&request.password, &user.password_hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        if !user.is_active {
            return Err(AuthError::AccountInactive);
        }

        if !user.is_email_verified {
            return Err(AuthError::EmailNotVerified);
        }

        self.user_repo.update_last_login(user.id).await?;

        let access_token = self.generate_jwt_token(&user)?;
        let refresh_token = self.generate_refresh_token(&user)?;

        Ok(AuthResponse {
            access_token,
            refresh_token,
        })
    }

    // Token Verification Methods
    // =========================

    pub async fn verify_email(&self, request: VerifyEmailRequest) -> Result<MessageResponse, AuthError> {
        request.validate().map_err(|e| AuthError::Validation(e.to_string()))?;

        let token_hash = self.crypto_service.hash_token(&request.token);

        let token = self.user_repo
            .find_email_verification_token_by_hash(&request.email, &token_hash)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        self.user_repo.update_email_verification(token.user_id, true).await?;
        self.user_repo.delete_email_verification_tokens(token.user_id).await?;

        Ok(MessageResponse {
            message: "Email verified successfully.".to_string(),
        })
    }

    pub async fn resend_verification(&self, request: ResendVerificationRequest) -> Result<MessageResponse, AuthError> {
        request.validate().map_err(|e| AuthError::Validation(e.to_string()))?;

        let user = self.user_repo.find_by_email(&request.email).await?
            .ok_or(AuthError::UserNotFound)?;

        if user.is_email_verified {
            return Ok(MessageResponse {
                message: "Email is already verified.".to_string(),
            });
        }

        self.user_repo.delete_email_verification_tokens(user.id).await?;

        let token = self.crypto_service.generate_6_digit_token();
        let token_hash = self.crypto_service.hash_token(&token);
        self.create_and_send_verification_token(&user, &token, &token_hash).await?;

        Ok(MessageResponse {
            message: "Verification code sent to your email.".to_string(),
        })
    }

    // Password Management
    // ==================

    pub async fn forgot_password(&self, request: ForgotPasswordRequest) -> Result<MessageResponse, AuthError> {
        request.validate().map_err(|e| AuthError::Validation(e.to_string()))?;

        if let Some(user) = self.user_repo.find_by_email(&request.email).await? {
            let token = self.crypto_service.generate_6_digit_token();
            let token_hash = self.crypto_service.hash_token(&token);
            self.create_and_send_password_reset_token(&user, &token, &token_hash).await?;
        }

        Ok(MessageResponse {
            message: "A password reset code has been sent to your email.".to_string(),
        })
    }

    pub async fn reset_password(&self, request: ResetPasswordRequest) -> Result<MessageResponse, AuthError> {
        request.validate().map_err(|e| AuthError::Validation(e.to_string()))?;

        let token_hash = self.crypto_service.hash_token(&request.token);

        let reset_token = self.user_repo
            .find_password_reset_token_by_hash(&token_hash)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        let password_hash = self.crypto_service.hash_password(&request.new_password)?;

        self.user_repo.update_password(reset_token.user_id, &password_hash).await?;
        self.user_repo.mark_password_reset_token_used(reset_token.id).await?;

        Ok(MessageResponse {
            message: "Password reset successfully.".to_string(),
        })
    }

    pub async fn change_password(&self, user_id: Uuid, request: ChangePasswordRequest) -> Result<MessageResponse, AuthError> {
        request.validate().map_err(|e| AuthError::Validation(e.to_string()))?;

        let user = self.user_repo.find_by_id(user_id).await?
            .ok_or(AuthError::UserNotFound)?;

        if !self.crypto_service.verify_password(&request.current_password, &user.password_hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        let password_hash = self.crypto_service.hash_password(&request.new_password)?;

        self.user_repo.update_password(user_id, &password_hash).await?;

        Ok(MessageResponse {
            message: "Password changed successfully.".to_string(),
        })
    }

    // Token Management
    // ================

    pub async fn refresh_token(&self, refresh_token: &str) -> Result<AuthResponse, AuthError> {
        let claims = self.crypto_service.decode_jwt_token(refresh_token)?;

        let user_id: Uuid = claims.sub.parse()
            .map_err(|_| AuthError::InvalidToken)?;

        let user = self.user_repo.find_by_id(user_id).await?
            .ok_or(AuthError::UserNotFound)?;

        if !user.is_active {
            return Err(AuthError::AccountInactive);
        }

        let access_token = self.generate_jwt_token(&user)?;
        let new_refresh_token = self.generate_refresh_token(&user)?;

        Ok(AuthResponse {
            access_token,
            refresh_token: new_refresh_token,
        })
    }

    // User Management
    // ===============

    pub async fn get_user_profile(&self, user_id: Uuid) -> Result<User, AuthError> {
        let user = self.user_repo.find_by_id(user_id).await?
            .ok_or(AuthError::UserNotFound)?;

        if !user.is_active {
            return Err(AuthError::AccountInactive);
        }

        Ok(user)
    }

    pub async fn update_user_profile(&self, user_id: Uuid, update_data: UpdateProfileRequest) -> Result<MessageResponse, AuthError> {
        update_data.validate().map_err(|e| AuthError::Validation(e.to_string()))?;

        let user = self.user_repo.find_by_id(user_id).await?
            .ok_or(AuthError::UserNotFound)?;

        if !user.is_active {
            return Err(AuthError::AccountInactive);
        }

        self.user_repo.update_user_profile(user_id, update_data).await?;

        Ok(MessageResponse {
            message: "Profile updated successfully.".to_string(),
        })
    }

    pub async fn deactivate_account(&self, user_id: Uuid) -> Result<MessageResponse, AuthError> {
        let user = self.user_repo.find_by_id(user_id).await?
            .ok_or(AuthError::UserNotFound)?;

        if !user.is_active {
            return Err(AuthError::AccountInactive);
        }

        self.user_repo.deactivate_user(user_id).await?;
        self.user_repo.delete_email_verification_tokens(user_id).await?;
        self.user_repo.delete_password_reset_tokens_for_user(user_id).await?;

        Ok(MessageResponse {
            message: "Account deactivated successfully.".to_string(),
        })
    }

    // Helper Methods
    // ==============

    async fn create_and_send_verification_token(
        &self,
        user: &User,
        token: &str,
        token_hash: &str,
    ) -> Result<(), AuthError> {
        let encrypted_token = self.crypto_service.encrypt_token(token)?;

        let verification_token = EmailVerificationToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token: encrypted_token,
            token_hash: token_hash.to_string(),
            expires_at: Utc::now() + Duration::minutes(5),
            created_at: Utc::now(),
        };

        self.user_repo.create_email_verification_token(&verification_token).await?;
        self.email_service.send_verification_email(&user.email, &user.first_name, token).await?;

        Ok(())
    }

    async fn create_and_send_password_reset_token(
        &self,
        user: &User,
        token: &str,
        token_hash: &str,
    ) -> Result<(), AuthError> {
        let encrypted_token = self.crypto_service.encrypt_token(token)?;

        let reset_token = PasswordResetToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token: encrypted_token,
            token_hash: token_hash.to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            used: false,
        };

        self.user_repo.create_password_reset_token(&reset_token).await?;
        self.email_service.send_password_reset_email(&user.email, &user.first_name, token).await?;

        Ok(())
    }

    fn generate_jwt_token(&self, user: &User) -> Result<String, AuthError> {
        self.crypto_service.generate_jwt_token(user.id, &user.email, user.role, 3600)
    }

    fn generate_refresh_token(&self, user: &User) -> Result<String, AuthError> {
        self.crypto_service.generate_jwt_token(user.id, &user.email, user.role, 2592000)
    }
    pub async fn logout(&self, user_id: Uuid, token: &str) -> Result<MessageResponse, AuthError> {
        let claims = self.crypto_service.decode_jwt_token(token)?;
        self.user_repo.blacklist_token(user_id, token, claims.exp).await?;

        Ok(MessageResponse {
            message: "Logged out successfully".to_string(),
        })
    }

    pub async fn cleanup_expired_tokens(&self) -> Result<(), AuthError> {
        self.user_repo.delete_expired_tokens().await?;
        Ok(())
    }

    pub async fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        self.crypto_service.decode_jwt_token(token)
    }

    pub async fn check_token_expiry(&self, token: &str) -> Result<bool, AuthError> {
        self.crypto_service.check_token_expiry(token)
    }
}