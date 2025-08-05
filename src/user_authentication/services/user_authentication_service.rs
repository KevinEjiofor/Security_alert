use crate::config::config::Config;
use crate::dtos::user_authentication_dto::*;
use crate::user_authentication::data::models::user::{User, EmailVerificationToken, PasswordResetToken};

use crate::utils::auth_error::AuthError;
use crate::config::database::Database;
use crate::utils::email::EmailService;
use crate::user_authentication::data::repositories::user_repository::UserRepository;
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;
use crate::enums::role::Role;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub role: Role,
    pub exp: i64,
    pub iat: i64,
}

pub struct AuthService {
    user_repo: UserRepository,
    email_service: EmailService,
    config: Config,
}

impl AuthService {
    pub fn new(db: Database, email_service: EmailService) -> Self {
        let config = Config::from_env().expect("Failed to load config");
        let user_repo = UserRepository::new(db);

        Self {
            user_repo,
            email_service,
            config,
        }
    }

    pub async fn register(&self, request: RegisterRequest) -> Result<MessageResponse, AuthError> {
        request.validate().map_err(|e| AuthError::Validation(e.to_string()))?;


        if let Some(_) = self.user_repo.find_by_email(&request.email).await? {
            return Err(AuthError::UserAlreadyExists);
        }


        let password_hash = hash(&request.password, DEFAULT_COST)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!(e)))?;


        let user = User {
            id: Uuid::new_v4(),
            email: request.email.clone(),
            password_hash,
            first_name: request.first_name.clone(),
            last_name: request.last_name,
            role: request.role.unwrap_or(Role::User),
            is_email_verified: false,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
        };

        let created_user = self.user_repo.create_user(&user).await?;


        let token = self.generate_6_digit_token();
        self.create_and_send_verification_token(&created_user, &token).await?;

        Ok(MessageResponse {
            message: "Registration successful. Please check your email for verification code.".to_string(),
        })
    }

    pub async fn login(&self, request: LoginRequest) -> Result<AuthResponse, AuthError> {
        request.validate().map_err(|e| AuthError::Validation(e.to_string()))?;


        let user = self.user_repo.find_by_email(&request.email).await?
            .ok_or(AuthError::InvalidCredentials)?;


        if !verify(&request.password, &user.password_hash)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!(e)))? {
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
            user: UserResponse {
                id: user.id,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                role: user.role,
                is_email_verified: user.is_email_verified,
                is_active: user.is_active,
            },
        })
    }

    pub async fn verify_email(&self, request: VerifyEmailRequest) -> Result<MessageResponse, AuthError> {
        request.validate().map_err(|e| AuthError::Validation(e.to_string()))?;

        let token = self.user_repo
            .find_email_verification_token(&request.email, &request.token)
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

        let token = self.generate_6_digit_token();
        self.create_and_send_verification_token(&user, &token).await?;

        Ok(MessageResponse {
            message: "Verification code sent to your email.".to_string(),
        })
    }

    pub async fn forgot_password(&self, request: ForgotPasswordRequest) -> Result<MessageResponse, AuthError> {
        request.validate().map_err(|e| AuthError::Validation(e.to_string()))?;

        if let Some(user) = self.user_repo.find_by_email(&request.email).await? {
            let token = self.generate_6_digit_token();
            self.create_and_send_password_reset_token(&user, &token).await?;
        }

        Ok(MessageResponse {
            message: "If an account with that email exists, a password reset code has been sent.".to_string(),
        })
    }

    pub async fn reset_password(&self, request: ResetPasswordRequest) -> Result<MessageResponse, AuthError> {
        request.validate().map_err(|e| AuthError::Validation(e.to_string()))?;


        let reset_token = self.user_repo
            .find_password_reset_token(&request.email, &request.token)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        let password_hash = hash(&request.new_password, DEFAULT_COST)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!(e)))?;

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


        if !verify(&request.current_password, &user.password_hash)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!(e)))? {
            return Err(AuthError::InvalidCredentials);
        }


        let password_hash = hash(&request.new_password, DEFAULT_COST)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!(e)))?;


        self.user_repo.update_password(user_id, &password_hash).await?;

        Ok(MessageResponse {
            message: "Password changed successfully.".to_string(),
        })
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> Result<AuthResponse, AuthError> {

        let claims = self.decode_jwt_token(refresh_token)?;

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
            user: UserResponse {
                id: user.id,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                role: user.role,
                is_email_verified: user.is_email_verified,
                is_active: user.is_active,
            },
        })
    }
    fn generate_6_digit_token(&self) -> String {
        let mut rng = rand::thread_rng();
        format!("{:06}", rng.gen_range(100000..=999999))
    }

    async fn create_and_send_verification_token(&self, user: &User, token: &str) -> Result<(), AuthError> {
        let verification_token = EmailVerificationToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token: token.to_string(),
            expires_at: Utc::now() + Duration::hours(24),
            created_at: Utc::now(),
        };

        self.user_repo.create_email_verification_token(&verification_token).await?;
        self.email_service.send_verification_email(&user.email, &user.first_name, token).await?;

        Ok(())
    }

    async fn create_and_send_password_reset_token(&self, user: &User, token: &str) -> Result<(), AuthError> {
        let reset_token = PasswordResetToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token: token.to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            used: false,
        };

        self.user_repo.create_password_reset_token(&reset_token).await?;
        self.email_service.send_password_reset_email(&user.email, &user.first_name, token).await?;

        Ok(())
    }

    fn generate_jwt_token(&self, user: &User) -> Result<String, AuthError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.jwt_expiration);

        let claims = Claims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            role: user.role,
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )?;

        Ok(token)
    }

    fn generate_refresh_token(&self, user: &User) -> Result<String, AuthError> {
        let now = Utc::now();
        let exp = now + Duration::days(30);

        let claims = Claims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            role: user.role,
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )?;

        Ok(token)
    }

    pub(crate) fn decode_jwt_token(&self, token: &str) -> Result<Claims, AuthError> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret.as_bytes()),
            &Validation::default(),
        )?;

        Ok(token_data.claims)
    }

    pub async fn cleanup_expired_tokens(&self) -> Result<(), AuthError> {
        self.user_repo.delete_expired_tokens().await?;
        Ok(())
    }
}
