use std::sync::Arc;
use chrono::{Duration, Utc};
use uuid::Uuid;
use tokio;
use mockall::{mock, predicate::*};
use anyhow::Result;

use crate::config::config::Config;
use crate::config::database::Database;
use crate::dtos::user_authentication_dto::*;
use crate::enums::role::Role;
use crate::user_authentication::data::models::user::{User, EmailVerificationToken, PasswordResetToken};
use crate::user_authentication::data::repositories::user_repository::UserRepository;
use crate::user_authentication::services::auth_service::{AuthService, Claims};
use crate::utils::auth_error::AuthError;
use crate::utils::email::EmailService;

// Mock the UserRepository
mock! {
    UserRepository {
        async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
        async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError>;
        async fn create_user(&self, user: &User) -> Result<User, AuthError>;
        async fn update_last_login(&self, user_id: Uuid) -> Result<(), AuthError>;
        async fn update_email_verification(&self, user_id: Uuid, is_verified: bool) -> Result<(), AuthError>;
        async fn delete_email_verification_tokens(&self, user_id: Uuid) -> Result<(), AuthError>;
        async fn find_email_verification_token(&self, email: &str, token: &str) -> Result<Option<EmailVerificationToken>, AuthError>;
        async fn create_email_verification_token(&self, token: &EmailVerificationToken) -> Result<(), AuthError>;
        async fn find_password_reset_token_by_token(&self, token: &str) -> Result<Option<PasswordResetToken>, AuthError>;
        async fn create_password_reset_token(&self, token: &PasswordResetToken) -> Result<(), AuthError>;
        async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), AuthError>;
        async fn mark_password_reset_token_used(&self, token_id: Uuid) -> Result<(), AuthError>;
        async fn delete_expired_tokens(&self) -> Result<(), AuthError>;
    }
}

// Mock the EmailService
mock! {
    EmailService {
        async fn send_verification_email(&self, email: &str, first_name: &str, token: &str) -> Result<(), AuthError>;
        async fn send_password_reset_email(&self, email: &str, first_name: &str, token: &str) -> Result<(), AuthError>;
    }
}

// Helper function to create a test user
fn create_test_user() -> User {
    User {
        id: Uuid::new_v4(),
        email: "test@example.com".to_string(),
        password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/bB2w2w2w2".to_string(), // "password123"
        first_name: "John".to_string(),
        last_name: "Doe".to_string(),
        role: Role::User,
        is_email_verified: true,
        is_active: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
    }
}

// Test helper to create AuthService with mocks
fn create_auth_service_with_mocks(
    mock_user_repo: MockUserRepository,
    mock_email_service: MockEmailService,
) -> AuthService {
    // This would need to be adjusted based on how you can inject mocks into AuthService
    // You might need to modify AuthService constructor to accept these as parameters
    // For now, I'll show the structure assuming dependency injection is possible
    AuthService::new_with_deps(mock_user_repo, mock_email_service)
}

#[cfg(test)]
mod auth_service_tests {
    use super::*;

    #[tokio::test]
    async fn test_register_success() {
        let mut mock_user_repo = MockUserRepository::new();
        let mut mock_email_service = MockEmailService::new();

        // Setup expectations
        mock_user_repo
            .expect_find_by_email()
            .with(eq("test@example.com"))
            .times(1)
            .returning(|_| Ok(None)); // User doesn't exist

        mock_user_repo
            .expect_create_user()
            .times(1)
            .returning(|user| Ok(user.clone()));

        mock_user_repo
            .expect_create_email_verification_token()
            .times(1)
            .returning(|_| Ok(()));

        mock_email_service
            .expect_send_verification_email()
            .times(1)
            .returning(|_, _, _| Ok(()));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = RegisterRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            first_name: "John".to_string(),
            last_name: "Doe".to_string(),
            role: Some(Role::User),
        };

        let result = auth_service.register(request).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().message, "Registration successful. Please check your email for verification code.");
    }

    #[tokio::test]
    async fn test_register_user_already_exists() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let existing_user = create_test_user();

        mock_user_repo
            .expect_find_by_email()
            .with(eq("test@example.com"))
            .times(1)
            .returning(move |_| Ok(Some(existing_user.clone())));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = RegisterRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            first_name: "John".to_string(),
            last_name: "Doe".to_string(),
            role: Some(Role::User),
        };

        let result = auth_service.register(request).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_register_invalid_email() {
        let mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = RegisterRequest {
            email: "invalid-email".to_string(),
            password: "password123".to_string(),
            first_name: "John".to_string(),
            last_name: "Doe".to_string(),
            role: Some(Role::User),
        };

        let result = auth_service.register(request).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::Validation(_)));
    }

    #[tokio::test]
    async fn test_login_success() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let user = create_test_user();
        let user_clone = user.clone();

        mock_user_repo
            .expect_find_by_email()
            .with(eq("test@example.com"))
            .times(1)
            .returning(move |_| Ok(Some(user_clone.clone())));

        mock_user_repo
            .expect_update_last_login()
            .times(1)
            .returning(|_| Ok(()));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };

        let result = auth_service.login(request).await;

        assert!(result.is_ok());
        let auth_response = result.unwrap();
        assert!(!auth_response.access_token.is_empty());
        assert!(!auth_response.refresh_token.is_empty());
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        mock_user_repo
            .expect_find_by_email()
            .with(eq("test@example.com"))
            .times(1)
            .returning(|_| Ok(None));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "wrongpassword".to_string(),
        };

        let result = auth_service.login(request).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::InvalidCredentials));
    }

    #[tokio::test]
    async fn test_login_inactive_account() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let mut user = create_test_user();
        user.is_active = false;

        mock_user_repo
            .expect_find_by_email()
            .with(eq("test@example.com"))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };

        let result = auth_service.login(request).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::AccountInactive));
    }

    #[tokio::test]
    async fn test_login_email_not_verified() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let mut user = create_test_user();
        user.is_email_verified = false;

        mock_user_repo
            .expect_find_by_email()
            .with(eq("test@example.com"))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };

        let result = auth_service.login(request).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::EmailNotVerified));
    }

    #[tokio::test]
    async fn test_verify_email_success() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let token = EmailVerificationToken {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token: "123456".to_string(),
            expires_at: Utc::now() + Duration::minutes(5),
            created_at: Utc::now(),
        };

        mock_user_repo
            .expect_find_email_verification_token()
            .with(eq("test@example.com"), eq("123456"))
            .times(1)
            .returning(move |_, _| Ok(Some(token.clone())));

        mock_user_repo
            .expect_update_email_verification()
            .times(1)
            .returning(|_, _| Ok(()));

        mock_user_repo
            .expect_delete_email_verification_tokens()
            .times(1)
            .returning(|_| Ok(()));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = VerifyEmailRequest {
            email: "test@example.com".to_string(),
            token: "123456".to_string(),
        };

        let result = auth_service.verify_email(request).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().message, "Email verified successfully.");
    }

    #[tokio::test]
    async fn test_verify_email_invalid_token() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        mock_user_repo
            .expect_find_email_verification_token()
            .with(eq("test@example.com"), eq("invalid"))
            .times(1)
            .returning(|_, _| Ok(None));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = VerifyEmailRequest {
            email: "test@example.com".to_string(),
            token: "invalid".to_string(),
        };

        let result = auth_service.verify_email(request).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn test_resend_verification_success() {
        let mut mock_user_repo = MockUserRepository::new();
        let mut mock_email_service = MockEmailService::new();

        let mut user = create_test_user();
        user.is_email_verified = false;

        mock_user_repo
            .expect_find_by_email()
            .with(eq("test@example.com"))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        mock_user_repo
            .expect_delete_email_verification_tokens()
            .times(1)
            .returning(|_| Ok(()));

        mock_user_repo
            .expect_create_email_verification_token()
            .times(1)
            .returning(|_| Ok(()));

        mock_email_service
            .expect_send_verification_email()
            .times(1)
            .returning(|_, _, _| Ok(()));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = ResendVerificationRequest {
            email: "test@example.com".to_string(),
        };

        let result = auth_service.resend_verification(request).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().message, "Verification code sent to your email.");
    }

    #[tokio::test]
    async fn test_resend_verification_already_verified() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let user = create_test_user(); // is_email_verified is true by default

        mock_user_repo
            .expect_find_by_email()
            .with(eq("test@example.com"))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = ResendVerificationRequest {
            email: "test@example.com".to_string(),
        };

        let result = auth_service.resend_verification(request).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().message, "Email is already verified.");
    }

    #[tokio::test]
    async fn test_forgot_password_success() {
        let mut mock_user_repo = MockUserRepository::new();
        let mut mock_email_service = MockEmailService::new();

        let user = create_test_user();

        mock_user_repo
            .expect_find_by_email()
            .with(eq("test@example.com"))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        mock_user_repo
            .expect_create_password_reset_token()
            .times(1)
            .returning(|_| Ok(()));

        mock_email_service
            .expect_send_password_reset_email()
            .times(1)
            .returning(|_, _, _| Ok(()));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = ForgotPasswordRequest {
            email: "test@example.com".to_string(),
        };

        let result = auth_service.forgot_password(request).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().message, "A password reset TOKEN has been sent to email.");
    }

    #[tokio::test]
    async fn test_forgot_password_user_not_found() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        mock_user_repo
            .expect_find_by_email()
            .with(eq("notfound@example.com"))
            .times(1)
            .returning(|_| Ok(None));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = ForgotPasswordRequest {
            email: "notfound@example.com".to_string(),
        };

        let result = auth_service.forgot_password(request).await;

        // Should still return success for security reasons
        assert!(result.is_ok());
        assert_eq!(result.unwrap().message, "A password reset TOKEN has been sent to email.");
    }

    #[tokio::test]
    async fn test_reset_password_success() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let reset_token = PasswordResetToken {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token: "123456".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            used: false,
        };

        mock_user_repo
            .expect_find_password_reset_token_by_token()
            .with(eq("123456"))
            .times(1)
            .returning(move |_| Ok(Some(reset_token.clone())));

        mock_user_repo
            .expect_update_password()
            .times(1)
            .returning(|_, _| Ok(()));

        mock_user_repo
            .expect_mark_password_reset_token_used()
            .times(1)
            .returning(|_| Ok(()));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = ResetPasswordRequest {
            token: "123456".to_string(),
            new_password: "newpassword123".to_string(),
        };

        let result = auth_service.reset_password(request).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().message, "Password reset successfully.");
    }

    #[tokio::test]
    async fn test_reset_password_invalid_token() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        mock_user_repo
            .expect_find_password_reset_token_by_token()
            .with(eq("invalid"))
            .times(1)
            .returning(|_| Ok(None));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = ResetPasswordRequest {
            token: "invalid".to_string(),
            new_password: "newpassword123".to_string(),
        };

        let result = auth_service.reset_password(request).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn test_change_password_success() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let user = create_test_user();
        let user_id = user.id;

        mock_user_repo
            .expect_find_by_id()
            .with(eq(user_id))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        mock_user_repo
            .expect_update_password()
            .times(1)
            .returning(|_, _| Ok(()));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = ChangePasswordRequest {
            current_password: "password123".to_string(),
            new_password: "newpassword123".to_string(),
        };

        let result = auth_service.change_password(user_id, request).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().message, "Password changed successfully.");
    }

    #[tokio::test]
    async fn test_change_password_wrong_current_password() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let user = create_test_user();
        let user_id = user.id;

        mock_user_repo
            .expect_find_by_id()
            .with(eq(user_id))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let request = ChangePasswordRequest {
            current_password: "wrongpassword".to_string(),
            new_password: "newpassword123".to_string(),
        };

        let result = auth_service.change_password(user_id, request).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::InvalidCredentials));
    }

    #[tokio::test]
    async fn test_refresh_token_success() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let user = create_test_user();
        let user_id = user.id;

        mock_user_repo
            .expect_find_by_id()
            .with(eq(user_id))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        // First generate a valid refresh token
        let refresh_token = auth_service.generate_refresh_token(&create_test_user()).unwrap();

        let result = auth_service.refresh_token(&refresh_token).await;

        assert!(result.is_ok());
        let auth_response = result.unwrap();
        assert!(!auth_response.access_token.is_empty());
        assert!(!auth_response.refresh_token.is_empty());
    }

    #[tokio::test]
    async fn test_refresh_token_inactive_user() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let mut user = create_test_user();
        user.is_active = false;
        let user_id = user.id;

        mock_user_repo
            .expect_find_by_id()
            .with(eq(user_id))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        // Generate a valid refresh token for active user first
        let active_user = create_test_user();
        let refresh_token = auth_service.generate_refresh_token(&active_user).unwrap();

        let result = auth_service.refresh_token(&refresh_token).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::AccountInactive));
    }

    #[tokio::test]
    async fn test_cleanup_expired_tokens() {
        let mut mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        mock_user_repo
            .expect_delete_expired_tokens()
            .times(1)
            .returning(|| Ok(()));

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let result = auth_service.cleanup_expired_tokens().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_generate_jwt_token() {
        let mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);
        let user = create_test_user();

        let result = auth_service.generate_jwt_token(&user);

        assert!(result.is_ok());
        let token = result.unwrap();
        assert!(!token.is_empty());

        // Test token decoding
        let decoded = auth_service.decode_jwt_token(&token);
        assert!(decoded.is_ok());
        let claims = decoded.unwrap();
        assert_eq!(claims.sub, user.id.to_string());
        assert_eq!(claims.email, user.email);
        assert_eq!(claims.role, user.role);
    }

    #[tokio::test]
    async fn test_generate_refresh_token() {
        let mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);
        let user = create_test_user();

        let result = auth_service.generate_refresh_token(&user);

        assert!(result.is_ok());
        let token = result.unwrap();
        assert!(!token.is_empty());

        // Test token decoding
        let decoded = auth_service.decode_jwt_token(&token);
        assert!(decoded.is_ok());
        let claims = decoded.unwrap();
        assert_eq!(claims.sub, user.id.to_string());
        assert_eq!(claims.email, user.email);
        assert_eq!(claims.role, user.role);
    }

    #[tokio::test]
    async fn test_decode_jwt_token_invalid() {
        let mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let result = auth_service.decode_jwt_token("invalid.token.here");

        assert!(result.is_err());
    }

    #[test]
    fn test_generate_6_digit_token() {
        let mock_user_repo = MockUserRepository::new();
        let mock_email_service = MockEmailService::new();

        let auth_service = create_auth_service_with_mocks(mock_user_repo, mock_email_service);

        let token = auth_service.generate_6_digit_token();

        assert_eq!(token.len(), 6);
        assert!(token.chars().all(|c| c.is_ascii_digit()));

        let token_num: u32 = token.parse().unwrap();
        assert!(token_num >= 100000);
        assert!(token_num <= 999999);
    }
}