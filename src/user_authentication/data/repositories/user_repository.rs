use crate::user_authentication::data::models::user::{User, EmailVerificationToken, PasswordResetToken};
use crate::utils::auth_error::AuthError;
use crate::config::database::Database;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone)]
pub struct UserRepository {
    db: Database,
}

impl UserRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn create_user(&self, user: &User) -> Result<User, AuthError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO users (id, email, password_hash, first_name, last_name, role, is_email_verified, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
            user.id,
            user.email,
            user.password_hash,
            user.first_name,
            user.last_name,
            user.role as _,
            user.is_email_verified,
            user.is_active,
            user.created_at,
            user.updated_at
        )
            .fetch_one(self.db.get_pool())
            .await?;

        Ok(User {
            id: row.id,
            email: row.email,
            password_hash: row.password_hash,
            first_name: row.first_name,
            last_name: row.last_name,
            role: row.role,
            is_email_verified: row.is_email_verified,
            is_active: row.is_active,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_login: row.last_login,
        })
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE email = $1",
            email
        )
            .fetch_optional(self.db.get_pool())
            .await?;

        Ok(row)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError> {
        let row = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE id = $1",
            id
        )
            .fetch_optional(self.db.get_pool())
            .await?;

        Ok(row)
    }

    pub async fn update_email_verification(&self, user_id: Uuid, verified: bool) -> Result<(), AuthError> {
        sqlx::query!(
            "UPDATE users SET is_email_verified = $1, updated_at = $2 WHERE id = $3",
            verified,
            Utc::now(),
            user_id
        )
            .execute(self.db.get_pool())
            .await?;

        Ok(())
    }

    pub async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), AuthError> {
        sqlx::query!(
            "UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3",
            password_hash,
            Utc::now(),
            user_id
        )
            .execute(self.db.get_pool())
            .await?;

        Ok(())
    }

    pub async fn update_last_login(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query!(
            "UPDATE users SET last_login = $1, updated_at = $2 WHERE id = $3",
            Utc::now(),
            Utc::now(),
            user_id
        )
            .execute(self.db.get_pool())
            .await?;

        Ok(())
    }

    pub async fn create_email_verification_token(&self, token: &EmailVerificationToken) -> Result<(), AuthError> {
        sqlx::query!(
            r#"
            INSERT INTO email_verification_tokens (id, user_id, token, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            token.id,
            token.user_id,
            token.token,
            token.expires_at,
            token.created_at
        )
            .execute(self.db.get_pool())
            .await?;

        Ok(())
    }

    pub async fn find_email_verification_token(&self, email: &str, token: &str) -> Result<Option<EmailVerificationToken>, AuthError> {
        let row = sqlx::query_as!(
            EmailVerificationToken,
            r#"
            SELECT evt.* FROM email_verification_tokens evt
            JOIN users u ON evt.user_id = u.id
            WHERE u.email = $1 AND evt.token = $2 AND evt.expires_at > $3
            "#,
            email,
            token,
            Utc::now()
        )
            .fetch_optional(self.db.get_pool())
            .await?;

        Ok(row)
    }

    pub async fn delete_email_verification_tokens(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query!(
            "DELETE FROM email_verification_tokens WHERE user_id = $1",
            user_id
        )
            .execute(self.db.get_pool())
            .await?;

        Ok(())
    }

    pub async fn create_password_reset_token(&self, token: &PasswordResetToken) -> Result<(), AuthError> {
        sqlx::query!(
            r#"
            INSERT INTO password_reset_tokens (id, user_id, token, expires_at, created_at, used)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            token.id,
            token.user_id,
            token.token,
            token.expires_at,
            token.created_at,
            token.used
        )
            .execute(self.db.get_pool())
            .await?;

        Ok(())
    }

    pub async fn find_password_reset_token(&self, email: &str, token: &str) -> Result<Option<PasswordResetToken>, AuthError> {
        let row = sqlx::query_as!(
            PasswordResetToken,
            r#"
            SELECT prt.* FROM password_reset_tokens prt
            JOIN users u ON prt.user_id = u.id
            WHERE u.email = $1 AND prt.token = $2 AND prt.expires_at > $3 AND prt.used = false
            "#,
            email,
            token,
            Utc::now()
        )
            .fetch_optional(self.db.get_pool())
            .await?;

        Ok(row)
    }

    pub async fn mark_password_reset_token_used(&self, token_id: Uuid) -> Result<(), AuthError> {
        sqlx::query!(
            "UPDATE password_reset_tokens SET used = true WHERE id = $1",
            token_id
        )
            .execute(self.db.get_pool())
            .await?;

        Ok(())
    }

    pub async fn delete_expired_tokens(&self) -> Result<(), AuthError> {
        let now = Utc::now();

        sqlx::query!(
            "DELETE FROM email_verification_tokens WHERE expires_at < $1",
            now
        )
            .execute(self.db.get_pool())
            .await?;

        sqlx::query!(
            "DELETE FROM password_reset_tokens WHERE expires_at < $1",
            now
        )
            .execute(self.db.get_pool())
            .await?;

        Ok(())
    }
}
