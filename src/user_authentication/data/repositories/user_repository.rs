use crate::{
    config::database::Database,
    enums::role::Role,
    user_authentication::data::models::user::{EmailVerificationToken, PasswordResetToken, User},
    utils::auth_error::AuthError,
    dtos::user_authentication_dto::UpdateProfileRequest,
};
use chrono::{DateTime, Utc};
use sqlx::postgres::PgArguments;
use sqlx::Arguments;
use uuid::Uuid;

#[derive(Clone)]
pub struct UserRepository {
    db: Database,
}

impl UserRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn find_email_verification_token_by_hash(
        &self,
        email: &str,
        token_hash: &str,
    ) -> Result<Option<EmailVerificationToken>, AuthError> {
        let row = sqlx::query_as!(
            EmailVerificationToken,
            r#"
            SELECT evt.id, evt.user_id, evt.token, evt.token_hash, evt.expires_at, evt.created_at
            FROM email_verification_tokens evt
            JOIN users u ON evt.user_id = u.id
            WHERE u.email = $1 AND evt.token_hash = $2 AND evt.expires_at > $3
            "#,
            email,
            token_hash,
            Utc::now()
        )
            .fetch_optional(self.db.get_pool())
            .await?;

        Ok(row)
    }

    pub async fn find_password_reset_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<PasswordResetToken>, AuthError> {
        let row = sqlx::query_as!(
            PasswordResetToken,
            r#"
            SELECT id, user_id, token, token_hash, expires_at, created_at, used
            FROM password_reset_tokens
            WHERE token_hash = $1 AND expires_at > $2 AND used = false
            "#,
            token_hash,
            Utc::now()
        )
            .fetch_optional(self.db.get_pool())
            .await?;

        Ok(row)
    }

    pub async fn create_email_verification_token(
        &self,
        token: &EmailVerificationToken,
    ) -> Result<(), AuthError> {
        sqlx::query!(
            r#"
            INSERT INTO email_verification_tokens (id, user_id, token, token_hash, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            token.id,
            token.user_id,
            token.token,
            token.token_hash,
            token.expires_at,
            token.created_at
        )
            .execute(self.db.get_pool())
            .await?;

        Ok(())
    }

    pub async fn create_password_reset_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<(), AuthError> {
        sqlx::query!(
            r#"
            INSERT INTO password_reset_tokens (id, user_id, token, token_hash, expires_at, created_at, used)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            token.id,
            token.user_id,
            token.token,
            token.token_hash,
            token.expires_at,
            token.created_at,
            token.used
        )
            .execute(self.db.get_pool())
            .await?;

        Ok(())
    }

    pub async fn create_user(&self, user: &User) -> Result<User, AuthError> {
        let mut query_args = PgArguments::default();
        query_args.add(user.id);
        query_args.add(&user.email);
        query_args.add(&user.password_hash);
        query_args.add(&user.first_name);
        query_args.add(&user.last_name);
        query_args.add(&user.phone_number);
        query_args.add(user.role);
        query_args.add(user.is_email_verified);
        query_args.add(user.is_active);
        query_args.add(user.created_at);
        query_args.add(user.updated_at);

        let query = sqlx::query_as_with(
            r#"
            INSERT INTO users
            (id, email, password_hash, first_name, last_name, phone_number, role, is_email_verified, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
            query_args,
        );

        let row = query.fetch_one(self.db.get_pool()).await?;
        Ok(row)
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query_as!(
            User,
            r#"
            SELECT
                id,
                email,
                password_hash,
                first_name,
                last_name,
                phone_number,
                role as "role: Role",
                is_email_verified,
                is_active,
                created_at,
                updated_at,
                last_login,
                profile_picture_url,
                timezone,
                locale,
                two_factor_enabled,
                two_factor_secret
            FROM users WHERE email = $1
            "#,
            email
        )
            .fetch_optional(self.db.get_pool())
            .await?;

        Ok(row)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError> {
        let row = sqlx::query_as!(
            User,
            r#"
            SELECT
                id,
                email,
                password_hash,
                first_name,
                last_name,
                phone_number,
                role as "role: Role",
                is_email_verified,
                is_active,
                created_at,
                updated_at,
                last_login,
                profile_picture_url,
                timezone,
                locale,
                two_factor_enabled,
                two_factor_secret
            FROM users WHERE id = $1
            "#,
            id
        )
            .fetch_optional(self.db.get_pool())
            .await?;

        Ok(row)
    }

    pub async fn find_by_phone(&self, phone_number: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query_as!(
            User,
            r#"
            SELECT
                id,
                email,
                password_hash,
                first_name,
                last_name,
                phone_number,
                role as "role: Role",
                is_email_verified,
                is_active,
                created_at,
                updated_at,
                last_login,
                profile_picture_url,
                timezone,
                locale,
                two_factor_enabled,
                two_factor_secret
            FROM users WHERE phone_number = $1
            "#,
            phone_number
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


    pub async fn update_user_profile(
        &self,
        user_id: Uuid,
        update_data: UpdateProfileRequest,
    ) -> Result<(), AuthError> {
        let mut query_parts = Vec::new();
        let mut query_args = PgArguments::default();
        let mut arg_count = 1;

        if let Some(first_name) = update_data.first_name {
            query_parts.push(format!("first_name = ${}", arg_count));
            query_args.add(first_name);
            arg_count += 1;
        }

        if let Some(last_name) = update_data.last_name {
            query_parts.push(format!("last_name = ${}", arg_count));
            query_args.add(last_name);
            arg_count += 1;
        }

        if let Some(phone_number) = update_data.phone_number {
            query_parts.push(format!("phone_number = ${}", arg_count));
            query_args.add(phone_number);
            arg_count += 1;
        }

        if let Some(profile_picture_url) = update_data.profile_picture_url {
            query_parts.push(format!("profile_picture_url = ${}", arg_count));
            query_args.add(profile_picture_url);
            arg_count += 1;
        }

        if let Some(timezone) = update_data.timezone {
            query_parts.push(format!("timezone = ${}", arg_count));
            query_args.add(timezone);
            arg_count += 1;
        }

        if let Some(locale) = update_data.locale {
            query_parts.push(format!("locale = ${}", arg_count));
            query_args.add(locale);
            arg_count += 1;
        }

        if query_parts.is_empty() {
            return Ok(()); // No fields to update
        }

        query_parts.push(format!("updated_at = ${}", arg_count));
        query_args.add(Utc::now());
        arg_count += 1;

        let query_str = format!(
            "UPDATE users SET {} WHERE id = ${}",
            query_parts.join(", "),
            arg_count
        );
        query_args.add(user_id);

        let query = sqlx::query_with(&query_str, query_args);
        query.execute(self.db.get_pool()).await?;

        Ok(())
    }

    // New method: deactivate_user
    pub async fn deactivate_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query!(
            "UPDATE users SET is_active = false, updated_at = $1 WHERE id = $2",
            Utc::now(),
            user_id
        )
            .execute(self.db.get_pool())
            .await?;

        Ok(())
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

    // New method: delete_password_reset_tokens_for_user
    pub async fn delete_password_reset_tokens_for_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query!(
            "DELETE FROM password_reset_tokens WHERE user_id = $1",
            user_id
        )
            .execute(self.db.get_pool())
            .await?;

        Ok(())
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
    pub async fn blacklist_token(&self, user_id: Uuid, token: &str, expires_at: i64) -> Result<(), AuthError> {

        let expires_at_datetime = DateTime::from_timestamp(expires_at, 0)
            .ok_or_else(|| AuthError::Database(sqlx::Error::Protocol("Invalid timestamp".to_string())))?;

        sqlx::query!(
        r#"
        INSERT INTO blacklisted_tokens (id, user_id, token, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        Uuid::new_v4(),
        user_id,
        token,
        expires_at_datetime,
        Utc::now()
    )
            .execute(self.db.get_pool())
            .await
            .map_err(|e| AuthError::Database(e))?;

        Ok(())
    }

    pub async fn is_token_blacklisted(&self, token: &str) -> Result<bool, AuthError> {
        let record = sqlx::query!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM blacklisted_tokens
            WHERE token = $1 AND expires_at > NOW()
        ) as "exists!"
        "#,
        token
    )
            .fetch_one(self.db.get_pool())
            .await
            .map_err(|e| AuthError::Database(e))?;

        Ok(record.exists)
    }
}