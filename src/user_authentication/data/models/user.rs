use crate::enums::role::Role;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    #[serde(with = "uuid::serde::simple")]
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub first_name: String,
    pub last_name: String,
    pub phone_number: String, // Made required - no longer Option<String>
    pub role: Role,
    pub is_email_verified: bool,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub profile_picture_url: Option<String>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub two_factor_enabled: bool,
    pub two_factor_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct EmailVerificationToken {
    #[serde(with = "uuid::serde::simple")]
    pub id: Uuid,
    #[serde(with = "uuid::serde::simple")]
    pub user_id: Uuid,
    pub token: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PasswordResetToken {
    #[serde(with = "uuid::serde::simple")]
    pub id: Uuid,
    #[serde(with = "uuid::serde::simple")]
    pub user_id: Uuid,
    pub token: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used: bool,
}