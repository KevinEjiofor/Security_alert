use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expiration: i64,
    pub encryption_key: String,
    pub smtp: SmtpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_email: String,
    pub from_name: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        // Validate encryption key length
        let encryption_key = env::var("ENCRYPTION_KEY")
            .unwrap_or_else(|_| "default-32-char-encryption-key!".to_string());

        if encryption_key.len() != 32 {
            return Err(anyhow::anyhow!(
                "ENCRYPTION_KEY must be exactly 32 bytes (characters) long, got {} characters",
                encryption_key.len()
            ));
        }

        Ok(Config {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://user:password@localhost/auth_db".to_string()),
            jwt_secret: env::var("JWT_SECRET")
                .unwrap_or_else(|_| "your-secret-key-change-in-production".to_string()),
            jwt_expiration: env::var("JWT_EXPIRATION")
                .unwrap_or_else(|_| "86400".to_string())
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid JWT_EXPIRATION value: {}", e))?,
            encryption_key,
            smtp: SmtpConfig {
                host: env::var("SMTP_HOST")
                    .unwrap_or_else(|_| "smtp.gmail.com".to_string()),
                port: env::var("SMTP_PORT")
                    .unwrap_or_else(|_| "587".to_string())
                    .parse()
                    .map_err(|e| anyhow::anyhow!("Invalid SMTP_PORT value: {}", e))?,
                username: env::var("SMTP_USERNAME")
                    .unwrap_or_default(),
                password: env::var("SMTP_PASSWORD")
                    .unwrap_or_default(),
                from_email: env::var("FROM_EMAIL")
                    .unwrap_or_else(|_| "noreply@example.com".to_string()),
                from_name: env::var("FROM_NAME")
                    .unwrap_or_else(|_| "Auth System".to_string()),
            },
        })
    }
}