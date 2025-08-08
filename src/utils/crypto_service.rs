use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use sha2::{Digest, Sha256};
use base64::{Engine as _, engine::general_purpose};
use anyhow;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

use crate::{
    config::config::Config,
    utils::auth_error::AuthError,
    enums::role::Role,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,       // Subject (user ID)
    pub email: String,    // User email
    pub role: Role,       // User role
    pub exp: i64,        // Expiration timestamp
    pub iat: i64,       // Issued at timestamp
}

/// Service for cryptographic operations including:
/// - Token generation and validation
/// - Password hashing and verification
/// - JWT operations
/// - Data encryption/decryption
pub struct CryptoService {
    cipher: Aes256Gcm,
    config: Config,
}

impl CryptoService {
    /// Creates a new CryptoService instance with the provided configuration
    pub fn new(config: Config) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(config.encryption_key.as_bytes());
        let cipher = Aes256Gcm::new(key);

        Self { cipher, config }
    }

    // Token Generation & Verification
    // ================================

    /// Generates a random 6-digit numeric token
    pub fn generate_6_digit_token(&self) -> String {
        let mut rng = rand::thread_rng();
        format!("{:06}", rng.gen_range(100000..=999999))
    }

    /// Hashes a token using SHA-256
    pub fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        general_purpose::STANDARD.encode(hasher.finalize())
    }

    // Encryption & Decryption
    // =======================

    /// Encrypts a token using AES-GCM
    pub fn encrypt_token(&self, token: &str) -> Result<String, AuthError> {
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, token.as_bytes())
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Encryption failed: {}", e)))?;

        let mut encrypted_data = nonce_bytes.to_vec();
        encrypted_data.extend_from_slice(&ciphertext);

        Ok(general_purpose::STANDARD.encode(encrypted_data))
    }

    pub fn decrypt_token(&self, encrypted_token: &str) -> Result<String, AuthError> {
        let encrypted_data = general_purpose::STANDARD
            .decode(encrypted_token)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Base64 decode failed: {}", e)))?;

        if encrypted_data.len() < 12 {
            return Err(AuthError::Internal(anyhow::anyhow!("Invalid encrypted token length")));
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Decryption failed: {}", e)))?;

        String::from_utf8(plaintext)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("UTF-8 decode failed: {}", e)))
    }

    // Password Handling
    // ================

    /// Hashes a password using bcrypt
    pub fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        hash(password, DEFAULT_COST)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!(e)))
    }

    /// Verifies a password against a bcrypt hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        verify(password, hash)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!(e)))
    }

    // JWT Operations
    // ==============

    /// Generates a JWT token with the specified claims and expiration
    pub fn generate_jwt_token(
        &self,
        user_id: Uuid,
        email: &str,
        role: Role,
        expiration_seconds: i64
    ) -> Result<String, AuthError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(expiration_seconds);

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role,
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        ).map_err(AuthError::from)
    }

    /// Decodes and validates a JWT token
    pub fn decode_jwt_token(&self, token: &str) -> Result<Claims, AuthError> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret.as_bytes()),
            &Validation::default(),
        )
            .map(|token_data| token_data.claims)
            .map_err(AuthError::from)
    }

    /// Checks if a JWT token is expired
    pub fn check_token_expiry(&self, token: &str) -> Result<bool, AuthError> {
        let claims = self.decode_jwt_token(token)?;
        Ok(claims.exp > Utc::now().timestamp())
    }
}