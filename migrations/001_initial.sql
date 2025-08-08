-- Create user_role enum
CREATE TYPE user_role AS ENUM ('user', 'admin', 'super_admin', 'police');

-- Create users table with required phone number
CREATE TABLE users (
                       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                       email VARCHAR(255) UNIQUE NOT NULL,
                       password_hash VARCHAR(255) NOT NULL,
                       first_name VARCHAR(100) NOT NULL,
                       last_name VARCHAR(100) NOT NULL,
                       phone_number VARCHAR(20) NOT NULL, -- Made required and not optional
                       role user_role NOT NULL DEFAULT 'user',
                       is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
                       is_active BOOLEAN NOT NULL DEFAULT TRUE,
                       created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                       updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                       last_login TIMESTAMPTZ,
                       profile_picture_url VARCHAR(500),
                       timezone VARCHAR(50),
                       locale VARCHAR(10),
                       two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                       two_factor_secret VARCHAR(255)
);

-- Create email verification tokens table
CREATE TABLE email_verification_tokens (
                                           id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                           user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                           token TEXT NOT NULL, -- Encrypted token storage
                                           token_hash VARCHAR(255) NOT NULL, -- Hash for lookup
                                           expires_at TIMESTAMPTZ NOT NULL,
                                           created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create password reset tokens table
CREATE TABLE password_reset_tokens (
                                       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                       user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                       token TEXT NOT NULL, -- Encrypted token storage
                                       token_hash VARCHAR(255) NOT NULL, -- Hash for lookup
                                       expires_at TIMESTAMPTZ NOT NULL,
                                       created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                                       used BOOLEAN NOT NULL DEFAULT FALSE
);

-- migrations/YYYYMMDDHHMMSS_create_blacklisted_tokens.sql
CREATE TABLE blacklisted_tokens (
                                    id UUID PRIMARY KEY,
                                    user_id UUID NOT NULL REFERENCES users(id),
                                    token TEXT NOT NULL,
                                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                                    UNIQUE(token)
);



-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone ON users(phone_number);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);
CREATE INDEX idx_email_verification_tokens_hash ON email_verification_tokens(token_hash);
CREATE INDEX idx_email_verification_tokens_expires_at ON email_verification_tokens(expires_at);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);
CREATE INDEX idx_blacklisted_tokens_token ON blacklisted_tokens(token);
CREATE INDEX idx_blacklisted_tokens_expires_at ON blacklisted_tokens(expires_at);

