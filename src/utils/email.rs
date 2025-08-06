use crate::config::config::SmtpConfig;
use crate::utils::auth_error::AuthError;
use lettre::{
    message::{header::ContentType, Mailbox, Message},
    transport::smtp::{authentication::Credentials, PoolConfig},
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};

#[derive(Clone)]
pub struct EmailService {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    from_mailbox: Mailbox,
}

impl EmailService {
    pub fn new(config: SmtpConfig) -> Result<Self, AuthError> {
        if config.username.is_empty() {
            return Err(AuthError::EmailService("SMTP username is empty".to_string()));
        }
        if config.password.is_empty() {
            return Err(AuthError::EmailService("SMTP password is empty".to_string()));
        }
        if config.from_email.is_empty() {
            return Err(AuthError::EmailService("From email is empty".to_string()));
        }

        let credentials = Credentials::new(config.username.clone(), config.password.clone());

        let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
            .map_err(|e| AuthError::EmailService(format!("Failed to connect to SMTP server: {}", e)))?
            .port(config.port)
            .credentials(credentials)
            .pool_config(PoolConfig::default())
            .build();

        let from_mailbox = format!("{} <{}>", config.from_name, config.from_email)
            .parse()
            .map_err(|e| AuthError::EmailService(format!("Invalid from address: {}", e)))?;

        Ok(Self {
            mailer,
            from_mailbox,
        })
    }

    pub async fn send_verification_email(&self, to_email: &str, first_name: &str, token: &str) -> Result<(), AuthError> {
        let subject = "Verify Your Email Address";
        let body = format!(
            r#"
            <html>
            <body>
                <h2>Email Verification</h2>
                <p>Hello {},</p>
                <p>Thank you for registering! Please use the following 6-digit code to verify your email address:</p>
                <h1 style="color: #4CAF50; text-align: center; letter-spacing: 5px;">{}</h1>
                <p>This code will expire in 24 hours.</p>
                <p>If you didn't request this verification, please ignore this email.</p>
                <br>
                <p>Best regards,<br>Auth System Team</p>
            </body>
            </html>
            "#,
            first_name, token
        );

        self.send_email(to_email, subject, &body).await
    }

    pub async fn send_password_reset_email(&self, to_email: &str, first_name: &str, token: &str) -> Result<(), AuthError> {
        let subject = "Password Reset Request";
        let body = format!(
            r#"
            <html>
            <body>
                <h2>Password Reset</h2>
                <p>Hello {},</p>
                <p>We received a request to reset your password. Please use the following 6-digit TOKEN:</p>
                <h1 style="color: #FF6B6B; text-align: center; letter-spacing: 5px;">{}</h1>
                <p>This TOKEN will expire in 5 minutes.</p>
                <p>If you didn't request a password reset, please ignore this email.</p>
                <br>
                <p>Best regards,<br>Auth System Team</p>
            </body>
            </html>
            "#,
            first_name, token
        );

        self.send_email(to_email, subject, &body).await
    }

    async fn send_email(&self, to_email: &str, subject: &str, body: &str) -> Result<(), AuthError> {
        let to_mailbox: Mailbox = to_email
            .parse()
            .map_err(|e| AuthError::EmailService(format!("Invalid recipient email: {}", e)))?;

        let email = Message::builder()
            .from(self.from_mailbox.clone())
            .to(to_mailbox)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body.to_string())
            .map_err(|e| AuthError::EmailService(format!("Failed to build email: {}", e)))?;

        self.mailer
            .send(email)
            .await
            .map_err(|e| AuthError::EmailService(format!("Failed to send email: {}", e)))?;

        Ok(())
    }
}
