use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
pub struct HealthResponse {
    pub service: String,
    pub status: String,
    pub database: String,
}

#[derive(Serialize, Debug)]
pub struct RegisterResponse {
    pub status: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub name: String,
    pub password: String,
}

#[allow(dead_code)]
pub struct User {
    pub email: String,
    pub name: String,
    pub password_hash: String,
}

#[derive(Debug)]
pub enum ValidationError {
    EmailInvalid,
    NameInvalid,
    EmailAlreadyExists,
    PasswordInvalid,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Debug)]
pub struct LoginResponse {
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Session {
    pub token: String,
    pub email: String,
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct MeUser {
    pub email: String,
    pub name: String,
}

#[derive(Serialize, Debug)]
pub struct LogoutResponse {
    pub status: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct MeResponse {
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<MeUser>,
}

#[derive(Serialize, Debug)]
pub struct PublicUser {
    pub email: String,
    pub name: String,
}

pub fn current_timestamp() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    now.as_secs()
}

pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let pass = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(pass.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let pass = PasswordHash::new(hash).unwrap();
    let res = Argon2::default().verify_password(password.as_bytes(), &pass);
    res.is_ok()
}

pub fn validate_new_user(req: RegisterRequest) -> Result<User, ValidationError> {
    if req.email.trim().is_empty() {
        return Err(ValidationError::EmailInvalid);
    } else if req.name.trim().is_empty() {
        return Err(ValidationError::NameInvalid);
    } else if req.password.trim().is_empty() {
        return Err(ValidationError::PasswordInvalid);
    };
    Ok(User {
        name: req.name.trim().to_string(),
        email: req.email.trim().to_lowercase().to_string(),
        password_hash: hash_password(req.password.trim()).unwrap(),
    })
}

pub fn validate_login_parameters(req: &LoginRequest) -> Result<(), ValidationError> {
    if req.email.trim().is_empty() {
        return Err(ValidationError::EmailInvalid);
    } else if req.password.trim().is_empty() {
        return Err(ValidationError::PasswordInvalid);
    }
    Ok(())
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ValidationError::EmailInvalid => write!(f, "There is an issue in email"),
            ValidationError::NameInvalid => write!(f, "There is an issue in name provided"),
            ValidationError::EmailAlreadyExists => write!(f, "Email already exists"),
            ValidationError::PasswordInvalid => write!(f, "Password is invalid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_registration_passes_validation() {
        let req = RegisterRequest {
            email: "test@example.com".to_string(),
            name: "Test".to_string(),
            password: "secret123".to_string(),
        };
        let result = validate_new_user(req);
        assert!(result.is_ok());
    }

    #[test]
    fn empty_email_fails() {
        let req = RegisterRequest {
            email: "   ".to_string(),
            name: "Test".to_string(),
            password: "secret123".to_string(),
        };
        let result = validate_new_user(req);
        assert!(result.is_err());
    }

    #[test]
    fn empty_name_fails() {
        let req = RegisterRequest {
            email: "test@example.com".to_string(),
            name: "   ".to_string(),
            password: "secret123".to_string(),
        };
        assert!(validate_new_user(req).is_err());
    }

    #[test]
    fn empty_password_fails() {
        let req = RegisterRequest {
            email: "test@example.com".to_string(),
            name: "Test".to_string(),
            password: "   ".to_string(),
        };
        assert!(validate_new_user(req).is_err());
    }

    #[test]
    fn login_with_valid_input_passes() {
        let req = LoginRequest {
            email: "test@example.com".to_string(),
            password: "secret".to_string(),
        };
        assert!(validate_login_parameters(&req).is_ok());
    }

    #[test]
    fn login_with_empty_email_fails() {
        let req = LoginRequest {
            email: "  ".to_string(),
            password: "p".to_string(),
        };
        assert!(validate_login_parameters(&req).is_err());
    }

    #[test]
    fn email_is_lowercased() {
        let req = RegisterRequest {
            email: "Test@Example.COM".to_string(),
            name: "Test".to_string(),
            password: "secret123".to_string(),
        };
        let user = validate_new_user(req).unwrap();
        assert_eq!(user.email, "test@example.com");
    }

    #[test]
    fn hash_and_verify_password_roundtrip() {
        let password = "mySecret123";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash));
    }

    #[test]
    fn wrong_password_fails_verification() {
        let hash = hash_password("correct").unwrap();
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn session_token_is_64_hex_chars() {
        let token = generate_session_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
