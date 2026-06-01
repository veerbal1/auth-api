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
        email: req.email.trim().to_string(),
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
