use axum::{Json, extract::State, http::StatusCode};
use axum_extra::TypedHeader;
use headers::{Authorization, authorization::Bearer};
use tracing::instrument;

use crate::{
    domain::{
        HealthResponse, LoginRequest, LoginResponse, LogoutResponse, MeResponse, MeUser,
        RegisterRequest, RegisterResponse, Session, ValidationError, current_timestamp,
        generate_session_token, validate_login_parameters, validate_new_user, verify_password,
    },
    state::AppState,
};

pub async fn home() -> &'static str {
    "Bhola Singh"
}

pub async fn health(State(app_state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let db_result = sqlx::query("SELECT 1").execute(&app_state.db).await;
    match db_result {
        Ok(_) => {
            let health_response = HealthResponse {
                service: "auth-api".to_string(),
                status: "ok".to_string(),
                database: "connected".to_string(),
            };
            (StatusCode::OK, Json(health_response))
        }
        Err(e) => {
            tracing::warn!("database health check failed: {}", e);
            let health_response = HealthResponse {
                service: "auth-api".to_string(),
                status: "degraded".to_string(),
                database: "disconnected".to_string(),
            };
            (StatusCode::SERVICE_UNAVAILABLE, Json(health_response))
        }
    }
}

#[instrument(skip(app_state, input))]
pub async fn register_preview(
    State(app_state): State<AppState>,
    Json(input): Json<RegisterRequest>,
) -> (StatusCode, Json<RegisterResponse>) {
    tracing::info!(email = %input.email, "registration attempt");
    let result = validate_new_user(input);
    match result {
        Ok(value) => {
            let mut users = app_state.users.lock().unwrap();
            if users.iter().any(|u| u.email == value.email) {
                let res = RegisterResponse {
                    status: "failed".to_string(),
                    message: format!("{}", ValidationError::EmailAlreadyExists),
                };
                tracing::warn!(email = %value.email, "registration failed: email already exists");
                return (StatusCode::BAD_REQUEST, Json(res));
            };
            tracing::info!(email = %value.email, "registration successful");
            users.push(value);
            let res = RegisterResponse {
                status: "success".to_string(),
                message: "User created successfully".to_string(),
            };
            (StatusCode::OK, Json(res))
        }
        Err(error) => {
            let res = RegisterResponse {
                status: "failed".to_string(),
                message: format!("{}", error),
            };
            (StatusCode::BAD_REQUEST, Json(res))
        }
    }
}

#[instrument(skip(app_state, input))]
pub async fn login(
    State(app_state): State<AppState>,
    Json(input): Json<LoginRequest>,
) -> (StatusCode, Json<LoginResponse>) {
    tracing::info!(email = %input.email, "login attempt");
    let validation = validate_login_parameters(&input);
    if validation.is_err() {
        tracing::warn!(email = %input.email, "login failed: invalid parameters");
        let res = LoginResponse {
            status: "failed".to_string(),
            message: "Either email or password wrong".to_string(),
            token: None,
        };
        return (StatusCode::UNAUTHORIZED, Json(res));
    };
    let users = app_state.users.lock().unwrap();
    let result = users.iter().find(|&user| input.email == user.email);
    if let Some(user) = result {
        let result = verify_password(&input.password, &user.password_hash);
        if !result {
            tracing::warn!(email = %input.email, "login failed: invalid credentials");
            let res = LoginResponse {
                status: "failed".to_string(),
                message: "Either email or password is invalid".to_string(),
                token: None,
            };
            (StatusCode::UNAUTHORIZED, Json(res))
        } else {
            let generated_token = generate_session_token();
            let mut sessions = app_state.sessions.lock().unwrap();
            sessions.push(Session {
                token: generated_token.clone(),
                email: user.email.to_owned(),
                created_at: current_timestamp(),
            });
            tracing::info!(email = %user.email, "login successful");
            let res = LoginResponse {
                status: "success".to_string(),
                message: "User found".to_string(),
                token: Some(generated_token),
            };
            (StatusCode::OK, Json(res))
        }
    } else {
        tracing::warn!(email = %input.email, "login failed: user not found");
        let res = LoginResponse {
            status: "failed".to_string(),
            message: "Either email or password is invalid".to_string(),
            token: None,
        };
        (StatusCode::UNAUTHORIZED, Json(res))
    }
}

#[instrument(skip(app_state, auth))]
pub async fn me(
    State(app_state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> (StatusCode, Json<MeResponse>) {
    let token = auth.token();
    let mut sessions = app_state.sessions.lock().unwrap();
    let session_index = sessions.iter().position(|session| session.token == token);
    if let Some(index) = session_index {
        let session = &sessions[index];
        let email = session.email.clone();
        if session.created_at + app_state.session_duration_seconds < current_timestamp() {
            sessions.remove(index);
            tracing::warn!(email = email, "session expired");
            let res = MeResponse {
                status: "failed".to_string(),
                message: "Session expired".to_string(),
                user: None,
            };
            return (StatusCode::UNAUTHORIZED, Json(res));
        }
        drop(sessions);
        let users = app_state.users.lock().unwrap();
        let user_result = users.iter().find(|user| user.email == email);

        if let Some(user) = user_result {
            tracing::info!(email = %user.email, "authenticated request successful");
            let user = MeUser {
                email: user.email.clone(),
                name: user.name.clone(),
            };
            let res = MeResponse {
                status: "success".to_string(),
                message: "Session found".to_string(),
                user: Some(user),
            };
            (StatusCode::OK, Json(res))
        } else {
            tracing::warn!(email = %email, "authenticated request failed: user not found");
            let res = MeResponse {
                status: "failed".to_string(),
                message: "User not found".to_string(),
                user: None,
            };
            (StatusCode::UNAUTHORIZED, Json(res))
        }
    } else {
        tracing::warn!("authenticated request failed: session not found");
        let res = MeResponse {
            status: "failed".to_string(),
            message: "Session not found".to_string(),
            user: None,
        };
        (StatusCode::UNAUTHORIZED, Json(res))
    }
}

#[instrument(skip(app_state, auth))]
pub async fn logout(
    State(app_state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> (StatusCode, Json<LogoutResponse>) {
    let token = auth.token();
    let mut sessions = app_state.sessions.lock().unwrap();
    let pos = sessions.iter().position(|s| s.token == token);
    match pos {
        Some(idx) => {
            sessions.remove(idx);
            tracing::info!("logout successful");
            (
                StatusCode::OK,
                Json(LogoutResponse {
                    status: "success".to_string(),
                    message: "Logged out successfully".to_string(),
                }),
            )
        }
        None => {
            tracing::warn!("logout failed: session not found");
            (
                StatusCode::UNAUTHORIZED,
                Json(LogoutResponse {
                    status: "failed".to_string(),
                    message: "Session not found".to_string(),
                }),
            )
        }
    }
}
