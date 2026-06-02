use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use axum_extra::TypedHeader;
use headers::{Authorization, authorization::Bearer};
use sqlx::Row;
use tracing::instrument;

use crate::{
    db::insert_user,
    domain::{
        HealthResponse, LoginRequest, LoginResponse, LogoutResponse, MeResponse, MeUser,
        PublicUser, RegisterRequest, RegisterResponse, ValidationError, current_timestamp,
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
            let insert_result = insert_user(
                &app_state.db,
                &value.email,
                &value.password_hash,
                &value.name,
            )
            .await;
            match insert_result {
                Ok(_) => {
                    tracing::info!(email = %value.email, "registration successful");
                    let res = RegisterResponse {
                        status: "success".to_string(),
                        message: "User created successfully".to_string(),
                    };
                    return (StatusCode::CREATED, Json(res));
                }
                Err(e) => {
                    if let sqlx::Error::Database(db_error) = &e
                        && db_error.constraint() == Some("users_email_key")
                    {
                        tracing::warn!(email = %value.email, "registration failed: email already exists");
                        let res = RegisterResponse {
                            status: "failed".to_string(),
                            message: format!("{}", ValidationError::EmailAlreadyExists),
                        };
                        return (StatusCode::CONFLICT, Json(res));
                    }
                    tracing::warn!(error = %e, "registration failed: database error");
                    let res = RegisterResponse {
                        status: "failed".to_string(),
                        message: "Internal server error".to_string(),
                    };
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(res))
                }
            }
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
    let normalized_email = input.email.trim().to_lowercase();

    let db_result = sqlx::query("SELECT email, password_hash, name FROM users WHERE email = $1")
        .bind(&normalized_email)
        .fetch_optional(&app_state.db)
        .await;

    match db_result {
        Ok(Some(row)) => {
            let stored_hash: String = row.get("password_hash");
            let user_email: String = row.get("email");

            if !verify_password(&input.password, &stored_hash) {
                tracing::warn!(email = %input.email, "login failed: invalid credentials");
                let res = LoginResponse {
                    status: "failed".to_string(),
                    message: "Either email or password is invalid".to_string(),
                    token: None,
                };
                return (StatusCode::UNAUTHORIZED, Json(res));
            }

            let generated_token = generate_session_token();
            sqlx::query("INSERT INTO sessions (token, email, created_at) VALUES ($1, $2, $3)")
                .bind(&generated_token)
                .bind(&user_email)
                .bind(current_timestamp() as i64)
                .execute(&app_state.db)
                .await
                .expect("failed to insert session");

            tracing::info!(email = %input.email, "login successful");
            let res = LoginResponse {
                status: "success".to_string(),
                message: "User found".to_string(),
                token: Some(generated_token),
            };
            (StatusCode::OK, Json(res))
        }
        Ok(None) => {
            tracing::warn!(email = %input.email, "login failed: user not found");
            let res = LoginResponse {
                status: "failed".to_string(),
                message: "Either email or password is invalid".to_string(),
                token: None,
            };
            (StatusCode::UNAUTHORIZED, Json(res))
        }

        Err(e) => {
            tracing::warn!(error = %e, "login failed: database error");
            let res = LoginResponse {
                status: "failed".to_string(),
                message: "Internal server error".to_string(),
                token: None,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(res))
        }
    }
}

#[instrument(skip(app_state, auth))]
pub async fn me(
    State(app_state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> (StatusCode, Json<MeResponse>) {
    let token = auth.token();

    let session_info = {
        let row = sqlx::query("SELECT email, created_at FROM sessions WHERE token = $1")
            .bind(token)
            .fetch_optional(&app_state.db)
            .await;
        match row {
            Ok(Some(row)) => {
                let email: String = row.get("email");
                let created_at: i64 = row.get("created_at");
                let expired =
                    created_at as u64 + app_state.session_duration_seconds < current_timestamp();
                if expired {
                    sqlx::query("DELETE FROM sessions WHERE token = $1")
                        .bind(token)
                        .execute(&app_state.db)
                        .await
                        .ok();
                }
                Some((email, expired))
            }
            _ => None,
        }
    };

    match session_info {
        Some((email, expired)) => {
            if expired {
                tracing::warn!(email = email, "session expired");
                let res = MeResponse {
                    status: "failed".to_string(),
                    message: "Session expired".to_string(),
                    user: None,
                };
                return (StatusCode::UNAUTHORIZED, Json(res));
            }
            let db_user = sqlx::query("SELECT email, name FROM users WHERE email = $1")
                .bind(&email)
                .fetch_optional(&app_state.db)
                .await;
            match db_user {
                Ok(Some(row)) => {
                    tracing::info!(email = %email, "authenticated request successful");
                    let user = MeUser {
                        email: row.get("email"),
                        name: row.get("name"),
                    };
                    let res = MeResponse {
                        status: "success".to_string(),
                        message: "Session found".to_string(),
                        user: Some(user),
                    };
                    (StatusCode::OK, Json(res))
                }
                Ok(None) => {
                    tracing::warn!(email = %email, "authenticated request failed: user not found");
                    let res = MeResponse {
                        status: "failed".to_string(),
                        message: "User not found".to_string(),
                        user: None,
                    };
                    (StatusCode::UNAUTHORIZED, Json(res))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "authenticated request failed: database error");
                    let res = MeResponse {
                        status: "failed".to_string(),
                        message: "Internal server error".to_string(),
                        user: None,
                    };
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(res))
                }
            }
        }
        None => {
            tracing::warn!("authenticated request failed: session not found");
            let res = MeResponse {
                status: "failed".to_string(),
                message: "Session not found".to_string(),
                user: None,
            };
            (StatusCode::UNAUTHORIZED, Json(res))
        }
    }
}

#[instrument(skip(app_state, auth))]
pub async fn logout(
    State(app_state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> (StatusCode, Json<LogoutResponse>) {
    let token = auth.token();
    let result = sqlx::query("DELETE FROM sessions WHERE token = $1")
        .bind(token)
        .execute(&app_state.db)
        .await;

    match result {
        Ok(query_result) => {
            if query_result.rows_affected() > 0 {
                tracing::info!("logout successful");
                (
                    StatusCode::OK,
                    Json(LogoutResponse {
                        status: "success".to_string(),
                        message: "Logged out successfully".to_string(),
                    }),
                )
            } else {
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
        Err(e) => {
            tracing::warn!(error = %e, "logout failed: database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LogoutResponse {
                    status: "failed".to_string(),
                    message: "Internal server error".to_string(),
                }),
            )
        }
    }
}

pub async fn get_user(
    State(app_state): State<AppState>,
    Path(email): Path<String>,
) -> (StatusCode, Json<PublicUser>) {
    let result = sqlx::query("SELECT email, name FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&app_state.db)
        .await;
    match result {
        Ok(Some(row)) => {
            let user = PublicUser {
                email: row.get("email"),
                name: row.get("name"),
            };
            (StatusCode::OK, Json(user))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(PublicUser {
                email,
                name: "not found".to_string(),
            }),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(PublicUser {
                email,
                name: "error".to_string(),
            }),
        ),
    }
}
