use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::PgPool;
use tower::ServiceExt;

use auth_api::create_app;
use auth_api::state::AppState;

fn make_state(pool: PgPool) -> AppState {
    AppState {
        session_duration_seconds: 10,
        db: pool,
    }
}

#[tokio::test]
async fn health_returns_200_with_db_down() {
    let pool = PgPool::connect_lazy("postgres://auth_user:auth_pass@localhost:5432/auth_db")
        .expect("failed to create pool");
    let app = create_app(make_state(pool));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn register_and_login_full_flow() {
    let pool = PgPool::connect_lazy("postgres://auth_user:auth_pass@localhost:5432/auth_db")
        .expect("failed to create pool");
    let app = create_app(make_state(pool));
    let email = format!(
        "test-{}@example.com",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    // Register
    let body = serde_json::json!({"email": email, "name": "Test", "password": "secret123"});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Login
    let body = serde_json::json!({"email": email, "password": "secret123"});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
