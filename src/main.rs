use axum::routing::post;
use axum::{Router, routing::get};
use tokio::net::TcpListener;

use crate::handlers::{health, home, login, logout, me, register_preview};
use crate::state::AppState;
use sqlx::postgres::PgPoolOptions;

mod domain;
mod handlers;
mod state;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let address = std::env::var("ADDRESS").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let session_duration_seconds: u64 = std::env::var("SESSION_DURATION_SECS")
        .unwrap_or_else(|_| "10".to_string())
        .parse()
        .unwrap();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pool: sqlx::PgPool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy(&database_url)
        .expect("could not connect to database");
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    tracing::info!("auth-api starting on {}", address);
    let listener = TcpListener::bind(address).await.unwrap();
    let app = Router::new()
        .route("/", get(home))
        .route("/health", get(health))
        .route("/register", post(register_preview))
        .route("/login", post(login))
        .route("/me", get(me))
        .route("/logout", post(logout))
        .with_state(AppState {
            session_duration_seconds,
            db: pool.clone(),
        });

    axum::serve(listener, app).await.unwrap();
}
