use std::sync::{Arc, Mutex};

use axum::routing::post;
use axum::{Router, routing::get};
use tokio::net::TcpListener;

use crate::handlers::{health, home, login, logout, me, register_preview};
use crate::state::AppState;

mod domain;
mod handlers;
mod state;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    tracing::info!("auth-api starting on 127.0.0.1:3000");
    let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
    let app = Router::new()
        .route("/", get(home))
        .route("/health", get(health))
        .route("/register", post(register_preview))
        .route("/login", post(login))
        .route("/me", get(me))
        .route("/logout", post(logout))
        .with_state(AppState {
            users: Arc::new(Mutex::new(Vec::new())),
            sessions: Arc::new(Mutex::new(Vec::new())),
        });

    axum::serve(listener, app).await.unwrap();
}
