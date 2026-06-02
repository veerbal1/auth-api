pub mod domain;
pub mod handlers;
pub mod state;

use axum::Router;

pub fn create_app(state: state::AppState) -> Router {
    use axum::routing::{get, post};
    use handlers::{get_user, health, home, login, logout, me, register_preview};

    Router::new()
        .route("/", get(home))
        .route("/health", get(health))
        .route("/register", post(register_preview))
        .route("/login", post(login))
        .route("/me", get(me))
        .route("/logout", post(logout))
        .route("/user/{email}", get(get_user))
        .with_state(state)
}
