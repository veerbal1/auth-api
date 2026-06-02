use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub session_duration_seconds: u64,
    #[allow(dead_code)]
    pub db: PgPool,
}
