use std::sync::{Arc, Mutex};

use crate::domain::{Session};
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub sessions: Arc<Mutex<Vec<Session>>>,
    pub session_duration_seconds: u64,
    #[allow(dead_code)]
    pub db: PgPool,
}
