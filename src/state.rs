use std::sync::{Arc, Mutex};

use crate::domain::{Session, User};

#[derive(Clone)]
#[allow(dead_code)]
pub struct AppState {
    pub users: Arc<Mutex<Vec<User>>>,
    pub sessions: Arc<Mutex<Vec<Session>>>,
}
