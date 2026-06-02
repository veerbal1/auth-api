use sqlx::{PgPool, Row};

pub async fn insert_user(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
    name: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3)")
        .bind(email)
        .bind(password_hash)
        .bind(name)
        .execute(pool)
        .await
        .map(|_| ())
}

pub struct UserRow {
    pub email: String,
    pub password_hash: String,
    pub name: String,
}

pub struct SessionRow {
    pub email: String,
    pub created_at: i64,
}

pub async fn find_user_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    let row = sqlx::query("SELECT email, password_hash, name FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| UserRow {
        email: r.get("email"),
        password_hash: r.get("password_hash"),
        name: r.get("name"),
    }))
}

pub async fn insert_session(
    pool: &PgPool,
    token: &str,
    email: &str,
    created_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO sessions (token, email, created_at) VALUES ($1, $2, $3)")
        .bind(token)
        .bind(email)
        .bind(created_at)
        .execute(pool)
        .await
        .map(|_| ())
}

pub async fn find_session(
    pool: &PgPool,
    token: &str,
) -> Result<Option<SessionRow>, sqlx::Error> {
    let row = sqlx::query("SELECT email, created_at FROM sessions WHERE token = $1")
        .bind(token)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| SessionRow {
        email: r.get("email"),
        created_at: r.get("created_at"),
    }))
}

pub async fn delete_session(pool: &PgPool, token: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM sessions WHERE token = $1")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
