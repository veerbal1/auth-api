use sqlx::PgPool;

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
