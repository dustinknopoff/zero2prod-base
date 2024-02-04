use anyhow::Context;
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::Email;

#[tracing::instrument(name = "Get user's email", skip(pool))]
pub async fn get_email(user_id: Uuid, pool: &PgPool) -> Result<Email, anyhow::Error> {
    let row = sqlx::query!(
        r#"
        SELECT email
        FROM users JOIN user_private
        ON users.user_id = user_private.user_id
        WHERE users.user_id = $1
        "#,
        user_id
    )
    .fetch_one(pool)
    .await
    .context("Failed to perform a query to retrieve a email.")?;
    Ok(Email::parse(row.email)?)
}
