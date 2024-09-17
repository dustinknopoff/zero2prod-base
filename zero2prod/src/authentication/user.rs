use anyhow::Context;
use secrecy::{ExposeSecret, Secret};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{domain::Email, telemetry::spawn_blocking_with_tracing};

use super::{password::compute_password_hash, AuthError};

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
    Email::parse(row.email)
}

pub struct NewUser {
    pub user_name: String,
    pub preferred_name: String,
    pub email: Secret<Email>,
    pub phone_number: Secret<String>,
    pub password: Secret<String>,
}

#[tracing::instrument(name = "Create User", skip(new_user, pool))]
pub async fn create_user(new_user: NewUser, pool: &PgPool) -> Result<Uuid, AuthError> {
    let password_hash =
        spawn_blocking_with_tracing(move || compute_password_hash(new_user.password))
            .await
            .context("Failed to hash password")
            .map_err(AuthError::UnexpectedError)??;

    let user_id = Uuid::new_v4();

    sqlx::query!(
        r#"
        INSERT INTO users (user_id, user_name, preferred_name, password_hash)
        VALUES ($1, $2, $3, $4)
        "#,
        user_id,
        new_user.user_name,
        new_user.preferred_name,
        password_hash.expose_secret()
    )
    .fetch_one(pool)
    .await
    .context("Failed to create user in users")
    .map_err(AuthError::UnexpectedError)?;

    sqlx::query!(
        r#"
        INSERT INTO user_private (user_id, email, phone_number)
        VALUES ($1, $2, $3)
        "#,
        user_id,
        new_user.email.expose_secret().as_ref(),
        new_user.phone_number.expose_secret(),
    )
    .fetch_one(pool)
    .await
    .context("Failed to create user in users")
    .map_err(AuthError::UnexpectedError)?;

    Ok(user_id)
}
