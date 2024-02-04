use axum::{
    extract::State,
    response::IntoResponse,
    Extension, Form, Json,
};
use axum_flash::Flash;
use http::StatusCode;
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use sqlx::PgPool;

use crate::{
    authentication::{get_email, validate_credentials, AuthError, Credentials, UserId},
    e500,
    error::ResponseError,
};

#[tracing::instrument(name = "Change password", skip(user_id, form))]
pub async fn change_password(
    flash: Flash,
    Extension(user_id): Extension<UserId>,
    State(pool): State<PgPool>,
    Form(form): Form<FormData>,
) -> Result<impl IntoResponse, ResponseError> {
    // Ensure the new password is the correct length
    if form.new_password.expose_secret().len() < 12 || form.new_password.expose_secret().len() > 128
    {
        return Ok((
            StatusCode::BAD_REQUEST,
           Json(serde_json::json!({ "error": "The new password should be between 12 and 128 characters long."}))
        ).into_response());
    }

    // Ensure the new password and confirmation match
    if form.new_password.expose_secret() != form.new_password_check.expose_secret() {
        return Ok((
            StatusCode::BAD_REQUEST,
           Json(serde_json::json!({ "error": "You entered two different new passwords - the field values must match."}))
        ).into_response());
    }

    // Ensure the old/current password is valid
    let email = get_email(*user_id, &pool).await.map_err(e500)?;

    let credentials = Credentials {
        email,
        password: form.current_password,
    };

    if let Err(e) = validate_credentials(credentials, &pool).await {
        return match e {
            AuthError::InvalidCredentials(_) => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "The current password is incorrect."})),
                )
                    .into_response());
            }
            AuthError::UnexpectedError(_) => Err(e500(e)),
        };
    }

    crate::authentication::change_password(*user_id, form.new_password, &pool)
        .await
        .map_err(e500)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "message": "Your password has been changed"})),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct FormData {
    current_password: Secret<String>,
    new_password: Secret<String>,
    new_password_check: Secret<String>,
}
