use axum::{
    extract::State, response::IntoResponse, Form, Json
};

use axum_macros::debug_handler;
use axum_session::SessionRedisPool;
use http::StatusCode;
use secrecy::Secret;
use serde::Deserialize;
use sqlx::PgPool;

use crate::{
    authentication::{validate_credentials, AuthError, Credentials}, domain::Email, error_chain_fmt, session_state::TypedSession
};

#[debug_handler(state = crate::startup::AppState)]
#[tracing::instrument(
    name = "Login posted"
    skip(form, session, pool),
    fields(email=tracing::field::Empty, user_id=tracing::field::Empty)
)]
pub async fn login(
    State(pool): State<PgPool>,
    session: TypedSession<SessionRedisPool>,
    Form(form): Form<FormData>,
) -> Result<impl IntoResponse, LoginError> {
    let credentials = Credentials {
        email: Email::parse(form.email)?,
        password: form.password,
    };

    tracing::Span::current().record("email", &tracing::field::display(&credentials.email));

    let response = match validate_credentials(credentials, &pool).await {
        Ok(user_id) => {
            tracing::Span::current().record("user_id", &tracing::field::display(&user_id));
            // In actix_web, it would be necessary to handle serialization failure here. Somehow axum gets around that.
            session.renew();
            session.insert_user_id(user_id);
            (StatusCode::OK,Json(serde_json::json!({
               "message": "Successfully logged in" 
            })))
        }
        Err(e) => {
            let e = match e {
                AuthError::InvalidCredentials(_) => LoginError::AuthError(e.into()),
                AuthError::UnexpectedError(_) => LoginError::UnexpectedError(e.into()),
            };
            tracing::error!("{:?}", &e);

           (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": e.to_string()
           })))
        }
    };

    Ok(response)
}

#[derive(Deserialize)]
pub struct FormData {
    email: String,
    password: Secret<String>,
}

#[derive(thiserror::Error)]
pub enum LoginError {
    #[error("Authentication failed")]
    AuthError(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}
impl IntoResponse for LoginError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{:?}", self);
        match self {
            LoginError::AuthError(_) => StatusCode::UNAUTHORIZED.into_response(),
            LoginError::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

impl std::fmt::Debug for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}
