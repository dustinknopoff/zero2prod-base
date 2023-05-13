use axum::response::{IntoResponse, Redirect};
use axum_extra::response::Html;
use axum_flash::{IncomingFlashes, Level};
use axum_session::SessionRedisPool;
use http::StatusCode;
use std::fmt::Write;

use crate::{error::ResponseInternalServerError, session_state::TypedSession};

#[tracing::instrument("Change password form" skip(session))]
pub async fn change_password_form(
    flashes: IncomingFlashes,
    session: TypedSession<SessionRedisPool>,
) -> Result<impl IntoResponse, ResponseInternalServerError<anyhow::Error>> {
    if session.get_user_id().is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let mut msg_html = String::new();
    for (level, text) in flashes.iter().filter(|m| m.0 == Level::Error) {
        writeln!(
            msg_html,
            "<p><strong>{:?}</strong>: <i>{}</i></p>\n",
            level, text
        )
        .unwrap();
    }
    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8">
    <title>Change Password</title>
</head>
<body>
    {msg_html}
    <form action="/admin/password" method="post">
        <label>Current password
            <input type="password" placeholder="Enter current password" name="current_password">
        </label>
        <br>
        <label>New password
            <input type="password" placeholder="New password" name="new_password">
        </label>
        <br>
        <label>
            <input type="password" placeholder="Type the new password again" name="new_password_check">
        </label>
        <br>
        <button type="submit">Change password</button>
    </form>
</body>
</html>"#
    );

    Ok(Html((StatusCode::OK, body)).into_response())
}
