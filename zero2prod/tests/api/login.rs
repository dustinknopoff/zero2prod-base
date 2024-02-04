use http::StatusCode;

use crate::helpers::spawn_app;

#[tokio::test]
async fn an_error_message_is_returned_on_error() {
    // Arrange
    let app = spawn_app().await;

    // Act 1
    let login_body = serde_json::json!({
        "email": "random-username@gmail.com",
        "password":"random-password"
    });
    let response = app.post_login(&login_body).await;

    // Assert 1
    assert_eq!(
        Some(&serde_json::Value::String(String::from(
            "Authentication failed"
        ))),
        response
            .json::<serde_json::Value>()
            .await
            .unwrap()
            .get("error")
    )
}

#[tokio::test]
async fn message_on_success() {
    // Arrange
    let app = spawn_app().await;

    // Act - Part 1 - Login
    let login_body = serde_json::json!({
        "email": &app.test_user.email,
        "password": &app.test_user.password,
    });

    let response = app.post_login(&login_body).await;

    // Assert - Part 1
    assert_eq!(response.status().as_u16(), StatusCode::OK);

    assert_eq!(
        Some(&serde_json::Value::String(String::from(
            "Successfully logged in"
        ))),
        response
            .json::<serde_json::Value>()
            .await
            .unwrap()
            .get("message")
    )
}
