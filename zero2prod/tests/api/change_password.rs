use http::StatusCode;
use uuid::Uuid;

use crate::helpers::spawn_app;

pub fn assert_is_error(response: &reqwest::Response, code: StatusCode) {
    assert_eq!(code, response.status().as_u16());
}

#[tokio::test]
async fn you_must_be_logged_in_to_see_the_change_password_form() {
    // Arrange
    let app = spawn_app().await;

    // Act
    let response = app.get_change_password().await;

    // Assert
    assert_is_error(&response, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn you_must_be_logged_in_to_change_your_password() {
    // Arrange
    let app = spawn_app().await;
    let new_password = Uuid::new_v4().to_string();

    // Act
    let response = app
        .post_change_password(&serde_json::json!({
        "current_password": Uuid::new_v4().to_string(),
        "new_password": &new_password,
        "new_password_check": &new_password,
        }))
        .await;
    // Assert
    assert_is_error(&response, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn new_password_fields_must_match() {
    // Arrange
    let app = spawn_app().await;
    let new_password = Uuid::new_v4().to_string();
    let another_new_password = Uuid::new_v4().to_string();

    // Act - Part 1 - Login
    let response = app
        .post_login(&serde_json::json!({
            "email": &app.test_user.email,
            "password": &app.test_user.password,
        }))
        .await;

    assert_eq!(response.status().as_u16(), StatusCode::OK);

    // Act - Part 2 - Try to change password
    let response = app
        .post_change_password(&serde_json::json!({
            "current_password": &app.test_user.password,
            "new_password": &new_password,
            "new_password_check": &another_new_password,
        }))
        .await;
    // Assert - Part 2
    assert_is_error(&response, StatusCode::BAD_REQUEST);

    assert_eq!(
        Some(&serde_json::Value::String(String::from(
            "You entered two different new passwords - the field values must match."
        ))),
        response
            .json::<serde_json::Value>()
            .await
            .unwrap()
            .get("error")
    );
}

#[tokio::test]
async fn current_password_must_be_valid() {
    // Arrange
    let app = spawn_app().await;
    let new_password = Uuid::new_v4().to_string();
    let wrong_password = Uuid::new_v4().to_string();

    // Act - Part 1 - Login
    app.post_login(&serde_json::json!({
        "email": &app.test_user.email,
        "password": &app.test_user.password,
    }))
    .await;

    // Act - Part 2 - Try to change password
    let response = app
        .post_change_password(&serde_json::json!({
            "current_password": &wrong_password,
            "new_password": &new_password,
            "new_password_check": &new_password,
        }))
        .await;

    assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(&serde_json::Value::String(String::from(
            "The current password is incorrect."
        ))),
        response
            .json::<serde_json::Value>()
            .await
            .unwrap()
            .get("error")
    )
}

#[tokio::test]
async fn new_password_must_be_correct_length() {
    // Arrange
    let app = spawn_app().await;

    let test_cases = vec![
        "99ds09a",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefd"
    ];

    for case in test_cases {
        // Act - Part 1 - Login
        app.post_login(&serde_json::json!({
            "email": &app.test_user.email,
            "password": &app.test_user.password,
        }))
        .await;

        // Act - Part 2 - Try to change password
        let response = app
            .post_change_password(&serde_json::json!({
                "current_password": &app.test_user.password,
                "new_password": &case,
                "new_password_check": &case,
            }))
            .await;

        // Assert - Part 2
        assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST);
        assert_eq!(
            Some(&serde_json::Value::String(String::from(
                "The new password should be between 12 and 128 characters long."
            ))),
            response
                .json::<serde_json::Value>()
                .await
                .unwrap()
                .get("error")
        )
    }
}

#[tokio::test]
async fn changing_password_works() {
    // Arrange
    let app = spawn_app().await;
    let new_password = Uuid::new_v4().to_string();

    // Act - Part 1 - Login
    let login_body = serde_json::json!({
        "email": &app.test_user.email,
        "password": &app.test_user.password,
    });

    app.post_login(&login_body).await;

    // Act - Part 2 - Change password
    let response = app
        .post_change_password(&serde_json::json!({
            "current_password": &app.test_user.password,
            "new_password": &new_password,
            "new_password_check": &new_password,
        }))
        .await;
    assert_is_error(&response, StatusCode::OK);

    // Act - Part 6 - Login using the new password
    let login_body = serde_json::json!({
        "email": &app.test_user.email,
        "password": &new_password,
    });

    let response = app.post_login(&login_body).await;
    assert_is_error(&response, StatusCode::OK);
}
