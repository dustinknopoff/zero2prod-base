use std::net::TcpListener;

use once_cell::sync::Lazy;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use uuid::Uuid;
use zero2prod::{
    configuration::{get_configuration, DatabaseSettings},
    email_client::EmailClient,
    telemetry::{get_subscriber, init_subscriber},
};

#[tokio::test]
async fn health_check_works() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange
    let app = spawn_app().await;
    let client = reqwest::Client::new();

    // Act
    let response = client
        .get(format!("{}/health_check", app.address))
        .send()
        .await
        .expect("failed to execute request");

    // Assert
    assert!(response.status().is_success());
    assert_eq!(Some(0), response.content_length());
    Ok(())
}

static TRACING: Lazy<()> = Lazy::new(|| {
    if std::env::var("TEST_LOG").is_ok() {
        let subscriber = get_subscriber(
            "test".into(),
            "zero2prod=debug,info".into(),
            std::io::stdout,
        );
        init_subscriber(subscriber);
    } else {
        let subscriber =
            get_subscriber("test".into(), "zero2prod=debug,info".into(), std::io::sink);
        init_subscriber(subscriber);
    }
});

async fn spawn_app() -> TestApp {
    // Set up subscriber for logging
    Lazy::force(&TRACING);

    // Set up listener and cache the port
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind random port");
    let port = listener.local_addr().unwrap().port();
    let address = format!("http://127.0.0.1:{port}");

    // Get the configuration from file
    let mut configuration = get_configuration().expect("failed to read configuration");
    configuration.database.database_name = Uuid::new_v4().to_string();

    // Set up database connection pool
    let connection_pool = configure_database(&configuration.database).await;

    // Build an email clientz
    let sender_email = configuration
        .email_client
        .sender()
        .expect("Invalid sender address.");
    let email_client = EmailClient::new(configuration.email_client.base_url, sender_email);

    // Start the server
    let server = zero2prod::startup::run(listener, connection_pool.clone(), email_client);
    tokio::spawn(server);

    TestApp {
        address,
        db_pool: connection_pool,
    }
}

pub async fn configure_database(config: &DatabaseSettings) -> PgPool {
    // Create a database
    let mut connection = PgConnection::connect_with(&config.without_db())
        .await
        .expect("failed to connect to Postgres");

    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, config.database_name).as_str())
        .await
        .expect("failed to create the database");

    //Run migrations on the database
    let connection_pool = PgPool::connect_with(config.with_db())
        .await
        .expect("failed to connect to Postgres");
    sqlx::migrate!("./migrations")
        .run(&connection_pool)
        .await
        .expect("failed to migrate the database");

    //Return the connection pool
    connection_pool
}

pub struct TestApp {
    pub address: String,
    pub db_pool: PgPool,
}

#[tokio::test]
async fn subscribe_returns_200_for_valid_form_data() {
    // Arrange
    let app = spawn_app().await;

    let client = reqwest::Client::new();

    // Act
    let body = "name=le%20guin&email=ursula_le_guin%40gmail.com";
    let response = client
        .post(&format!("{}/subscriptions", &app.address))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .expect("failed to execute request");

    // Assert
    assert_eq!(200, response.status().as_u16());

    let saved = sqlx::query!("SELECT email, name FROM subscriptions",)
        .fetch_one(&app.db_pool)
        .await
        .expect("failed to fetch saved subscription");

    assert_eq!(saved.email, "ursula_le_guin@gmail.com");
    assert_eq!(saved.name, "le guin");
}

#[tokio::test]
async fn subscribe_returns_422_when_data_is_missing() {
    // Arrange
    let app = spawn_app().await;
    let client = reqwest::Client::new();

    let test_cases = vec![
        ("name=le%20guin", "missing the email"),
        ("email=ursula_le_guin%40gmail.com", "missing the name"),
        ("", "missing both the name and the email"),
    ];

    for (invalid_body, error_message) in test_cases {
        // Act
        let response = client
            .post(&format!("{}/subscriptions", app.address))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(invalid_body)
            .send()
            .await
            .expect("failed to execute request");

        // Assert
        assert_eq!(
            422,
            response.status().as_u16(),
            "The API did not fail with 400 when the payload was {error_message}"
        );
    }
}

#[tokio::test]
async fn subscribe_returns_422_when_fields_are_present_but_invalid() {
    // Arrange
    let app = spawn_app().await;
    let client = reqwest::Client::new();
    let test_cases = vec![
        ("name=&email=ursula_le_guin%40gmail.com", "empty name"),
        ("name=Ursula&email=", "empty email"),
        ("name=Ursula&email=definitely-not-an-email", "invalid email"),
    ];

    for (body, description) in test_cases {
        // Act
        let response = client
            .post(&format!("{}/subscriptions", app.address))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .expect("Failed to execute request");

        // Assert
        assert_eq!(
            422,
            response.status().as_u16(),
            "The API did not return a 422 Unprocessable Entity when the payload was {}",
            description
        );
    }
}
