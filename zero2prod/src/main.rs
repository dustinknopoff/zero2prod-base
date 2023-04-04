use std::net::TcpListener;

use sqlx::PgPool;
use zero2prod::{configuration::get_configuration, startup::run, telemetry};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up tracing
    let subscriber = telemetry::get_subscriber("zero2prod".into(), "info".into());
    telemetry::init_subscriber(subscriber);

    // Set up configuration
    let configuration = get_configuration().expect("failed to read configuration");

    let db = PgPool::connect(&configuration.database.connection_string())
        .await
        .expect("Failed to connect to Postgres");

    let port = configuration.application.port;
    tracing::info!("Starting server and listening on {}", port);

    let listener = TcpListener::bind(format!("[::]:{port}")).map_err(|e| {
        tracing::error!("failed to bind port {}", port);
        e
    })?;

    let _ = run(listener, db).await;
    Ok(())
}
