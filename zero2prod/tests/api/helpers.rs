use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use fake::{
    faker::{internet::en::SafeEmail, phone_number::en::PhoneNumber},
    Fake,
};
use once_cell::sync::Lazy;
use reqwest::Response;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use uuid::Uuid;
use wiremock::MockServer;
use zero2prod::{
    configuration::{get_configuration, DatabaseSettings},
    email_client::EmailClient,
    startup::{get_db_pool, Application},
    telemetry::{get_subscriber, init_subscriber},
};

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

pub async fn spawn_app() -> TestApp {
    // Set up subscriber for logging, only first time per run. Other times use existing subscriber.
    Lazy::force(&TRACING);

    let email_server = MockServer::start().await;
    let configuration = {
        // Get the configuration from file
        let mut c = get_configuration().expect("Failed to read configuration");
        // Use a different database for each test
        c.database.database_name = Uuid::new_v4().to_string();
        // Use a random OS port
        c.application.port = 0;
        c.email_client.base_url = email_server.uri();
        c
    };

    // Set up database connection pool
    configure_database(&configuration.database).await;

    // Start the server
    let app = Application::build(configuration.clone())
        .await
        .expect("Failed to build application");
    let port = app.port();
    let address = format!("http://127.0.0.1:{}", app.port());
    tokio::spawn(app.run_until_stopped());

    let api_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();

    let test_app = TestApp {
        address,
        port,
        db_pool: get_db_pool(&configuration.database),
        email_server,
        test_user: TestUser::generate(),
        api_client,
        email_client: configuration.email_client.client(),
    };

    test_app.test_user.store(&test_app.db_pool).await;

    test_app
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

pub struct TestUser {
    pub user_id: Uuid,
    pub email: String,
    pub password: String,
    pub phone_number: String,
}

impl TestUser {
    pub fn generate() -> Self {
        Self {
            user_id: Uuid::new_v4(),
            email: SafeEmail().fake(),
            password: Uuid::new_v4().to_string(),
            phone_number: PhoneNumber().fake(),
        }
    }

    #[allow(dead_code)]
    pub async fn login(&self, app: &TestApp) -> Response {
        app.post_login(&serde_json::json!({
            "email": &self.email,
            "password": &self.password,
        }))
        .await
    }
    async fn store(&self, pool: &PgPool) {
        let salt = SaltString::generate(&mut rand::thread_rng());
        let password_hash = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        )
        .hash_password(self.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

        sqlx::query!(
            r#"
            INSERT INTO users (user_id, user_name, preferred_name, password_hash)
            VALUES ($1, $2, $3, $4)
            "#,
            self.user_id,
            "test_user",
            "user_1",
            password_hash,
        )
        .execute(pool)
        .await
        .expect("Failed to store test user");

        sqlx::query!(
            r#"
            INSERT INTO user_private (user_id, email, phone_number)
            VALUES ($1, $2, $3)
            "#,
            self.user_id,
            self.email,
            self.phone_number,
        )
        .execute(pool)
        .await
        .expect("Failed to store test user");
    }
}

pub struct TestApp {
    pub address: String,
    pub port: u16,
    pub db_pool: PgPool,
    pub email_server: MockServer,
    pub test_user: TestUser,
    pub api_client: reqwest::Client,
    pub email_client: EmailClient,
}

impl TestApp {
    /// Send a get request to the change admin password endpoint
    pub async fn get_change_password(&self) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/admin/password", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    /// Send a post request to the change admin password endpoint
    pub async fn post_change_password<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .post(&format!("{}/admin/password", &self.address))
            .form(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    /// Send a post request to the login endpoint.
    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .post(&format!("{}/login", &self.address))
            .form(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    /// Send a post request to the logout endpoint.
    #[allow(dead_code)]
    pub async fn post_logout(&self) -> reqwest::Response {
        self.api_client
            .post(&format!("{}/admin/logout", self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }
}
