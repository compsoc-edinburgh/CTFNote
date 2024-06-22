use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use routes::admin_api::route;
use sqlx;
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::config::config;

mod config;
mod routes;

struct AppState {
    db_pool: PgPool,
}

#[tokio::main]
async fn main() {
    eprintln!("Server started");
    // load config
    let config = config().await;

    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to database");

    let app_state = Arc::new(AppState {
        db_pool
    });

    let app = Router::new().nest("/api/admin", route(app_state.clone()));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
