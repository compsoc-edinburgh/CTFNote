use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum_csrf::CsrfConfig;
use sqlx;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::config;

mod config;
mod routes;

struct AppState {
    db_pool: PgPool,
}

#[tokio::main]
async fn main() {
    // load config
    let config = config().await;

    // start tracing - level set by either RUST_LOG env variable or defaults to debug
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // axum logs rejections from built-in extractors with the `axum::rejection`
                // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                "ctfnote_extra=debug,tower_http=debug,axum::rejection=trace".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to database");

    //TODO: use csrf as middleware
    let csrf = CsrfConfig::default().with_cookie_name("ctf-extra_csrf_token");

    let app_state = Arc::new(AppState {
        db_pool,
    });

    let app = Router::new()
        .nest("/api/admin", routes::admin_api::route(app_state.clone()))
        .nest("/", routes::pages::route(csrf))
        .layer(
            TraceLayer::new_for_http()
            .on_response(
                DefaultOnResponse::new().level(Level::INFO)
            )
        );

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
