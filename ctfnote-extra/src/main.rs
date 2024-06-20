use std::time::Duration;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::config::config;

mod config;

#[derive(Deserialize)]
struct LinkDiscordRequest {
    token: String,
    discord_id: String,
}

#[derive(Serialize)]
struct LinkDiscordResponse {
    message: String,
}

async fn link_discord(
    State(pool): State<PgPool>,
    Json(link_discord_request): Json<LinkDiscordRequest>,
) -> (StatusCode, Json<LinkDiscordResponse>) {
    let token = link_discord_request.token;

    // get user id from token
    let query_result: Option<i32> = sqlx::query_scalar("SELECT u.id FROM ctfnote_private.user as u JOIN ctfnote.profile as profile ON u.id = profile.id WHERE u.token = $1 AND discord_id is NULL")
        .bind(&token)
        .fetch_optional(&pool)
        .await.expect("Failed to get user id from token");
    let Some(user_id) = query_result else {
        return (
            StatusCode::BAD_REQUEST,
            Json(LinkDiscordResponse {
                message: "No account with such token found that is not already linked!".to_string(),
            }),
        );
    };

    // update discord id for user
    let discord_id = link_discord_request.discord_id;
    let result = sqlx::query("UPDATE ctfnote.profile SET discord_id = $2 WHERE id = $1")
        .bind(user_id)
        .bind(discord_id)
        .execute(&pool)
        .await
        .expect("Failed to set discord id for user in the database");
    if result.rows_affected() != 1 {
        return (StatusCode::BAD_REQUEST, Json(LinkDiscordResponse {
            message: "You can't link the same Discord account twice! Please use a different Discord account or investigate why your account is already linked.".to_string(),
        }));
    }
    return (
        StatusCode::OK,
        Json(LinkDiscordResponse {
            message: "Successfully linked your Discord account to your CTFNote account!"
                .to_string(),
        }),
    );
}

#[tokio::main]
async fn main() {
    // load config
    let config = config().await;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to database");

    let admin_api_routes = Router::new()
        .route("/link-discord", post(link_discord))
        .with_state(pool);

    let app = Router::new().nest("/api/admin", admin_api_routes);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
