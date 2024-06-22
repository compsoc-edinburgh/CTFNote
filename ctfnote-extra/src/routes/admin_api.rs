use std::sync::Arc;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use jsonwebtoken::get_current_timestamp;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{config::config, AppState};

pub fn route(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/link-discord", post(link_discord))
        .route("/generate-jwt", post(generate_jwt))
        .with_state(app_state)
}

async fn get_user_by_token(pool: &PgPool, token: String) -> Option<i32> {
    sqlx::query_scalar("SELECT u.id FROM ctfnote_private.user as u JOIN ctfnote.profile as profile ON u.id = profile.id WHERE u.token = $1 AND discord_id is NULL")
        .bind(&token)
        .fetch_optional(pool)
        .await.expect("Failed to get user id from token")
}

async fn get_user_by_discord_id(pool: &PgPool, discord_id: String) -> Option<i32> {
    sqlx::query_scalar("SELECT id FROM ctfnote.profile WHERE discord_id = $1 LIMIT 1")
        .bind(&discord_id)
        .fetch_optional(pool)
        .await
        .expect("Failed to get user id from discord id")
}

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
    State(app_state): State<Arc<AppState>>,
    Json(link_discord_request): Json<LinkDiscordRequest>,
) -> (StatusCode, Json<LinkDiscordResponse>) {
    let db_pool = &app_state.db_pool;
    let token = link_discord_request.token;

    // get user id from token
    let result = get_user_by_token(db_pool, token).await;
    let Some(user_id) = result else {
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
        .execute(db_pool)
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

#[derive(Deserialize)]
struct GenerateJwtRequest {
    discord_id: String,
}

#[derive(Serialize)]
struct GenerateJwtResponse {
    jwt: Option<GenerateJwtResponseJwt>,
    message: String,
}

#[derive(Serialize)]
struct GenerateJwtResponseJwt {
    token: String,
    claim: JwtClaim,
}

#[derive(sqlx::Type, Debug)]
#[sqlx(type_name = "jwt")]
struct Jwt {
    user_id: i32,
    role: Option<Role>,
    exp: i64,
}

#[derive(sqlx::Type, Debug, Clone)]
#[sqlx(type_name = "role")] // only for PostgreSQL to match a type definition
#[sqlx(rename_all = "snake_case")]
enum Role {
    UserGuest,
    UserMember,
    UserManager,
    UserAdmin,
}

impl Serialize for Role {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let display = match self {
            Role::UserGuest => "user_guest",
            Role::UserMember => "user_member",
            Role::UserManager => "user_manager",
            Role::UserAdmin => "user_admin",
        };
        serializer.serialize_str(display)
    }
}

#[derive(Serialize)]
struct JwtClaim {
    user_id: i32,
    role: Role,
    exp: usize,
    iat: usize,
    aud: String,
    iss: String,
}

async fn generate_jwt(
    State(app_state): State<Arc<AppState>>,
    Json(request): Json<GenerateJwtRequest>,
) -> (StatusCode, Json<GenerateJwtResponse>) {
    let db_pool = &app_state.db_pool;
    let config = config().await;
    let discord_id = request.discord_id;

    let result = get_user_by_discord_id(db_pool, discord_id).await;
    let Some(user_id) = result else {
        return (
            StatusCode::BAD_REQUEST,
            Json(GenerateJwtResponse {
                jwt: None,
                message: "No CTFNote account linked to the Discord user.".to_string(),
            }),
        );
    };

    let jwt: Jwt = sqlx::query_scalar("SELECT ctfnote_private.new_token($1)")
        .bind(user_id)
        .fetch_one(db_pool)
        .await
        .expect("Failed to generate JWT");

    if jwt.role.is_none() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GenerateJwtResponse {
                jwt: None,
                message: "Cannot generate JWT for the user. This is unexpected.".to_string(),
            }),
        );
    }

    let claim = JwtClaim {
        user_id: jwt.user_id,
        role: jwt.role.clone().unwrap(),
        exp: (get_current_timestamp() + 1800) as usize,
        iat: get_current_timestamp() as usize,
        aud: "postgraphile".to_string(),
        iss: "Admin API".to_string(),
    };

    let jwt_encoded = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claim,
        &jsonwebtoken::EncodingKey::from_secret(config.session_secret.as_bytes()),
    )
    .unwrap();

    return (
        StatusCode::OK,
        Json(GenerateJwtResponse {
            jwt: Some(GenerateJwtResponseJwt {
                token: jwt_encoded,
                claim,
            }),
            message: "Successfully generated JWT!".to_string(),
        }),
    );
}
