use std::sync::Arc;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use jsonwebtoken::get_current_timestamp;
use rand::{self, thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgQueryResult, PgPool};

use crate::{config::config, AppState};

pub fn route(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/link-discord", post(link_discord))
        .route("/generate-jwt", post(generate_jwt_for_discord_user))
        .route("/register", post(register_and_link_discord))
        .with_state(app_state)
}

async fn get_user_by_token(pool: &PgPool, token: String) -> Option<i32> {
    sqlx::query_scalar("SELECT u.id FROM ctfnote_private.user as u JOIN ctfnote.profile as profile ON u.id = profile.id WHERE u.token = $1 AND discord_id is NULL")
        .bind(&token)
        .fetch_optional(pool)
        .await.expect("Failed to get user id from token")
}

async fn get_user_by_discord_id(pool: &PgPool, discord_id: &String) -> Option<i32> {
    sqlx::query_scalar("SELECT id FROM ctfnote.profile WHERE discord_id = $1 LIMIT 1")
        .bind(discord_id)
        .fetch_optional(pool)
        .await
        .expect("Failed to get user id from discord id")
}

async fn set_discord_id_for_user(
    db_pool: &PgPool,
    user_id: i32,
    discord_id: &String,
) -> PgQueryResult {
    sqlx::query("UPDATE ctfnote.profile SET discord_id = $2 WHERE id = $1")
        .bind(user_id)
        .bind(discord_id)
        .execute(db_pool)
        .await
        .expect("Failed to set discord id for user in the database")
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
    let result = set_discord_id_for_user(db_pool, user_id, &discord_id).await;
    if result.rows_affected() != 1 {
        return (StatusCode::BAD_REQUEST, Json(LinkDiscordResponse {
            message: "You can't link the same Discord account twice!".to_string(),
        }));
    }
    tracing::info!("Linked user {} to Discord user {}", user_id, discord_id);
    return (
        StatusCode::OK,
        Json(LinkDiscordResponse {
            message: "Successfully linked Discord account to CTFNote account!"
                .to_string(),
        }),
    );
}

#[derive(Deserialize)]
struct GenerateJwtForDiscordUserRequest {
    discord_id: String,
}

#[derive(Serialize)]
struct GenerateJwtForDiscordUserResponse {
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

async fn generate_jwt_for_discord_user(
    State(app_state): State<Arc<AppState>>,
    Json(request): Json<GenerateJwtForDiscordUserRequest>,
) -> (StatusCode, Json<GenerateJwtForDiscordUserResponse>) {
    let db_pool = &app_state.db_pool;
    let config = config();
    let discord_id = request.discord_id;

    let result = get_user_by_discord_id(db_pool, &discord_id).await;
    let Some(user_id) = result else {
        return (
            StatusCode::BAD_REQUEST,
            Json(GenerateJwtForDiscordUserResponse {
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
            Json(GenerateJwtForDiscordUserResponse {
                jwt: None,
                message: "Cannot generate JWT for the user. This is unexpected.".to_string(),
            }),
        );
    }

    let claim = JwtClaim {
        user_id: jwt.user_id,
        role: jwt.role.clone().unwrap(),
        exp: (get_current_timestamp() + 300) as usize,
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
        Json(GenerateJwtForDiscordUserResponse {
            jwt: Some(GenerateJwtResponseJwt {
                token: jwt_encoded,
                claim,
            }),
            message: "Successfully generated JWT!".to_string(),
        }),
    );
}

#[derive(Deserialize)]
struct RegisterAndLinkDiscordRequest {
    username: String,
    discord_id: String,
}

#[derive(Serialize)]
struct RegisterAndLinkDiscordResponse {
    message: String,
}

async fn register_and_link_discord(
    State(app_state): State<Arc<AppState>>,
    Json(request): Json<RegisterAndLinkDiscordRequest>,
) -> (StatusCode, Json<RegisterAndLinkDiscordResponse>) {
    let db_pool = &app_state.db_pool;
    let discord_id = request.discord_id;

    //TODO: make atomic
    let user = get_user_by_discord_id(db_pool, &discord_id).await;
    if user.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterAndLinkDiscordResponse {
                message: "Discord account already linked to CTFNote account.".to_string(),
            }),
        );
    }

    let mut random_password = vec![0; 32];
    thread_rng().fill_bytes(&mut random_password);
    let result: Result<Jwt, sqlx::Error> =
        sqlx::query_scalar("SELECT ctfnote_private.do_register($1, $2, 'user_guest')")
            .bind(request.username)
            .bind(format!("{:x?}", random_password))
            .fetch_one(db_pool)
            .await;

    // if username exists
    if let Err(err) = result {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterAndLinkDiscordResponse {
                message: err.as_database_error().unwrap().message().to_string(),
            }),
        );
    }

    let user_id = result.unwrap().user_id;
    let result = set_discord_id_for_user(db_pool, user_id, &discord_id).await;
    if result.rows_affected() != 1 {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RegisterAndLinkDiscordResponse {
                message: "Could not link Discord account. This is unexpected.".to_string(),
            }),
        );
    }
    (
        StatusCode::OK,
        Json(RegisterAndLinkDiscordResponse {
            message: "Successfully created CTFNote account!".to_string(),
        }),
    )
}
