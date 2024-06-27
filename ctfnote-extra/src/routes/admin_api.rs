use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{serde::ts_seconds, DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgQueryResult, PgPool};

use crate::{tokens::Token, utils::get_random_hex_string, AppState};

pub fn route(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/link-discord", post(link_discord))
        .route("/get-token", post(get_token_for_discord_user))
        .route("/register", post(register_and_link_discord))
        .route("/role", get(get_role_for_discord_user))
        .route("/upcoming-ctf", get(upcoming_ctfs))
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
        return (
            StatusCode::BAD_REQUEST,
            Json(LinkDiscordResponse {
                message: "You can't link the same Discord account twice!".to_string(),
            }),
        );
    }
    tracing::info!("Linked user {} to Discord user {}", user_id, discord_id);
    return (
        StatusCode::OK,
        Json(LinkDiscordResponse {
            message: "Successfully linked Discord account to CTFNote account!".to_string(),
        }),
    );
}

#[derive(Deserialize)]
struct GetTokenForDiscordUserRequest {
    discord_id: String,
}

#[derive(Serialize)]
struct GetTokenForDiscordUserResponse {
    token: Option<Token>,
    message: String,
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

async fn get_token_for_discord_user(
    State(app_state): State<Arc<AppState>>,
    Json(request): Json<GetTokenForDiscordUserRequest>,
) -> (StatusCode, Json<GetTokenForDiscordUserResponse>) {
    let db_pool = &app_state.db_pool;
    let discord_id = request.discord_id;

    let result: Option<i32> = get_user_by_discord_id(db_pool, &discord_id).await;
    let Some(user_id) = result else {
        return (
            StatusCode::BAD_REQUEST,
            Json(GetTokenForDiscordUserResponse {
                token: None,
                message: "No CTFNote account linked to the Discord user.".to_string(),
            }),
        );
    };

    let token = app_state.tokens.lock().unwrap().add_token_for_user(user_id);

    (
        StatusCode::BAD_REQUEST,
        Json(GetTokenForDiscordUserResponse {
            token: Some(token),
            message: "Successfully created token.".to_string(),
        }),
    )
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

    let random_password = get_random_hex_string(32);
    let result: Result<Jwt, sqlx::Error> =
        sqlx::query_scalar("SELECT ctfnote_private.do_register($1, $2, 'user_guest')")
            .bind(request.username)
            .bind(random_password)
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

#[derive(Deserialize)]
struct GetRoleForDiscordUserRequest {
    discord_id: String,
}

#[derive(Serialize)]
struct GetRoleForDiscordUserResponse {
    role: Option<Role>,
    message: String,
}

async fn get_role_for_discord_user(
    State(app_state): State<Arc<AppState>>,
    Query(request): Query<GetRoleForDiscordUserRequest>,
) -> (StatusCode, Json<GetRoleForDiscordUserResponse>) {
    let db_pool = &app_state.db_pool;
    let discord_id = request.discord_id;

    let role: Option<Role> = sqlx::query_scalar("SELECT u.role FROM ctfnote_private.user as u JOIN ctfnote.profile as profile ON u.id = profile.id WHERE discord_id = $1")
        .bind(&discord_id)
        .fetch_optional(db_pool)
        .await.expect("Failed to get role from discord id");
    let message = match role {
        Some(_) => "Successfully get role of the user.",
        None =>  "Cannot get role for the user.",
    };
    let status_code = match role {
        Some(_) => StatusCode::OK,
        None => StatusCode::NOT_FOUND,
    };

    (
        status_code,
        Json(GetRoleForDiscordUserResponse {
            role,
            message: message.to_string(),
        }),
    )
}

#[derive(sqlx::Type, Debug, Serialize)]
#[sqlx(type_name = "ctf")]
struct Ctf {
    id: i32,
    title: String,
    weight: f64,
    ctf_url: String,
    logo_url: String,
    ctftime_url: String,
    description: String,
    #[serde(with = "ts_seconds")]
    start_time: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    end_time: DateTime<Utc>,
    // secrets_id: foreign key
}

#[derive(Serialize)]
struct GetUpcomingCtfResponse(Vec<Ctf>);

async fn upcoming_ctfs(
    State(app_state): State<Arc<AppState>>,
) -> (StatusCode, Json<GetUpcomingCtfResponse>) {
    let db_pool = &app_state.db_pool;

    let result: Result<Vec<Ctf>, sqlx::Error> = sqlx::query_scalar("SELECT ctfnote.incoming_ctf()")
        .fetch_all(db_pool)
        .await;

    (
        StatusCode::OK,
        Json(GetUpcomingCtfResponse(result.unwrap())),
    )
}
