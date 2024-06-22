use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Form, Router,
};
use axum_csrf::CsrfToken;
use jsonwebtoken::get_current_timestamp;
use serde::{Deserialize, Serialize};

use crate::AppState;

pub fn route(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/token-login", get(token_login_confirm).post(token_login))
        .with_state(app_state)
}

#[derive(Template)]
#[template(path = "token_login_confirm.html")]
struct TokenLoginConfirmTemplate {
    csrf_token: String,
    token: String,
}

#[derive(Deserialize)]
struct TokenLoginConfirmRequest {
    token: String,
}

async fn token_login_confirm(
    State(_app_state): State<Arc<AppState>>,
    csrf: CsrfToken,
    Query(params): Query<TokenLoginConfirmRequest>,
) -> impl IntoResponse {
    let csrf_token = csrf.authenticity_token().unwrap();
    let template = TokenLoginConfirmTemplate {
        csrf_token,
        token: params.token,
    };
    (csrf, HtmlTemplate(template)).into_response()
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

#[derive(Deserialize)]
struct TokenLoginRequest {
    csrf_token: String,
    token: String,
}

#[derive(Template)]
#[template(path = "token_login.html")]
struct TokenLoginTemplate {
    jwt: String,
}

async fn token_login(
    State(app_state): State<Arc<AppState>>,
    csrf: CsrfToken,
    Form(request): Form<TokenLoginRequest>,
) -> impl IntoResponse {
    // check csrf
    if csrf.verify(&request.csrf_token).is_err() {
        return (StatusCode::BAD_REQUEST, "Invalid csrf token.").into_response();
    }

    let config = &app_state.config;

    let token = request.token;
    let token = app_state.tokens.lock().unwrap().verify_token(token);
    let Some(token) = token else {
        return (StatusCode::BAD_REQUEST, "Invalid token.").into_response();
    };
    let user_id = token.user_id;
    let db_pool = &app_state.db_pool;
    let jwt: Jwt = sqlx::query_scalar("SELECT ctfnote_private.new_token($1)")
        .bind(user_id)
        .fetch_one(db_pool)
        .await
        .expect("Failed to get JWT");

    if jwt.role.is_none() {
        return (StatusCode::BAD_REQUEST, "Could not get user.").into_response();
    }

    let claim = JwtClaim {
        user_id: jwt.user_id,
        role: jwt.role.clone().unwrap(),
        exp: jwt.exp as usize,
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

    let template = TokenLoginTemplate {
        jwt: jwt_encoded,
    };
    HtmlTemplate(template).into_response()
}

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => {
                tracing::error!("Failed to render template. Error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Internal Server Error."),
                )
                    .into_response()
            }
        }
    }
}
