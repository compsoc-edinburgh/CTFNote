use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Form, Router,
};
use axum_csrf::{CsrfConfig, CsrfToken};
use serde::Deserialize;

pub fn route(csrf: CsrfConfig) -> Router {
    Router::new()
        .route("/token-login", get(token_login_confirm).post(token_login))
        .with_state(csrf)
}

#[derive(Template)]
#[template(path = "token_login_confirm.html")]
struct TokenLoginConfirmTemplate {
    csrf_token: String,
}

async fn token_login_confirm(
    csrf: CsrfToken,
) -> impl IntoResponse {
    let csrf_token = csrf.authenticity_token().unwrap();
    let template = TokenLoginConfirmTemplate {
        csrf_token,
    };
    (csrf, HtmlTemplate(template)).into_response()
}

#[derive(Deserialize)]
struct TokenLoginRequest {
    csrf_token: String,
    token: String,
}

#[derive(Template)]
#[template(path = "token_login.html")]
struct TokenLoginTemplate {
    token: String,
}

async fn token_login(csrf: CsrfToken, Form(request): Form<TokenLoginRequest>) -> impl IntoResponse {
    if csrf.verify(&request.csrf_token).is_err() {
        return (StatusCode::BAD_REQUEST, "Invalid csrf token.").into_response()
    }
    let template = TokenLoginTemplate {
        token: request.token,
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
