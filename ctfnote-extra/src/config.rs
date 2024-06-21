use std::env;
use dotenvy::dotenv;

pub struct Config {
    pub database_url: String,
    pub session_secret: String,
}

pub async fn config() -> Config {
    dotenv().ok();

    Config {
        database_url: env::var("DATABASE_URL").expect("DATABASE_URL environment variable missing!"),
        session_secret: env::var("SESSION_SECRET").expect("SESSION_SECRET environment variable missing!"),
    }
}
