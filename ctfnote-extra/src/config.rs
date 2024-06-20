use std::env;
use dotenvy::dotenv;

pub struct Config {
    pub database_url: String,
}

pub async fn config() -> Config {
    dotenv().ok();

    Config {
        database_url: env::var("DATABASE_URL").expect("DATABASE_URL environment variable missing!")
    }
}
