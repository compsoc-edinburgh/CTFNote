use jsonwebtoken::get_current_timestamp;
use serde::Serialize;

use crate::utils::get_random_hex_string;

#[derive(Clone, Serialize)]
pub struct Token {
    token: String,
    pub user_id: i32,
    exp: i64,
}

pub struct Tokens(Vec<Token>);

impl Tokens {
    pub fn new() -> Self {
        Tokens(Vec::new())
    }

    fn remove_expired(&mut self) -> () {
        let current_time = get_current_timestamp();
        self.0.retain(|t: &Token| t.exp > current_time.try_into().unwrap());
    }

    pub fn consume_token(&mut self, token: &String) -> Option<Token> {
        self.remove_expired();
        let i = self.0.iter().position(|t| &t.token == token);
        let Some(index) = i else {
            return None;
        };
        Some(self.0.swap_remove(index))
    }

    pub fn token_exists(&mut self, token: &String) -> bool {
        self.remove_expired();
        return self.0.iter().any(|t| &t.token == token)
    }

    pub fn add_token_for_user(&mut self, user_id: i32) -> Token {
        self.remove_expired();
        // generate token until unique
        let mut token;
        loop {
            token = get_random_hex_string(32);
            if !self.token_exists(&token) {
                break;
            }
        }
        let token = Token {
            token,
            user_id,
            exp: (get_current_timestamp() + 300) as i64,
        };
        self.0.push(token.clone());
        token
    }
}
