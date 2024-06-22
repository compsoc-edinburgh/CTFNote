use rand::{thread_rng, RngCore};

pub fn get_random_hex_string(byte_length: usize) -> String {
    let mut bytes = vec![0; byte_length];
    thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
