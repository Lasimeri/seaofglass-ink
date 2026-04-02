use wasm_bindgen::prelude::*;
use argon2::{Algorithm, Argon2, Params, Version};

#[wasm_bindgen]
pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_len: u32,
) -> Result<Vec<u8>, JsError> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(output_len as usize))
        .map_err(|e| JsError::new(&e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; output_len as usize];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(output)
}
