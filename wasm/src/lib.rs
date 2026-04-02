use wasm_bindgen::prelude::*;
use sss_rs::prelude::{share, reconstruct};

// ─── Compression (zstd) ───

#[wasm_bindgen]
pub fn zstd_compress(data: &[u8], level: i32) -> Result<Vec<u8>, JsError> {
    zstd::bulk::compress(data, level).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn zstd_decompress(data: &[u8]) -> Result<Vec<u8>, JsError> {
    // Limit decompressed size to 10MB to prevent decompression bombs
    zstd::bulk::decompress(data, 10 * 1024 * 1024).map_err(|e| JsError::new(&e.to_string()))
}

// ─── Argon2id key derivation ───

#[wasm_bindgen]
pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_len: u32,
) -> Result<Vec<u8>, JsError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(memory_kib, iterations, parallelism, Some(output_len as usize))
        .map_err(|e| JsError::new(&e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; output_len as usize];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(output)
}

// ─── Markdown → HTML ───

#[wasm_bindgen]
pub fn markdown_to_html(markdown: &str) -> String {
    use pulldown_cmark::{html, Options, Parser};

    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);

    let parser = Parser::new_ext(markdown, opts);
    let mut html_output = String::with_capacity(markdown.len() * 2);
    html::push_html(&mut html_output, parser);
    html_output
}

// ─── Fuzzy search ───

/// Score a candidate string against a query using a simplified Smith-Waterman-like algorithm.
/// Returns 0 if no match, higher = better match. Consecutive matches and word-boundary
/// matches score higher.
fn fuzzy_score(query: &str, candidate: &str) -> u32 {
    let query_lower: Vec<char> = query.chars().flat_map(|c| c.to_lowercase()).collect();
    let cand_lower: Vec<char> = candidate.chars().flat_map(|c| c.to_lowercase()).collect();

    if query_lower.is_empty() {
        return 1; // empty query matches everything
    }

    let mut qi = 0;
    let mut score: u32 = 0;
    let mut consecutive: u32 = 0;
    let mut prev_match = false;

    for (ci, &ch) in cand_lower.iter().enumerate() {
        if qi < query_lower.len() && ch == query_lower[qi] {
            qi += 1;
            score += 1;

            // Bonus for consecutive matches
            if prev_match {
                consecutive += 1;
                score += consecutive * 2;
            } else {
                consecutive = 0;
            }

            // Bonus for word boundary match (start of string or after separator)
            if ci == 0 || matches!(cand_lower.get(ci - 1), Some(' ' | '/' | '.' | '-' | '_')) {
                score += 5;
            }

            prev_match = true;
        } else {
            prev_match = false;
            consecutive = 0;
        }
    }

    if qi < query_lower.len() {
        return 0; // not all query chars matched
    }

    // Bonus for shorter candidates (more precise match)
    score += (100 / (cand_lower.len() as u32 + 1)).min(10);

    score
}

/// Search lines of text for a fuzzy query. Returns JSON array of {line, score, text}.
/// Results are sorted by score descending, limited to top N.
#[wasm_bindgen]
pub fn fuzzy_search(text: &str, query: &str, max_results: u32) -> String {
    let mut results: Vec<(usize, u32, &str)> = Vec::new();

    for (i, line) in text.lines().enumerate() {
        let score = fuzzy_score(query, line);
        if score > 0 {
            results.push((i + 1, score, line));
        }
    }

    results.sort_by(|a, b| b.1.cmp(&a.1));
    results.truncate(max_results as usize);

    // Build JSON manually to avoid serde dependency
    let mut json = String::from("[");
    for (idx, (line_num, score, text)) in results.iter().enumerate() {
        if idx > 0 {
            json.push(',');
        }
        json.push_str(&format!(
            "{{\"line\":{},\"score\":{},\"text\":{}}}",
            line_num,
            score,
            json_escape(text)
        ));
    }
    json.push(']');
    json
}

// ─── Ed25519 signatures ───

#[wasm_bindgen]
pub fn ed25519_keygen() -> Vec<u8> {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    // Return 64 bytes: [32-byte secret][32-byte public]
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(sk.as_bytes());
    out.extend_from_slice(sk.verifying_key().as_bytes());
    out
}

#[wasm_bindgen]
pub fn ed25519_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    use ed25519_dalek::{Signer, SigningKey};
    if secret_key.len() != 32 {
        return Err(JsError::new("secret key must be 32 bytes"));
    }
    let sk = SigningKey::from_bytes(secret_key.try_into().unwrap());
    let sig = sk.sign(message);
    Ok(sig.to_bytes().to_vec())
}

#[wasm_bindgen]
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if public_key.len() != 32 {
        return Err(JsError::new("public key must be 32 bytes"));
    }
    if signature.len() != 64 {
        return Err(JsError::new("signature must be 64 bytes"));
    }
    let vk = VerifyingKey::from_bytes(public_key.try_into().unwrap())
        .map_err(|e| JsError::new(&e.to_string()))?;
    let sig = Signature::from_bytes(signature.try_into().unwrap());
    Ok(vk.verify(message, &sig).is_ok())
}

// ─── Shamir's Secret Sharing ───

#[wasm_bindgen]
pub fn shamir_split(secret: &[u8], shares_count: u8, threshold: u8) -> Result<Vec<u8>, JsError> {
    if threshold < 2 || threshold > shares_count {
        return Err(JsError::new("threshold must be >= 2 and <= shares_count"));
    }

    // sss_rs::share returns Vec<Vec<u8>> — one vec per share
    let shares: Vec<Vec<u8>> = share(secret, shares_count, threshold, true)
        .map_err(|e| JsError::new(&format!("{:?}", e)))?;

    // Pack: [1-byte threshold][1-byte count][per share: 2-byte-BE len + data]
    let mut out = Vec::new();
    out.push(threshold);
    out.push(shares_count);
    for s in shares.iter() {
        let len = s.len() as u16;
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
        out.extend_from_slice(s);
    }
    Ok(out)
}

#[wasm_bindgen]
pub fn shamir_combine(packed_shares: &[u8]) -> Result<Vec<u8>, JsError> {
    if packed_shares.len() < 2 {
        return Err(JsError::new("invalid packed shares"));
    }
    let _threshold = packed_shares[0];
    let _count = packed_shares[1];

    let mut pos = 2usize;
    let mut shares: Vec<Vec<u8>> = Vec::new();
    while pos + 2 <= packed_shares.len() {
        let len = ((packed_shares[pos] as usize) << 8) | (packed_shares[pos + 1] as usize);
        pos += 2;
        if pos + len > packed_shares.len() {
            return Err(JsError::new("truncated share data"));
        }
        shares.push(packed_shares[pos..pos + len].to_vec());
        pos += len;
    }

    reconstruct(&shares, true)
        .map_err(|e| JsError::new(&format!("{:?}", e)))
}

// ─── Helpers ───

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
