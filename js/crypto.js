// AES-256-GCM encrypt/decrypt
// Pipeline: plaintext -> compress (deflate) -> encrypt -> base64url
// Compression UNDER encryption so ciphertext is smaller

// --- Key management ---

export async function generateKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function exportKey(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return base64url(new Uint8Array(raw));
}

export async function importKey(encoded) {
  const raw = unbase64url(encoded);
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
}

// --- Link/public mode: random key ---

export async function encrypt(plaintext, key) {
  const compressed = await compress(new TextEncoder().encode(plaintext));
  const padded = padToBlock(compressed);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, padded);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), 12);
  return base64url(out);
}

export async function decrypt(encoded, key) {
  const buf = unbase64url(encoded);
  const iv = buf.slice(0, 12);
  const ct = buf.slice(12);
  const decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
  // Try padded format first, fall back to legacy unpadded
  try {
    return new TextDecoder().decode(await decompress(unpad(decrypted)));
  } catch {
    return new TextDecoder().decode(await decompress(decrypted));
  }
}

// --- Password mode: PBKDF2 -> AES-GCM ---

export async function encryptWithPassword(plaintext, password) {
  const compressed = await compress(new TextEncoder().encode(plaintext));
  const padded = padToBlock(compressed);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, padded);
  const out = new Uint8Array(16 + 12 + ct.byteLength);
  out.set(salt);
  out.set(iv, 16);
  out.set(new Uint8Array(ct), 28);
  return base64url(out);
}

export async function decryptWithPassword(encoded, password) {
  const buf = unbase64url(encoded);
  const salt = buf.slice(0, 16);
  const iv = buf.slice(16, 28);
  const ct = buf.slice(28);
  const key = await deriveKey(password, salt);
  const decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
  // Try padded format first, fall back to legacy unpadded
  try {
    return new TextDecoder().decode(await decompress(unpad(decrypted)));
  } catch {
    return new TextDecoder().decode(await decompress(decrypted));
  }
}

async function deriveKey(password, salt) {
  const raw = new TextEncoder().encode(password);
  const material = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// --- Size padding (anonymization) ---

/** Pad compressed data to next 256-byte boundary to prevent size correlation.
 *  Format: [2-byte BE length][compressed data][random padding]
 *  Total is always a multiple of 256. If already aligned, adds an extra 256. */
function padToBlock(compressed) {
  const raw = compressed.byteLength;
  const withHeader = 2 + raw;
  let total = Math.ceil(withHeader / 256) * 256;
  if (total === withHeader) total += 256; // avoid zero-padding ambiguity
  const buf = new Uint8Array(total);
  buf[0] = (raw >> 8) & 0xff;
  buf[1] = raw & 0xff;
  buf.set(compressed, 2);
  // fill remaining bytes with random padding
  crypto.getRandomValues(buf.subarray(2 + raw));
  return buf;
}

/** Strip padding and extract original compressed data. */
function unpad(buf) {
  const len = (buf[0] << 8) | buf[1];
  return buf.slice(2, 2 + len);
}

// --- Compression (deflate) ---

async function compress(data) {
  const cs = new CompressionStream('deflate');
  const w = cs.writable.getWriter();
  w.write(data);
  w.close();
  return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}

async function decompress(data) {
  const ds = new DecompressionStream('deflate');
  const w = ds.writable.getWriter();
  w.write(data);
  w.close();
  return new Uint8Array(await new Response(ds.readable).arrayBuffer());
}

// --- Size estimation ---

export async function estimateSizes(plaintext) {
  const raw = new TextEncoder().encode(plaintext);
  const compressed = await compress(raw);
  const withHeader = 2 + compressed.byteLength;
  let padded = Math.ceil(withHeader / 256) * 256;
  if (padded === withHeader) padded += 256;
  const encrypted = padded + 12 + 16; // padded + iv + auth tag
  const encoded = Math.ceil(encrypted * 4 / 3);
  return { raw: raw.byteLength, compressed: compressed.byteLength, encrypted, encoded };
}

// --- Base64url encoding ---

export function base64url(buf) {
  return btoa(String.fromCharCode(...buf))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unbase64url(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s + '='.repeat((4 - s.length % 4) % 4);
  return Uint8Array.from(atob(pad), c => c.charCodeAt(0));
}
