// AES-256-GCM encrypt/decrypt
// Pipeline: plaintext -> compress (brotli) -> pad -> encrypt -> base64url
// Compression UNDER encryption so ciphertext is smaller
// Backward compat: decompress auto-detects brotli (BR prefix) vs zstd (magic) vs deflate

import { brotliCompress, brotliDecompress, zstdDecompress, argon2idDerive } from './wasm.js?v=10';

const BROTLI_MAGIC = [0x42, 0x52]; // "BR" prefix for brotli-compressed data
const ARGON2_MAGIC = [0x49, 0x4E, 0x4B, 0x31]; // "INK1"

function isBrotli(data) {
  return data.length >= 2 && data[0] === 0x42 && data[1] === 0x52;
}

function isZstd(data) {
  return data.length >= 4 && data[0] === 0x28 && data[1] === 0xB5 && data[2] === 0x2F && data[3] === 0xFD;
}

function isArgon2Format(buf) {
  return buf.length >= 4 && buf[0] === 0x49 && buf[1] === 0x4E && buf[2] === 0x4B && buf[3] === 0x31;
}

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

// --- Password mode: Argon2id -> AES-GCM (with PBKDF2 fallback for old pastes) ---
// New format: [4-byte "INK1"][16-byte salt][12-byte IV][ciphertext]
// Old format: [16-byte salt][12-byte IV][ciphertext] (PBKDF2)

export async function encryptWithPassword(plaintext, password) {
  const compressed = await compress(new TextEncoder().encode(plaintext));
  const padded = padToBlock(compressed);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyArgon2(password, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, padded);
  // INK1 magic + salt + iv + ciphertext
  const out = new Uint8Array(4 + 16 + 12 + ct.byteLength);
  out.set(ARGON2_MAGIC);
  out.set(salt, 4);
  out.set(iv, 20);
  out.set(new Uint8Array(ct), 32);
  return base64url(out);
}

export async function decryptWithPassword(encoded, password) {
  const buf = unbase64url(encoded);
  let salt, iv, ct, key;

  if (isArgon2Format(buf)) {
    // New Argon2id format
    salt = buf.slice(4, 20);
    iv = buf.slice(20, 32);
    ct = buf.slice(32);
    key = await deriveKeyArgon2(password, salt);
  } else {
    // Legacy PBKDF2 format
    salt = buf.slice(0, 16);
    iv = buf.slice(16, 28);
    ct = buf.slice(28);
    key = await deriveKeyPBKDF2(password, salt);
  }

  const decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
  try {
    return new TextDecoder().decode(await decompress(unpad(decrypted)));
  } catch {
    return new TextDecoder().decode(await decompress(decrypted));
  }
}

async function deriveKeyArgon2(password, salt) {
  const rawKey = await argon2idDerive(password, salt, {
    memory: 65536,    // 64MB
    iterations: 3,
    parallelism: 1,
    outputLen: 32,
  });
  return crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function deriveKeyPBKDF2(password, salt) {
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

// --- Compression ---

// New pastes use zstd; old pastes used deflate. Auto-detect on decompress.
async function compress(data) {
  try {
    // Brotli quality 11 (max compression). Prepend "BR" magic for detection.
    const compressed = await brotliCompress(data, 11);
    const out = new Uint8Array(2 + compressed.length);
    out[0] = 0x42; out[1] = 0x52; // "BR"
    out.set(compressed, 2);
    return out;
  } catch {
    // WASM not available — fall back to deflate
    return deflateCompress(data);
  }
}

async function decompress(data) {
  if (isBrotli(data)) {
    // Strip "BR" prefix, decompress brotli
    return brotliDecompress(data.slice(2));
  }
  if (isZstd(data)) {
    // Legacy zstd-compressed pastes
    return zstdDecompress(data);
  }
  // Legacy deflate-compressed pastes
  return deflateDecompress(data);
}

// Legacy deflate (fallback for old pastes + WASM-unavailable environments)
async function deflateCompress(data) {
  const cs = new CompressionStream('deflate');
  const w = cs.writable.getWriter();
  w.write(data);
  w.close();
  return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}

async function deflateDecompress(data) {
  const ds = new DecompressionStream('deflate');
  const w = ds.writable.getWriter();
  w.write(data);
  w.close();
  return new Uint8Array(await new Response(ds.readable).arrayBuffer());
}

// --- Size estimation ---

export async function estimateSizes(plaintext) {
  const raw = new TextEncoder().encode(plaintext);
  let compressed;
  try { compressed = await compress(raw); }
  catch { compressed = await deflateCompress(raw); }
  const withHeader = 2 + compressed.byteLength;
  let padded = Math.ceil(withHeader / 256) * 256;
  if (padded === withHeader) padded += 256;
  const encrypted = padded + 12 + 16; // padded + iv + auth tag
  const encoded = Math.ceil(encrypted * 4 / 3);
  return { raw: raw.byteLength, compressed: compressed.byteLength, encrypted, encoded };
}

// --- Delete hash helpers (no compression/padding — for short metadata) ---

export async function sha256hex(input) {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function encryptRaw(plaintext, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext)
  );
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), 12);
  return base64url(out);
}

export async function encryptRawWithPassword(plaintext, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyArgon2(password, salt);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext)
  );
  // INK1 magic + salt + iv + ciphertext
  const out = new Uint8Array(4 + 16 + 12 + ct.byteLength);
  out.set(ARGON2_MAGIC);
  out.set(salt, 4);
  out.set(iv, 20);
  out.set(new Uint8Array(ct), 32);
  return base64url(out);
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
