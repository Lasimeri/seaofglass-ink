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

// --- Deniable encryption (plausible deniability) ---
// Pipeline per payload: data (already PGP-encrypted by caller) → brotli compress → AES-GCM (Argon2id)
// Container: [0xDE][16 salt_r][16 salt_d][4-BE real_ct_len][12 iv_r][real_ct][12 iv_d][decoy_ct][random_pad]
// Fixed container size. Both Argon2id derivations always run (constant time).
// Caller handles PGP encryption before calling these functions.

const DENIABLE_CONTAINER = 2048;
const DENIABLE_OVERHEAD = 1 + 16 + 16 + 4 + 12 + 12; // 61 bytes

export async function encryptDeniable(realData, realPassword, decoyData, decoyPassword) {
  // realData / decoyData are strings (PGP-encrypted + base64 from caller, or raw text)
  const realBytes = await compress(new TextEncoder().encode(realData));
  const decoyBytes = await compress(new TextEncoder().encode(decoyData));

  const saltR = crypto.getRandomValues(new Uint8Array(16));
  const saltD = crypto.getRandomValues(new Uint8Array(16));
  const ivR = crypto.getRandomValues(new Uint8Array(12));
  const ivD = crypto.getRandomValues(new Uint8Array(12));

  const keyR = await deriveKeyArgon2(realPassword, saltR);
  const keyD = await deriveKeyArgon2(decoyPassword, saltD);

  const realCt = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivR }, keyR, realBytes));
  const decoyCt = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivD }, keyD, decoyBytes));

  const payloadSize = DENIABLE_OVERHEAD + realCt.length + decoyCt.length;
  if (payloadSize > DENIABLE_CONTAINER) {
    throw new Error(`content too large for deniable container (${payloadSize} > ${DENIABLE_CONTAINER})`);
  }

  const buf = new Uint8Array(DENIABLE_CONTAINER);
  crypto.getRandomValues(buf); // unused bytes are random — indistinguishable from ciphertext
  let p = 0;
  buf[p++] = 0xDE;
  buf.set(saltR, p); p += 16;
  buf.set(saltD, p); p += 16;
  buf[p++] = (realCt.length >> 24) & 0xff;
  buf[p++] = (realCt.length >> 16) & 0xff;
  buf[p++] = (realCt.length >> 8) & 0xff;
  buf[p++] = realCt.length & 0xff;
  buf.set(ivR, p); p += 12;
  buf.set(realCt, p); p += realCt.length;
  buf.set(ivD, p); p += 12;
  buf.set(decoyCt, p);

  return base64url(buf);
}

export async function decryptDeniable(encoded, password) {
  const buf = unbase64url(encoded);
  if (buf.length < DENIABLE_OVERHEAD || buf[0] !== 0xDE) {
    throw new Error('not a deniable container');
  }

  let p = 1;
  const saltR = buf.slice(p, p + 16); p += 16;
  const saltD = buf.slice(p, p + 16); p += 16;
  const realCtLen = (buf[p] << 24) | (buf[p+1] << 16) | (buf[p+2] << 8) | buf[p+3]; p += 4;
  const ivR = buf.slice(p, p + 12); p += 12;
  const realCt = buf.slice(p, p + realCtLen); p += realCtLen;
  const ivD = buf.slice(p, p + 12); p += 12;
  const decoyCt = buf.slice(p);

  // Always derive BOTH keys — constant time prevents timing attacks
  const [keyR, keyD] = await Promise.all([
    deriveKeyArgon2(password, saltR),
    deriveKeyArgon2(password, saltD),
  ]);

  // Try real payload
  try {
    const decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivR }, keyR, realCt));
    return new TextDecoder().decode(await decompress(decrypted));
  } catch { /* wrong key — try decoy */ }

  // Try decoy payload
  try {
    const decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivD }, keyD, decoyCt));
    return new TextDecoder().decode(await decompress(decrypted));
  } catch {
    throw new Error('invalid password');
  }
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

// --- Multi-record chunking with Merkle root ---

const CHUNK_COUNT = 4;
const MAX_CHUNK_DATA = 3400; // leave room for JSON envelope per record

export function splitIntoChunks(data) {
  // data is a base64url string — split into CHUNK_COUNT equal parts
  const chunkSize = Math.ceil(data.length / CHUNK_COUNT);
  const chunks = [];
  for (let i = 0; i < CHUNK_COUNT; i++) {
    chunks.push(data.slice(i * chunkSize, (i + 1) * chunkSize));
  }
  return chunks;
}

export function reassembleChunks(chunks) {
  // chunks is array of strings sorted by index — concatenate
  return chunks.join('');
}

export async function computeMerkleRoot(chunks) {
  // SHA-256 each chunk, then pairwise hash up to root
  // For 4 chunks: root = H(H(c0||c1) || H(c2||c3))
  const leaves = await Promise.all(chunks.map(c => sha256hex(c)));

  // Pad to power of 2 (already 4, which is 2^2)
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] || left; // duplicate last if odd
      next.push(await sha256hex(left + right));
    }
    level = next;
  }
  return level[0];
}

export async function verifyMerkleRoot(chunks, expectedRoot) {
  const computed = await computeMerkleRoot(chunks);
  return computed === expectedRoot;
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
