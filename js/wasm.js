// wasm.js — Lazy-loading wrapper for ink-wasm + ink-brotli modules
//
// Load order:
// 1. ink_wasm (core) loads uncompressed — provides zstd, crypto, search, etc.
// 2. ink_brotli.wasm.zst is fetched and decompressed via core's zstd
// 3. Brotli module initialized from decompressed bytes
// 4. All paste compression uses brotli. Zstd retained for WASM bootstrapping only.

let coreModule = null;
let corePromise = null;
let brotliModule = null;
let brotliPromise = null;

// ─── Core (ink_wasm) — zstd + crypto + search + markdown + ed25519 + shamir ───

async function initCore() {
  if (coreModule) return coreModule;
  if (corePromise) return corePromise;
  corePromise = (async () => {
    const mod = await import('./ink_wasm.js');
    await mod.default('./ink_wasm_bg.wasm');
    coreModule = mod;
    return mod;
  })();
  return corePromise;
}

// ─── Brotli (ink_brotli) — decompressed from .wasm.zst via core's zstd ───

async function initBrotli() {
  if (brotliModule) return brotliModule;
  if (brotliPromise) return brotliPromise;
  brotliPromise = (async () => {
    const core = await initCore();
    // Fetch zstd-compressed brotli WASM
    const resp = await fetch('./ink_brotli_bg.wasm.zst');
    const compressed = new Uint8Array(await resp.arrayBuffer());
    // Decompress with core's zstd
    const wasmBytes = core.zstd_decompress(compressed);
    // Instantiate brotli module from decompressed bytes
    const mod = await import('./ink_brotli.js');
    await mod.default(wasmBytes.buffer);
    brotliModule = mod;
    return mod;
  })();
  return brotliPromise;
}

// ─── Compression (brotli for data, zstd for WASM bootstrap) ───

export async function brotliCompress(data, quality = 11) {
  const mod = await initBrotli();
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return mod.brotli_compress(input, quality);
}

export async function brotliDecompress(data) {
  const mod = await initBrotli();
  return mod.brotli_decompress(data);
}

// Zstd kept for decompressing .wasm.zst files only
export async function zstdCompress(data, level = 3) {
  const mod = await initCore();
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return mod.zstd_compress(input, level);
}

export async function zstdDecompress(data) {
  const mod = await initCore();
  return mod.zstd_decompress(data);
}

// ─── Argon2id ───

export async function argon2idDerive(password, salt, opts = {}) {
  const mod = await initCore();
  const pw = typeof password === 'string' ? new TextEncoder().encode(password) : password;
  const s = typeof salt === 'string' ? new TextEncoder().encode(salt) : salt;
  const memoryKib = opts.memory || 65536;
  const iterations = opts.iterations || 3;
  const parallelism = opts.parallelism || 1;
  const outputLen = opts.outputLen || 32;
  return mod.argon2id_derive(pw, s, memoryKib, iterations, parallelism, outputLen);
}

// ─── Markdown ───

export async function markdownToHtml(markdown) {
  const mod = await initCore();
  return mod.markdown_to_html(markdown);
}

// ─── Fuzzy search ───

export async function fuzzySearch(text, query, maxResults = 50) {
  const mod = await initCore();
  const json = mod.fuzzy_search(text, query, maxResults);
  return JSON.parse(json);
}

// ─── Ed25519 signatures ───

export async function ed25519Keygen() {
  const mod = await initCore();
  const bytes = mod.ed25519_keygen();
  return { secret: bytes.slice(0, 32), public: bytes.slice(32) };
}

export async function ed25519Sign(secretKey, message) {
  const mod = await initCore();
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  return mod.ed25519_sign(secretKey, msg);
}

export async function ed25519Verify(publicKey, message, signature) {
  const mod = await initCore();
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  return mod.ed25519_verify(publicKey, msg, signature);
}

// ─── Shamir's Secret Sharing ───

export async function shamirSplit(secret, totalShares, threshold) {
  const mod = await initCore();
  const data = typeof secret === 'string' ? new TextEncoder().encode(secret) : secret;
  return mod.shamir_split(data, totalShares, threshold);
}

export async function shamirCombine(packedShares) {
  const mod = await initCore();
  return mod.shamir_combine(packedShares);
}

// ─── Status ───

export async function isLoaded() {
  return coreModule !== null;
}

export async function isBrotliLoaded() {
  return brotliModule !== null;
}

export async function preload() {
  await initCore();
  await initBrotli();
}
