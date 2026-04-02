// wasm.js — Lazy-loading wrapper for ink-wasm modules
// Loads the WASM binary on first use, not on page load.

let wasmModule = null;
let initPromise = null;

async function init() {
  if (wasmModule) return wasmModule;
  if (initPromise) return initPromise;
  initPromise = (async () => {
    const mod = await import('./ink_wasm.js');
    await mod.default('./ink_wasm_bg.wasm');
    wasmModule = mod;
    return mod;
  })();
  return initPromise;
}

// ─── Compression ───

export async function zstdCompress(data, level = 3) {
  const mod = await init();
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return mod.zstd_compress(input, level);
}

export async function zstdDecompress(data) {
  const mod = await init();
  return mod.zstd_decompress(data);
}

// ─── Argon2id ───

export async function argon2idDerive(password, salt, opts = {}) {
  const mod = await init();
  const pw = typeof password === 'string' ? new TextEncoder().encode(password) : password;
  const s = typeof salt === 'string' ? new TextEncoder().encode(salt) : salt;
  const memoryKib = opts.memory || 65536;  // 64MB default
  const iterations = opts.iterations || 3;
  const parallelism = opts.parallelism || 1; // WASM is single-threaded
  const outputLen = opts.outputLen || 32;    // 256-bit key
  return mod.argon2id_derive(pw, s, memoryKib, iterations, parallelism, outputLen);
}

// ─── Markdown ───

export async function markdownToHtml(markdown) {
  const mod = await init();
  return mod.markdown_to_html(markdown);
}

// ─── Fuzzy search ───

export async function fuzzySearch(text, query, maxResults = 50) {
  const mod = await init();
  const json = mod.fuzzy_search(text, query, maxResults);
  return JSON.parse(json);
}

// ─── Status ───

export async function isLoaded() {
  return wasmModule !== null;
}

export async function preload() {
  await init();
}
