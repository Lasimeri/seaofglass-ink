// pgp-worker.js — Web Worker for PGP keygen (keeps UI responsive)
// Runs in a separate thread. Communicates via postMessage.

let pgpMod = null;

async function initPgp() {
  if (pgpMod) return;
  // Load brotli to decompress PGP WASM
  const coreMod = await import('./ink_wasm.js');
  await coreMod.default();
  const coreResp = await fetch(new URL('./ink_brotli_bg.wasm.zst', import.meta.url));
  const coreCompressed = new Uint8Array(await coreResp.arrayBuffer());
  const brotliBytes = coreMod.zstd_decompress(coreCompressed);
  const brotliMod = await import('./ink_brotli.js');
  await brotliMod.default(brotliBytes.buffer.slice(brotliBytes.byteOffset, brotliBytes.byteOffset + brotliBytes.byteLength));

  const pgpResp = await fetch(new URL('./ink_pgp_bg.wasm.br', import.meta.url));
  const pgpCompressed = new Uint8Array(await pgpResp.arrayBuffer());
  const pgpBytes = brotliMod.brotli_decompress(pgpCompressed);
  pgpMod = await import('./ink_pgp.js');
  await pgpMod.default(pgpBytes.buffer.slice(pgpBytes.byteOffset, pgpBytes.byteOffset + pgpBytes.byteLength));
}

self.onmessage = async (e) => {
  const { type, name, email, passphrase, data, publicKey, secretKey } = e.data;

  try {
    self.postMessage({ type: 'progress', phase: 'loading wasm...' });
    await initPgp();

    if (type === 'keygen') {
      self.postMessage({ type: 'progress', phase: 'generating 4096-bit rsa keypair...' });
      const json = pgpMod.pgp_keygen(name, email, passphrase);
      self.postMessage({ type: 'result', result: JSON.parse(json) });
    } else if (type === 'encrypt') {
      self.postMessage({ type: 'progress', phase: 'encrypting with pgp...' });
      const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
      const ct = pgpMod.pgp_encrypt(input, publicKey);
      self.postMessage({ type: 'result', result: ct });
    } else if (type === 'decrypt') {
      self.postMessage({ type: 'progress', phase: 'decrypting with pgp...' });
      const pt = pgpMod.pgp_decrypt(data, secretKey, passphrase);
      self.postMessage({ type: 'result', result: pt });
    }
  } catch (err) {
    self.postMessage({ type: 'error', error: err.message || String(err) });
  }
};
