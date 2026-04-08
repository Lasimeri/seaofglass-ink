// Paste storage: R2 (permanent) + DNS TXT records (expiring)
// R2: single JSON object per paste, read/write via worker API
// DNS: 4-chunk v2 format for expiring pastes, read via DoH or worker API

import { splitIntoChunks, reassembleChunks, computeMerkleRoot, verifyMerkleRoot } from './crypto.js?v=20';

export const WORKER_URL = 'https://sea-ink.seaofglass.workers.dev';
const DOH_URL = 'https://cloudflare-dns.com/dns-query';
const DOMAIN = 'seaofglass.ink';

// --- Write ---

export async function store(data, title, mode, publicKey, encryptedH, expiry, plainTitle, shareKey) {
  const body = { data, mode };
  if (title) body.title = title;
  if (plainTitle) body.plainTitle = plainTitle;
  if (shareKey) body.shareKey = shareKey;
  if (publicKey) body.key = publicKey;
  if (encryptedH) body.h = encryptedH;

  // Expiring pastes go to DNS (4 chunks)
  if (expiry) {
    const chunks = splitIntoChunks(data);
    const merkleRoot = await computeMerkleRoot(chunks);
    body.chunks = chunks;
    body.merkleRoot = merkleRoot;
    body.expiry = expiry;
  }

  const res = await fetch(`${WORKER_URL}/store`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `store failed: ${res.status}`);
  }
  return res.json(); // { id, storage }
}

// --- Delete ---

export async function remove(id, deleteToken, key, password) {
  const body = { token: deleteToken };
  if (key) body.key = key;
  if (password) body.password = password;
  const res = await fetch(`${WORKER_URL}/paste/${id}`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `delete failed: ${res.status}`);
  }
}

// --- Read ---

// Worker API read (used for all R2 pastes and admin tab)
export async function loadDirect(id, admin = false) {
  const res = await fetch(`${WORKER_URL}/read/${id}${admin ? '?admin=1' : ''}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `read failed: ${res.status}`);
  }
  const result = await res.json();

  // R2 response: flat object with d, m, c, t, k fields
  if (result.d && !result.records) return result;

  // DNS v2 chunked response
  if (result.records) {
    const chunks = result.records.sort((a, b) => a.i - b.i).map(r => r.d);
    const meta = result.records.find(r => r.i === 0) || {};
    if (meta.mr) {
      const valid = await verifyMerkleRoot(chunks, meta.mr);
      if (!valid) throw new Error('merkle root verification failed — data corrupted');
    }
    return { ...meta, d: reassembleChunks(chunks) };
  }

  // v1 fallback
  return result;
}

// Smart read: try worker API first (covers R2 + DNS), fall back to DoH for DNS pastes
export async function load(id) {
  try {
    return await loadDirect(id);
  } catch (e) {
    // If worker returns 404, try DoH as last resort (edge-cached DNS pastes)
    if (!e.message.includes('not found')) throw e;
  }
  return loadFromDoH(id);
}

// DoH fallback for DNS expiring pastes
async function loadFromDoH(id) {
  const name = `${id}.d.${DOMAIN}`;
  const res = await fetch(`${DOH_URL}?name=${encodeURIComponent(name)}&type=TXT`, {
    headers: { 'Accept': 'application/dns-json' },
  });
  if (!res.ok) throw new Error(`dns fetch failed: ${res.status}`);
  const dns = await res.json();
  if (!dns.Answer || !dns.Answer.length) throw new Error('paste not found');

  function parseTxtRecord(data) {
    let raw = data;
    if (raw.includes('" "')) raw = raw.replace(/" "/g, '');
    try { raw = JSON.parse(raw); } catch { raw = raw.replace(/^"|"$/g, ''); }
    try { return JSON.parse(raw); } catch { return null; }
  }

  if (dns.Answer.length > 1) {
    const records = dns.Answer.map(a => parseTxtRecord(a.data)).filter(Boolean);
    const sorted = records.sort((a, b) => (a.i || 0) - (b.i || 0));
    const chunks = sorted.map(r => r.d);
    const meta = sorted.find(r => r.i === 0) || sorted[0] || {};
    if (meta && meta.mr) {
      const valid = await verifyMerkleRoot(chunks, meta.mr);
      if (!valid) throw new Error('merkle root verification failed — data corrupted');
    }
    return { ...meta, d: reassembleChunks(chunks) };
  }

  const parsed = parseTxtRecord(dns.Answer[0].data);
  if (!parsed) throw new Error('corrupt paste data');
  return parsed;
}

// --- PGP handshake ---

export async function fetchWorkerKey() {
  const res = await fetch(`${WORKER_URL}/worker-key`);
  if (!res.ok) throw new Error('failed to fetch worker key');
  return res.json();
}

export async function handshake(readerPublicKey) {
  const res = await fetch(`${WORKER_URL}/handshake`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey: readerPublicKey }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `handshake failed: ${res.status}`);
  }
  return res.json();
}

// --- Public directory ---

export async function listPublic() {
  const res = await fetch(`${WORKER_URL}/public`);
  if (!res.ok) throw new Error('failed to load');
  return (await res.json()).pastes || [];
}
