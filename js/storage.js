// DNS-backed paste storage via Cloudflare Worker + DoH
// v2: Multi-record chunked storage with Merkle root verification

import { splitIntoChunks, reassembleChunks, computeMerkleRoot, verifyMerkleRoot } from './crypto.js?v=11';

export const WORKER_URL = 'https://sea-ink.seaofglass.workers.dev';
const DOH_URL = 'https://cloudflare-dns.com/dns-query';
const DOMAIN = 'seaofglass.ink';

// --- Write operations ---

export async function store(data, title, mode, publicKey, encryptedH, expiry) {
  const chunks = splitIntoChunks(data);
  const merkleRoot = await computeMerkleRoot(chunks);

  const body = {
    chunks,
    merkleRoot,
    mode,
  };
  if (title) body.title = title;
  if (publicKey) body.key = publicKey;
  if (encryptedH) body.h = encryptedH;
  if (expiry) body.expiry = expiry;

  const res = await fetch(`${WORKER_URL}/store`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `store failed: ${res.status}`);
  }
  return res.json(); // { id }
}

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

// --- Read operations ---

// Reassemble chunks from multiple records, verify Merkle root
function reassembleFromRecords(records) {
  // Each record is JSON: {v:2, n:N, i:I, d:"...", ...metadata in chunk 0}
  const parsed = records.map(r => {
    let data = r;
    if (typeof r === 'string') {
      try { data = JSON.parse(r); } catch { data = JSON.parse(r.replace(/^"|"$/g, '')); }
    }
    return data;
  });

  // Check for v2 format (chunked)
  if (parsed.length > 0 && parsed[0].v === 2) {
    // Sort by index
    parsed.sort((a, b) => a.i - b.i);
    const chunks = parsed.map(p => p.d);
    const meta = parsed[0]; // chunk 0 has metadata
    return { chunks, meta };
  }

  // v1 fallback — single record (legacy)
  return { chunks: null, meta: parsed[0] || parsed };
}

// Direct read via worker CF API (no propagation delay — used for admin tab)
export async function loadDirect(id, admin = false) {
  const res = await fetch(`${WORKER_URL}/read/${id}${admin ? '?admin=1' : ''}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `read failed: ${res.status}`);
  }
  const result = await res.json();

  // v2: worker returns {records: [...], meta: {...}}
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

// Read via DoH (cached at edge — used for share links)
export async function load(id) {
  const name = `${id}.d.${DOMAIN}`;
  const res = await fetch(`${DOH_URL}?name=${encodeURIComponent(name)}&type=TXT`, {
    headers: { 'Accept': 'application/dns-json' },
  });
  if (!res.ok) throw new Error(`dns fetch failed: ${res.status}`);
  const dns = await res.json();
  if (!dns.Answer || !dns.Answer.length) throw new Error('paste not found');

  // Multiple TXT records = v2 chunked format
  if (dns.Answer.length > 1) {
    const records = dns.Answer.map(a => {
      let raw = a.data;
      try { raw = JSON.parse(raw); } catch { raw = raw.replace(/^"|"$/g, ''); }
      try { return JSON.parse(raw); } catch { return null; }
    }).filter(Boolean);

    const sorted = records.sort((a, b) => (a.i || 0) - (b.i || 0));
    const chunks = sorted.map(r => r.d);
    const meta = sorted.find(r => r.i === 0) || sorted[0];

    if (meta.mr) {
      const valid = await verifyMerkleRoot(chunks, meta.mr);
      if (!valid) throw new Error('merkle root verification failed — data corrupted');
    }

    return { ...meta, d: reassembleChunks(chunks) };
  }

  // Single record — v1 or small v2
  let raw = dns.Answer[0].data;
  try { raw = JSON.parse(raw); } catch { raw = raw.replace(/^"|"$/g, ''); }
  try { return JSON.parse(raw); }
  catch { throw new Error('corrupt paste data'); }
}

// --- Public directory ---

export async function listPublic() {
  const res = await fetch(`${WORKER_URL}/public`);
  if (!res.ok) throw new Error('failed to load');
  return (await res.json()).pastes || [];
}
