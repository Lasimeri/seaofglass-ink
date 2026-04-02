// DNS-backed paste storage via Cloudflare Worker + DoH

export const WORKER_URL = 'https://sea-ink.seaofglass.workers.dev';
const DOH_URL = 'https://cloudflare-dns.com/dns-query';
const DOMAIN = 'seaofglass.ink';

// --- Write operations ---

export async function store(data, title, mode, publicKey, encryptedH, expiry) {
  const body = { data, mode };
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
  return res.json(); // { id, deleteToken }
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

// Direct read via worker CF API (no propagation delay — used for admin tab)
export async function loadDirect(id, admin = false) {
  const res = await fetch(`${WORKER_URL}/read/${id}${admin ? '?admin=1' : ''}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `read failed: ${res.status}`);
  }
  return res.json();
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
