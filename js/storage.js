const WORKER_URL = 'https://sea-ink.seaofglass.workers.dev';
const DOH_URL = 'https://cloudflare-dns.com/dns-query';
const DOMAIN = 'seaofglass.ink';

export async function store(data, title, mode, publicKey) {
  const body = { data, mode };
  if (title) body.title = title;
  if (publicKey) body.key = publicKey;
  const res = await fetch(`${WORKER_URL}/store`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `store failed: ${res.status}`);
  }
  return res.json();
}

export async function load(id) {
  const name = `${id}.d.${DOMAIN}`;
  const res = await fetch(`${DOH_URL}?name=${encodeURIComponent(name)}&type=TXT`, {
    headers: { 'Accept': 'application/dns-json' },
  });
  if (!res.ok) throw new Error(`dns fetch failed: ${res.status}`);
  const dns = await res.json();
  if (!dns.Answer || !dns.Answer.length) throw new Error('paste not found');
  const raw = dns.Answer[0].data.replace(/^"|"$/g, '');
  try { return JSON.parse(raw); }
  catch { return { d: raw, m: 'link', c: 0 }; }
}

export async function remove(id) {
  const res = await fetch(`${WORKER_URL}/paste/${id}`, { method: 'DELETE' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `delete failed: ${res.status}`);
  }
}

export async function listPublic() {
  const res = await fetch(`${WORKER_URL}/public`);
  if (!res.ok) throw new Error('failed to load');
  return (await res.json()).pastes || [];
}
