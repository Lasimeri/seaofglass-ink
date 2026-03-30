// Write via CF Worker, read via DNS-over-HTTPS

const WORKER_URL = 'https://sea-ink.seaofglass.workers.dev';
const DOH_URL = 'https://cloudflare-dns.com/dns-query';
const DOMAIN = 'seaofglass.ink';

export async function store(data) {
  const res = await fetch(`${WORKER_URL}/store`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `store failed: ${res.status}`);
  }
  return (await res.json()).id;
}

export async function load(id) {
  const name = `${id}.d.${DOMAIN}`;
  const res = await fetch(`${DOH_URL}?name=${encodeURIComponent(name)}&type=TXT`, {
    headers: { 'Accept': 'application/dns-json' },
  });
  if (!res.ok) throw new Error(`dns fetch failed: ${res.status}`);

  const dns = await res.json();
  if (!dns.Answer || dns.Answer.length === 0) throw new Error('paste not found');

  // TXT record data comes quoted, strip quotes
  return dns.Answer[0].data.replace(/^"|"$/g, '');
}

export async function remove(id) {
  const res = await fetch(`${WORKER_URL}/paste/${id}`, { method: 'DELETE' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `delete failed: ${res.status}`);
  }
}
