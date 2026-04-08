import { argon2id_derive } from '../argon2-wasm/pkg/argon2_worker';

// ─────────────────────────────────────────────
// Types & Interfaces
// ─────────────────────────────────────────────

interface Env {
	CF_API_TOKEN: string;
	CF_ZONE_ID: string;
	PURGE_SECRET: string;
	WORKER_RSA_PUBLIC: string;
	WORKER_RSA_PRIVATE: string;
	PASTE_BUCKET: R2Bucket;
}

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

const CF_API = 'https://api.cloudflare.com/client/v4';
const DOMAIN = 'seaofglass.ink';
const ALLOWED_ORIGIN = `https://${DOMAIN}`;
const MAX_RECORD_LEN = 4000;
const DELETE_TTL = 600; // 10 minutes

// Rate limiting (per-isolate, resets on cold start)
const rateMap = new Map<string, number[]>();
const RATE_LIMIT = 10;
const RATE_WINDOW = 60_000;

// ─────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────

function rateOk(ip: string): boolean {
	const now = Date.now();
	const hits = (rateMap.get(ip) || []).filter(t => now - t < RATE_WINDOW);
	if (hits.length >= RATE_LIMIT) return false;
	hits.push(now);
	rateMap.set(ip, hits);
	return true;
}

function cors(res: Response): Response {
	const h = new Headers(res.headers);
	h.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
	h.set('Access-Control-Allow-Methods', 'POST, DELETE, GET, OPTIONS');
	h.set('Access-Control-Allow-Headers', 'Content-Type');
	h.set('Access-Control-Max-Age', '86400');
	h.set('Vary', 'Origin');
	return new Response(res.body, { status: res.status, headers: h });
}

function json(data: unknown, status = 200): Response {
	return cors(new Response(JSON.stringify(data), {
		status,
		headers: { 'Content-Type': 'application/json' },
	}));
}

function err(msg: string, status = 400): Response {
	return json({ error: msg }, status);
}

async function sha256hex(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const hash = await crypto.subtle.digest('SHA-256', data);
	return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function unbase64url(str: string): Uint8Array {
	const s = str.replace(/-/g, '+').replace(/_/g, '/');
	const pad = s + '='.repeat((4 - s.length % 4) % 4);
	const binary = atob(pad);
	const buf = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
	return buf;
}

async function decryptRawWithKey(encoded: string, keyStr: string): Promise<string> {
	const buf = unbase64url(encoded);
	const iv = buf.slice(0, 12);
	const ct = buf.slice(12);
	const key = await crypto.subtle.importKey('raw', unbase64url(keyStr), 'AES-GCM', false, ['decrypt']);
	const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
	return new TextDecoder().decode(decrypted);
}

async function decryptRawWithPassword(encoded: string, password: string): Promise<string> {
	const buf = unbase64url(encoded);
	let salt: Uint8Array, iv: Uint8Array, ct: Uint8Array, key: CryptoKey;

	if (buf.length >= 4 && buf[0] === 0x49 && buf[1] === 0x4E && buf[2] === 0x4B && buf[3] === 0x31) {
		salt = buf.slice(4, 20);
		iv = buf.slice(20, 32);
		ct = buf.slice(32);
		const rawKey = argon2id_derive(
			new TextEncoder().encode(password), salt,
			65536, 3, 1, 32
		);
		key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
	} else {
		salt = buf.slice(0, 16);
		iv = buf.slice(16, 28);
		ct = buf.slice(28);
		const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
		key = await crypto.subtle.deriveKey(
			{ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
			material,
			{ name: 'AES-GCM', length: 256 },
			false, ['decrypt']
		);
	}

	const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
	return new TextDecoder().decode(decrypted);
}

function isLegacyHash(h: string): boolean {
	return h.length === 64 && /^[a-f0-9]{64}$/.test(h);
}

// ─────────────────────────────────────────────
// DNS Operations (for expiring pastes only)
// ─────────────────────────────────────────────

const DNS_CHUNK_COUNT = 4;
const DNS_CHUNK0_RESERVE = 2000;
const DNS_MAX_RECORD = 3200;

async function dnsCreate(env: Env, name: string, content: string): Promise<{ ok: boolean; error?: string }> {
	const res = await fetch(`${CF_API}/zones/${env.CF_ZONE_ID}/dns_records`, {
		method: 'POST',
		headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}`, 'Content-Type': 'application/json' },
		body: JSON.stringify({ type: 'TXT', name: `${name}.d.${DOMAIN}`, content, ttl: 1 }),
	});
	if (!res.ok) {
		const body: any = await res.json().catch(() => ({}));
		return { ok: false, error: body?.errors?.[0]?.message || `cf api ${res.status}` };
	}
	return { ok: true };
}

async function dnsFind(env: Env, name: string): Promise<any[]> {
	const res = await fetch(
		`${CF_API}/zones/${env.CF_ZONE_ID}/dns_records?name=${name}.d.${DOMAIN}&type=TXT`,
		{ headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` } },
	);
	const data: any = await res.json();
	return data.result || [];
}

async function dnsDelete(env: Env, recordId: string): Promise<void> {
	await fetch(`${CF_API}/zones/${env.CF_ZONE_ID}/dns_records/${recordId}`, {
		method: 'DELETE',
		headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` },
	});
}

async function dnsUpdate(env: Env, recordId: string, name: string, content: string): Promise<boolean> {
	const res = await fetch(`${CF_API}/zones/${env.CF_ZONE_ID}/dns_records/${recordId}`, {
		method: 'PUT',
		headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}`, 'Content-Type': 'application/json' },
		body: JSON.stringify({ type: 'TXT', name, content, ttl: 1 }),
	});
	return res.ok;
}

async function dnsListAll(env: Env): Promise<any[]> {
	let allRecords: any[] = [];
	let page = 1;
	while (true) {
		const res = await fetch(
			`${CF_API}/zones/${env.CF_ZONE_ID}/dns_records?type=TXT&per_page=100&page=${page}`,
			{ headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` } },
		);
		const data: any = await res.json();
		const records = data.result || [];
		allRecords = allRecords.concat(records.filter((r: any) => r.name.endsWith(`.d.${DOMAIN}`)));
		if (records.length < 100) break;
		page++;
	}
	return allRecords;
}

// ─────────────────────────────────────────────
// Delete token validation (shared by R2 and DNS)
// ─────────────────────────────────────────────

async function validateDeleteToken(parsed: any, token: string, deleteBody: any): Promise<string | null> {
	if (!parsed.h) return 'delete token revoked';

	const now = Math.floor(Date.now() / 3600000) * 3600;
	if (parsed.c && (now - parsed.c) > DELETE_TTL) return 'delete token expired';

	const tokenHash = await sha256hex(token);
	if (isLegacyHash(parsed.h)) {
		return parsed.h !== tokenHash ? 'invalid delete token' : null;
	}

	const { key, password } = deleteBody;
	let expectedHash: string;
	try {
		if (key) expectedHash = await decryptRawWithKey(parsed.h, key);
		else if (password) expectedHash = await decryptRawWithPassword(parsed.h, password);
		else return 'missing decryption key';
	} catch { return 'invalid key'; }
	return expectedHash !== tokenHash ? 'invalid delete token' : null;
}

// ─────────────────────────────────────────────
// Route Handlers
// ─────────────────────────────────────────────

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === 'OPTIONS') {
			return cors(new Response(null, { status: 204 }));
		}

		const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
		if (!rateOk(ip)) return err('rate limited', 429);

		// ── POST /store ─────────────────────────────
		if (request.method === 'POST' && url.pathname === '/store') {
			const ct = request.headers.get('Content-Type');
			if (!ct || !ct.includes('application/json')) return err('invalid content type');

			let body: any;
			try { body = await request.json(); } catch { return err('invalid json'); }

			const { data, title, plainTitle, shareKey, mode, key: publicKey, h: encryptedH, expiry, chunks, merkleRoot } = body;
			if (!['link', 'password', 'public', 'burn', 'deniable'].includes(mode)) return err('invalid mode');

			const id = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
			const now = Math.floor(Date.now() / 3600000) * 3600;
			const expirySeconds = typeof expiry === 'number' && expiry > 0 ? expiry : undefined;

			// ── DNS path: expiring pastes use DNS TXT records (4 chunks) ──
			if (expirySeconds && chunks && Array.isArray(chunks) && merkleRoot) {
				for (let i = 0; i < chunks.length; i++) {
					const rec: Record<string, unknown> = { v: 2, n: chunks.length, i, d: chunks[i] };
					if (i === 0) {
						rec.mr = merkleRoot;
						rec.m = mode;
						rec.c = now;
						if (encryptedH) rec.h = encryptedH;
						if (title) rec.t = title;
						if (publicKey && mode === 'public') rec.k = publicKey;
						rec.e = now + expirySeconds;
					}
					const content = JSON.stringify(rec);
					if (content.length > MAX_RECORD_LEN) return err(`chunk ${i} too large (${content.length})`, 413);
					const result = await dnsCreate(env, id, content);
					if (!result.ok) return err(`chunk ${i} storage failed: ${result.error}`, 500);
				}
				return json({ id, storage: 'dns' }, 201);
			}

			// ── R2 path: permanent pastes go to R2 ──
			if (!data || typeof data !== 'string') return err('missing data');
			const paste: Record<string, unknown> = { d: data, m: mode, c: now };
			if (encryptedH) paste.h = encryptedH;
			if (title) paste.t = title;
			if (publicKey && mode === 'public') paste.k = publicKey;

			const meta: Record<string, string> = { mode, created: String(now) };
			if (plainTitle) meta.plainTitle = String(plainTitle).slice(0, 100);
			if (shareKey) meta.shareKey = String(shareKey);
			await env.PASTE_BUCKET.put(id, JSON.stringify(paste), { customMetadata: meta });
			return json({ id, storage: 'r2' }, 201);
		}

		// ── DELETE /paste/:id ────────────────────────
		if (request.method === 'DELETE' && url.pathname.startsWith('/paste/')) {
			const id = url.pathname.slice(7);
			if (!/^[a-f0-9]{8,12}$/.test(id)) return err('invalid id');

			let deleteBody: any;
			try { deleteBody = await request.json(); } catch { return err('invalid json'); }
			const token = deleteBody?.token;
			if (!token || typeof token !== 'string') return err('missing delete token', 403);

			// Try R2 first
			const obj = await env.PASTE_BUCKET.get(id);
			if (obj) {
				const parsed = JSON.parse(await obj.text());
				const rejection = await validateDeleteToken(parsed, token, deleteBody);
				if (rejection) return err(rejection, 403);
				await env.PASTE_BUCKET.delete(id);
				return json({ deleted: true });
			}

			// Fall back to DNS
			const records = await dnsFind(env, id);
			if (!records.length) return err('not found', 404);

			let parsed: any;
			for (const rec of records) {
				try {
					const p = JSON.parse(rec.content);
					if (p.h) { parsed = p; break; }
					if (!parsed) parsed = p;
				} catch {}
			}
			if (!parsed) return err('corrupt record', 500);

			const rejection = await validateDeleteToken(parsed, token, deleteBody);
			if (rejection) return err(rejection, 403);

			for (const rec of records) await dnsDelete(env, rec.id);
			return json({ deleted: true });
		}

		// ── POST /revoke/:id ────────────────────────
		if (request.method === 'POST' && url.pathname.startsWith('/revoke/')) {
			const id = url.pathname.slice(8);
			if (!/^[a-f0-9]{8,12}$/.test(id)) return err('invalid id');

			let body: any;
			try { body = await request.json(); } catch { return err('invalid json'); }
			const { token } = body;
			if (!token) return err('missing token', 403);

			// Try R2
			const obj = await env.PASTE_BUCKET.get(id);
			if (obj) {
				const parsed = JSON.parse(await obj.text());
				if (!parsed.h) return json({ revoked: true });
				const rejection = await validateDeleteToken(parsed, token, body);
				if (rejection) return err(rejection, 403);
				delete parsed.h;
				await env.PASTE_BUCKET.put(id, JSON.stringify(parsed));
				return json({ revoked: true });
			}

			// Fall back to DNS
			const records = await dnsFind(env, id);
			if (!records.length) return err('not found', 404);
			let parsed: any;
			try { parsed = JSON.parse(records[0].content); } catch { return err('corrupt record', 500); }
			if (!parsed.h) return json({ revoked: true });
			const rejection = await validateDeleteToken(parsed, token, body);
			if (rejection) return err(rejection, 403);
			delete parsed.h;
			await dnsUpdate(env, records[0].id, records[0].name, JSON.stringify(parsed));
			return json({ revoked: true });
		}

		// ── GET /read/:id ───────────────────────────
		if ((request.method === 'GET' || request.method === 'HEAD') && url.pathname.startsWith('/read/')) {
			const id = url.pathname.slice(6);
			if (!/^[a-f0-9]{8,12}$/.test(id)) return err('invalid id');

			// Try R2 first
			const obj = await env.PASTE_BUCKET.get(id);
			if (obj) {
				const parsed = JSON.parse(await obj.text());
				// Burn after read
				if (parsed.m === 'burn' && !url.searchParams.has('admin')) {
					await env.PASTE_BUCKET.delete(id);
				}
				delete parsed.h; // strip delete hash
				return json(parsed);
			}

			// Fall back to DNS (expiring pastes)
			const records = await dnsFind(env, id);
			if (!records.length) return err('not found', 404);

			const allParsed: any[] = [];
			for (const rec of records) {
				try { allParsed.push(JSON.parse(rec.content)); } catch {}
			}
			if (!allParsed.length) return err('corrupt record', 500);

			const isV2 = allParsed.some(p => p.v === 2);
			if (isV2) {
				const meta = allParsed.find(p => p.i === 0) || allParsed[0];
				if (meta.e && Math.floor(Date.now() / 1000) > meta.e) {
					for (const rec of records) await dnsDelete(env, rec.id);
					return err('paste expired', 410);
				}
				const cleanRecords = allParsed.map(p => { const c = { ...p }; delete c.h; return c; });
				if (meta.m === 'burn' && !url.searchParams.has('admin')) {
					for (const rec of records) await dnsDelete(env, rec.id);
				}
				return json({ records: cleanRecords });
			}

			// v1 fallback
			const parsed = allParsed[0];
			if (parsed.e && Math.floor(Date.now() / 1000) > parsed.e) {
				for (const rec of records) await dnsDelete(env, rec.id);
				return err('paste expired', 410);
			}
			delete parsed.h;
			if (parsed.m === 'burn' && !url.searchParams.has('admin')) {
				for (const rec of records) await dnsDelete(env, rec.id);
			}
			return json(parsed);
		}

		// ════════════════════════════════════════════
		// Utility endpoints (must be before /s/:id catch-all)
		// ════════════════════════════════════════════

		// ── GET /s/blot — ASCII Rorschach inkblot ────
		if (request.method === 'GET' && url.pathname === '/s/blot') {
			const ts = String(Date.now());
			const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ts));
			const bytes = new Uint8Array(hashBuf);
			const hashHex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
			const chars = ['█', '▓', '▒', '░', ' '];
			const half = 8;
			const rows: string[] = [];
			for (let y = 0; y < 15; y++) {
				const left: string[] = [];
				for (let x = 0; x < half; x++) {
					const idx = (y * half + x) % bytes.length;
					left.push(chars[bytes[idx] % chars.length]);
				}
				const center = chars[bytes[(y * half + half) % bytes.length] % chars.length];
				const right = [...left].reverse();
				rows.push(left.join('') + center + right.join(''));
			}
			const blot = rows.join('\n') + '\n\n' + hashHex;
			return cors(new Response(blot, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } }));
		}

		// ── GET/POST /s/canary — warrant canary ─────
		if (url.pathname === '/s/canary') {
			if (request.method === 'GET') {
				const obj = await env.PASTE_BUCKET.get('canary:current');
				if (!obj) return err('no canary set', 404);
				const data = JSON.parse(await obj.text());
				return json(data);
			}
			if (request.method === 'POST') {
				let body: any;
				try { body = await request.json(); } catch { return err('invalid json'); }
				if (!body.secret || body.secret !== env.PURGE_SECRET) return err('unauthorized', 403);
				if (!body.message || typeof body.message !== 'string') return err('missing message');
				const canary = { message: body.message, updated: new Date().toISOString() };
				await env.PASTE_BUCKET.put('canary:current', JSON.stringify(canary));
				return json(canary, 201);
			}
		}

		// ── GET/POST /s/drift — anonymous paste exchange ──
		if (url.pathname === '/s/drift') {
			const DRIFT_KEY = 'drift:queue';
			if (request.method === 'GET') {
				const obj = await env.PASTE_BUCKET.head(DRIFT_KEY);
				return json({ available: !!obj });
			}
			if (request.method === 'POST') {
				const ct = request.headers.get('Content-Type');
				if (!ct || !ct.includes('application/json')) return err('invalid content type');
				let body: any;
				try { body = await request.json(); } catch { return err('invalid json'); }
				if (!body.data || typeof body.data !== 'string') return err('missing data');
				if (body.data.length > 50000) return err('too large (50KB max)', 413);
				const existing = await env.PASTE_BUCKET.get(DRIFT_KEY);
				const now = Math.floor(Date.now() / 1000);
				await env.PASTE_BUCKET.put(DRIFT_KEY, JSON.stringify({ d: body.data, t: now }));
				if (existing) {
					const old = JSON.parse(await existing.text());
					return json({ found: true, data: old.d, drifted: now - old.t });
				}
				return json({ found: false, message: 'your message is adrift' });
			}
			return err('method not allowed', 405);
		}

		// ── GET/POST /s/seal — time-locked encryption ────
		if (url.pathname === '/s/seal' && request.method === 'POST') {
			const ct = request.headers.get('Content-Type');
			if (!ct || !ct.includes('application/json')) return err('invalid content type');
			let body: any;
			try { body = await request.json(); } catch { return err('invalid json'); }
			const { data, unlock, title } = body;
			if (!data || typeof data !== 'string') return err('missing data');
			if (!unlock || typeof unlock !== 'number') return err('missing unlock timestamp');
			if (data.length > 100000) return err('too large (100KB max)', 413);
			const now = Math.floor(Date.now() / 1000);
			if (unlock <= now) return err('unlock must be in the future');
			if (unlock - now > 365 * 86400) return err('max 1 year lock');
			const id = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
			await env.PASTE_BUCKET.put(`seal:${id}`, JSON.stringify({ d: data, u: unlock, t: now, ...(title ? { n: title } : {}) }), {
				customMetadata: { unlock: String(unlock) },
			});
			return json({ id, unlock, url: `https://${DOMAIN}/s/seal/${id}` }, 201);
		}
		if (url.pathname.startsWith('/s/seal/') && (request.method === 'GET' || request.method === 'HEAD')) {
			const id = url.pathname.slice(8);
			if (!/^[a-f0-9]{8,12}$/.test(id)) return err('invalid id');
			const obj = await env.PASTE_BUCKET.get(`seal:${id}`);
			if (!obj) return err('not found', 404);
			const sealed = JSON.parse(await obj.text());
			const now = Math.floor(Date.now() / 1000);
			if (now < sealed.u) {
				return json({ locked: true, unlock: sealed.u, remaining: sealed.u - now, title: sealed.n || null });
			}
			return json({ locked: false, data: sealed.d, sealed_at: sealed.t, unlocked_at: sealed.u, title: sealed.n || null });
		}

		// ── GET/POST /s/share — ephemeral clipboard relay ──
		if (url.pathname === '/s/share' && request.method === 'GET') {
			const shareId = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
			const shareHtml = `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>share — ink</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0a0a0f;color:#c4945a;font-family:'SF Mono','Cascadia Code','Fira Code','Consolas',monospace;padding:1.5rem;max-width:700px;margin:0 auto}h1{font-size:1rem;margin-bottom:0.3rem}p{font-size:0.65rem;opacity:0.5;margin-bottom:1rem}textarea{width:100%;height:60vh;background:#12121a;color:#c4945a;border:1px solid #1e1e2e;padding:0.8rem;font:inherit;font-size:0.8rem;resize:vertical;outline:none}textarea:focus{border-color:#c4945a}.bar{display:flex;gap:0.5rem;margin-top:0.5rem;align-items:center}.bar button{background:none;border:1px solid #1e1e2e;color:#c4945a;padding:0.3rem 0.8rem;font:inherit;font-size:0.7rem;cursor:pointer}.bar button:hover{border-color:#c4945a}.status{font-size:0.6rem;opacity:0.5}</style>
</head><body>
<h1>shared clipboard</h1>
<p>anyone with this URL can read and write — auto-syncs every 2s</p>
<textarea id="t" placeholder="type here..." spellcheck="false"></textarea>
<div class="bar"><button onclick="copy()">copy</button><button onclick="clear_()">clear</button><span class="status" id="s"></span></div>
<script>
const id='${shareId}',base=location.origin+'/s/share/';
let last='',saving=false,syncing=false;
const t=document.getElementById('t'),s=document.getElementById('s');
async function sync(){if(saving||syncing)return;syncing=true;try{const r=await fetch(base+id);if(r.ok){const d=await r.json();if(d.text!==undefined&&d.text!==last){last=d.text;if(t.value!==d.text)t.value=d.text;s.textContent='synced'}}}catch{}syncing=false}
async function save(){if(syncing)return;saving=true;try{await fetch(base+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:t.value})});last=t.value;s.textContent='saved'}catch{s.textContent='error'}saving=false}
let timer;t.addEventListener('input',()=>{clearTimeout(timer);s.textContent='typing...';timer=setTimeout(save,500)});
setInterval(sync,2000);sync();
function copy(){navigator.clipboard.writeText(t.value);s.textContent='copied'}
function clear_(){t.value='';save()}
</script></body></html>`;
			return new Response(shareHtml, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
		}
		if (url.pathname.startsWith('/s/share/')) {
			const id = url.pathname.slice(9);
			if (!/^[a-f0-9]{6,12}$/.test(id)) return err('invalid id');
			const SHARE_KEY = `share:${id}`;
			const SHARE_TTL = 300;
			if (request.method === 'GET') {
				const obj = await env.PASTE_BUCKET.get(SHARE_KEY);
				if (!obj) return json({ text: '' });
				const data = JSON.parse(await obj.text());
				if (data.exp && Date.now() / 1000 > data.exp) {
					await env.PASTE_BUCKET.delete(SHARE_KEY);
					return json({ text: '' });
				}
				return json({ text: data.text || '' });
			}
			if (request.method === 'POST') {
				const ct = request.headers.get('Content-Type');
				if (!ct || !ct.includes('application/json')) return err('invalid content type');
				let body: any;
				try { body = await request.json(); } catch { return err('invalid json'); }
				const text = typeof body.text === 'string' ? body.text.slice(0, 50000) : '';
				const exp = Math.floor(Date.now() / 1000) + SHARE_TTL;
				await env.PASTE_BUCKET.put(SHARE_KEY, JSON.stringify({ text, exp }));
				return json({ saved: true, expires: exp });
			}
			return err('method not allowed', 405);
		}

		// ════════════════════════════════════════════
		// Paste embed (catch-all for /s/:id — must be LAST)
		// ════════════════════════════════════════════

		// ── GET /s/:id — short embed URL ────────────
		// Served on seaofglass.ink/s/:id via Worker Route.
		// Also accessible via worker subdomain for backward compat.
		// Returns HTML with OG/Twitter Card meta tags + instant redirect.
		if ((request.method === 'GET' || request.method === 'HEAD') && url.pathname.startsWith('/s/')) {
			const id = url.pathname.slice(3).replace(/\/$/, '');
			if (!id || !/^[a-f0-9]{8,12}$/.test(id)) return err('invalid id');

			let title = 'ink paste';
			let description = 'encrypted paste — seaofglass.ink';
			let shareKey = '';

			const obj = await env.PASTE_BUCKET.head(id);
			if (obj?.customMetadata) {
				if (obj.customMetadata.plainTitle) title = obj.customMetadata.plainTitle;
				if (obj.customMetadata.shareKey) shareKey = obj.customMetadata.shareKey;
				const mode = obj.customMetadata.mode;
				if (mode === 'public') description = 'public paste — seaofglass.ink';
				else if (mode === 'burn') description = 'burn after read — seaofglass.ink';
			}

			const redirectUrl = shareKey
				? `https://${DOMAIN}/#${id}:${shareKey}`
				: `https://${DOMAIN}/#${id}`;

			const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

			const html = `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:type" content="article">
<meta property="og:site_name" content="ink — sea of glass">
<meta property="og:url" content="https://${DOMAIN}/s/${id}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${esc(title)}">
<meta name="twitter:description" content="${esc(description)}">
<meta name="theme-color" content="#0a0a0f">
<meta http-equiv="refresh" content="0; url=${esc(redirectUrl)}">
<title>${esc(title)} — ink</title>
<style>body{background:#0a0a0f;color:#c4945a;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}a{color:#c4945a}</style>
</head><body><p>redirecting to <a href="${esc(redirectUrl)}">paste</a>...</p></body></html>`;

			return new Response(html, {
				status: 200,
				headers: {
					'Content-Type': 'text/html; charset=utf-8',
					'Cache-Control': 'public, max-age=3600',
				},
			});
		}

		// ── GET /public ─────────────────────────────
		if ((request.method === 'GET' || request.method === 'HEAD') && url.pathname === '/public') {
			const publicPastes: any[] = [];

			// R2: list objects with mode=public metadata
			const listed = await env.PASTE_BUCKET.list({ limit: 500, include: ['customMetadata'] });
			for (const obj of listed.objects) {
				if (obj.customMetadata?.mode === 'public') {
					const full = await env.PASTE_BUCKET.get(obj.key);
					if (!full) continue;
					const parsed = JSON.parse(await full.text());
					publicPastes.push({
						id: obj.key,
						title: parsed.t || obj.key,
						created: parsed.c,
						key: parsed.k || null,
					});
				}
			}

			// DNS: check for any public expiring pastes
			const dnsRecords = await dnsListAll(env);
			for (const rec of dnsRecords) {
				try {
					const parsed = JSON.parse(rec.content);
					if (parsed.e && Math.floor(Date.now() / 1000) > parsed.e) continue;
					if (parsed.m === 'public') {
						publicPastes.push({
							id: rec.name.split('.')[0],
							title: parsed.t || rec.name.split('.')[0],
							created: parsed.c,
							key: parsed.k || null,
						});
					}
				} catch {}
			}

			publicPastes.sort((a, b) => b.created - a.created);
			const res = json({ pastes: publicPastes });
			const headers = new Headers(res.headers);
			headers.set('Cache-Control', 'public, max-age=30');
			return new Response(res.body, { status: res.status, headers });
		}

		// ── POST /purge ─────────────────────────────
		if (request.method === 'POST' && url.pathname === '/purge') {
			const ct = request.headers.get('Content-Type');
			if (!ct || !ct.includes('application/json')) return err('invalid content type');
			let body: any;
			try { body = await request.json(); } catch { return err('invalid json'); }
			if (!body.secret || body.secret !== env.PURGE_SECRET) return err('unauthorized', 403);
			const purgeRes = await fetch(`${CF_API}/zones/${env.CF_ZONE_ID}/purge_cache`, {
				method: 'POST',
				headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}`, 'Content-Type': 'application/json' },
				body: JSON.stringify({ purge_everything: true }),
			});
			if (!purgeRes.ok) return err('purge failed: ' + purgeRes.status, 500);
			return json({ purged: true });
		}

		// ── GET /worker-key ─────────────────────────
		if ((request.method === 'GET' || request.method === 'HEAD') && url.pathname === '/worker-key') {
			const jwk = JSON.parse(env.WORKER_RSA_PUBLIC);
			const modBytes = Uint8Array.from(atob(jwk.n.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
			const fpBuf = await crypto.subtle.digest('SHA-256', modBytes);
			const fingerprint = Array.from(new Uint8Array(fpBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
			return json({ publicKey: env.WORKER_RSA_PUBLIC, fingerprint });
		}

		// ── POST /handshake ─────────────────────────
		if (request.method === 'POST' && url.pathname === '/handshake') {
			const ct = request.headers.get('Content-Type');
			if (!ct || !ct.includes('application/json')) return err('invalid content type');
			let body: any;
			try { body = await request.json(); } catch { return err('invalid json'); }
			const readerPubJwk = body.publicKey;
			if (!readerPubJwk) return err('missing public key');

			let readerKey: CryptoKey;
			try {
				const jwk = typeof readerPubJwk === 'string' ? JSON.parse(readerPubJwk) : readerPubJwk;
				readerKey = await crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
			} catch (e: any) {
				return err('invalid public key: ' + e.message);
			}

			const keyBytes = new Uint8Array(48);
			crypto.getRandomValues(keyBytes);
			const key64 = btoa(String.fromCharCode(...keyBytes)).slice(0, 64);
			const keyData = new TextEncoder().encode(key64);
			const encryptedBuf = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, readerKey, keyData);
			const encB64 = btoa(String.fromCharCode(...new Uint8Array(encryptedBuf)));

			const workerPrivJwk = JSON.parse(env.WORKER_RSA_PRIVATE);
			const signJwk = { ...workerPrivJwk, alg: 'RS256' };
			delete signJwk.key_ops;
			const workerSignKey = await crypto.subtle.importKey(
				'jwk', signJwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']
			);
			const sigBuf = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', workerSignKey, new Uint8Array(encryptedBuf));
			const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));

			return json({ encryptedKey: encB64, signature: sigB64 });
		}

		// ── GET /stats ──────────────────────────────
		if ((request.method === 'GET' || request.method === 'HEAD') && url.pathname === '/stats') {
			const dnsRecords = await dnsListAll(env);
			const r2Listed = await env.PASTE_BUCKET.list({ limit: 1000 });
			return json({
				dns: { records: dnsRecords.length },
				r2: { objects: r2Listed.objects.length },
			});
		}

		// ── POST /cleanup ───────────────────────────
		if (request.method === 'POST' && url.pathname === '/cleanup') {
			let body: any;
			try { body = await request.json(); } catch { return err('invalid json'); }
			if (!body.secret || body.secret !== env.PURGE_SECRET) return err('unauthorized', 403);
			const ids: string[] = body.ids;
			if (!ids || !Array.isArray(ids)) return err('missing ids array');
			let deleted = 0;
			for (const id of ids) {
				// R2
				const obj = await env.PASTE_BUCKET.head(id);
				if (obj) { await env.PASTE_BUCKET.delete(id); deleted++; continue; }
				// DNS
				const records = await dnsFind(env, id);
				for (const rec of records) { await dnsDelete(env, rec.id); deleted++; }
			}
			return json({ deleted });
		}

		return err('not found', 404);
	},
};
