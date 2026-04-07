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

			const { data, title, mode, key: publicKey, h: encryptedH, expiry, chunks, merkleRoot } = body;
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

			await env.PASTE_BUCKET.put(id, JSON.stringify(paste), {
				customMetadata: { mode, created: String(now), ...(title ? { hasTitle: '1' } : {}) },
			});
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

		// ── GET /public ─────────────────────────────
		if ((request.method === 'GET' || request.method === 'HEAD') && url.pathname === '/public') {
			const publicPastes: any[] = [];

			// R2: list objects with mode=public metadata
			const listed = await env.PASTE_BUCKET.list({ limit: 500 });
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
