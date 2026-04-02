import { argon2id_derive } from '../argon2-wasm/pkg/argon2_worker';
// PGP module lazy-loaded on demand (avoids crashing worker on startup)
let pgpMod: any = null;
async function getPgp() {
	if (pgpMod) return pgpMod;
	pgpMod = await import('../pgp-wasm/ink_pgp');
	return pgpMod;
}

// ─────────────────────────────────────────────
// Types & Interfaces
// ─────────────────────────────────────────────

interface Env {
	CF_API_TOKEN: string;
	CF_ZONE_ID: string;
	PURGE_SECRET: string;
	WORKER_PGP_PUBLIC: string;
	WORKER_PGP_SECRET_1: string;
	WORKER_PGP_SECRET_2: string;
	WORKER_PGP_PASS: string;
}

// CF_API_TOKEN should be scoped to: Zone → DNS → Edit
// for the seaofglass.ink zone only. Do not use a global API key.

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

const CF_API = 'https://api.cloudflare.com/client/v4';
const DOMAIN = 'seaofglass.ink';
const ALLOWED_ORIGIN = `https://${DOMAIN}`;
const MAX_RECORD_LEN = 4000; // Cloudflare TXT record limit ~4KB, leave some margin
const DELETE_TTL = 600; // 10 minutes — delete token expires after this

// Rate limiting (per-isolate, resets on cold start)
const rateMap = new Map<string, number[]>();
const RATE_LIMIT = 10;
const RATE_WINDOW = 60_000;

// ─────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────

/** Sliding-window rate limiter keyed by IP */
function rateOk(ip: string): boolean {
	const now = Date.now();
	const hits = (rateMap.get(ip) || []).filter(t => now - t < RATE_WINDOW);
	if (hits.length >= RATE_LIMIT) return false;
	hits.push(now);
	rateMap.set(ip, hits);
	return true;
}

/** Attach CORS headers to a response */
function cors(res: Response): Response {
	const h = new Headers(res.headers);
	h.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
	h.set('Access-Control-Allow-Methods', 'POST, DELETE, GET, OPTIONS');
	h.set('Access-Control-Allow-Headers', 'Content-Type');
	h.set('Access-Control-Max-Age', '86400');
	h.set('Vary', 'Origin');
	return new Response(res.body, { status: res.status, headers: h });
}

/** JSON response with CORS */
function json(data: unknown, status = 200): Response {
	return cors(new Response(JSON.stringify(data), {
		status,
		headers: { 'Content-Type': 'application/json' },
	}));
}

/** Error response shorthand */
function err(msg: string, status = 400): Response {
	return json({ error: msg }, status);
}

/** SHA-256 hex digest of a string */
async function sha256hex(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const hash = await crypto.subtle.digest('SHA-256', data);
	return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Base64url decode */
function unbase64url(str: string): Uint8Array {
	const s = str.replace(/-/g, '+').replace(/_/g, '/');
	const pad = s + '='.repeat((4 - s.length % 4) % 4);
	const binary = atob(pad);
	const buf = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
	return buf;
}

/** Decrypt AES-GCM encrypted metadata using a raw base64url key */
async function decryptRawWithKey(encoded: string, keyStr: string): Promise<string> {
	const buf = unbase64url(encoded);
	const iv = buf.slice(0, 12);
	const ct = buf.slice(12);
	const key = await crypto.subtle.importKey('raw', unbase64url(keyStr), 'AES-GCM', false, ['decrypt']);
	const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
	return new TextDecoder().decode(decrypted);
}

/** Decrypt password-encrypted metadata — auto-detects Argon2id (INK1 prefix) vs legacy PBKDF2 */
async function decryptRawWithPassword(encoded: string, password: string): Promise<string> {
	const buf = unbase64url(encoded);
	let salt: Uint8Array, iv: Uint8Array, ct: Uint8Array, key: CryptoKey;

	// INK1 magic = Argon2id format
	if (buf.length >= 4 && buf[0] === 0x49 && buf[1] === 0x4E && buf[2] === 0x4B && buf[3] === 0x31) {
		salt = buf.slice(4, 20);
		iv = buf.slice(20, 32);
		ct = buf.slice(32);
		const rawKey = argon2id_derive(
			new TextEncoder().encode(password), salt,
			65536, 3, 1, 32  // 64MB, 3 iterations, 1 thread, 32-byte output
		);
		key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
	} else {
		// Legacy PBKDF2 format
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

/** Check if a string looks like a legacy plaintext SHA-256 hex hash */
function isLegacyHash(h: string): boolean {
	return h.length === 64 && /^[a-f0-9]{64}$/.test(h);
}

/**
 * Build TXT record JSON envelope.
 * Fields: d=data, t=title, m=mode, c=created, k=publicKey, h=encryptedDeleteHash, e=expiresAt, p=encryptedPgpKey
 */
function buildRecord(data: string, title: string | null, mode: string, encryptedH: string | null, publicKey?: string, expiry?: number, pgpKey?: string): string {
	const now = Math.floor(Date.now() / 3600000) * 3600;
	const rec: Record<string, unknown> = {
		d: data,
		m: mode,
		c: now,
	};
	if (encryptedH) rec.h = encryptedH;
	if (title) rec.t = title;
	if (publicKey) rec.k = publicKey;
	if (expiry && expiry > 0) rec.e = now + expiry;
	if (pgpKey) rec.p = pgpKey;
	return JSON.stringify(rec);
}

// ─────────────────────────────────────────────
// DNS Operations (Cloudflare API)
// ─────────────────────────────────────────────

/** Create a TXT record under <id>.d.seaofglass.ink */
async function dnsCreate(env: Env, name: string, content: string): Promise<boolean> {
	const res = await fetch(`${CF_API}/zones/${env.CF_ZONE_ID}/dns_records`, {
		method: 'POST',
		headers: {
			'Authorization': `Bearer ${env.CF_API_TOKEN}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({ type: 'TXT', name: `${name}.d.${DOMAIN}`, content, ttl: 1 }),
	});
	return res.ok;
}

/** Find TXT records for a given paste ID */
async function dnsFind(env: Env, name: string): Promise<any[]> {
	const res = await fetch(
		`${CF_API}/zones/${env.CF_ZONE_ID}/dns_records?name=${name}.d.${DOMAIN}&type=TXT`,
		{ headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` } },
	);
	const data: any = await res.json();
	return data.result || [];
}

/** Delete a DNS record by ID */
async function dnsDelete(env: Env, recordId: string): Promise<void> {
	await fetch(`${CF_API}/zones/${env.CF_ZONE_ID}/dns_records/${recordId}`, {
		method: 'DELETE',
		headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` },
	});
}

/** Update a DNS record in place */
async function dnsUpdate(env: Env, recordId: string, name: string, content: string): Promise<boolean> {
	const res = await fetch(`${CF_API}/zones/${env.CF_ZONE_ID}/dns_records/${recordId}`, {
		method: 'PUT',
		headers: {
			'Authorization': `Bearer ${env.CF_API_TOKEN}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({ type: 'TXT', name, content, ttl: 1 }),
	});
	return res.ok;
}

/** Paginate all TXT records under *.d.seaofglass.ink
 *  CF API doesn't support wildcard name filtering — must fetch all TXT and filter client-side.
 *  /public response is cached at edge (30s) to mitigate the cost. */
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
		const matching = records.filter((r: any) => r.name.endsWith(`.d.${DOMAIN}`));
		allRecords = allRecords.concat(matching);
		if (records.length < 100) break;
		page++;
	}
	return allRecords;
}

// ─────────────────────────────────────────────
// Route Handlers
// ─────────────────────────────────────────────

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		// CORS preflight
		if (request.method === 'OPTIONS') {
			return cors(new Response(null, { status: 204 }));
		}

		// Rate limiting
		const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
		if (!rateOk(ip)) return err('rate limited', 429);

		// POST /store — create a new paste
		if (request.method === 'POST' && url.pathname === '/store') {
			const ct = request.headers.get('Content-Type');
			if (!ct || !ct.includes('application/json')) return err('invalid content type');

			let body: any;
			try { body = await request.json(); }
			catch { return err('invalid json'); }

			const { chunks, merkleRoot, data, title, mode, key: publicKey, h: encryptedH, expiry } = body;
			if (!['link', 'password', 'public', 'burn', 'deniable'].includes(mode)) return err('invalid mode');
			if (title !== undefined && title !== null && typeof title !== 'string') return err('invalid title');

			const id = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
			const now = Math.floor(Date.now() / 3600000) * 3600;
			const expirySeconds = typeof expiry === 'number' && expiry > 0 ? expiry : undefined;

			// v2: chunked storage with Merkle root
			if (chunks && Array.isArray(chunks) && chunks.length > 0 && merkleRoot) {
				for (let i = 0; i < chunks.length; i++) {
					const rec: Record<string, unknown> = { v: 2, n: chunks.length, i, d: chunks[i] };
					if (i === 0) {
						// Chunk 0 carries metadata
						rec.mr = merkleRoot;
						rec.m = mode;
						rec.c = now;
						if (encryptedH) rec.h = encryptedH;
						if (title) rec.t = title;
						if (publicKey && mode === 'public') rec.k = publicKey;
						if (expirySeconds) rec.e = now + expirySeconds;
					}
					const content = JSON.stringify(rec);
					if (content.length > MAX_RECORD_LEN) return err(`chunk ${i} too large (${content.length})`, 413);
					const ok = await dnsCreate(env, id, content);
					if (!ok) return err(`chunk ${i} storage failed`, 500);
				}
				return json({ id }, 201);
			}

			// v1 fallback: single record (legacy / small pastes)
			if (!data || typeof data !== 'string' || !data.trim()) return err('missing data');
			const record = buildRecord(data, title || null, mode, encryptedH || null, mode === 'public' ? publicKey : undefined, expirySeconds, pgpKey || undefined);
			if (record.length > MAX_RECORD_LEN) return err('paste too large', 413);
			const ok = await dnsCreate(env, id, record);
			if (!ok) return err('storage failed', 500);
			return json({ id }, 201);
		}

		// DELETE /paste/:id — delete a paste by ID with valid token (in body)
		if (request.method === 'DELETE' && url.pathname.startsWith('/paste/')) {
			const id = url.pathname.slice(7);
			if (!/^[a-f0-9]{8,12}$/.test(id)) return err('invalid id');

			let deleteBody: any;
			try { deleteBody = await request.json(); } catch { return err('invalid json'); }
			const token = deleteBody?.token;
			if (!token || typeof token !== 'string') return err('missing delete token', 403);

			const records = await dnsFind(env, id);
			if (!records.length) return err('not found', 404);

			// Find the metadata record (chunk 0 in v2, or the single record in v1)
			let parsed: any;
			for (const rec of records) {
				try {
					const p = JSON.parse(rec.content);
					if (p.h) { parsed = p; break; } // found the record with delete hash
					if (!parsed) parsed = p; // fallback to first parseable
				} catch { /* skip */ }
			}
			if (!parsed) return err('corrupt record', 500);

			// Check if delete capability has been revoked
			if (!parsed.h) return err('delete token revoked', 403);

			// Check TTL — token expires DELETE_TTL seconds after paste creation
			const now = Math.floor(Date.now() / 3600000) * 3600;
			if (parsed.c && (now - parsed.c) > DELETE_TTL) return err('delete token expired', 403);

			// Validate delete token — decrypt the client-encrypted hash, then compare
			const tokenHash = await sha256hex(token);
			if (isLegacyHash(parsed.h)) {
				// Legacy plaintext hash (old pastes / public mode)
				if (parsed.h !== tokenHash) return err('invalid delete token', 403);
			} else {
				// Client-encrypted hash — need key or password to decrypt
				const { key, password } = deleteBody;
				let expectedHash: string;
				try {
					if (key) expectedHash = await decryptRawWithKey(parsed.h, key);
					else if (password) expectedHash = await decryptRawWithPassword(parsed.h, password);
					else return err('missing decryption key', 403);
				} catch { return err('invalid key', 403); }
				if (expectedHash !== tokenHash) return err('invalid delete token', 403);
			}

			for (const rec of records) await dnsDelete(env, rec.id);
			return json({ deleted: true });
		}

		// POST /revoke/:id — permanently revoke delete capability (called via sendBeacon on tab close)
		if (request.method === 'POST' && url.pathname.startsWith('/revoke/')) {
			const id = url.pathname.slice(8);
			if (!/^[a-f0-9]{8,12}$/.test(id)) return err('invalid id');

			let body: any;
			try { body = await request.json(); } catch { return err('invalid json'); }
			const { token } = body;
			if (!token) return err('missing token', 403);

			const records = await dnsFind(env, id);
			if (!records.length) return err('not found', 404);

			let parsed: any;
			try { parsed = JSON.parse(records[0].content); } catch { return err('corrupt record', 500); }

			if (!parsed.h) return json({ revoked: true }); // already revoked

			// Validate token before revoking — decrypt if encrypted
			const tokenHash = await sha256hex(token);
			if (isLegacyHash(parsed.h)) {
				if (parsed.h !== tokenHash) return err('invalid token', 403);
			} else {
				const { key, password } = body;
				let expectedHash: string;
				try {
					if (key) expectedHash = await decryptRawWithKey(parsed.h, key);
					else if (password) expectedHash = await decryptRawWithPassword(parsed.h, password);
					else return err('missing decryption key', 403);
				} catch { return err('invalid key', 403); }
				if (expectedHash !== tokenHash) return err('invalid token', 403);
			}

			// Remove hash from record — delete is now permanently disabled
			delete parsed.h;
			const updated = JSON.stringify(parsed);
			await dnsUpdate(env, records[0].id, records[0].name, updated);

			return json({ revoked: true });
		}

		// GET /read/:id — read paste directly from CF API (bypasses DNS propagation delay)
		if ((request.method === 'GET' || request.method === 'HEAD') && url.pathname.startsWith('/read/')) {
			const id = url.pathname.slice(6);
			if (!/^[a-f0-9]{8,12}$/.test(id)) return err('invalid id');

			const records = await dnsFind(env, id);
			if (!records.length) return err('not found', 404);

			// Parse all records
			const allParsed: any[] = [];
			for (const rec of records) {
				try { allParsed.push(JSON.parse(rec.content)); } catch { /* skip malformed */ }
			}
			if (!allParsed.length) return err('corrupt record', 500);

			// Detect v2 (chunked) vs v1 (single)
			const isV2 = allParsed.some(p => p.v === 2);

			if (isV2) {
				const meta = allParsed.find(p => p.i === 0) || allParsed[0];

				// Check expiry
				if (meta.e) {
					const now = Math.floor(Date.now() / 1000);
					if (now > meta.e) {
						for (const rec of records) await dnsDelete(env, rec.id);
						return err('paste expired', 410);
					}
				}

				// Strip delete hash from metadata
				const cleanRecords = allParsed.map(p => {
					const copy = { ...p };
					delete copy.h;
					return copy;
				});

				// Burn after read
				if (meta.m === 'burn' && !url.searchParams.has('admin')) {
					for (const rec of records) await dnsDelete(env, rec.id);
				}

				return json({ records: cleanRecords });
			}

			// v1 fallback
			const parsed = allParsed[0];

			if (parsed.e) {
				const now = Math.floor(Date.now() / 1000);
				if (now > parsed.e) {
					for (const rec of records) await dnsDelete(env, rec.id);
					return err('paste expired', 410);
				}
			}

			delete parsed.h;

			if (parsed.m === 'burn' && !url.searchParams.has('admin')) {
				for (const rec of records) await dnsDelete(env, rec.id);
			}

			return json(parsed);
		}

		// GET /public — list all public pastes, newest first
		if ((request.method === 'GET' || request.method === 'HEAD') && url.pathname === '/public') {
			const records = await dnsListAll(env);
			const publicPastes: any[] = [];
			for (const rec of records) {
				try {
					const parsed = JSON.parse(rec.content);
					if (parsed.e && Math.floor(Date.now() / 1000) > parsed.e) continue; // expired
				if (parsed.m === 'public') {
						const id = rec.name.split('.')[0];
						publicPastes.push({
							id,
							title: parsed.t || id,
							created: parsed.c,
							key: parsed.k || null,
						});
					}
				} catch { /* skip malformed records */ }
			}
			publicPastes.sort((a, b) => b.created - a.created);
			const res = json({ pastes: publicPastes });
			const headers = new Headers(res.headers);
			headers.set('Cache-Control', 'public, max-age=30');
			return new Response(res.body, { status: res.status, headers });
		}

		// POST /purge — purge Cloudflare CDN cache for the site (requires CF_API_TOKEN)
		if (request.method === 'POST' && url.pathname === '/purge') {
			const ct = request.headers.get('Content-Type');
			if (!ct || !ct.includes('application/json')) return err('invalid content type');
			let body: any;
			try { body = await request.json(); } catch { return err('invalid json'); }
			// Simple shared secret — set PURGE_SECRET in worker env
			if (!body.secret || body.secret !== (env as any).PURGE_SECRET) return err('unauthorized', 403);

			const purgeRes = await fetch(`${CF_API}/zones/${env.CF_ZONE_ID}/purge_cache`, {
				method: 'POST',
				headers: {
					'Authorization': `Bearer ${env.CF_API_TOKEN}`,
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ purge_everything: true }),
			});
			if (!purgeRes.ok) return err('purge failed: ' + purgeRes.status, 500);
			return json({ purged: true });
		}

		// GET /worker-key — return the worker's PGP public key
		if ((request.method === 'GET' || request.method === 'HEAD') && url.pathname === '/worker-key') {
			const pgp = await getPgp();
			return json({ publicKey: env.WORKER_PGP_PUBLIC, fingerprint: pgp.pgp_fingerprint(env.WORKER_PGP_PUBLIC) });
		}

		// POST /handshake — generate 64-char key, PGP-encrypt to reader's pubkey, sign with worker's key
		if (request.method === 'POST' && url.pathname === '/handshake') {
			const ct = request.headers.get('Content-Type');
			if (!ct || !ct.includes('application/json')) return err('invalid content type');

			let body: any;
			try { body = await request.json(); } catch { return err('invalid json'); }
			const readerPubKey = body.publicKey;
			if (!readerPubKey || typeof readerPubKey !== 'string') return err('missing public key');

			const pgp = await getPgp();

			// Generate 64-char random key
			const keyBytes = new Uint8Array(48);
			crypto.getRandomValues(keyBytes);
			const key64 = btoa(String.fromCharCode(...keyBytes)).slice(0, 64);

			// PGP-encrypt the 64-char key to the reader's public key
			const keyData = new TextEncoder().encode(key64);
			let encryptedKey: Uint8Array;
			try {
				encryptedKey = pgp.pgp_encrypt(keyData, readerPubKey);
			} catch (e: any) {
				return err('pgp encrypt failed: ' + e.message, 500);
			}

			// Sign with worker's private key
			const workerSecretKey = new TextDecoder().decode(
				Uint8Array.from(atob(env.WORKER_PGP_SECRET_1 + env.WORKER_PGP_SECRET_2), c => c.charCodeAt(0))
			);
			let signature: Uint8Array;
			try {
				signature = pgp.pgp_sign(encryptedKey, workerSecretKey, env.WORKER_PGP_PASS);
			} catch (e: any) {
				return err('pgp sign failed: ' + e.message, 500);
			}

			const encB64 = btoa(String.fromCharCode(...encryptedKey));
			const sigB64 = btoa(String.fromCharCode(...signature));

			return json({
				encryptedKey: encB64,
				signature: sigB64,
				workerFingerprint: pgp.pgp_fingerprint(env.WORKER_PGP_PUBLIC),
			});
		}

		return err('not found', 404);
	},
};
