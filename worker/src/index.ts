interface Env {
	CF_API_TOKEN: string;
	CF_ZONE_ID: string;
}

const CF_API = 'https://api.cloudflare.com/client/v4';
const DOMAIN = 'seaofglass.ink';
const ALLOWED_ORIGIN = `https://${DOMAIN}`;
const MAX_RECORD_LEN = 3500;
const DELETE_TTL = 600; // 10 minutes — delete token expires after this

// Rate limiter (per-isolate, resets on cold start)
const rateMap = new Map<string, number[]>();
const RATE_LIMIT = 10;
const RATE_WINDOW = 60_000;

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

// TXT record JSON envelope:
// { d, t?, m, c, k?, h } — h = SHA-256 of delete token
function buildRecord(data: string, title: string | null, mode: string, deleteHash: string, publicKey?: string): string {
	const rec: Record<string, unknown> = {
		d: data,
		m: mode,
		c: Math.floor(Date.now() / 1000),
		h: deleteHash,
	};
	if (title) rec.t = title;
	if (publicKey) rec.k = publicKey;
	return JSON.stringify(rec);
}

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
		headers: {
			'Authorization': `Bearer ${env.CF_API_TOKEN}`,
			'Content-Type': 'application/json',
		},
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
		const matching = records.filter((r: any) => r.name.endsWith(`.d.${DOMAIN}`));
		allRecords = allRecords.concat(matching);
		if (records.length < 100) break;
		page++;
	}
	return allRecords;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === 'OPTIONS') {
			return cors(new Response(null, { status: 204 }));
		}

		const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
		if (!rateOk(ip)) return err('rate limited', 429);

		// POST /store — create paste
		if (request.method === 'POST' && url.pathname === '/store') {
			let body: any;
			try { body = await request.json(); }
			catch { return err('invalid json'); }

			const { data, title, mode, key: publicKey } = body;
			if (!data || typeof data !== 'string') return err('missing data');
			if (!['link', 'password', 'public'].includes(mode)) return err('invalid mode');

			const id = crypto.randomUUID().slice(0, 8);
			const deleteToken = crypto.randomUUID();
			const deleteHash = await sha256hex(deleteToken);

			const record = buildRecord(data, title || null, mode, deleteHash, mode === 'public' ? publicKey : undefined);
			if (record.length > MAX_RECORD_LEN) return err('paste too large', 413);

			const ok = await dnsCreate(env, id, record);
			if (!ok) return err('storage failed', 500);

			return json({ id, deleteToken }, 201);
		}

		// DELETE /paste/:id?token=xxx
		if (request.method === 'DELETE' && url.pathname.startsWith('/paste/')) {
			const id = url.pathname.slice(7);
			if (!/^[a-f0-9]{8}$/.test(id)) return err('invalid id');

			const token = url.searchParams.get('token');
			if (!token) return err('missing delete token', 403);

			const records = await dnsFind(env, id);
			if (!records.length) return err('not found', 404);

			let parsed: any;
			try { parsed = JSON.parse(records[0].content); } catch { return err('corrupt record', 500); }

			// Check if delete capability has been revoked
			if (!parsed.h) return err('delete token revoked', 403);

			// Check TTL — token expires DELETE_TTL seconds after paste creation
			const now = Math.floor(Date.now() / 1000);
			if (parsed.c && (now - parsed.c) > DELETE_TTL) return err('delete token expired', 403);

			// Validate delete token against stored hash
			const tokenHash = await sha256hex(token);
			if (parsed.h !== tokenHash) return err('invalid delete token', 403);

			for (const rec of records) await dnsDelete(env, rec.id);
			return json({ deleted: true });
		}

		// POST /revoke/:id — revoke delete capability (called via sendBeacon on tab close)
		if (request.method === 'POST' && url.pathname.startsWith('/revoke/')) {
			const id = url.pathname.slice(8);
			if (!/^[a-f0-9]{8}$/.test(id)) return err('invalid id');

			let body: any;
			try { body = await request.json(); } catch { return err('invalid json'); }
			const { token } = body;
			if (!token) return err('missing token', 403);

			const records = await dnsFind(env, id);
			if (!records.length) return err('not found', 404);

			let parsed: any;
			try { parsed = JSON.parse(records[0].content); } catch { return err('corrupt record', 500); }

			if (!parsed.h) return json({ revoked: true }); // already revoked

			// Validate token before revoking
			const tokenHash = await sha256hex(token);
			if (parsed.h !== tokenHash) return err('invalid token', 403);

			// Remove hash from record — delete is now permanently disabled
			delete parsed.h;
			const updated = JSON.stringify(parsed);
			await dnsUpdate(env, records[0].id, records[0].name, updated);

			return json({ revoked: true });
		}

		// GET /public — list public pastes
		if (request.method === 'GET' && url.pathname === '/public') {
			const records = await dnsListAll(env);
			const publicPastes: any[] = [];
			for (const rec of records) {
				try {
					const parsed = JSON.parse(rec.content);
					if (parsed.m === 'public') {
						const id = rec.name.split('.')[0];
						publicPastes.push({
							id,
							title: parsed.t || id,
							created: parsed.c,
							key: parsed.k || null,
						});
					}
				} catch { /* skip */ }
			}
			publicPastes.sort((a, b) => b.created - a.created);
			return json({ pastes: publicPastes });
		}

		return err('not found', 404);
	},
};
