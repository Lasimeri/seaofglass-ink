interface Env {
	CF_API_TOKEN: string;
	CF_ZONE_ID: string;
}

const CF_API = 'https://api.cloudflare.com/client/v4';
const DOMAIN = 'seaofglass.ink';
const ALLOWED_ORIGIN = `https://${DOMAIN}`;
const MAX_DATA_LEN = 3500; // ~2.6KB raw ciphertext after base64

// Simple in-memory rate limiter (per-isolate, resets on cold start)
const rateMap = new Map<string, number[]>();
const RATE_LIMIT = 10; // requests per minute per IP
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
	h.set('Access-Control-Allow-Methods', 'POST, DELETE, OPTIONS');
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

async function dnsCreate(env: Env, name: string, content: string): Promise<boolean> {
	const res = await fetch(`${CF_API}/zones/${env.CF_ZONE_ID}/dns_records`, {
		method: 'POST',
		headers: {
			'Authorization': `Bearer ${env.CF_API_TOKEN}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			type: 'TXT',
			name: `${name}.d.${DOMAIN}`,
			content,
			ttl: 1,
		}),
	});
	return res.ok;
}

async function dnsFindAndDelete(env: Env, name: string): Promise<boolean> {
	const listRes = await fetch(
		`${CF_API}/zones/${env.CF_ZONE_ID}/dns_records?name=${name}.d.${DOMAIN}&type=TXT`,
		{ headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` } },
	);
	const list: any = await listRes.json();
	if (!list.result?.length) return false;
	for (const rec of list.result) {
		await fetch(`${CF_API}/zones/${env.CF_ZONE_ID}/dns_records/${rec.id}`, {
			method: 'DELETE',
			headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` },
		});
	}
	return true;
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

			const { data } = body;
			if (!data || typeof data !== 'string') return err('missing data');
			if (data.length > MAX_DATA_LEN) return err('paste too large (max ~2.5KB)', 413);

			const id = crypto.randomUUID().slice(0, 8);
			const ok = await dnsCreate(env, id, data);
			if (!ok) return err('storage failed', 500);

			return json({ id }, 201);
		}

		// DELETE /paste/:id — delete paste
		if (request.method === 'DELETE' && url.pathname.startsWith('/paste/')) {
			const id = url.pathname.slice(7);
			if (!/^[a-f0-9]{8}$/.test(id)) return err('invalid id');
			const ok = await dnsFindAndDelete(env, id);
			return ok ? json({ deleted: true }) : err('not found', 404);
		}

		return err('not found', 404);
	},
};
