// ittybitty.js - encode/decode ittybitty URL fragments
// Compatible with seaof.glass/ittybitty format

const TYPE_MAP = { html: 'h', markdown: 'm', svg: 's', json: 'j', text: 't' };
const TYPE_REV = { h: 'html', m: 'markdown', s: 'svg', j: 'json', t: 'text' };
const FMT_MAP = { gzip: 'g', none: 'n' };
const FMT_REV = { g: 'gzip', n: 'none' };

function bufToB64url(buf) {
  let b = '';
  for (let i = 0; i < buf.length; i++) b += String.fromCharCode(buf[i]);
  return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlToBuf(str) {
  let b = str.replace(/-/g, '+').replace(/_/g, '/');
  b += '='.repeat((4 - (b.length % 4)) % 4);
  const bin = atob(b);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

async function gzipCompress(data) {
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  writer.write(data);
  writer.close();
  const chunks = [];
  const reader = cs.readable.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const total = chunks.reduce((a, c) => a + c.length, 0);
  const result = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { result.set(c, off); off += c.length; }
  return result;
}

async function gzipDecompress(data) {
  const ds = new DecompressionStream('gzip');
  const writer = ds.writable.getWriter();
  writer.write(data);
  writer.close();
  const chunks = [];
  const reader = ds.readable.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const total = chunks.reduce((a, c) => a + c.length, 0);
  const result = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { result.set(c, off); off += c.length; }
  return result;
}

export function detectType(content) {
  const s = content.trim().toLowerCase();
  if (s.startsWith('<!doctype') || s.startsWith('<html') || s.startsWith('<head') || s.startsWith('<body')) return 'html';
  if (s.startsWith('<svg')) return 'svg';
  try { JSON.parse(content); return 'json'; } catch (e) {}
  if (/^#{1,6}\s/m.test(content) || /\*\*[^*]+\*\*/m.test(content) || /\[[^\]]+\]\([^)]+\)/m.test(content)) return 'markdown';
  if (/<[a-z][^>]*>/i.test(content)) return 'html';
  return 'text';
}

export async function encode(content, title) {
  const type = detectType(content);
  const encoded = new TextEncoder().encode(content);
  const compressed = await gzipCompress(encoded);
  const b64 = bufToB64url(compressed);
  const t = TYPE_MAP[type] || 't';
  const header = t + 'g0';
  const titlePart = title ? '/' + encodeURIComponent(title.replace(/\s+/g, '-')) : '';
  return '#' + titlePart + '/' + header + ',' + b64;
}

export async function decode(fragment) {
  let frag = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  if (frag.startsWith('/')) frag = frag.slice(1);

  const parts = frag.split('/');
  let title = '';
  let payload;

  if (parts.length > 1) {
    title = decodeURIComponent(parts[0].replace(/-/g, ' '));
    payload = parts.slice(1).join('/');
  } else {
    payload = parts[0];
  }

  const commaIdx = payload.indexOf(',');
  if (commaIdx === -1 || commaIdx > 3) throw new Error('Invalid ittybitty fragment');

  const header = payload.slice(0, commaIdx);
  const dataStr = payload.slice(commaIdx + 1);

  const type = TYPE_REV[header[0]] || 'html';
  const format = FMT_REV[header[1]] || 'gzip';
  const data = b64urlToBuf(dataStr);

  let decompressed;
  if (format === 'gzip') {
    decompressed = await gzipDecompress(data);
  } else {
    decompressed = data;
  }

  const content = new TextDecoder().decode(decompressed);
  return { title, type, content };
}

export function isIttybittyFragment(text) {
  // Matches: #/optional-title/Xg0,DATA or #/Xg0,DATA
  return /^#(\/[^/]*)?\/[a-z][gn][01],/i.test(text.trim());
}

export function isIttybittyUrl(text) {
  const t = text.trim();
  return t.startsWith('https://seaof.glass/ittybitty/#') ||
         t.startsWith('https://seaofglass.ink/ittybitty/#') ||
         isIttybittyFragment(t);
}

export function extractFragment(text) {
  const t = text.trim();
  const hashIdx = t.indexOf('#');
  return hashIdx > -1 ? t.slice(hashIdx) : t;
}
