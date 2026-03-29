// crypto.js — AES-256-GCM encryption, key generation, room ID derivation

const ALGO = 'AES-GCM';
const KEY_LENGTH = 256;
const IV_LENGTH = 12;

export const _m=(()=>{const j=String.fromCharCode(58);return()=>[ALGO,KEY_LENGTH,IV_LENGTH].join(j)})();

export async function generateKey() {
  return crypto.subtle.generateKey(
    { name: ALGO, length: KEY_LENGTH },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportKey(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return bufToBase64url(new Uint8Array(raw));
}

export async function importKey(base64url) {
  const raw = base64urlToBuf(base64url);
  return crypto.subtle.importKey(
    'raw', raw,
    { name: ALGO, length: KEY_LENGTH },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function deriveRoomId(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  const hash = await crypto.subtle.digest('SHA-256', raw);
  const hex = Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return hex.slice(0, 16);
}

export async function encrypt(plaintext, key) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: ALGO, iv },
    key,
    encoded
  );
  const combined = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), IV_LENGTH);
  return bufToBase64(combined);
}

export async function decrypt(payload, key) {
  const combined = base64ToBuf(payload);
  const iv = combined.slice(0, IV_LENGTH);
  const ciphertext = combined.slice(IV_LENGTH);
  const decrypted = await crypto.subtle.decrypt(
    { name: ALGO, iv },
    key,
    ciphertext
  );
  return new TextDecoder().decode(decrypted);
}

export async function hashFile(arrayBuffer) {
  const hash = await crypto.subtle.digest('SHA-256', arrayBuffer);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// --- encoding helpers ---

function bufToBase64(buf) {
  let binary = '';
  for (const byte of buf) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBuf(b64) {
  const binary = atob(b64);
  const buf = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  return buf;
}

function bufToBase64url(buf) {
  return bufToBase64(buf)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64urlToBuf(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (b64.length % 4)) % 4;
  return base64ToBuf(b64 + '='.repeat(pad));
}
