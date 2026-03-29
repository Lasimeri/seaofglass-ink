// main.js — Encrypted pastebin state machine

import {
  generateKey, exportKey, importKey, deriveRoomId,
  encrypt, decrypt
} from './crypto.js?v=1';
import { createPaste, fetchPaste, setLogger } from './storage.js?v=1';
import { compress, decompress } from './compress.js?v=1';
import { getFingerprintKey } from './fingerprint.js?v=2';

// --- DOM ---
const $ = (id) => document.getElementById(id);
const statusEl = $('status');
const debugEl = $('debug');
const createSection = $('create-section');
const shareSection = $('share-section');
const readSection = $('read-section');
const passwordSection = $('password-section');
const pasteInput = $('paste-input');
const createBtn = $('create-paste');
const modeSelect = $('mode-select');
const passwordInput = $('password-input');
const shareLinkEl = $('share-link');
const copyLinkBtn = $('copy-link');
const decryptedEl = $('decrypted-text');
const copyTextBtn = $('copy-text');
const readPasswordInput = $('read-password');
const readPasswordBtn = $('read-password-btn');

function setStatus(msg) { statusEl.textContent = msg; }

function log(msg) {
  console.log(`[ink] ${msg}`);
  const line = document.createElement('div');
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  debugEl.appendChild(line);
  debugEl.scrollTop = debugEl.scrollHeight;
  debugEl.classList.remove('hidden');
}

setLogger(log);

// --- Helpers ---

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

async function derivePasswordKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function parseFragment() {
  const frag = location.hash.slice(1);
  if (!frag) return null;

  const hasPassword = frag.endsWith(':p');
  const clean = hasPassword ? frag.slice(0, -2) : frag;

  if (clean.startsWith('d:')) {
    return { mode: 'device', pasteId: clean.slice(2), hasPassword };
  }
  return { mode: 'shareable', key: clean, hasPassword };
}

// --- Create Paste ---
createBtn.addEventListener('click', async () => {
  const text = pasteInput.value;
  if (!text.trim()) return;

  const mode = modeSelect.value;
  const password = passwordInput.value;
  const hasPassword = password.length > 0;

  createBtn.disabled = true;
  try {
    setStatus('Compressing...');
    log(`Mode: ${mode}, password: ${hasPassword ? 'yes' : 'no'}`);
    const compressed = await compress(text);
    log(`Compressed: ${text.length} → ${compressed.length} bytes`);

    // Determine main encryption key
    let mainKey, keyExport, pasteId;
    if (mode === 'device') {
      setStatus('Generating device key...');
      mainKey = await getFingerprintKey();
      const randomBuf = crypto.getRandomValues(new Uint8Array(8));
      pasteId = Array.from(randomBuf).map(b => b.toString(16).padStart(2, '0')).join('');
      log(`Device-bound paste, ID: ${pasteId}`);
    } else {
      mainKey = await generateKey();
      keyExport = await exportKey(mainKey);
      pasteId = await deriveRoomId(mainKey);
      log(`Shareable paste, ID: ${pasteId}`);
    }

    // Encrypt: compress → password layer (optional) → main key layer → base64
    let payload = bufToBase64(compressed);

    if (hasPassword) {
      setStatus('Encrypting with password...');
      const pwKey = await derivePasswordKey(password, pasteId);
      payload = await encrypt(payload, pwKey);
      log('Password layer applied');
    }

    setStatus('Encrypting...');
    payload = await encrypt(payload, mainKey);
    log('Main encryption layer applied');

    setStatus('Storing paste...');
    await createPaste(pasteId, payload);

    // Build share URL
    let fragment;
    if (mode === 'device') {
      fragment = `d:${pasteId}${hasPassword ? ':p' : ''}`;
    } else {
      fragment = `${keyExport}${hasPassword ? ':p' : ''}`;
    }
    const url = `${location.origin}${location.pathname}#${fragment}`;
    shareLinkEl.value = url;
    createSection.classList.add('hidden');
    shareSection.classList.remove('hidden');
    history.replaceState(null, '', location.pathname);

    setStatus('Paste created — share the link');
    log('Paste stored and encrypted successfully');

  } catch (err) {
    setStatus(`Error: ${err.message}`);
    log(`ERROR: ${err.message}`);
    createBtn.disabled = false;
  }
});

// --- Read Paste ---
async function readPaste(password) {
  const parsed = parseFragment();
  if (!parsed) return;

  history.replaceState(null, '', location.pathname);
  createSection.classList.add('hidden');

  try {
    let mainKey, pasteId;
    if (parsed.mode === 'device') {
      setStatus('Generating device key...');
      mainKey = await getFingerprintKey();
      pasteId = parsed.pasteId;
      log(`Device-bound paste, ID: ${pasteId}`);
    } else {
      setStatus('Importing key...');
      mainKey = await importKey(parsed.key);
      pasteId = await deriveRoomId(mainKey);
      log(`Shareable paste, ID: ${pasteId}`);
    }

    // If password required but not yet provided, show prompt
    if (parsed.hasPassword && !password) {
      passwordSection.classList.remove('hidden');
      setStatus('Password required');
      log('Paste requires password');
      window._pendingPaste = parsed;
      return;
    }

    setStatus('Fetching paste...');
    let payload = await fetchPaste(pasteId);

    setStatus('Decrypting...');
    payload = await decrypt(payload, mainKey);
    log('Main layer decrypted');

    if (parsed.hasPassword) {
      setStatus('Decrypting password layer...');
      const pwKey = await derivePasswordKey(password, pasteId);
      payload = await decrypt(payload, pwKey);
      log('Password layer decrypted');
    }

    setStatus('Decompressing...');
    const compressed = base64ToBuf(payload);
    const text = await decompress(compressed);
    log(`Decompressed: ${compressed.length} → ${text.length} chars`);

    decryptedEl.textContent = text;
    readSection.classList.remove('hidden');
    passwordSection.classList.add('hidden');
    setStatus('Paste decrypted');

  } catch (err) {
    setStatus(`Error: ${err.message}`);
    log(`ERROR: ${err.message}`);
  }
}

// Password submit handler — uses replaceState to avoid leaking key in history
if (readPasswordBtn) {
  readPasswordBtn.addEventListener('click', () => {
    const pw = readPasswordInput.value;
    if (!pw) return;
    const parsed = window._pendingPaste;
    if (parsed) {
      let frag;
      if (parsed.mode === 'device') {
        frag = `d:${parsed.pasteId}:p`;
      } else {
        frag = `${parsed.key}:p`;
      }
      history.replaceState(null, '', '#' + frag);
      readPaste(pw);
    }
  });
}

// --- Copy Handlers ---
copyLinkBtn.addEventListener('click', () => {
  shareLinkEl.select();
  navigator.clipboard.writeText(shareLinkEl.value);
  copyLinkBtn.textContent = 'Copied!';
  setTimeout(() => { copyLinkBtn.textContent = 'Copy'; }, 2000);
});

copyTextBtn.addEventListener('click', () => {
  navigator.clipboard.writeText(decryptedEl.textContent);
  copyTextBtn.textContent = 'Copied!';
  setTimeout(() => { copyTextBtn.textContent = 'Copy'; }, 2000);
});

// --- Init ---
if (location.hash.length > 1) {
  readPaste(null);
}
