// main.js - Encrypted pastebin state machine

import {
  generateKey, exportKey, importKey, deriveRoomId,
  encrypt, decrypt
} from './crypto.js?v=1';
import { createPaste, fetchPaste, listPastes, setLogger } from './storage.js?v=2';
import { compress, decompress } from './compress.js?v=1';

// --- Inline fingerprint (avoids module loading issues) ---
async function getFingerprintKey() {
  const signals = [];
  try {
    const c = document.createElement('canvas');
    c.width = 200; c.height = 50;
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#c4945a';
    ctx.fillText('seaofglass.ink:fp', 2, 2);
    ctx.fillStyle = 'rgba(10,10,15,0.7)';
    ctx.fillRect(50, 10, 80, 30);
    signals.push(c.toDataURL());
  } catch (e) { signals.push('canvas:n/a'); }
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    signals.push(ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : 'webgl:no-ext');
  } catch (e) { signals.push('webgl:n/a'); }
  signals.push(screen.width + 'x' + screen.height + 'x' + screen.colorDepth);
  signals.push(Intl.DateTimeFormat().resolvedOptions().timeZone);
  signals.push(navigator.language);
  signals.push(navigator.platform);
  signals.push(String(navigator.hardwareConcurrency || 0));
  const raw = new TextEncoder().encode(signals.join('|'));
  const hash = await crypto.subtle.digest('SHA-256', raw);
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// --- DOM ---
const $ = (id) => document.getElementById(id);
const statusEl = $('status');
const logEl = $('log');
const createSection = $('create-section');
const shareSection = $('share-section');
const readSection = $('read-section');
const passwordSection = $('password-section');
const dirPanel = $('dir-panel');
const directoryList = $('directory-list');
const dirToggle = $('dir-toggle');
const dirClose = $('dir-close');
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

const charCountEl = $('char-count');
const lineCountEl = $('line-count');

function setStatus(msg) { statusEl.textContent = msg; }

// Live char/line counter
pasteInput.addEventListener('input', () => {
  const v = pasteInput.value;
  charCountEl.textContent = v.length + ' chars';
  lineCountEl.textContent = (v.split('\n').length) + ' lines';
});

function log(msg) {
  console.log('[ink] ' + msg);
  const line = document.createElement('div');
  line.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
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

// Site-level rotating key for public pastes — data at rest is always encrypted
// Key rotates monthly. Epoch stored in issue title so old pastes remain decryptable.
const PUB_SEED = 'seaofglass.ink:pub:v1';
function getPubEpoch() {
  const d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
}
async function derivePubKey(epoch) {
  const raw = new TextEncoder().encode(PUB_SEED + ':' + epoch);
  const hash = await crypto.subtle.digest('SHA-256', raw);
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
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
  if (clean.startsWith('p:')) {
    return { mode: 'public', pasteId: clean.slice(2), hasPassword: false };
  }
  return { mode: 'shareable', key: clean, hasPassword };
}

function formatAge(dateStr) {
  const ms = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return mins + 'm ago';
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + 'h ago';
  const days = Math.floor(hrs / 24);
  return days + 'd ago';
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
    log('Mode: ' + mode + ', password: ' + (hasPassword ? 'yes' : 'no'));

    setStatus('Compressing...');
    log('Compressing ' + text.length + ' chars...');
    const compressed = await compress(text);
    log('Compressed: ' + text.length + ' -> ' + compressed.length + ' bytes');

    let mainKey, keyExport, pasteId;
    let payload = bufToBase64(compressed);
    log('Base64 encoded: ' + payload.length + ' chars');

    if (mode === 'public') {
      const epoch = getPubEpoch();
      setStatus('Deriving site key...');
      log('Deriving rotating site key (epoch: ' + epoch + ')...');
      mainKey = await derivePubKey(epoch);
      const randomBuf = crypto.getRandomValues(new Uint8Array(8));
      pasteId = epoch + '.' + Array.from(randomBuf).map(b => b.toString(16).padStart(2, '0')).join('');
      log('Public paste, ID: ' + pasteId);
    } else if (mode === 'device') {
      setStatus('Generating device key...');
      log('Deriving device key...');
      mainKey = await getFingerprintKey();
      const randomBuf = crypto.getRandomValues(new Uint8Array(8));
      pasteId = Array.from(randomBuf).map(b => b.toString(16).padStart(2, '0')).join('');
      log('Device-bound paste, ID: ' + pasteId);
    } else {
      setStatus('Generating key...');
      log('Generating AES-256-GCM key...');
      mainKey = await generateKey();
      keyExport = await exportKey(mainKey);
      pasteId = await deriveRoomId(mainKey);
      log('Shareable paste, ID: ' + pasteId);
    }

    if (hasPassword && mode !== 'public') {
      setStatus('Encrypting with password...');
      log('Applying PBKDF2 password layer (100k iterations)...');
      const pwKey = await derivePasswordKey(password, pasteId);
      payload = await encrypt(payload, pwKey);
      log('Password layer applied: ' + payload.length + ' chars');
    }

    setStatus('Encrypting...');
    log('Applying ' + (mode === 'public' ? 'site' : 'main') + ' encryption layer...');
    payload = await encrypt(payload, mainKey);
    log('Encrypted: ' + payload.length + ' chars');

    setStatus('Uploading to GitHub...');
    log('Posting paste to GitHub Issues...');
    await createPaste(pasteId, payload, mode === 'public');
    log('Paste stored successfully');

    let fragment;
    if (mode === 'public') {
      fragment = 'p:' + pasteId;
    } else if (mode === 'device') {
      fragment = 'd:' + pasteId + (hasPassword ? ':p' : '');
    } else {
      fragment = keyExport + (hasPassword ? ':p' : '');
    }
    const url = location.origin + location.pathname + '#' + fragment;
    shareLinkEl.value = url;
    createSection.classList.add('hidden');
    shareSection.classList.remove('hidden');
    history.replaceState(null, '', location.pathname);

    setStatus('Paste created');
    log('Share URL ready');

  } catch (err) {
    setStatus('Error: ' + err.message);
    log('ERROR: ' + err.message);
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
    if (parsed.mode === 'public') {
      pasteId = parsed.pasteId;
      // Extract epoch from pasteId (format: YYYY-MM.hexhex)
      const epoch = pasteId.split('.')[0];
      setStatus('Deriving site key...');
      log('Public paste, epoch: ' + epoch + ', ID: ' + pasteId);
      mainKey = await derivePubKey(epoch);
    } else if (parsed.mode === 'device') {
      setStatus('Generating device key...');
      log('Deriving device key...');
      mainKey = await getFingerprintKey();
      pasteId = parsed.pasteId;
      log('Device-bound paste, ID: ' + pasteId);
    } else {
      setStatus('Importing key...');
      log('Importing key from URL fragment...');
      mainKey = await importKey(parsed.key);
      pasteId = await deriveRoomId(mainKey);
      log('Shareable paste, ID: ' + pasteId);
    }

    if (parsed.hasPassword && !password) {
      passwordSection.classList.remove('hidden');
      setStatus('Password required');
      log('Paste requires password');
      window._pendingPaste = parsed;
      return;
    }

    setStatus('Fetching paste...');
    log('Searching GitHub Issues for paste...');
    let payload = await fetchPaste(pasteId);
    log('Paste fetched: ' + payload.length + ' chars');

    setStatus('Decrypting...');
    log('Decrypting ' + (parsed.mode === 'public' ? 'site' : 'main') + ' layer...');
    payload = await decrypt(payload, mainKey);
    log('Decrypted');

    if (parsed.hasPassword) {
      setStatus('Decrypting password layer...');
      log('Decrypting PBKDF2 password layer...');
      const pwKey = await derivePasswordKey(password, pasteId);
      payload = await decrypt(payload, pwKey);
      log('Password layer decrypted');
    }

    setStatus('Decompressing...');
    log('Decompressing...');
    const compressed = base64ToBuf(payload);
    const text = await decompress(compressed);
    log('Decompressed: ' + compressed.length + ' bytes -> ' + text.length + ' chars');

    decryptedEl.textContent = text;
    readSection.classList.remove('hidden');
    passwordSection.classList.add('hidden');
    setStatus('Paste loaded');
    log('Done');

  } catch (err) {
    setStatus('Error: ' + err.message);
    log('ERROR: ' + err.message);
  }
}

// Password submit handler
if (readPasswordBtn) {
  readPasswordBtn.addEventListener('click', () => {
    const pw = readPasswordInput.value;
    if (!pw) return;
    const parsed = window._pendingPaste;
    if (parsed) {
      let frag;
      if (parsed.mode === 'device') {
        frag = 'd:' + parsed.pasteId + ':p';
      } else {
        frag = parsed.key + ':p';
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

// --- Paste Directory Panel ---
let dirLoaded = false;

async function loadDirectory() {
  if (dirLoaded) return;
  directoryList.innerHTML = '<div class="dir-empty">loading...</div>';
  log('Loading paste directory...');
  try {
    const pastes = await listPastes();
    if (pastes.length === 0) {
      directoryList.innerHTML = '<div class="dir-empty">no pastes yet</div>';
    } else {
      directoryList.innerHTML = '';
      for (const p of pastes) {
        const el = document.createElement('a');
        el.className = 'dir-entry';
        const frag = p.isPublic ? 'p:' + p.id : p.id;
        el.href = '#' + frag;
        const badge = p.isPublic ? '<span class="dir-badge pub">public</span>' : '<span class="dir-badge enc">encrypted</span>';
        el.innerHTML = '<span class="dir-id">' + p.id + '</span>' + badge + '<span class="dir-age">' + formatAge(p.created) + '</span>';
        if (p.isPublic) {
          el.addEventListener('click', (e) => {
            e.preventDefault();
            location.hash = 'p:' + p.id;
            readPaste(null);
          });
        }
        directoryList.appendChild(el);
      }
    }
    dirLoaded = true;
    log(pastes.length + ' paste(s) in directory');
  } catch (err) {
    directoryList.innerHTML = '<div class="dir-empty">failed to load</div>';
    log('Directory error: ' + err.message);
  }
}

function toggleDir() {
  const open = dirPanel.classList.toggle('hidden');
  dirToggle.classList.toggle('active', !open);
  if (!open) return; // closing
  loadDirectory();
}

dirToggle.addEventListener('click', toggleDir);
dirClose.addEventListener('click', toggleDir);

// --- Init ---
if (location.hash.length > 1) {
  readPaste(null);
}
