import {
  generateKey, exportKey, importKey,
  encrypt, decrypt, encryptWithPassword, decryptWithPassword,
  estimateSizes, base64url,
} from './crypto.js';
import { store, load, remove, listPublic } from './storage.js';

const $ = s => document.querySelector(s);

// Editor elements
const editor = $('#paste-input');
const charCount = $('#char-count');
const lineCount = $('#line-count');
const sizeRaw = $('#size-raw');
const sizeCompressed = $('#size-compressed');
const sizeEncrypted = $('#size-encrypted');
const sizeEncoded = $('#size-encoded');
const sizeLimit = $('#size-limit');
const titleInput = $('#title-input');
const modeSelect = $('#mode-select');
const passwordRow = $('#password-row');
const passwordInput = $('#password-input');
const createBtn = $('#create-btn');

// Sections
const createSection = $('#create-section');
const shareSection = $('#share-section');
const readSection = $('#read-section');
const passwordPrompt = $('#password-prompt');

// Share elements
const shareLink = $('#share-link');
const copyLinkBtn = $('#copy-link');
const deleteBtn = $('#delete-btn');

// Read elements
const readTitle = $('#read-title');
const readDate = $('#read-date');
const decryptedText = $('#decrypted-text');
const copyTextBtn = $('#copy-text');

// Password prompt elements
const promptInput = $('#prompt-password');
const promptBtn = $('#prompt-decrypt');
const promptError = $('#prompt-error');

// Directory
const dirList = $('#directory-list');
const dirRefresh = $('#dir-refresh');

// Status
const status = $('#status');

let currentDeleteId = null;
let sizeDebounce = null;

function log(msg, isError) {
  status.textContent = msg;
  status.className = isError ? 'status error' : 'status';
}

function fmt(n) {
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

function fmtDate(ts) {
  if (!ts) return '';
  return new Date(ts * 1000).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// --- Mode toggle ---
modeSelect.addEventListener('change', () => {
  passwordRow.classList.toggle('hidden', modeSelect.value !== 'password');
});

// --- Editor stats + size calc ---
editor.addEventListener('input', () => {
  const v = editor.value;
  charCount.textContent = `${v.length} chars`;
  lineCount.textContent = `${v.split('\n').length} lines`;
  clearTimeout(sizeDebounce);
  sizeDebounce = setTimeout(calcSizes, 300);
});

async function calcSizes() {
  const text = editor.value;
  if (!text) {
    sizeRaw.textContent = 'raw: 0 B';
    sizeCompressed.textContent = 'deflate: 0 B';
    sizeEncrypted.textContent = 'aes-gcm: 0 B';
    sizeEncoded.textContent = 'base64: 0 B';
    sizeLimit.textContent = '';
    sizeLimit.className = 'size-limit';
    return;
  }
  try {
    const s = await estimateSizes(text);
    sizeRaw.textContent = `raw: ${fmt(s.raw)}`;
    sizeCompressed.textContent = `deflate: ${fmt(s.compressed)}`;
    sizeEncrypted.textContent = `aes-gcm: ${fmt(s.encrypted)}`;
    sizeEncoded.textContent = `base64: ${fmt(s.encoded)}`;
    const total = s.encoded + 80; // envelope overhead
    const pct = Math.min(100, Math.round(total / 3500 * 100));
    sizeLimit.textContent = `${pct}% of limit`;
    sizeLimit.className = 'size-limit' + (pct > 95 ? ' danger' : pct > 75 ? ' warn' : '');
  } catch { /* ignore */ }
}

// --- Create paste ---
createBtn.addEventListener('click', async () => {
  const text = editor.value.trim();
  if (!text) return log('nothing to encrypt', true);

  const mode = modeSelect.value;
  if (mode === 'password' && !passwordInput.value) return log('password required', true);

  createBtn.disabled = true;
  log('encrypting...');

  try {
    let data, keyStr = null;

    if (mode === 'password') {
      data = await encryptWithPassword(text, passwordInput.value);
    } else {
      const key = await generateKey();
      data = await encrypt(text, key);
      keyStr = await exportKey(key);
    }

    log('storing in dns...');
    const title = titleInput.value.trim() || null;
    // For public pastes, include the key in the record so directory can link to them
    const result = await store(data, title, mode, mode === 'public' ? keyStr : undefined);

    let url;
    if (mode === 'password') {
      url = `${location.origin}/#p:${result.id}`;
    } else {
      url = `${location.origin}/#${result.id}:${keyStr}`;
    }

    shareLink.value = url;
    shareSection.classList.remove('hidden');
    currentDeleteId = result.id;
    deleteBtn.classList.remove('hidden');
    log('paste created');
  } catch (e) {
    log(e.message, true);
  } finally {
    createBtn.disabled = false;
  }
});

// --- Delete (session only) ---
deleteBtn.addEventListener('click', async () => {
  if (!currentDeleteId) return;
  deleteBtn.disabled = true;
  log('deleting...');
  try {
    await remove(currentDeleteId);
    log('paste deleted');
    shareSection.classList.add('hidden');
    deleteBtn.classList.add('hidden');
    currentDeleteId = null;
  } catch (e) {
    log(e.message, true);
  } finally {
    deleteBtn.disabled = false;
  }
});

// --- Copy buttons ---
copyLinkBtn.addEventListener('click', () => {
  navigator.clipboard.writeText(shareLink.value);
  copyLinkBtn.textContent = 'copied';
  setTimeout(() => copyLinkBtn.textContent = 'copy', 1500);
});

copyTextBtn.addEventListener('click', () => {
  navigator.clipboard.writeText(decryptedText.textContent);
  copyTextBtn.textContent = 'copied';
  setTimeout(() => copyTextBtn.textContent = 'copy', 1500);
});

// --- Read paste ---
async function readPaste() {
  const hash = location.hash.slice(1);
  if (!hash) return;

  // Password mode: #p:id
  if (hash.startsWith('p:')) {
    const id = hash.slice(2);
    createSection.classList.add('hidden');
    passwordPrompt.classList.remove('hidden');
    log('fetching from dns...');

    let record;
    try { record = await load(id); }
    catch (e) { return log(e.message, true); }

    const pTitle = $('#prompt-title');
    const pDate = $('#prompt-date');
    if (record.t) pTitle.textContent = record.t;
    if (record.c) pDate.textContent = fmtDate(record.c);
    log('enter password to decrypt');

    const doDecrypt = async () => {
      const pw = promptInput.value;
      if (!pw) return;
      promptBtn.disabled = true;
      promptError.classList.add('hidden');
      try {
        const text = await decryptWithPassword(record.d, pw);
        passwordPrompt.classList.add('hidden');
        readSection.classList.remove('hidden');
        decryptedText.textContent = text;
        log('decrypted');
      } catch {
        promptError.textContent = 'wrong password';
        promptError.classList.remove('hidden');
      } finally {
        promptBtn.disabled = false;
      }
    };
    promptBtn.onclick = doDecrypt;
    promptInput.onkeydown = e => { if (e.key === 'Enter') doDecrypt(); };
    promptInput.focus();
    return;
  }

  // Link/public mode: #id:key
  if (!hash.includes(':')) return;
  const [id, keyStr] = hash.split(':', 2);
  if (!id || !keyStr) return;

  createSection.classList.add('hidden');
  readSection.classList.remove('hidden');
  log('fetching from dns...');

  try {
    const record = await load(id);
    if (record.t) readTitle.textContent = record.t;
    if (record.c) readDate.textContent = fmtDate(record.c);
    log('decrypting...');
    const key = await importKey(keyStr);
    const text = await decrypt(record.d, key);
    decryptedText.textContent = text;
    log('decrypted');
  } catch (e) {
    log(e.message, true);
  }
}

// --- Public directory ---
async function loadDirectory() {
  dirList.innerHTML = '<div class="dir-loading">loading...</div>';
  try {
    const pastes = await listPublic();
    if (!pastes.length) {
      dirList.innerHTML = '<div class="dir-empty">no public pastes</div>';
      return;
    }
    dirList.innerHTML = pastes.map(p => `
      <a href="/#${p.id}:${p.key}" class="dir-entry">
        <span class="dir-title">${esc(p.title)}</span>
        <span class="dir-date">${fmtDate(p.created)}</span>
      </a>
    `).join('');
  } catch (e) {
    dirList.innerHTML = `<div class="dir-empty">${esc(e.message)}</div>`;
  }
}

dirRefresh.addEventListener('click', loadDirectory);

// --- Init ---
readPaste();
