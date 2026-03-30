import {
  generateKey, exportKey, importKey,
  encrypt, decrypt, encryptWithPassword, decryptWithPassword,
  estimateSizes,
} from './crypto.js?v=2';
import { store, load, loadDirect, remove, listPublic, WORKER_URL } from './storage.js?v=2';

const $ = s => document.querySelector(s);

// Parse the URL fragment to determine view mode
function parseFragment() {
  const hash = location.hash.slice(1);
  if (!hash) return { mode: 'create' };

  // Admin link mode: #a:id:key:deleteToken
  if (hash.startsWith('a:')) {
    const parts = hash.slice(2).split(':');
    if (parts.length >= 3) {
      return { mode: 'admin', id: parts[0], key: parts[1], deleteToken: parts[2] };
    }
  }

  // Admin password mode: #ap:id:deleteToken
  if (hash.startsWith('ap:')) {
    const parts = hash.slice(3).split(':');
    if (parts.length >= 2) {
      return { mode: 'admin-password', id: parts[0], deleteToken: parts[1] };
    }
  }

  // Reader password mode: #p:id
  if (hash.startsWith('p:')) {
    return { mode: 'password', id: hash.slice(2) };
  }

  // Reader link mode: #id:key
  if (hash.includes(':')) {
    const [id, key] = hash.split(':', 2);
    if (id && key) return { mode: 'read', id, key };
  }

  return { mode: 'create' };
}

const route = parseFragment();

// --- Shared helpers ---
function log(msg, isError) {
  const el = $('#status');
  if (el) { el.textContent = msg; el.className = isError ? 'status error' : 'status'; }
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

// ============================================================
// CREATE MODE — editor, size calc, creates paste + opens admin tab
// ============================================================
if (route.mode === 'create') {
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
  let sizeDebounce = null;

  modeSelect.addEventListener('change', () => {
    passwordRow.classList.toggle('hidden', modeSelect.value !== 'password');
  });

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
      const total = s.encoded + 80;
      const pct = Math.min(100, Math.round(total / 3500 * 100));
      sizeLimit.textContent = `${pct}% of limit`;
      sizeLimit.className = 'size-limit' + (pct > 95 ? ' danger' : pct > 75 ? ' warn' : '');
    } catch { /* ignore */ }
  }

  createBtn.addEventListener('click', async () => {
    const text = editor.value.trim();
    if (!text) return log('nothing to encrypt', true);

    const mode = modeSelect.value;
    if (mode === 'password' && !passwordInput.value) return log('password required', true);

    // Open blank tab SYNCHRONOUSLY within the click gesture (before any await)
    // This prevents popup blockers from killing it
    const adminTab = window.open('about:blank', '_blank');

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
      const result = await store(data, title, mode, mode === 'public' ? keyStr : undefined);

      // Build admin URL and navigate the pre-opened tab
      let adminUrl;
      if (mode === 'password') {
        adminUrl = `${location.origin}/#ap:${result.id}:${result.deleteToken}`;
      } else {
        adminUrl = `${location.origin}/#a:${result.id}:${keyStr}:${result.deleteToken}`;
      }

      if (adminTab) {
        adminTab.location.href = adminUrl;
      } else {
        // Fallback: navigate current page if popup was still blocked
        location.href = adminUrl;
      }

      log('paste created');
      editor.value = '';
      charCount.textContent = '0 chars';
      lineCount.textContent = '1 line';
      calcSizes();
    } catch (e) {
      log(e.message, true);
      // Close the blank tab if creation failed
      if (adminTab) adminTab.close();
    } finally {
      createBtn.disabled = false;
    }
  });
}

// ============================================================
// ADMIN MODE — shows paste + share link + delete button
// ============================================================
if (route.mode === 'admin' || route.mode === 'admin-password') {
  const createSection = $('#create-section');
  const adminSection = $('#admin-section');
  createSection.classList.add('hidden');
  adminSection.classList.remove('hidden');

  const adminTitle = $('#admin-title');
  const adminDate = $('#admin-date');
  const adminText = $('#admin-text');
  const adminShareLink = $('#admin-share-link');
  const adminCopyLink = $('#admin-copy-link');
  const adminCopyText = $('#admin-copy-text');
  const adminDeleteBtn = $('#admin-delete');
  const adminPasswordPrompt = $('#admin-password-prompt');
  const adminPromptInput = $('#admin-prompt-password');
  const adminPromptBtn = $('#admin-prompt-decrypt');
  const adminPromptError = $('#admin-prompt-error');
  const adminContent = $('#admin-content');

  log('fetching paste...');

  loadDirect(route.id).then(async record => {
    if (record.t) adminTitle.textContent = record.t;
    if (record.c) adminDate.textContent = fmtDate(record.c);

    if (route.mode === 'admin') {
      // Build reader share link (no delete token)
      adminShareLink.value = `${location.origin}/#${route.id}:${route.key}`;

      // Decrypt and show
      log('decrypting...');
      try {
        const key = await importKey(route.key);
        const text = await decrypt(record.d, key);
        adminText.textContent = text;
        adminContent.classList.remove('hidden');
        log('');
      } catch (e) {
        log(e.message, true);
      }
    } else {
      // Admin password mode — need password to decrypt
      adminShareLink.value = `${location.origin}/#p:${route.id}`;
      adminPasswordPrompt.classList.remove('hidden');
      log('enter password to decrypt');

      const doDecrypt = async () => {
        const pw = adminPromptInput.value;
        if (!pw) return;
        adminPromptBtn.disabled = true;
        adminPromptError.classList.add('hidden');
        try {
          const text = await decryptWithPassword(record.d, pw);
          adminPasswordPrompt.classList.add('hidden');
          adminText.textContent = text;
          adminContent.classList.remove('hidden');
          log('');
        } catch {
          adminPromptError.textContent = 'wrong password';
          adminPromptError.classList.remove('hidden');
        } finally {
          adminPromptBtn.disabled = false;
        }
      };
      adminPromptBtn.onclick = doDecrypt;
      adminPromptInput.onkeydown = e => { if (e.key === 'Enter') doDecrypt(); };
      adminPromptInput.focus();
    }
  }).catch(e => log(e.message, true));

  // Copy link
  adminCopyLink.addEventListener('click', () => {
    navigator.clipboard.writeText(adminShareLink.value);
    adminCopyLink.textContent = 'copied';
    setTimeout(() => adminCopyLink.textContent = 'copy', 1500);
  });

  // Copy text
  adminCopyText.addEventListener('click', () => {
    navigator.clipboard.writeText(adminText.textContent);
    adminCopyText.textContent = 'copied';
    setTimeout(() => adminCopyText.textContent = 'copy', 1500);
  });

  // Delete
  let deleted = false;
  adminDeleteBtn.addEventListener('click', async () => {
    adminDeleteBtn.disabled = true;
    log('deleting...');
    try {
      await remove(route.id, route.deleteToken);
      deleted = true;
      log('paste deleted');
      adminContent.classList.add('hidden');
      adminShareLink.value = '';
      adminDeleteBtn.classList.add('hidden');
    } catch (e) {
      log(e.message, true);
      adminDeleteBtn.disabled = false;
    }
  });

  // Revoke delete token when admin tab closes
  // sendBeacon is reliable during page unload (unlike fetch)
  function revokeToken() {
    if (deleted) return; // already deleted, nothing to revoke
    const body = JSON.stringify({ token: route.deleteToken });
    navigator.sendBeacon(`${WORKER_URL}/revoke/${route.id}`, new Blob([body], { type: 'application/json' }));
  }

  window.addEventListener('pagehide', revokeToken);
}

// ============================================================
// READ MODE — shows decrypted paste only
// ============================================================
if (route.mode === 'read') {
  const createSection = $('#create-section');
  const readSection = $('#read-section');
  createSection.classList.add('hidden');
  readSection.classList.remove('hidden');

  const readTitle = $('#read-title');
  const readDate = $('#read-date');
  const decryptedText = $('#decrypted-text');
  const copyTextBtn = $('#copy-text');

  log('fetching from dns...');

  load(route.id).then(async record => {
    if (record.t) readTitle.textContent = record.t;
    if (record.c) readDate.textContent = fmtDate(record.c);
    log('decrypting...');
    const key = await importKey(route.key);
    const text = await decrypt(record.d, key);
    decryptedText.textContent = text;
    log('decrypted');
  }).catch(e => log(e.message, true));

  copyTextBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(decryptedText.textContent);
    copyTextBtn.textContent = 'copied';
    setTimeout(() => copyTextBtn.textContent = 'copy', 1500);
  });
}

// ============================================================
// PASSWORD READ MODE
// ============================================================
if (route.mode === 'password') {
  const createSection = $('#create-section');
  const passwordPrompt = $('#password-prompt');
  const readSection = $('#read-section');
  createSection.classList.add('hidden');
  passwordPrompt.classList.remove('hidden');

  const promptTitle = $('#prompt-title');
  const promptDate = $('#prompt-date');
  const promptInput = $('#prompt-password');
  const promptBtn = $('#prompt-decrypt');
  const promptError = $('#prompt-error');
  const readTitle = $('#read-title');
  const readDate = $('#read-date');
  const decryptedText = $('#decrypted-text');
  const copyTextBtn = $('#copy-text');

  log('fetching from dns...');

  load(route.id).then(record => {
    if (record.t) promptTitle.textContent = record.t;
    if (record.c) promptDate.textContent = fmtDate(record.c);
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
        if (record.t) readTitle.textContent = record.t;
        if (record.c) readDate.textContent = fmtDate(record.c);
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
  }).catch(e => log(e.message, true));

  copyTextBtn.addEventListener('click', () => {
    navigator.clipboard.writeText($('#decrypted-text').textContent);
    copyTextBtn.textContent = 'copied';
    setTimeout(() => copyTextBtn.textContent = 'copy', 1500);
  });
}

// ============================================================
// PUBLIC DIRECTORY — always visible
// ============================================================
const dirList = $('#directory-list');
const dirRefresh = $('#dir-refresh');

async function loadDirectory() {
  dirList.innerHTML = '<div class="dir-loading">loading...</div>';
  try {
    const pastes = await listPublic();
    if (!pastes.length) {
      dirList.innerHTML = '<div class="dir-empty">no public pastes</div>';
      return;
    }
    dirList.innerHTML = pastes.map(p => `
      <a href="/#${p.id}:${p.key}" target="_blank" rel="noopener" class="dir-entry">
        <span class="dir-title">${esc(p.title)}</span>
        <span class="dir-date">${fmtDate(p.created)}</span>
      </a>
    `).join('');
  } catch (e) {
    dirList.innerHTML = `<div class="dir-empty">${esc(e.message)}</div>`;
  }
}

dirRefresh.addEventListener('click', loadDirectory);
