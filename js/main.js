import {
  generateKey, exportKey, importKey,
  encrypt, decrypt, encryptWithPassword, decryptWithPassword,
  estimateSizes,
} from './crypto.js?v=3';
import { store, load, loadDirect, remove, listPublic, WORKER_URL } from './storage.js?v=3';

const $ = s => document.querySelector(s);

// --- URL fragment routing ---

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
  if (el) {
    el.textContent = isError ? '\u2715 ' + msg : msg;
    el.className = isError ? 'status error' : 'status';
  }
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

function fmtRelative(ts) {
  if (!ts) return '';
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
  return fmtDate(ts);
}

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Double-click password fields to toggle visibility
document.querySelectorAll('input[type="password"]').forEach(input => {
  input.addEventListener('dblclick', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
  });
});

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
    localStorage.setItem('ink-draft', v);
  });

  // Restore draft
  const saved = localStorage.getItem('ink-draft');
  if (saved) { editor.value = saved; editor.dispatchEvent(new Event('input')); }

  editor.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const start = editor.selectionStart;
      const end = editor.selectionEnd;
      editor.value = editor.value.substring(0, start) + '\t' + editor.value.substring(end);
      editor.selectionStart = editor.selectionEnd = start + 1;
      editor.dispatchEvent(new Event('input'));
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      createBtn.click();
    }
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

    // Open blank tab synchronously within the click gesture (before any await)
    // to prevent popup blockers from killing it
    const adminTab = window.open('about:blank', '_blank');

    createBtn.disabled = true;
    log('encrypting...');

    try {
      let data, keyStr = null, key = null;

      if (mode === 'password') {
        data = await encryptWithPassword(text, passwordInput.value);
      } else {
        key = await generateKey();
        data = await encrypt(text, key);
        keyStr = await exportKey(key);
      }

      log('storing in dns...');
      let title = titleInput.value.trim() || null;
      if (title && mode === 'password') {
        title = await encryptWithPassword(title, passwordInput.value);
      } else if (title && mode === 'link' && key) {
        title = await encrypt(title, key);
      }
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
        // Popup blocked — copy admin link and stay on create page
        navigator.clipboard.writeText(adminUrl).catch(() => {});
        log('popup blocked \u2014 admin link copied to clipboard');
      }

      log('paste created');
      editor.value = '';
      localStorage.removeItem('ink-draft');
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
  history.replaceState(null, '', location.pathname);

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
    if (record.c) adminDate.textContent = fmtDate(record.c);

    // Delete TTL countdown
    if (record.c) {
      const expiresAt = record.c + 600; // DELETE_TTL = 600 seconds
      const updateCountdown = () => {
        const remaining = expiresAt - Math.floor(Date.now() / 1000);
        if (remaining <= 0) {
          adminDeleteBtn.disabled = true;
          adminDeleteBtn.textContent = 'delete expired';
          return;
        }
        const mins = Math.floor(remaining / 60);
        const secs = remaining % 60;
        adminDeleteBtn.textContent = `delete paste (${mins}:${String(secs).padStart(2, '0')})`;
        setTimeout(updateCountdown, 1000);
      };
      updateCountdown();
    }

    if (route.mode === 'admin') {
      // Build reader share link (no delete token)
      adminShareLink.value = `${location.origin}/#${route.id}:${route.key}`;

      // Decrypt and show
      log('decrypting...');
      try {
        const key = await importKey(route.key);
        if (record.t) {
          try { adminTitle.textContent = await decrypt(record.t, key); }
          catch { adminTitle.textContent = record.t; }
        }
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
          if (record.t) {
            try { adminTitle.textContent = await decryptWithPassword(record.t, pw); }
            catch { adminTitle.textContent = record.t; }
          }
          adminPasswordPrompt.classList.add('hidden');
          adminText.textContent = text;
          adminContent.classList.remove('hidden');
          log('');
        } catch {
          adminPromptError.textContent = '\u2715 wrong password';
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
    adminCopyLink.textContent = '\u2713 copied';
    setTimeout(() => adminCopyLink.textContent = 'copy', 1500);
  });

  // Share link tap-to-copy
  adminShareLink.addEventListener('click', () => {
    adminShareLink.select();
    navigator.clipboard.writeText(adminShareLink.value);
    adminCopyLink.textContent = '\u2713 copied';
    setTimeout(() => adminCopyLink.textContent = 'copy', 1500);
  });

  // Copy text
  adminCopyText.addEventListener('click', () => {
    navigator.clipboard.writeText(adminText.textContent);
    adminCopyText.textContent = '\u2713 copied';
    setTimeout(() => adminCopyText.textContent = 'copy', 1500);
  });

  // Delete
  let deleted = false;
  adminDeleteBtn.addEventListener('click', async () => {
    if (!confirm('delete this paste permanently?')) return;
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
    if (deleted) return;
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
  history.replaceState(null, '', location.pathname);

  const readTitle = $('#read-title');
  const readDate = $('#read-date');
  const decryptedText = $('#decrypted-text');
  const copyTextBtn = $('#copy-text');

  log('fetching from dns...');

  load(route.id).then(async record => {
    if (record.c) readDate.textContent = fmtDate(record.c);
    log('decrypting...');
    const key = await importKey(route.key);
    if (record.t) {
      try { readTitle.textContent = await decrypt(record.t, key); }
      catch { readTitle.textContent = record.t; }
    }
    const text = await decrypt(record.d, key);
    decryptedText.textContent = text;
    log('decrypted');
  }).catch(e => log(e.message, true));

  copyTextBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(decryptedText.textContent);
    copyTextBtn.textContent = '\u2713 copied';
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
  history.replaceState(null, '', location.pathname);

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
    if (record.c) promptDate.textContent = fmtDate(record.c);
    log('enter password to decrypt');

    const doDecrypt = async () => {
      const pw = promptInput.value;
      if (!pw) return;
      promptBtn.disabled = true;
      promptError.classList.add('hidden');
      try {
        const text = await decryptWithPassword(record.d, pw);
        let decTitle = null;
        if (record.t) {
          try { decTitle = await decryptWithPassword(record.t, pw); }
          catch { decTitle = record.t; }
        }
        passwordPrompt.classList.add('hidden');
        readSection.classList.remove('hidden');
        if (decTitle) readTitle.textContent = decTitle;
        if (record.c) readDate.textContent = fmtDate(record.c);
        decryptedText.textContent = text;
        log('decrypted');
      } catch {
        promptError.textContent = '\u2715 wrong password';
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
    copyTextBtn.textContent = '\u2713 copied';
    setTimeout(() => copyTextBtn.textContent = 'copy', 1500);
  });
}

// ============================================================
// PUBLIC DIRECTORY — always visible
// ============================================================

const dirList = $('#directory-list');
const dirRefresh = $('#dir-refresh');

// Add search filter
const dirSearch = document.createElement('input');
dirSearch.type = 'text';
dirSearch.placeholder = 'filter...';
dirSearch.className = 'dir-search';
dirSearch.setAttribute('aria-label', 'Filter public pastes');
document.querySelector('.dir-header').appendChild(dirSearch);

dirSearch.addEventListener('input', () => {
  const q = dirSearch.value.toLowerCase();
  dirList.querySelectorAll('.dir-entry').forEach(el => {
    const title = el.querySelector('.dir-title')?.textContent.toLowerCase() || '';
    el.style.display = title.includes(q) ? '' : 'none';
  });
});

async function loadDirectory() {
  dirList.innerHTML = '<div class="dir-loading">loading...</div>';
  try {
    const pastes = await listPublic();
    if (!pastes.length) {
      dirList.innerHTML = '<div class="dir-empty">no public pastes</div>';
      document.querySelector('.dir-label').textContent = 'public pastes (0)';
      return;
    }
    dirList.innerHTML = pastes.map(p => `
      <a href="/#${esc(p.id)}:${esc(p.key)}" target="_blank" rel="noopener" class="dir-entry">
        <span class="dir-title">${esc(p.title)}</span>
        <span class="dir-date" title="${fmtDate(p.created)}">${fmtRelative(p.created)}</span>
      </a>
    `).join('');
    document.querySelector('.dir-label').textContent = 'public pastes (' + pastes.length + ')';
  } catch (e) {
    dirList.innerHTML = `<div class="dir-empty">${esc(e.message)}</div>`;
  }
}

dirRefresh.addEventListener('click', loadDirectory);
loadDirectory();
