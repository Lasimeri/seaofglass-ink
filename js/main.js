import {
  generateKey, exportKey, importKey,
  encrypt, decrypt, encryptWithPassword, decryptWithPassword,
  estimateSizes, sha256hex, encryptRaw, encryptRawWithPassword,
} from './crypto.js?v=10';
import { store, load, loadDirect, remove, listPublic, WORKER_URL } from './storage.js?v=10';
import { renderQR } from './qr.js?v=10';
import { downloadPDF } from './pdf.js?v=10';
import { fuzzySearch, markdownToHtml } from './wasm.js?v=10';

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

function showNotFound(msg) {
  const c = document.querySelector('.container');
  c.querySelectorAll('#create-section,#admin-section,#read-section,#password-prompt').forEach(el => el.classList.add('hidden'));
  const el = document.createElement('div');
  el.className = 'not-found';
  el.innerHTML = `<p>${esc(msg)}</p><a href="/">create a new paste</a>`;
  c.appendChild(el);
}

function linkify(text) {
  return text.replace(/(https?:\/\/[^\s<>"')\]]+)/g,
    '<a href="$1" target="_blank" rel="noopener noreferrer" class="paste-link">$1</a>');
}

function renderNumberedText(pre, text) {
  pre.dataset.raw = text;
  const lines = text.split('\n');
  pre.innerHTML = lines.map((line, i) =>
    `<span class="line" data-ln="${i + 1}"><span class="ln">${i + 1}</span>${linkify(esc(line))}</span>`
  ).join('\n');
  pre.addEventListener('click', (e) => {
    const ln = e.target.closest('.ln');
    if (!ln) return;
    const line = ln.parentElement;
    pre.querySelectorAll('.line.highlighted').forEach(el => el.classList.remove('highlighted'));
    line.classList.toggle('highlighted');
  });
}

function downloadText(text, filename) {
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename || 'paste.txt';
  a.click();
  URL.revokeObjectURL(a.href);
}

function setupWrapToggle(btn, pre) {
  if (!btn || !pre) return;
  btn.addEventListener('click', () => {
    pre.classList.toggle('nowrap');
    btn.textContent = pre.classList.contains('nowrap') ? 'wrap' : 'no-wrap';
  });
}

function setupScrollIndicator(frame) {
  const pre = frame.querySelector('pre');
  if (!pre) return;
  const check = () => {
    const hasOverflow = pre.scrollHeight > pre.clientHeight;
    const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 4;
    frame.classList.toggle('has-overflow', hasOverflow && !atBottom);
    frame.classList.toggle('scrolled-bottom', atBottom);
  };
  pre.addEventListener('scroll', check);
  requestAnimationFrame(check);
}

// Double-click password fields to toggle visibility
document.querySelectorAll('input[type="password"]').forEach(input => {
  input.addEventListener('dblclick', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
  });
});

// Keyboard shortcuts overlay
document.addEventListener('keydown', (e) => {
  if (e.key === '?' && !e.ctrlKey && !e.metaKey && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
    e.preventDefault();
    let overlay = $('#shortcuts-overlay');
    if (overlay) { overlay.remove(); return; }
    overlay = document.createElement('div');
    overlay.id = 'shortcuts-overlay';
    overlay.className = 'shortcuts-overlay';
    overlay.innerHTML = `
      <div class="shortcuts-box">
        <div class="shortcuts-title">keyboard shortcuts</div>
        <div class="shortcut"><kbd>Tab</kbd> insert tab in editor</div>
        <div class="shortcut"><kbd>Ctrl+Enter</kbd> encrypt &amp; save</div>
        <div class="shortcut"><kbd>dblclick</kbd> toggle password visibility</div>
        <div class="shortcut"><kbd>?</kbd> this overlay</div>
        <div class="shortcuts-dismiss">press ? or click to close</div>
      </div>
    `;
    overlay.addEventListener('click', () => overlay.remove());
    document.body.appendChild(overlay);
  }
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

  // Drag-and-drop file into editor
  editor.addEventListener('dragover', (e) => { e.preventDefault(); editor.classList.add('dragover'); });
  editor.addEventListener('dragleave', () => { editor.classList.remove('dragover'); });
  editor.addEventListener('drop', (e) => {
    e.preventDefault();
    editor.classList.remove('dragover');
    const file = e.dataTransfer?.files?.[0];
    if (file && file.size < 50000) { // 50KB limit
      const reader = new FileReader();
      reader.onload = () => {
        editor.value = reader.result;
        editor.dispatchEvent(new Event('input'));
      };
      reader.readAsText(file);
    }
  });

  // Editor line-number gutter
  const gutter = $('#editor-gutter');
  function updateGutter() {
    const lines = editor.value.split('\n').length;
    const nums = [];
    for (let i = 1; i <= lines; i++) nums.push(i);
    gutter.textContent = nums.join('\n');
  }
  editor.addEventListener('input', updateGutter);
  editor.addEventListener('scroll', () => { gutter.scrollTop = editor.scrollTop; });
  updateGutter();

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

  // Local paste history
  const HISTORY_KEY = 'ink-history';
  function getHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); } catch { return []; }
  }
  function saveToHistory(entry) {
    const h = getHistory();
    h.unshift(entry);
    if (h.length > 50) h.pop(); // keep last 50
    localStorage.setItem(HISTORY_KEY, JSON.stringify(h));
  }
  function renderHistory() {
    const container = $('#paste-history');
    if (!container) return;
    const h = getHistory();
    if (!h.length) { container.classList.add('hidden'); return; }
    container.classList.remove('hidden');
    const list = container.querySelector('.history-list');
    list.innerHTML = h.map(e => `
      <a href="${esc(e.url)}" target="_blank" rel="noopener" class="history-entry">
        <span class="history-title">${esc(e.title || e.id)}</span>
        <span class="history-meta">${esc(e.mode)} · ${fmtRelative(e.created)}</span>
      </a>
    `).join('');
  }
  renderHistory();

  // Paste from clipboard button
  $('#paste-clipboard').addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      editor.value = text;
      editor.dispatchEvent(new Event('input'));
    } catch { log('clipboard access denied', true); }
  });

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
      } else if (title && (mode === 'link' || mode === 'burn') && key) {
        title = await encrypt(title, key);
      }

      // Client-generated delete token — hash encrypted with paste key
      const deleteToken = crypto.randomUUID();
      const deleteHash = await sha256hex(deleteToken);
      let encryptedH;
      if (mode === 'password') {
        encryptedH = await encryptRawWithPassword(deleteHash, passwordInput.value);
      } else if (key) {
        encryptedH = await encryptRaw(deleteHash, key);
      } else {
        encryptedH = deleteHash; // public mode: plaintext hash
      }

      const expiry = parseInt($('#expiry-select').value) || 0;
      const result = await store(data, title, mode, mode === 'public' ? keyStr : undefined, encryptedH, expiry);

      // Build admin URL and navigate the pre-opened tab
      let adminUrl;
      if (mode === 'password') {
        adminUrl = `${location.origin}/#ap:${result.id}:${deleteToken}`;
      } else {
        adminUrl = `${location.origin}/#a:${result.id}:${keyStr}:${deleteToken}`;
      }

      // Save to local paste history (reader URL, not admin URL)
      let readerUrl;
      if (mode === 'password') {
        readerUrl = `${location.origin}/#p:${result.id}`;
      } else {
        readerUrl = `${location.origin}/#${result.id}:${keyStr}`;
      }
      saveToHistory({
        id: result.id,
        title: titleInput.value.trim() || result.id,
        mode,
        created: Math.floor(Date.now() / 1000),
        url: readerUrl,
      });
      renderHistory();

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
  let adminPassword = null; // stored after password decryption for delete/revoke

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

  loadDirect(route.id, true).then(async record => {
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

      // QR code for share link
      const qrCanvas = $('#admin-qr');
      if (qrCanvas && adminShareLink.value) {
        try {
          renderQR(qrCanvas, adminShareLink.value);
          qrCanvas.classList.remove('hidden');
        } catch { /* QR generation failed — hide canvas */ }
      }

      // Decrypt and show
      log('decrypting...');
      try {
        const key = await importKey(route.key);
        if (record.t) {
          try { adminTitle.textContent = await decrypt(record.t, key); }
          catch { adminTitle.textContent = record.t; }
        }
        const text = await decrypt(record.d, key);
        renderNumberedText(adminText, text);
        adminContent.classList.remove('hidden');
        setupScrollIndicator(adminText.closest('.read-frame'));
        setupWrapToggle($('#admin-wrap'), adminText);
        log('');
      } catch (e) {
        log(e.message, true);
      }
    } else {
      // Admin password mode — need password to decrypt
      adminShareLink.value = `${location.origin}/#p:${route.id}`;

      // QR code for share link
      const qrCanvas = $('#admin-qr');
      if (qrCanvas && adminShareLink.value) {
        try {
          renderQR(qrCanvas, adminShareLink.value);
          qrCanvas.classList.remove('hidden');
        } catch { /* QR generation failed — hide canvas */ }
      }

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
          adminPassword = pw; // retain for delete/revoke
          adminPasswordPrompt.classList.add('hidden');
          renderNumberedText(adminText, text);
          adminContent.classList.remove('hidden');
          setupScrollIndicator(adminText.closest('.read-frame'));
          setupWrapToggle($('#admin-wrap'), adminText);
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
  }).catch(e => {
    if (/not found/i.test(e.message)) showNotFound(e.message);
    else log(e.message, true);
  });

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
    navigator.clipboard.writeText(adminText.dataset.raw || adminText.textContent);
    adminCopyText.textContent = '\u2713 copied';
    setTimeout(() => adminCopyText.textContent = 'copy', 1500);
  });

  // Open raw
  $('#admin-raw').addEventListener('click', () => {
    const raw = adminText.dataset.raw || adminText.textContent;
    window.open('data:text/plain;charset=utf-8,' + encodeURIComponent(raw));
  });

  $('#admin-download').addEventListener('click', () => {
    downloadText(adminText.dataset.raw || adminText.textContent);
  });

  $('#admin-pdf').addEventListener('click', () => {
    const raw = adminText.dataset.raw || adminText.textContent;
    const title = adminTitle.textContent || undefined;
    downloadPDF(raw, 'paste.pdf', { title });
  });

  // Delete
  let deleted = false;
  adminDeleteBtn.addEventListener('click', async () => {
    if (!confirm('delete this paste permanently?')) return;
    adminDeleteBtn.disabled = true;
    log('deleting...');
    try {
      await remove(route.id, route.deleteToken, route.key || null, adminPassword);
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
    const revokeBody = { token: route.deleteToken };
    if (route.key) revokeBody.key = route.key;
    if (adminPassword) revokeBody.password = adminPassword;
    navigator.sendBeacon(`${WORKER_URL}/revoke/${route.id}`, new Blob([JSON.stringify(revokeBody)], { type: 'application/json' }));
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
    if (record.e && Math.floor(Date.now() / 1000) > record.e) throw new Error('paste expired');
    if (record.c) readDate.textContent = fmtDate(record.c);
    log('decrypting...');
    const key = await importKey(route.key);
    if (record.t) {
      try { readTitle.textContent = await decrypt(record.t, key); }
      catch { readTitle.textContent = record.t; }
    }
    const text = await decrypt(record.d, key);
    renderNumberedText(decryptedText, text);
    setupScrollIndicator(decryptedText.closest('.read-frame'));
    setupWrapToggle($('#read-wrap'), decryptedText);

    // Show search for pastes with 10+ lines
    if (text.split('\n').length >= 10) {
      const searchBox = $('#read-search');
      const searchInput = $('#paste-search-input');
      const searchResults = $('#paste-search-results');
      searchBox.classList.remove('hidden');
      let searchDebounce = null;
      searchInput.addEventListener('input', () => {
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(async () => {
          const q = searchInput.value.trim();
          if (!q) { searchResults.innerHTML = ''; return; }
          try {
            const results = await fuzzySearch(text, q, 20);
            searchResults.innerHTML = results.map(r =>
              `<div class="search-result" data-line="${r.line}"><span class="sr-line">${r.line}</span>${esc(r.text.slice(0, 120))}</div>`
            ).join('');
            searchResults.querySelectorAll('.search-result').forEach(el => {
              el.addEventListener('click', () => {
                const ln = el.dataset.line;
                const target = decryptedText.querySelector(`.line[data-ln="${ln}"]`);
                if (target) {
                  decryptedText.querySelectorAll('.line.highlighted').forEach(l => l.classList.remove('highlighted'));
                  target.classList.add('highlighted');
                  target.scrollIntoView({ block: 'center' });
                }
              });
            });
          } catch { /* WASM not loaded yet */ }
        }, 300);
      });
    }

    // Detect markdown and show toggle
    if (/^#{1,3}\s|^\*\s|^-\s|^\d+\.\s|```|^\|.*\|/m.test(text)) {
      const mdBtn = $('#read-md');
      const mdFrame = $('#read-md-frame');
      mdBtn.classList.remove('hidden');
      let mdRendered = false;
      mdBtn.addEventListener('click', async () => {
        if (mdFrame.classList.contains('hidden')) {
          if (!mdRendered) {
            try {
              mdFrame.innerHTML = await markdownToHtml(text);
              mdRendered = true;
            } catch { mdFrame.innerHTML = '<p>markdown rendering unavailable</p>'; }
          }
          mdFrame.classList.remove('hidden');
          mdBtn.textContent = 'source';
        } else {
          mdFrame.classList.add('hidden');
          mdBtn.textContent = 'markdown';
        }
      });
    }

    if (record.m === 'burn') log('this paste has been burned');
    else log('decrypted');
  }).catch(e => {
    if (/not found/i.test(e.message)) showNotFound(e.message);
    else log(e.message, true);
  });

  copyTextBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(decryptedText.dataset.raw || decryptedText.textContent);
    copyTextBtn.textContent = '\u2713 copied';
    setTimeout(() => copyTextBtn.textContent = 'copy', 1500);
  });

  $('#read-raw').addEventListener('click', () => {
    const raw = decryptedText.dataset.raw || decryptedText.textContent;
    window.open('data:text/plain;charset=utf-8,' + encodeURIComponent(raw));
  });

  $('#read-download').addEventListener('click', () => {
    downloadText(decryptedText.dataset.raw || decryptedText.textContent);
  });

  $('#read-pdf').addEventListener('click', () => {
    const raw = decryptedText.dataset.raw || decryptedText.textContent;
    const title = readTitle.textContent || undefined;
    downloadPDF(raw, 'paste.pdf', { title });
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
    if (record.e && Math.floor(Date.now() / 1000) > record.e) throw new Error('paste expired');
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
        renderNumberedText(decryptedText, text);
        setupScrollIndicator(decryptedText.closest('.read-frame'));
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
  }).catch(e => {
    if (/not found/i.test(e.message)) showNotFound(e.message);
    else log(e.message, true);
  });

  copyTextBtn.addEventListener('click', () => {
    const dt = $('#decrypted-text');
    navigator.clipboard.writeText(dt.dataset.raw || dt.textContent);
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
  dirList.innerHTML = '<div class="dir-skeleton"><div class="skel-bar"></div><div class="skel-bar"></div><div class="skel-bar"></div></div>';
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
