import { generateKey, exportKey, importKey, encrypt, decrypt } from './crypto.js';
import { store, load } from './storage.js';

const $ = s => document.querySelector(s);

const editor = $('#paste-input');
const charCount = $('#char-count');
const lineCount = $('#line-count');
const createBtn = $('#create-btn');
const createSection = $('#create-section');
const readSection = $('#read-section');
const shareSection = $('#share-section');
const shareLink = $('#share-link');
const copyLinkBtn = $('#copy-link');
const copyTextBtn = $('#copy-text');
const decryptedText = $('#decrypted-text');
const status = $('#status');

function log(msg, isError) {
  status.textContent = msg;
  status.className = isError ? 'status error' : 'status';
}

// Editor stats
editor?.addEventListener('input', () => {
  const v = editor.value;
  charCount.textContent = `${v.length} chars`;
  lineCount.textContent = `${v.split('\n').length} lines`;
});

// Create paste
createBtn?.addEventListener('click', async () => {
  const text = editor.value.trim();
  if (!text) return log('nothing to encrypt', true);

  createBtn.disabled = true;
  log('encrypting...');

  try {
    const key = await generateKey();
    const data = await encrypt(text, key);
    log('storing in dns...');
    const id = await store(data);
    const keyStr = await exportKey(key);

    const url = `${location.origin}/#${id}:${keyStr}`;
    shareLink.value = url;
    shareSection.classList.remove('hidden');
    log('paste created');
  } catch (e) {
    log(e.message, true);
  } finally {
    createBtn.disabled = false;
  }
});

// Copy buttons
copyLinkBtn?.addEventListener('click', () => {
  navigator.clipboard.writeText(shareLink.value);
  copyLinkBtn.textContent = 'copied';
  setTimeout(() => copyLinkBtn.textContent = 'copy', 1500);
});

copyTextBtn?.addEventListener('click', () => {
  navigator.clipboard.writeText(decryptedText.textContent);
  copyTextBtn.textContent = 'copied';
  setTimeout(() => copyTextBtn.textContent = 'copy', 1500);
});

// Read paste from URL fragment
async function readPaste() {
  const hash = location.hash.slice(1);
  if (!hash || !hash.includes(':')) return;

  const [id, keyStr] = hash.split(':', 2);
  if (!id || !keyStr) return;

  // Switch to read mode
  createSection.classList.add('hidden');
  readSection.classList.remove('hidden');
  log('fetching from dns...');

  try {
    const data = await load(id);
    log('decrypting...');
    const key = await importKey(keyStr);
    const text = await decrypt(data, key);
    decryptedText.textContent = text;
    log('decrypted');
  } catch (e) {
    log(e.message, true);
  }
}

readPaste();
