// fingerprint.js - Browser fingerprint to AES-256-GCM key derivation

export async function getFingerprintKey() {
  const signals = [];

  // Canvas fingerprint
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 50;
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#c4945a';
    ctx.fillText('seaofglass.ink:fp', 2, 2);
    ctx.fillStyle = 'rgba(10,10,15,0.7)';
    ctx.fillRect(50, 10, 80, 30);
    signals.push(canvas.toDataURL());
  } catch (e) {
    signals.push('canvas:unavailable');
  }

  // WebGL renderer
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    signals.push(ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : 'webgl:no-ext');
  } catch (e) {
    signals.push('webgl:unavailable');
  }

  // Screen
  signals.push(`${screen.width}x${screen.height}x${screen.colorDepth}`);

  // Timezone + locale
  signals.push(Intl.DateTimeFormat().resolvedOptions().timeZone);
  signals.push(navigator.language);

  // Platform + core UA
  signals.push(navigator.platform);
  signals.push(navigator.hardwareConcurrency?.toString() || '0');

  // Hash all signals → AES-256-GCM key
  const raw = new TextEncoder().encode(signals.join('|'));
  const hash = await crypto.subtle.digest('SHA-256', raw);
  return crypto.subtle.importKey(
    'raw', hash,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
