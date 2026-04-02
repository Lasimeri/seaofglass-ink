# seaofglass.ink

Encrypted pastebin — DNS-backed, zero trust.

Pastes are encrypted client-side and stored as DNS TXT records. The static page is the only way to decrypt them. The host cannot read paste content.

**Live:** [seaofglass.ink](https://seaofglass.ink)

## Architecture

```
Static site (GitHub Pages)  →  Browser (client-side crypto)
                               ↕
Cloudflare Worker (API)     →  DNS TXT records (storage)
                               ↕
DoH (Cloudflare DNS)        →  Read path (cached at edge)
```

No databases. No servers storing plaintext. DNS is the storage layer.

## Encryption Pipeline

### Non-public pastes (link / password / burn modes)

```
plaintext
→ PGP encrypt (4096-bit RSA, recipient's public key)
→ brotli compress (quality 11)
→ pad to 256-byte boundary (anonymization)
→ AES-256-GCM encrypt (random key or Argon2id-derived from password)
→ base64url encode
→ DNS TXT record
```

Breaking the AES layer yields brotli-compressed PGP ciphertext — still gibberish without the private key. Three layers of encryption.

### Public pastes

```
plaintext → brotli compress → pad → AES-256-GCM (key stored in record) → DNS
```

No PGP layer. Encryption is at-rest only — anyone with the link can read.

## Modes

| Mode | Key transport | Who can read |
|---|---|---|
| **link-only** | AES key in URL fragment (never sent to server) | Anyone with the link |
| **password** | Argon2id (64MB, 3 iter) key derived from password | Anyone with the password |
| **burn** | Same as link, but paste self-destructs after first read | First reader only |
| **public** | Key stored in DNS record alongside data | Anyone, via public directory |

## Security Features

- **AES-256-GCM** — authenticated encryption with random IVs
- **Argon2id** — memory-hard KDF for password mode (64MB, 3 iterations, GPU-resistant)
- **PGP 4096-bit RSA** — additional encryption layer under AES, passphrase-protected keys
- **Ed25519 signatures** — paste signing and verification
- **Shamir's Secret Sharing** — split secrets into N shares, require K to reconstruct
- **Client-encrypted delete hashes** — delete tokens encrypted with paste key, opaque in DNS
- **Ciphertext padding** — 256-byte blocks prevent size correlation
- **Timestamp rounding** — creation times rounded to the hour
- **CSP + Referrer-Policy** — blocks injection, prevents paste ID leaks
- **CORS enforcement** — Content-Type validation blocks cross-origin abuse

## WASM Modules

All CPU-intensive crypto runs in Rust → WebAssembly, lazy-loaded.

### Bootstrap chain

```
ink_wasm.wasm (668KB, loads uncompressed)
  → zstd decompresses ink_brotli_bg.wasm.zst (393KB → 974KB)
    → brotli decompresses ink_pgp_bg.wasm.br (309KB → 1.1MB)
    → brotli decompresses grammar .wasm.br files (on demand)
```

### Module inventory

| Module | Crate | Purpose | Size |
|---|---|---|---|
| [ink-wasm](https://github.com/Lasimeri/ink-wasm) | zstd, argon2, pulldown-cmark, ed25519-dalek, sss-rs | Core: compression bootstrap, KDF, markdown, search, signatures, secret sharing | 668KB |
| [ink-brotli](https://github.com/Lasimeri/ink-brotli) | brotli | Paste compression (quality 11) | 974KB (393KB zstd) |
| [ink-pgp](https://github.com/Lasimeri/ink-pgp) | pgp | 4096-bit RSA keygen/encrypt/decrypt/sign | 1.1MB (309KB brotli) |
| [mini-pdf](https://github.com/Lasimeri/mini-pdf) | — (pure JS) | PDF export from paste content | 5.8KB |

## Syntax Highlighting

24 languages via tree-sitter WASM grammars, brotli-compressed (1.85MB total). Loaded on demand when a language is detected.

**Languages:** JavaScript, TypeScript, TSX, Python, Rust, C, C++, Go, Java, Ruby, Bash, JSON, HTML, CSS, SQL, TOML, YAML, Lua, Swift, Kotlin, Zig, Elixir, Scala, Make

## Features

### Editor
- Line numbers with gutter
- Tab key inserts `\t`, Ctrl+Enter submits
- Draft autosave to localStorage
- Live size calculator (raw → deflate → aes-gcm → base64)
- Drag-and-drop file support
- Paste from clipboard button

### Read View
- Numbered lines with click-to-highlight
- Syntax highlighting (auto-detected)
- Fuzzy search (WASM, for pastes ≥10 lines)
- Markdown rendering toggle (auto-detected)
- Word wrap toggle
- URL auto-linking
- Scroll indicator on overflow
- Copy / Open raw / Download / PDF export

### Admin
- QR code for share link
- Delete with TTL countdown (10-minute window)
- Revoke-on-close via sendBeacon
- SHA-256 hash display (paste + public key)

### Directory
- Auto-loading public paste list
- Relative timestamps with full date on hover
- Search/filter
- Paste count badge
- Long title truncation

### Paste Lifecycle
- Expiry: never / 1h / 24h / 7d / 30d (auto-deleted on read after expiry)
- Burn after read: single-use pastes, deleted after first non-admin read
- Local paste history (localStorage, last 50)

## Worker

Cloudflare Worker at `sea-ink.seaofglass.workers.dev`.

| Endpoint | Method | Purpose |
|---|---|---|
| `/store` | POST | Create paste (stores in DNS TXT) |
| `/paste/:id` | DELETE | Delete paste (requires token + key) |
| `/revoke/:id` | POST | Revoke delete capability |
| `/read/:id` | GET | Direct read (bypasses DNS propagation) |
| `/public` | GET | List public pastes (cached 30s) |

Worker bundles Argon2id WASM (33KB) for server-side password verification during delete/revoke.

## Backward Compatibility

Three generations of compression (deflate → zstd → brotli) and two KDF formats (PBKDF2 → Argon2id) are auto-detected on decrypt:

| Format | Detection | Status |
|---|---|---|
| Deflate | No magic bytes, no padding | Legacy (oldest pastes) |
| Zstd | Magic `0x28B52FFD` | Legacy |
| Brotli | `BR` prefix (0x42 0x52) | Current |
| PBKDF2 | No `INK1` prefix | Legacy password pastes |
| Argon2id | `INK1` prefix (0x494E4B31) | Current password pastes |

## Build

```bash
# Static site — no build step, just HTML/JS/CSS
# Worker
cd worker && npm install && npx wrangler deploy

# WASM modules
cd wasm && wasm-pack build --target web --release
cd worker/argon2-wasm && wasm-pack build --target bundler --release
```

## License

Source code is public for auditability. The encryption is the trust model, not access control.
