# Architecture

## Principle: invert the trust model

The original prototype trusted the server (it held keys and decrypted content).
This rebuild treats the server as hostile and seizable. **All confidentiality
and authenticity controls run on the client.** The server is a dumb,
zero-knowledge, content-addressed blob store.

## Components

### `nofault.crypto` — client-side cryptographic core
* `aead` — XChaCha20-Poly1305 (`nonce||ct`); the only symmetric cipher.
* `identity` — Argon2id passphrase→seed; BLAKE2b domain-separated subkeys →
  Ed25519 (sign) + X25519 (box). Encrypted keystore with optional duress slot.
* `document` — `Document` (plaintext) → `EncryptedDocument`: per-doc DEK,
  payload AEAD-encrypted (title+body+meta all inside), DEK sealed to each
  recipient (X25519 sealed box), manifest Ed25519-signed, ciphertext addressed
  by BLAKE2b. `verify()` is offline and pins the author fingerprint.
* `hashing` — BLAKE2b-256 content addressing of *ciphertext*.
* `shamir` — GF(256) k-of-n recovery (the only non-libsodium primitive; audited
  separately).

### `nofault.render` — safe publishing
* `html` — Markdown → allowlist-sanitized HTML (nh3) + strict CSP (no JS) +
  `no-referrer`. Jinja2 autoescape on. Kills the stored-XSS class.
* `media` — mandatory image re-encode to drop EXIF/XMP/IPTC; rejects non-images.

### `nofault.bundle` — transmission-agnostic unit
A signed tar (`.nfb`) of manifest+ciphertext blobs plus a signed index
committing to every blob address. Verifies fully offline; deterministic (no
timestamps) so it is reproducible. Travels over Tor, IPFS, USB, or mesh
identically.

### `nofault.relay` — the only server component
* `store` — sharded content-addressed blob store; verifies content==address on
  write; atomic; idempotent.
* `auth` — anonymous capability tokens: enrolled publisher signs a short-lived
  statement → relay issues an HMAC bearer token. No accounts, no passwords.
* `app` — FastAPI: `PUT /blob` (token), `GET/HEAD /blob/{addr}` (anonymous),
  `POST /auth/token`, `GET /healthz`. **Access logging disabled.** Binds
  `127.0.0.1`; reachable only via a Tor onion service.

### `nofault.client` — authoring & safety
* `repo` — local index (opaque addresses only, no plaintext) + local blob cache
  + shred-vault. create / edit (signed version chain) / open / list / delete /
  crypto-shred.
* `vault` — device-local DEK store for shreddable docs (random vault key, not
  passphrase-derived → genuinely shreddable).
* `transport` — relay client; `over_tor()` uses `socks5h://`.
* `safety` — panic shred, dead-man's switch.
* `cli` — `nofault` command.

## Data flow (publish → read)

1. Author writes Markdown. `Document` serialized to canonical JSON.
2. Random DEK; `ciphertext = AEAD(DEK, payload)`; `ct_addr = BLAKE2b(ciphertext)`.
3. DEK sealed to each recipient's X25519 key (author included unless shreddable).
4. Manifest `{scheme, doc_id, version, prev_address, ct_addr, recipients,
   author_fingerprint}` is Ed25519-signed.
5. Two opaque blobs (signed manifest, ciphertext) uploaded to the relay over Tor
   (or exported as a bundle).
6. Reader fetches manifest by address, **verifies signature + pinned
   fingerprint + ct address**, fetches ciphertext, unwraps DEK with their X25519
   key, decrypts, renders to sanitized HTML.

## Editing & versioning

"Edit" = new `EncryptedDocument` whose manifest `prev_address` points at the
prior version's manifest address → a signed, tamper-evident chain. Because the
server is zero-knowledge, listing/search/edit all happen client-side over
locally-decrypted data. (The original had no update/delete/list at all.)

## Deployment

`deploy/docker-compose.yml`: a `relay` container (non-root, read-only FS,
cap-drop, healthcheck, `127.0.0.1` only) + a `tor` sidecar exposing a v3 onion
service. Secrets (`NOFAULT_RELAY_SECRET`, publisher allowlist) are injected at
runtime, never baked into images. No host ports are published.

## Roadmap (not yet built)

* Browser SPA + desktop (Tauri) authoring UI with editor/preview/history/search,
  ephemeral RAM-only mode.
* IPFS publishing path (ciphertext-only, node behind Tor, maintained Kubo RPC).
* Connection-bound / blinded-token write auth; cover traffic.
* Hash-locked deps, SBOM, signed reproducible releases.
* Independent security audit.
