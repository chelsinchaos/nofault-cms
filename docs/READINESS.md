# Readiness Checklist

The tool is **field-ready only when every box is checked.** Until then, do not
use it to protect a real source. Status reflects this rebuild branch.

## Trust model & crypto
- [x] Server provably holds zero plaintext and zero private key material — `tests/test_seizure.py`
- [x] All content encryption is client-side; the server never holds a decryption key
- [x] Per-document AEAD (XChaCha20-Poly1305) + X25519 envelope + Ed25519 signing + Argon2id KDF
- [x] Shamir k-of-n recovery shares
- [x] Title, body, and metadata are all encrypted (nothing source-identifying stored in clear)

## Anonymity & transport
- [x] Relay binds `127.0.0.1` only; no host ports published
- [x] Tor onion service config provided (`deploy/`)
- [x] Client egress over Tor via `socks5h://` (no DNS/IP leak) — `RelayClient.over_tor`
- [x] No request/IP/URL logging on the relay (`access_log=False`, no logging middleware)
- [x] Image metadata stripped client-side before encryption
- [ ] Bundle/transport size-padding and cover-traffic design (anonymity set) — **TODO**
- [ ] Tor onion ingress validated end-to-end in a reference deployment — **TODO**

## Publishing & integrity
- [x] Every artifact is a signed, content-addressed bundle verifiable offline
- [x] Author-fingerprint pinning defeats hostile-mirror key substitution
- [x] Sneakernet export/import round-trips (`tests/test_e2e.py`)
- [ ] IPFS publishing path (ciphertext-only, node behind Tor, maintained Kubo RPC) — **TODO**

## Auth, sessions, duress
- [x] No anonymous writes; short-lived capability tokens; no server-side passwords/keys
- [x] No `NoEncryption()` private keys anywhere
- [x] Duress decoy slot, panic crypto-shred, dead-man's switch (best-effort, documented)
- [ ] Connection-bound (DPoP-style) and/or blinded-token / PoW write auth — **TODO**

## Editability
- [x] Create / edit (signed version chain) / list / open / delete / crypto-shred (library + CLI)
- [ ] Browser/desktop authoring UI: editor, preview, revision-history view, client-side search — **TODO**
- [ ] Ephemeral RAM-only "borrowed device" mode — **TODO**

## Engineering & supply chain
- [x] Orphaned/dead prototype removed; one coherent data path
- [x] Test suite incl. security invariants; CI with ruff/mypy/bandit/pip-audit
- [x] Containers non-root, read-only FS, cap-drop, healthcheck; secrets runtime-injected
- [ ] Hash-locked dependencies (pip-compile/uv) + SBOM in every release — **partial: pinned, not hash-locked**
- [ ] Signed, reproducible releases with verification instructions — **TODO**

## Docs & honesty
- [x] No false security claims; README states exactly what the code does + limitations
- [x] Real `THREAT_MODEL.md`, `OPSEC.md`, `ARCHITECTURE.md`
- [ ] `SECURITY.md` disclosure contact + published PGP/age key filled in with real values — **TODO (placeholders)**

## External validation
- [ ] **Independent third-party security audit passed** (focus: crypto + seizure invariants + Shamir) — **TODO**
- [ ] Field workflows dry-run by a trusted journalist/opsec reviewer — **TODO**
