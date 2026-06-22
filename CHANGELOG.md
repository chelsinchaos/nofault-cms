# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [0.1.0-alpha] — rebuild

Complete ground-up rebuild around a zero-knowledge, anonymity-first trust model.
The original prototype's security claims did not match its implementation; this
release replaces it.

### Removed (dangerous / dead code from the prototype)
- `db/database.py`, `db/create_keypair.py`, root `main.py` — orphaned, non-runnable
  "FlatFileDatabase" with `eval()`-based RCE, method-shadowing that silently
  disabled RBAC, an undefined `self.lock`, RSA-only encryption, and unauthenticated
  destructive admin endpoints.
- `authentication_service/` — authenticated nobody; wrote private keys with
  `NoEncryption()`; "AES-512" (not a real cipher).
- `logging_service/` — logged request method/URL/timestamps (a deanonymization
  weapon by design).
- `feed_aggregation_service/` — SSRF via user-supplied feed URLs; dead gRPC-to-HTTP
  mismatch; fictional AES-512.
- `admin_panel/` — `DEBUG=True` dev server, hardcoded secret, could not boot.
- `content_generation_service/`, `data_management_service/`, `ipfs_publishing_service/`
  — server-side trust model; replaced by client-side crypto + the zero-knowledge relay.
- `setup.sh` — destructive code generator that overwrote hand-edited files.
- Committed virtualenvs (`myvenv/`, `db/venv/`, `pysqlcipher3/`) and example `.env`.

### Added
- `nofault.crypto`: Argon2id identity, per-document XChaCha20-Poly1305, X25519
  envelope encryption, Ed25519 signing, BLAKE2b content addressing, GF(256)
  Shamir recovery.
- `nofault.relay`: zero-knowledge content-addressed blob store with anonymous
  capability-token writes and no logging.
- `nofault.render`: Markdown→sanitized HTML with strict CSP; mandatory image
  metadata stripping.
- `nofault.bundle`: signed, content-addressed, offline-verifiable bundles
  (transmission-agnostic).
- `nofault.client`: repo (versioned editing, crypto-shred), Tor-capable transport,
  panic + dead-man's switch, CLI.
- Hardened `deploy/` (onion-only relay), CI (ruff/mypy/bandit/pip-audit/pytest),
  honest docs (`THREAT_MODEL.md`, `OPSEC.md`, `ARCHITECTURE.md`, `READINESS.md`),
  and a real `SECURITY.md` policy.
- Test suite including the `tests/test_seizure.py` no-plaintext-on-seizure invariant.

### Security
- Inverted the trust model: a seized server no longer yields plaintext, titles,
  metadata, or keys.
- Removed all false security claims from documentation.

> This release is **pre-audit alpha** and must not be used to protect a real
> source until an independent audit has signed off. See `docs/READINESS.md`.
