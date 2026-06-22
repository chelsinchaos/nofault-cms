# NoFaultCMS

> ## ⚠️ STATUS: ALPHA — NOT YET SAFE FOR REAL SOURCES
> This is a security-critical tool undergoing a ground-up rebuild. **It has not
> had an independent security audit.** Do **not** use it to protect a real
> source, or to publish from a genuinely contested environment, until the
> [Readiness Checklist](#readiness-checklist) is fully green and an external
> audit has signed off. False confidence in a tool like this can get people
> imprisoned or killed. We would rather you trust nothing here yet.

NoFaultCMS is a **zero-knowledge, anonymity-first publishing system** for
investigative journalists who must research and disseminate work from
potentially hostile environments — where the network is surveilled, the device
may be borrowed or seized, the server may be confiscated, and the operator may
be coerced.

## What it actually does (and does not)

Unlike the original prototype (which encrypted content *on the server* and made
several false cryptographic claims), this rebuild inverts the trust model:

* **The client is the only trusted component.** All encryption, signing, and
  rendering happen on the journalist's device.
* **The server (`relay`) is a dumb, content-addressed blob store.** It holds
  only ciphertext and signed manifests. It cannot read content or titles, has
  no user database or passwords, and keeps **no request/IP/URL logs**. A seized
  relay yields nothing but opaque, signed ciphertext. (This is enforced by a
  test: `tests/test_seizure.py`.)
* **Every published artifact is end-to-end encrypted** (per-document key,
  XChaCha20-Poly1305) and **Ed25519-signed**, so any recipient can verify it
  **offline** against a pinned author key — whether it arrived over Tor, IPFS,
  or a USB stick.
* **Identity derives from a passphrase** (Argon2id), so a journalist can
  reconstitute it on any device from memory; recovery shares (Shamir) protect
  against passphrase loss.
* **Coercion-resistance, honestly scoped:** a duress/decoy keystore, a
  `crypto-shred` for self-destructing documents, and a dead-man's switch — all
  documented as *best-effort*, not magic. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

Honest limitations today: the rich authoring UI (browser/desktop editor) is not
built yet — authoring is via a Python CLI and library. Tor onion service and
IPFS publishing are configured/spec'd but require operator setup. PDFs and
non-image media are **rejected** rather than sanitized. None of this has been
externally audited.

## Architecture

```
 journalist's device (TRUSTED)                 server (UNTRUSTED, seizable)
 ┌─────────────────────────────┐               ┌──────────────────────────┐
 │ nofault.client / nofault.crypto │  ciphertext  │ nofault.relay            │
 │  • Argon2id identity         │  + signed     │  • content-addressed blobs│
 │  • per-doc XChaCha20-Poly1305│  manifest     │  • capability-token writes│
 │  • X25519 envelope to recips │ ───────────►  │  • anonymous reads        │
 │  • Ed25519 signing           │   over Tor    │  • NO logs, NO plaintext  │
 │  • Markdown→sanitized HTML+CSP│ ◄───────────  │  • bind 127.0.0.1 (.onion)│
 │  • EXIF strip, shred, duress │               └──────────────────────────┘
 └─────────────────────────────┘   also: signed offline bundles (USB/IPFS/mesh)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for detail.

## Install (development)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # or: pip install -r requirements.txt -r requirements-dev.txt
pytest                            # run the full test suite incl. security invariants
```

## Try it (local, no Tor)

```bash
export NOFAULT_HOME=./demo-home NOFAULT_PASSPHRASE='correct horse battery staple'
nofault init                                  # prints your publisher key (enroll on relay)
nofault new --title "First report" --body-file article.md
nofault export --out report.nfb               # signed offline bundle
nofault verify --in report.nfb                # verifies offline
# run a relay (see docs/ARCHITECTURE.md for NOFAULT_RELAY_* env), then:
nofault publish --doc-id <id> --relay http://127.0.0.1:8800
```

## Run the relay (production: onion-only)

The relay binds `127.0.0.1` and is exposed **only** as a Tor v3 onion service.
See [`deploy/`](deploy/) and `docker compose -f deploy/docker-compose.yml up`.

## Documentation

* [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversary model, what is and is **not** protected.
* [`docs/OPSEC.md`](docs/OPSEC.md) — operational security guide for journalists.
* [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components, data flow, crypto.
* [`SECURITY.md`](SECURITY.md) — how to report a vulnerability (responsibly).

## Readiness checklist

The tool is field-ready only when **every** box is checked. Tracked in
[`docs/READINESS.md`](docs/READINESS.md). Highlights:

- [x] Server holds zero plaintext / zero private key material (enforced by `tests/test_seizure.py`)
- [x] All content encryption is client-side; per-document AEAD + X25519 envelope + Ed25519 signing + Argon2id
- [x] Offline-verifiable signed bundles (transmission-agnostic)
- [x] No request/IP/URL logging on the relay
- [x] Client-side HTML sanitization + strict CSP; mandatory image metadata stripping
- [x] Duress decoy, crypto-shred, dead-man's switch (best-effort)
- [x] Full test suite incl. security invariants; CI with lint/type/SAST/dep-audit
- [ ] Tor onion service is the default, tested ingress in a reference deployment
- [ ] Browser/desktop authoring UI with editor, preview, revision history, search
- [ ] Hash-locked dependencies + signed, reproducible releases + SBOM in every release
- [ ] **Independent third-party security audit passed**
- [ ] Field workflows dry-run by a trusted journalist/opsec reviewer

## License

MIT — see [`LICENSE`](LICENSE).
