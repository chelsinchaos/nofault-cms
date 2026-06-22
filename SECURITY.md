# Security Policy

NoFaultCMS is intended to protect people whose safety may depend on it. We take
vulnerability reports extremely seriously and ask you to disclose them
responsibly.

## Project status

This project is **pre-audit alpha**. It has **not** undergone an independent
security review. Until it has, assume it may contain serious flaws and do not
rely on it to protect a real source. See the Readiness Checklist in
[`README.md`](README.md) and [`docs/READINESS.md`](docs/READINESS.md).

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities**, especially
anything that could deanonymize a source or operator.

* Preferred: encrypted email to `security@example.org` using our public key
  (PGP/age) published at `https://example.org/.well-known/security.txt`.
  *(Maintainer: replace these placeholders with a real, monitored contact and
  a real published key before any public release — a tool of this kind without
  a working confidential disclosure channel is itself a safety defect.)*
* If you cannot use encrypted email, request an initial contact via the same
  address and we will establish a secure channel.

Please include: affected version/commit, a description, reproduction steps, and
your assessment of impact (especially any anonymity/metadata implications).

## What to expect

* **Acknowledgement** within 72 hours.
* An initial assessment and severity rating within 7 days.
* Coordinated disclosure: we will agree a timeline with you, prioritizing user
  safety. Anonymity-affecting issues are treated as the highest severity.
* Credit in the changelog if you wish (or anonymity if you prefer).

## Scope

In scope: the `nofault` package (client, crypto, relay, render, bundle),
deployment configs in `deploy/`, and documentation that could mislead users
about safety. The deprecated original prototype has been removed.

## Cryptography notes for reviewers

* Primitives are libsodium (PyNaCl): Ed25519, X25519 sealed box,
  XChaCha20-Poly1305, Argon2id, BLAKE2b. The only hand-written primitive is the
  GF(256) Shamir implementation in `nofault/crypto/shamir.py` — please scrutinize
  it.
* The core invariant ("a seized relay yields no plaintext / no private key
  material") is asserted by `tests/test_seizure.py`. Attacks that violate it are
  the highest priority.
