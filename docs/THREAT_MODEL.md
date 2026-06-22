# NoFaultCMS Threat Model

This document states plainly **who the adversary is**, **what we protect**, and —
critically — **what we do NOT protect**. If a property you need is in the
"Non-goals / not protected" section, do not rely on this tool for it.

> Source protection is life-safety critical. When in doubt, this document
> errs toward telling you we protect *less* than you might hope.

## Assets

1. **Source identity** — who provided information. The highest-value asset;
   disclosure can be fatal.
2. **Content** — research, drafts, documents, and their **titles** (titles
   alone often identify a subject or source).
3. **Journalist identity / authorship linkage** — which person operates an
   account or device.
4. **Availability** — the ability to publish and for readers to receive,
   despite censorship.
5. **Authenticity** — readers receiving genuine, untampered content.

## Adversary

We design against a **well-resourced, potentially nation-state adversary** who can:

* perform passive and active **network surveillance** (including TLS metadata,
  timing, and volume analysis);
* **seize the server** and all its storage at any time;
* **seize or borrow the journalist's device** (including covert imaging);
* **coerce** the journalist or a colleague (rubber-hose);
* run or compromise **mirrors / relays / IPFS nodes**;
* compel a hosting provider or CA.

We assume the adversary **cannot** break modern cryptographic primitives
(Ed25519, X25519, XChaCha20-Poly1305, Argon2id, BLAKE2b) and **cannot** extract
a passphrase that exists only in the journalist's memory and was never typed
into a compromised device.

## What we protect (and how)

| Asset | Protection | Mechanism |
|---|---|---|
| Content & titles confidentiality | Server seizure reveals nothing | Client-side per-document **XChaCha20-Poly1305**; titles+body+meta all inside the encrypted payload |
| Key compromise blast radius | Per-document keys; multi-recipient | Random DEK per doc, **X25519 sealed-box** envelope per recipient |
| Authenticity / anti-tampering | Offline-verifiable | **Ed25519** signature over a content-addressed manifest; reader pins author fingerprint |
| Identity portability | Recover on any device | **Argon2id** passphrase → seed → keypairs; **Shamir** k-of-n recovery shares |
| Server knowledge | Zero-knowledge relay | Content-addressed opaque blobs; **no logs**; no user DB; bind 127.0.0.1 |
| Network location | Anonymity transport | **Tor v3 onion** ingress; `socks5h://` egress (no DNS/IP leak) |
| Reader safety | No active content | Markdown→**allowlist-sanitized** HTML + **strict CSP** (no JS) + `no-referrer` |
| Source media metadata | Mandatory stripping | Image **re-encode** drops EXIF/XMP/IPTC; non-images rejected |
| Self-destruction | Crypto-shred | Shreddable docs keep the DEK only in a device-local vault; destroying it is irreversible |
| Coercion | Best-effort | Duress/decoy keystore slot; panic shred; dead-man's switch |
| Availability / censorship | Multi-channel | Same signed bundle over Tor, IPFS, USB/sneakernet, mesh |

## Non-goals / NOT protected (read this carefully)

* **A compromised client device before/while you use it.** If your device is
  already malware-infected or hardware-implanted, it can capture your
  passphrase and plaintext. Use a clean device (e.g. Tails); see `OPSEC.md`.
* **Cryptographically deniable storage.** The duress/decoy keystore is
  *best-effort*: an adversary who knows our file format can see that two slots
  exist. This is **not** a hidden-volume scheme and should not be presented to
  an adversary as proof there is nothing else.
* **Recovery of crypto-shredded or panicked shreddable documents.** That is the
  point — they are gone. Identity-sealed (normal) documents, by contrast,
  remain recoverable by anyone with the passphrase, so panic does **not** make
  them unreadable to a coercer who extracts your passphrase. Choose
  "shreddable" for anything you must be able to destroy.
* **Perfect traffic-analysis resistance.** Tor mitigates but does not eliminate
  timing/volume correlation by a global passive adversary. We pad bundle sizes
  but make no strong anonymity-set guarantee.
* **Deletion of content already replicated to IPFS or downloaded by others.**
  Content-addressed/immutable distribution cannot be recalled. `delete` only
  unpins from a cooperating relay.
* **Metadata that you place inside content.** We strip image metadata; we do
  **not** scrub identifying phrasing, writing style (stylometry), or facts you
  include.
* **Endpoint security of your readers.** We forbid active content to reduce
  risk, but a reader on a compromised device is beyond our reach.
* **PDFs / office documents / video.** Rejected, not sanitized — they carry too
  much hidden state to handle safely yet.

## Residual risks being tracked

* The capability-token write path is not yet bound to the connection
  (DPoP-style) and uses operator-enrolled keys rather than fully anonymous
  blinded-token / proof-of-work enrolment.
* No formal anonymity-set / cover-traffic design yet.
* GF(256) Shamir implementation is in-repo and must be covered by the external
  audit (everything else is libsodium).
* `shred_file` overwrite is best-effort on SSD/CoW filesystems.

## Trust assumptions summary

Trust: your memory (passphrase), a clean client device, libsodium, the math.
Do **not** trust: the server, the network, mirrors, the hosting provider, or
any device you did not bring up clean.
