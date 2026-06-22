# Operational Security Guide (for journalists)

This tool is only as safe as how you use it. The software cannot protect you
from a compromised device or a leaked passphrase. Read this before relying on
NoFaultCMS for anything sensitive. When in doubt, slow down and consult your
outlet's security desk.

> Nothing here is a substitute for training. If a source's life may be at risk,
> get expert operational support.

## The one rule

**Your passphrase + a clean device = your identity.** If either is
compromised, so is everything you can decrypt. Protect both above all else.

## Use a clean, amnesic device

* Prefer **Tails** (booted from USB) or a dedicated, hardened laptop. An
  amnesic system means nothing persists locally after shutdown.
* Do **not** type your passphrase into a shared, work-issued, or untrusted
  computer. Keyloggers and implants defeat all the cryptography.
* Do **not** `apt-get install` random software onto Tails per ad-hoc guides.
  (The old `helpers/README.md` advice to do so was wrong and has been removed.)

## Passphrase & recovery

* Choose a long passphrase (a 6+ word diceware phrase). It is never stored; it
  *is* your identity and is recoverable only from your memory.
* Create **Shamir recovery shares** (`nofault recovery-split --shares 5
  --threshold 3`) and distribute them to trusted, separated parties. Any 3 can
  rebuild your identity if you forget the passphrase; any 2 learn nothing.
* Never store shares together or label them in a way that links them to you.

## Network

* Run the client over **Tor** (`--tor`). Never publish from your home/office IP.
* The relay is reached as a `.onion`; resolution happens inside Tor
  (`socks5h://`), so your IP and DNS do not leak.
* Be mindful of **timing**: publishing immediately after meeting a source can
  correlate you. Decouple authoring (offline) from publishing (later, over Tor).

## Content hygiene

* **Media:** the tool strips metadata from JPEG/PNG/WebP/GIF by re-encoding.
  It **rejects** PDFs, Office docs, and video — convert sensitive documents to
  flattened images yourself, on a clean device, and verify them.
* **Inside the text:** the tool cannot remove identifying details, source
  quotes that fingerprint a person, or your writing style. Edit for source
  protection deliberately.
* Published pages contain **no JavaScript** by design; do not try to add any.

## Choosing shreddable vs. normal documents

* **Normal** documents are recoverable on any device from your passphrase — but
  that means they cannot be truly destroyed, and anyone who extracts your
  passphrase can read them.
* **Shreddable** documents (`--shreddable`) keep their key only on this device.
  `nofault shred --doc-id ...` or `nofault panic` destroys it permanently.
  Use shreddable for the most sensitive material you must be able to erase.
  Trade-off: you cannot recover them on another device.

## Coercion & emergencies

* **Duress passphrase:** set one at `init --with-duress`. Entering it opens a
  decoy identity. Understand its limits (see `THREAT_MODEL.md`): a knowledgeable
  adversary can see a decoy slot exists.
* **Panic:** `nofault panic` destroys local secret material fast. It makes
  *shreddable* documents unrecoverable; it cannot un-ring already-published or
  passphrase-recoverable content.
* **Dead-man's switch:** `nofault deadman arm ...` releases a prepared bundle
  if you fail to check in. It depends on an external scheduler actually
  running; treat it as best-effort insurance, not a guarantee.

## Publishing is often irreversible

Content sent to IPFS or downloaded by readers **cannot be recalled**. Verify
twice before publishing. `delete` only unpins from a cooperating relay.

## For readers / recipients

* Verify bundles offline before trusting them:
  `nofault verify --in file.nfb --author-fingerprint nf1:...`
* Obtain the author's fingerprint over an independent, trusted channel.

## If something goes wrong

Report security issues per [`SECURITY.md`](../SECURITY.md). If a source may be
exposed, prioritize their physical safety over the story.
