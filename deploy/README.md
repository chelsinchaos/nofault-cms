# Deploying the NoFault relay (onion-only)

The relay is a zero-knowledge blob store. It learns nothing about content and
keeps no logs. It is reachable **only** through a Tor v3 onion service — no host
ports are published.

## 1. Generate a relay token-signing secret

```bash
export NOFAULT_RELAY_SECRET=$(python3 -c "import os;print(os.urandom(32).hex())")
```

Keep this out of shell history / images / version control. It only signs
short-lived write tokens; rotating it simply invalidates outstanding tokens.

## 2. Enroll publisher keys

Each journalist runs `nofault whoami` and sends you their **publisher
verify-key** (hex) over a trusted channel. Concatenate them:

```bash
export NOFAULT_RELAY_ALLOWLIST="<hexkey1>,<hexkey2>"
```

Enrolling a public key lets that author obtain write tokens. It does **not**
tell the relay who they are.

## 3. Start

```bash
docker compose -f deploy/docker-compose.yml up --build -d
```

## 4. Read the onion address

```bash
docker compose -f deploy/docker-compose.yml exec tor cat /var/lib/tor/nofault/hostname
```

Distribute that `.onion` to authors (`--relay http://<onion> --tor`) and to
readers.

## Hardening notes (production)

* **Pin base images by digest** (both `python:3.12-slim` and the tor image).
  The tags here are for readability.
* Back up `tor_hidden_service` (the onion private key) securely; losing it
  changes your address, leaking it lets someone impersonate the address.
* Run on a host with full-disk encryption; the blobs are ciphertext but the
  onion key and relay secret are sensitive.
* Consider client authorization (`HiddenServiceAuthorizeClient`) to make the
  onion address itself a shared secret among trusted authors/readers.
* The relay's `delete` (unpin) is intentionally not exposed over HTTP; operate
  it out-of-band.
