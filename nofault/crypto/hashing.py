"""Content addressing via BLAKE2b.

A blob's address is the BLAKE2b-256 digest of its *ciphertext*. Addressing the
ciphertext (not the plaintext) is deliberate: the relay can verify that a blob
matches its claimed address without ever seeing plaintext, and two encryptions
of the same plaintext produce different addresses (no equality leakage).
"""

from __future__ import annotations

import hashlib

# 32 bytes / 256 bits. Stable on-disk and on-wire identifier length.
DIGEST_SIZE = 32
ADDRESS_PREFIX = "b2"  # versioned address scheme tag


def content_address(data: bytes) -> str:
    """Return the canonical content address for ``data``.

    Format: ``"b2:<64 hex chars>"``. The prefix lets us migrate hash schemes
    later without ambiguity.
    """
    digest = hashlib.blake2b(data, digest_size=DIGEST_SIZE).hexdigest()
    return f"{ADDRESS_PREFIX}:{digest}"


def verify_address(data: bytes, address: str) -> bool:
    """Constant-time-ish check that ``data`` hashes to ``address``.

    ``hmac.compare_digest`` is used to avoid leaking match position via timing,
    which matters because addresses are attacker-influenced on the relay.
    """
    import hmac

    return hmac.compare_digest(content_address(data), address)
