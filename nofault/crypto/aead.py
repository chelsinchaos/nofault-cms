"""Authenticated encryption via XChaCha20-Poly1305 (libsodium).

XChaCha20-Poly1305 is chosen over AES-GCM because its 24-byte random nonce can
be generated safely without a counter or per-key nonce bookkeeping — important
for a client that may run on borrowed hardware with no reliable state. The
output is ``nonce || ciphertext_with_tag`` so callers never manage nonces.

This replaces every broken cipher in the original codebase (the fictional
"AES-512", the reused/never-transmitted IV, the no-integrity CFB mode, and the
single shared Fernet key).
"""

from __future__ import annotations

import nacl.bindings as _b

KEY_BYTES = _b.crypto_aead_xchacha20poly1305_ietf_KEYBYTES  # 32
NONCE_BYTES = _b.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24


def generate_key() -> bytes:
    """Return a fresh 32-byte AEAD key from the OS CSPRNG."""
    return _b.randombytes(KEY_BYTES)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt ``plaintext`` under ``key``; returns ``nonce || ct``.

    ``aad`` (additional authenticated data) is authenticated but not encrypted.
    """
    if len(key) != KEY_BYTES:
        raise ValueError(f"key must be {KEY_BYTES} bytes")
    nonce = _b.randombytes(NONCE_BYTES)
    ct = _b.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return nonce + ct


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Decrypt ``nonce || ct`` produced by :func:`encrypt`.

    Raises ``nacl.exceptions.CryptoError`` (or ValueError for malformed input)
    if the key/aad is wrong or the ciphertext was tampered with.
    """
    if len(key) != KEY_BYTES:
        raise ValueError(f"key must be {KEY_BYTES} bytes")
    if len(blob) < NONCE_BYTES:
        raise ValueError("ciphertext too short")
    nonce, ct = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    return _b.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, nonce, key)
