"""Shamir secret sharing over GF(2^8) for key recovery / escrow.

Used to split a 32-byte root seed into ``n`` shares such that any ``k`` of them
reconstruct it, and any ``k-1`` reveal nothing. This backs the "recover your
identity on a new device after device loss" and "trusted-colleague escrow"
features.

Construction notes (for the auditor):

* We use the standard AES field GF(2^8) with reducing polynomial 0x11B.
* Each secret byte is shared independently with an independent random
  polynomial whose constant term is the secret byte.
* Share x-coordinates are 1..n (never 0, since f(0) is the secret).
* This module is pure-Python and constant-time-ish but NOT hardened against
  side channels; it operates on at-rest recovery material, not online secrets.

This is the one primitive in the crypto core that is not delegated to
libsodium, because libsodium has no secret-sharing API. It is covered by
known-answer and round-trip tests and is explicitly in scope for the external
audit.
"""

from __future__ import annotations

import secrets

# --- GF(2^8) arithmetic via exp/log tables (generator 0x03) ---------------

_EXP = [0] * 512
_LOG = [0] * 256


def _build_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # multiply by generator 3: x = x*2 ^ x, with reduction by 0x11b
        x2 = x << 1
        if x2 & 0x100:
            x2 ^= 0x11B
        x = x2 ^ x
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def _gmul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gdiv(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(2^8)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _eval_poly(coeffs: list[int], x: int) -> int:
    """Evaluate polynomial (coeffs[0] = constant term) at x in GF(2^8)."""
    result = 0
    for coeff in reversed(coeffs):
        result = _gmul(result, x) ^ coeff
    return result


def split(secret: bytes, k: int, n: int) -> list[tuple[int, bytes]]:
    """Split ``secret`` into ``n`` shares; any ``k`` reconstruct it.

    Returns a list of ``(x, share_bytes)`` where ``x`` is 1..n and
    ``share_bytes`` has the same length as ``secret``.
    """
    if not 1 <= k <= n <= 255:
        raise ValueError("require 1 <= k <= n <= 255")
    if k == 1:
        # Degenerate: every share is the secret itself.
        return [(i + 1, bytes(secret)) for i in range(n)]
    if len(secret) == 0:
        raise ValueError("secret must be non-empty")

    shares: list[bytearray] = [bytearray() for _ in range(n)]
    for byte in secret:
        # random degree-(k-1) polynomial with constant term = byte
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(k - 1)]
        for i in range(n):
            x = i + 1
            shares[i].append(_eval_poly(coeffs, x))
    return [(i + 1, bytes(shares[i])) for i in range(n)]


def combine(shares: list[tuple[int, bytes]]) -> bytes:
    """Reconstruct the secret from ``k`` (or more) ``(x, share_bytes)`` pairs."""
    if not shares:
        raise ValueError("no shares provided")
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share x-coordinates")
    length = len(shares[0][1])
    if any(len(s) != length for _, s in shares):
        raise ValueError("shares differ in length")

    secret = bytearray(length)
    for pos in range(length):
        # Lagrange interpolation at x=0 over GF(2^8).
        acc = 0
        for j, (xj, sj) in enumerate(shares):
            num, den = 1, 1
            for m, (xm, _) in enumerate(shares):
                if m == j:
                    continue
                num = _gmul(num, xm)
                den = _gmul(den, xj ^ xm)
            lagrange = _gdiv(num, den)
            acc ^= _gmul(sj[pos], lagrange)
        secret[pos] = acc
    return bytes(secret)
