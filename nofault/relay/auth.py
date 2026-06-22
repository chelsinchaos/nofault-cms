"""Anonymous capability tokens for write access.

Reads are anonymous (publishing platform). Writes must be gated, or the relay
becomes an open dumping ground — but the gate must not deanonymise the
publisher and must not rely on per-IP limits (Tor users share exit IPs).

Design: the relay operator enrolls one or more **publisher verify-keys** (an
outlet's Ed25519 public keys). To write, a client proves control of an
enrolled key by signing a short-lived statement; the relay returns a bearer
capability token (an HMAC over ``pubkey || exp``). The relay learns only the
public key it already enrolled — no identity, no IP binding, no account.

This is deliberately simple and stateless. Hardening notes (token-to-connection
binding à la DPoP, blinded tokens / proof-of-work for fully anonymous
enrolment) are tracked in ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

MAX_TTL_SECONDS = 300
MAX_BLOB_BYTES = 25 * 1024 * 1024


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64u(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def build_auth_request(
    signing_key, ttl: int = MAX_TTL_SECONDS, *, now: float | None = None
) -> dict:
    """Client-side: build a signed request proving control of a publisher key."""
    now = time.time() if now is None else now
    exp = int(now) + int(ttl)
    pubkey = bytes(signing_key.verify_key)
    statement = json.dumps({"pubkey": _b64u(pubkey), "exp": exp}, sort_keys=True).encode()
    signature = signing_key.sign(statement).signature
    return {
        "statement": _b64u(statement),
        "signature": _b64u(signature),
    }


class CapabilityIssuer:
    def __init__(
        self,
        relay_secret: bytes,
        allowlist: set[str],
        *,
        max_ttl: int = MAX_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ):
        if len(relay_secret) < 32:
            raise ValueError("relay_secret must be >= 32 bytes")
        self._secret = relay_secret
        # allowlist holds hex-encoded Ed25519 verify keys
        self._allowlist = {k.lower() for k in allowlist}
        self._max_ttl = max_ttl
        self._clock = clock

    def _sign_token(self, pubkey_hex: str, exp: int) -> str:
        body = json.dumps({"pubkey": pubkey_hex, "exp": exp}, sort_keys=True).encode()
        tag = hmac.new(self._secret, body, hashlib.sha256).digest()
        return f"{_b64u(body)}.{_b64u(tag)}"

    def issue(self, request: dict) -> dict:
        """Verify a signed request and return ``{token, exp}``.

        Raises ``PermissionError`` if the key is not enrolled or the signature
        / expiry is invalid.
        """
        try:
            statement = _unb64u(request["statement"])
            signature = _unb64u(request["signature"])
            claims = json.loads(statement)
            pubkey = _unb64u(claims["pubkey"])
            exp = int(claims["exp"])
        except (KeyError, ValueError, TypeError) as exc:
            raise PermissionError("malformed auth request") from exc

        pubkey_hex = pubkey.hex()
        if pubkey_hex not in self._allowlist:
            raise PermissionError("publisher key not enrolled")

        try:
            VerifyKey(pubkey).verify(statement, signature)
        except (BadSignatureError, ValueError) as exc:
            raise PermissionError("bad signature") from exc

        now = self._clock()
        if exp <= now:
            raise PermissionError("request already expired")
        # clamp the granted TTL regardless of what the client asked for
        granted_exp = min(exp, int(now) + self._max_ttl)
        return {"token": self._sign_token(pubkey_hex, granted_exp), "exp": granted_exp}

    def verify(self, token: str) -> dict:
        """Validate a bearer token; return its claims or raise PermissionError."""
        try:
            body_b64, tag_b64 = token.split(".", 1)
            body = _unb64u(body_b64)
            tag = _unb64u(tag_b64)
        except (ValueError, TypeError) as exc:
            raise PermissionError("malformed token") from exc

        expected = hmac.new(self._secret, body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise PermissionError("bad token signature")

        claims = json.loads(body)
        if int(claims["exp"]) <= self._clock():
            raise PermissionError("token expired")
        return claims
