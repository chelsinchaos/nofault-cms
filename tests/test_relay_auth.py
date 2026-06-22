import os

import pytest

from nofault.relay.auth import CapabilityIssuer, build_auth_request


def _issuer(publisher_vk_hex, *, now_holder):
    return CapabilityIssuer(
        os.urandom(32), {publisher_vk_hex}, clock=lambda: now_holder["t"]
    )


def test_enrolled_publisher_gets_token(alice):
    now = {"t": 1000.0}
    issuer = _issuer(alice.verify_key_bytes.hex(), now_holder=now)
    req = build_auth_request(alice.signing_key, now=1000.0)
    granted = issuer.issue(req)
    claims = issuer.verify(granted["token"])
    assert claims["pubkey"] == alice.verify_key_bytes.hex()


def test_unenrolled_publisher_rejected(alice, eve):
    now = {"t": 1000.0}
    issuer = _issuer(alice.verify_key_bytes.hex(), now_holder=now)
    req = build_auth_request(eve.signing_key, now=1000.0)
    with pytest.raises(PermissionError):
        issuer.issue(req)


def test_bad_signature_rejected(alice):
    now = {"t": 1000.0}
    issuer = _issuer(alice.verify_key_bytes.hex(), now_holder=now)
    req = build_auth_request(alice.signing_key, now=1000.0)
    req["signature"] = req["signature"][:-2] + ("AA" if not req["signature"].endswith("AA") else "BB")
    with pytest.raises(PermissionError):
        issuer.issue(req)


def test_token_expires(alice):
    now = {"t": 1000.0}
    issuer = _issuer(alice.verify_key_bytes.hex(), now_holder=now)
    granted = issuer.issue(build_auth_request(alice.signing_key, ttl=60, now=1000.0))
    issuer.verify(granted["token"])  # ok now
    now["t"] = 2000.0  # well past expiry
    with pytest.raises(PermissionError):
        issuer.verify(granted["token"])


def test_ttl_is_clamped(alice):
    now = {"t": 1000.0}
    issuer = CapabilityIssuer(
        os.urandom(32), {alice.verify_key_bytes.hex()}, max_ttl=100, clock=lambda: now["t"]
    )
    granted = issuer.issue(build_auth_request(alice.signing_key, ttl=99999, now=1000.0))
    assert granted["exp"] <= 1000 + 100


def test_forged_token_rejected(alice):
    now = {"t": 1000.0}
    issuer = _issuer(alice.verify_key_bytes.hex(), now_holder=now)
    granted = issuer.issue(build_auth_request(alice.signing_key, now=1000.0))
    body, _tag = granted["token"].split(".", 1)
    forged = body + "." + "AAAA"
    with pytest.raises(PermissionError):
        issuer.verify(forged)


def test_token_from_other_relay_secret_rejected(alice):
    now = {"t": 1000.0}
    a = CapabilityIssuer(os.urandom(32), {alice.verify_key_bytes.hex()}, clock=lambda: now["t"])
    b = CapabilityIssuer(os.urandom(32), {alice.verify_key_bytes.hex()}, clock=lambda: now["t"])
    token = a.issue(build_auth_request(alice.signing_key, now=1000.0))["token"]
    with pytest.raises(PermissionError):
        b.verify(token)  # different relay secret
