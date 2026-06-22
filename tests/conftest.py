"""Shared fixtures. Uses the cheapest real Argon2id parameters so the suite is
fast while still exercising the genuine KDF path."""

from __future__ import annotations

import os

import nacl.pwhash
import pytest

from nofault.crypto.identity import Identity

# Real Argon2id, interactive cost — fast enough for CI, still the true code path.
FAST_KDF = {
    "opslimit": nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE,
    "memlimit": nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE,
}


@pytest.fixture
def alice() -> Identity:
    return Identity.from_seed(os.urandom(32))


@pytest.fixture
def bob() -> Identity:
    return Identity.from_seed(os.urandom(32))


@pytest.fixture
def eve() -> Identity:
    return Identity.from_seed(os.urandom(32))
