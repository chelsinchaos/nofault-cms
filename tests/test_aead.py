import os

import pytest
from nacl.exceptions import CryptoError

from nofault.crypto import aead


def test_round_trip():
    key = aead.generate_key()
    msg = b"contested-environment payload"
    blob = aead.encrypt(key, msg)
    assert aead.decrypt(key, blob) == msg


def test_nonce_is_random_per_call():
    key = aead.generate_key()
    a = aead.encrypt(key, b"same")
    b = aead.encrypt(key, b"same")
    assert a != b  # nonce differs => ciphertext differs (no equality leak)


def test_wrong_key_fails():
    blob = aead.encrypt(aead.generate_key(), b"secret")
    with pytest.raises(CryptoError):
        aead.decrypt(aead.generate_key(), blob)


def test_tamper_detected():
    key = aead.generate_key()
    blob = bytearray(aead.encrypt(key, b"secret"))
    blob[-1] ^= 0x01
    with pytest.raises(CryptoError):
        aead.decrypt(key, bytes(blob))


def test_aad_must_match():
    key = aead.generate_key()
    blob = aead.encrypt(key, b"x", aad=b"context-A")
    with pytest.raises(CryptoError):
        aead.decrypt(key, blob, aad=b"context-B")


def test_bad_key_size():
    with pytest.raises(ValueError):
        aead.encrypt(os.urandom(16), b"x")
