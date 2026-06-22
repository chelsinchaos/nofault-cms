import os

import pytest

from nofault.crypto import shamir


def test_round_trip_k_of_n():
    secret = os.urandom(32)
    shares = shamir.split(secret, 3, 5)
    assert len(shares) == 5
    # any 3 reconstruct
    assert shamir.combine(shares[:3]) == secret
    assert shamir.combine(shares[1:4]) == secret
    assert shamir.combine([shares[0], shares[2], shares[4]]) == secret


def test_all_shares_reconstruct():
    secret = b"the source is in apartment 4b"
    shares = shamir.split(secret, 2, 4)
    assert shamir.combine(shares) == secret


def test_fewer_than_threshold_does_not_reveal_secret():
    secret = os.urandom(32)
    shares = shamir.split(secret, 3, 5)
    # 2 shares (below threshold) must not yield the secret
    wrong = shamir.combine(shares[:2])
    assert wrong != secret


def test_k_equals_one_degenerate():
    secret = b"\x01\x02\x03"
    shares = shamir.split(secret, 1, 3)
    assert all(s == secret for _, s in shares)
    assert shamir.combine([shares[0]]) == secret


def test_known_answer_gf_mul():
    # GF(2^8) sanity: 0x53 * 0xCA = 0x01 (classic AES inverse pair)
    assert shamir._gmul(0x53, 0xCA) == 0x01
    assert shamir._gmul(0, 123) == 0
    assert shamir._gmul(1, 200) == 200


def test_invalid_params():
    with pytest.raises(ValueError):
        shamir.split(b"x", 5, 3)  # k > n
    with pytest.raises(ValueError):
        shamir.split(b"", 2, 3)  # empty secret
    with pytest.raises(ValueError):
        shamir.combine([(1, b"aa"), (1, b"bb")])  # duplicate x


def test_corrupted_share_changes_output():
    secret = os.urandom(16)
    shares = shamir.split(secret, 2, 3)
    x, s = shares[0]
    corrupted = (x, bytes([s[0] ^ 0xFF]) + s[1:])
    assert shamir.combine([corrupted, shares[1]]) != secret
