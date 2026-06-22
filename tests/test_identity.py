import os

import pytest

from nofault.crypto.identity import (
    Identity,
    new_salt,
    read_keystore,
    read_keystore_seed,
    shred_file,
    write_keystore,
)
from tests.conftest import FAST_KDF


def test_identity_deterministic_from_seed():
    seed = os.urandom(32)
    a = Identity.from_seed(seed)
    b = Identity.from_seed(seed)
    assert a.verify_key_bytes == b.verify_key_bytes
    assert a.box_public_bytes == b.box_public_bytes
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint.startswith("nf1:")


def test_signing_and_box_keys_differ():
    ident = Identity.from_seed(os.urandom(32))
    assert ident.verify_key_bytes != ident.box_public_bytes


def test_passphrase_recovery_is_device_agnostic():
    # Same passphrase + same salt -> same identity on any device.
    salt = new_salt()
    a = Identity.from_passphrase("correct horse battery staple", salt, **FAST_KDF)
    b = Identity.from_passphrase("correct horse battery staple", salt, **FAST_KDF)
    assert a.fingerprint == b.fingerprint
    c = Identity.from_passphrase("different", salt, **FAST_KDF)
    assert c.fingerprint != a.fingerprint


def test_keystore_round_trip(tmp_path):
    seed = os.urandom(32)
    path = str(tmp_path / "ks.json")
    write_keystore(path, "pw", seed, **FAST_KDF)
    assert read_keystore_seed(path, "pw") == seed
    assert read_keystore(path, "pw").fingerprint == Identity.from_seed(seed).fingerprint


def test_keystore_wrong_passphrase(tmp_path):
    path = str(tmp_path / "ks.json")
    write_keystore(path, "pw", os.urandom(32), **FAST_KDF)
    with pytest.raises(ValueError):
        read_keystore_seed(path, "wrong")


def test_duress_slot_returns_decoy(tmp_path):
    path = str(tmp_path / "ks.json")
    real = os.urandom(32)
    decoy = os.urandom(32)
    write_keystore(path, "real-pw", real, duress_passphrase="decoy-pw", duress_seed=decoy, **FAST_KDF)
    assert read_keystore_seed(path, "real-pw") == real
    assert read_keystore_seed(path, "decoy-pw") == decoy  # silently the decoy
    assert read_keystore_seed(path, "real-pw") != read_keystore_seed(path, "decoy-pw")


def test_keystore_permissions(tmp_path):
    path = str(tmp_path / "ks.json")
    write_keystore(path, "pw", os.urandom(32), **FAST_KDF)
    mode = os.stat(path).st_mode & 0o777
    assert mode == 0o600


def test_shred_file(tmp_path):
    path = str(tmp_path / "secret.bin")
    with open(path, "wb") as f:
        f.write(b"top secret")
    shred_file(path)
    assert not os.path.exists(path)
    shred_file(path)  # idempotent on missing file
