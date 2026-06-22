"""THE invariant test: a seized relay yields no plaintext and no identity-recovering secret.

If this test ever regresses, the system has lost its entire reason to exist.
It is marked ``security`` so it can be run as a required gate.
"""

import os

import pytest
from fastapi.testclient import TestClient

from nofault.client.repo import Repo
from nofault.client.transport import RelayClient
from nofault.crypto.identity import Identity
from nofault.relay.app import create_app
from nofault.relay.auth import CapabilityIssuer
from nofault.relay.store import BlobStore

# Distinctive sentinels so "absent" is meaningful.
SECRET_TITLE = "ZZZ-SECRET-TITLE-minister-bribery-ledger-7f3a"
SECRET_BODY = "ZZZ-SECRET-BODY-source-is-in-apartment-4b-deepthroat"


pytestmark = pytest.mark.security


@pytest.fixture
def published(tmp_path):
    alice = Identity.from_seed(os.urandom(32))
    store_root = str(tmp_path / "relay-data")
    store = BlobStore(store_root)
    issuer = CapabilityIssuer(os.urandom(32), {alice.verify_key_bytes.hex()})
    http = TestClient(create_app(store, issuer))
    client = RelayClient(http)

    repo = Repo(str(tmp_path / "repo"), alice)
    enc_normal = repo.create(SECRET_TITLE, SECRET_BODY)
    enc_shred = repo.create(SECRET_TITLE + "-2", SECRET_BODY + "-2", shreddable=True)
    client.publish(enc_normal, alice)
    client.publish(enc_shred, alice)
    return store_root, alice, repo


def _all_relay_bytes(store_root: str) -> bytes:
    chunks = []
    for dirpath, _dirs, files in os.walk(store_root):
        for name in files:
            with open(os.path.join(dirpath, name), "rb") as f:
                chunks.append(f.read())
    return b"".join(chunks)


def test_no_plaintext_title_or_body_on_disk(published):
    store_root, _alice, _repo = published
    blob = _all_relay_bytes(store_root)
    assert blob, "expected blobs on the relay"
    assert SECRET_TITLE.encode() not in blob
    assert SECRET_BODY.encode() not in blob
    assert (SECRET_TITLE + "-2").encode() not in blob
    assert (SECRET_BODY + "-2").encode() not in blob


def test_no_private_key_material_on_disk(published):
    store_root, alice, _repo = published
    blob = _all_relay_bytes(store_root)
    # the author's private signing/box keys must never reach the relay
    assert bytes(alice.signing_key) not in blob
    assert bytes(alice.box_private) not in blob


def test_relay_keeps_no_request_logs(published):
    store_root, _alice, _repo = published
    for _dirpath, _dirs, files in os.walk(store_root):
        for name in files:
            assert not name.endswith(".log")


def test_operator_with_all_blobs_cannot_decrypt(published, tmp_path):
    store_root, _alice, _repo = published
    # An adversary who seizes the relay and has all blobs but a different
    # identity learns nothing.
    eve = Identity.from_seed(os.urandom(32))
    import json

    from nofault.crypto.document import EncryptedDocument, verify

    decrypted_any = False
    # Reconstruct each manifest+ciphertext pair from disk and try to read it.
    blobs = {}
    for dirpath, _dirs, files in os.walk(store_root):
        for name in files:
            with open(os.path.join(dirpath, name), "rb") as f:
                data = f.read()
            blobs[name] = data
    for data in list(blobs.values()):
        try:
            outer = json.loads(data)
            ct_addr = outer["manifest"]["ciphertext_address"]
        except Exception:
            continue
        ct_name = ct_addr.split(":", 1)[1]
        if ct_name not in blobs:
            continue
        encdoc = EncryptedDocument.from_manifest_blob(data, blobs[ct_name])
        assert verify(encdoc)  # signature still verifies (public)
        try:
            from nofault.crypto.document import decrypt_document

            decrypt_document(encdoc, eve)
            decrypted_any = True
        except Exception:
            pass
    assert decrypted_any is False
