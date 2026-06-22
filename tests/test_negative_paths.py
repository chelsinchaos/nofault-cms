"""Error-path and edge-case coverage for the security-critical branches."""

import io
import os
import tarfile

import pytest
from fastapi.testclient import TestClient
from nacl.exceptions import CryptoError

from nofault.bundle import Bundle
from nofault.client.repo import Repo
from nofault.client.transport import RelayClient, RelayError
from nofault.crypto import aead
from nofault.crypto.document import Document, decrypt_with_dek, encrypt_document
from nofault.crypto.identity import Identity, new_salt
from nofault.relay.app import create_app
from nofault.relay.auth import CapabilityIssuer
from nofault.relay.store import BlobStore

# --- aead -----------------------------------------------------------------

def test_aead_decrypt_rejects_bad_key_size():
    with pytest.raises(ValueError):
        aead.decrypt(os.urandom(16), b"x" * 40)


def test_aead_decrypt_rejects_short_blob():
    with pytest.raises(ValueError):
        aead.decrypt(aead.generate_key(), b"short")


# --- identity -------------------------------------------------------------

def test_identity_rejects_bad_seed_length():
    with pytest.raises(ValueError):
        Identity.from_seed(b"too-short")


def test_new_salt_length():
    from nofault.crypto.identity import SALT_BYTES

    assert len(new_salt()) == SALT_BYTES


def test_duress_order_randomized_both_directions(tmp_path):
    # Write many keystores; both passphrases must always open their own seed
    # regardless of internal slot order.
    from nofault.crypto.identity import read_keystore_seed, write_keystore
    from tests.conftest import FAST_KDF

    for i in range(6):
        path = str(tmp_path / f"ks{i}.json")
        real, decoy = os.urandom(32), os.urandom(32)
        write_keystore(path, "r", real, duress_passphrase="d", duress_seed=decoy, **FAST_KDF)
        assert read_keystore_seed(path, "r") == real
        assert read_keystore_seed(path, "d") == decoy


# --- document -------------------------------------------------------------

def test_decrypt_with_dek_rejects_tampered(alice):
    encdoc, dek = encrypt_document(
        Document(doc_id="x", title="t", body_markdown="b"), alice, include_author=False
    )
    encdoc.manifest["doc_id"] = "tampered"
    with pytest.raises(CryptoError):
        decrypt_with_dek(encdoc, dek)


# --- relay store ----------------------------------------------------------

def test_store_delete_malformed_address(tmp_path):
    store = BlobStore(str(tmp_path))
    assert store.delete("not-an-address") is False


def test_store_iter_skips_tmp(tmp_path):
    store = BlobStore(str(tmp_path))
    store.put(b"real-blob")
    # a stray temp file must not be yielded as a blob
    with open(os.path.join(str(tmp_path), "stray.tmp"), "wb") as f:
        f.write(b"junk")
    paths = list(store.iter_blob_paths())
    assert all(not p.endswith(".tmp") for p in paths)
    assert len(paths) == 1


# --- relay auth -----------------------------------------------------------

def test_issuer_rejects_malformed_request():
    issuer = CapabilityIssuer(os.urandom(32), set())
    with pytest.raises(PermissionError):
        issuer.issue({"nonsense": "value"})


def test_issuer_rejects_malformed_token():
    issuer = CapabilityIssuer(os.urandom(32), set())
    with pytest.raises(PermissionError):
        issuer.verify("not.a.valid.token")


def test_issuer_requires_strong_secret():
    with pytest.raises(ValueError):
        CapabilityIssuer(b"short", set())


# --- bundle ---------------------------------------------------------------

def test_bundle_missing_index_rejected():
    # a tar with no index.json must be rejected
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("blobs/whatever")
        data = b"orphan"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(ValueError):
        Bundle.from_tar_bytes(buf.getvalue())


# --- repo -----------------------------------------------------------------

def test_repo_edit_unknown_doc(tmp_path, alice):
    repo = Repo(str(tmp_path / "repo"), alice)
    with pytest.raises(KeyError):
        repo.edit("does-not-exist", title="x", body_markdown="y")


def test_repo_delete_unknown_returns_empty(tmp_path, alice):
    repo = Repo(str(tmp_path / "repo"), alice)
    assert repo.delete("nope") == []


def test_repo_latest_address(tmp_path, alice):
    repo = Repo(str(tmp_path / "repo"), alice)
    enc = repo.create("A", "a")
    assert repo.latest_address(enc.manifest["doc_id"]) == enc.manifest_address


# --- transport ------------------------------------------------------------

def _client(tmp_path, alice):
    store = BlobStore(str(tmp_path / "blobs"))
    issuer = CapabilityIssuer(os.urandom(32), {alice.verify_key_bytes.hex()})
    return RelayClient(TestClient(create_app(store, issuer)))


def test_transport_refuses_to_publish_unverifiable(tmp_path, alice):
    client = _client(tmp_path, alice)
    encdoc, _ = encrypt_document(Document(doc_id="x", title="t", body_markdown="b"), alice)
    encdoc.manifest["doc_id"] = "tampered"  # breaks signature
    with pytest.raises(RelayError):
        client.publish(encdoc, alice)


def test_transport_fetch_missing_ciphertext(tmp_path, alice):
    client = _client(tmp_path, alice)
    encdoc, _ = encrypt_document(Document(doc_id="x", title="t", body_markdown="b"), alice)
    token = client.request_token(alice)
    # upload ONLY the manifest blob, not the ciphertext
    manifest_blob = encdoc.signed_manifest_bytes()
    addr = client.put_blob(manifest_blob, token)
    with pytest.raises(RelayError):
        client.fetch(addr)
