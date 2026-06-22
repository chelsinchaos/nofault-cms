import pytest

from nofault.bundle import Bundle
from nofault.crypto.document import Document, decrypt_document, encrypt_document


def _make(alice, n=2):
    docs = []
    for i in range(n):
        enc, _ = encrypt_document(
            Document(doc_id=f"d{i}", title=f"T{i}", body_markdown=f"body {i}"), alice
        )
        docs.append(enc)
    return Bundle(docs=docs, author_verify_key=alice.verify_key_bytes)


def test_bundle_round_trip(alice):
    bundle = _make(alice)
    data = bundle.to_tar_bytes(alice)
    restored = Bundle.from_tar_bytes(data)
    assert len(restored.docs) == 2
    titles = {decrypt_document(d, alice).title for d in restored.docs}
    assert titles == {"T0", "T1"}


def test_bundle_is_deterministic_no_timestamps(alice):
    bundle = _make(alice, 1)
    a = bundle.to_tar_bytes(alice)
    b = bundle.to_tar_bytes(alice)
    assert a == b  # no mtime/uid leakage; reproducible


def test_bundle_tamper_in_blob_detected(alice):
    bundle = _make(alice)
    data = bytearray(bundle.to_tar_bytes(alice))
    # corrupt an actual ciphertext byte so the recomputed address won't match
    idx = data.find(bundle.docs[0].ciphertext)
    assert idx != -1
    data[idx] ^= 0x01
    with pytest.raises(ValueError):
        Bundle.from_tar_bytes(bytes(data))


def test_bundle_signing_identity_must_match(alice, bob):
    bundle = _make(alice, 1)
    with pytest.raises(ValueError):
        bundle.to_tar_bytes(bob)  # bob's key doesn't match bundle author key


def test_bundle_offline_verification_no_plaintext(alice):
    data = _make(alice, 1).to_tar_bytes(alice)
    assert b"T0" not in data
    assert b"body 0" not in data
