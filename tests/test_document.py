import pytest
from nacl.exceptions import CryptoError

from nofault.crypto.document import (
    Document,
    EncryptedDocument,
    decrypt_document,
    decrypt_with_dek,
    encrypt_document,
    verify,
)


def _doc(**kw):
    base = {"doc_id": "abc123", "title": "The Leak", "body_markdown": "# secret\nbody"}
    base.update(kw)
    return Document(**base)


def test_encrypt_decrypt_round_trip(alice):
    encdoc, _ = encrypt_document(_doc(), alice)
    out = decrypt_document(encdoc, alice)
    assert out.title == "The Leak"
    assert out.body_markdown == "# secret\nbody"


def test_title_and_body_not_in_ciphertext(alice):
    encdoc, _ = encrypt_document(_doc(), alice)
    blob_bytes = b"".join(encdoc.to_blobs().values())
    assert b"The Leak" not in blob_bytes
    assert b"secret" not in blob_bytes


def test_authorized_recipient_can_read(alice, bob):
    encdoc, _ = encrypt_document(_doc(), alice, recipients=[bob.box_public_bytes])
    assert decrypt_document(encdoc, bob).title == "The Leak"
    assert decrypt_document(encdoc, alice).title == "The Leak"  # author always can


def test_unauthorized_recipient_cannot_read(alice, eve):
    encdoc, _ = encrypt_document(_doc(), alice)  # eve not a recipient
    with pytest.raises(CryptoError):
        decrypt_document(encdoc, eve)


def test_signature_tamper_detected(alice):
    encdoc, _ = encrypt_document(_doc(), alice)
    encdoc.manifest["doc_id"] = "tampered"
    assert verify(encdoc) is False
    with pytest.raises(CryptoError):
        decrypt_document(encdoc, alice)


def test_ciphertext_tamper_detected(alice):
    encdoc, _ = encrypt_document(_doc(), alice)
    encdoc.ciphertext = encdoc.ciphertext + b"x"
    # address no longer matches the signed manifest
    assert verify(encdoc) is False


def test_author_fingerprint_pinning(alice, eve):
    encdoc, _ = encrypt_document(_doc(), alice)
    assert verify(encdoc, expected_author_fingerprint=alice.fingerprint) is True
    # a hostile mirror re-signing with eve's key cannot pass alice's pin
    forged, _ = encrypt_document(_doc(), eve)
    assert verify(forged, expected_author_fingerprint=alice.fingerprint) is False


def test_key_substitution_attack_fails(alice, eve):
    # Attacker keeps alice's manifest claim but swaps in their own verify key
    encdoc, _ = encrypt_document(_doc(), alice)
    encdoc.author_verify_key = eve.verify_key_bytes
    assert verify(encdoc) is False  # signature no longer matches


def test_version_chain(alice):
    v1, _ = encrypt_document(_doc(version=1), alice)
    v2, _ = encrypt_document(
        _doc(version=2, prev_address=v1.manifest_address), alice
    )
    assert v2.manifest["prev_address"] == v1.manifest_address
    assert v2.manifest["version"] == 2


def test_shreddable_path_with_dek(alice):
    encdoc, dek = encrypt_document(_doc(), alice, include_author=False)
    # author is NOT a recipient -> identity cannot decrypt
    with pytest.raises(CryptoError):
        decrypt_document(encdoc, alice)
    # but the DEK can
    assert decrypt_with_dek(encdoc, dek).title == "The Leak"


def test_serialization_round_trip(alice):
    encdoc, _ = encrypt_document(_doc(), alice)
    blobs = encdoc.to_blobs()
    manifest_blob = blobs[encdoc.manifest_address]
    rebuilt = EncryptedDocument.from_manifest_blob(manifest_blob, encdoc.ciphertext)
    assert verify(rebuilt)
    assert decrypt_document(rebuilt, alice).title == "The Leak"
