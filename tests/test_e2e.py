"""End-to-end journeys across multiple transports, proving the same encrypted
artifact verifies and decrypts whether it arrived over the relay or as an
offline bundle (transmission-agnostic)."""

import os

import pytest
from fastapi.testclient import TestClient

from nofault.bundle import Bundle
from nofault.client.repo import Repo
from nofault.client.transport import RelayClient
from nofault.crypto.identity import Identity
from nofault.relay.app import create_app
from nofault.relay.auth import CapabilityIssuer
from nofault.relay.store import BlobStore
from nofault.render.html import render_page

pytestmark = pytest.mark.integration


def test_author_to_relay_to_reader_render(tmp_path):
    alice = Identity.from_seed(os.urandom(32))
    store = BlobStore(str(tmp_path / "r"))
    issuer = CapabilityIssuer(os.urandom(32), {alice.verify_key_bytes.hex()})
    client = RelayClient(TestClient(create_app(store, issuer)))

    repo = Repo(str(tmp_path / "repo"), alice)
    enc = repo.create("Investigation", "## Findings\n\nThe **ledger** shows bribery.")
    addr = client.publish(enc, alice)

    fetched = client.fetch(addr)
    doc = repo.open(fetched)
    page = render_page(doc.title, doc.body_markdown)
    assert "Investigation" in page
    assert "<strong>ledger</strong>" in page
    assert "default-src 'none'" in page


def test_offline_sneakernet_bundle_journey(tmp_path):
    """Author exports a bundle to 'USB'; an independent reader imports it on a
    fresh machine and verifies it offline against the author's pinned key."""
    alice = Identity.from_seed(os.urandom(32))
    repo = Repo(str(tmp_path / "repo"), alice)
    enc = repo.create("Border Story", "smuggled across as a file")

    bundle = Bundle(docs=[repo.get_encrypted(enc.manifest["doc_id"])],
                    author_verify_key=alice.verify_key_bytes)
    usb_bytes = bundle.to_tar_bytes(alice)

    # ... carried across a border, opened on a clean device ...
    received = Bundle.from_tar_bytes(usb_bytes)
    from nofault.crypto.document import decrypt_document, verify

    assert all(verify(d, expected_author_fingerprint=alice.fingerprint) for d in received.docs)
    # alice (or any authorized recipient) can read it
    assert decrypt_document(received.docs[0], alice).title == "Border Story"


def test_tampered_bundle_from_hostile_mirror_rejected(tmp_path):
    alice = Identity.from_seed(os.urandom(32))
    repo = Repo(str(tmp_path / "repo"), alice)
    enc = repo.create("Real", "authentic content")
    ed = repo.get_encrypted(enc.manifest["doc_id"])
    bundle = Bundle(docs=[ed], author_verify_key=alice.verify_key_bytes)
    data = bytearray(bundle.to_tar_bytes(alice))
    # corrupt an actual ciphertext byte (not tar padding) -> address mismatch
    idx = data.find(ed.ciphertext)
    assert idx != -1
    data[idx] ^= 0xFF
    with pytest.raises(ValueError):
        Bundle.from_tar_bytes(bytes(data))
