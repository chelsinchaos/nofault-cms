import os

import pytest
from fastapi.testclient import TestClient

from nofault.client.transport import RelayClient
from nofault.crypto.document import Document, decrypt_document, encrypt_document
from nofault.relay.app import create_app
from nofault.relay.auth import CapabilityIssuer
from nofault.relay.store import BlobStore


@pytest.fixture
def relay_client(tmp_path, alice):
    store = BlobStore(str(tmp_path / "blobs"))
    issuer = CapabilityIssuer(os.urandom(32), {alice.verify_key_bytes.hex()})
    http = TestClient(create_app(store, issuer))
    return RelayClient(http), alice


def test_publish_then_fetch_round_trip(relay_client):
    client, alice = relay_client
    enc, _ = encrypt_document(Document(doc_id="x1", title="Hdr", body_markdown="b"), alice)
    addr = client.publish(enc, alice)
    fetched = client.fetch(addr)
    assert decrypt_document(fetched, alice).title == "Hdr"


def test_fetch_missing_raises(relay_client):
    client, _ = relay_client
    from nofault.client.transport import RelayError

    with pytest.raises(RelayError):
        client.fetch("b2:" + "0" * 64)
