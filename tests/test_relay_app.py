import os

import pytest
from fastapi.testclient import TestClient

from nofault.relay.app import create_app
from nofault.relay.auth import CapabilityIssuer, build_auth_request
from nofault.relay.store import BlobStore


@pytest.fixture
def app_client(tmp_path, alice):
    store = BlobStore(str(tmp_path / "blobs"))
    issuer = CapabilityIssuer(os.urandom(32), {alice.verify_key_bytes.hex()})
    return TestClient(create_app(store, issuer, max_blob_bytes=1024)), alice


def _token(client, identity):
    resp = client.post("/auth/token", json=build_auth_request(identity.signing_key))
    assert resp.status_code == 200
    return resp.json()["token"]


def test_healthz(app_client):
    client, _ = app_client
    assert client.get("/healthz").json() == {"status": "ok"}


def test_put_requires_token(app_client):
    client, _ = app_client
    resp = client.put("/blob", content=b"data")
    assert resp.status_code == 401


def test_put_and_get(app_client):
    client, alice = app_client
    token = _token(client, alice)
    resp = client.put("/blob", content=b"ciphertext", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    addr = resp.json()["address"]
    got = client.get(f"/blob/{addr}")
    assert got.status_code == 200
    assert got.content == b"ciphertext"


def test_get_anonymous_no_auth_needed(app_client):
    client, alice = app_client
    token = _token(client, alice)
    addr = client.put("/blob", content=b"x", headers={"Authorization": f"Bearer {token}"}).json()["address"]
    # no auth header on GET
    assert client.get(f"/blob/{addr}").status_code == 200


def test_unenrolled_cannot_get_token(app_client, eve):
    client, _ = app_client
    resp = client.post("/auth/token", json=build_auth_request(eve.signing_key))
    assert resp.status_code == 403


def test_blob_too_large_rejected(app_client):
    client, alice = app_client
    token = _token(client, alice)
    resp = client.put("/blob", content=b"x" * 2048, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 413


def test_missing_blob_404(app_client):
    client, _ = app_client
    assert client.get("/blob/b2:" + "0" * 64).status_code == 404
