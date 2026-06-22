"""Relay transport — pluggable, Tor-by-default.

A thin client over the relay's HTTP API. In production the ``base_url`` is a
``.onion`` address and traffic is routed through Tor's SOCKS proxy
(``socks5h://`` so that onion resolution happens inside Tor, never leaking DNS
or the publisher's IP). For tests we inject an in-process ASGI client.

The same encrypted artifacts also travel as offline bundles (see
``nofault.bundle``); this transport is just one of several interchangeable
channels.
"""

from __future__ import annotations

from typing import Any

from ..crypto.document import EncryptedDocument, verify
from ..crypto.identity import Identity
from ..relay.auth import build_auth_request


class RelayError(RuntimeError):
    pass


class RelayClient:
    def __init__(self, http_client: Any):
        # http_client is an httpx.Client (or FastAPI TestClient) with a base_url
        self._http = http_client

    @classmethod
    def over_tor(  # pragma: no cover - requires a live Tor daemon
        cls, onion_base_url: str, *, socks_port: int = 9050, timeout: float = 60.0
    ) -> RelayClient:
        import httpx

        client = httpx.Client(
            base_url=onion_base_url,
            proxy=f"socks5h://127.0.0.1:{socks_port}",
            timeout=timeout,
        )
        return cls(client)

    def request_token(self, identity: Identity) -> str:
        req = build_auth_request(identity.signing_key)
        resp = self._http.post("/auth/token", json=req)
        if resp.status_code != 200:
            raise RelayError(f"token request failed: {resp.status_code} {resp.text}")
        return resp.json()["token"]

    def put_blob(self, blob: bytes, token: str) -> str:
        resp = self._http.put(
            "/blob", content=blob, headers={"Authorization": f"Bearer {token}"}
        )
        if resp.status_code != 200:
            raise RelayError(f"put failed: {resp.status_code} {resp.text}")
        return resp.json()["address"]

    def get_blob(self, address: str) -> bytes | None:
        resp = self._http.get(f"/blob/{address}")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise RelayError(f"get failed: {resp.status_code}")
        return resp.content

    def publish(self, encdoc: EncryptedDocument, identity: Identity) -> str:
        """Upload both blobs; returns the manifest address. Verifies first."""
        if not verify(encdoc):
            raise RelayError("refusing to publish an artifact that fails verification")
        token = self.request_token(identity)
        for blob in encdoc.to_blobs().values():
            self.put_blob(blob, token)
        return encdoc.manifest_address

    def fetch(self, manifest_address: str) -> EncryptedDocument:
        """Fetch + reconstruct + verify a document by its manifest address."""
        manifest_blob = self.get_blob(manifest_address)
        if manifest_blob is None:
            raise RelayError("manifest not found")
        import json

        outer = json.loads(manifest_blob)
        ct_address = outer["manifest"]["ciphertext_address"]
        ciphertext = self.get_blob(ct_address)
        if ciphertext is None:
            raise RelayError("ciphertext not found")
        encdoc = EncryptedDocument.from_manifest_blob(manifest_blob, ciphertext)
        if not verify(encdoc):
            raise RelayError("fetched artifact failed verification")
        return encdoc
