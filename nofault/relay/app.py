"""FastAPI zero-knowledge blob relay.

Endpoints:

* ``GET  /healthz``            — liveness (no logging)
* ``POST /auth/token``         — exchange a signed publisher statement for a
                                 short-lived capability token
* ``PUT  /blob``               — store an opaque blob (requires bearer token)
* ``GET  /blob/{address}``     — fetch a blob (anonymous)
* ``HEAD /blob/{address}``     — existence check (anonymous)

The app installs NO access/request logging. It never sees plaintext: blobs are
ciphertext + signed manifests produced entirely on the client.
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .auth import MAX_BLOB_BYTES, CapabilityIssuer
from .store import BlobStore


def create_app(
    store: BlobStore, issuer: CapabilityIssuer, *, max_blob_bytes: int = MAX_BLOB_BYTES
) -> FastAPI:
    app = FastAPI(title="NoFault Relay", docs_url=None, redoc_url=None, openapi_url=None)

    def require_token(authorization: str | None = Header(default=None)) -> dict:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        try:
            return issuer.verify(authorization[len("Bearer "):])
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/auth/token")
    async def auth_token(request: dict) -> JSONResponse:
        try:
            return JSONResponse(issuer.issue(request))
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.put("/blob")
    async def put_blob(request: Request, _claims: dict = Depends(require_token)) -> dict:
        body = await request.body()
        if len(body) == 0:
            raise HTTPException(status_code=400, detail="empty blob")
        if len(body) > max_blob_bytes:
            raise HTTPException(status_code=413, detail="blob too large")
        address = store.put(body)
        return {"address": address}

    @app.get("/blob/{address}")
    async def get_blob(address: str) -> Response:
        blob = store.get(address)
        if blob is None:
            raise HTTPException(status_code=404, detail="not found")
        return Response(content=blob, media_type="application/octet-stream")

    @app.head("/blob/{address}")
    async def head_blob(address: str) -> Response:
        if not store.has(address):
            raise HTTPException(status_code=404, detail="not found")
        return Response(status_code=200)

    return app


def run() -> None:  # pragma: no cover - process entrypoint
    """Entrypoint: bind 127.0.0.1 only (exposed to the world via a Tor onion).

    Reads configuration from the environment so secrets are never baked into
    images or compose files:
      NOFAULT_RELAY_STORE      directory for blobs (default ./relay-data)
      NOFAULT_RELAY_SECRET     hex, >= 32 bytes, token-signing secret (required)
      NOFAULT_RELAY_ALLOWLIST  comma-separated hex Ed25519 publisher verify-keys
      NOFAULT_RELAY_PORT       default 8800
    """
    import uvicorn

    secret_hex = os.environ.get("NOFAULT_RELAY_SECRET")
    if not secret_hex:
        raise SystemExit("NOFAULT_RELAY_SECRET is required (hex, >= 32 bytes)")
    allowlist = {
        k.strip().lower()
        for k in os.environ.get("NOFAULT_RELAY_ALLOWLIST", "").split(",")
        if k.strip()
    }
    store = BlobStore(os.environ.get("NOFAULT_RELAY_STORE", "./relay-data"))
    issuer = CapabilityIssuer(bytes.fromhex(secret_hex), allowlist)
    app = create_app(store, issuer)
    uvicorn.run(
        app,
        host="127.0.0.1",  # NEVER 0.0.0.0 — reachability is via the onion only
        port=int(os.environ.get("NOFAULT_RELAY_PORT", "8800")),
        access_log=False,  # no request/IP/URL logging, ever
        server_header=False,
        date_header=False,
    )
