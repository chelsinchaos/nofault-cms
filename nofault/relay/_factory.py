"""Uvicorn ``--factory`` entrypoint that builds the relay app from environment.

Kept separate from :mod:`nofault.relay.app` so the app module stays free of
process/config concerns and remains trivially testable.
"""

from __future__ import annotations

import os

from .app import create_app
from .auth import CapabilityIssuer
from .store import BlobStore


def build():  # pragma: no cover - process entrypoint, exercised via deployment
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
    return create_app(store, issuer)
