"""Device-local shred-vault for per-document keys.

Holds the DEKs of "shreddable" documents, encrypted under a random *vault key*
that is stored on the device only (never derived from the passphrase, never
sealed to the long-term identity). Because the vault key is not recoverable
from anything the journalist can be coerced into revealing, destroying the
vault (``shred``) makes the corresponding ciphertext permanently unreadable —
even to an adversary who later extracts the passphrase. This is the mechanism
behind ``crypto-shred`` and the data-destruction part of ``panic``.

Tradeoff: shreddable documents are NOT recoverable on another device. Normal
(identity-sealed) documents recover anywhere from the passphrase but cannot be
crypto-shredded. See ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

import json
import os

from ..crypto import aead
from ..crypto.identity import shred_file


class ShredVault:
    def __init__(self, path: str):
        self.path = path
        self.key_path = path + ".key"

    def _vault_key(self) -> bytes:
        if not os.path.exists(self.key_path):
            key = aead.generate_key()
            tmp = self.key_path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(key)
            os.replace(tmp, self.key_path)
            os.chmod(self.key_path, 0o600)
            return key
        with open(self.key_path, "rb") as f:
            return f.read()

    def _load(self) -> dict[str, str]:
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "rb") as f:
            blob = f.read()
        if not blob:
            return {}
        return json.loads(aead.decrypt(self._vault_key(), blob, aad=b"nf-vault"))

    def _save(self, data: dict[str, str]) -> None:
        blob = aead.encrypt(self._vault_key(), json.dumps(data).encode(), aad=b"nf-vault")
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    def put(self, ref: str, dek: bytes) -> None:
        data = self._load()
        data[ref] = dek.hex()
        self._save(data)

    def get(self, ref: str) -> bytes | None:
        value = self._load().get(ref)
        return bytes.fromhex(value) if value else None

    def remove(self, ref: str) -> None:
        data = self._load()
        if ref in data:
            del data[ref]
            self._save(data)

    def shred(self) -> None:
        """Destroy the vault and its key — irreversible for shreddable docs."""
        shred_file(self.path)
        shred_file(self.key_path)
