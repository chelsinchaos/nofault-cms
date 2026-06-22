"""Local document repository: authoring, versioning, opening, deletion.

The repo tracks only **opaque** local state (random ``doc_id`` -> content
addresses + a shreddable flag). It stores no titles or bodies in clear; the
plaintext exists only transiently in memory while authoring or viewing.

"Edit" creates a new version whose manifest references the previous version's
address, forming a signed, tamper-evident chain. "Delete" removes the document
from the local index and returns the relay addresses to unpin; for shreddable
documents it also destroys the local DEK (crypto-shred).
"""

from __future__ import annotations

import json
import os
import secrets

from ..crypto.document import (
    Document,
    EncryptedDocument,
    decrypt_document,
    decrypt_with_dek,
    encrypt_document,
)
from ..crypto.identity import Identity
from ..relay.store import BlobStore
from .vault import ShredVault


class Repo:
    def __init__(self, root: str, identity: Identity):
        self.root = root
        self.identity = identity
        os.makedirs(root, exist_ok=True)
        self.index_path = os.path.join(root, "index.json")
        self.vault = ShredVault(os.path.join(root, "shred-vault"))
        # Local cache of this author's own encrypted blobs, so the document can
        # be re-published, exported to a bundle, or opened later. Holds only
        # ciphertext + signed manifests — identical to what the relay stores.
        self.blobs = BlobStore(os.path.join(root, "blobs"))

    # --- index -----------------------------------------------------------
    def _index(self) -> dict:
        if not os.path.exists(self.index_path):
            return {}
        with open(self.index_path, encoding="utf-8") as f:
            return json.load(f)

    def _write_index(self, index: dict) -> None:
        tmp = self.index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(index, f)
        os.replace(tmp, self.index_path)

    # --- authoring -------------------------------------------------------
    def create(
        self, title: str, body_markdown: str, *,
        shreddable: bool = False, recipients: list[bytes] | None = None,
    ) -> EncryptedDocument:
        doc = Document(doc_id=secrets.token_hex(16), title=title, body_markdown=body_markdown)
        return self._encrypt_and_register(doc, shreddable=shreddable, recipients=recipients)

    def edit(
        self, doc_id: str, *, title: str, body_markdown: str,
        recipients: list[bytes] | None = None,
    ) -> EncryptedDocument:
        index = self._index()
        if doc_id not in index:
            raise KeyError(f"unknown doc_id {doc_id}")
        entry = index[doc_id]
        doc = Document(
            doc_id=doc_id,
            title=title,
            body_markdown=body_markdown,
            version=entry["version"] + 1,
            prev_address=entry["manifest_address"],
        )
        return self._encrypt_and_register(
            doc, shreddable=entry["shreddable"], recipients=recipients
        )

    def _encrypt_and_register(
        self, doc: Document, *, shreddable: bool, recipients: list[bytes] | None
    ) -> EncryptedDocument:
        encdoc, dek = encrypt_document(
            doc, self.identity, recipients, include_author=not shreddable
        )
        if shreddable:
            self.vault.put(encdoc.ciphertext_address, dek)
        for blob in encdoc.to_blobs().values():
            self.blobs.put(blob)
        index = self._index()
        index[doc.doc_id] = {
            "version": doc.version,
            "manifest_address": encdoc.manifest_address,
            "ciphertext_address": encdoc.ciphertext_address,
            "shreddable": shreddable,
        }
        self._write_index(index)
        return encdoc

    # --- reading ---------------------------------------------------------
    def get_encrypted(self, doc_id: str) -> EncryptedDocument:
        """Reconstruct the latest encrypted artifact for ``doc_id`` from cache."""
        entry = self._index()[doc_id]
        manifest_blob = self.blobs.get(entry["manifest_address"])
        ciphertext = self.blobs.get(entry["ciphertext_address"])
        if manifest_blob is None or ciphertext is None:
            raise KeyError(f"local blobs for {doc_id} are missing")
        return EncryptedDocument.from_manifest_blob(manifest_blob, ciphertext)

    def open(self, encdoc: EncryptedDocument) -> Document:
        index = self._index()
        entry = index.get(encdoc.manifest["doc_id"])
        if entry and entry.get("shreddable"):
            dek = self.vault.get(encdoc.ciphertext_address)
            if dek is None:
                raise KeyError("document was crypto-shredded; key destroyed")
            return decrypt_with_dek(encdoc, dek)
        return decrypt_document(encdoc, self.identity)

    # --- listing / deletion ---------------------------------------------
    def list_docs(self) -> list[dict]:
        return [{"doc_id": k, **v} for k, v in sorted(self._index().items())]

    def latest_address(self, doc_id: str) -> str:
        return self._index()[doc_id]["manifest_address"]

    def delete(self, doc_id: str) -> list[str]:
        """Remove from index; return relay addresses to unpin. Crypto-shred if able."""
        index = self._index()
        entry = index.pop(doc_id, None)
        if entry is None:
            return []
        self._write_index(index)
        if entry.get("shreddable"):
            self.vault.remove(entry["ciphertext_address"])
        return [entry["manifest_address"], entry["ciphertext_address"]]

    def crypto_shred(self, doc_id: str) -> bool:
        """Destroy the local DEK for a shreddable doc; returns True if shredded."""
        entry = self._index().get(doc_id)
        if not entry or not entry.get("shreddable"):
            return False
        self.vault.remove(entry["ciphertext_address"])
        return True

    def wipe_index(self) -> None:
        from ..crypto.identity import shred_file

        shred_file(self.index_path)
