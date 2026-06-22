"""Signed, content-addressed bundles — the transmission-agnostic unit.

A bundle is a self-contained ``.nfb`` (tar) file carrying one or more encrypted
document artifacts (manifest blobs + ciphertext blobs) plus a signed bundle
index. The *same* bundle can travel over:

* a Tor onion relay (``nofault publish`` / ``nofault fetch``),
* IPFS (ciphertext only — never plaintext),
* a USB stick / SD card handed across a border (``export`` / ``import``),
* a mesh or dead-drop.

A recipient verifies the bundle entirely offline against a pinned author key,
so a hostile mirror cannot substitute or inject content without detection.

Bundles never contain private keys and never contain plaintext.
"""

from __future__ import annotations

import io
import json
import tarfile
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .crypto.document import EncryptedDocument, _b64, _canonical, _unb64, verify
from .crypto.hashing import content_address, verify_address
from .crypto.identity import Identity

BUNDLE_SCHEME = "nofault-bundle/1"
_INDEX_NAME = "index.json"
_BLOB_DIR = "blobs"


@dataclass
class Bundle:
    """A verifiable collection of encrypted documents."""

    docs: list[EncryptedDocument]
    author_verify_key: bytes
    signature: bytes | None = None

    def _blobs(self) -> dict[str, bytes]:
        blobs: dict[str, bytes] = {}
        for d in self.docs:
            blobs.update(d.to_blobs())
        return blobs

    def _index_body(self) -> dict:
        # The signed index commits to every blob address in the bundle, so the
        # signature covers the whole content set, not just individual docs.
        return {
            "scheme": BUNDLE_SCHEME,
            "manifest_addresses": sorted(d.manifest_address for d in self.docs),
            "blob_addresses": sorted(self._blobs().keys()),
        }

    def to_tar_bytes(self, author: Identity) -> bytes:
        """Serialize + sign the bundle into ``.nfb`` (tar) bytes."""
        if author.verify_key_bytes != self.author_verify_key:
            raise ValueError("signing identity does not match bundle author key")
        index = self._index_body()
        signature = author.signing_key.sign(_canonical(index)).signature
        signed_index = {
            "index": index,
            "author_verify_key": _b64(self.author_verify_key),
            "signature": _b64(signature),
        }

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            _add(tar, _INDEX_NAME, _canonical(signed_index))
            for address, blob in self._blobs().items():
                _add(tar, f"{_BLOB_DIR}/{address.replace(':', '_')}", blob)
        return buf.getvalue()

    @classmethod
    def from_tar_bytes(cls, data: bytes) -> Bundle:
        """Parse + fully verify a ``.nfb`` bundle. Raises on any tampering."""
        blobs: dict[str, bytes] = {}
        signed_index: dict | None = None
        with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                content = extracted.read()
                if member.name == _INDEX_NAME:
                    signed_index = json.loads(content)
                elif member.name.startswith(f"{_BLOB_DIR}/"):
                    # Recompute the address from content; do not trust the name.
                    address = content_address(content)
                    blobs[address] = content

        if signed_index is None:
            raise ValueError("bundle missing index")

        index = signed_index["index"]
        author_vk = _unb64(signed_index["author_verify_key"])
        signature = _unb64(signed_index["signature"])

        # 1. index signature
        try:
            VerifyKey(author_vk).verify(_canonical(index), signature)
        except (BadSignatureError, ValueError) as exc:
            raise ValueError("bundle index signature invalid") from exc

        # 2. every blob the index commits to is present and address-correct
        for address in index["blob_addresses"]:
            if address not in blobs:
                raise ValueError(f"bundle missing committed blob {address}")
            if not verify_address(blobs[address], address):
                raise ValueError(f"bundle blob {address} fails content address")

        # 3. reconstruct documents and verify each one end to end
        docs: list[EncryptedDocument] = []
        for manifest_address in index["manifest_addresses"]:
            manifest_blob = blobs[manifest_address]
            outer = json.loads(manifest_blob)
            ct_address = outer["manifest"]["ciphertext_address"]
            if ct_address not in blobs:
                raise ValueError("bundle missing ciphertext for a manifest")
            encdoc = EncryptedDocument.from_manifest_blob(manifest_blob, blobs[ct_address])
            if not verify(encdoc):
                raise ValueError("bundle contains a document that fails verification")
            docs.append(encdoc)

        return cls(docs=docs, author_verify_key=author_vk, signature=signature)


def _add(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = 0  # deterministic / no timestamp metadata leakage
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    tar.addfile(info, io.BytesIO(data))
