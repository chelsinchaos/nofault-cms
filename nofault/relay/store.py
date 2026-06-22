"""On-disk content-addressed blob store.

Blobs are stored under a sharded directory tree keyed by their content address.
The store verifies that a blob actually hashes to its claimed address before
writing, so a buggy or malicious client cannot poison an address. Writes are
atomic (temp file + rename) and idempotent (same content -> same address).
"""

from __future__ import annotations

import os
import re

from ..crypto.hashing import content_address, verify_address

_ADDRESS_RE = re.compile(r"^b2:[0-9a-f]{64}$")


class BlobStore:
    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)

    def _path(self, address: str) -> str:
        if not _ADDRESS_RE.match(address):
            raise ValueError("malformed content address")
        digest = address.split(":", 1)[1]
        # shard by first 2 bytes to avoid giant flat dirs
        shard = os.path.join(self.root, digest[:2], digest[2:4])
        return os.path.join(shard, digest)

    def put(self, blob: bytes) -> str:
        """Store ``blob``; returns its content address. Idempotent."""
        address = content_address(blob)
        path = self._path(address)
        if os.path.exists(path):
            return address
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return address

    def get(self, address: str) -> bytes | None:
        try:
            path = self._path(address)
        except ValueError:
            return None
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            data = f.read()
        # Defensive: never hand back a blob that doesn't match its address.
        if not verify_address(data, address):
            return None
        return data

    def has(self, address: str) -> bool:
        try:
            return os.path.exists(self._path(address))
        except ValueError:
            return False

    def delete(self, address: str) -> bool:
        """Operator-only unpin. Content-addressed data is otherwise immutable."""
        try:
            path = self._path(address)
        except ValueError:
            return False
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def iter_blob_paths(self):
        """Yield every blob file path (used by GC and the seizure test)."""
        for dirpath, _dirs, files in os.walk(self.root):
            for name in files:
                if name.endswith(".tmp"):
                    continue
                yield os.path.join(dirpath, name)
