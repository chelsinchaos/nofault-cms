"""Coercion-resistance features: panic shred and dead-man's switch.

These are **best-effort** and honestly documented as such. They cannot defeat a
hardware adversary who has already imaged the device, and the dead-man's switch
depends on an external scheduler actually running. They raise the cost of
coercion and seizure; they are not magic. See ``docs/OPSEC.md``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from ..crypto.identity import shred_file


def panic(*, keystore_path: str | None = None, repo=None) -> dict:
    """Destroy local secret material as fast as possible.

    * Shreds the encrypted keystore (so the on-device identity is gone; note a
      memorised passphrase can still reconstruct *identity-sealed* documents —
      only *shreddable* documents become unrecoverable).
    * Shreds the repo's shred-vault (destroying all shreddable-document DEKs)
      and wipes the local index.

    Returns a summary of what was destroyed.
    """
    destroyed = []
    if keystore_path and os.path.exists(keystore_path):
        shred_file(keystore_path)
        destroyed.append("keystore")
    if repo is not None:
        repo.vault.shred()
        repo.wipe_index()
        destroyed.append("shred-vault")
        destroyed.append("index")
    return {"destroyed": destroyed}


@dataclass
class DeadManSwitch:
    """If the journalist does not check in by ``deadline``, ``fire`` releases a
    pre-built bundle (e.g. to publish an insurance file).

    Time is passed in explicitly (``now``) so behaviour is deterministic and
    testable, and so the caller controls the clock source.
    """

    path: str

    def arm(self, *, interval_seconds: int, release_bundle_path: str, now: float) -> None:
        config = {
            "interval_seconds": int(interval_seconds),
            "release_bundle_path": release_bundle_path,
            "deadline": int(now) + int(interval_seconds),
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(config, f)
        os.replace(tmp, self.path)

    def _read(self) -> dict:
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def check_in(self, *, now: float) -> None:
        config = self._read()
        config["deadline"] = int(now) + int(config["interval_seconds"])
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(config, f)
        os.replace(tmp, self.path)

    def is_expired(self, *, now: float) -> bool:
        return now >= self._read()["deadline"]

    def fire(self, *, now: float) -> str | None:
        """Return the release-bundle path iff the deadline has passed."""
        config = self._read()
        return config["release_bundle_path"] if now >= config["deadline"] else None
