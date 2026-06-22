"""Journalist identity: passphrase-derived keys + duress-capable keystore.

An identity is two keypairs derived deterministically from a single 32-byte
root seed:

* **Ed25519** for signing published artifacts (authenticity).
* **X25519** for sealing per-document keys to recipients (confidentiality).

Because the keys derive from the seed, and the seed derives from a passphrase
(or is recoverable via Shamir shares), the journalist can reconstitute their
full identity **on any device from memory alone** — satisfying the
"device-agnostic / no-trusted-device" requirement. No private key file needs
to survive a border crossing.

The on-disk keystore is optional (for convenience on a personal device). It is
encrypted with an Argon2id-derived key and supports a **duress slot**: a decoy
passphrase opens a decoy identity. This is best-effort deniability — an
adversary who knows this file format can see that two slots exist — and is
documented as such in ``docs/THREAT_MODEL.md``. It is NOT a hidden-volume
scheme.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

import nacl.pwhash
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

from . import aead

SEED_BYTES = 32
SALT_BYTES = nacl.pwhash.argon2id.SALTBYTES  # 16

# Argon2id cost. INTERACTIVE is the floor; real keystores use MODERATE. Tests
# override to INTERACTIVE for speed via the explicit kwargs.
_OPS_MODERATE = nacl.pwhash.argon2id.OPSLIMIT_MODERATE
_MEM_MODERATE = nacl.pwhash.argon2id.MEMLIMIT_MODERATE

_PERSON_SIGN = b"nf-sign-ed25519"  # <= 16 bytes
_PERSON_BOX = b"nf-box-x25519"


def _subkey(seed: bytes, person: bytes) -> bytes:
    """Derive a 32-byte domain-separated subkey from the root seed."""
    return hashlib.blake2b(seed, digest_size=32, person=person).digest()


@dataclass(frozen=True)
class Identity:
    """A signing + boxing keypair pair with a stable fingerprint."""

    signing_key: SigningKey
    box_private: PrivateKey

    @classmethod
    def from_seed(cls, seed: bytes) -> Identity:
        if len(seed) != SEED_BYTES:
            raise ValueError(f"seed must be {SEED_BYTES} bytes")
        return cls(
            signing_key=SigningKey(_subkey(seed, _PERSON_SIGN)),
            box_private=PrivateKey(_subkey(seed, _PERSON_BOX)),
        )

    @classmethod
    def from_passphrase(
        cls, passphrase: str, salt: bytes, *, opslimit: int | None = None,
        memlimit: int | None = None,
    ) -> Identity:
        seed = derive_seed(passphrase, salt, opslimit=opslimit, memlimit=memlimit)
        return cls.from_seed(seed)

    @property
    def verify_key(self) -> VerifyKey:
        return self.signing_key.verify_key

    @property
    def box_public(self) -> PublicKey:
        return self.box_private.public_key

    @property
    def verify_key_bytes(self) -> bytes:
        return bytes(self.verify_key)

    @property
    def box_public_bytes(self) -> bytes:
        return bytes(self.box_public)

    @property
    def fingerprint(self) -> str:
        """Short stable id binding both public keys (16 bytes hex)."""
        return fingerprint_of(self.verify_key_bytes, self.box_public_bytes)


def fingerprint_of(verify_key_bytes: bytes, box_public_bytes: bytes) -> str:
    digest = hashlib.blake2b(
        verify_key_bytes + box_public_bytes, digest_size=16
    ).hexdigest()
    return f"nf1:{digest}"


def new_salt() -> bytes:
    return os.urandom(SALT_BYTES)


def derive_seed(
    passphrase: str, salt: bytes, *, opslimit: int | None = None,
    memlimit: int | None = None,
) -> bytes:
    """Argon2id: passphrase + salt -> 32-byte root seed."""
    if len(salt) != SALT_BYTES:
        raise ValueError(f"salt must be {SALT_BYTES} bytes")
    return nacl.pwhash.argon2id.kdf(
        SEED_BYTES,
        passphrase.encode("utf-8"),
        salt,
        opslimit=opslimit if opslimit is not None else _OPS_MODERATE,
        memlimit=memlimit if memlimit is not None else _MEM_MODERATE,
    )


# --- Keystore (optional, encrypted at rest, with duress slot) -------------

_KEYSTORE_VERSION = 1


def _slot(passphrase: str, seed: bytes, opslimit: int, memlimit: int) -> dict:
    salt = new_salt()
    kek = nacl.pwhash.argon2id.kdf(
        aead.KEY_BYTES, passphrase.encode("utf-8"), salt,
        opslimit=opslimit, memlimit=memlimit,
    )
    ct = aead.encrypt(kek, seed, aad=b"nf-keystore")
    return {
        "salt": salt.hex(),
        "opslimit": opslimit,
        "memlimit": memlimit,
        "ct": ct.hex(),
    }


def write_keystore(
    path: str, passphrase: str, seed: bytes, *,
    duress_passphrase: str | None = None, duress_seed: bytes | None = None,
    opslimit: int = _OPS_MODERATE, memlimit: int = _MEM_MODERATE,
) -> None:
    """Write an encrypted keystore. Optionally include a duress decoy slot.

    Slot order is randomized so the real slot is not always first.
    """
    slots = [_slot(passphrase, seed, opslimit, memlimit)]
    if duress_passphrase is not None:
        decoy = duress_seed if duress_seed is not None else os.urandom(SEED_BYTES)
        slots.append(_slot(duress_passphrase, decoy, opslimit, memlimit))
        # randomize order so position doesn't reveal which is real
        if os.urandom(1)[0] & 1:
            slots.reverse()
    doc = {"version": _KEYSTORE_VERSION, "kdf": "argon2id", "slots": slots}
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def read_keystore_seed(path: str, passphrase: str) -> bytes:
    """Open a keystore with ``passphrase``; return the raw 32-byte seed.

    A wrong passphrase that matches no slot raises ValueError. A duress
    passphrase silently returns the decoy seed.
    """
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if doc.get("version") != _KEYSTORE_VERSION:
        raise ValueError("unsupported keystore version")
    for slot in doc["slots"]:
        salt = bytes.fromhex(slot["salt"])
        kek = nacl.pwhash.argon2id.kdf(
            aead.KEY_BYTES, passphrase.encode("utf-8"), salt,
            opslimit=slot["opslimit"], memlimit=slot["memlimit"],
        )
        try:
            return aead.decrypt(kek, bytes.fromhex(slot["ct"]), aad=b"nf-keystore")
        except Exception:  # noqa: S112  # nosec B112 - wrong slot for this passphrase, try next
            continue
    raise ValueError("no keystore slot matched the passphrase")


def read_keystore(path: str, passphrase: str) -> Identity:
    """Open a keystore with ``passphrase``; returns whichever identity it unlocks."""
    return Identity.from_seed(read_keystore_seed(path, passphrase))


def shred_file(path: str) -> None:
    """Best-effort secure delete: overwrite then unlink.

    On modern SSDs/journaling/copy-on-write filesystems, overwrite-in-place is
    not a guarantee (wear-levelling may retain old blocks). This is documented
    as best-effort in OPSEC.md; the real protection is that the file only ever
    held ciphertext under an Argon2id-wrapped key. Used by ``panic``.
    """
    if not os.path.exists(path):
        return
    length = os.path.getsize(path)
    with open(path, "r+b", buffering=0) as f:
        for _ in range(3):
            f.seek(0)
            f.write(os.urandom(max(length, 1)))
            f.flush()
            os.fsync(f.fileno())
    os.remove(path)
