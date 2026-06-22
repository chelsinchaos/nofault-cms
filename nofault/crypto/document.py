"""End-to-end encrypted, signed, content-addressed documents.

This is the unit of everything the system stores or publishes. A document is:

1. Serialized to canonical JSON (title + body + metadata are ALL inside the
   plaintext payload — nothing is stored in clear, unlike the original which
   left titles plaintext).
2. Encrypted with a fresh per-document key (DEK) using XChaCha20-Poly1305.
3. The DEK is sealed (X25519 anonymous sealed box) to each recipient's public
   key — the author is always a recipient, so they can always read their own
   work.
4. A manifest describing the ciphertext (by content address) and the sealed
   DEKs is Ed25519-signed by the author.

The server only ever sees the ciphertext blob and the signed manifest blob,
both opaque. A reader fetches the manifest, verifies the signature against a
pinned author key, fetches the ciphertext by its address, verifies the
address, unwraps the DEK, and decrypts — entirely offline-capable, so the same
artifact verifies whether it arrived over Tor, IPFS, or a USB stick.

"Edit" = publish a new version whose manifest references the previous version's
address (``prev_address``), forming a signed, tamper-evident version chain.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field

from nacl.exceptions import BadSignatureError, CryptoError
from nacl.public import PublicKey, SealedBox
from nacl.signing import VerifyKey

from . import aead
from .hashing import content_address, verify_address
from .identity import Identity, fingerprint_of

SCHEME = "nofault-doc/1"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class Document:
    """Plaintext document, as authored. Never leaves the client unencrypted."""

    doc_id: str
    title: str
    body_markdown: str
    version: int = 1
    prev_address: str | None = None
    # arbitrary author metadata kept INSIDE the encrypted payload
    meta: dict = field(default_factory=dict)

    def to_payload(self) -> bytes:
        return _canonical(
            {
                "doc_id": self.doc_id,
                "title": self.title,
                "body_markdown": self.body_markdown,
                "version": self.version,
                "prev_address": self.prev_address,
                "meta": self.meta,
            }
        )

    @classmethod
    def from_payload(cls, payload: bytes) -> Document:
        obj = json.loads(payload)
        return cls(
            doc_id=obj["doc_id"],
            title=obj["title"],
            body_markdown=obj["body_markdown"],
            version=obj.get("version", 1),
            prev_address=obj.get("prev_address"),
            meta=obj.get("meta", {}),
        )


@dataclass
class EncryptedDocument:
    """The publishable artifact: a signed manifest plus its ciphertext blob."""

    manifest: dict
    signature: bytes
    author_verify_key: bytes
    ciphertext: bytes

    # --- addresses -------------------------------------------------------
    @property
    def ciphertext_address(self) -> str:
        return self.manifest["ciphertext_address"]

    def signed_manifest_bytes(self) -> bytes:
        """The exact bytes that are signed and content-addressed."""
        return _canonical(
            {
                "manifest": self.manifest,
                "author_verify_key": _b64(self.author_verify_key),
                "signature": _b64(self.signature),
            }
        )

    @property
    def manifest_address(self) -> str:
        return content_address(self.signed_manifest_bytes())

    # --- serialization ---------------------------------------------------
    def to_blobs(self) -> dict[str, bytes]:
        """Return ``{address: blob}`` for everything that must be stored.

        Two blobs: the signed manifest and the ciphertext. Both are opaque to
        the relay.
        """
        return {
            self.manifest_address: self.signed_manifest_bytes(),
            self.ciphertext_address: self.ciphertext,
        }

    @classmethod
    def from_manifest_blob(cls, manifest_blob: bytes, ciphertext: bytes) -> EncryptedDocument:
        outer = json.loads(manifest_blob)
        return cls(
            manifest=outer["manifest"],
            signature=_unb64(outer["signature"]),
            author_verify_key=_unb64(outer["author_verify_key"]),
            ciphertext=ciphertext,
        )


def encrypt_document(
    doc: Document,
    author: Identity,
    recipients: list[bytes] | None = None,
    *,
    include_author: bool = True,
) -> tuple[EncryptedDocument, bytes]:
    """Encrypt + sign ``doc``. ``recipients`` are X25519 public-key bytes.

    Returns ``(encrypted_document, dek)``. The DEK is returned so the caller can
    store it in a local shred-vault for "shreddable" documents.

    When ``include_author`` is True (default) the author is added as a recipient
    so they can always recover the document from their identity alone (good for
    device-agnostic recovery). For *shreddable* documents the caller passes
    ``include_author=False`` and keeps the DEK only in a device-local vault, so
    destroying that vault renders the ciphertext permanently unreadable — true
    crypto-shred, at the cost of cross-device recoverability. This tradeoff is
    documented in ``docs/THREAT_MODEL.md``.
    """
    recipient_keys = list(recipients or [])
    if include_author and author.box_public_bytes not in recipient_keys:
        recipient_keys.append(author.box_public_bytes)

    dek = aead.generate_key()
    payload = doc.to_payload()
    ciphertext = aead.encrypt(dek, payload, aad=SCHEME.encode())
    ct_address = content_address(ciphertext)

    wrapped = []
    for pk in recipient_keys:
        sealed = SealedBox(PublicKey(pk)).encrypt(dek)
        wrapped.append(
            {
                "fingerprint": fingerprint_of(author.verify_key_bytes, pk)
                if pk == author.box_public_bytes
                else _recipient_fp(pk),
                "box_public": _b64(pk),
                "wrapped_dek": _b64(sealed),
            }
        )

    manifest = {
        "scheme": SCHEME,
        "doc_id": doc.doc_id,
        "version": doc.version,
        "prev_address": doc.prev_address,
        "ciphertext_address": ct_address,
        "author_fingerprint": author.fingerprint,
        "recipients": wrapped,
    }
    signature = author.signing_key.sign(_canonical(manifest)).signature
    encdoc = EncryptedDocument(
        manifest=manifest,
        signature=signature,
        author_verify_key=author.verify_key_bytes,
        ciphertext=ciphertext,
    )
    return encdoc, dek


def decrypt_with_dek(encdoc: EncryptedDocument, dek: bytes) -> Document:
    """Decrypt using a directly-supplied DEK (the shreddable-document path).

    Used for documents whose DEK lives only in a device-local shred-vault and
    was not sealed to any long-term recipient key. Still verifies the artifact
    before decrypting.
    """
    if not verify(encdoc):
        raise CryptoError("document failed verification")
    payload = aead.decrypt(dek, encdoc.ciphertext, aad=SCHEME.encode())
    return Document.from_payload(payload)


def _recipient_fp(box_public: bytes) -> str:
    # Recipients other than the author are identified by their box key alone.
    import hashlib

    return "nfr:" + hashlib.blake2b(box_public, digest_size=16).hexdigest()


def verify(encdoc: EncryptedDocument, *, expected_author_fingerprint: str | None = None) -> bool:
    """Verify signature + ciphertext integrity. Returns True iff genuine.

    This is the function a reader/relay/mirror runs offline. It checks:
    * the manifest signature against the embedded author verify-key,
    * that the embedded verify-key matches ``expected_author_fingerprint`` if
      the caller pinned one (defeats key-substitution by a hostile mirror),
    * that the ciphertext hashes to the address named in the signed manifest.
    """
    try:
        vk = VerifyKey(encdoc.author_verify_key)
        vk.verify(_canonical(encdoc.manifest), encdoc.signature)
    except (BadSignatureError, ValueError):
        return False

    if expected_author_fingerprint is not None:
        # bind to the author's box key as recorded in the manifest
        if encdoc.manifest.get("author_fingerprint") != expected_author_fingerprint:
            return False
        # ...and ensure that fingerprint actually derives from this verify-key
        author_box = next(
            (
                _unb64(r["box_public"])
                for r in encdoc.manifest["recipients"]
                if r.get("fingerprint") == expected_author_fingerprint
            ),
            None,
        )
        if author_box is None:
            return False
        if fingerprint_of(encdoc.author_verify_key, author_box) != expected_author_fingerprint:
            return False

    return verify_address(encdoc.ciphertext, encdoc.ciphertext_address)


def decrypt_document(encdoc: EncryptedDocument, recipient: Identity) -> Document:
    """Verify then decrypt for ``recipient``. Raises on any failure."""
    if not verify(encdoc):
        raise CryptoError("document failed verification")

    sealed_box = SealedBox(recipient.box_private)
    dek = None
    for r in encdoc.manifest["recipients"]:
        if _unb64(r["box_public"]) == recipient.box_public_bytes:
            dek = sealed_box.decrypt(_unb64(r["wrapped_dek"]))
            break
    if dek is None:
        raise CryptoError("recipient is not authorized to read this document")

    payload = aead.decrypt(dek, encdoc.ciphertext, aad=SCHEME.encode())
    return Document.from_payload(payload)
