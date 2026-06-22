"""The zero-knowledge relay.

This is the ONLY server-side component. It is a content-addressed blob store
that holds opaque ciphertext and signed manifests. It cannot decrypt anything,
has no user database, no passwords, and — by design — keeps no request/IP/URL
logs. Writes require an anonymous capability token derived from a relay-enrolled
publisher key; reads are anonymous because this is a publishing platform.

On seizure, the relay yields only ciphertext addressed by hash. The
``tests/test_seizure.py`` invariant test asserts exactly this.
"""
