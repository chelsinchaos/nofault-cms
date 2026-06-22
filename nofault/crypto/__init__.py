"""Client-side cryptographic core.

Everything in this subpackage is designed to run on the journalist's device.
The server never imports it. Primitives are provided by libsodium via PyNaCl;
we do not hand-roll ciphers. The one exception is :mod:`nofault.crypto.shamir`
(GF(256) secret sharing), which is a standard, well-tested construction with
no libsodium equivalent — it ships with known-answer tests and is flagged for
external audit.
"""
