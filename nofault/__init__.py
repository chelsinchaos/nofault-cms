"""NoFaultCMS — zero-knowledge publishing for investigative journalists.

The security model is the whole point of this package:

* All confidentiality and authenticity controls run **on the journalist's
  client**, never on the server.
* The server (``nofault.relay``) is a content-addressed blob store that holds
  only ciphertext and learns nothing about content, titles, or authorship.
* Every published artifact is end-to-end encrypted (per-document key) and
  Ed25519-signed, so it can be verified offline after travelling over any
  channel (Tor, IPFS, USB/sneakernet).

See ``docs/THREAT_MODEL.md`` for the adversary model and ``docs/OPSEC.md`` for
operational guidance. Nothing in this package should be trusted to protect a
real source until the readiness checklist in ``README.md`` is fully green and
an independent audit has signed off.
"""

__version__ = "0.1.0-alpha"
