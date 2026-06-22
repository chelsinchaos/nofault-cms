"""Safe rendering of decrypted documents into publishable static HTML.

Rendering happens on the client, AFTER decryption, and is the layer that
prevents the stored-XSS class that plagued the original
(``{{ content.body | safe }}`` with autoescape off). Every untrusted string is
either escaped (Jinja2 autoescape) or sanitized through an allowlist
(nh3/ammonia). Output pages carry a strict Content-Security-Policy and
``Referrer-Policy: no-referrer`` so a reader on Tor does not leak the source
page URL on outbound navigation.
"""
