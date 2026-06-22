"""Markdown -> sanitized, CSP-protected static HTML.

Threat-model rationale:

* The body is authored as Markdown, rendered to HTML, then **always** passed
  through an allowlist sanitizer. ``<script>``, event handlers, ``style``,
  ``iframe``, ``object`` and ``javascript:`` URLs cannot survive.
* The page template runs with Jinja2 ``autoescape=True`` so the title and any
  interpolated string is HTML-escaped.
* A strict CSP forbids scripts and remote loads entirely — published pages are
  static text/images, so there is no legitimate need for JS, and forbidding it
  removes the most powerful deanonymisation/beaconing vector against readers
  (who may be on Tor).
* ``Referrer-Policy: no-referrer`` and ``rel="noopener noreferrer nofollow"``
  on links prevent leaking the (possibly .onion) page URL when a reader clicks
  out.
"""

from __future__ import annotations

import nh3
from jinja2 import Environment, select_autoescape
from markdown_it import MarkdownIt

# Strict CSP: no scripts, no inline anything, images only from same origin or
# data: (for embedded, metadata-stripped media). No connect/frame/object.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "img-src 'self' data:; "
    "style-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}

_ALLOWED_TAGS = {
    "p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6",
    "blockquote", "pre", "code", "em", "strong", "del", "sub", "sup",
    "ul", "ol", "li", "a", "img", "table", "thead", "tbody", "tr", "th", "td",
    "figure", "figcaption",
}
_ALLOWED_ATTRS = {
    "a": {"href", "title"},
    "img": {"src", "alt", "title"},
}

_md = MarkdownIt("commonmark", {"html": False, "linkify": False})

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))

_PAGE_TEMPLATE = _env.from_string(
    """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="{{ csp }}">
<meta name="referrer" content="no-referrer">
<title>{{ title }}</title>
</head>
<body>
<main>
<h1>{{ title }}</h1>
{{ body_html_safe }}
</main>
</body>
</html>
"""
)


def sanitize_html(html: str) -> str:
    """Allowlist-sanitize HTML; forces safe rel/target on links."""
    return nh3.clean(
        html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        link_rel="noopener noreferrer nofollow",
        url_schemes={"https", "http", "mailto", "data"},
    )


def render_markdown(body_markdown: str) -> str:
    """Render Markdown to HTML and sanitize the result."""
    raw_html = _md.render(body_markdown)
    return sanitize_html(raw_html)


def render_page(title: str, body_markdown: str) -> str:
    """Render a complete, safe static HTML page from a document's fields."""
    from markupsafe import Markup

    body_html = render_markdown(body_markdown)
    # nosec justification: body_html is the OUTPUT of render_markdown(), which
    # runs nh3 allowlist sanitization — it is sanitized HTML, not untrusted raw
    # input. CONTENT_SECURITY_POLICY is a trusted module constant. The title is
    # NOT wrapped in Markup and stays autoescaped.
    return _PAGE_TEMPLATE.render(
        title=title,  # autoescaped (untrusted)
        body_html_safe=Markup(body_html),  # nosec B704 - sanitized by nh3 above
        csp=Markup(CONTENT_SECURITY_POLICY),  # nosec B704 - trusted constant
    )
