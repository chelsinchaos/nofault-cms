from nofault.render.html import (
    CONTENT_SECURITY_POLICY,
    render_markdown,
    render_page,
    sanitize_html,
)


def test_script_tag_stripped():
    out = render_markdown("hello <script>alert(1)</script> world")
    assert "<script" not in out.lower()
    assert "alert" not in out or "<script" not in out.lower()


def test_javascript_url_stripped():
    # markdown-it refuses to build a link with a dangerous scheme: it renders
    # inert text with no href, so nothing is clickable.
    out = render_markdown("[click me](javascript:alert(document.cookie))")
    assert "href" not in out.lower()
    # and if a javascript: href reaches the sanitizer via raw HTML, nh3 drops it
    cleaned = sanitize_html('<a href="javascript:alert(1)">x</a>')
    assert "javascript:" not in cleaned.lower()


def test_event_handler_stripped():
    out = sanitize_html('<img src="x" onerror="steal()">')
    assert "onerror" not in out.lower()


def test_links_get_safe_rel():
    out = sanitize_html('<a href="https://example.com">x</a>')
    assert "noopener" in out and "noreferrer" in out


def test_markdown_basic_formatting():
    out = render_markdown("**bold** and *italic*")
    assert "<strong>" in out and "<em>" in out


def test_page_has_strict_csp_and_no_referrer():
    page = render_page("Title", "body")
    assert "Content-Security-Policy" in page
    assert "default-src 'none'" in page
    assert "no-referrer" in page
    assert "script-src" not in CONTENT_SECURITY_POLICY  # scripts simply not allowed


def test_title_is_escaped_not_injected():
    page = render_page('<img src=x onerror=alert(1)>', "body")
    # the raw tag must be escaped in the <title>, not present as a live element
    assert "<img" not in page
    assert "&lt;img" in page
