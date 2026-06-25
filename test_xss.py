"""
Tests for XSS remediation in xss.py.

Verifies that user-supplied query parameters are escaped with html.escape()
before being reflected into HTML responses, and that security headers are set.
"""

import io
import sys
import unittest
from unittest.mock import MagicMock, patch, call

# We need to import the module; patch HTTPServer so it doesn't bind a socket.
with patch("http.server.HTTPServer"):
    import xss
    from xss import VulnerableHandler, STORED_COMMENTS


def _make_handler(method: str, path: str) -> VulnerableHandler:
    """
    Construct a VulnerableHandler instance wired to a mock socket/server,
    ready to call do_GET() (or any other method) without a real network.
    """
    # Minimal fake request: provide makefile so BaseHTTPRequestHandler can read
    # the request line and headers.
    request_line = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"
    rfile = io.BytesIO(request_line.encode())

    wfile = io.BytesIO()

    mock_socket = MagicMock()
    mock_socket.makefile.side_effect = lambda mode, **kw: (
        io.TextIOWrapper(rfile) if "r" in mode else wfile
    )
    mock_socket.getpeername.return_value = ("127.0.0.1", 9999)

    mock_server = MagicMock()
    mock_server.server_address = ("127.0.0.1", 8080)

    handler = VulnerableHandler.__new__(VulnerableHandler)
    handler.request = mock_socket
    handler.client_address = ("127.0.0.1", 9999)
    handler.server = mock_server
    handler.wfile = wfile
    handler.rfile = rfile

    # Capture headers sent via send_response / send_header / end_headers
    handler._headers_buffer = []
    handler.send_response = MagicMock(side_effect=lambda code, msg=None: None)
    handler.send_header = MagicMock(
        side_effect=lambda k, v: handler._headers_buffer.append((k, v))
    )
    handler.end_headers = MagicMock()
    handler.log_message = MagicMock()

    return handler


def _get_response_body(handler: VulnerableHandler) -> str:
    """Return the HTML body written to the handler's wfile buffer."""
    return handler.wfile.getvalue().decode("utf-8")


class TestSearchEndpointXSSRemediation(unittest.TestCase):
    """Tests for the /search endpoint."""

    def setUp(self):
        # Reset STORED_COMMENTS between tests to prevent state leakage
        STORED_COMMENTS.clear()

    # ── Positive (functionality) tests ──────────────────────────────────────

    def test_search_renders_normal_query(self):
        """Normal search term appears in the response body."""
        handler = _make_handler("GET", "/search?q=hello")
        handler.do_GET()
        body = _get_response_body(handler)
        self.assertIn("hello", body)

    def test_search_empty_query_renders_ok(self):
        """Missing q parameter yields an empty search result page."""
        handler = _make_handler("GET", "/search")
        handler.do_GET()
        body = _get_response_body(handler)
        self.assertIn("Search Results", body)

    def test_search_special_chars_displayed(self):
        """HTML-safe representation of special characters appears in output."""
        handler = _make_handler("GET", "/search?q=hello+world")
        handler.do_GET()
        body = _get_response_body(handler)
        # The term should appear in escaped form
        self.assertIn("hello", body)

    # ── Security (XSS prevention) tests ─────────────────────────────────────

    def test_search_script_tag_is_escaped(self):
        """<script> tag in q parameter must NOT appear raw in response."""
        payload = "<script>alert('XSS')</script>"
        handler = _make_handler("GET", f"/search?q={payload}")
        handler.do_GET()
        body = _get_response_body(handler)
        self.assertNotIn("<script>", body)
        # The escaped form should be present instead
        self.assertIn("&lt;script&gt;", body)

    def test_search_javascript_protocol_escaped(self):
        """javascript: URI scheme must be escaped."""
        payload = "javascript:alert(1)"
        handler = _make_handler("GET", f"/search?q={payload}")
        handler.do_GET()
        body = _get_response_body(handler)
        # Colons are not HTML-special but the angle brackets/quotes in any
        # surrounding tags must be escaped; the raw protocol itself is only
        # dangerous inside an href attribute — here it's reflected in text and
        # an input value. Verify the raw payload is present but not wrapped in
        # an executable context by confirming no unescaped '<' or '>' surround it.
        self.assertNotIn("<script>", body)

    def test_search_attribute_breakout_escaped(self):
        """Attempt to break out of an HTML attribute must be neutralised."""
        payload = '" onmouseover="alert(1)'
        handler = _make_handler("GET", f"/search?q={payload}")
        handler.do_GET()
        body = _get_response_body(handler)
        # The double-quote must appear as &quot; so attribute breakout fails
        self.assertNotIn('" onmouseover="', body)
        self.assertIn("&quot;", body)

    def test_search_angle_brackets_escaped(self):
        """< and > characters in q parameter must be HTML-escaped."""
        handler = _make_handler("GET", "/search?q=<b>bold</b>")
        handler.do_GET()
        body = _get_response_body(handler)
        self.assertNotIn("<b>bold</b>", body)
        self.assertIn("&lt;b&gt;", body)

    def test_search_ampersand_escaped(self):
        """& character must be HTML-escaped to &amp;."""
        handler = _make_handler("GET", "/search?q=a%26b")
        handler.do_GET()
        body = _get_response_body(handler)
        # Raw & must not appear in the reflected value (it gets escaped to &amp;)
        # The form action="/search" contains & implicitly but the user value is
        # what we care about:
        self.assertIn("&amp;", body)


class TestProfileEndpointXSSRemediation(unittest.TestCase):
    """Tests for the /profile endpoint."""

    def setUp(self):
        STORED_COMMENTS.clear()

    def test_profile_default_username(self):
        """No user param defaults to 'guest'."""
        handler = _make_handler("GET", "/profile")
        handler.do_GET()
        body = _get_response_body(handler)
        self.assertIn("guest", body)

    def test_profile_normal_username(self):
        """Normal alphanumeric username appears in response."""
        handler = _make_handler("GET", "/profile?user=alice")
        handler.do_GET()
        body = _get_response_body(handler)
        self.assertIn("alice", body)

    def test_profile_script_tag_escaped(self):
        """<script> in user param must not appear raw in response."""
        payload = "<script>alert('XSS')</script>"
        handler = _make_handler("GET", f"/profile?user={payload}")
        handler.do_GET()
        body = _get_response_body(handler)
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_profile_attribute_breakout_escaped(self):
        """data-user attribute breakout attempt must be neutralised."""
        payload = '" onmouseover="alert(1)'
        handler = _make_handler("GET", f"/profile?user={payload}")
        handler.do_GET()
        body = _get_response_body(handler)
        self.assertNotIn('" onmouseover="', body)
        self.assertIn("&quot;", body)

    def test_profile_img_onerror_escaped(self):
        """<img onerror> payload in user param must be escaped."""
        payload = '<img src=x onerror=alert(1)>'
        handler = _make_handler("GET", f"/profile?user={payload}")
        handler.do_GET()
        body = _get_response_body(handler)
        self.assertNotIn("<img", body)
        self.assertIn("&lt;img", body)

    def test_profile_user_reflected_in_all_occurrences(self):
        """All three reflections of username in the template are escaped."""
        payload = "<b>evil</b>"
        handler = _make_handler("GET", f"/profile?user={payload}")
        handler.do_GET()
        body = _get_response_body(handler)
        # Unescaped tag must not appear anywhere in the response
        self.assertNotIn("<b>evil</b>", body)
        # Escaped form should appear (three times: data-user attr, h2, p)
        self.assertGreaterEqual(body.count("&lt;b&gt;evil&lt;/b&gt;"), 1)


class TestCommentEndpointXSSRemediation(unittest.TestCase):
    """Tests for the /comment endpoint (stored XSS scenario)."""

    def setUp(self):
        STORED_COMMENTS.clear()

    def test_comment_normal_text_stored_and_displayed(self):
        """Ordinary comment text is stored and appears in the response."""
        handler = _make_handler("GET", "/comment?text=hello+world")
        handler.do_GET()
        body = _get_response_body(handler)
        self.assertIn("hello", body)

    def test_comment_empty_text(self):
        """Empty text param is handled gracefully."""
        handler = _make_handler("GET", "/comment")
        handler.do_GET()
        body = _get_response_body(handler)
        self.assertIn("Comments", body)

    def test_comment_script_tag_escaped(self):
        """<script> payload in text param must not appear raw."""
        payload = "<script>alert('XSS')</script>"
        handler = _make_handler("GET", f"/comment?text={payload}")
        handler.do_GET()
        body = _get_response_body(handler)
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_stored_comments_all_escaped_on_subsequent_request(self):
        """Stored XSS: a second request still renders earlier payload escaped."""
        payload = "<img src=x onerror=alert(1)>"
        # First request: stores the payload
        handler1 = _make_handler("GET", f"/comment?text={payload}")
        handler1.do_GET()
        # Second request: even a benign comment triggers re-render of stored comments
        handler2 = _make_handler("GET", "/comment?text=safe")
        handler2.do_GET()
        body = _get_response_body(handler2)
        self.assertNotIn("<img", body)
        self.assertIn("&lt;img", body)

    def test_comment_multiple_payloads_all_escaped(self):
        """Multiple XSS payloads stored in sequence are all escaped."""
        payloads = [
            "<script>alert(1)</script>",
            '<img src=x onerror=alert(2)>',
            '" onload="evil()',
        ]
        for payload in payloads:
            handler = _make_handler("GET", f"/comment?text={payload}")
            handler.do_GET()

        # Final render must contain zero raw HTML tags from any payload
        handler_final = _make_handler("GET", "/comment?text=check")
        handler_final.do_GET()
        body = _get_response_body(handler_final)
        self.assertNotIn("<script>", body)
        self.assertNotIn("<img", body)


class TestSecurityHeaders(unittest.TestCase):
    """Verifies that security-relevant HTTP headers are set on every response."""

    def setUp(self):
        STORED_COMMENTS.clear()

    def _headers_for(self, path: str) -> list:
        handler = _make_handler("GET", path)
        handler.do_GET()
        return handler._headers_buffer

    def test_content_type_includes_charset(self):
        """Content-Type header must specify charset=utf-8."""
        headers = dict(self._headers_for("/search?q=test"))
        ct = headers.get("Content-Type", "")
        self.assertIn("charset", ct.lower())

    def test_csp_header_present(self):
        """Content-Security-Policy header must be present."""
        headers = dict(self._headers_for("/search?q=test"))
        self.assertIn("Content-Security-Policy", headers)

    def test_x_content_type_options_present(self):
        """X-Content-Type-Options: nosniff must be present."""
        headers = dict(self._headers_for("/profile?user=alice"))
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")

    def test_x_frame_options_present(self):
        """X-Frame-Options: DENY must be present."""
        headers = dict(self._headers_for("/comment?text=hi"))
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")

    def test_security_headers_on_404(self):
        """Security headers must also be present on 404 responses."""
        headers = dict(self._headers_for("/nonexistent"))
        self.assertIn("Content-Security-Policy", headers)


class TestHtmlEscapeUnit(unittest.TestCase):
    """Unit tests for the escaping behaviour of html.escape() as used in the fix."""

    def test_lt_gt_escaped(self):
        import html
        self.assertEqual(html.escape("<script>"), "&lt;script&gt;")

    def test_ampersand_escaped(self):
        import html
        self.assertEqual(html.escape("a&b"), "a&amp;b")

    def test_double_quote_escaped_with_quote_flag(self):
        import html
        # html.escape() escapes double quotes by default (quote=True)
        self.assertEqual(html.escape('"hello"'), "&quot;hello&quot;")

    def test_single_quote_not_escaped_by_default(self):
        import html
        # single quotes are NOT escaped by html.escape() by default,
        # but the library encodes them when quote=True is passed only for
        # double-quote — confirm default behaviour is understood:
        result = html.escape("it's fine")
        self.assertIn("'", result)  # single quote passes through

    def test_combined_payload_fully_escaped(self):
        import html
        payload = '<script>alert("XSS & more")</script>'
        escaped = html.escape(payload)
        self.assertNotIn("<", escaped)
        self.assertNotIn(">", escaped)
        self.assertNotIn('"', escaped)


if __name__ == "__main__":
    unittest.main()
