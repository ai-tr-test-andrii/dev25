import html as html_module
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class VulnerableHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/search":
            # Escape user input with html.escape() before reflecting into HTML
            query = html_module.escape(params.get("q", [""])[0])

            html = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Search</title></head>
            <body>
                <h1>Search Results</h1>
                <form method="GET" action="/search">
                    <input type="text" name="q" value="{query}">
                    <button type="submit">Search</button>
                </form>
                <p>You searched for: {query}</p>
                <p>No results found for <b>{query}</b>.</p>
            </body>
            </html>
            """
            self._send(html)

        elif parsed.path == "/profile":
            # Escape user input with html.escape() before inserting into attribute and body
            username = html_module.escape(params.get("user", ["guest"])[0])

            html = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Profile</title></head>
            <body>
                <div class="profile" data-user="{username}">
                    <h2>Profile: {username}</h2>
                    <p>Welcome back, {username}!</p>
                </div>
            </body>
            </html>
            """
            self._send(html)

        elif parsed.path == "/comment":
            # Escape stored comment with html.escape() before rendering into the DOM
            comment = params.get("text", [""])[0]
            STORED_COMMENTS.append(comment)

            comments_html = "".join(
                f"<li>{html_module.escape(c)}</li>" for c in STORED_COMMENTS
            )

            html = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Comments</title></head>
            <body>
                <h1>Comments</h1>
                <form method="GET" action="/comment">
                    <input type="text" name="text" placeholder="Leave a comment">
                    <button type="submit">Post</button>
                </form>
                <ul>{comments_html}</ul>
            </body>
            </html>
            """
            self._send(html)

        else:
            self._send("<h1>404</h1>", status=404)

    def _send(self, html: str, status: int = 200):
        encoded = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        pass  # silence default access log


STORED_COMMENTS = []

if __name__ == "__main__":
    print("Vulnerable server running at http://localhost:8080")
    print()
    print("Attack URLs to try:")
    print()
    print("  Reflected XSS (search box):")
    print('  http://localhost:8080/search?q=<script>alert("XSS")</script>')
    print()
    print("  Attribute breakout (profile page):")
    print('  http://localhost:8080/profile?user=" onmouseover="alert(1)')
    print()
    print("  Stored XSS (post a payload, then reload /comment):")
    print('  http://localhost:8080/comment?text=<img src=x onerror=alert("stored XSS")>')
    print()
    HTTPServer(("", 8080), VulnerableHandler).serve_forever()
