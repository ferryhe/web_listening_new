"""Owned loopback fixture for the explicitly authorized real-browser matrix."""

from __future__ import annotations

import json
import threading
from collections import Counter
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@contextmanager
def fixture_server(*, robots_status=200):  # pylint: disable=too-many-statements
    """Serve only frozen paths; log actual reads and inject fixture-only failures."""
    reads = []
    counts = Counter()

    class Handler(BaseHTTPRequestHandler):
        """Serve deterministic owned-site cases."""

        def log_message(self, _format, *args):  # pylint: disable=arguments-differ
            pass

        def do_GET(self):  # pylint: disable=invalid-name,too-many-branches
            """Return a frozen response and record its actual size."""
            counts[self.path] += 1
            status, mime = 200, "text/html"
            if self.path == "/robots.txt":
                status, mime = robots_status, "text/plain"
                body = b"User-agent: *\nDisallow: /deny\n"
            elif self.path in {"/http", "/qualification"}:
                body = (
                    b"<html><body><main>Frozen governed public fixture content."
                    b"</main></body></html>"
                )
            elif self.path == "/cloudflare":
                status, body = 403, b"Blocked fixture; never a source artifact"
            elif self.path == "/auth":
                status, body = 401, b"Authentication required"
            elif self.path == "/file":
                mime, body = (
                    "application/pdf",
                    b"%PDF-1.7\n% frozen fixture only\n%%EOF",
                )
            elif self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/browser")
                self.send_header("Content-Length", "0")
                self.end_headers()
                reads.append({"path": self.path, "status": 302, "bytes": 0})
                return
            elif self.path == "/app.js":
                mime = "application/javascript"
                body = (
                    b"fetch('/data.json').then(r=>r.json()).then(d=>{"
                    b"document.body.innerHTML='<main>'+d.value.repeat(200)+'</main>';});"
                )
            elif self.path == "/data.json":
                mime = "application/json"
                body = json.dumps(
                    {"value": "Frozen rendered browser content. "}
                ).encode()
            elif self.path == "/favicon.ico":
                mime, body = "image/x-icon", b""
            elif self.path == "/out-of-scope":
                body = b"<script>fetch('http://127.0.0.1:1/forbidden')</script>"
            elif self.path == "/interactive":
                body = b"<div class='g-recaptcha'>Verify you are human</div>"
            elif self.path == "/failed" or (
                self.path == "/cloak" and counts[self.path] == 2
            ):
                body = b"<title>Just a moment...</title><script></script>"
            elif self.path in {"/browser", "/cloak"}:
                body = b"<html><head><script src='/app.js'></script></head><body></body></html>"
            else:
                status, body = 404, b"Not found"
            reads.append({"path": self.path, "status": status, "bytes": len(body)})
            self.send_response(status)
            if self.path == "/cloudflare":
                self.send_header("CF-Mitigated", "challenge")
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", reads
    finally:
        server.shutdown()
        server.server_close()
        thread.join(1)
