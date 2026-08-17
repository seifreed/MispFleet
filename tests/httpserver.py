"""A real threaded localhost HTTP server shared by the fake integration servers.

The OpenCTI and TAXII fakes only differ in how they route requests; the server
lifecycle and the JSON/raw reply helpers are identical, so they live here.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class AppServer(ThreadingHTTPServer):
    """HTTP server carrying a reference to its owning fake application."""

    app: Any


class LocalHTTPServer:
    """One threaded localhost HTTP server per test; subclasses supply a handler."""

    def __init__(self, handler_class: type[BaseHTTPRequestHandler]) -> None:
        self._server = AppServer(("127.0.0.1", 0), handler_class)
        self._server.app = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        """Start serving on a random localhost port."""
        self._thread.start()

    def stop(self) -> None:
        """Shut the server down and join its thread."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    @property
    def url(self) -> str:
        """Base URL of the server."""
        return f"http://127.0.0.1:{self._server.server_address[1]}"


def serve[ServerT: LocalHTTPServer](server: ServerT) -> Iterator[ServerT]:
    """Pytest-fixture body: start ``server``, yield it, stop it on teardown."""
    server.start()
    try:
        yield server
    finally:
        server.stop()


class JSONRequestHandler(BaseHTTPRequestHandler):
    """Silences request logging and replies with a JSON or raw HTML body."""

    content_type = "application/json"

    def log_message(self, format: str, *args: Any) -> None:
        """Silence request logging during tests."""

    def _reply(self, status: int, payload: Any) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", self.content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _reply_raw(self, status: int, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
