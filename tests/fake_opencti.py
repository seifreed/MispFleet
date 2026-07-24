"""A real, minimal OpenCTI GraphQL server for integration tests."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

TOKEN = "opencti-" + "token"
VERSION = "6.2.0"


class FakeOpenCTI:
    """In-memory OpenCTI-like GraphQL endpoint, one instance per test."""

    def __init__(self) -> None:
        self.pushed: list[dict[str, Any]] = []
        self.status: int | None = None
        self.reply_html: bool = False
        self.graphql_error: str | None = None
        self._server = _Server(("127.0.0.1", 0), _Handler)
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


class _Server(ThreadingHTTPServer):
    app: FakeOpenCTI


class _Handler(BaseHTTPRequestHandler):
    @property
    def app(self) -> FakeOpenCTI:
        return cast(_Server, self.server).app

    def log_message(self, format: str, *args: Any) -> None:
        """Silence request logging during tests."""

    def _reply(self, status: int, payload: Any) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
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

    def do_POST(self) -> None:
        app = self.app
        if app.status is not None:
            self._reply(app.status, {"error": "scripted"})
            return
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self._reply(401, {"errors": [{"message": "Unauthorized"}]})
            return
        if app.reply_html:
            self._reply_raw(200, "<html>not json</html>")
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        if app.graphql_error is not None:
            self._reply(200, {"errors": [{"message": app.graphql_error}]})
            return
        query = payload.get("query", "")
        if "about" in query:
            self._reply(200, {"data": {"about": {"version": VERSION}}})
            return
        if "stixBundlePush" in query:
            bundle = json.loads(payload["variables"]["bundle"])
            app.pushed.append(bundle)
            self._reply(200, {"data": {"stixBundlePush": "work-1"}})
            return
        self._reply(200, {"errors": [{"message": "unknown operation"}]})
