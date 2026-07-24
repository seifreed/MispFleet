"""A real, minimal TAXII 2.1 server for integration tests."""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

TOKEN = "taxii-" + "token"
API_ROOT = "api1"
COLLECTION_ID = "collection-1"

_OBJECTS = re.compile(r"^/(?P<root>[^/]+)/collections/(?P<collection>[^/]+)/objects/$")


class FakeTaxii:
    """In-memory TAXII 2.1 application state, one instance per test."""

    def __init__(self) -> None:
        self.pushed: list[dict[str, Any]] = []
        self.status: int | None = None
        self.reply_html: bool = False
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
    app: FakeTaxii


class _Handler(BaseHTTPRequestHandler):
    @property
    def app(self) -> FakeTaxii:
        return cast(_Server, self.server).app

    def log_message(self, format: str, *args: Any) -> None:
        """Silence request logging during tests."""

    def _reply(self, status: int, payload: Any) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/taxii+json;version=2.1")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authorized(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def _reply_raw(self, status: int, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.app.reply_html:
            self._reply_raw(200, "<html>not json</html>")
            return
        if self.app.status is not None:
            self._reply(self.app.status, {"title": "scripted error"})
            return
        if not self._authorized():
            self._reply(401, {"title": "Unauthorized"})
            return
        if self.path == "/taxii2/":
            self._reply(
                200,
                {"title": "Fake TAXII", "api_roots": [f"{self.path_root()}/{API_ROOT}/"]},
            )
            return
        if self.path == f"/{API_ROOT}/collections/":
            self._reply(
                200,
                {"collections": [{"id": COLLECTION_ID, "title": "Test", "can_write": True}]},
            )
            return
        self._reply(404, {"title": "Not found"})

    def path_root(self) -> str:
        return f"http://127.0.0.1:{self.app._server.server_address[1]}"

    def do_POST(self) -> None:
        if self.app.status is not None:
            self._reply(self.app.status, {"title": "scripted error"})
            return
        if not self._authorized():
            self._reply(401, {"title": "Unauthorized"})
            return
        match = _OBJECTS.match(self.path)
        if (
            match is None
            or match.group("root") != API_ROOT
            or match.group("collection") != COLLECTION_ID
        ):
            self._reply(404, {"title": "Not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        objects = body.get("objects", [])
        self.app.pushed.extend(objects)
        self._reply(
            202,
            {"id": "status-1", "status": "complete", "success_count": len(objects)},
        )
