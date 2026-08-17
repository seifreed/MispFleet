"""A real, minimal TAXII 2.1 server for integration tests."""

from __future__ import annotations

import json
import re
from typing import Any, cast

from tests.httpserver import AppServer, JSONRequestHandler, LocalHTTPServer

TOKEN = "taxii-" + "token"
API_ROOT = "api1"
COLLECTION_ID = "collection-1"

_OBJECTS = re.compile(r"^/(?P<root>[^/]+)/collections/(?P<collection>[^/]+)/objects/$")


class FakeTaxii(LocalHTTPServer):
    """In-memory TAXII 2.1 application state, one instance per test."""

    def __init__(self) -> None:
        self.pushed: list[dict[str, Any]] = []
        self.status: int | None = None
        self.reply_html: bool = False
        self.collections_body: dict[str, Any] | None = None
        # Real TAXII servers answer 202 and report per-object outcomes in the
        # status resource, so a fully rejected push still looks like success
        # at the HTTP layer.
        self.reject_pushes: bool = False
        super().__init__(_Handler)


class _Handler(JSONRequestHandler):
    content_type = "application/taxii+json;version=2.1"

    @property
    def app(self) -> FakeTaxii:
        return cast(FakeTaxii, cast(AppServer, self.server).app)

    def _authorized(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

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
            body = self.app.collections_body
            self._reply(
                200,
                (
                    body
                    if body is not None
                    else {
                        "collections": [{"id": COLLECTION_ID, "title": "Test", "can_write": True}]
                    }
                ),
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
        if self.app.reject_pushes:
            self._reply(
                202,
                {
                    "id": "status-1",
                    "status": "complete",
                    "success_count": 0,
                    "failure_count": len(objects),
                },
            )
            return
        self.app.pushed.extend(objects)
        self._reply(
            202,
            {"id": "status-1", "status": "complete", "success_count": len(objects)},
        )
