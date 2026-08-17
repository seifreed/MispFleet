"""A real, minimal OpenCTI GraphQL server for integration tests."""

from __future__ import annotations

import json
from typing import Any, cast

from tests.httpserver import AppServer, JSONRequestHandler, LocalHTTPServer

TOKEN = "opencti-" + "token"
VERSION = "6.2.0"


class FakeOpenCTI(LocalHTTPServer):
    """In-memory OpenCTI-like GraphQL endpoint, one instance per test."""

    def __init__(self) -> None:
        self.pushed: list[dict[str, Any]] = []
        self.status: int | None = None
        self.reply_json_array = False
        self.reply_html: bool = False
        self.graphql_error: str | None = None
        self.raw_errors: Any | None = None
        super().__init__(_Handler)


class _Handler(JSONRequestHandler):
    @property
    def app(self) -> FakeOpenCTI:
        return cast(FakeOpenCTI, cast(AppServer, self.server).app)

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
        if app.reply_json_array:
            self._reply(200, ["not", "an", "object"])
            return
        if app.raw_errors is not None:
            self._reply(200, {"errors": app.raw_errors})
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
