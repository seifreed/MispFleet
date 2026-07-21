"""A real, scriptable HTTP server that behaves like a minimal MISP API.

Tests run actual network round trips against this server instead of mocking
the HTTP layer.
"""

from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

API_KEY = "test-api-key"

_EVENT_VIEW = re.compile(r"^/events/view/(?P<identifier>[^/]+)$")
_EVENT_EDIT = re.compile(r"^/events/edit/(?P<identifier>[^/]+)$")

_LIST_ROUTES = {
    "/tags",
    "/taxonomies",
    "/galaxies",
    "/warninglists",
    "/objectTemplates",
    "/organisations",
    "/servers",
}


class FakeMisp:
    """In-memory MISP-like application state, one instance per test."""

    def __init__(self) -> None:
        self.events: dict[str, dict[str, Any]] = {}
        self.attributes: list[dict[str, Any]] = []
        self.templates: list[dict[str, Any]] = []
        self.version_payload: dict[str, Any] = {"version": "2.4.190", "perm_sync": True}
        self.scripted: list[tuple[int, dict[str, str], str]] = []
        self.delay: float = 0.0
        self.static_search: bool = False
        self.close_next: bool = False
        self.requests_seen: list[tuple[str, str]] = []
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._server.app = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        """Start serving on a random localhost port."""
        self._thread.start()

    def stop(self) -> None:
        """Shut the server down and join its thread; safe to call twice."""
        if not self._thread.is_alive():
            return
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    @property
    def port(self) -> int:
        """The bound localhost port."""
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        """Base URL of the server."""
        return f"http://127.0.0.1:{self.port}"

    def script(self, status: int, body: str = "", headers: dict[str, str] | None = None) -> None:
        """Queue a canned response returned before normal routing."""
        self.scripted.append((status, headers or {}, body))

    def add_event(self, event: dict[str, Any]) -> None:
        """Register a raw MISP event (inner ``Event`` dictionary)."""
        self.events[str(event["uuid"])] = event

    def find_event(self, identifier: str) -> dict[str, Any] | None:
        """Locate an event by UUID or numeric id."""
        event = self.events.get(identifier)
        if event is not None:
            return event
        for candidate in self.events.values():
            if str(candidate.get("id")) == identifier:
                return candidate
        return None

    def search_attributes(self, body: dict[str, Any]) -> list[dict[str, Any]]:
        """Filter registered attributes like a very small restSearch."""
        matches = self.attributes
        value = body.get("value")
        if value is not None:
            wanted = value if isinstance(value, list) else [value]
            matches = [item for item in matches if item.get("value") in wanted]
        types = body.get("type")
        if types is not None:
            matches = [item for item in matches if item.get("type") in types]
        if self.static_search:
            return matches[: int(body.get("limit", 10))]
        page = int(body.get("page", 1))
        limit = int(body.get("limit", 10))
        start = (page - 1) * limit
        return matches[start : start + limit]


class _Server(ThreadingHTTPServer):
    """HTTP server carrying a typed reference to its FakeMisp application."""

    app: FakeMisp


class _Handler(BaseHTTPRequestHandler):
    """Routes requests to the owning FakeMisp instance."""

    @property
    def app(self) -> FakeMisp:
        return cast(_Server, self.server).app

    def log_message(self, format: str, *args: Any) -> None:
        """Silence request logging during tests."""

    def _reply(self, status: int, payload: Any, headers: dict[str, str] | None = None) -> None:
        body = payload if isinstance(payload, str) else json.dumps(payload)
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        return dict(data)

    def _handle(self) -> None:
        app = self.app
        app.requests_seen.append((self.command, self.path))
        if app.delay:
            time.sleep(app.delay)
        if app.close_next:
            app.close_next = False
            self.wfile.close()
            self.connection.close()
            return
        if app.scripted:
            status, headers, body = app.scripted.pop(0)
            self._reply(status, body, headers)
            return
        if self.headers.get("Authorization") != API_KEY:
            self._reply(401, {"message": "Authentication failed."})
            return
        if self.command == "GET" and self.path == "/servers/getVersion":
            self._reply(200, app.version_payload)
            return
        if self.command == "GET" and self.path == "/objectTemplates":
            self._reply(200, app.templates)
            return
        if self.command == "GET" and self.path in _LIST_ROUTES:
            self._reply(200, [])
            return
        view = _EVENT_VIEW.match(self.path)
        if self.command == "GET" and view:
            event = app.find_event(view.group("identifier"))
            if event is None:
                self._reply(404, {"message": "Invalid event."})
                return
            self._reply(200, {"Event": event})
            return
        if self.command == "POST" and self.path == "/attributes/restSearch":
            body_data = self._read_body()
            matches = app.search_attributes(body_data)
            self._reply(200, {"response": {"Attribute": matches}})
            return
        if self.command == "POST" and self.path == "/events/add":
            event = self._read_body()["Event"]
            if str(event.get("uuid")) in app.events:
                self._reply(409, {"message": "Event already exists."})
                return
            app.add_event(event)
            self._reply(200, {"Event": event})
            return
        edit = _EVENT_EDIT.match(self.path)
        if self.command == "POST" and edit:
            existing = app.find_event(edit.group("identifier"))
            if existing is None:
                self._reply(404, {"message": "Invalid event."})
                return
            event = self._read_body()["Event"]
            app.add_event(event)
            self._reply(200, {"Event": event})
            return
        self._reply(404, {"message": "Invalid URL."})

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()
