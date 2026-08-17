"""A real, scriptable HTTP server that behaves like a minimal MISP API.

Tests run actual network round trips against this server instead of mocking
the HTTP layer.
"""

from __future__ import annotations

import base64
import json
import re
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote

API_KEY = "test-api-key"

_EVENT_VIEW = re.compile(r"^/events/view/(?P<identifier>[^/]+)$")
_ATTRIBUTE_VIEW = re.compile(r"^/attributes/view/(?P<identifier>[^/]+)$")
_EVENT_EDIT = re.compile(r"^/events/edit/(?P<identifier>[^/]+)$")
_EVENT_DELETE = re.compile(r"^/events/delete/(?P<identifier>[^/]+)$")
_EVENT_PUBLISH = re.compile(r"^/events/(?P<action>publish|unpublish)/(?P<identifier>[^/]+)$")
_EVENT_TAG = re.compile(
    r"^/events/(?P<action>addTag|removeTag)/(?P<identifier>[^/]+)/(?P<tag>[^/]+)"
    r"(?:/local:(?P<local>[01]))?$"
)
_EVENT_ENRICH = re.compile(r"^/events/enrichEvent/(?P<identifier>[^/]+)$")
_ATTRIBUTE_ADD = re.compile(r"^/attributes/add/(?P<identifier>[^/]+)$")
_ATTRIBUTE_EDIT = re.compile(r"^/attributes/edit/(?P<identifier>[^/]+)$")
_ATTRIBUTE_DELETE = re.compile(r"^/attributes/delete/(?P<identifier>[^/]+)$")
_ATTRIBUTE_RESTORE = re.compile(r"^/attributes/restore/(?P<identifier>[^/]+)$")
_ATTRIBUTE_TAG = re.compile(
    r"^/attributes/(?P<action>addTag|removeTag)/(?P<identifier>[^/]+)/(?P<tag>[^/]+)"
    r"(?:/local:(?P<local>[01]))?$"
)
_ATTRIBUTE_STATS = re.compile(
    r"^/attributes/attributeStatistics/(?P<context>[^/]+)/(?P<percentage>[01])$"
)
_ATTRIBUTE_B64 = re.compile(r"^/attributes/getAttributeByB64Value/(?P<value>[^/]+)$")
_ATTRIBUTE_ENRICH = re.compile(r"^/attributes/enrich/(?P<identifier>[^/]+)$")

_TAG_VIEW = re.compile(r"^/tags/view/(?P<identifier>[^/]+)$")
_TAG_EDIT = re.compile(r"^/tags/edit/(?P<identifier>[^/]+)$")
_TAG_DELETE = re.compile(r"^/tags/delete/(?P<identifier>[^/]+)$")
_TAG_SEARCH = re.compile(r"^/tags/search/(?P<term>[^/]+)$")
_SIGHTING_INDEX = re.compile(r"^/sightings/index/(?P<identifier>[^/]+)$")
_SIGHTING_ADD_ATTRIBUTE = re.compile(r"^/sightings/add/(?P<identifier>[^/]+)$")
_SIGHTING_DELETE = re.compile(r"^/sightings/delete/(?P<identifier>[^/]+)$")
_OBJECT_VIEW = re.compile(r"^/objects/view/(?P<identifier>[^/]+)$")
_OBJECT_ADD = re.compile(r"^/objects/add/(?P<event>[^/]+)/(?P<template>[^/]+)$")
_OBJECT_DELETE = re.compile(r"^/objects/delete/(?P<identifier>[^/]+)/(?P<hard>[01])$")

_TAXONOMY_VIEW = re.compile(r"^/taxonomies/view/(?P<identifier>[^/]+)$")
_TAXONOMY_TOGGLE = re.compile(r"^/taxonomies/(?P<action>enable|disable)/(?P<identifier>[^/]+)$")
_TAXONOMY_TAGS = re.compile(r"^/taxonomies/taxonomy_tags/(?P<identifier>[^/]+)$")
_TAXONOMY_EXPORT = re.compile(r"^/taxonomies/export/(?P<identifier>[^/]+)$")
_WARNINGLIST_VIEW = re.compile(r"^/warninglists/view/(?P<identifier>[^/]+)$")
_NOTICELIST_VIEW = re.compile(r"^/noticelists/view/(?P<identifier>[^/]+)$")
_NOTICELIST_TOGGLE = re.compile(r"^/noticelists/toggleEnable/(?P<identifier>[^/]+)$")

_GALAXY_VIEW = re.compile(r"^/galaxies/view/(?P<identifier>[^/]+)$")
_GALAXY_DELETE = re.compile(r"^/galaxies/delete/(?P<identifier>[^/]+)$")
_GALAXY_EXPORT = re.compile(r"^/galaxies/export/(?P<identifier>[^/]+)$")
_GALAXY_ATTACH = re.compile(
    r"^/galaxies/attachCluster/(?P<target>[^/]+)/(?P<type>[^/]+)/local:(?P<local>[01])$"
)
_CLUSTER_INDEX = re.compile(r"^/galaxy_clusters/index/(?P<identifier>[^/]+)$")
_CLUSTER_VIEW = re.compile(r"^/galaxy_clusters/view/(?P<identifier>[^/]+)$")
_CLUSTER_ADD = re.compile(r"^/galaxy_clusters/add/(?P<identifier>[^/]+)$")
_CLUSTER_EDIT = re.compile(r"^/galaxy_clusters/edit/(?P<identifier>[^/]+)$")
_CLUSTER_ACTION = re.compile(
    r"^/galaxy_clusters/(?P<action>publish|unpublish|delete|restore)/(?P<identifier>[^/]+)$"
)

_SERVER_EDIT = re.compile(r"^/servers/edit/(?P<identifier>[^/]+)$")
_SERVER_DELETE = re.compile(r"^/servers/delete/(?P<identifier>[^/]+)$")
_SERVER_PULL_PUSH = re.compile(
    r"^/servers/(?P<action>pull|push)/(?P<identifier>[^/]+)/(?P<technique>[^/]+)$"
)
_SERVER_START_WORKER = re.compile(r"^/servers/startWorker/(?P<worker>[^/]+)$")
_SERVER_STOP_WORKER = re.compile(r"^/servers/stopWorker/(?P<pid>[^/]+)$")
_SERVER_GET_SETTING = re.compile(r"^/servers/getSetting/(?P<name>[^/]+)$")
_SERVER_EDIT_SETTING = re.compile(r"^/servers/serverSettingsEdit/(?P<name>[^/]+)$")

_SERVER_SIMPLE_POSTS = {
    "/servers/killAllWorkers": "Workers killed.",
    "/servers/restartWorkers": "Workers restarted.",
    "/servers/restartDeadWorkers": "Dead workers restarted.",
    "/servers/update": "MISP updated.",
    "/servers/updateJSON": "Submodules updated.",
    "/servers/cache": "Caching queued.",
}

_ORG_VIEW = re.compile(r"^/organisations/view/(?P<identifier>[^/]+)$")
_ORG_EDIT = re.compile(r"^/admin/organisations/edit/(?P<identifier>[^/]+)$")
_ORG_DELETE = re.compile(r"^/admin/organisations/delete/(?P<identifier>[^/]+)$")
_USER_VIEW = re.compile(r"^/admin/users/view/(?P<identifier>[^/]+)$")
_USER_EDIT = re.compile(r"^/admin/users/edit/(?P<identifier>[^/]+)$")
_USER_DELETE = re.compile(r"^/admin/users/delete/(?P<identifier>[^/]+)$")
_USER_RESET = re.compile(r"^/users/initiatePasswordReset/(?P<identifier>[^/]+)/(?P<first>[01])$")
_USER_TOTP = re.compile(r"^/users/totp_delete/(?P<identifier>[^/]+)$")
_AUTHKEY_VIEW = re.compile(r"^/auth_keys/view/(?P<identifier>[^/]+)$")
_AUTHKEY_ADD = re.compile(r"^/auth_keys/add/(?P<identifier>[^/]+)$")
_AUTHKEY_EDIT = re.compile(r"^/auth_keys/edit/(?P<identifier>[^/]+)$")
_AUTHKEY_DELETE = re.compile(r"^/auth_keys/delete/(?P<identifier>[^/]+)$")
_USERSETTING_VIEW = re.compile(r"^/user_settings/view/(?P<identifier>[^/]+)$")
_USERSETTING_DELETE = re.compile(r"^/user_settings/delete/(?P<identifier>[^/]+)$")
_USERSETTING_GET = re.compile(r"^/user_settings/getSetting/(?P<user>[^/]+)/(?P<name>[^/]+)$")
_USERSETTING_SET = re.compile(r"^/user_settings/setSetting/(?P<user>[^/]+)/(?P<name>[^/]+)$")

_FEED_VIEW = re.compile(r"^/feeds/view/(?P<identifier>[^/]+)$")
_FEED_EDIT = re.compile(r"^/feeds/edit/(?P<identifier>[^/]+)$")
_FEED_TOGGLE = re.compile(r"^/feeds/(?P<action>enable|disable)/(?P<identifier>[^/]+)$")
_FEED_CACHE = re.compile(r"^/feeds/cacheFeeds/(?P<scope>[^/]+)$")
_FEED_FETCH = re.compile(r"^/feeds/fetchFromFeed/(?P<identifier>[^/]+)$")
_SG_VIEW = re.compile(r"^/sharing_groups/view/(?P<identifier>[^/]+)$")
_SG_EDIT = re.compile(r"^/sharing_groups/edit/(?P<identifier>[^/]+)$")
_SG_DELETE = re.compile(r"^/sharing_groups/delete/(?P<identifier>[^/]+)$")
_SG_MEMBER = re.compile(
    r"^/sharing_groups/(?P<action>addOrg|removeOrg|addServer|removeServer)"
    r"/(?P<group>[^/]+)/(?P<member>[^/]+)$"
)
_SGB_VIEW = re.compile(r"^/sharing_group_blueprints/view/(?P<identifier>[^/]+)$")
_SGB_ORGS = re.compile(r"^/sharing_group_blueprints/viewOrgs/(?P<identifier>[^/]+)$")
_SGB_EDIT = re.compile(r"^/sharing_group_blueprints/edit/(?P<identifier>[^/]+)$")
_SGB_ACTION = re.compile(
    r"^/sharing_group_blueprints/(?P<action>execute|detach)/(?P<identifier>[^/]+)$"
)
_SGB_DELETE = re.compile(r"^/sharing_group_blueprints/delete/(?P<identifier>[^/]+)$")

_REPORT_VIEW = re.compile(r"^/eventReports/view/(?P<identifier>[^/]+)$")
_REPORT_ADD = re.compile(r"^/eventReports/add/(?P<identifier>[^/]+)$")
_REPORT_EDIT = re.compile(r"^/eventReports/edit/(?P<identifier>[^/]+)$")
_REPORT_DELETE = re.compile(r"^/eventReports/delete/(?P<identifier>[^/]+)(?:/(?P<hard>1))?$")
_REPORT_RESTORE = re.compile(r"^/eventReports/restore/(?P<identifier>[^/]+)$")
_REPORT_IMPORT = re.compile(r"^/eventReports/importReportFromUrl/(?P<identifier>[^/]+)$")
_ANALYST_INDEX = re.compile(r"^/analystData/index/(?P<type>[^/]+)$")
_ANALYST_VIEW = re.compile(r"^/analystData/view/(?P<type>[^/]+)/(?P<identifier>[^/]+)$")
_ANALYST_ADD = re.compile(
    r"^/analystData/add/(?P<type>[^/]+)/(?P<uuid>[^/]+)/(?P<object_type>[^/]+)$"
)
_ANALYST_EDIT = re.compile(r"^/analystData/edit/(?P<type>[^/]+)/(?P<identifier>[^/]+)$")
_ANALYST_DELETE = re.compile(r"^/analystData/delete/(?P<type>[^/]+)/(?P<identifier>[^/]+)$")
_COLLECTION_VIEW = re.compile(r"^/collections/view/(?P<identifier>[^/]+)$")
_COLLECTION_EDIT = re.compile(r"^/collections/edit/(?P<identifier>[^/]+)$")
_COLLECTION_DELETE = re.compile(r"^/collections/delete/(?P<identifier>[^/]+)$")
_COLLECTION_INDEX = re.compile(r"^/collections/index/(?P<filter>[^/]+)$")

_LIST_ROUTES = {
    "/objectTemplates",
}


class FakeMisp:
    """In-memory MISP-like application state, one instance per test."""

    def __init__(self, certfile: Path | None = None, keyfile: Path | None = None) -> None:
        self.tls = certfile is not None
        self.events: dict[str, dict[str, Any]] = {}
        self.attributes: list[dict[str, Any]] = []
        self.templates: list[dict[str, Any]] = []
        self.tags: list[dict[str, Any]] = []
        self.sightings: list[dict[str, Any]] = []
        self.objects: list[dict[str, Any]] = []
        self.taxonomies: list[dict[str, Any]] = []
        self.warninglists: list[dict[str, Any]] = []
        self.noticelists: list[dict[str, Any]] = []
        self.galaxies: list[dict[str, Any]] = []
        self.clusters: list[dict[str, Any]] = []
        self.misp_servers: list[dict[str, Any]] = []
        self.workers: dict[str, Any] = {}
        self.settings: dict[str, Any] = {}
        self.organisations: list[dict[str, Any]] = []
        self.users: list[dict[str, Any]] = []
        self.auth_keys: list[dict[str, Any]] = []
        self.user_settings: list[dict[str, Any]] = []
        self.feeds: list[dict[str, Any]] = []
        self.sharing_groups: list[dict[str, Any]] = []
        self.blueprints: list[dict[str, Any]] = []
        self.reports: list[dict[str, Any]] = []
        self.analyst_data: dict[str, list[dict[str, Any]]] = {}
        self.collections: list[dict[str, Any]] = []
        self.logs: list[dict[str, Any]] = []
        self.instance_uuid = "0f6b1c2e-0000-4000-8000-0000000000ff"
        # Mirrors a real /servers/getVersion for an admin key on MISP 2.5.44.
        self.version_payload: dict[str, Any] = {
            "version": "2.4.190",
            "perm_sync": True,
            "perm_sighting": True,
            "perm_galaxy_editor": True,
        }
        self.scripted: list[tuple[int, dict[str, str], str]] = []
        self.delay: float = 0.0
        self.static_search: bool = False
        self.close_next: bool = False
        self.requests_seen: list[tuple[str, str]] = []
        self.search_bodies: list[dict[str, Any]] = []
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._server.app = self
        if certfile is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(certfile), str(keyfile) if keyfile else None)
            self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
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
        scheme = "https" if self.tls else "http"
        return f"{scheme}://127.0.0.1:{self.port}"

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

    def find_attribute(self, identifier: str) -> dict[str, Any] | None:
        """Locate an attribute by UUID or numeric id."""
        for item in self.attributes:
            if identifier in (item.get("uuid"), str(item.get("id"))):
                return item
        return None

    def search_events(self, body: dict[str, Any]) -> list[dict[str, Any]]:
        """Filter registered events like a very small events restSearch."""
        self.search_bodies.append(body)
        matches = list(self.events.values())
        info = body.get("eventinfo")
        if info is not None:
            needle = info.strip("%")
            matches = [item for item in matches if needle in str(item.get("info", ""))]
        return matches[: int(body.get("limit", 10))]

    def search_attributes(self, body: dict[str, Any]) -> list[dict[str, Any]]:
        """Filter registered attributes like a very small restSearch."""
        self.search_bodies.append(body)
        matches = self.attributes
        value = body.get("value")
        if value is not None:
            wanted = value if isinstance(value, list) else [value]
            matches = [item for item in matches if item.get("value") in wanted]
        types = body.get("type")
        if types is not None:
            matches = [item for item in matches if item.get("type") in types]
        orgs = body.get("org")
        if orgs is not None:
            matches = [item for item in matches if item.get("org") in orgs]
        # No object_name filter on purpose: it is absent from
        # AttributeRestSearchFilter in openapi.yaml, and real MISP discards
        # unknown restSearch keys silently. Implementing it here made the fake
        # answer a question the real endpoint cannot, hiding the defect.
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

    def _read_list_body(self) -> list[Any]:
        """Read a request body that the MISP spec declares as a bare array."""
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return []
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        return list(data)

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
        attribute_view = _ATTRIBUTE_VIEW.match(self.path)
        if self.command == "GET" and attribute_view:
            identifier = attribute_view.group("identifier")
            for item in app.attributes:
                if identifier in (item.get("uuid"), item.get("id")):
                    self._reply(200, {"Attribute": item})
                    return
            self._reply(404, {"message": "Invalid attribute."})
            return
        if self.command == "POST" and self.path == "/events/index":
            body_data = self._read_body()
            wanted_tags = set(body_data.get("tags", []))
            entries = []
            for event in app.events.values():
                names = {tag["name"] for tag in event.get("Tag", []) if "name" in tag}
                if wanted_tags and not (wanted_tags & names):
                    continue
                entries.append(
                    {
                        "id": event.get("id"),
                        "uuid": event.get("uuid"),
                        "info": event.get("info"),
                        "timestamp": event.get("timestamp"),
                    }
                )
            self._reply(200, entries)
            return
        if self.command == "POST" and self.path == "/attributes/restSearch":
            body_data = self._read_body()
            matches = app.search_attributes(body_data)
            self._reply(200, {"response": {"Attribute": matches}})
            return
        if self.command == "POST" and self.path == "/events/restSearch":
            events = app.search_events(self._read_body())
            self._reply(200, {"response": [{"Event": event} for event in events]})
            return
        if self._handle_event_mutations(app):
            return
        if self._handle_attribute_routes(app):
            return
        if self._handle_tag_routes(app):
            return
        if self._handle_sighting_routes(app):
            return
        if self._handle_object_routes(app):
            return
        if self._handle_library_routes(app):
            return
        if self._handle_galaxy_routes(app):
            return
        if self._handle_server_routes(app):
            return
        if self._handle_admin_routes(app):
            return
        if self._handle_feed_routes(app):
            return
        if self._handle_sharing_routes(app):
            return
        if self._handle_report_routes(app):
            return
        if self._handle_analyst_and_collection_routes(app):
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
        if self.command == "PUT" and edit:
            existing = app.find_event(edit.group("identifier"))
            if existing is None:
                self._reply(404, {"message": "Invalid event."})
                return
            event = self._read_body()["Event"]
            app.add_event(event)
            self._reply(200, {"Event": event})
            return
        self._reply(404, {"message": "Invalid URL."})

    def _handle_event_mutations(self, app: FakeMisp) -> bool:
        delete = _EVENT_DELETE.match(self.path)
        if self.command == "DELETE" and delete:
            event = app.find_event(delete.group("identifier"))
            if event is None:
                self._reply(404, {"message": "Invalid event."})
            else:
                del app.events[str(event["uuid"])]
                self._reply(200, {"message": "Event deleted."})
            return True
        publish = _EVENT_PUBLISH.match(self.path)
        if self.command == "POST" and publish:
            event = app.find_event(publish.group("identifier"))
            if event is None:
                self._reply(404, {"message": "Invalid event."})
            else:
                event["published"] = publish.group("action") == "publish"
                self._reply(200, {"message": f"Event {publish.group('action')}ed."})
            return True
        tag = _EVENT_TAG.match(self.path)
        if self.command == "POST" and tag:
            event = app.find_event(tag.group("identifier"))
            if event is None:
                self._reply(404, {"message": "Invalid event."})
                return True
            self._apply_tag(event, tag.group("action"), unquote(tag.group("tag")))
            self._reply(200, {"saved": True})
            return True
        enrich = _EVENT_ENRICH.match(self.path)
        if self.command == "POST" and enrich:
            if app.find_event(enrich.group("identifier")) is None:
                self._reply(404, {"message": "Invalid event."})
            else:
                self._reply(200, {"results": self._read_body()})
            return True
        return False

    def _handle_attribute_routes(self, app: FakeMisp) -> bool:
        if self.command == "GET" and self.path == "/attributes":
            # Real MISP answers this index with a bare JSON array.
            self._reply(200, app.attributes)
            return True
        if self.command == "GET" and self.path == "/events":
            self._reply(
                200,
                [
                    {"id": e.get("id"), "uuid": e.get("uuid"), "info": e.get("info")}
                    for e in app.events.values()
                ],
            )
            return True
        if self.command == "GET" and self.path == "/attributes/describeTypes":
            self._reply(200, {"result": {"types": sorted({a["type"] for a in app.attributes})}})
            return True
        stats = _ATTRIBUTE_STATS.match(self.path)
        if self.command == "GET" and stats:
            counts: dict[str, int] = {}
            for entry in app.attributes:
                key = str(entry.get(stats.group("context"), ""))
                counts[key] = counts.get(key, 0) + 1
            self._reply(200, counts)
            return True
        b64 = _ATTRIBUTE_B64.match(self.path)
        if self.command == "GET" and b64:
            value = base64.b64decode(unquote(b64.group("value"))).decode("utf-8")
            matches = [item for item in app.attributes if item.get("value") == value]
            self._reply(200, matches)
            return True
        add = _ATTRIBUTE_ADD.match(self.path)
        if self.command == "POST" and add:
            if app.find_event(add.group("identifier")) is None:
                self._reply(404, {"message": "Invalid event."})
                return True
            created_attribute = self._read_body()
            created_attribute.setdefault("id", str(len(app.attributes) + 1))
            app.attributes.append(created_attribute)
            self._reply(200, {"Attribute": created_attribute})
            return True
        edit = _ATTRIBUTE_EDIT.match(self.path)
        if self.command == "PUT" and edit:
            item = app.find_attribute(edit.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid attribute."})
            else:
                item.update(self._read_body())
                self._reply(200, {"Attribute": item})
            return True
        delete = _ATTRIBUTE_DELETE.match(self.path)
        if self.command == "DELETE" and delete:
            item = app.find_attribute(delete.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid attribute."})
            else:
                item["deleted"] = True
                self._reply(200, {"message": "Attribute deleted."})
            return True
        restore = _ATTRIBUTE_RESTORE.match(self.path)
        if self.command == "POST" and restore:
            item = app.find_attribute(restore.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid attribute."})
            else:
                item["deleted"] = False
                self._reply(200, {"Attribute": item})
            return True
        tag = _ATTRIBUTE_TAG.match(self.path)
        if self.command == "POST" and tag:
            item = app.find_attribute(tag.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid attribute."})
                return True
            self._apply_tag(item, tag.group("action"), unquote(tag.group("tag")))
            self._reply(200, {"saved": True})
            return True
        enrich = _ATTRIBUTE_ENRICH.match(self.path)
        if self.command == "POST" and enrich:
            if app.find_attribute(enrich.group("identifier")) is None:
                self._reply(404, {"message": "Invalid attribute."})
            else:
                self._reply(200, {"results": self._read_body()})
            return True
        return False

    def _handle_tag_routes(self, app: FakeMisp) -> bool:
        if self.command == "GET" and self.path == "/tags":
            self._reply(200, {"Tag": app.tags})
            return True
        view = _TAG_VIEW.match(self.path)
        if self.command == "GET" and view:
            for tag in app.tags:
                if str(tag.get("id")) == view.group("identifier"):
                    self._reply(200, {"Tag": tag})
                    return True
            self._reply(404, {"message": "Invalid tag."})
            return True
        if self.command == "POST" and self.path == "/tags/add":
            tag = self._read_body()["Tag"]
            tag.setdefault("id", str(len(app.tags) + 1))
            app.tags.append(tag)
            self._reply(200, {"Tag": tag})
            return True
        edit = _TAG_EDIT.match(self.path)
        if self.command == "POST" and edit:
            for tag in app.tags:
                if str(tag.get("id")) == edit.group("identifier"):
                    tag.update(self._read_body()["Tag"])
                    self._reply(200, {"Tag": tag})
                    return True
            self._reply(404, {"message": "Invalid tag."})
            return True
        delete = _TAG_DELETE.match(self.path)
        if self.command == "POST" and delete:
            before = len(app.tags)
            app.tags = [tag for tag in app.tags if str(tag.get("id")) != delete.group("identifier")]
            if len(app.tags) == before:
                self._reply(404, {"message": "Invalid tag."})
            else:
                self._reply(200, {"message": "Tag deleted."})
            return True
        search = _TAG_SEARCH.match(self.path)
        if self.command == "GET" and search:
            term = unquote(search.group("term"))
            matches = [{"Tag": tag} for tag in app.tags if term in str(tag.get("name", ""))]
            self._reply(200, matches)
            return True
        return False

    def _handle_sighting_routes(self, app: FakeMisp) -> bool:
        index = _SIGHTING_INDEX.match(self.path)
        if self.command == "GET" and index:
            # MISP matches the numeric event id only; a UUID yields an empty
            # array rather than an error.
            wanted = index.group("identifier")
            matches = [
                {"Sighting": item}
                for item in app.sightings
                if wanted.isdigit() and item.get("event_id") == wanted
            ]
            self._reply(200, matches)
            return True
        if self.command == "POST" and self.path == "/sightings/add":
            body = self._read_body()
            created = []
            for candidate in app.attributes:
                if candidate.get("value") in set(body.get("values", [])):
                    sighting = {
                        "id": str(len(app.sightings) + 1),
                        "uuid": f"00000000-0000-4000-8000-{len(app.sightings) + 1:012d}",
                        "attribute_uuid": candidate.get("uuid"),
                        "event_id": candidate.get("event_id"),
                        "type": body.get("type", "0"),
                    }
                    app.sightings.append(sighting)
                    created.append(sighting)
            # Verified against MISP 2.5.44: the response is the created
            # Sighting under a "Sighting" envelope — openapi.yaml declares it
            # unwrapped, and the server disagrees — or a message with no
            # leading count when nothing matched.
            if created:
                self._reply(200, {"Sighting": created[0] if len(created) == 1 else created})
            else:
                self._reply(
                    200,
                    {
                        "message": (
                            "Could not add the Sighting. Reason: No valid "
                            "attributes found that match the criteria."
                        )
                    },
                )
            return True
        add_attr = _SIGHTING_ADD_ATTRIBUTE.match(self.path)
        if self.command == "POST" and add_attr:
            item = app.find_attribute(add_attr.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid attribute."})
                return True
            sighting = {
                "id": str(len(app.sightings) + 1),
                "attribute_uuid": item.get("uuid"),
                "event_id": item.get("event_id"),
                "type": "0",
            }
            app.sightings.append(sighting)
            self._reply(200, {"Sighting": sighting})
            return True
        delete = _SIGHTING_DELETE.match(self.path)
        if self.command == "POST" and delete:
            before = len(app.sightings)
            app.sightings = [
                item for item in app.sightings if str(item.get("id")) != delete.group("identifier")
            ]
            if len(app.sightings) == before:
                self._reply(404, {"message": "Invalid sighting."})
            else:
                self._reply(200, {"message": "Sighting deleted."})
            return True
        return False

    def _handle_object_routes(self, app: FakeMisp) -> bool:
        if self.command == "POST" and self.path == "/objects/restsearch":
            body = self._read_body()
            matches = app.objects
            name = body.get("object_name")
            if name is not None:
                matches = [item for item in matches if item.get("name") == name]
            self._reply(200, {"response": [{"Object": item} for item in matches]})
            return True
        view = _OBJECT_VIEW.match(self.path)
        if self.command == "GET" and view:
            for item in app.objects:
                if view.group("identifier") in (item.get("uuid"), str(item.get("id"))):
                    self._reply(200, {"Object": item})
                    return True
            self._reply(404, {"message": "Invalid object."})
            return True
        add = _OBJECT_ADD.match(self.path)
        if self.command == "POST" and add:
            if app.find_event(add.group("event")) is None:
                self._reply(404, {"message": "Invalid event."})
                return True
            item = self._read_body()
            item.setdefault("id", str(len(app.objects) + 1))
            item["template_uuid"] = unquote(add.group("template"))
            app.objects.append(item)
            self._reply(200, {"Object": item})
            return True
        delete = _OBJECT_DELETE.match(self.path)
        if self.command == "DELETE" and delete:
            before = len(app.objects)
            app.objects = [
                item
                for item in app.objects
                if delete.group("identifier") not in (item.get("uuid"), str(item.get("id")))
            ]
            if len(app.objects) == before:
                self._reply(404, {"message": "Invalid object."})
            else:
                self._reply(200, {"message": "Object deleted."})
            return True
        return False

    @staticmethod
    def _find_by_id(items: list[dict[str, Any]], identifier: str) -> dict[str, Any] | None:
        for item in items:
            if str(item.get("id")) == identifier:
                return item
        return None

    def _handle_library_routes(self, app: FakeMisp) -> bool:
        if self.command == "GET" and self.path == "/taxonomies":
            self._reply(200, [{"Taxonomy": item} for item in app.taxonomies])
            return True
        if self.command == "POST" and self.path == "/taxonomies/update":
            self._reply(200, {"message": "Taxonomies updated."})
            return True
        view = _TAXONOMY_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(app.taxonomies, view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid taxonomy."})
            else:
                self._reply(200, {"Taxonomy": item})
            return True
        toggle = _TAXONOMY_TOGGLE.match(self.path)
        if self.command == "POST" and toggle:
            item = self._find_by_id(app.taxonomies, toggle.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid taxonomy."})
            else:
                item["enabled"] = toggle.group("action") == "enable"
                self._reply(200, {"message": f"Taxonomy {toggle.group('action')}d."})
            return True
        taxonomy_tags = _TAXONOMY_TAGS.match(self.path)
        if self.command == "GET" and taxonomy_tags:
            item = self._find_by_id(app.taxonomies, taxonomy_tags.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid taxonomy."})
            else:
                self._reply(200, {"Taxonomy": item, "entries": item.get("tags", [])})
            return True
        export = _TAXONOMY_EXPORT.match(self.path)
        if self.command == "GET" and export:
            item = self._find_by_id(app.taxonomies, export.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid taxonomy."})
            else:
                self._reply(200, {"namespace": item.get("namespace")})
            return True
        if self.path == "/warninglists" and self.command in ("GET", "POST"):
            matches = app.warninglists
            if self.command == "POST":
                value = self._read_body().get("value", "")
                matches = [item for item in matches if value in item.get("entries", [])]
            self._reply(200, {"Warninglists": [{"Warninglist": item} for item in matches]})
            return True
        wl_view = _WARNINGLIST_VIEW.match(self.path)
        if self.command == "GET" and wl_view:
            item = self._find_by_id(app.warninglists, wl_view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid warninglist."})
            else:
                self._reply(200, {"Warninglist": item})
            return True
        if self.command == "POST" and self.path == "/warninglists/toggleEnable":
            body = self._read_body()
            wanted = {str(identifier) for identifier in body.get("id", [])}
            changed = 0
            for item in app.warninglists:
                if str(item.get("id")) in wanted:
                    item["enabled"] = bool(body.get("enabled"))
                    changed += 1
            self._reply(200, {"success": f"{changed} warninglist(s) toggled"})
            return True
        if self.command == "POST" and self.path == "/warninglists/checkValue":
            values = self._read_list_body()
            result: dict[str, Any] = {}
            for value in values:
                hits = [
                    {"id": item.get("id"), "name": item.get("name")}
                    for item in app.warninglists
                    if item.get("enabled") and value in item.get("entries", [])
                ]
                if hits:
                    result[value] = hits
            # MISP is PHP: an empty associative array serializes as [], not {}.
            self._reply(200, result or [])
            return True
        if self.command == "POST" and self.path == "/warninglists/update":
            self._reply(200, {"message": "Warninglists updated."})
            return True
        if self.command == "GET" and self.path == "/noticelists":
            self._reply(200, [{"Noticelist": item} for item in app.noticelists])
            return True
        if self.command == "POST" and self.path == "/noticelists/update":
            self._reply(200, {"message": "Noticelists updated."})
            return True
        nl_view = _NOTICELIST_VIEW.match(self.path)
        if self.command == "GET" and nl_view:
            item = self._find_by_id(app.noticelists, nl_view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid noticelist."})
            else:
                self._reply(200, {"Noticelist": item})
            return True
        nl_toggle = _NOTICELIST_TOGGLE.match(self.path)
        if self.command == "POST" and nl_toggle:
            item = self._find_by_id(app.noticelists, nl_toggle.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid noticelist."})
            else:
                item["enabled"] = not item.get("enabled", False)
                self._reply(200, {"Noticelist": item})
            return True
        return False

    def _handle_galaxy_routes(self, app: FakeMisp) -> bool:
        if self.path == "/galaxies" and self.command in ("GET", "POST"):
            matches = app.galaxies
            if self.command == "POST":
                value = self._read_body().get("value", "")
                matches = [item for item in matches if value in str(item.get("name", ""))]
            self._reply(200, [{"Galaxy": item} for item in matches])
            return True
        if self.command == "POST" and self.path == "/galaxies/update":
            self._reply(200, {"message": "Galaxies updated."})
            return True
        if self.command == "POST" and self.path == "/galaxies/import":
            clusters = self._read_list_body()
            app.clusters.extend(clusters)
            self._reply(200, {"message": f"{len(clusters)} cluster(s) imported."})
            return True
        view = _GALAXY_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(app.galaxies, view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid galaxy."})
            else:
                self._reply(200, {"Galaxy": item})
            return True
        delete = _GALAXY_DELETE.match(self.path)
        if self.command == "DELETE" and delete:
            item = self._find_by_id(app.galaxies, delete.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid galaxy."})
            else:
                app.galaxies.remove(item)
                self._reply(200, {"message": "Galaxy deleted."})
            return True
        export = _GALAXY_EXPORT.match(self.path)
        if self.command == "POST" and export:
            item = self._find_by_id(app.galaxies, export.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid galaxy."})
            else:
                wanted = str(item.get("id"))
                # Neither flag set means "no clusters", exactly as MISP documents.
                flags = self._read_body().get("Galaxy", {})
                selected = [c for c in app.clusters if str(c.get("galaxy_id")) == wanted]
                # Neither flag set, or no distribution filter, means "nothing".
                if (not flags.get("default") and not flags.get("custom")) or not flags.get(
                    "distribution"
                ):
                    selected = []
                self._reply(200, selected)
            return True
        attach = _GALAXY_ATTACH.match(self.path)
        if self.command == "POST" and attach:
            target = app.find_event(attach.group("target"))
            if target is None:
                self._reply(404, {"message": "Invalid target."})
                return True
            cluster_id = self._read_body()["Galaxy"]["target_id"]
            cluster = self._find_by_id(app.clusters, str(cluster_id))
            if cluster is None:
                self._reply(404, {"message": "Invalid cluster."})
                return True
            target.setdefault("Galaxy", []).append(cluster)
            self._reply(200, {"saved": True})
            return True
        return self._handle_cluster_routes(app)

    def _handle_cluster_routes(self, app: FakeMisp) -> bool:
        index = _CLUSTER_INDEX.match(self.path)
        if index and self.command in ("GET", "POST"):
            wanted = index.group("identifier")
            matches = [c for c in app.clusters if str(c.get("galaxy_id")) == wanted]
            if self.command == "POST":
                term = self._read_body().get("searchall", "")
                matches = [c for c in matches if term in str(c.get("value", ""))]
            self._reply(200, [{"GalaxyCluster": item} for item in matches])
            return True
        view = _CLUSTER_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(app.clusters, view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid cluster."})
            else:
                self._reply(200, {"GalaxyCluster": item})
            return True
        add = _CLUSTER_ADD.match(self.path)
        if self.command == "POST" and add:
            if self._find_by_id(app.galaxies, add.group("identifier")) is None:
                self._reply(404, {"message": "Invalid galaxy."})
                return True
            item = self._read_body()["GalaxyCluster"]
            item.setdefault("id", str(len(app.clusters) + 1))
            item["galaxy_id"] = add.group("identifier")
            app.clusters.append(item)
            self._reply(200, {"GalaxyCluster": item})
            return True
        edit = _CLUSTER_EDIT.match(self.path)
        if self.command == "PUT" and edit:
            item = self._find_by_id(app.clusters, edit.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid cluster."})
            else:
                item.update(self._read_body()["GalaxyCluster"])
                self._reply(200, {"GalaxyCluster": item})
            return True
        action = _CLUSTER_ACTION.match(self.path)
        if self.command == "POST" and action:
            item = self._find_by_id(app.clusters, action.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid cluster."})
                return True
            verb = action.group("action")
            if verb in ("publish", "unpublish"):
                item["published"] = verb == "publish"
            else:
                item["deleted"] = verb == "delete"
            self._reply(200, {"saved": True})
            return True
        return False

    def _handle_server_routes(self, app: FakeMisp) -> bool:
        if self.command == "GET" and self.path == "/servers":
            self._reply(200, [{"Server": item} for item in app.misp_servers])
            return True
        if self.command == "POST" and self.path == "/servers/add":
            server = self._read_body()["Server"]
            server.setdefault("id", str(len(app.misp_servers) + 1))
            app.misp_servers.append(server)
            self._reply(200, {"Server": server})
            return True
        if self.command == "POST" and self.path == "/servers/import":
            server = self._read_body().get("Server", {})
            server.setdefault("id", str(len(app.misp_servers) + 1))
            app.misp_servers.append(server)
            self._reply(200, {"Server": server})
            return True
        if self.command == "POST" and self.path == "/servers/createSync":
            self._reply(200, {"Server": {"url": app.url, "uuid": app.instance_uuid}})
            return True
        if self.command == "GET" and self.path == "/servers/getPyMISPVersion":
            self._reply(200, {"version": "2.4.190"})
            return True
        if self.command == "GET" and self.path == "/servers/serverSettings":
            self._reply(
                200,
                {"finalSettings": [{"setting": k, "value": v} for k, v in app.settings.items()]},
            )
            return True
        if self.command == "GET" and self.path == "/servers/getWorkers":
            self._reply(200, app.workers)
            return True
        if self.command == "GET" and self.path == "/servers/getInstanceUUID":
            self._reply(200, {"uuid": app.instance_uuid})
            return True
        if self.command == "POST" and self.path in _SERVER_SIMPLE_POSTS:
            self._reply(200, {"message": _SERVER_SIMPLE_POSTS[self.path]})
            return True
        edit = _SERVER_EDIT.match(self.path)
        if self.command == "PUT" and edit:
            item = self._find_by_id(app.misp_servers, edit.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid server."})
            else:
                item.update(self._read_body()["Server"])
                self._reply(200, {"Server": item})
            return True
        delete = _SERVER_DELETE.match(self.path)
        if self.command == "POST" and delete:
            item = self._find_by_id(app.misp_servers, delete.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid server."})
            else:
                app.misp_servers.remove(item)
                self._reply(200, {"message": "Server deleted."})
            return True
        pull_push = _SERVER_PULL_PUSH.match(self.path)
        if self.command == "GET" and pull_push:
            item = self._find_by_id(app.misp_servers, pull_push.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid server."})
            else:
                action = pull_push.group("action")
                self._reply(200, {"message": f"{action} queued ({pull_push.group('technique')})"})
            return True
        start = _SERVER_START_WORKER.match(self.path)
        if self.command == "POST" and start:
            pid = str(1000 + len(app.workers))
            app.workers[pid] = {"type": start.group("worker"), "alive": True}
            self._reply(200, {"message": f"Worker {pid} started."})
            return True
        stop = _SERVER_STOP_WORKER.match(self.path)
        if self.command == "POST" and stop:
            worker = app.workers.pop(stop.group("pid"), None)
            if worker is None:
                self._reply(404, {"message": "Invalid worker."})
            else:
                self._reply(200, {"message": "Worker stopped."})
            return True
        get_setting = _SERVER_GET_SETTING.match(self.path)
        if self.command == "GET" and get_setting:
            name = unquote(get_setting.group("name"))
            if name not in app.settings:
                self._reply(404, {"message": "Invalid setting."})
            else:
                self._reply(200, {"setting": name, "value": app.settings[name]})
            return True
        edit_setting = _SERVER_EDIT_SETTING.match(self.path)
        if self.command == "POST" and edit_setting:
            name = unquote(edit_setting.group("name"))
            app.settings[name] = self._read_body().get("value")
            self._reply(200, {"message": "Setting saved.", "setting": name})
            return True
        return False

    def _handle_admin_routes(self, app: FakeMisp) -> bool:
        return (
            self._handle_organisation_routes(app)
            or self._handle_user_routes(app)
            or self._handle_authkey_routes(app)
            or self._handle_usersetting_routes(app)
        )

    def _handle_organisation_routes(self, app: FakeMisp) -> bool:
        if self.command == "GET" and self.path == "/organisations":
            self._reply(200, [{"Organisation": item} for item in app.organisations])
            return True
        if self.command == "POST" and self.path == "/admin/organisations/add":
            item = self._read_body()["Organisation"]
            item.setdefault("id", str(len(app.organisations) + 1))
            app.organisations.append(item)
            self._reply(200, {"Organisation": item})
            return True
        view = _ORG_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(app.organisations, view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid organisation."})
            else:
                self._reply(200, {"Organisation": item})
            return True
        edit = _ORG_EDIT.match(self.path)
        if self.command == "PUT" and edit:
            item = self._find_by_id(app.organisations, edit.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid organisation."})
            else:
                item.update(self._read_body()["Organisation"])
                self._reply(200, {"Organisation": item})
            return True
        delete = _ORG_DELETE.match(self.path)
        if self.command == "DELETE" and delete:
            item = self._find_by_id(app.organisations, delete.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid organisation."})
            else:
                app.organisations.remove(item)
                self._reply(200, {"message": "Organisation deleted."})
            return True
        return False

    def _handle_user_routes(self, app: FakeMisp) -> bool:
        if self.command == "GET" and self.path == "/admin/users":
            self._reply(200, [{"User": item} for item in app.users])
            return True
        if self.command == "POST" and self.path == "/admin/users/add":
            item = self._read_body()["User"]
            item.setdefault("id", str(len(app.users) + 1))
            app.users.append(item)
            self._reply(200, {"User": item})
            return True
        view = _USER_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(app.users, view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid user."})
            else:
                self._reply(200, {"User": item})
            return True
        edit = _USER_EDIT.match(self.path)
        if self.command == "PUT" and edit:
            item = self._find_by_id(app.users, edit.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid user."})
            else:
                item.update(self._read_body()["User"])
                self._reply(200, {"User": item})
            return True
        delete = _USER_DELETE.match(self.path)
        if self.command == "DELETE" and delete:
            item = self._find_by_id(app.users, delete.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid user."})
            else:
                app.users.remove(item)
                self._reply(200, {"message": "User deleted."})
            return True
        reset = _USER_RESET.match(self.path)
        if self.command == "POST" and reset:
            item = self._find_by_id(app.users, reset.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid user."})
            else:
                item["password_reset"] = "first" if reset.group("first") == "1" else "normal"
                self._reply(200, {"message": "Password reset initiated."})
            return True
        totp = _USER_TOTP.match(self.path)
        if self.command == "DELETE" and totp:
            item = self._find_by_id(app.users, totp.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid user."})
            else:
                item["totp"] = None
                self._reply(200, {"message": "TOTP deleted."})
            return True
        return False

    def _handle_authkey_routes(self, app: FakeMisp) -> bool:
        if self.path == "/auth_keys" and self.command in ("GET", "POST"):
            matches = app.auth_keys
            if self.command == "POST":
                # The documented search fields; `value` is not one of them.
                body = self._read_body()
                comment = str(body.get("comment", ""))
                matches = [item for item in matches if comment in str(item.get("comment", ""))]
            self._reply(200, [{"AuthKey": item} for item in matches])
            return True
        add = _AUTHKEY_ADD.match(self.path)
        if self.command == "POST" and add:
            if self._find_by_id(app.users, add.group("identifier")) is None:
                self._reply(404, {"message": "Invalid user."})
                return True
            item = self._read_body().get("AuthKey", {})
            item.setdefault("id", str(len(app.auth_keys) + 1))
            item["user_id"] = add.group("identifier")
            item["authkey_raw"] = f"raw-key-{item['id']}"
            app.auth_keys.append(item)
            self._reply(200, {"AuthKey": item})
            return True
        view = _AUTHKEY_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(app.auth_keys, view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid auth key."})
            else:
                self._reply(200, {"AuthKey": {k: v for k, v in item.items() if k != "authkey_raw"}})
            return True
        edit = _AUTHKEY_EDIT.match(self.path)
        if self.command == "POST" and edit:
            item = self._find_by_id(app.auth_keys, edit.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid auth key."})
            else:
                item.update(self._read_body()["AuthKey"])
                self._reply(200, {"AuthKey": item})
            return True
        delete = _AUTHKEY_DELETE.match(self.path)
        if self.command == "DELETE" and delete:
            item = self._find_by_id(app.auth_keys, delete.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid auth key."})
            else:
                app.auth_keys.remove(item)
                self._reply(200, {"message": "Auth key deleted."})
            return True
        return False

    def _handle_usersetting_routes(self, app: FakeMisp) -> bool:
        if self.path == "/user_settings" and self.command in ("GET", "POST"):
            matches = app.user_settings
            if self.command == "POST":
                setting = self._read_body().get("setting", "")
                matches = [item for item in matches if item.get("setting") == setting]
            self._reply(200, [{"UserSetting": item} for item in matches])
            return True
        view = _USERSETTING_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(app.user_settings, view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid user setting."})
            else:
                self._reply(200, {"UserSetting": item})
            return True
        get_setting = _USERSETTING_GET.match(self.path)
        if self.command == "GET" and get_setting:
            for item in app.user_settings:
                if item.get("user_id") == get_setting.group("user") and item.get(
                    "setting"
                ) == unquote(get_setting.group("name")):
                    self._reply(200, {"UserSetting": item})
                    return True
            self._reply(404, {"message": "Invalid user setting."})
            return True
        set_setting = _USERSETTING_SET.match(self.path)
        if self.command == "POST" and set_setting:
            name = unquote(set_setting.group("name"))
            user = set_setting.group("user")
            # The request body is the setting object itself: SetUserSettingRequest
            # is an anyOf over the setting schemas, with no "value" wrapper. The
            # stored UserSetting record does carry the content under "value".
            value = self._read_body()
            for item in app.user_settings:
                if item.get("user_id") == user and item.get("setting") == name:
                    item["value"] = value
                    self._reply(200, {"UserSetting": item})
                    return True
            item = {
                "id": str(len(app.user_settings) + 1),
                "user_id": user,
                "setting": name,
                "value": value,
            }
            app.user_settings.append(item)
            self._reply(200, {"UserSetting": item})
            return True
        delete = _USERSETTING_DELETE.match(self.path)
        if self.command == "DELETE" and delete:
            item = self._find_by_id(app.user_settings, delete.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid user setting."})
            else:
                app.user_settings.remove(item)
                self._reply(200, {"message": "User setting deleted."})
            return True
        return False

    def _handle_feed_routes(self, app: FakeMisp) -> bool:
        if self.command == "GET" and self.path == "/feeds":
            self._reply(200, [{"Feed": item} for item in app.feeds])
            return True
        if self.command == "POST" and self.path == "/feeds/add":
            item = self._read_body()["Feed"]
            item.setdefault("id", str(len(app.feeds) + 1))
            app.feeds.append(item)
            self._reply(200, {"Feed": item})
            return True
        if self.command == "POST" and self.path == "/feeds/fetchFromAllFeeds":
            self._reply(200, {"message": "Fetching all feeds."})
            return True
        view = _FEED_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(app.feeds, view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid feed."})
            else:
                self._reply(200, {"Feed": item})
            return True
        edit = _FEED_EDIT.match(self.path)
        if self.command == "PUT" and edit:
            item = self._find_by_id(app.feeds, edit.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid feed."})
            else:
                item.update(self._read_body()["Feed"])
                self._reply(200, {"Feed": item})
            return True
        toggle = _FEED_TOGGLE.match(self.path)
        if self.command == "POST" and toggle:
            item = self._find_by_id(app.feeds, toggle.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid feed."})
            else:
                item["enabled"] = toggle.group("action") == "enable"
                self._reply(200, {"message": f"Feed {toggle.group('action')}d."})
            return True
        cache = _FEED_CACHE.match(self.path)
        if self.command == "POST" and cache:
            self._reply(200, {"message": f"Caching feeds ({cache.group('scope')})."})
            return True
        fetch = _FEED_FETCH.match(self.path)
        if self.command == "POST" and fetch:
            item = self._find_by_id(app.feeds, fetch.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid feed."})
            else:
                self._reply(200, {"message": "Fetching feed."})
            return True
        return False

    def _handle_sharing_routes(self, app: FakeMisp) -> bool:
        if self.command == "GET" and self.path == "/sharing_groups":
            self._reply(200, {"response": [{"SharingGroup": item} for item in app.sharing_groups]})
            return True
        if self.command == "POST" and self.path == "/sharing_groups/add":
            item = self._read_body()["SharingGroup"]
            item.setdefault("id", str(len(app.sharing_groups) + 1))
            item.setdefault("orgs", [])
            item.setdefault("servers", [])
            app.sharing_groups.append(item)
            self._reply(200, {"SharingGroup": item})
            return True
        view = _SG_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(app.sharing_groups, view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid sharing group."})
            else:
                self._reply(200, {"SharingGroup": item})
            return True
        edit = _SG_EDIT.match(self.path)
        if self.command == "POST" and edit:
            item = self._find_by_id(app.sharing_groups, edit.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid sharing group."})
            else:
                item.update(self._read_body()["SharingGroup"])
                self._reply(200, {"SharingGroup": item})
            return True
        delete = _SG_DELETE.match(self.path)
        if self.command == "DELETE" and delete:
            item = self._find_by_id(app.sharing_groups, delete.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid sharing group."})
            else:
                app.sharing_groups.remove(item)
                self._reply(200, {"message": "Sharing group deleted."})
            return True
        member = _SG_MEMBER.match(self.path)
        if self.command == "POST" and member:
            item = self._find_by_id(app.sharing_groups, member.group("group"))
            if item is None:
                self._reply(404, {"message": "Invalid sharing group."})
                return True
            key = "orgs" if "Org" in member.group("action") else "servers"
            if member.group("action").startswith("add"):
                item[key].append(member.group("member"))
            else:
                item[key] = [entry for entry in item[key] if entry != member.group("member")]
            self._reply(200, {"saved": True})
            return True
        return self._handle_blueprint_routes(app)

    def _handle_blueprint_routes(self, app: FakeMisp) -> bool:
        if self.command == "GET" and self.path == "/sharing_group_blueprints/index":
            self._reply(200, [{"SharingGroupBlueprint": item} for item in app.blueprints])
            return True
        if self.command == "POST" and self.path == "/sharing_group_blueprints/add":
            item = self._read_body()["SharingGroupBlueprint"]
            item.setdefault("id", str(len(app.blueprints) + 1))
            app.blueprints.append(item)
            self._reply(200, {"SharingGroupBlueprint": item})
            return True
        view = _SGB_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(app.blueprints, view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid blueprint."})
            else:
                self._reply(200, {"SharingGroupBlueprint": item})
            return True
        orgs = _SGB_ORGS.match(self.path)
        if self.command == "GET" and orgs:
            item = self._find_by_id(app.blueprints, orgs.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid blueprint."})
            else:
                self._reply(200, [{"Organisation": org} for org in app.organisations])
            return True
        edit = _SGB_EDIT.match(self.path)
        if self.command == "POST" and edit:
            item = self._find_by_id(app.blueprints, edit.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid blueprint."})
            else:
                item.update(self._read_body()["SharingGroupBlueprint"])
                self._reply(200, {"SharingGroupBlueprint": item})
            return True
        action = _SGB_ACTION.match(self.path)
        if self.command == "POST" and action:
            item = self._find_by_id(app.blueprints, action.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid blueprint."})
                return True
            if action.group("action") == "execute":
                group = {"id": str(len(app.sharing_groups) + 1), "name": item.get("name")}
                group.setdefault("orgs", [])
                group.setdefault("servers", [])
                app.sharing_groups.append(group)
                item["sharing_group_id"] = group["id"]
            else:
                item["sharing_group_id"] = None
            self._reply(200, {"SharingGroupBlueprint": item})
            return True
        delete = _SGB_DELETE.match(self.path)
        if self.command == "DELETE" and delete:
            item = self._find_by_id(app.blueprints, delete.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid blueprint."})
            else:
                app.blueprints.remove(item)
                self._reply(200, {"message": "Blueprint deleted."})
            return True
        return False

    def _handle_report_routes(self, app: FakeMisp) -> bool:
        if self.command == "GET" and self.path == "/eventReports/index":
            self._reply(200, [{"EventReport": item} for item in app.reports])
            return True
        view = _REPORT_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(app.reports, view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid report."})
            else:
                self._reply(200, {"EventReport": item})
            return True
        add = _REPORT_ADD.match(self.path)
        if self.command == "POST" and add:
            if app.find_event(add.group("identifier")) is None:
                self._reply(404, {"message": "Invalid event."})
                return True
            item = self._read_body()["EventReport"]
            item.setdefault("id", str(len(app.reports) + 1))
            item["event_id"] = add.group("identifier")
            app.reports.append(item)
            self._reply(200, {"EventReport": item})
            return True
        import_url = _REPORT_IMPORT.match(self.path)
        if self.command == "POST" and import_url:
            if app.find_event(import_url.group("identifier")) is None:
                self._reply(404, {"message": "Invalid event."})
                return True
            item = {
                "id": str(len(app.reports) + 1),
                "event_id": import_url.group("identifier"),
                "name": self._read_body().get("url", ""),
            }
            app.reports.append(item)
            self._reply(200, {"EventReport": item})
            return True
        edit = _REPORT_EDIT.match(self.path)
        if self.command == "POST" and edit:
            item = self._find_by_id(app.reports, edit.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid report."})
            else:
                item.update(self._read_body()["EventReport"])
                self._reply(200, {"EventReport": item})
            return True
        restore = _REPORT_RESTORE.match(self.path)
        if self.command == "POST" and restore:
            item = self._find_by_id(app.reports, restore.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid report."})
            else:
                item["deleted"] = False
                self._reply(200, {"EventReport": item})
            return True
        delete = _REPORT_DELETE.match(self.path)
        if self.command == "POST" and delete:
            item = self._find_by_id(app.reports, delete.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid report."})
            elif delete.group("hard"):
                app.reports.remove(item)
                self._reply(200, {"message": "Report hard-deleted."})
            else:
                item["deleted"] = True
                self._reply(200, {"message": "Report deleted."})
            return True
        return False

    def _handle_analyst_and_collection_routes(self, app: FakeMisp) -> bool:
        if self.command == "POST" and self.path == "/analystData/indexMinimal":
            # MinimalAnalystDataResponse: an object keyed by analyst type,
            # each mapping uuid to timestamp, or an empty array when there is
            # nothing to report.
            minimal: dict[str, Any] = {}
            for kind, items in sorted(app.analyst_data.items()):
                entries = {
                    str(item.get("uuid")): str(item.get("modified", "2026-01-01 00:00:00"))
                    for item in items
                }
                if entries:
                    minimal[kind] = entries
            self._reply(200, minimal if minimal else [])
            return True
        index = _ANALYST_INDEX.match(self.path)
        if self.command == "GET" and index:
            kind = index.group("type")
            self._reply(200, [{kind: item} for item in app.analyst_data.get(kind, [])])
            return True
        view = _ANALYST_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(
                app.analyst_data.get(view.group("type"), []), view.group("identifier")
            )
            if item is None:
                self._reply(404, {"message": "Invalid analyst data."})
            else:
                self._reply(200, {view.group("type"): item})
            return True
        add = _ANALYST_ADD.match(self.path)
        if self.command == "POST" and add:
            kind = add.group("type")
            items = app.analyst_data.setdefault(kind, [])
            # Flat body: AddAnalystDataRequest is a oneOf over AnalystNote,
            # AnalystOpinion and AnalystRelationship, none of them wrapped.
            item = self._read_body()
            item.setdefault("id", str(len(items) + 1))
            item["object_uuid"] = add.group("uuid")
            item["object_type"] = add.group("object_type")
            items.append(item)
            self._reply(200, {kind: item})
            return True
        edit = _ANALYST_EDIT.match(self.path)
        if self.command == "POST" and edit:
            kind = edit.group("type")
            item = self._find_by_id(app.analyst_data.get(kind, []), edit.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid analyst data."})
            else:
                item.update(self._read_body())
                self._reply(200, {kind: item})
            return True
        delete = _ANALYST_DELETE.match(self.path)
        if self.command == "DELETE" and delete:
            kind = delete.group("type")
            item = self._find_by_id(app.analyst_data.get(kind, []), delete.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid analyst data."})
            else:
                app.analyst_data[kind].remove(item)
                self._reply(200, {"message": "Analyst data deleted."})
            return True
        if self.command == "POST" and self.path == "/admin/logs":
            filters = self._read_body()
            if not filters:
                # MISP 2.5.44 crashes on an empty request body for this route.
                self._reply(500, {"message": "An Internal Error Has Occurred."})
                return True
            matches = app.logs
            model = filters.get("model")
            if model is not None:
                matches = [item for item in matches if item.get("model") == model]
            self._reply(200, [{"Log": item} for item in matches])
            return True
        return self._handle_collection_routes(app)

    def _handle_collection_routes(self, app: FakeMisp) -> bool:
        index = _COLLECTION_INDEX.match(self.path)
        if self.command == "POST" and index:
            if not self._read_body():
                # MISP 2.5.44 crashes on an empty request body for this route.
                self._reply(500, {"message": "An Internal Error Has Occurred."})
                return True
            # The path filter is an enum: my_collections or org_collections.
            if index.group("filter") not in ("my_collections", "org_collections"):
                self._reply(404, {"message": "Invalid filter."})
                return True
            matches = app.collections
            if index.group("filter") == "my_collections":
                matches = [item for item in matches if item.get("mine")]
            self._reply(200, [{"Collection": item} for item in matches])
            return True
        if self.command == "POST" and self.path == "/collections/add":
            item = self._read_body()["Collection"]
            item.setdefault("id", str(len(app.collections) + 1))
            app.collections.append(item)
            self._reply(200, {"Collection": item})
            return True
        view = _COLLECTION_VIEW.match(self.path)
        if self.command == "GET" and view:
            item = self._find_by_id(app.collections, view.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid collection."})
            else:
                self._reply(200, {"Collection": item})
            return True
        edit = _COLLECTION_EDIT.match(self.path)
        if self.command == "POST" and edit:
            item = self._find_by_id(app.collections, edit.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid collection."})
            else:
                item.update(self._read_body()["Collection"])
                self._reply(200, {"Collection": item})
            return True
        delete = _COLLECTION_DELETE.match(self.path)
        if self.command == "DELETE" and delete:
            item = self._find_by_id(app.collections, delete.group("identifier"))
            if item is None:
                self._reply(404, {"message": "Invalid collection."})
            else:
                app.collections.remove(item)
                self._reply(200, {"message": "Collection deleted."})
            return True
        return False

    @staticmethod
    def _apply_tag(entity: dict[str, Any], action: str, name: str) -> None:
        tags = entity.setdefault("Tag", [])
        if action == "addTag":
            tags.append({"name": name})
        else:
            entity["Tag"] = [tag for tag in tags if tag.get("name") != name]

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()
