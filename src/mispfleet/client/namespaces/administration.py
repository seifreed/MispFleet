"""Administration namespaces: servers, organisations, users, feeds, sharing groups."""

from __future__ import annotations

import builtins
from typing import Any
from urllib.parse import quote

from mispfleet.client.namespaces._base import _as_dict, _as_list, _Namespace, _unwrap


class ServersNamespace(_Namespace):
    """Remote-server management, worker and instance-setting endpoints."""

    async def list(self) -> builtins.list[dict[str, Any]]:
        """Return the configured sync servers."""
        data = await self._transport.request("GET", "/servers")
        return _as_list(data)

    async def add(self, server: dict[str, Any]) -> dict[str, Any]:
        """Register a new sync server."""
        data = await self._transport.request(
            "POST", "/servers/add", json_body={"Server": server}, idempotent=False
        )
        return _unwrap(data, "Server")

    async def update(self, server_id: str, server: dict[str, Any]) -> dict[str, Any]:
        """Update a sync server."""
        data = await self._transport.request(
            "PUT",
            f"/servers/edit/{quote(server_id, safe='')}",
            json_body={"Server": server},
            idempotent=False,
        )
        return _unwrap(data, "Server")

    async def delete(self, server_id: str) -> dict[str, Any]:
        """Delete a sync server."""
        data = await self._transport.request(
            "POST", f"/servers/delete/{quote(server_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def pull(self, server_id: str, technique: str = "full") -> dict[str, Any]:
        """Trigger a pull from a sync server."""
        path = f"/servers/pull/{quote(server_id, safe='')}/{quote(technique, safe='')}"
        data = await self._transport.request("GET", path, idempotent=False)
        return _as_dict(data)

    async def push(self, server_id: str, technique: str = "full") -> dict[str, Any]:
        """Trigger a push to a sync server."""
        path = f"/servers/push/{quote(server_id, safe='')}/{quote(technique, safe='')}"
        data = await self._transport.request("GET", path, idempotent=False)
        return _as_dict(data)

    async def pymisp_version(self) -> dict[str, Any]:
        """Return the PyMISP version the server recommends."""
        data = await self._transport.request("GET", "/servers/getPyMISPVersion")
        return _as_dict(data)

    async def settings(self) -> dict[str, Any]:
        """Return the full server-settings report."""
        data = await self._transport.request("GET", "/servers/serverSettings")
        return _as_dict(data)

    async def get_setting(self, name: str) -> dict[str, Any]:
        """Return one server setting."""
        data = await self._transport.request("GET", f"/servers/getSetting/{quote(name, safe='')}")
        return _as_dict(data)

    async def set_setting(self, name: str, value: Any) -> dict[str, Any]:
        """Change one server setting."""
        data = await self._transport.request(
            "POST",
            f"/servers/serverSettingsEdit/{quote(name, safe='')}",
            json_body={"value": value},
            idempotent=False,
        )
        return _as_dict(data)

    async def workers(self) -> dict[str, Any]:
        """Return the background-worker overview."""
        data = await self._transport.request("GET", "/servers/getWorkers")
        return _as_dict(data)

    async def start_worker(self, worker_type: str) -> dict[str, Any]:
        """Start a background worker of the given type."""
        data = await self._transport.request(
            "POST", f"/servers/startWorker/{quote(worker_type, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def stop_worker(self, worker_pid: str) -> dict[str, Any]:
        """Stop the background worker with the given pid."""
        data = await self._transport.request(
            "POST", f"/servers/stopWorker/{quote(worker_pid, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def kill_all_workers(self) -> dict[str, Any]:
        """Kill every background worker."""
        data = await self._transport.request("POST", "/servers/killAllWorkers", idempotent=False)
        return _as_dict(data)

    async def restart_workers(self) -> dict[str, Any]:
        """Restart every background worker."""
        data = await self._transport.request("POST", "/servers/restartWorkers", idempotent=False)
        return _as_dict(data)

    async def restart_dead_workers(self) -> dict[str, Any]:
        """Restart only the dead background workers."""
        data = await self._transport.request(
            "POST", "/servers/restartDeadWorkers", idempotent=False
        )
        return _as_dict(data)

    async def update_misp(self) -> dict[str, Any]:
        """Update the MISP installation itself."""
        data = await self._transport.request("POST", "/servers/update", idempotent=False)
        return _as_dict(data)

    async def update_json(self) -> dict[str, Any]:
        """Update the submodule JSON definitions."""
        data = await self._transport.request("POST", "/servers/updateJSON", idempotent=False)
        return _as_dict(data)

    async def cache(self) -> dict[str, Any]:
        """Cache the configured sync-server feeds."""
        data = await self._transport.request("POST", "/servers/cache", idempotent=False)
        return _as_dict(data)

    async def create_sync(self) -> dict[str, Any]:
        """Return this instance's sync-server configuration for a peer."""
        data = await self._transport.request("POST", "/servers/createSync", idempotent=False)
        return _as_dict(data)

    async def instance_uuid(self) -> dict[str, Any]:
        """Return this instance's UUID."""
        data = await self._transport.request("GET", "/servers/getInstanceUUID")
        return _as_dict(data)

    async def import_server(self, config: dict[str, Any]) -> dict[str, Any]:
        """Import a sync-server definition produced by ``create_sync``."""
        data = await self._transport.request(
            "POST", "/servers/import", json_body=config, idempotent=False
        )
        return _unwrap(data, "Server")


class OrganisationsNamespace(_Namespace):
    """Organisation listing and admin CRUD endpoints."""

    async def list(self) -> builtins.list[dict[str, Any]]:
        """Return the organisation index."""
        data = await self._transport.request("GET", "/organisations")
        return _as_list(data)

    async def get(self, organisation_id: str) -> dict[str, Any]:
        """Fetch one organisation by id or UUID."""
        data = await self._transport.request(
            "GET", f"/organisations/view/{quote(organisation_id, safe='')}"
        )
        return _unwrap(data, "Organisation")

    async def add(self, organisation: dict[str, Any]) -> dict[str, Any]:
        """Create an organisation (admin only)."""
        data = await self._transport.request(
            "POST",
            "/admin/organisations/add",
            json_body={"Organisation": organisation},
            idempotent=False,
        )
        return _unwrap(data, "Organisation")

    async def update(self, organisation_id: str, organisation: dict[str, Any]) -> dict[str, Any]:
        """Update an organisation (admin only)."""
        data = await self._transport.request(
            "PUT",
            f"/admin/organisations/edit/{quote(organisation_id, safe='')}",
            json_body={"Organisation": organisation},
            idempotent=False,
        )
        return _unwrap(data, "Organisation")

    async def delete(self, organisation_id: str) -> dict[str, Any]:
        """Delete an organisation (admin only)."""
        data = await self._transport.request(
            "DELETE",
            f"/admin/organisations/delete/{quote(organisation_id, safe='')}",
            idempotent=False,
        )
        return _as_dict(data)


class UsersNamespace(_Namespace):
    """User admin CRUD and account-maintenance endpoints."""

    async def list(self) -> builtins.list[dict[str, Any]]:
        """Return the user index (admin only)."""
        data = await self._transport.request("GET", "/admin/users")
        return _as_list(data)

    async def get(self, user_id: str) -> dict[str, Any]:
        """Fetch one user (admin only)."""
        data = await self._transport.request("GET", f"/admin/users/view/{quote(user_id, safe='')}")
        return _unwrap(data, "User")

    async def add(self, user: dict[str, Any]) -> dict[str, Any]:
        """Create a user (admin only)."""
        data = await self._transport.request(
            "POST", "/admin/users/add", json_body={"User": user}, idempotent=False
        )
        return _unwrap(data, "User")

    async def update(self, user_id: str, user: dict[str, Any]) -> dict[str, Any]:
        """Update a user (admin only)."""
        data = await self._transport.request(
            "PUT",
            f"/admin/users/edit/{quote(user_id, safe='')}",
            json_body={"User": user},
            idempotent=False,
        )
        return _unwrap(data, "User")

    async def delete(self, user_id: str) -> dict[str, Any]:
        """Delete a user (admin only)."""
        data = await self._transport.request(
            "DELETE", f"/admin/users/delete/{quote(user_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def initiate_password_reset(
        self, user_id: str, first_time: bool = False
    ) -> dict[str, Any]:
        """Send a password-reset message to a user."""
        path = (
            f"/users/initiatePasswordReset/{quote(user_id, safe='')}"
            f"/{'1' if first_time else '0'}"
        )
        data = await self._transport.request("POST", path, idempotent=False)
        return _as_dict(data)

    async def delete_totp(self, user_id: str) -> dict[str, Any]:
        """Remove a user's TOTP token."""
        data = await self._transport.request(
            "DELETE", f"/users/totp_delete/{quote(user_id, safe='')}", idempotent=False
        )
        return _as_dict(data)


class AuthKeysNamespace(_Namespace):
    """Authentication-key listing and CRUD endpoints."""

    async def list(self, filters: dict[str, Any] | None = None) -> builtins.list[dict[str, Any]]:
        """Return the auth-key index, optionally filtered.

        ``filters`` holds the documented POST ``/auth_keys`` search fields
        (``authkey_start``, ``authkey_end``, ``id``, ``uuid``, ``comment``,
        ``user_id``, ...). ``value`` is not one of them: MISP drops unknown
        keys and answers with every auth key, which is dangerous for anything
        that acts on the result.
        """
        if not filters:
            data = await self._transport.request("GET", "/auth_keys")
        else:
            data = await self._transport.request("POST", "/auth_keys", json_body=dict(filters))
        return _as_list(data)

    async def get(self, auth_key_id: str) -> dict[str, Any]:
        """Fetch one auth key's metadata."""
        data = await self._transport.request(
            "GET", f"/auth_keys/view/{quote(auth_key_id, safe='')}"
        )
        return _unwrap(data, "AuthKey")

    async def add(self, user_id: str, auth_key: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create an auth key for a user; the raw key appears only in this response."""
        data = await self._transport.request(
            "POST",
            f"/auth_keys/add/{quote(user_id, safe='')}",
            json_body={"AuthKey": auth_key or {}},
            idempotent=False,
        )
        return _unwrap(data, "AuthKey")

    async def update(self, auth_key_id: str, auth_key: dict[str, Any]) -> dict[str, Any]:
        """Update an auth key's metadata."""
        data = await self._transport.request(
            "POST",
            f"/auth_keys/edit/{quote(auth_key_id, safe='')}",
            json_body={"AuthKey": auth_key},
            idempotent=False,
        )
        return _unwrap(data, "AuthKey")

    async def delete(self, auth_key_id: str) -> dict[str, Any]:
        """Revoke an auth key."""
        data = await self._transport.request(
            "DELETE", f"/auth_keys/delete/{quote(auth_key_id, safe='')}", idempotent=False
        )
        return _as_dict(data)


class UserSettingsNamespace(_Namespace):
    """Per-user setting endpoints."""

    async def list(self, setting: str | None = None) -> builtins.list[dict[str, Any]]:
        """Return the user-setting index, optionally filtered by setting name."""
        if setting is None:
            data = await self._transport.request("GET", "/user_settings")
        else:
            data = await self._transport.request(
                "POST", "/user_settings", json_body={"setting": setting}
            )
        return _as_list(data)

    async def get(self, user_setting_id: str) -> dict[str, Any]:
        """Fetch one user setting by id."""
        data = await self._transport.request(
            "GET", f"/user_settings/view/{quote(user_setting_id, safe='')}"
        )
        return _unwrap(data, "UserSetting")

    async def get_setting(self, user_id: str, name: str) -> dict[str, Any]:
        """Fetch one user's setting by name."""
        path = f"/user_settings/getSetting/{quote(user_id, safe='')}/{quote(name, safe='')}"
        data = await self._transport.request("GET", path)
        return _unwrap(data, "UserSetting")

    async def set_setting(self, user_id: str, name: str, value: Any) -> dict[str, Any]:
        """Set one user's setting by name."""
        path = f"/user_settings/setSetting/{quote(user_id, safe='')}/{quote(name, safe='')}"
        # The body is the setting object itself (SetUserSettingRequest is an
        # anyOf over the setting schemas); a {"value": ...} wrapper was stored
        # verbatim, so the setting round-tripped as {"value": {...}}.
        data = await self._transport.request("POST", path, json_body=value, idempotent=False)
        return _unwrap(data, "UserSetting")

    async def delete(self, user_setting_id: str) -> dict[str, Any]:
        """Delete one user setting."""
        data = await self._transport.request(
            "DELETE", f"/user_settings/delete/{quote(user_setting_id, safe='')}", idempotent=False
        )
        return _as_dict(data)


class FeedsNamespace(_Namespace):
    """Feed listing, activation and fetch endpoints."""

    async def list(self) -> builtins.list[dict[str, Any]]:
        """Return the feed index."""
        data = await self._transport.request("GET", "/feeds")
        return _as_list(data)

    async def get(self, feed_id: str) -> dict[str, Any]:
        """Fetch one feed's configuration."""
        data = await self._transport.request("GET", f"/feeds/view/{quote(feed_id, safe='')}")
        return _unwrap(data, "Feed")

    async def add(self, feed: dict[str, Any]) -> dict[str, Any]:
        """Register a feed."""
        data = await self._transport.request(
            "POST", "/feeds/add", json_body={"Feed": feed}, idempotent=False
        )
        return _unwrap(data, "Feed")

    async def update(self, feed_id: str, feed: dict[str, Any]) -> dict[str, Any]:
        """Update a feed."""
        data = await self._transport.request(
            "PUT",
            f"/feeds/edit/{quote(feed_id, safe='')}",
            json_body={"Feed": feed},
            idempotent=False,
        )
        return _unwrap(data, "Feed")

    async def enable(self, feed_id: str) -> dict[str, Any]:
        """Enable a feed."""
        data = await self._transport.request(
            "POST", f"/feeds/enable/{quote(feed_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def disable(self, feed_id: str) -> dict[str, Any]:
        """Disable a feed."""
        data = await self._transport.request(
            "POST", f"/feeds/disable/{quote(feed_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def cache(self, scope: str = "all") -> dict[str, Any]:
        """Cache feeds within the given scope."""
        data = await self._transport.request(
            "POST", f"/feeds/cacheFeeds/{quote(scope, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def fetch(self, feed_id: str) -> dict[str, Any]:
        """Fetch and ingest one feed."""
        data = await self._transport.request(
            "POST", f"/feeds/fetchFromFeed/{quote(feed_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def fetch_all(self) -> dict[str, Any]:
        """Fetch and ingest every enabled feed."""
        data = await self._transport.request("POST", "/feeds/fetchFromAllFeeds", idempotent=False)
        return _as_dict(data)


class SharingGroupsNamespace(_Namespace):
    """Sharing-group CRUD and membership endpoints."""

    async def list(self) -> builtins.list[dict[str, Any]]:
        """Return the sharing-group index."""
        data = await self._transport.request("GET", "/sharing_groups")
        return _as_list(_as_dict(data).get("response", data) if isinstance(data, dict) else data)

    async def get(self, sharing_group_id: str) -> dict[str, Any]:
        """Fetch one sharing group."""
        data = await self._transport.request(
            "GET", f"/sharing_groups/view/{quote(sharing_group_id, safe='')}"
        )
        return _unwrap(data, "SharingGroup")

    async def add(self, sharing_group: dict[str, Any]) -> dict[str, Any]:
        """Create a sharing group."""
        data = await self._transport.request(
            "POST",
            "/sharing_groups/add",
            json_body={"SharingGroup": sharing_group},
            idempotent=False,
        )
        return _unwrap(data, "SharingGroup")

    async def update(self, sharing_group_id: str, sharing_group: dict[str, Any]) -> dict[str, Any]:
        """Update a sharing group."""
        data = await self._transport.request(
            "POST",
            f"/sharing_groups/edit/{quote(sharing_group_id, safe='')}",
            json_body={"SharingGroup": sharing_group},
            idempotent=False,
        )
        return _unwrap(data, "SharingGroup")

    async def delete(self, sharing_group_id: str) -> dict[str, Any]:
        """Delete a sharing group."""
        data = await self._transport.request(
            "DELETE", f"/sharing_groups/delete/{quote(sharing_group_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def add_org(self, sharing_group_id: str, organisation_id: str) -> dict[str, Any]:
        """Add an organisation to a sharing group."""
        path = (
            f"/sharing_groups/addOrg/{quote(sharing_group_id, safe='')}"
            f"/{quote(organisation_id, safe='')}"
        )
        data = await self._transport.request("POST", path, idempotent=False)
        return _as_dict(data)

    async def remove_org(self, sharing_group_id: str, organisation_id: str) -> dict[str, Any]:
        """Remove an organisation from a sharing group."""
        path = (
            f"/sharing_groups/removeOrg/{quote(sharing_group_id, safe='')}"
            f"/{quote(organisation_id, safe='')}"
        )
        data = await self._transport.request("POST", path, idempotent=False)
        return _as_dict(data)

    async def add_server(self, sharing_group_id: str, server_id: str) -> dict[str, Any]:
        """Add a sync server to a sharing group."""
        path = (
            f"/sharing_groups/addServer/{quote(sharing_group_id, safe='')}"
            f"/{quote(server_id, safe='')}"
        )
        data = await self._transport.request("POST", path, idempotent=False)
        return _as_dict(data)

    async def remove_server(self, sharing_group_id: str, server_id: str) -> dict[str, Any]:
        """Remove a sync server from a sharing group."""
        path = (
            f"/sharing_groups/removeServer/{quote(sharing_group_id, safe='')}"
            f"/{quote(server_id, safe='')}"
        )
        data = await self._transport.request("POST", path, idempotent=False)
        return _as_dict(data)


class SharingGroupBlueprintsNamespace(_Namespace):
    """Sharing-group blueprint CRUD and execution endpoints."""

    async def list(self) -> builtins.list[dict[str, Any]]:
        """Return the blueprint index."""
        data = await self._transport.request("GET", "/sharing_group_blueprints/index")
        return _as_list(data)

    async def get(self, blueprint_id: str) -> dict[str, Any]:
        """Fetch one blueprint."""
        data = await self._transport.request(
            "GET", f"/sharing_group_blueprints/view/{quote(blueprint_id, safe='')}"
        )
        return _unwrap(data, "SharingGroupBlueprint")

    async def orgs(self, blueprint_id: str) -> builtins.list[dict[str, Any]]:
        """Return the organisations a blueprint currently resolves to."""
        data = await self._transport.request(
            "GET", f"/sharing_group_blueprints/viewOrgs/{quote(blueprint_id, safe='')}"
        )
        return _as_list(data)

    async def add(self, blueprint: dict[str, Any]) -> dict[str, Any]:
        """Create a blueprint."""
        data = await self._transport.request(
            "POST",
            "/sharing_group_blueprints/add",
            json_body={"SharingGroupBlueprint": blueprint},
            idempotent=False,
        )
        return _unwrap(data, "SharingGroupBlueprint")

    async def update(self, blueprint_id: str, blueprint: dict[str, Any]) -> dict[str, Any]:
        """Update a blueprint."""
        data = await self._transport.request(
            "POST",
            f"/sharing_group_blueprints/edit/{quote(blueprint_id, safe='')}",
            json_body={"SharingGroupBlueprint": blueprint},
            idempotent=False,
        )
        return _unwrap(data, "SharingGroupBlueprint")

    async def execute(self, blueprint_id: str) -> dict[str, Any]:
        """Materialize the blueprint into its sharing group."""
        data = await self._transport.request(
            "POST",
            f"/sharing_group_blueprints/execute/{quote(blueprint_id, safe='')}",
            idempotent=False,
        )
        return _as_dict(data)

    async def detach(self, blueprint_id: str) -> dict[str, Any]:
        """Detach the blueprint from its generated sharing group."""
        data = await self._transport.request(
            "POST",
            f"/sharing_group_blueprints/detach/{quote(blueprint_id, safe='')}",
            idempotent=False,
        )
        return _as_dict(data)

    async def delete(self, blueprint_id: str) -> dict[str, Any]:
        """Delete a blueprint."""
        data = await self._transport.request(
            "DELETE",
            f"/sharing_group_blueprints/delete/{quote(blueprint_id, safe='')}",
            idempotent=False,
        )
        return _as_dict(data)
