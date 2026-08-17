"""Integration tests for the single-server client and pagination."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from mispfleet.client import MispClient
from mispfleet.client.capabilities import capabilities_from_version
from mispfleet.client.pagination import paginate
from mispfleet.credentials import CredentialResolver, MemoryCredentialProvider
from mispfleet.exceptions import InvalidResponseError, NotFoundError
from mispfleet.models.attribute import MISPAttribute, MISPObject
from mispfleet.models.event import MISPEvent
from mispfleet.models.query import SearchQuery
from tests.conftest import config_for
from tests.fake_misp import API_KEY, FakeMisp
from tests.support import contains, eq, ne, ok

RAW_EVENT: dict[str, Any] = {
    "id": "7",
    "uuid": "9c5c1c2e-0000-4000-8000-00000000000e",
    "info": "Campaign X",
    "date": "2026-01-01",
    "published": True,
    "Attribute": [{"type": "domain", "value": "evil.example"}],
}


def attribute(index: int) -> dict[str, Any]:
    return {"type": "sha256", "value": f"{index:064x}", "event_id": str(index)}


async def test_client_event_get_by_uuid_and_id(fake_misp: FakeMisp) -> None:
    fake_misp.add_event(dict(RAW_EVENT))
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        by_uuid = await client.events.get(RAW_EVENT["uuid"])
        eq(by_uuid.info, "Campaign X")
        by_id = await client.events.get("7")
        eq(by_id.uuid, RAW_EVENT["uuid"])
        with pytest.raises(NotFoundError):
            await client.events.get("missing")


async def test_client_event_add_and_update(fake_misp: FakeMisp) -> None:
    event = MISPEvent.from_misp(RAW_EVENT)
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.events.add(event)
        eq(created.uuid, event.uuid)
        event.info = "Campaign X (updated)"
        updated = await client.events.update(event)
        eq(updated.info, "Campaign X (updated)")


async def test_client_event_lifecycle_publish_tags_delete(fake_misp: FakeMisp) -> None:
    fake_misp.add_event(dict(RAW_EVENT))
    uuid = RAW_EVENT["uuid"]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        eq([entry["uuid"] for entry in await client.events.list()], [uuid])
        found = await client.events.search(SearchQuery(event_info="Campaign"))
        eq([event.uuid for event in found], [uuid])
        capped = await client.events.search(SearchQuery(limit_per_server=1))
        eq(len(capped), 1)
        eq(fake_misp.search_bodies[-1]["limit"], 1)
        eq(await client.events.search(SearchQuery(event_info="absent")), [])
        await client.events.publish(uuid)
        ok(fake_misp.events[uuid]["published"])
        await client.events.unpublish(uuid)
        ok(not fake_misp.events[uuid]["published"])
        await client.events.add_tag(uuid, "tlp:green", local=True)
        eq(fake_misp.events[uuid]["Tag"], [{"name": "tlp:green"}])
        await client.events.remove_tag(uuid, "tlp:green")
        eq(fake_misp.events[uuid]["Tag"], [])
        enriched = await client.events.enrich(uuid, ["dns"])
        eq(enriched["results"], {"dns": 1})
        await client.events.delete(uuid)
        eq(fake_misp.events, {})
        with pytest.raises(NotFoundError):
            await client.events.delete(uuid)


async def test_client_attribute_crud_and_tags(fake_misp: FakeMisp) -> None:
    fake_misp.add_event(dict(RAW_EVENT))
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.attributes.add(
            RAW_EVENT["uuid"],
            MISPAttribute(
                uuid="aa0c1c2e-0000-4000-8000-0000000000aa", type="domain", value="a.example"
            ),
        )
        eq(created.value, "a.example")
        listed = await client.attributes.list()
        eq([item.value for item in listed], ["a.example"])
        created.comment = "edited"
        updated = await client.attributes.update(created)
        eq(updated.comment, "edited")
        await client.attributes.add_tag(created.uuid or "", "tlp:amber")
        eq(fake_misp.attributes[0]["Tag"], [{"name": "tlp:amber"}])
        await client.attributes.remove_tag(created.uuid or "", "tlp:amber")
        eq(fake_misp.attributes[0]["Tag"], [])
        await client.attributes.delete(created.uuid or "")
        ok(fake_misp.attributes[0]["deleted"])
        restored = await client.attributes.restore(created.uuid or "")
        eq(restored.deleted, False)
        enriched = await client.attributes.enrich(created.uuid or "", ["dns"])
        eq(enriched["results"], {"dns": 1})
        with pytest.raises(NotFoundError):
            await client.attributes.add("missing", created)


async def test_client_attribute_lookups_and_statistics(fake_misp: FakeMisp) -> None:
    fake_misp.attributes = [attribute(1), attribute(2)]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        types = await client.attributes.describe_types()
        eq(types["types"], ["sha256"])
        stats = await client.attributes.statistics()
        eq(stats, {"sha256": 2})
        encoded = base64.b64encode(attribute(1)["value"].encode()).decode()
        matches = await client.attributes.by_base64_value(encoded)
        eq([item.value for item in matches], [attribute(1)["value"]])


async def test_client_tag_crud_and_search(fake_misp: FakeMisp) -> None:
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.tags.add({"name": "tlp:green", "colour": "#00ff00"})
        eq(created["id"], "1")
        eq([tag["name"] for tag in await client.tags.list()], ["tlp:green"])
        eq((await client.tags.get("1"))["name"], "tlp:green")
        updated = await client.tags.update("1", {"name": "tlp:amber"})
        eq(updated["name"], "tlp:amber")
        found = await client.tags.search("amber")
        eq(len(found), 1)
        await client.tags.delete("1")
        eq(await client.tags.list(), [])
        with pytest.raises(NotFoundError):
            await client.tags.get("1")
        with pytest.raises(NotFoundError):
            await client.tags.update("1", {"name": "x"})
        with pytest.raises(NotFoundError):
            await client.tags.delete("1")


async def test_client_sighting_lifecycle(fake_misp: FakeMisp) -> None:
    sighted_event = "7c0c1c2e-0000-4000-8000-00000000007e"
    fake_misp.add_event({"uuid": sighted_event, "id": "7", "info": "Sighted"})
    fake_misp.attributes = [
        {"uuid": "aa0c1c2e-0000-4000-8000-0000000000aa", "value": "evil.example", "event_id": "7"},
    ]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        added = await client.sightings.add("evil.example")
        # MISP 2.5.44 wraps it, though openapi.yaml declares it unwrapped.
        eq(added["Sighting"]["attribute_uuid"], "aa0c1c2e-0000-4000-8000-0000000000aa")
        direct = await client.sightings.add_to_attribute("aa0c1c2e-0000-4000-8000-0000000000aa")
        eq(direct["Sighting"]["event_id"], "7")
        listed = await client.sightings.index("7")
        eq(len(listed), 2)
        # The endpoint matches the numeric id only; a UUID must be resolved
        # first, or it silently reports that the event has no sightings.
        by_uuid = await client.sightings.index(sighted_event)
        eq([s.attribute_uuid for s in by_uuid], [s.attribute_uuid for s in listed])
        eq(listed[0].attribute_uuid, "aa0c1c2e-0000-4000-8000-0000000000aa")
        await client.sightings.delete("1")
        eq(len(await client.sightings.index("7")), 1)
        with pytest.raises(NotFoundError):
            await client.sightings.delete("1")
        with pytest.raises(NotFoundError):
            await client.sightings.add_to_attribute("missing")


async def test_client_object_lifecycle(fake_misp: FakeMisp) -> None:
    fake_misp.add_event(dict(RAW_EVENT))
    obj = MISPObject(
        uuid="bb0c1c2e-0000-4000-8000-0000000000bb",
        name="domain-ip",
        attributes=[MISPAttribute(type="domain", value="pair.example")],
    )
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.objects.add(RAW_EVENT["uuid"], "template-uuid-1", obj)
        eq(created.template_uuid, "template-uuid-1")
        fetched = await client.objects.get(obj.uuid or "")
        eq(fetched.name, "domain-ip")
        eq(fetched.attributes[0].value, "pair.example")
        found = await client.objects.search(SearchQuery(object_name="domain-ip"))
        eq(len(found), 1)
        capped = await client.objects.search(SearchQuery(limit_per_server=1))
        eq(len(capped), 1)
        eq(await client.objects.search(SearchQuery(object_name="absent")), [])
        await client.objects.delete(obj.uuid or "", hard=True)
        with pytest.raises(NotFoundError):
            await client.objects.get(obj.uuid or "")
        with pytest.raises(NotFoundError):
            await client.objects.delete(obj.uuid or "")
        with pytest.raises(NotFoundError):
            await client.objects.add("missing", "template-uuid-1", obj)


async def test_client_taxonomy_lifecycle(fake_misp: FakeMisp) -> None:
    fake_misp.taxonomies = [
        {"id": "1", "namespace": "tlp", "enabled": False, "tags": [{"tag": "tlp:green"}]},
    ]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        listed = await client.taxonomies.list()
        eq(listed[0]["Taxonomy"]["namespace"], "tlp")
        eq((await client.taxonomies.get("1"))["Taxonomy"]["namespace"], "tlp")
        await client.taxonomies.enable("1")
        ok(fake_misp.taxonomies[0]["enabled"])
        await client.taxonomies.disable("1")
        ok(not fake_misp.taxonomies[0]["enabled"])
        eq(await client.taxonomies.tags("1"), [{"tag": "tlp:green"}])
        eq((await client.taxonomies.export("1"))["namespace"], "tlp")
        contains((await client.taxonomies.update())["message"], "updated")
        with pytest.raises(NotFoundError):
            await client.taxonomies.get("9")
        with pytest.raises(NotFoundError):
            await client.taxonomies.enable("9")
        with pytest.raises(NotFoundError):
            await client.taxonomies.tags("9")
        with pytest.raises(NotFoundError):
            await client.taxonomies.export("9")


async def test_client_warninglist_lifecycle(fake_misp: FakeMisp) -> None:
    fake_misp.warninglists = [
        {"id": "1", "name": "rfc5735", "enabled": False, "entries": ["127.0.0.1"]},
        {"id": "2", "name": "empty", "enabled": True, "entries": []},
    ]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        eq(len(await client.warninglists.list()), 2)
        filtered = await client.warninglists.list(value="127.0.0.1")
        eq(len(filtered), 1)
        eq((await client.warninglists.get("1"))["Warninglist"]["name"], "rfc5735")
        eq(await client.warninglists.check_value(["127.0.0.1"]), {})
        await client.warninglists.toggle(["1"], enabled=True)
        ok(fake_misp.warninglists[0]["enabled"])
        checked = await client.warninglists.check_value(["127.0.0.1", "8.8.8.8"])
        eq(list(checked), ["127.0.0.1"])
        contains((await client.warninglists.update())["message"], "updated")
        with pytest.raises(NotFoundError):
            await client.warninglists.get("9")


async def test_client_noticelist_lifecycle(fake_misp: FakeMisp) -> None:
    fake_misp.noticelists = [{"id": "1", "name": "gdpr", "enabled": False}]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        listed = await client.noticelists.list()
        eq(listed[0]["Noticelist"]["name"], "gdpr")
        eq((await client.noticelists.get("1"))["Noticelist"]["name"], "gdpr")
        toggled = await client.noticelists.toggle("1")
        ok(toggled["Noticelist"]["enabled"])
        contains((await client.noticelists.update())["message"], "updated")
        with pytest.raises(NotFoundError):
            await client.noticelists.get("9")
        with pytest.raises(NotFoundError):
            await client.noticelists.toggle("9")


async def test_client_galaxy_lifecycle(fake_misp: FakeMisp) -> None:
    fake_misp.galaxies = [{"id": "1", "name": "Threat Actor", "uuid": "gal-1"}]
    fake_misp.clusters = [{"id": "1", "galaxy_id": "1", "value": "APT-X", "published": False}]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        eq((await client.galaxies.list())[0]["Galaxy"]["name"], "Threat Actor")
        eq(len(await client.galaxies.list(search="Threat")), 1)
        eq(await client.galaxies.list(search="absent"), [])
        eq((await client.galaxies.get("1"))["Galaxy"]["name"], "Threat Actor")
        contains((await client.galaxies.update())["message"], "updated")
        exported = await client.galaxies.export("1")
        eq([item["value"] for item in exported], ["APT-X"])
        imported = await client.galaxies.import_clusters([{"galaxy_id": "1", "value": "APT-Y"}])
        contains(imported["message"], "1 cluster(s)")
        with pytest.raises(NotFoundError):
            await client.galaxies.get("9")
        with pytest.raises(NotFoundError):
            await client.galaxies.export("9")
        await client.galaxies.delete("1")
        eq(await client.galaxies.list(), [])
        with pytest.raises(NotFoundError):
            await client.galaxies.delete("1")


async def test_client_galaxy_cluster_attach_to_event(fake_misp: FakeMisp) -> None:
    fake_misp.add_event(dict(RAW_EVENT))
    fake_misp.clusters = [{"id": "5", "galaxy_id": "1", "value": "APT-X"}]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        await client.galaxies.attach_cluster(RAW_EVENT["uuid"], "event", "5", local=True)
        eq(fake_misp.events[RAW_EVENT["uuid"]]["Galaxy"][0]["value"], "APT-X")
        with pytest.raises(NotFoundError):
            await client.galaxies.attach_cluster("missing", "event", "5")
        with pytest.raises(NotFoundError):
            await client.galaxies.attach_cluster(RAW_EVENT["uuid"], "event", "9")


async def test_client_galaxy_cluster_lifecycle(fake_misp: FakeMisp) -> None:
    fake_misp.galaxies = [{"id": "1", "name": "Threat Actor"}]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.galaxy_clusters.add("1", {"value": "APT-X"})
        cluster_id = created["GalaxyCluster"]["id"]
        eq(created["GalaxyCluster"]["galaxy_id"], "1")
        eq(len(await client.galaxy_clusters.index("1")), 1)
        eq(len(await client.galaxy_clusters.index("1", search="APT")), 1)
        eq(await client.galaxy_clusters.index("1", search="absent"), [])
        eq((await client.galaxy_clusters.get(cluster_id))["GalaxyCluster"]["value"], "APT-X")
        updated = await client.galaxy_clusters.update(cluster_id, {"value": "APT-X2"})
        eq(updated["GalaxyCluster"]["value"], "APT-X2")
        await client.galaxy_clusters.publish(cluster_id)
        ok(fake_misp.clusters[0]["published"])
        await client.galaxy_clusters.unpublish(cluster_id)
        ok(not fake_misp.clusters[0]["published"])
        await client.galaxy_clusters.delete(cluster_id)
        ok(fake_misp.clusters[0]["deleted"])
        await client.galaxy_clusters.restore(cluster_id)
        ok(not fake_misp.clusters[0]["deleted"])
        with pytest.raises(NotFoundError):
            await client.galaxy_clusters.get("9")
        with pytest.raises(NotFoundError):
            await client.galaxy_clusters.add("9", {"value": "x"})
        with pytest.raises(NotFoundError):
            await client.galaxy_clusters.update("9", {"value": "x"})
        with pytest.raises(NotFoundError):
            await client.galaxy_clusters.publish("9")


async def test_client_sync_server_crud_and_transfers(fake_misp: FakeMisp) -> None:
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.servers.add({"name": "peer", "url": "https://peer.example"})
        eq(created["id"], "1")
        eq((await client.servers.list())[0]["Server"]["name"], "peer")
        updated = await client.servers.update("1", {"name": "peer-2"})
        eq(updated["name"], "peer-2")
        contains((await client.servers.pull("1"))["message"], "pull queued (full)")
        contains((await client.servers.push("1", "incremental"))["message"], "incremental")
        exported = await client.servers.create_sync()
        eq(exported["Server"]["uuid"], fake_misp.instance_uuid)
        imported = await client.servers.import_server(exported)
        eq(imported["id"], "2")
        await client.servers.delete("2")
        eq(len(await client.servers.list()), 1)
        with pytest.raises(NotFoundError):
            await client.servers.update("9", {})
        with pytest.raises(NotFoundError):
            await client.servers.delete("9")
        with pytest.raises(NotFoundError):
            await client.servers.pull("9")


async def test_client_server_workers_and_settings(fake_misp: FakeMisp) -> None:
    fake_misp.settings = {"MISP.live": True}
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        eq((await client.servers.pymisp_version())["version"], "2.4.190")
        eq((await client.servers.instance_uuid())["uuid"], fake_misp.instance_uuid)
        report = await client.servers.settings()
        eq(report["finalSettings"][0]["setting"], "MISP.live")
        eq((await client.servers.get_setting("MISP.live"))["value"], True)
        await client.servers.set_setting("MISP.lang", "en")
        eq(fake_misp.settings["MISP.lang"], "en")
        with pytest.raises(NotFoundError):
            await client.servers.get_setting("absent")
        started = await client.servers.start_worker("default")
        contains(started["message"], "started")
        pid = next(iter(fake_misp.workers))
        eq((await client.servers.workers())[pid]["type"], "default")
        await client.servers.stop_worker(pid)
        eq(fake_misp.workers, {})
        with pytest.raises(NotFoundError):
            await client.servers.stop_worker(pid)
        for call in (
            client.servers.kill_all_workers,
            client.servers.restart_workers,
            client.servers.restart_dead_workers,
            client.servers.update_misp,
            client.servers.update_json,
            client.servers.cache,
        ):
            ok("message" in await call())


async def test_client_organisation_crud(fake_misp: FakeMisp) -> None:
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.organisations.add({"name": "CERT-A"})
        eq(created["id"], "1")
        eq((await client.organisations.list())[0]["Organisation"]["name"], "CERT-A")
        eq((await client.organisations.get("1"))["name"], "CERT-A")
        updated = await client.organisations.update("1", {"name": "CERT-B"})
        eq(updated["name"], "CERT-B")
        await client.organisations.delete("1")
        eq(await client.organisations.list(), [])
        with pytest.raises(NotFoundError):
            await client.organisations.get("1")
        with pytest.raises(NotFoundError):
            await client.organisations.update("1", {})
        with pytest.raises(NotFoundError):
            await client.organisations.delete("1")


async def test_client_user_admin_lifecycle(fake_misp: FakeMisp) -> None:
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.users.add({"email": "analyst@cert.example"})
        eq(created["id"], "1")
        eq((await client.users.list())[0]["User"]["email"], "analyst@cert.example")
        eq((await client.users.get("1"))["email"], "analyst@cert.example")
        updated = await client.users.update("1", {"email": "analyst2@cert.example"})
        eq(updated["email"], "analyst2@cert.example")
        await client.users.initiate_password_reset("1", first_time=True)
        eq(fake_misp.users[0]["password_reset"], "first")
        await client.users.delete_totp("1")
        eq(fake_misp.users[0]["totp"], None)
        await client.users.delete("1")
        eq(await client.users.list(), [])
        with pytest.raises(NotFoundError):
            await client.users.get("1")
        with pytest.raises(NotFoundError):
            await client.users.initiate_password_reset("1")
        with pytest.raises(NotFoundError):
            await client.users.delete_totp("1")
        with pytest.raises(NotFoundError):
            await client.users.update("1", {})
        with pytest.raises(NotFoundError):
            await client.users.delete("1")


async def test_client_auth_key_lifecycle(fake_misp: FakeMisp) -> None:
    fake_misp.users = [{"id": "1", "email": "analyst@cert.example"}]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.auth_keys.add("1", {"comment": "automation"})
        eq(created["authkey_raw"], "raw-key-1")
        fetched = await client.auth_keys.get("1")
        ok("authkey_raw" not in fetched)
        eq(len(await client.auth_keys.list()), 1)
        eq(len(await client.auth_keys.list({"comment": "automation"})), 1)
        eq(await client.auth_keys.list({"comment": "absent"}), [])
        updated = await client.auth_keys.update("1", {"comment": "rotated"})
        eq(updated["comment"], "rotated")
        await client.auth_keys.delete("1")
        eq(await client.auth_keys.list(), [])
        with pytest.raises(NotFoundError):
            await client.auth_keys.add("9")
        with pytest.raises(NotFoundError):
            await client.auth_keys.get("1")
        with pytest.raises(NotFoundError):
            await client.auth_keys.update("1", {})
        with pytest.raises(NotFoundError):
            await client.auth_keys.delete("1")


async def test_client_user_settings_lifecycle(fake_misp: FakeMisp) -> None:
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.user_settings.set_setting("1", "homepage", {"path": "/events"})
        eq(created["id"], "1")
        again = await client.user_settings.set_setting("1", "homepage", {"path": "/tags"})
        eq(again["id"], "1")
        eq(again["value"], {"path": "/tags"})
        eq(len(await client.user_settings.list()), 1)
        eq(len(await client.user_settings.list(setting="homepage")), 1)
        eq(await client.user_settings.list(setting="absent"), [])
        eq((await client.user_settings.get("1"))["setting"], "homepage")
        eq((await client.user_settings.get_setting("1", "homepage"))["value"], {"path": "/tags"})
        await client.user_settings.delete("1")
        eq(await client.user_settings.list(), [])
        with pytest.raises(NotFoundError):
            await client.user_settings.get("1")
        with pytest.raises(NotFoundError):
            await client.user_settings.get_setting("1", "homepage")
        with pytest.raises(NotFoundError):
            await client.user_settings.delete("1")


async def test_client_feed_lifecycle(fake_misp: FakeMisp) -> None:
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.feeds.add({"name": "circl-osint", "url": "https://feed.example"})
        eq(created["id"], "1")
        eq((await client.feeds.list())[0]["Feed"]["name"], "circl-osint")
        eq((await client.feeds.get("1"))["name"], "circl-osint")
        updated = await client.feeds.update("1", {"name": "circl-osint-2"})
        eq(updated["name"], "circl-osint-2")
        await client.feeds.enable("1")
        ok(fake_misp.feeds[0]["enabled"])
        await client.feeds.disable("1")
        ok(not fake_misp.feeds[0]["enabled"])
        contains((await client.feeds.cache())["message"], "all")
        contains((await client.feeds.fetch("1"))["message"], "Fetching feed")
        contains((await client.feeds.fetch_all())["message"], "all feeds")
        with pytest.raises(NotFoundError):
            await client.feeds.get("9")
        with pytest.raises(NotFoundError):
            await client.feeds.update("9", {})
        with pytest.raises(NotFoundError):
            await client.feeds.enable("9")
        with pytest.raises(NotFoundError):
            await client.feeds.fetch("9")


async def test_client_sharing_group_lifecycle(fake_misp: FakeMisp) -> None:
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.sharing_groups.add({"name": "partners"})
        eq(created["id"], "1")
        eq((await client.sharing_groups.list())[0]["SharingGroup"]["name"], "partners")
        eq((await client.sharing_groups.get("1"))["name"], "partners")
        updated = await client.sharing_groups.update("1", {"name": "partners-2"})
        eq(updated["name"], "partners-2")
        await client.sharing_groups.add_org("1", "10")
        eq(fake_misp.sharing_groups[0]["orgs"], ["10"])
        await client.sharing_groups.remove_org("1", "10")
        eq(fake_misp.sharing_groups[0]["orgs"], [])
        await client.sharing_groups.add_server("1", "20")
        eq(fake_misp.sharing_groups[0]["servers"], ["20"])
        await client.sharing_groups.remove_server("1", "20")
        eq(fake_misp.sharing_groups[0]["servers"], [])
        await client.sharing_groups.delete("1")
        eq(await client.sharing_groups.list(), [])
        with pytest.raises(NotFoundError):
            await client.sharing_groups.get("1")
        with pytest.raises(NotFoundError):
            await client.sharing_groups.update("1", {})
        with pytest.raises(NotFoundError):
            await client.sharing_groups.add_org("1", "10")
        with pytest.raises(NotFoundError):
            await client.sharing_groups.delete("1")


async def test_client_sharing_group_blueprint_lifecycle(fake_misp: FakeMisp) -> None:
    fake_misp.organisations = [{"id": "1", "name": "CERT-A"}]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.sharing_group_blueprints.add({"name": "eu-certs", "rules": {}})
        eq(created["id"], "1")
        listed = await client.sharing_group_blueprints.list()
        eq(listed[0]["SharingGroupBlueprint"]["name"], "eu-certs")
        eq((await client.sharing_group_blueprints.get("1"))["name"], "eu-certs")
        eq((await client.sharing_group_blueprints.orgs("1"))[0]["Organisation"]["name"], "CERT-A")
        updated = await client.sharing_group_blueprints.update("1", {"name": "eu-certs-2"})
        eq(updated["name"], "eu-certs-2")
        executed = await client.sharing_group_blueprints.execute("1")
        eq(executed["SharingGroupBlueprint"]["sharing_group_id"], "1")
        eq(len(await client.sharing_groups.list()), 1)
        detached = await client.sharing_group_blueprints.detach("1")
        eq(detached["SharingGroupBlueprint"]["sharing_group_id"], None)
        await client.sharing_group_blueprints.delete("1")
        eq(await client.sharing_group_blueprints.list(), [])
        with pytest.raises(NotFoundError):
            await client.sharing_group_blueprints.get("1")
        with pytest.raises(NotFoundError):
            await client.sharing_group_blueprints.orgs("1")
        with pytest.raises(NotFoundError):
            await client.sharing_group_blueprints.update("1", {})
        with pytest.raises(NotFoundError):
            await client.sharing_group_blueprints.execute("1")
        with pytest.raises(NotFoundError):
            await client.sharing_group_blueprints.delete("1")


async def test_client_event_report_lifecycle(fake_misp: FakeMisp) -> None:
    fake_misp.add_event(dict(RAW_EVENT))
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.event_reports.add(RAW_EVENT["uuid"], {"name": "triage notes"})
        eq(created["id"], "1")
        eq((await client.event_reports.list())[0]["EventReport"]["name"], "triage notes")
        eq((await client.event_reports.get("1"))["name"], "triage notes")
        updated = await client.event_reports.update("1", {"name": "final notes"})
        eq(updated["name"], "final notes")
        await client.event_reports.delete("1")
        ok(fake_misp.reports[0]["deleted"])
        restored = await client.event_reports.restore("1")
        eq(restored["deleted"], False)
        imported = await client.event_reports.import_from_url(
            RAW_EVENT["uuid"], "https://report.example/doc"
        )
        eq(imported["name"], "https://report.example/doc")
        await client.event_reports.delete("2", hard=True)
        eq(len(fake_misp.reports), 1)
        with pytest.raises(NotFoundError):
            await client.event_reports.add("missing", {})
        with pytest.raises(NotFoundError):
            await client.event_reports.import_from_url("missing", "https://x.example")
        with pytest.raises(NotFoundError):
            await client.event_reports.get("9")
        with pytest.raises(NotFoundError):
            await client.event_reports.update("9", {})
        with pytest.raises(NotFoundError):
            await client.event_reports.restore("9")
        with pytest.raises(NotFoundError):
            await client.event_reports.delete("9")


async def test_client_analyst_data_lifecycle(fake_misp: FakeMisp) -> None:
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.analyst_data.add(
            "Note", RAW_EVENT["uuid"], "Event", {"note": "seen in the wild", "uuid": "note-1"}
        )
        eq(created["Note"]["object_uuid"], RAW_EVENT["uuid"])
        listed = await client.analyst_data.index("Note")
        eq(listed[0]["Note"]["note"], "seen in the wild")
        eq((await client.analyst_data.get("Note", "1"))["Note"]["note"], "seen in the wild")
        updated = await client.analyst_data.update("Note", "1", {"note": "confirmed"})
        eq(updated["Note"]["note"], "confirmed")
        minimal = await client.analyst_data.index_minimal()
        eq(sorted(minimal["Note"]), ["note-1"])
        await client.analyst_data.delete("Note", "1")
        eq(await client.analyst_data.index("Note"), [])
        with pytest.raises(NotFoundError):
            await client.analyst_data.get("Note", "1")
        with pytest.raises(NotFoundError):
            await client.analyst_data.update("Note", "1", {})
        with pytest.raises(NotFoundError):
            await client.analyst_data.delete("Note", "1")


async def test_client_collection_lifecycle(fake_misp: FakeMisp) -> None:
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.collections.add({"name": "campaign-2026", "mine": True})
        eq(created["id"], "1")
        eq((await client.collections.list())[0]["Collection"]["name"], "campaign-2026")
        eq(len(await client.collections.list("my_collections")), 1)
        eq((await client.collections.get("1"))["name"], "campaign-2026")
        updated = await client.collections.update("1", {"name": "campaign-2026-q3"})
        eq(updated["name"], "campaign-2026-q3")
        await client.collections.delete("1")
        eq(await client.collections.list(), [])
        with pytest.raises(NotFoundError):
            await client.collections.get("1")
        with pytest.raises(NotFoundError):
            await client.collections.update("1", {})
        with pytest.raises(NotFoundError):
            await client.collections.delete("1")


async def test_client_log_search(fake_misp: FakeMisp) -> None:
    fake_misp.logs = [
        {"id": "1", "model": "Event", "action": "add"},
        {"id": "2", "model": "User", "action": "login"},
    ]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        eq(len(await client.logs.search()), 2)
        filtered = await client.logs.search({"model": "Event"})
        eq(len(filtered), 1)
        eq(filtered[0]["Log"]["action"], "add")


async def test_client_resolves_credentials_through_resolver(fake_misp: FakeMisp) -> None:
    resolver = CredentialResolver({"memory": MemoryCredentialProvider({"test-server": API_KEY})})
    async with MispClient(config_for(fake_misp), resolver=resolver) as client:
        version = await client.system.version()
        eq(version["version"], "2.4.190")


async def test_client_capabilities_and_list_namespaces(fake_misp: FakeMisp) -> None:
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        capabilities = await client.system.capabilities()
        contains(capabilities, "sync")
        contains(capabilities, "version")
        for namespace in (
            client.taxonomies,
            client.galaxies,
            client.warninglists,
            client.templates,
            client.organisations,
            client.servers,
        ):
            eq(await namespace.list(), [])
        eq(await client.tags.list(), [])


def test_capabilities_from_minimal_version_payload() -> None:
    capabilities = capabilities_from_version({})
    contains(capabilities, "rest-search")
    ok("sync" not in capabilities)
    full = capabilities_from_version(
        {"version": "2.4.190", "perm_sync": 1, "perm_sighting": 1, "perm_galaxy_editor": 1}
    )
    contains(full, "sightings")
    contains(full, "galaxies")


async def test_attribute_search_filters_by_value_and_type(fake_misp: FakeMisp) -> None:
    fake_misp.attributes = [
        {"type": "domain", "value": "evil.example"},
        {"type": "sha256", "value": "aa" * 32},
    ]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        matches = await client.attributes.search(SearchQuery(value="evil.example"))
        eq(len(matches), 1)
        eq(matches[0]["type"], "domain")
        typed = await client.attributes.search(SearchQuery(attribute_types={"sha256"}))
        eq(len(typed), 1)
        both = await client.attributes.search(SearchQuery())
        eq(len(both), 2)
        capped = await client.attributes.search(SearchQuery(limit_per_server=1))
        eq(len(capped), 1)


async def test_iter_search_streams_across_pages(fake_misp: FakeMisp) -> None:
    fake_misp.attributes = [attribute(index) for index in range(25)]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        seen = [item async for item in client.attributes.iter_search(SearchQuery(), page_size=10)]
        eq(len(seen), 25)
        eq(sorted({item.type for item in seen}), ["sha256"])
        pages = [path for method, path in fake_misp.requests_seen if method == "POST"]
        eq(len(pages), 3)


async def test_iter_search_respects_max_records(fake_misp: FakeMisp) -> None:
    fake_misp.attributes = [attribute(index) for index in range(25)]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        seen = [
            item
            async for item in client.attributes.iter_search(
                SearchQuery(), page_size=10, max_records=12
            )
        ]
        eq(len(seen), 12)


async def test_iter_search_honors_query_limit_per_server(fake_misp: FakeMisp) -> None:
    fake_misp.attributes = [attribute(index) for index in range(25)]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        seen = [
            item
            async for item in client.attributes.iter_search(
                SearchQuery(limit_per_server=10), page_size=5
            )
        ]
        eq(len(seen), 10)


async def test_iter_search_stops_on_non_advancing_pages(fake_misp: FakeMisp) -> None:
    fake_misp.attributes = [attribute(index) for index in range(30)]
    fake_misp.static_search = True
    warnings: list[str] = []
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        seen = [
            item
            async for item in client.attributes.iter_search(
                SearchQuery(), page_size=10, on_warning=warnings.append
            )
        ]
    eq(len(seen), 10)
    eq(len(warnings), 1)
    contains(warnings[0], "not advancing")


async def test_paginate_empty_first_page_yields_nothing() -> None:
    async def fetch_empty(page: int, limit: int) -> list[dict[str, Any]]:
        return []

    eq([item async for item in paginate(fetch_empty, page_size=1)], [])


async def test_paginate_reports_pages_to_checkpoint_callback() -> None:
    data = [[{"n": 1}, {"n": 2}], [{"n": 3}, {"n": 4}], []]
    checkpoints: list[tuple[int, int]] = []

    async def fetch(page: int, limit: int) -> list[dict[str, Any]]:
        return data[page - 1]

    def on_page(page: int, records: int) -> None:
        checkpoints.append((page, records))

    seen = [item async for item in paginate(fetch, page_size=2, on_page=on_page)]
    eq(len(seen), 4)
    eq(checkpoints, [(1, 2), (2, 4)])


async def test_paginate_checkpoints_the_page_that_hit_max_records() -> None:
    data = [[{"n": 1}, {"n": 2}], [{"n": 3}, {"n": 4}]]
    checkpoints: list[tuple[int, int]] = []

    async def fetch(page: int, limit: int) -> list[dict[str, Any]]:
        return data[page - 1]

    def on_page(page: int, records: int) -> None:
        checkpoints.append((page, records))

    seen = [item async for item in paginate(fetch, page_size=2, max_records=3, on_page=on_page)]
    eq(len(seen), 3)
    # Reported per page FETCHED, not per record consumed: a consumer that
    # stops mid-page suspends the generator, so a callback after the loop
    # never fired for the page in flight and the checkpoint was lost.
    eq(checkpoints, [(1, 2), (2, 4)])


async def test_paginate_resumes_from_checkpoint_page() -> None:
    requested: list[int] = []

    async def fetch(page: int, limit: int) -> list[dict[str, Any]]:
        requested.append(page)
        return [{"page": page}] if page < 4 else []

    seen = [item async for item in paginate(fetch, page_size=1, start_page=3)]
    eq(requested[0], 3)
    eq(len(seen), 1)
    ne(seen[0]["page"], 1)


async def test_client_accepts_prebuilt_transport(fake_misp: FakeMisp) -> None:
    from mispfleet.client.transport import AsyncTransport

    transport = AsyncTransport(config_for(fake_misp), API_KEY)
    async with MispClient(config_for(fake_misp), transport=transport) as client:
        version = await client.system.version()
        eq(version["version"], "2.4.190")


async def test_iter_search_repeated_page_without_warning_callback(fake_misp: FakeMisp) -> None:
    fake_misp.attributes = [attribute(index) for index in range(30)]
    fake_misp.static_search = True
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        seen = [item async for item in client.attributes.iter_search(SearchQuery(), page_size=10)]
    eq(len(seen), 10)


async def test_paginate_stops_on_a_server_alternating_two_pages() -> None:
    """The guard kept only the previous page's fingerprint.

    A server answering A, B, A, B... never repeats consecutively, so the
    "not advancing" detection never fired and iteration streamed duplicates
    without end.
    """
    calls = {"n": 0}
    warnings: list[str] = []

    async def alternating(page: int, limit: int) -> list[dict[str, object]]:
        calls["n"] += 1
        marker = "A" if calls["n"] % 2 else "B"
        return [{"page": marker} for _ in range(limit)]

    records = [
        item async for item in paginate(alternating, page_size=3, on_warning=warnings.append)
    ]
    eq(len(records), 6)
    contains(warnings[0], "not advancing")


async def test_paginate_with_a_zero_record_cap_yields_nothing() -> None:
    """The cap was checked after the yield, so max_records=0 emitted one record."""

    async def fetch(page: int, limit: int) -> list[dict[str, object]]:
        return [{"index": index} for index in range(limit)]

    eq([item async for item in paginate(fetch, page_size=5, max_records=0)], [])
    eq(len([item async for item in paginate(fetch, page_size=5, max_records=2)]), 2)


async def test_wrongly_shaped_responses_raise_typed_errors(fake_misp: FakeMisp) -> None:
    """Nothing between the transport and the models checked the JSON shape.

    A proxy or a non-MISP server answering with an array or a scalar produced
    a raw TypeError or AttributeError instead of the documented typed error.
    """
    from mispfleet.client.namespaces._base import _as_dict, _as_list, _unwrap

    for wrong in (123, [1, 2], "haha", None):
        with pytest.raises(InvalidResponseError) as excinfo:
            _as_dict(wrong)
        contains(str(excinfo.value), "where an object was expected")
    for wrong_list in (123, {"a": 1}, "haha"):
        with pytest.raises(InvalidResponseError):
            _as_list(wrong_list)
    eq(_as_dict({"a": 1}), {"a": 1})
    eq(_as_list([1]), [1])
    eq(_unwrap({"Server": {"id": "1"}}, "Server"), {"id": "1"})
    eq(_unwrap({"id": "1"}, "Server"), {"id": "1"})
    with pytest.raises(InvalidResponseError):
        _unwrap({"Server": [1]}, "Server")


async def test_scalar_bodies_from_a_hostile_server_stay_typed(fake_misp: FakeMisp) -> None:
    """Every namespace used to trust the body it was handed."""
    fake_misp.script(200, "123")
    fake_misp.script(200, "[1,2]")
    fake_misp.script(200, '"haha"')
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        with pytest.raises(InvalidResponseError):
            await client.events.list()
        with pytest.raises(InvalidResponseError):
            await client.events.search(SearchQuery())
        with pytest.raises(InvalidResponseError):
            await client.tags.list()


async def test_client_search_applies_the_filters_misp_ignores(fake_misp: FakeMisp) -> None:
    """The local filter reached the fleet path only.

    docs/search.md documents client.attributes.iter_search alongside
    fleet.iter_search, but the single-server API returned every record.
    """
    fake_misp.attributes = [
        {
            "id": "1",
            "type": "domain",
            "value": "ongoing.example",
            "Event": {"uuid": "9c5c1c2e-0000-4000-8000-00000000000e", "analysis": "0"},
        },
        {
            "id": "2",
            "type": "domain",
            "value": "complete.example",
            "Event": {"uuid": "9c5c1c2e-0000-4000-8000-00000000000e", "analysis": "2"},
        },
    ]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        eq(len(await client.attributes.search(SearchQuery())), 2)
        scoped = await client.attributes.search(SearchQuery(analysis="2"))
        eq([raw["value"] for raw in scoped], ["complete.example"])
        streamed = [
            attribute.value
            async for attribute in client.attributes.iter_search(SearchQuery(analysis="0"))
        ]
        eq(streamed, ["ongoing.example"])


async def test_limit_per_server_counts_records_the_caller_receives(fake_misp: FakeMisp) -> None:
    """The cap was applied inside paginate, before the local filter.

    A scoped query therefore returned a fraction of limit_per_server: with
    every other record matching, a cap of 5 yielded 2.
    """
    fake_misp.attributes = [
        {
            "id": str(index),
            "type": "domain",
            "value": f"v{index}",
            "Event": {
                "uuid": "9c5c1c2e-0000-4000-8000-00000000000e",
                "analysis": "2" if index % 2 else "0",
            },
        }
        for index in range(20)
    ]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        capped = [
            attribute.value
            async for attribute in client.attributes.iter_search(
                SearchQuery(analysis="2", limit_per_server=5), page_size=5
            )
        ]
        eq(capped, ["v1", "v3", "v5", "v7", "v9"])
        uncapped = [
            attribute.value
            async for attribute in client.attributes.iter_search(
                SearchQuery(analysis="2"), page_size=5
            )
        ]
        eq(len(uncapped), 10)


async def test_restsearch_envelope_surprises_stay_typed(fake_misp: FakeMisp) -> None:
    """A misshapen restSearch envelope owes InvalidResponseError.

    Iterating a dict-shaped "response" walked its string keys straight into
    query.matches_locally, which does raw.get(...) — an AttributeError from
    inside client code rather than the documented typed error.
    """
    fake_misp.script(200, '{"response": {"unexpected": "object"}}')
    fake_misp.script(200, '{"response": ["not", "an", "object"]}')
    fake_misp.script(200, '{"response": {"oops": 1}}')
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        with pytest.raises(InvalidResponseError):
            await client.events.search(SearchQuery(value="x"))
        with pytest.raises(InvalidResponseError):
            await client.attributes.search(SearchQuery(value="x"))
        with pytest.raises(InvalidResponseError):
            await client.objects.search(SearchQuery(value="x"))


async def test_collections_list_refuses_a_filter_outside_the_endpoint_enum(
    fake_misp: FakeMisp,
) -> None:
    """The path filter is an enum of my_collections/org_collections.

    The old default of "all" sat outside it, so the scope a conforming server
    applied to `collections.list()` was undefined.
    """
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        with pytest.raises(ValueError):
            await client.collections.list("all")
        await client.collections.add({"name": "shared", "mine": False})
        eq(len(await client.collections.list("org_collections")), 1)
        eq(await client.collections.list("my_collections"), [])
