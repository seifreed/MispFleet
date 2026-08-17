"""Fleet configuration-consistency audit: collect per-server snapshots and diff them."""

from __future__ import annotations

from typing import Any

from mispfleet.client import MispClient
from mispfleet.models.audit import AuditFinding, AuditFindingKind, AuditSnapshot

AUDIT_DIMENSIONS = ("taxonomies", "warninglists", "galaxies", "feeds", "templates")


def _flag(enabled: Any) -> str:
    """Render a MISP enabled flag, tolerating its string form.

    Builds in the supported range answer with the strings "0"/"1" as well as
    real booleans, and ``bool("0")`` is True: a disabled taxonomy then read as
    enabled and drift was reported against servers that agreed.
    """
    if isinstance(enabled, str):
        return "on" if enabled.strip().lower() in {"1", "true"} else "off"
    return "on" if enabled else "off"


def _taxonomies(raw: list[dict[str, Any]]) -> dict[str, str]:
    entries: dict[str, str] = {}
    for item in raw:
        taxonomy = item.get("Taxonomy", item)
        if "namespace" in taxonomy:
            version = taxonomy.get("version", "?")
            entries[str(taxonomy["namespace"])] = f"{_flag(taxonomy.get('enabled'))} v{version}"
    return entries


def _warninglists(raw: list[dict[str, Any]]) -> dict[str, str]:
    entries: dict[str, str] = {}
    for item in raw:
        warninglist = item.get("Warninglist", item)
        if "name" in warninglist:
            version = warninglist.get("version", "?")
            entries[str(warninglist["name"])] = f"{_flag(warninglist.get('enabled'))} v{version}"
    return entries


def _galaxies(raw: list[dict[str, Any]]) -> dict[str, str]:
    entries: dict[str, str] = {}
    for item in raw:
        galaxy = item.get("Galaxy", item)
        if "name" in galaxy:
            entries[str(galaxy["name"])] = f"v{galaxy.get('version', '?')}"
    return entries


def _feeds(raw: list[dict[str, Any]]) -> dict[str, str]:
    entries: dict[str, str] = {}
    for item in raw:
        feed = item.get("Feed", item)
        if "name" in feed:
            entries[str(feed["name"])] = f"{feed.get('url', '?')} {_flag(feed.get('enabled'))}"
    return entries


def _templates(raw: list[dict[str, Any]]) -> dict[str, str]:
    entries: dict[str, str] = {}
    for item in raw:
        template = item.get("ObjectTemplate", item)
        if "name" in template:
            entries[str(template["name"])] = f"v{template.get('version', '?')}"
    return entries


async def collect_snapshot(client: MispClient) -> AuditSnapshot:
    """Read one server's auditable configuration through the public namespaces."""
    version = await client.system.version()
    return AuditSnapshot(
        server=client.config.name,
        misp_version=str(version.get("version")) if version.get("version") else None,
        taxonomies=_taxonomies(await client.taxonomies.list()),
        warninglists=_warninglists(await client.warninglists.list()),
        galaxies=_galaxies(await client.galaxies.list()),
        feeds=_feeds(await client.feeds.list()),
        templates=_templates(await client.templates.list()),
    )


def _classify_drift(values: dict[str, str | None], server_count: int) -> AuditFindingKind | None:
    """How a single key's per-server values diverge, or ``None`` when they agree.

    A ``None`` value means the server did not report the key, not that it
    disagrees: keeping those out of the comparison is what stops drift being
    flagged across servers that actually agree. A key nobody reports is no
    finding at all, exactly as an unreported version is not drift.
    """
    present = [value for value in values.values() if value is not None]
    if not present:
        return None
    if len(present) < server_count:
        return AuditFindingKind.MISSING
    if len(set(present)) > 1:
        return AuditFindingKind.MISMATCH
    return None


def compare_snapshots(snapshots: dict[str, AuditSnapshot]) -> list[AuditFinding]:
    """Diff the snapshots of every successful server deterministically.

    A key present on some servers but not all yields a ``missing`` finding;
    a key present everywhere with diverging descriptions yields ``mismatch``.
    MISP versions are compared as their own dimension.
    """
    if len(snapshots) < 2:
        return []
    servers = sorted(snapshots)
    findings: list[AuditFinding] = []
    versions: dict[str, str | None] = {name: snapshots[name].misp_version for name in servers}
    version_drift = _classify_drift(versions, len(servers))
    if version_drift is not None:
        findings.append(
            AuditFinding(dimension="misp", key="version", kind=version_drift, values=dict(versions))
        )
    for dimension in AUDIT_DIMENSIONS:
        keys = sorted({key for name in servers for key in snapshots[name].dimension(dimension)})
        for key in keys:
            values: dict[str, str | None] = {
                name: snapshots[name].dimension(dimension).get(key) for name in servers
            }
            kind = _classify_drift(values, len(servers))
            if kind is not None:
                findings.append(
                    AuditFinding(dimension=dimension, key=key, kind=kind, values=values)
                )
    return findings
