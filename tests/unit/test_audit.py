"""Unit tests for fleet configuration drift comparison."""

from __future__ import annotations

from mispfleet.models.audit import AuditFindingKind, AuditSnapshot
from mispfleet.services.audit import compare_snapshots
from tests.support import eq


def snapshot(server: str, version: str | None) -> AuditSnapshot:
    return AuditSnapshot(server=server, misp_version=version)


def versions(snapshots: dict[str, AuditSnapshot]) -> list[AuditFindingKind]:
    return [f.kind for f in compare_snapshots(snapshots) if f.key == "version"]


def test_an_unreadable_version_is_missing_not_a_mismatch() -> None:
    """None means the server did not report a version, not that it disagrees.

    Letting None into the comparison set flagged drift across servers whose
    versions all agreed.
    """
    agreeing = {name: snapshot(name, "2.5.44") for name in ("a", "b", "c")}
    eq(versions(agreeing), [])

    silent = {**agreeing, "d": snapshot("d", None)}
    eq(versions(silent), [AuditFindingKind.MISSING])

    diverging = {**agreeing, "d": snapshot("d", "2.4.190")}
    eq(versions(diverging), [AuditFindingKind.MISMATCH])


def test_a_fleet_where_nobody_reports_a_version_is_not_drifting() -> None:
    """A key absent from every server produces no finding in any dimension."""
    eq(versions({name: snapshot(name, None) for name in ("a", "b")}), [])
