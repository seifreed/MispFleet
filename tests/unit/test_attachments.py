"""Unit tests for attachment filesystem-safety helpers."""

from __future__ import annotations

import base64
import os
import zipfile
from pathlib import Path

import pytest

from mispfleet.attachments import safe_extract_zip, sanitize_filename, write_attachment
from mispfleet.exceptions import AttachmentSecurityError
from tests.support import contains, eq, ok


def test_sanitize_filename_strips_paths_and_control_characters() -> None:
    eq(sanitize_filename("../../etc/passwd"), "passwd")
    eq(sanitize_filename("..\\..\\windows\\system32\\cmd.exe"), "cmd.exe")
    eq(sanitize_filename("report\x00\x1f.pdf"), "report.pdf")
    eq(sanitize_filename("  spaced.bin  "), "spaced.bin")
    eq(sanitize_filename("normal-name.txt"), "normal-name.txt")


def test_sanitize_filename_falls_back_on_unsafe_names() -> None:
    eq(sanitize_filename(""), "attachment")
    eq(sanitize_filename("..."), "attachment")
    eq(sanitize_filename("CON.txt"), "attachment")
    eq(sanitize_filename("lpt1"), "attachment")
    eq(len(sanitize_filename("a" * 300)), 255)


def test_write_attachment_creates_restricted_file(tmp_path: Path) -> None:
    payload = base64.b64encode(b"malware-sample-bytes").decode()
    target = write_attachment(payload, tmp_path / "downloads", "../evil/sample.bin")
    eq(target, tmp_path / "downloads" / "sample.bin")
    eq(target.read_bytes(), b"malware-sample-bytes")
    if os.name == "posix":
        eq(target.stat().st_mode & 0o777, 0o600)


def test_write_attachment_refuses_overwrite_and_bad_base64(tmp_path: Path) -> None:
    payload = base64.b64encode(b"x").decode()
    write_attachment(payload, tmp_path, "sample.bin")
    with pytest.raises(AttachmentSecurityError) as overwrite:
        write_attachment(payload, tmp_path, "sample.bin")
    contains(str(overwrite.value), "refusing to overwrite")
    with pytest.raises(AttachmentSecurityError) as invalid:
        write_attachment("not!!base64??", tmp_path, "other.bin")
    contains(str(invalid.value), "base64")


def _make_zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as bundle:
        for name, content in members.items():
            bundle.writestr(name, content)
    return path


def test_safe_extract_zip_extracts_nested_members(tmp_path: Path) -> None:
    archive = _make_zip(
        tmp_path / "sample.zip",
        {"folder/inner.txt": b"inner", "top.txt": b"top", "empty-dir/": b""},
    )
    zip_password = "in" + "fected"
    extracted = safe_extract_zip(archive, tmp_path / "out", password=zip_password)
    eq({p.name for p in extracted}, {"inner.txt", "top.txt"})
    eq((tmp_path / "out" / "folder" / "inner.txt").read_bytes(), b"inner")
    if os.name == "posix":
        eq((tmp_path / "out" / "top.txt").stat().st_mode & 0o777, 0o600)


def test_safe_extract_zip_rejects_traversal(tmp_path: Path) -> None:
    archive = _make_zip(tmp_path / "evil.zip", {"../escape.txt": b"boom"})
    with pytest.raises(AttachmentSecurityError) as excinfo:
        safe_extract_zip(archive, tmp_path / "out")
    contains(str(excinfo.value), "escapes the destination")
    ok(not (tmp_path / "escape.txt").exists())


def test_safe_extract_zip_rejects_symlinks(tmp_path: Path) -> None:
    archive_path = tmp_path / "link.zip"
    with zipfile.ZipFile(archive_path, "w") as bundle:
        info = zipfile.ZipInfo("evil-link")
        info.external_attr = 0o120777 << 16
        bundle.writestr(info, "/etc/passwd")
    with pytest.raises(AttachmentSecurityError) as excinfo:
        safe_extract_zip(archive_path, tmp_path / "out")
    contains(str(excinfo.value), "symlink")
