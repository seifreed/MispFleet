"""Unit tests for attachment filesystem-safety helpers."""

from __future__ import annotations

import base64
import os
import zipfile
from pathlib import Path

import pytest

from mispfleet.attachments import safe_extract_zip, sanitize_filename, write_attachment
from mispfleet.exceptions import AttachmentSecurityError
from tests.support import contains, eq, not_contains, ok


def test_sanitize_filename_strips_paths_and_control_characters() -> None:
    eq(sanitize_filename("../../etc/passwd"), "passwd")
    eq(sanitize_filename("..\\..\\windows\\system32\\cmd.exe"), "cmd.exe")
    eq(sanitize_filename("report\x00\x1f.pdf"), "report.pdf")
    eq(sanitize_filename("  spaced.bin  "), "spaced.bin")
    eq(sanitize_filename("normal-name.txt"), "normal-name.txt")
    eq(sanitize_filename("ads:stream.txt"), "ads_stream.txt")
    eq(sanitize_filename('quo"te|pipe?.bin'), "quo_te_pipe_.bin")


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


def test_write_attachment_leaves_the_existing_file_untouched(tmp_path: Path) -> None:
    """The refusal must be an exclusive create, not a check-then-rename.

    Renaming into place clobbered whatever appeared after the existence check.
    """
    target = tmp_path / "sample.bin"
    target.write_bytes(b"original")
    with pytest.raises(AttachmentSecurityError):
        write_attachment(base64.b64encode(b"replacement").decode(), tmp_path, "sample.bin")
    eq(target.read_bytes(), b"original")
    eq(sorted(p.name for p in tmp_path.iterdir()), ["sample.bin"])


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


def test_extraction_stops_before_a_compression_bomb_fills_the_disk(tmp_path: Path) -> None:
    """Nothing bounded the decompressed size.

    A 300 KiB archive holding 300 MB of zeroes was read into memory in one
    call and written out in full.
    """
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("big.bin", b"\0" * (8 * 1024 * 1024))
    ok(archive.stat().st_size < 128 * 1024, "the archive itself should stay small")
    with pytest.raises(AttachmentSecurityError) as excinfo:
        safe_extract_zip(archive, tmp_path / "out", max_total_bytes=1024 * 1024)
    contains(str(excinfo.value), "expands beyond")


def test_corrupt_and_password_protected_archives_raise_typed_errors(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.zip"
    corrupt.write_bytes(b"definitely not a zip archive")
    with pytest.raises(AttachmentSecurityError) as excinfo:
        safe_extract_zip(corrupt, tmp_path / "out")
    contains(str(excinfo.value), "cannot extract")
    encrypted = tmp_path / "encrypted.zip"
    with zipfile.ZipFile(encrypted, "w") as bundle:
        bundle.writestr("plain.txt", b"secret content")
    with zipfile.ZipFile(encrypted) as bundle:
        eq(len(bundle.infolist()), 1)


def test_over_long_names_are_truncated_by_bytes_not_characters(tmp_path: Path) -> None:
    """Filesystems cap names in bytes: 200 emoji are 800 bytes."""
    name = sanitize_filename("\U0001f4a9" * 200 + ".bin")
    ok(len(name.encode("utf-8")) <= 255, f"{len(name.encode('utf-8'))} bytes")
    target = write_attachment(base64.b64encode(b"x").decode(), tmp_path, "\U0001f4a9" * 200)
    ok(target.exists())


def test_archive_member_names_are_length_limited(tmp_path: Path) -> None:
    archive = tmp_path / "long.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("x" * 300 + ".txt", b"content")
    extracted = safe_extract_zip(archive, tmp_path / "out")
    eq(len(extracted), 1)
    ok(len(extracted[0].name.encode("utf-8")) <= 255)


def test_safe_extract_zip_sanitizes_windows_hostile_member_names(tmp_path: Path) -> None:
    """Member components get the same treatment as download filenames.

    "report.txt:payload" stays under the destination, so the traversal check
    passes it, but on Windows it writes an NTFS alternate data stream instead
    of a visible file.
    """
    archive = _make_zip(
        tmp_path / "hostile.zip",
        {"nested/report.txt:payload": b"ads", "CON": b"device", 'we"ird|name.txt': b"chars"},
    )
    extracted = safe_extract_zip(archive, tmp_path / "out")
    names = sorted(path.name for path in extracted)
    for name in names:
        not_contains(name, ":")
        not_contains(name, '"')
        not_contains(name, "|")
    not_contains(names, "CON")


def test_a_rejected_extraction_leaves_nothing_on_disk(tmp_path: Path) -> None:
    """ "Extraction rejected" has to mean nothing was written.

    The truncated member — and every member extracted before it — used to stay
    in the destination, so a caller that treated the error as "no output"
    still found attacker-controlled bytes there.
    """
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("first.txt", b"harmless")
        bundle.writestr("zeros.bin", b"\0" * (4 * 1024 * 1024))
    destination = tmp_path / "out"
    with pytest.raises(AttachmentSecurityError):
        safe_extract_zip(archive, destination, max_total_bytes=1024 * 1024)
    eq(sorted(path.name for path in destination.iterdir()), [])


def test_two_members_of_the_same_name_are_refused_not_overwritten(tmp_path: Path) -> None:
    """O_TRUNC let a second member replace the first without a word.

    Distinct member names collide once sanitized — as do names differing only
    in case, which are one file on macOS and Windows. write_attachment already
    refused to overwrite; extraction did not.
    """
    archive = tmp_path / "dup.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("report_x.txt", b"BENIGN")
        bundle.writestr("report|x.txt", b"MALICIOUS")
    destination = tmp_path / "out"
    with pytest.raises(AttachmentSecurityError):
        safe_extract_zip(archive, destination)
    eq(sorted(path.name for path in destination.iterdir()), [])


def test_write_attachment_reports_an_unwritable_destination_as_typed(tmp_path: Path) -> None:
    """safe_extract_zip already typed this failure; the two must not diverge."""
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    with pytest.raises(AttachmentSecurityError):
        write_attachment(base64.b64encode(b"payload").decode(), blocked / "sub", "f.bin")


def test_a_rejected_extraction_leaves_no_attacker_named_directories(tmp_path: Path) -> None:
    """ "Nothing was written" has to include the tree the members created.

    Removing only the files left the member's own directory names behind, so
    attacker-chosen paths survived an error the caller reads as "no output".
    """
    archive = tmp_path / "nested.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("evil-c2-campaign/stage1/first.txt", b"harmless")
        bundle.writestr("evil-c2-campaign/stage1/zeros.bin", b"\0" * (4 * 1024 * 1024))
    destination = tmp_path / "out"
    with pytest.raises(AttachmentSecurityError):
        safe_extract_zip(archive, destination, max_total_bytes=1024 * 1024)
    eq(sorted(str(p.relative_to(destination)) for p in destination.rglob("*")), [])


def test_extraction_still_creates_the_nested_tree_it_needs(tmp_path: Path) -> None:
    archive = _make_zip(tmp_path / "deep.zip", {"sub/deeper/a.txt": b"A"})
    extracted = safe_extract_zip(archive, tmp_path / "out")
    eq(len(extracted), 1)
    eq(extracted[0].read_bytes(), b"A")


def test_cleanup_never_removes_what_the_extraction_did_not_create(tmp_path: Path) -> None:
    """Only this call's own files and directories are discarded.

    A destination reused across extractions holds directories and files the
    rejected call has no business deleting.
    """
    destination = tmp_path / "out"
    (destination / "sub").mkdir(parents=True)
    (destination / "sub" / "preexisting.txt").write_text("keep me", encoding="utf-8")
    archive = tmp_path / "mixed.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("sub/mine.txt", b"ours")
        bundle.writestr("fresh/zeros.bin", b"\0" * (4 * 1024 * 1024))
    with pytest.raises(AttachmentSecurityError):
        safe_extract_zip(archive, destination, max_total_bytes=1024 * 1024)
    eq(
        sorted(p.relative_to(destination).as_posix() for p in destination.rglob("*")),
        ["sub", "sub/preexisting.txt"],
    )
