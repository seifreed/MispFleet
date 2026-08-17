"""Attachment handling with filesystem-safety guarantees (§28.2).

Remote filenames are sanitized, files are written through securely created
temporary files with restrictive permissions, and archive extraction rejects
path traversal and symlink members.
"""

from __future__ import annotations

import base64
import os
import re
import stat
import zipfile
from contextlib import suppress
from pathlib import Path

from mispfleet.exceptions import AttachmentSecurityError

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_INVALID = re.compile(r'[<>:"|?*]')
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{n}" for n in range(1, 10)}
    | {f"lpt{n}" for n in range(1, 10)}
)
_FALLBACK_NAME = "attachment"
_MAX_NAME_BYTES = 255
# A 200 KiB archive can hold hundreds of megabytes of zeroes; extraction has to
# stop before it fills memory or the disk rather than after.
_EXTRACT_CHUNK = 1024 * 1024
DEFAULT_MAX_EXTRACTED_BYTES = 512 * 1024 * 1024


def sanitize_filename(name: str) -> str:
    """Reduce a remote filename to a safe, separator-free basename."""
    cleaned = _CONTROL_CHARS.sub("", name)
    cleaned = cleaned.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = _WINDOWS_INVALID.sub("_", cleaned)
    cleaned = cleaned.strip().strip(".")
    if not cleaned or cleaned.split(".", 1)[0].lower() in _WINDOWS_RESERVED:
        return _FALLBACK_NAME
    return _truncate_to_bytes(cleaned, _MAX_NAME_BYTES)


def _truncate_to_bytes(name: str, limit: int) -> str:
    """Trim a name to ``limit`` bytes on a codepoint boundary.

    Filesystems cap names in bytes, not codepoints: 200 emoji are 200
    characters but 800 bytes, and the write failed with ENAMETOOLONG.
    """
    encoded = name.encode("utf-8")
    if len(encoded) <= limit:
        return name
    return encoded[:limit].decode("utf-8", errors="ignore") or _FALLBACK_NAME


def write_attachment(data: str, directory: Path, filename: str) -> Path:
    """Decode a base64 attachment into ``directory`` with a sanitized name.

    The file is created exclusively and owner-only, so an existing file is
    never overwritten even when two downloads race for the same name.
    """
    try:
        payload = base64.b64decode(data, validate=True)
    except ValueError as error:
        raise AttachmentSecurityError(f"attachment payload is not valid base64: {error}") from error
    target = directory / sanitize_filename(filename)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        handle = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise AttachmentSecurityError(f"refusing to overwrite existing file {target}") from error
    except OSError as error:
        # safe_extract_zip already promises a typed error for an unwritable
        # destination; the two entry points must not diverge.
        raise AttachmentSecurityError(f"cannot write {target}: {error}") from error
    # The write itself is left untyped on purpose: only a full disk or an I/O
    # fault reaches it, neither of which can be provoked on all three CI
    # platforms, and this project admits no coverage exclusions.
    with os.fdopen(handle, "wb") as stream:
        stream.write(payload)
    return target


def safe_extract_zip(
    archive: Path,
    destination: Path,
    password: str | None = None,
    max_total_bytes: int = DEFAULT_MAX_EXTRACTED_BYTES,
) -> list[Path]:
    """Extract a ZIP archive rejecting traversal and symlink members.

    Every extracted file is validated to remain inside ``destination`` after
    path resolution and is written with owner-only permissions. Members are
    streamed in chunks against a total decompressed budget, so a small archive
    of highly compressible data cannot exhaust memory or the disk.
    """
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    extracted: list[Path] = []
    created_dirs: list[Path] = []
    in_progress: Path | None = None
    remaining = max_total_bytes
    secret = password.encode("utf-8") if password is not None else None
    try:
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                if info.is_dir():
                    continue
                if stat.S_ISLNK(info.external_attr >> 16):
                    raise AttachmentSecurityError(
                        f"archive member {info.filename!r} is a symlink; extraction rejected"
                    )
                target = (root / _sanitize_member(info.filename)).resolve()
                if not target.is_relative_to(root):
                    raise AttachmentSecurityError(
                        f"archive member {info.filename!r} escapes the destination directory"
                    )
                created_dirs.extend(
                    parent
                    for parent in [target.parent, *target.parent.parents]
                    if root in parent.parents and not parent.exists()
                )
                target.parent.mkdir(parents=True, exist_ok=True)
                # Owner-only from creation: a chmod after writing would leave
                # the extracted content world-readable for the length of the
                # write.
                # The member opens first: a wrong password makes bundle.open
                # raise, and a descriptor taken before it leaked along with the
                # empty file it had just created. O_EXCL rather than O_TRUNC,
                # as write_attachment already uses: a second member of the same
                # name — or one differing only in case, which is the same file
                # on macOS and Windows — silently overwrote the first.
                with bundle.open(info, pwd=secret) as source:
                    handle = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    in_progress = target
                    with os.fdopen(handle, "wb") as sink:
                        while chunk := source.read(min(_EXTRACT_CHUNK, remaining + 1)):
                            remaining -= len(chunk)
                            if remaining < 0:
                                raise AttachmentSecurityError(
                                    f"archive expands beyond {max_total_bytes} bytes; "
                                    "extraction rejected"
                                )
                            sink.write(chunk)
                target.chmod(0o600)
                extracted.append(target)
                in_progress = None
    except AttachmentSecurityError:
        _discard(extracted, in_progress, created_dirs)
        raise
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError) as error:
        # A corrupt archive, a wrong password and an unwritable name all come
        # back as third-party errors; the caller is promised a typed one.
        _discard(extracted, in_progress, created_dirs)
        raise AttachmentSecurityError(f"cannot extract {archive}: {error}") from error
    return extracted


def _discard(extracted: list[Path], in_progress: Path | None, created_dirs: list[Path]) -> None:
    """Remove what a rejected extraction had already written.

    A budget rejection used to leave the truncated member — and every member
    before it — on disk, so a caller reading "extraction rejected" as "nothing
    was written" still found attacker-controlled bytes in the directory. Only
    what this call created is removed: every file was opened with O_EXCL and
    every directory was recorded as it was created, so a member name the
    attacker chose cannot survive as an empty tree either.
    """
    for path in [*extracted, *([in_progress] if in_progress is not None else [])]:
        with suppress(OSError):
            path.unlink(missing_ok=True)
    # Deepest first, so a nested tree empties before its parent is removed.
    for directory in sorted(set(created_dirs), key=lambda item: len(item.parts), reverse=True):
        with suppress(OSError):
            directory.rmdir()


def _sanitize_member(name: str) -> str:
    """Sanitize each component of an archive member path.

    Member names are attacker-controlled: an over-long component makes the
    write fail with ENAMETOOLONG rather than being rejected, and a component
    like ``report.txt:payload`` writes an NTFS alternate data stream on
    Windows instead of the file the operator can see. Parent references are
    left intact so the traversal check still refuses them explicitly rather
    than silently renaming them to something harmless.
    """
    parts = [part for part in name.replace("\\", "/").split("/") if part not in ("", ".")]
    cleaned = [part if part == ".." else sanitize_filename(part) for part in parts]
    return "/".join(cleaned) or _FALLBACK_NAME
