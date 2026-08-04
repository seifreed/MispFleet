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
import tempfile
import zipfile
from pathlib import Path

from mispfleet.exceptions import AttachmentSecurityError

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{n}" for n in range(1, 10)}
    | {f"lpt{n}" for n in range(1, 10)}
)
_FALLBACK_NAME = "attachment"


def sanitize_filename(name: str) -> str:
    """Reduce a remote filename to a safe, separator-free basename."""
    cleaned = _CONTROL_CHARS.sub("", name)
    cleaned = cleaned.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = cleaned.strip().strip(".")
    if not cleaned or cleaned.split(".", 1)[0].lower() in _WINDOWS_RESERVED:
        return _FALLBACK_NAME
    return cleaned[:255]


def write_attachment(data: str, directory: Path, filename: str) -> Path:
    """Decode a base64 attachment into ``directory`` with a sanitized name.

    The payload lands in a securely created temporary file (0600) inside the
    destination directory and is atomically renamed into place; an existing
    file is never overwritten.
    """
    try:
        payload = base64.b64decode(data, validate=True)
    except ValueError as error:
        raise AttachmentSecurityError(f"attachment payload is not valid base64: {error}") from error
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / sanitize_filename(filename)
    if target.exists():
        raise AttachmentSecurityError(f"refusing to overwrite existing file {target}")
    handle, temp_name = tempfile.mkstemp(dir=directory)
    with os.fdopen(handle, "wb") as stream:
        stream.write(payload)
    Path(temp_name).replace(target)
    return target


def safe_extract_zip(
    archive: Path,
    destination: Path,
    password: str | None = None,
) -> list[Path]:
    """Extract a ZIP archive rejecting traversal and symlink members.

    Every extracted file is validated to remain inside ``destination`` after
    path resolution and is written with owner-only permissions.
    """
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    extracted: list[Path] = []
    secret = password.encode("utf-8") if password is not None else None
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            if info.is_dir():
                continue
            if stat.S_ISLNK(info.external_attr >> 16):
                raise AttachmentSecurityError(
                    f"archive member {info.filename!r} is a symlink; extraction rejected"
                )
            target = (root / info.filename).resolve()
            if not target.is_relative_to(root):
                raise AttachmentSecurityError(
                    f"archive member {info.filename!r} escapes the destination directory"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info, pwd=secret) as source, target.open("wb") as sink:
                sink.write(source.read())
            target.chmod(0o600)
            extracted.append(target)
    return extracted
