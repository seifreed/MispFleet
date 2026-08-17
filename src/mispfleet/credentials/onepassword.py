"""1Password credential provider backed by the ``op`` CLI.

Secrets are referenced as ``op://vault/item/field`` and resolved by running
``op read`` locally; the secret value only ever lives in the pipe between the
CLI and this process.
"""

from __future__ import annotations

import os
import shutil

from mispfleet.exceptions import CredentialResolutionError

_KEY_PREFIX = "op://"


class OnePasswordCredentialProvider:
    """Resolves ``op://`` secret references through the 1Password CLI."""

    def __init__(self, executable: str = "op", spawn_supported: bool | None = None) -> None:
        self._executable = executable
        # os.posix_spawn and its file actions do not exist on Windows; the
        # flag is injectable so the unsupported path is exercised anywhere.
        self._spawn_supported = (
            hasattr(os, "posix_spawn") if spawn_supported is None else spawn_supported
        )

    def resolve(self, key: str) -> str:
        """Run ``op read`` for ``key`` and return the secret it prints."""
        if not key.startswith(_KEY_PREFIX):
            raise CredentialResolutionError(
                f"1Password references must start with {_KEY_PREFIX!r}, got {key!r}"
            )
        if not self._spawn_supported:
            raise CredentialResolutionError(
                "the 1Password provider needs a POSIX platform; on Windows, "
                "resolve the secret with 'op read' and pass it through the "
                "'env' provider instead"
            )
        executable = shutil.which(self._executable)
        if executable is None:
            raise CredentialResolutionError(
                f"the 1Password CLI {self._executable!r} was not found on PATH"
            )
        read_fd, write_fd = os.pipe()
        try:
            pid = os.posix_spawn(
                executable,
                [executable, "read", key, "--no-newline"],
                dict(os.environ),
                file_actions=[
                    (os.POSIX_SPAWN_DUP2, write_fd, 1),
                    (os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0o644),
                ],
            )
        except OSError as error:
            # `which` found it a moment ago, so a spawn failure here means the
            # binary lost its exec bit or vanished. The provider contract
            # promises a typed error, and the read end leaked with the raw one.
            os.close(read_fd)
            raise CredentialResolutionError(
                f"the 1Password CLI {self._executable!r} could not be started: {error}"
            ) from error
        finally:
            os.close(write_fd)
        try:
            chunks = []
            while chunk := os.read(read_fd, 4096):
                chunks.append(chunk)
        finally:
            os.close(read_fd)
        _, status = os.waitpid(pid, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            raise CredentialResolutionError(
                f"the 1Password CLI could not read {key!r}; run 'op read {key}' to diagnose"
            )
        try:
            secret = b"".join(chunks).decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise CredentialResolutionError(
                f"the 1Password CLI returned non-UTF-8 output for {key!r}"
            ) from error
        if not secret:
            raise CredentialResolutionError(f"the 1Password CLI returned no value for {key!r}")
        return secret
