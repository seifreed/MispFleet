"""1Password credential provider backed by the ``op`` CLI.

Secrets are referenced as ``op://vault/item/field`` and resolved by running
``op read`` locally; the secret value only ever lives in the pipe between the
CLI and this process.
"""

from __future__ import annotations

import os
import shutil

# subprocess only ever launches the ``op`` binary resolved through
# shutil.which, with a fixed argv list and no shell, so there is no shell
# interpretation and no injection surface.
import subprocess  # nosec B404

from mispfleet.exceptions import CredentialResolutionError

_KEY_PREFIX = "op://"


class OnePasswordCredentialProvider:
    """Resolves ``op://`` secret references through the 1Password CLI."""

    def __init__(self, executable: str = "op") -> None:
        self._executable = executable

    def resolve(self, key: str) -> str:
        """Run ``op read`` for ``key`` and return the secret it prints."""
        if not key.startswith(_KEY_PREFIX):
            raise CredentialResolutionError(
                f"1Password references must start with {_KEY_PREFIX!r}, got {key!r}"
            )
        executable = shutil.which(self._executable)
        if executable is None:
            raise CredentialResolutionError(
                f"the 1Password CLI {self._executable!r} was not found on PATH"
            )
        try:
            # argv[0] is a full path from shutil.which and there is no shell,
            # so the op:// reference travels as a plain argument, never as code.
            completed = subprocess.run(  # nosec B603
                [executable, "read", key, "--no-newline"],
                capture_output=True,
                env=dict(os.environ),
                check=False,
            )
        except OSError as error:
            # `which` found it a moment ago, so a start failure here means the
            # binary lost its exec bit or vanished; the provider contract
            # promises a typed error rather than a raw OSError.
            raise CredentialResolutionError(
                f"the 1Password CLI {self._executable!r} could not be started: {error}"
            ) from error
        if completed.returncode != 0:
            raise CredentialResolutionError(
                f"the 1Password CLI could not read {key!r}; run 'op read {key}' to diagnose"
            )
        try:
            secret = completed.stdout.decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise CredentialResolutionError(
                f"the 1Password CLI returned non-UTF-8 output for {key!r}"
            ) from error
        if not secret:
            raise CredentialResolutionError(f"the 1Password CLI returned no value for {key!r}")
        return secret
