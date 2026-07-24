"""A real, ephemeral MariaDB server for integration tests.

Spawned with :func:`os.posix_spawn` from the locally installed MariaDB
distribution; CI environments provide a ready server through the
``MISPFLEET_TEST_MARIADB_DSN`` environment variable instead.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import tempfile
import time
from pathlib import Path

import pymysql

TEST_DATABASE = "mispfleet_test"

_CANDIDATE_DIRS = (
    "/opt/homebrew/opt/mariadb/bin",
    "/opt/homebrew/opt/mariadb@11.4/bin",
    "/usr/local/opt/mariadb/bin",
    "/usr/sbin",
    "/usr/bin",
)


def find_binary(name: str) -> str | None:
    """Locate a MariaDB binary in PATH or the usual install prefixes."""
    found = shutil.which(name)
    if found:
        return found
    for directory in _CANDIDATE_DIRS:
        candidate = Path(directory) / name
        if candidate.is_file():
            return str(candidate)
    return None


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _spawn(argv: list[str]) -> int:
    """Start a process with stdout/stderr sent to /dev/null."""
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        return os.posix_spawn(
            argv[0],
            argv,
            dict(os.environ),
            file_actions=[
                (os.POSIX_SPAWN_DUP2, devnull, 1),
                (os.POSIX_SPAWN_DUP2, devnull, 2),
            ],
        )
    finally:
        os.close(devnull)


class EphemeralMariaDB:
    """Initializes and runs a throwaway MariaDB instance on a random port."""

    def __init__(self) -> None:
        self.port = _free_port()
        self.datadir = Path(tempfile.mkdtemp(prefix="mfleet-db-"))
        self._pid: int | None = None

    @property
    def dsn(self) -> str:
        """DSN pointing at the ephemeral test database."""
        return f"mysql://root@127.0.0.1:{self.port}/{TEST_DATABASE}"

    def start(self, timeout: float = 60.0) -> None:
        """Initialize the datadir, boot the server and create the database."""
        installer = find_binary("mariadb-install-db")
        server = find_binary("mariadbd")
        if installer is None or server is None:
            raise RuntimeError(
                "MariaDB binaries not found; install mariadb or set "
                "MISPFLEET_TEST_MARIADB_DSN to a running server"
            )
        install_pid = _spawn(
            [
                installer,
                "--no-defaults",
                f"--datadir={self.datadir}",
                "--auth-root-authentication-method=normal",
                "--skip-test-db",
            ]
        )
        _, status = os.waitpid(install_pid, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError("mariadb-install-db failed")
        self._pid = _spawn(
            [
                server,
                "--no-defaults",
                f"--datadir={self.datadir}",
                "--bind-address=127.0.0.1",
                f"--port={self.port}",
                f"--socket={self.datadir}/m.sock",
                "--skip-grant-tables",
            ]
        )
        self._wait_ready(timeout)

    def _wait_ready(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                connection = pymysql.connect(host="127.0.0.1", port=self.port, user="root")
            except pymysql.MySQLError as error:
                last_error = error
                time.sleep(0.3)
                continue
            with connection.cursor() as cursor:
                cursor.execute("CREATE DATABASE IF NOT EXISTS mispfleet_test")
            connection.close()
            return
        raise RuntimeError(f"MariaDB did not become ready in {timeout}s: {last_error}")

    def stop(self) -> None:
        """Terminate the server and remove its data directory."""
        if self._pid is not None:
            os.kill(self._pid, signal.SIGTERM)
            os.waitpid(self._pid, 0)
            self._pid = None
        shutil.rmtree(self.datadir, ignore_errors=True)
