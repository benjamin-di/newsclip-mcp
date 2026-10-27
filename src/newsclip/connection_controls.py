"""Durable user-scoped provider controls, separate from identity-provider sessions."""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from .account_keys import require_account_key
from .errors import PersistenceError, SessionRequiredError
from .private_state import atomic_private_write, exclusive_lock
from .provider_keys import is_provider_key
from .tenancy import read_private_file


class ConnectionControls:
    """Legacy unadopted records may be active; adopted or required records fail closed.

    Phase 0 is active, 1 disconnected, 2 cleanup pending and 3 an explicit
    reconnect awaiting independently verified publication. The record lock is
    held only for short control or final-publication operations.
    """

    def __init__(self, root: Path, *, clock=time.time, require_existing=None):
        self.root = Path(root) / "connections"
        self.clock = clock
        self.required = (
            os.environ.get("CONNECTIONS_REQUIRE_CONTROLS", "0") != "0"
            if require_existing is None
            else require_existing
        )

    def marker(self, path):
        return self.root.parent / (".connection-" + path.stem + "-initialized")

    def mark(self, path):
        marker = self.marker(path)
        if not marker.exists():
            atomic_private_write(marker, b"1\n")

    def initialize(self, provider, account="default"):
        with self.edit(provider, account):
            pass
        return self.status(provider, account)

    def path(self, provider, account="default"):
        if not is_provider_key(provider):
            raise ValueError("invalid provider")
        account = require_account_key(account)
        key = hashlib.sha256(account.encode()).hexdigest()[:24]
        return self.root / f"{provider}-{key}.json"

    def _directory(self):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = self.root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.getuid()
        ):
            raise PersistenceError(
                "connection controls require an owned private directory"
            )

    def _read(self, path):
        try:
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
                or info.st_uid != os.getuid()
            ):
                raise ValueError("private record")
            value = json.loads(read_private_file(path, max_bytes=4096))
            if (
                not isinstance(value, dict)
                or not isinstance(value.get("revision"), str)
                or not 1 <= len(value["revision"]) <= 128
                or type(value.get("phase")) is not int
                or value["phase"] not in range(4)
                or type(value.get("human_until", 0)) not in (int, float)
                or not math.isfinite(value.get("human_until", 0))
            ):
                raise ValueError("invalid record")
            self.mark(path)
            return value
        except FileNotFoundError:
            if (
                self.required
                or self.marker(path).exists()
                or self.marker(path).is_symlink()
            ):
                raise PersistenceError(
                    "connection controls are missing; access remains stopped"
                ) from None
            return {"revision": "initial", "phase": 0}
        except (OSError, ValueError, TypeError):
            raise PersistenceError("connection controls cannot be verified") from None

    def status(self, provider, account="default"):
        if self.root.exists() or self.root.is_symlink():
            self._directory()
        return self._read(self.path(provider, account))

    @contextmanager
    def edit(self, provider, account="default"):
        self._directory()
        path = self.path(provider, account)
        with exclusive_lock(path.with_suffix(".lock"), timeout_seconds=5):
            value = self._read(path)
            yield value
            self.mark(path)
            atomic_private_write(path, json.dumps(value).encode())

    def require_active(self, provider, account="default"):
        if self.status(provider, account)["phase"]:
            raise SessionRequiredError("connection_disconnected")

    def maintenance_blocker(self, provider, account="default"):
        value = self.status(provider, account)
        if value["phase"]:
            return "connection_disconnected"
        if value.get("human_until", 0) > self.clock():
            return "connection_interactive"
        return None

    def require_maintenance(self, provider, account="default"):
        blocker = self.maintenance_blocker(provider, account)
        if blocker:
            raise SessionRequiredError(blocker)

    def current(self, provider, account, revision):
        value = self.status(provider, account)
        return value["phase"] in (0, 3) and value["revision"] == revision

    def begin(self, provider, account="default"):
        with self.edit(provider, account) as value:
            if value["phase"] == 2:
                raise SessionRequiredError("connection_disconnected")
            value.update(
                revision=secrets.token_urlsafe(24),
                phase=3 if value["phase"] else 0,
                human_until=self.clock() + 600,
            )
            return value["revision"]

    def cancel(self, provider, account, revision):
        with self.edit(provider, account) as value:
            if value["phase"] == 2 or value["revision"] != revision:
                return
            value.update(revision=secrets.token_urlsafe(24))
            value.pop("human_until", None)

    def started(self, provider, account, revision):
        with self.edit(provider, account) as value:
            if value["phase"] not in (0, 3) or value["revision"] != revision:
                raise SessionRequiredError("connection_disconnected")
            value["human_until"] = self.clock() + 600

    def suspend(self, provider, account="default", *, expected_revision=None):
        with self.edit(provider, account) as value:
            if expected_revision is not None and value["revision"] != expected_revision:
                return None
            value.clear()
            value.update(revision=secrets.token_urlsafe(24), phase=2)
            return value["revision"]

    def disconnect_current(self, provider, account, revision):
        value = self.status(provider, account)
        return value["phase"] == 2 and value["revision"] == revision

    def disconnected(self, provider, account="default", *, revision):
        with self.edit(provider, account) as value:
            if value["phase"] != 2 or value["revision"] != revision:
                return
            value.clear()
            value.update(revision=secrets.token_urlsafe(24), phase=1)

    @contextmanager
    def publication(self, provider, account, *, revision=None, authority=True):
        self._directory()
        path = self.path(provider, account)
        with exclusive_lock(path.with_suffix(".lock"), timeout_seconds=5):
            value = self._read(path)
            if revision is not None:
                if (
                    value["phase"] not in (0, 3)
                    or value["revision"] != revision
                    or value.get("human_until", 0) <= self.clock()
                ):
                    raise SessionRequiredError("connection_disconnected")
            elif authority and (
                value["phase"] or value.get("human_until", 0) > self.clock()
            ):
                raise SessionRequiredError("connection_disconnected")
            yield
            if revision is not None:
                value["phase"] = 0
                value.pop("human_until", None)
                atomic_private_write(path, json.dumps(value).encode())


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Initialize reviewed publisher controls once"
    )
    parser.add_argument("--initialize", action="store_true", required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--provider", action="append", required=True)
    parser.add_argument("--account", default="default")
    args = parser.parse_args()
    controls = ConnectionControls(args.root, require_existing=False)
    for provider in args.provider:
        controls.initialize(provider, args.account)
