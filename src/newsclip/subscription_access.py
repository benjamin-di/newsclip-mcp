"""Application-owned sharing records; credentials and native controls stay in place."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

import account_connections as sharing
from signin_window.state import read_private_file as _read_private_file

from .errors import PersistenceError, SessionRequiredError
from .private_state import atomic_private_write, exclusive_lock, fsync_directory
from .provider_keys import is_provider_key
from .tenancy import load_users, require_user

_REVISION = re.compile(r"[a-f0-9]{32}\Z")
_USE = frozenset({"subscription"})


def read_private_file(path, *, max_bytes):
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("owned private file required")
    return _read_private_file(path, max_bytes=max_bytes)


def _selection(row):
    value = row["selection"]
    return sharing.Selection(
        sharing.Choice(value["owner"], value["grant"]) if value else None,
        row["revision"],
    )


def _save_selection(row, value):
    row.update(
        selection={"owner": value.choice.owner, "grant": value.choice.grant_revision}
        if value.choice
        else None,
        revision=value.revision,
    )


def _grant(row):
    return sharing.Grant(row, _USE) if row is not None else None


def _rules(operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except sharing.ConnectionError as error:
        raise SessionRequiredError(error.code) from None


@dataclass(frozen=True)
class Admission:
    actor: str
    provider: str
    selected: sharing.Selection

    @property
    def owner(self):
        assert self.selected.choice is not None
        return self.selected.choice.owner


class SubscriptionAccess:
    """One short process-safe lock precedes native controls and profile leases.

    Bootstrap is explicit at host startup. Reads never initialize or repair state.
    Records are separate so an unrelated damaged user cannot hide healthy controls.
    The manifest enrolls users before their file appears; interrupted enrollment
    stays stopped and requires recovery, never reconstruction around old authority.
    """

    def __init__(self, root: Path, users_path: Path):
        self.parent = Path(root)
        self.root = self.parent / "subscription-access"
        self.marker = self.parent / ".subscription-access-adopted"
        self.users_path = users_path

    def lock(self):
        return exclusive_lock(
            self.parent / ".subscription-access.lock", timeout_seconds=10
        )

    def users(self):
        return {user.id for user in load_users(self.users_path)}

    def _private_directory(self):
        info = self.root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("private directory required")

    def _manifest(self):
        self._private_directory()
        value = json.loads(
            read_private_file(self.root / "manifest.json", max_bytes=32768)
        )
        if (
            not isinstance(value, dict)
            or set(value) != {"version", "users", "providers"}
            or type(value["version"]) is not int
            or value["version"] != 1
            or not isinstance(value["users"], list)
            or len(value["users"]) > 100
            or len(set(value["users"])) != len(value["users"])
        ):
            raise ValueError("invalid manifest")
        for user in value["users"]:
            require_user(user)
        providers = value["providers"]
        if (
            not isinstance(providers, list)
            or len(providers) > 100
            or len(set(providers)) != len(providers)
            or not all(is_provider_key(key) for key in providers)
        ):
            raise ValueError("invalid providers")
        return value

    def bootstrap(self, providers):
        """Adopt without touching credentials, controls, archives, holds or budgets."""
        self.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            with self.lock():
                users = self.users()
                providers = sorted(set(providers))
                if not all(is_provider_key(key) for key in providers):
                    raise ValueError("invalid providers")
                if not self.root.exists():
                    if self.marker.exists() or self.root.is_symlink():
                        raise ValueError("adopted controls lost")
                    staging = self.parent / (
                        ".subscription-new-" + secrets.token_hex(8)
                    )
                    staging.mkdir(mode=0o700)
                    atomic_private_write(
                        staging / "manifest.json",
                        json.dumps(
                            {
                                "version": 1,
                                "users": sorted(users),
                                "providers": providers,
                            }
                        ).encode(),
                    )
                    for user in users:
                        atomic_private_write(
                            staging / (user + ".json"), self._initial(user, providers)
                        )
                    staging.rename(self.root)
                    fsync_directory(self.parent)
                manifest = self._manifest()
                # Existing publisher namespaces are immutable in this schema.
                # New publishers need an explicit migration, never reader repair.
                if not set(providers) <= set(manifest["providers"]):
                    raise ValueError("new publishers require a sharing-state migration")
                for user in sorted(users - set(manifest["users"])):
                    if self.path(user).exists():
                        raise ValueError("unexpected retained user record")
                    manifest["users"].append(user)
                    atomic_private_write(
                        self.root / "manifest.json", json.dumps(manifest).encode()
                    )
                    atomic_private_write(
                        self.path(user), self._initial(user, manifest["providers"])
                    )
                atomic_private_write(self.marker, b"1\n")
        except (OSError, ValueError, TypeError):
            raise PersistenceError(
                "subscription controls cannot be adopted; "
                "retained state was not repaired"
            ) from None

    @staticmethod
    def _initial(user, providers):
        return json.dumps(
            {
                "version": 1,
                "providers": {
                    key: {
                        "selection": {"owner": user, "grant": None},
                        "revision": sharing.revision(),
                        "grants": {},
                    }
                    for key in providers
                },
            }
        ).encode()

    def path(self, user):
        return self.root / (require_user(user) + ".json")

    def _read(self, user, *, adopted=True):
        try:
            if adopted and read_private_file(self.marker, max_bytes=16) != b"1\n":
                raise ValueError("missing adoption marker")
            manifest = self._manifest()
            if user not in manifest["users"]:
                raise ValueError("user not enrolled")
            value = json.loads(
                read_private_file(self.path(user), max_bytes=1024 * 1024)
            )
            if (
                not isinstance(value, dict)
                or set(value) != {"version", "providers"}
                or type(value["version"]) is not int
                or value["version"] != 1
                or not isinstance(value["providers"], dict)
                or len(value["providers"]) > 100
            ):
                raise ValueError("invalid sharing record")
            if set(value["providers"]) != set(manifest["providers"]):
                raise ValueError("publisher authority missing")
            for provider, row in value["providers"].items():
                if (
                    not is_provider_key(provider)
                    or not isinstance(row, dict)
                    or set(row) != {"selection", "revision", "grants"}
                ):
                    raise ValueError("invalid provider record")
                if not isinstance(row["revision"], str) or not _REVISION.fullmatch(
                    row["revision"]
                ):
                    raise ValueError("invalid selection revision")
                choice = row["selection"]
                if choice is not None:
                    if not isinstance(choice, dict) or set(choice) != {
                        "owner",
                        "grant",
                    }:
                        raise ValueError("invalid choice")
                    require_user(choice["owner"])
                    if choice["grant"] is not None and (
                        not isinstance(choice["grant"], str)
                        or not _REVISION.fullmatch(choice["grant"])
                    ):
                        raise ValueError("invalid grant reference")
                if not isinstance(row["grants"], dict) or len(row["grants"]) > 99:
                    raise ValueError("invalid grants")
                for member, grant in row["grants"].items():
                    require_user(member)
                    if (
                        member == user
                        or not isinstance(grant, str)
                        or not _REVISION.fullmatch(grant)
                    ):
                        raise ValueError("invalid grant")
            return value
        except (OSError, ValueError, TypeError, KeyError):
            raise PersistenceError(
                "subscription controls unavailable; "
                "ask the administrator to recover them"
            ) from None

    def _row(self, data, actor, provider):
        if not is_provider_key(provider):
            raise ValueError("invalid provider")
        try:
            return data["providers"][provider]
        except KeyError:
            raise PersistenceError("publisher sharing controls not adopted") from None

    def _write(self, actor, provider, data, row):
        data["providers"][provider] = row
        atomic_private_write(
            self.path(actor), json.dumps(data, sort_keys=True).encode()
        )

    def _eligible(self, *actors):
        if not set(actors) <= self.users():
            raise SessionRequiredError(
                "subscription access requires current registered users"
            )

    def _resolve(self, actor, provider):
        self._eligible(actor)
        row = self._row(self._read(actor), actor, provider)
        selected = _selection(row)
        grant = None
        if selected.choice and selected.choice.owner != actor:
            owner = selected.choice.owner
            self._eligible(owner)
            owner_row = self._row(self._read(owner), owner, provider)
            grant = _grant(owner_row["grants"].get(actor))
        _rules(sharing.resolve, actor, selected, grant, capability="subscription")
        return Admission(actor, provider, selected)

    def admit(self, actor, provider):
        with self.lock():
            return self._resolve(actor, provider)

    def revalidate(self, admitted):
        with self.lock():
            if self._resolve(admitted.actor, admitted.provider) != admitted:
                raise SessionRequiredError("account_changed")

    def view(self, actor, provider):
        with self.lock():
            self._eligible(actor)
            row = self._row(self._read(actor), actor, provider)
            offers, unavailable = [], False
            for owner in sorted(self.users() - {actor}):
                try:
                    candidate = self._row(self._read(owner), owner, provider)
                    if actor in candidate["grants"]:
                        offers.append((owner, candidate["grants"][actor]))
                except PersistenceError:
                    unavailable = True
            return row, offers, unavailable

    def choose(self, actor, provider, owner, expected, grant):
        with self.lock():
            self._eligible(actor, owner)
            data = self._read(actor)
            row = self._row(data, actor, provider)
            offered = (
                None
                if actor == owner
                else _grant(
                    self._row(self._read(owner), owner, provider)["grants"].get(actor)
                )
            )
            selected = _rules(
                sharing.choose,
                actor,
                _selection(row),
                sharing.Choice(owner, grant),
                offered,
                expected=expected,
            )
            _save_selection(row, selected)
            self._write(actor, provider, data, row)

    def share(self, owner, provider, member, expected):
        with self.lock():
            self._eligible(owner, member)
            if owner == member:
                raise ValueError("cannot share with self")
            self._read(member)
            data = self._read(owner)
            row = self._row(data, owner, provider)
            grant = _rules(
                sharing.offer,
                _grant(row["grants"].get(member)),
                expected=expected,
                capabilities=_USE,
            )
            row["grants"][member] = grant.revision
            self._write(owner, provider, data, row)

    def revoke(self, owner, provider, member, expected, *, leaving=False):
        with self.lock():
            # An owner may revoke a removed or damaged recipient without reading it.
            self._eligible(member if leaving else owner)
            data = self._read(owner)
            row = self._row(data, owner, provider)
            _rules(sharing.revoke, _grant(row["grants"].get(member)), expected=expected)
            del row["grants"][member]
            self._write(owner, provider, data, row)
            if leaving:
                data = self._read(member)
                row = self._row(data, member, provider)
                _save_selection(row, sharing.leave(_selection(row), owner))
                self._write(member, provider, data, row)
