"""User identity and private storage boundaries for standalone installations."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from .private_state import atomic_private_write, exclusive_lock

_USER = re.compile(r"[a-z][a-z0-9_-]{0,47}\Z")
_CURRENT_USER: ContextVar[str | None] = ContextVar("newsclip_user", default=None)


def require_user(value: str) -> str:
    if not isinstance(value, str) or _USER.fullmatch(value) is None:
        raise ValueError(
            "user id must start with a letter and use 1–48 lowercase letters, "
            "digits, _ or -"
        )
    return value


@contextmanager
def user_scope(user: str | None) -> Iterator[None]:
    """Scope construction and callbacks without changing process environment."""

    token = _CURRENT_USER.set(require_user(user) if user is not None else None)
    try:
        yield
    finally:
        _CURRENT_USER.reset(token)


def application_root(environment_name: str, fallback: str) -> Path:
    configured = os.environ.get(environment_name)
    root = (
        Path(configured).expanduser()
        if configured
        else Path.home() / fallback / "newsclip"
    )
    return scope_path(root)


def current_user() -> str | None:
    return _CURRENT_USER.get()


def scope_path(root: Path) -> Path:
    user = current_user()
    return root if user is None else root / "users" / user


@dataclass(frozen=True)
class User:
    id: str
    token_sha256: str

    def accepts(self, token: str) -> bool:
        return hmac.compare_digest(
            self.token_sha256, hashlib.sha256(token.encode()).hexdigest()
        )


def load_users(path: Path) -> tuple[User, ...]:
    """Load a fail-closed, bounded registry. Tokens never appear in it."""

    if path.stat().st_size > 1024 * 1024:
        raise ValueError("user registry is too large")
    data = json.loads(path.read_text())
    if (
        not isinstance(data, dict)
        or data.get("version") != 1
        or set(data) != {"version", "users"}
    ):
        raise ValueError("invalid user registry")
    rows = data["users"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
        raise ValueError("configure between 1 and 100 users")
    users: list[User] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "token_sha256"}:
            raise ValueError("invalid user registry entry")
        identifier = require_user(row["id"])
        digest = row["token_sha256"]
        if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
            raise ValueError("invalid token hash")
        if any(user.id == identifier or user.token_sha256 == digest for user in users):
            raise ValueError("duplicate user or token")
        users.append(User(identifier, digest))
    return tuple(users)


def add_user(
    path: Path, identifier: str, token_file: Path, *, rotate: bool = False
) -> None:
    """Create a token in a private file; refuse to overwrite unrelated files."""

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with exclusive_lock(path.with_suffix(".lock"), timeout_seconds=10):
        _add_user(path, identifier, token_file, rotate=rotate)


def _add_user(path: Path, identifier: str, token_file: Path, *, rotate: bool) -> None:
    identifier = require_user(identifier)
    users = list(load_users(path)) if path.exists() else []
    existing = next((user for user in users if user.id == identifier), None)
    if existing and not rotate:
        raise ValueError("user exists; use --rotate to replace their token")
    if token_file.exists() or token_file.is_symlink():
        raise ValueError("token file already exists; choose a new path")
    if not existing and len(users) >= 100:
        raise ValueError("at most 100 users are supported")
    token = secrets.token_urlsafe(32)
    token_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(token + "\n")
    replacement = User(identifier, hashlib.sha256(token.encode()).hexdigest())
    users = [user for user in users if user.id != identifier] + [replacement]
    try:
        atomic_private_write(
            path,
            json.dumps(
                {"version": 1, "users": [vars(user) for user in users]}
            ).encode(),
        )
    except BaseException:
        token_file.unlink()
        raise
