"""Bounded source identity shared by product timing and live acceptance."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path, PurePosixPath

from pydantic import Field, field_validator, model_validator

from .models import FrozenModel

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REVISION_PATTERN = r"^[0-9a-f]{7,64}$"
_MANIFEST_FILES = frozenset(
    {
        "pyproject.toml",
        "uv.lock",
    }
)


def _manifest_files() -> frozenset[str]:
    return _MANIFEST_FILES


class SourceIdentityError(RuntimeError):
    """The bounded behavior source could not be identified safely."""


class SourceManifestEntry(FrozenModel):
    path: str = Field(min_length=1, max_length=256)
    sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or str(path) != value:
            raise ValueError("source manifest path must be canonical and relative")
        return value


class SourceIdentity(FrozenModel):
    git_head: str | None = Field(default=None, pattern=_REVISION_PATTERN)
    source_manifest: tuple[SourceManifestEntry, ...]
    source_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    behavior_tree_dirty: bool | None


class BuildIdentitySource(StrEnum):
    ENVIRONMENT = "environment"
    LOCAL_CHECKOUT = "local_checkout"
    UNAVAILABLE = "unavailable"
    LEGACY = "legacy"


class BuildIdentityUnavailableReason(StrEnum):
    INVALID_ENVIRONMENT = "invalid_environment"
    SOURCE_TREE_UNAVAILABLE = "source_tree_unavailable"
    LEGACY_RECORD = "legacy_record"


class BuildIdentity(FrozenModel):
    revision: str | None = Field(default=None, pattern=_REVISION_PATTERN)
    dirty: bool | None = None
    source_fingerprint: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    source: BuildIdentitySource
    unavailable_reason: BuildIdentityUnavailableReason | None = None

    @model_validator(mode="after")
    def validate_source(self) -> BuildIdentity:
        if self.source is BuildIdentitySource.ENVIRONMENT:
            if (
                self.revision is None
                or self.dirty is None
                or self.source_fingerprint is None
                or self.unavailable_reason is not None
            ):
                raise ValueError("environment build identity must be complete")
        elif self.source is BuildIdentitySource.LOCAL_CHECKOUT:
            if self.source_fingerprint is None or self.unavailable_reason is not None:
                raise ValueError("local build identity must have a fingerprint")
        elif self.source is BuildIdentitySource.UNAVAILABLE:
            if (
                self.revision is not None
                or self.dirty is not None
                or self.source_fingerprint is not None
                or self.unavailable_reason is None
            ):
                raise ValueError("unavailable build identity is inconsistent")
        elif (
            self.unavailable_reason is not BuildIdentityUnavailableReason.LEGACY_RECORD
        ):
            raise ValueError("legacy build identity must be explicitly marked")
        return self


def build_source_identity(repository: Path) -> SourceIdentity:
    """Hash the bounded behavior-relevant tree without retaining source content."""

    repository = Path(repository).resolve()
    relative_paths = _behavior_paths(repository)
    entries = tuple(
        SourceManifestEntry(
            path=path.as_posix(),
            sha256=hashlib.sha256(_read_regular_file(repository / path)).hexdigest(),
        )
        for path in relative_paths
    )
    canonical = json.dumps(
        [entry.model_dump(mode="json") for entry in entries],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return SourceIdentity(
        git_head=_git_head(repository),
        source_manifest=entries,
        source_fingerprint=hashlib.sha256(canonical).hexdigest(),
        behavior_tree_dirty=_behavior_tree_dirty(repository),
    )


def resolve_build_identity(
    repository: Path | None,
    *,
    environment: Mapping[str, str] | None = None,
) -> BuildIdentity:
    """Resolve one compact identity without mixing partial authorities."""

    selected_environment = os.environ if environment is None else environment
    revision = selected_environment.get("NEWSCLIP_BUILD_REVISION")
    dirty_value = selected_environment.get("NEWSCLIP_BUILD_DIRTY")
    fingerprint = selected_environment.get("NEWSCLIP_BUILD_SOURCE_FINGERPRINT")
    if any(value is not None for value in (revision, dirty_value, fingerprint)):
        dirty = _parse_dirty(dirty_value)
        if (
            revision is not None
            and re.fullmatch(_REVISION_PATTERN, revision)
            and dirty is not None
            and fingerprint is not None
            and re.fullmatch(_SHA256_PATTERN, fingerprint)
        ):
            return BuildIdentity(
                revision=revision,
                dirty=dirty,
                source_fingerprint=fingerprint,
                source=BuildIdentitySource.ENVIRONMENT,
            )
        return BuildIdentity(
            source=BuildIdentitySource.UNAVAILABLE,
            unavailable_reason=BuildIdentityUnavailableReason.INVALID_ENVIRONMENT,
        )
    if repository is None:
        return BuildIdentity(
            source=BuildIdentitySource.UNAVAILABLE,
            unavailable_reason=BuildIdentityUnavailableReason.SOURCE_TREE_UNAVAILABLE,
        )
    try:
        source = build_source_identity(repository)
    except (SourceIdentityError, OSError, ValueError):
        return BuildIdentity(
            source=BuildIdentitySource.UNAVAILABLE,
            unavailable_reason=BuildIdentityUnavailableReason.SOURCE_TREE_UNAVAILABLE,
        )
    return BuildIdentity(
        revision=source.git_head,
        dirty=source.behavior_tree_dirty,
        source_fingerprint=source.source_fingerprint,
        source=BuildIdentitySource.LOCAL_CHECKOUT,
    )


def legacy_build_identity(
    revision: str | None,
    dirty: bool | None,
) -> BuildIdentity:
    """Represent callers and retained traces that predate compact provenance."""

    return BuildIdentity(
        revision=revision,
        dirty=dirty,
        source=BuildIdentitySource.LEGACY,
        unavailable_reason=BuildIdentityUnavailableReason.LEGACY_RECORD,
    )


def _behavior_paths(repository: Path) -> tuple[Path, ...]:
    candidates = {
        path.relative_to(repository)
        for path in (repository / "src/newsclip").rglob("*.py")
    }
    for definitions in ("provider_definitions",):
        candidates.update(
            path.relative_to(repository)
            for path in (repository / "src/newsclip" / definitions).glob("*.toml")
        )
    candidates.update(Path(value) for value in _manifest_files())
    missing = [path for path in candidates if not (repository / path).exists()]
    if missing:
        raise SourceIdentityError("behavior source manifest is incomplete")
    return tuple(sorted(candidates, key=lambda path: path.as_posix()))


def _read_regular_file(path: Path) -> bytes:
    try:
        if path.is_symlink():
            raise SourceIdentityError("behavior source cannot be a symlink")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise SourceIdentityError("behavior source must be a regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                return handle.read()
        finally:
            os.close(descriptor)
    except OSError as error:
        raise SourceIdentityError("behavior source could not be read") from error


def _git_head(repository: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    value = completed.stdout.strip()
    return (
        value
        if completed.returncode == 0 and re.fullmatch(_REVISION_PATTERN, value)
        else None
    )


def _behavior_tree_dirty(repository: Path) -> bool | None:
    try:
        tracked = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", *_git_pathspecs()],
            cwd=repository,
            capture_output=True,
            check=False,
        )
        untracked = subprocess.run(
            [
                "git",
                "ls-files",
                "--others",
                "--exclude-standard",
                "--",
                *_git_pathspecs(),
            ],
            cwd=repository,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if tracked.returncode not in {0, 1} or untracked.returncode != 0:
        return None
    return tracked.returncode == 1 or bool(untracked.stdout.strip())


def _git_pathspecs() -> tuple[str, ...]:
    return (
        "src/newsclip/*.py",
        "src/newsclip/**/*.py",
        "src/newsclip/provider_definitions/*.toml",
        *_manifest_files(),
    )


def _parse_dirty(value: str | None) -> bool | None:
    if value == "1":
        return True
    if value == "0":
        return False
    return None
