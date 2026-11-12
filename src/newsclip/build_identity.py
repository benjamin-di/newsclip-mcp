"""Immutable installed build identity; no runtime Git or environment authority."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution, version
from pathlib import Path
from typing import Literal, TypedDict
from uuid import uuid4

from .models import FrozenModel


@dataclass(frozen=True)
class ApplicationBuild:
    service: Literal["newsclip"]
    version: str
    source_revision: str
    source_fingerprint: str | None = None
    dirty: bool | None = None


class DiagnosticIdentity(FrozenModel):
    """Optional only for historical retained records; writers supply all fields."""

    service: Literal["newsclip"] | None = None
    version: str | None = None
    source_revision: str | None = None
    instance: str | None = None


def _object(pairs: list[tuple[str, object]]) -> dict:
    data = dict(pairs)
    if len(data) != len(pairs):
        raise ValueError("Duplicate application build identity fields")
    return data


def _source_development() -> bool:
    try:
        installed = distribution("newsclip")
    except PackageNotFoundError:
        return False
    try:
        direct = json.loads(installed.read_text("direct_url.json") or "{}")
    except (TypeError, ValueError):
        return False
    return (
        isinstance(direct, dict)
        and isinstance(direct.get("dir_info"), dict)
        and direct["dir_info"].get("editable") is True
    )


def load_build(path: Path | None = None) -> ApplicationBuild:
    try:
        product_version = version("newsclip")
    except PackageNotFoundError:
        product_version = "dev"
    path = path if path is not None else Path(__file__).with_name("build_identity.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object)
    except FileNotFoundError:
        if not _source_development():
            raise ValueError(
                "Missing application build identity in installed package"
            ) from None
        return ApplicationBuild("newsclip", product_version, "unknown")
    except (ValueError, UnicodeError) as error:
        raise ValueError("Invalid application build identity") from error
    if (
        not isinstance(data, dict)
        or set(data)
        != {"service", "version", "source_revision", "source_fingerprint", "dirty"}
        or data["service"] != "newsclip"
        or data["version"] != product_version
        or not isinstance(data["source_revision"], str)
        or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", data["source_revision"])
        or not isinstance(data["source_fingerprint"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", data["source_fingerprint"])
        or not isinstance(data["dirty"], bool)
    ):
        raise ValueError(
            "Application build identity conflicts with the installed package"
        )
    return ApplicationBuild(**data)


BUILD = load_build()


_INSTANCE = uuid4().hex


def _after_fork() -> None:
    global _INSTANCE
    _INSTANCE = uuid4().hex


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


class LogFields(TypedDict):
    service: Literal["newsclip"]
    version: str
    source_revision: str
    instance: str


def log_fields() -> LogFields:
    return {
        "service": BUILD.service,
        "version": BUILD.version,
        "source_revision": BUILD.source_revision,
        "instance": _INSTANCE,
    }
