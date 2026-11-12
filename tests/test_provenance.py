from __future__ import annotations

from pathlib import Path

from newsclip import build_identity as application_identity
from newsclip.provenance import (
    BuildIdentitySource,
    BuildIdentityUnavailableReason,
    build_source_identity,
    resolve_build_identity,
)


def _repository(root: Path) -> Path:
    files = {
        "src/newsclip/__init__.py": b"VALUE = 1\n",
        "src/newsclip/provider_definitions/ft.toml": b"key = 'ft'\n",
        "scripts/live_check.py": b"print('live')\n",
        "tests/test_live_providers.py": b"def test_live(): pass\n",
        "pyproject.toml": b"[project]\nname = 'fixture'\n",
        "uv.lock": b"version = 1\n",
    }
    for relative, payload in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    return root


def test_complete_environment_cannot_relabel_source_development() -> None:
    identity = resolve_build_identity(
        None,
        environment={
            "NEWSCLIP_BUILD_REVISION": "1234567",
            "NEWSCLIP_BUILD_DIRTY": "0",
            "NEWSCLIP_BUILD_SOURCE_FINGERPRINT": "a" * 64,
        },
    )

    assert identity.source is BuildIdentitySource.UNAVAILABLE
    assert identity.revision is None
    assert identity.dirty is None
    assert identity.source_fingerprint is None


def test_partial_environment_build_identity_is_explicitly_unavailable() -> None:
    identity = resolve_build_identity(
        None,
        environment={"NEWSCLIP_BUILD_REVISION": "1234567"},
    )

    assert identity.source is BuildIdentitySource.UNAVAILABLE
    assert (
        identity.unavailable_reason
        is BuildIdentityUnavailableReason.UNSTAMPED_DEVELOPMENT
    )
    assert identity.revision is None
    assert identity.dirty is None
    assert identity.source_fingerprint is None


def test_local_checkout_identity_has_a_bounded_fingerprint(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repository")

    identity = build_source_identity(repository)

    assert identity.source_fingerprint is not None
    assert len(identity.source_fingerprint) == 64


def test_runtime_uses_packaged_identity_without_inspecting_git(monkeypatch, tmp_path):
    monkeypatch.setattr(
        application_identity,
        "BUILD",
        application_identity.ApplicationBuild(
            "newsclip",
            "2.0.3",
            "a" * 40,
            "b" * 64,
            True,
        ),
    )
    monkeypatch.setattr(
        "newsclip.provenance.build_source_identity",
        lambda _: (_ for _ in ()).throw(AssertionError("runtime source inspection")),
    )
    identity = resolve_build_identity(
        tmp_path,
        environment={
            "NEWSCLIP_BUILD_REVISION": "c" * 40,
            "NEWSCLIP_BUILD_DIRTY": "0",
            "NEWSCLIP_BUILD_SOURCE_FINGERPRINT": "d" * 64,
        },
    )
    assert identity.source is BuildIdentitySource.PACKAGED
    assert identity.revision == "a" * 40 and identity.dirty is True
    assert identity.source_fingerprint == "b" * 64


def test_unstamped_development_stays_explicit_without_source_inspection(
    tmp_path: Path,
) -> None:
    identity = resolve_build_identity(tmp_path / "missing", environment={})

    assert identity.source is BuildIdentitySource.UNAVAILABLE
    assert (
        identity.unavailable_reason
        is BuildIdentityUnavailableReason.UNSTAMPED_DEVELOPMENT
    )
