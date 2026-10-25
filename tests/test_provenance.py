from __future__ import annotations

from pathlib import Path

from newsclip.provenance import (
    BuildIdentitySource,
    BuildIdentityUnavailableReason,
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


def test_complete_environment_build_identity_is_authoritative() -> None:
    identity = resolve_build_identity(
        None,
        environment={
            "NEWSCLIP_BUILD_REVISION": "1234567",
            "NEWSCLIP_BUILD_DIRTY": "0",
            "NEWSCLIP_BUILD_SOURCE_FINGERPRINT": "a" * 64,
        },
    )

    assert identity.source is BuildIdentitySource.ENVIRONMENT
    assert identity.revision == "1234567"
    assert identity.dirty is False
    assert identity.source_fingerprint == "a" * 64
    assert identity.unavailable_reason is None


def test_partial_environment_build_identity_is_explicitly_unavailable() -> None:
    identity = resolve_build_identity(
        None,
        environment={"NEWSCLIP_BUILD_REVISION": "1234567"},
    )

    assert identity.source is BuildIdentitySource.UNAVAILABLE
    assert (
        identity.unavailable_reason
        is BuildIdentityUnavailableReason.INVALID_ENVIRONMENT
    )
    assert identity.revision is None
    assert identity.dirty is None
    assert identity.source_fingerprint is None


def test_local_checkout_identity_has_a_bounded_fingerprint(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repository")

    identity = resolve_build_identity(repository, environment={})

    assert identity.source is BuildIdentitySource.LOCAL_CHECKOUT
    assert identity.source_fingerprint is not None
    assert len(identity.source_fingerprint) == 64


def test_missing_source_tree_is_explicitly_unavailable(tmp_path: Path) -> None:
    identity = resolve_build_identity(tmp_path / "missing", environment={})

    assert identity.source is BuildIdentitySource.UNAVAILABLE
    assert (
        identity.unavailable_reason
        is BuildIdentityUnavailableReason.SOURCE_TREE_UNAVAILABLE
    )
