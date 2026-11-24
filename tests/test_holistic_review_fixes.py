"""Regression tests for holistic review fixes (P1/P2 bugs, UI/UX, efficiency)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from newsclip.archive import ArchiveStore
from newsclip.browser_retrieval import PatchrightBrowserRetriever, _response_content
from newsclip.client import NewsclipClient
from newsclip.errors import (
    ProviderTransportError,
    SessionRequiredError,
    UsageError,
)
from newsclip.http import MAX_RESPONSE_BYTES, _read_response_bytes
from newsclip.maintenance_cycle import run_command, run_maintenance_cycle
from newsclip.models import (
    AccessState,
    Article,
    ArticleAssessment,
    ExtractedArticle,
    ExtractionMeta,
    PortableCookie,
    RawFetch,
    SessionArtifact,
)
from newsclip.ops_server import CommandOutcome, _command_response
from newsclip.recovery_watch import RecoveryWatch
from newsclip.subscription_access import SubscriptionAccess
from newsclip.tenancy import add_proxy_user, user_scope


def test_maintenance_cycle_passes_selected_user_to_children(tmp_path: Path) -> None:
    captured: list[list[str]] = []

    def fake_runner(arguments: list[str], *, timeout: int, lock_fd: int):
        captured.append(list(arguments))
        return 0, {
            "provider": "ft",
            "action": "fresh",
            "overall_state": "healthy",
        }

    with user_scope("alice"):
        result = run_maintenance_cycle(
            ["ft"],
            root=tmp_path,
            mode="keep",
            runner=fake_runner,
        )
    assert result.needs_attention is False
    assert captured == [
        [
            "--user",
            "alice",
            "auth",
            "keep",
            "ft",
            "--json",
            "--max-age-hours",
            "12",
        ]
    ]


def test_maintenance_run_command_strips_ambient_newsclip_user(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("NEWSCLIP_USER", "ambient-user")
    recorded_env: dict[str, str] = {}

    class FakePopen:
        def __init__(self, args, **kwargs) -> None:
            recorded_env.update(kwargs["env"])
            kwargs["stdout"].write(b'{"ok": true}')
            kwargs["stdout"].flush()
            self.pid = 12345

        def wait(self, timeout=None) -> int:
            return 0

        def poll(self) -> int:
            return 0

    monkeypatch.setattr("newsclip.maintenance_cycle.subprocess.Popen", FakePopen)
    with (tmp_path / "lock").open("wb") as handle:
        code, data = run_command(
            ["auth", "keep", "ft"], timeout=60, lock_fd=handle.fileno()
        )
    assert code == 0
    assert data == {"ok": True}
    assert "NEWSCLIP_USER" not in recorded_env


def test_browser_reader_rechecks_authorization_under_profile_lease(
    tmp_path: Path,
) -> None:
    """If disconnect happens after initial auth check and before profile lease
    acquisition, the reader must not recreate or seed the profile."""

    calls: list[str] = []
    disconnected = False

    def authorize(_session: SessionArtifact) -> None:
        calls.append("authorize")
        if disconnected:
            raise SessionRequiredError("connection_disconnected")

    class FlippingLeases:
        def hold_profile(self, _profile: Path):
            nonlocal disconnected
            calls.append("hold_profile")
            disconnected = True

            class _Lease:
                released = False

                def release(self) -> None:
                    self.released = True
                    calls.append("release_lease")

            return _Lease()

    launched = False

    def launch(_profile: str):
        nonlocal launched
        launched = True
        raise AssertionError("browser must not launch after disconnect")

    client = PatchrightBrowserRetriever(
        context_factory=launch,
        profile_resolver=lambda p, _a, **_k: tmp_path / "profiles" / p,
        lease_manager=FlippingLeases(),  # type: ignore[arg-type]
        require_virtual_display=False,
        authorize_session=authorize,
    )
    session = SessionArtifact(
        schema_version=2,
        browser_profile_id=uuid4(),
        generation_id=uuid4(),
        provider="ft",
        account_key="default",
        created_at=datetime.now(UTC),
        verified_at=datetime.now(UTC),
        cookies=(
            PortableCookie(
                name="FTSession",
                value="secret",
                domain=".ft.com",
                path="/",
                secure=True,
                http_only=True,
            ),
        ),
        user_agent="TestAgent/1.0",
    )
    with pytest.raises(SessionRequiredError, match="connection_disconnected"):
        client.warm(session)
    assert launched is False
    assert calls == ["authorize", "hold_profile", "authorize", "release_lease"]


def test_http_response_byte_ceiling_rejects_oversized_content() -> None:
    closed = False

    class OversizedStream:
        headers = {}

        def iter_content(self, chunk_size: int = 65536):
            yield b"a" * (MAX_RESPONSE_BYTES // 2 + 1)
            yield b"b" * (MAX_RESPONSE_BYTES // 2 + 1)

        def close(self) -> None:
            nonlocal closed
            closed = True

    with pytest.raises(ProviderTransportError, match="exceeds size limit") as exc:
        _read_response_bytes(OversizedStream(), streamed=True)
    assert exc.value.retryable is False
    assert closed is True


def test_browser_response_byte_ceiling_rejects_oversized_dom() -> None:
    class FakePage:
        def evaluate(self, _script: str) -> int:
            return MAX_RESPONSE_BYTES + 1

        def content(self) -> str:
            raise AssertionError("page.content() must not be called for huge DOM")

    response = SimpleNamespace(headers={"content-type": "text/html"})
    with pytest.raises(ProviderTransportError, match="exceeds size limit") as exc:
        _response_content(response, FakePage())
    assert exc.value.retryable is False


def test_concurrent_archive_initialization_succeeds(tmp_path: Path) -> None:
    db_path = tmp_path / "archive.sqlite"

    def open_store(_i: int) -> str:
        store = ArchiveStore(db_path)
        return store.integrity_check().integrity.value

    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(open_store, range(8)))
    assert statuses == ["ok"] * 8


def test_archive_integrity_rejects_non_promotable_extraction_assessment(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "archive.sqlite"
    store = ArchiveStore(db_path)
    now = datetime.now(UTC)
    raw = b"<html><body><article>Full story content.</article></body></html>"
    fetch = RawFetch(
        requested_url="https://example.com/story-1",  # type: ignore[arg-type]
        final_url="https://example.com/story-1",  # type: ignore[arg-type]
        http_status=200,
        content_type="text/html",
        retrieved_at=now,
        session_cookie_present=False,
        raw_html=raw,
    )
    good_assessment = ArticleAssessment(
        canonical_url="https://example.com/story-1",  # type: ignore[arg-type]
        provider_article_id="story-1",
        access_state=AccessState.FULL,
        identity_match=True,
        word_count=50,
        session_cookie_present=False,
        reason="full_article_verified",
    )
    extraction = ExtractedArticle(
        body_markdown="Full story content.",
        metadata={},
        word_count=50,
    )
    article = Article(
        id="ap:story-1",
        provider="ap",
        provider_article_id="story-1",
        url="https://example.com/story-1",  # type: ignore[arg-type]
        canonical_url="https://example.com/story-1",  # type: ignore[arg-type]
        headline="Headline",
        body_markdown="Full story content.",
        word_count=50,
        retrieved_at=now,
        extraction=ExtractionMeta(
            extractor_name="trafilatura",
            extractor_version="2.0",
            policy_version="test-v1",
            assessment_schema_version=1,
            raw_sha256=hashlib.sha256(raw).hexdigest(),
        ),
    )
    store.save("ap", article, fetch, good_assessment, extraction)

    bad_assessment = good_assessment.model_copy(
        update={"provider_article_id": "different-story"}
    )
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE extraction_assessments SET assessment_json = ?",
            (bad_assessment.model_dump_json(),),
        )
        conn.commit()

    result = store.integrity_check()
    assert result.ok is False
    assert result.integrity.value == "failed"


def test_subscription_access_survives_user_turnover_past_100(tmp_path: Path) -> None:
    users_path = tmp_path / "users.json"
    for idx in range(100):
        add_proxy_user(users_path, f"u{idx:03d}")
    access = SubscriptionAccess(tmp_path / "state", users_path)
    access.bootstrap(["ft"])

    # Replace one user in the active 100-user registry (turnover to 101st enrolled user)
    data = json.loads(users_path.read_text())
    data["users"] = [u for u in data["users"] if u["id"] != "u000"] + [
        {"id": "u100", "token_sha256": None}
    ]
    users_path.write_text(json.dumps(data))

    access.bootstrap(["ft"])
    admitted = access.admit("u001", "ft")
    assert admitted.owner == "u001"
    admitted_new = access.admit("u100", "ft")
    assert admitted_new.owner == "u100"


def test_ops_command_response_fails_on_unstructured_nonzero_exit() -> None:
    garbage = CommandOutcome(exit_code=1, stdout="crash traceback")
    payload = garbage.payload()
    assert payload == {"exit_code": 1}
    response = _command_response(payload)
    assert response["ok"] is False
    assert response["exit_code"] == 1

    # Valid exit-1 guard verdict stays a structured ok result
    held = CommandOutcome(
        exit_code=1, stdout=json.dumps({"action": "held", "provider": "ft"})
    )
    held_resp = _command_response(held.payload())
    assert held_resp["ok"] is True
    assert held_resp["result"]["action"] == "held"


def test_remote_client_maps_400_and_413_to_non_retryable_usage_error() -> None:
    for status in (400, 413):
        transport = httpx.MockTransport(
            lambda _req, code=status: httpx.Response(code, json={"detail": "bad"})
        )
        client = NewsclipClient(
            "http://127.0.0.1:8000/users/alice", "token-123", transport=transport
        )
        try:
            with pytest.raises(UsageError, match="rejected the request"):
                client.request("search", query="x")
        finally:
            client.close()


def test_recovery_watch_close_terminates_active_child_group() -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    watch = RecoveryWatch(
        store=SimpleNamespace(),  # type: ignore[arg-type]
        providers=("ft",),
        allow_credentials=False,
    )
    with watch._children_lock:
        watch._active_children.add(child)
    started = time.monotonic()
    try:
        watch.close()
        assert child.poll() is not None
        assert time.monotonic() - started < 10.0
    finally:
        with watch._children_lock:
            watch._active_children.discard(child)
        if child.poll() is None:
            child.kill()
            child.wait()


def test_cli_login_and_fallback_acquirer_honor_detect_only_env(monkeypatch) -> None:
    from typer.testing import CliRunner

    from newsclip.challenges import ChallengeMode
    from newsclip.cli import _session_acquirer, app

    recorded_login_modes: list[ChallengeMode] = []
    recorded_child_argvs: list[list[str]] = []

    class FakeService:
        def requires_browser_for_provider(self, _provider: str) -> bool:
            return False

        def login(
            self,
            provider: str,
            *,
            headless: bool = True,
            challenge_mode: ChallengeMode = ChallengeMode.AUTO,
            before_browser=None,
            **_kwargs,
        ):
            recorded_login_modes.append(challenge_mode)
            if callable(before_browser):
                before_browser()
            return SimpleNamespace(
                public_dict=lambda: {"provider": provider, "status": "verified"}
            )

    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: FakeService())
    monkeypatch.setattr(
        "newsclip.cli._prepare_virtual_display",
        lambda argv, **_kwargs: recorded_child_argvs.append(list(argv)),
    )

    monkeypatch.setenv("NEWSCLIP_CHALLENGE_MODE", "detect-only")
    result = CliRunner().invoke(app, ["auth", "login", "ft", "--json"])
    assert result.exit_code == 0, result.output
    assert recorded_login_modes[-1] is ChallengeMode.DETECT_ONLY

    # Explicit --challenge-mode auto cannot override a detect-only deployment env.
    result_override = CliRunner().invoke(
        app, ["auth", "login", "ft", "--challenge-mode", "auto", "--json"]
    )
    assert result_override.exit_code == 0, result_override.output
    assert recorded_login_modes[-1] is ChallengeMode.DETECT_ONLY

    # Fallback acquirer passes detect-only to both in-process login and child argv.
    acquire = _session_acquirer(FakeService(), json_output=True)  # type: ignore[arg-type]
    acquire("ft")
    assert recorded_login_modes[-1] is ChallengeMode.DETECT_ONLY
    assert "--challenge-mode" in recorded_child_argvs[-1]
    idx = recorded_child_argvs[-1].index("--challenge-mode")
    assert recorded_child_argvs[-1][idx + 1] == "detect-only"

    # When configured for auto, both direct and fallback pass auto.
    monkeypatch.setenv("NEWSCLIP_CHALLENGE_MODE", "auto")
    acquire("ft")
    assert recorded_login_modes[-1] is ChallengeMode.AUTO
    idx = recorded_child_argvs[-1].index("--challenge-mode")
    assert recorded_child_argvs[-1][idx + 1] == "auto"
