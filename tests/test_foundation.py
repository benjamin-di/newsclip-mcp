from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from newsclip.browser_runtime import HttpOperationRole
from newsclip.cli import app
from newsclip.contracts import HttpClient
from newsclip.errors import ContentNotFullError, SessionRequiredError, UsageError
from newsclip.models import (
    AccessState,
    ArticleAssessment,
    ExtractedArticle,
    PortableCookie,
    ProviderCapabilities,
    RateBudget,
    RawFetch,
    SearchFilters,
    SearchResult,
    SessionArtifact,
    SessionStatus,
    StoredSession,
)
from newsclip.providers import ProviderRegistry
from newsclip.service import NewsclipService

NOW = datetime(2026, 7, 17, tzinfo=UTC)
URL = "https://example.test/content/fixture-id"


class FakeHttp(HttpClient):
    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=session is not None,
            raw_html=b"<html>fixture</html>",
        )


class FakeExtractor:
    name = "fixture"
    version = "1"

    def extract(
        self,
        fetch: RawFetch,
        *,
        scope_xpath: tuple[str, ...] | None = None,
    ) -> ExtractedArticle:
        return ExtractedArticle(
            body_markdown="fixture body",
            metadata={"title": "Fixture headline", "author": "A, B"},
            word_count=2,
        )


class FakeProvider:
    key = "fixture"
    capabilities = ProviderCapabilities(requires_session_for_retrieve=False)
    login_recipe = None
    assessment_policy_version = "fixture-v1"
    extraction_scope: tuple[str, ...] | None = None

    def owns_url(self, url: str) -> bool:
        return url.startswith("https://example.test/content/")

    def search(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
    ) -> list[SearchResult]:
        return [SearchResult(provider=self.key, url=URL, headline=f"Result: {query}")][
            : filters.limit
        ]

    def fetch(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        url: str,
    ) -> RawFetch:
        return http.get(url, session=session)

    def assess(
        self,
        requested_url: str,
        fetch: RawFetch,
        extraction: ExtractedArticle,
    ) -> ArticleAssessment:
        return ArticleAssessment(
            access_state=AccessState.FULL,
            provider_article_id="fixture-id",
            canonical_url=URL,
            identity_match=True,
            structural_signals=("fixture_article",),
            word_count=extraction.word_count,
            session_cookie_present=fetch.session_cookie_present,
            reason="full_fixture",
        )

    def rate_budget(self) -> RateBudget:
        return RateBudget(requests_per_second=1, burst=1)


class RejectingProvider(FakeProvider):
    key = "reject"

    def owns_url(self, url: str) -> bool:
        return url.startswith("https://reject.test/content/")

    def assess(
        self,
        requested_url: str,
        fetch: RawFetch,
        extraction: ExtractedArticle,
    ) -> ArticleAssessment:
        return ArticleAssessment(
            access_state=AccessState.UNKNOWN,
            word_count=extraction.word_count,
            reason="unknown_fixture",
        )


class UnexpectedSessions:
    def get_valid_session(
        self, provider: str, account_key: str = "default"
    ) -> SessionArtifact:
        raise AssertionError("anonymous provider attempted to load a session")


class RecordingSessions:
    def __init__(self, artifact: SessionArtifact) -> None:
        self.artifact = artifact
        self.loaded: list[tuple[str, str]] = []
        self.marked_required = False

    def get_valid_session(
        self, provider: str, account_key: str = "default"
    ) -> SessionArtifact:
        self.loaded.append((provider, account_key))
        return self.artifact

    def mark_required(
        self,
        provider: str,
        account_key: str = "default",
        *,
        generation_id=None,
    ) -> None:
        self.marked_required = True


def _artifact(cookie_value: str = "COOKIE_VALUE_SENTINEL") -> SessionArtifact:
    return SessionArtifact(
        generation_id=uuid4(),
        provider="fixture",
        created_at=NOW,
        verified_at=NOW,
        cookies=(
            PortableCookie(
                name="Session",
                value=cookie_value,
                domain="example.test",
            ),
        ),
    )


def test_cli_help_has_no_state_or_optional_browser_side_effect(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    completed = subprocess.run(
        [sys.executable, "-m", "newsclip.cli", "--help"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    # Module invocation has no runner; the installed console path is covered below.
    assert completed.returncode == 0
    assert not (tmp_path / ".local" / "state" / "newsclip").exists()
    assert "patchright" not in completed.stdout.lower()

    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "news from supported providers" in result.stdout


def test_importing_core_does_not_load_provider_implementations_or_definitions() -> None:
    script = """
from pathlib import Path
import sys

original = Path.read_text
read_paths = []

def recording_read(path, *args, **kwargs):
    read_paths.append(str(path))
    return original(path, *args, **kwargs)

Path.read_text = recording_read
import newsclip.service

concrete = {
    "newsclip.providers.ap",
    "newsclip.providers.guardian",
    "newsclip.providers.bloomberg",
    "newsclip.providers.cnbc",
    "newsclip.providers.economist",
    "newsclip.providers.ft",
    "newsclip.providers.reuters",
    "newsclip.providers.wsj",
}
assert concrete.isdisjoint(sys.modules), sorted(concrete.intersection(sys.modules))
assert not [path for path in read_paths if path.endswith(".toml")], read_paths
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_provider_capabilities_reject_unimplemented_profile_authority() -> None:
    with pytest.raises(ValidationError):
        ProviderCapabilities(session_kind="profile")  # type: ignore[arg-type]


def test_cli_version_matches_installed_distribution() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == distribution_version("newsclip")


def test_fake_provider_runs_through_provider_neutral_service() -> None:
    service = NewsclipService(
        ProviderRegistry((FakeProvider(),)), FakeHttp(), FakeExtractor()
    )
    results = service.search("fixture", "banks")
    article = service.get(URL)

    assert results[0].provider == "fixture"
    assert article.id == "fixture:fixture-id"
    assert article.headline == "Fixture headline"
    assert article.authors == ("A", "B")


def test_transport_probe_uses_injected_client_and_product_assessment() -> None:
    provider = FakeProvider()
    provider.capabilities = ProviderCapabilities(requires_session_for_retrieve=True)
    sessions = RecordingSessions(_artifact())

    class UnexpectedProductHttp(FakeHttp):
        def get(self, *args, **kwargs) -> RawFetch:
            raise AssertionError("probe used the configured product transport")

    class RecordingTransport(FakeHttp):
        def __init__(self) -> None:
            self.sessions: list[SessionArtifact | None] = []

        def get(
            self,
            url: str,
            *,
            session: SessionArtifact | None = None,
            timeout: float = 40,
        ) -> RawFetch:
            self.sessions.append(session)
            return super().get(url, session=session, timeout=timeout)

    transport = RecordingTransport()
    service = NewsclipService(
        ProviderRegistry((provider,)),
        UnexpectedProductHttp(),
        FakeExtractor(),
        sessions=sessions,
    )

    result = service.probe_transport(URL, transport)

    assert result.provider == "fixture"
    assert result.http_status == 200
    assert result.access_state is AccessState.FULL
    assert result.promotable is True
    assert result.reason == "full_fixture"
    assert transport.sessions == [sessions.artifact]
    assert sessions.loaded == [("fixture", "default")]
    assert sessions.marked_required is False


def test_transport_probe_returns_non_full_without_read_path_side_effects() -> None:
    provider = RejectingProvider()
    provider.capabilities = ProviderCapabilities(requires_session_for_retrieve=True)
    artifact = _artifact()
    artifact = artifact.model_copy(update={"provider": "reject"})
    sessions = RecordingSessions(artifact)
    service = NewsclipService(
        ProviderRegistry((provider,)),
        FakeHttp(),
        FakeExtractor(),
        sessions=sessions,
    )

    result = service.probe_transport(
        "https://reject.test/content/fixture-id",
        FakeHttp(),
    )

    assert result.access_state is AccessState.UNKNOWN
    assert result.promotable is False
    assert result.reason == "unknown_fixture"
    assert sessions.marked_required is False


def test_anonymous_provider_never_loads_or_manages_sessions() -> None:
    provider = FakeProvider()
    provider.capabilities = ProviderCapabilities(
        session_kind="none",
        requires_session_for_retrieve=False,
        requires_session_for_search=False,
    )
    service = NewsclipService(
        ProviderRegistry((provider,)),
        FakeHttp(),
        FakeExtractor(),
        sessions=UnexpectedSessions(),
    )

    assert service.search("fixture", "banks")[0].provider == "fixture"
    assert service.get(URL).id == "fixture:fixture-id"
    with pytest.raises(UsageError, match="does not use authenticated sessions"):
        service.login("fixture")
    with pytest.raises(UsageError, match="does not use authenticated sessions"):
        service.session_status("fixture")
    with pytest.raises(UsageError, match="does not use authenticated sessions"):
        service.session_checkpoint("fixture")


def test_browser_search_requirement_uses_search_transport() -> None:
    provider = FakeProvider()
    provider.capabilities = ProviderCapabilities(search_transport="browser")
    service = NewsclipService(
        ProviderRegistry((provider,)), FakeHttp(), FakeExtractor()
    )

    assert service.requires_browser_for_search(("fixture",)) is True
    assert service.requires_browser_for_url(URL) is False
    assert service.requires_browser_runtime(("fixture",)) is True


def test_browser_runtime_requirement_includes_browser_retrieve_providers() -> None:
    provider = FakeProvider()
    provider.capabilities = ProviderCapabilities(
        search_transport="http",
        retrieval_transport="browser",
    )
    service = NewsclipService(
        ProviderRegistry((provider,)), FakeHttp(), FakeExtractor()
    )

    assert service.requires_browser_for_search(("fixture",)) is False
    assert service.requires_browser_for_url(URL) is True
    assert service.requires_browser_runtime(("fixture",)) is True


def test_http_challenge_fallback_is_provider_bound_and_preflighted() -> None:
    class ChallengeProvider(FakeProvider):
        def is_interactive_challenge(self, fetch: RawFetch) -> bool:
            return b"CHALLENGE" in fetch.raw_html

        def rate_budget(self) -> RateBudget:
            return RateBudget(requests_per_second=1000, burst=2)

    class ChallengeHttp(FakeHttp):
        def __init__(self) -> None:
            self.calls: list[str] = []

        def get(self, url, *, session=None, timeout: float = 40) -> RawFetch:
            self.calls.append(url)
            return (
                super()
                .get(url, session=session, timeout=timeout)
                .model_copy(update={"raw_html": b"CHALLENGE"})
            )

    class BrowserClient(FakeHttp):
        def __init__(self) -> None:
            self.calls: list[str] = []

        def get(self, url, *, session=None, timeout: float = 40) -> RawFetch:
            self.calls.append(url)
            return super().get(url, session=session, timeout=timeout)

    class BrowserPlane:
        def __init__(self) -> None:
            self.client = BrowserClient()
            self.bindings: list[tuple[str, HttpOperationRole]] = []

        def allows_http_fallback(self, provider: str) -> bool:
            return provider == "fixture"

        def for_provider(
            self,
            provider: str,
            *,
            role: HttpOperationRole,
        ) -> BrowserClient:
            self.bindings.append((provider, role))
            return self.client

        def release(self) -> None: ...

        def close(self) -> None: ...

    primary = ChallengeHttp()
    browser = BrowserPlane()
    service = NewsclipService(
        ProviderRegistry((ChallengeProvider(),)),
        primary,
        FakeExtractor(),
        browser_retriever=browser,  # type: ignore[arg-type]
    )

    article = service.get(URL)

    assert article.id == "fixture:fixture-id"
    assert primary.calls == [URL]
    assert browser.client.calls == [URL]
    assert browser.bindings == [("fixture", HttpOperationRole.FETCH)]
    assert service.requires_browser_for_url(URL) is True
    assert service.requires_browser_for_search(("fixture",)) is True
    assert service.requires_browser_runtime(("fixture",)) is True


def test_missing_session_does_not_invent_login() -> None:
    provider = FakeProvider()
    provider.capabilities = ProviderCapabilities(requires_session_for_retrieve=True)
    service = NewsclipService(
        ProviderRegistry((provider,)), FakeHttp(), FakeExtractor()
    )
    with pytest.raises(SessionRequiredError):
        service.get(URL)


def test_unknown_content_fails_closed() -> None:
    url = "https://reject.test/content/fixture-id"
    service = NewsclipService(
        ProviderRegistry((RejectingProvider(),)), FakeHttp(), FakeExtractor()
    )
    with pytest.raises(ContentNotFullError, match="unknown_fixture"):
        service.get(url)


def test_registry_requires_exactly_one_owner() -> None:
    registry = ProviderRegistry((FakeProvider(),))
    with pytest.raises(UsageError):
        registry.for_url("https://not-owned.test/content/id")


def test_registry_rejects_invalid_provider_keys_at_registration() -> None:
    class InvalidKeyProvider(FakeProvider):
        key = "../fixture"

    with pytest.raises(ValueError, match="invalid provider key"):
        ProviderRegistry((InvalidKeyProvider(),))


def test_schema_and_identity_mismatches_fail_closed() -> None:
    data: dict[str, Any] = _artifact().model_dump(mode="json")
    data["schema_version"] = 2
    with pytest.raises(ValidationError):
        SessionArtifact.model_validate(data)

    data = _artifact().model_dump(mode="json")
    data["user_agent"] = "FixtureBrowser/1\r\nInjected: value"
    with pytest.raises(ValidationError, match="single line"):
        SessionArtifact.model_validate(data)

    with pytest.raises(ValueError, match="provider/account mismatch"):
        _artifact().assert_identity("other")

    with pytest.raises(ValidationError):
        StoredSession.model_validate(
            {"schema_version": 2, "status": SessionStatus.REQUIRED.value}
        )


def test_verified_models_require_their_sensitive_internal_payload() -> None:
    with pytest.raises(ValidationError):
        StoredSession(status=SessionStatus.VERIFIED)
