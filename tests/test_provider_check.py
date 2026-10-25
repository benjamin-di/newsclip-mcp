from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from typer.testing import CliRunner

from newsclip.browser_readiness import (
    BrowserReadinessObservation,
    BrowserSemanticSnapshot,
    ReadinessCoverageBucket,
    ReadinessTerminalState,
)
from newsclip.browser_retrieval import BrowserSnapshotRejected
from newsclip.cli import app
from newsclip.defense import DefenseState
from newsclip.errors import ProviderTransportError, TransportFailure
from newsclip.incidents import IncidentStore, SearchFailureKind
from newsclip.models import (
    AccessState,
    ArticleAssessment,
    ExtractedArticle,
    PortableCookie,
    ProviderCapabilities,
    ProviderSearchPage,
    RateBudget,
    RawFetch,
    SearchFilters,
    SearchResult,
    SessionArtifact,
    SessionVerification,
)
from newsclip.provenance import BuildIdentity, BuildIdentitySource
from newsclip.provider_check import ProviderCheckFailure, ProviderCheckResult
from newsclip.provider_config import ProviderCheckSpec
from newsclip.providers import ProviderRegistry
from newsclip.service import NewsclipService, _search_leg_failure
from newsclip.timing import TimingOperation

NOW = datetime(2026, 7, 24, tzinfo=UTC)
ARTICLE_URL = "https://fixture.test/content/article"
SEARCH_URL = "https://fixture.test/search?q=canary"


class CheckHttp:
    def __init__(self, *, status: int = 200) -> None:
        self.calls: list[str] = []
        self.status = status

    def get(self, url: str, *, session=None, timeout: float = 40) -> RawFetch:
        del timeout
        self.calls.append(url)
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=self.status,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=session is not None,
            raw_html=b"<html><body>bounded fixture</body></html>",
        )


class CheckExtractor:
    name = "check"
    version = "1"

    def extract(
        self,
        fetch: RawFetch,
        *,
        scope_xpath: tuple[str, ...] | None = None,
    ) -> ExtractedArticle:
        del fetch
        return ExtractedArticle(
            body_markdown=" ".join("fixture" for _ in range(400)),
            metadata={"title": "Fixture"},
            word_count=400,
        )


class CheckProvider:
    key = "fixture"
    check = ProviderCheckSpec(query="canary", canonical_url=ARTICLE_URL)
    capabilities = ProviderCapabilities(
        requires_session_for_retrieve=False,
        session_kind="none",
    )
    login_recipe = None
    assessment_policy_version = "fixture-check-v1"
    extraction_scope: tuple[str, ...] | None = None

    def __init__(
        self,
        *,
        state: AccessState = AccessState.FULL,
        search_missing: bool = False,
    ) -> None:
        self.state = state
        self.search_missing = search_missing

    def owns_url(self, url: str) -> bool:
        return url == ARTICLE_URL

    def search(self, http, session, query: str, filters: SearchFilters):
        return list(
            self.search_page(
                http,
                session,
                query,
                filters,
                metadata_fetch_budget=0,
            ).results
        )

    def search_page(
        self,
        http,
        session,
        query: str,
        filters: SearchFilters,
        *,
        next_url=None,
        metadata_fetch_budget=None,
    ) -> ProviderSearchPage:
        del next_url, metadata_fetch_budget
        http.get(SEARCH_URL, session=session)
        results = (
            ()
            if self.search_missing
            else (
                SearchResult(
                    provider=self.key,
                    url=ARTICLE_URL,
                    headline=f"Fixture {query}",
                ),
            )
        )
        return ProviderSearchPage(results=results[: filters.limit])

    def fetch(self, http, session, url: str) -> RawFetch:
        return http.get(url, session=session)

    def assess(
        self,
        requested_url: str,
        fetch: RawFetch,
        extraction: ExtractedArticle,
    ) -> ArticleAssessment:
        del requested_url
        return ArticleAssessment(
            access_state=self.state,
            canonical_url=ARTICLE_URL,
            provider_article_id="article",
            identity_match=self.state is not AccessState.BLOCKED,
            word_count=extraction.word_count,
            session_cookie_present=fetch.session_cookie_present,
            reason=(
                "full_article_verified"
                if self.state is AccessState.FULL
                else (
                    "interactive_challenge"
                    if self.state is AccessState.BLOCKED
                    else "paywall_teaser"
                )
            ),
        )

    def rate_budget(self) -> RateBudget:
        return RateBudget(requests_per_second=100, burst=10)


def _identity() -> BuildIdentity:
    return BuildIdentity(
        revision="a" * 40,
        dirty=False,
        source_fingerprint="a" * 64,
        source=BuildIdentitySource.ENVIRONMENT,
    )


def _service(
    tmp_path: Path,
    provider: CheckProvider,
    *,
    sessions=None,
    status: int = 200,
    http_override: CheckHttp | None = None,
    browser_retriever=None,
    defense: DefenseState | None = None,
) -> tuple[NewsclipService, CheckHttp, IncidentStore]:
    http = http_override or CheckHttp(status=status)
    incidents = IncidentStore(
        tmp_path / "incidents",
        build_identity=_identity(),
        utc_now=lambda: NOW,
    )
    return (
        NewsclipService(
            ProviderRegistry((provider,)),
            http,
            CheckExtractor(),
            sessions=sessions,
            browser_retriever=browser_retriever,
            incidents=incidents,
            network_sleep=lambda _seconds: None,
            defense=defense,
        ),
        http,
        incidents,
    )


def test_provider_check_runs_one_search_and_retrieval_without_archive(
    tmp_path: Path,
) -> None:
    service, http, incidents = _service(tmp_path, CheckProvider())

    result = service.provider_check("fixture")

    assert result.ok is True
    assert result.failure is None
    assert result.search_result_count == 1
    assert result.access_state is AccessState.FULL
    assert http.calls == [SEARCH_URL, ARTICLE_URL]
    assert tuple(incidents.iter_capsules()) == ()


def test_provider_check_uses_single_navigation_browser_plane(
    tmp_path: Path,
) -> None:
    class BrowserCheckProvider(CheckProvider):
        capabilities = ProviderCapabilities(
            requires_session_for_retrieve=False,
            retrieval_transport="browser",
            session_kind="none",
        )

    class CheckBrowser:
        def __init__(self) -> None:
            self.check_calls: list[str] = []

        def get(self, url: str, *, session=None, timeout: float = 40) -> RawFetch:
            del url, session, timeout
            raise AssertionError("ordinary browser retrieval must not be used")

        def get_for_check(
            self,
            url: str,
            *,
            session=None,
            timeout: float = 40,
        ) -> RawFetch:
            del timeout
            self.check_calls.append(url)
            return RawFetch(
                requested_url=url,
                final_url=url,
                http_status=200,
                content_type="text/html",
                retrieved_at=NOW,
                session_cookie_present=session is not None,
                raw_html=b"<html><body>bounded fixture</body></html>",
            )

        def release(self) -> None: ...

        def close(self) -> None: ...

    browser = CheckBrowser()
    service, http, _ = _service(
        tmp_path,
        BrowserCheckProvider(),
        browser_retriever=browser,
    )

    result = service.provider_check("fixture")

    assert result.ok is True
    assert http.calls == [SEARCH_URL]
    assert browser.check_calls == [ARTICLE_URL]


def test_provider_check_http_challenge_uses_check_only_browser_fallback(
    tmp_path: Path,
) -> None:
    class ChallengeCheckProvider(CheckProvider):
        def is_interactive_challenge(self, fetch: RawFetch) -> bool:
            return str(fetch.requested_url) == ARTICLE_URL

    class BoundCheckBrowser:
        def __init__(self) -> None:
            self.check_calls: list[str] = []

        def get(self, url: str, *, session=None, timeout: float = 40) -> RawFetch:
            del url, session, timeout
            raise AssertionError("ordinary browser fallback must not be used")

        def get_for_check(
            self,
            url: str,
            *,
            session=None,
            timeout: float = 40,
        ) -> RawFetch:
            del timeout
            self.check_calls.append(url)
            return RawFetch(
                requested_url=url,
                final_url=url,
                http_status=200,
                content_type="text/html",
                retrieved_at=NOW,
                session_cookie_present=session is not None,
                raw_html=b"<html><body>bounded browser fallback</body></html>",
            )

    class BrowserPlane:
        def __init__(self) -> None:
            self.client = BoundCheckBrowser()

        def allows_http_fallback(self, provider: str) -> bool:
            return provider == "fixture"

        def for_provider(self, provider: str, *, role) -> BoundCheckBrowser:
            del role
            assert provider == "fixture"
            return self.client

        def release(self) -> None: ...

        def close(self) -> None: ...

    browser = BrowserPlane()
    service, http, _ = _service(
        tmp_path,
        ChallengeCheckProvider(),
        browser_retriever=browser,
    )

    result = service.provider_check("fixture")

    assert result.ok is True
    assert http.calls == [SEARCH_URL, ARTICLE_URL]
    assert browser.client.check_calls == [ARTICLE_URL]


def test_provider_check_search_challenge_uses_one_browser_fallback(
    tmp_path: Path,
) -> None:
    class SearchChallengeProvider(CheckProvider):
        def is_interactive_challenge(self, fetch: RawFetch) -> bool:
            return str(fetch.requested_url) == SEARCH_URL

    class BoundCheckBrowser:
        def __init__(self) -> None:
            self.check_calls: list[str] = []

        def get(self, url: str, *, session=None, timeout: float = 40) -> RawFetch:
            del url, session, timeout
            raise AssertionError("ordinary browser fallback must not be used")

        def get_for_check(
            self,
            url: str,
            *,
            session=None,
            timeout: float = 40,
        ) -> RawFetch:
            del timeout
            self.check_calls.append(url)
            return RawFetch(
                requested_url=url,
                final_url=url,
                http_status=200,
                content_type="text/html",
                retrieved_at=NOW,
                session_cookie_present=session is not None,
                raw_html=b"<html><body>bounded browser search</body></html>",
            )

    class BrowserPlane:
        def __init__(self) -> None:
            self.client = BoundCheckBrowser()

        def allows_http_fallback(self, provider: str) -> bool:
            return provider == "fixture"

        def for_provider(self, provider: str, *, role) -> BoundCheckBrowser:
            del role
            assert provider == "fixture"
            return self.client

        def release(self) -> None: ...

        def close(self) -> None: ...

    browser = BrowserPlane()
    service, http, _ = _service(
        tmp_path,
        SearchChallengeProvider(),
        browser_retriever=browser,
    )

    result = service.provider_check("fixture")

    assert result.ok is True
    assert http.calls == [SEARCH_URL, ARTICLE_URL]
    assert browser.client.check_calls == [SEARCH_URL]


@pytest.mark.parametrize("challenge_url", [SEARCH_URL, ARTICLE_URL])
def test_provider_check_classifies_unsupported_challenge_as_defense(
    tmp_path: Path,
    challenge_url: str,
) -> None:
    class UnsupportedChallengeProvider(CheckProvider):
        def is_interactive_challenge(self, fetch: RawFetch) -> bool:
            return str(fetch.requested_url) == challenge_url

    service, http, incidents = _service(
        tmp_path,
        UnsupportedChallengeProvider(),
    )

    result = service.provider_check("fixture")

    assert result.failure is ProviderCheckFailure.PROVIDER_DEFENSE
    assert result.search_result_count == (1 if challenge_url == ARTICLE_URL else 0)
    assert http.calls == (
        [SEARCH_URL, ARTICLE_URL] if challenge_url == ARTICLE_URL else [SEARCH_URL]
    )
    assert result.incident_id is not None
    capsule = incidents.load(result.incident_id)
    assert tuple(incidents.iter_capsules()) == (capsule,)
    assert capsule.screenshot_status == "not_browser"
    assert (
        incidents.capture_path(capsule).read_bytes()
        == b"<html><body>bounded fixture</body></html>"
    )
    assert str(incidents.load_context(capsule).requested_url) == challenge_url


def test_provider_check_captures_missing_expected_result(tmp_path: Path) -> None:
    service, http, incidents = _service(
        tmp_path,
        CheckProvider(search_missing=True),
    )

    result = service.provider_check("fixture")

    assert result.failure is ProviderCheckFailure.EXPECTED_RESULT_MISSING
    assert http.calls == [SEARCH_URL]
    capsule = next(incidents.iter_capsules())
    assert result.incident_id == capsule.incident_id
    assert capsule.operation is TimingOperation.SEARCH
    assert capsule.search_failure is SearchFailureKind.CONTRACT


OTHER_URL = "https://fixture.test/content/newer"


class AgedCanaryProvider(CheckProvider):
    """A valid first page that no longer ranks the pinned canary article."""

    def owns_url(self, url: str) -> bool:
        return url in {ARTICLE_URL, OTHER_URL}

    def search_page(self, http, session, query, filters, **kwargs):
        http.get(SEARCH_URL, session=session)
        return ProviderSearchPage(
            results=(SearchResult(provider=self.key, url=OTHER_URL, headline=query),)
        )


def test_aged_out_canary_is_healthy_when_retrieval_is_full(tmp_path: Path) -> None:
    """FT 2026-09-28: the canary ranked past page one while it still served.

    Retrieval decides the verdict; the absence is a non-durable advisory, and
    the real search count is reported rather than zero.
    """

    service, http, incidents = _service(tmp_path, AgedCanaryProvider())

    result = service.provider_check("fixture")

    assert result.ok is True
    assert result.failure is None
    assert result.canary_in_search is False
    assert result.search_result_count == 1
    assert result.access_state is AccessState.FULL
    assert http.calls == [SEARCH_URL, ARTICLE_URL]
    assert tuple(incidents.iter_capsules()) == ()


def test_aged_out_canary_holds_only_on_a_retrieval_failure(tmp_path: Path) -> None:
    service, http, incidents = _service(
        tmp_path, AgedCanaryProvider(state=AccessState.TEASER)
    )

    result = service.provider_check("fixture")

    assert result.failure is ProviderCheckFailure.CONTENT_NOT_FULL
    assert result.canary_in_search is False
    assert result.search_result_count == 1
    assert http.calls == [SEARCH_URL, ARTICLE_URL]
    capsule = next(incidents.iter_capsules())
    assert result.incident_id == capsule.incident_id
    assert capsule.operation is TimingOperation.GET


def test_ranked_canary_reports_its_presence(tmp_path: Path) -> None:
    service, _, _ = _service(tmp_path, CheckProvider())

    assert service.provider_check("fixture").canary_in_search is True


def test_optional_canary_carries_no_search_advisory(tmp_path: Path) -> None:
    class OptionalCanaryProvider(AgedCanaryProvider):
        check = ProviderCheckSpec(
            query="canary",
            canonical_url=ARTICLE_URL,
            require_canonical_result=False,
        )

    service, _, _ = _service(tmp_path, OptionalCanaryProvider())

    result = service.provider_check("fixture")

    assert result.ok is True
    assert result.canary_in_search is None


def test_aged_out_canary_on_a_refused_search_is_still_defense(tmp_path: Path) -> None:
    class RefusingSearchHttp(CheckHttp):
        def get(self, url: str, *, session=None, timeout: float = 40) -> RawFetch:
            fetch = super().get(url, session=session, timeout=timeout)
            if url != SEARCH_URL:
                return fetch
            return fetch.model_copy(update={"http_status": 403})

    service, http, _ = _service(
        tmp_path, AgedCanaryProvider(), http_override=RefusingSearchHttp()
    )

    result = service.provider_check("fixture")

    assert result.failure is ProviderCheckFailure.PROVIDER_DEFENSE
    assert result.search_result_count == 1
    assert http.calls == [SEARCH_URL]


@pytest.mark.parametrize(
    "allow_empty,coverage,ok",
    [(False, NOW, False), (True, None, False), (True, NOW, True)],
)
def test_empty_search_requires_opt_in_and_feed_coverage(
    tmp_path, allow_empty, coverage, ok
):
    class RollingProvider(CheckProvider):
        check = ProviderCheckSpec(
            query="canary",
            canonical_url=ARTICLE_URL,
            require_canonical_result=False,
            allow_empty_search=allow_empty,
        )

        def search_page(self, http, session, query, filters, **kwargs):
            http.get(SEARCH_URL, session=session)
            return ProviderSearchPage(results=(), coverage_start=coverage)

    service, http, _ = _service(tmp_path, RollingProvider())
    result = service.provider_check("fixture")
    assert result.ok is ok
    assert http.calls == ([SEARCH_URL, ARTICLE_URL] if ok else [SEARCH_URL])


def test_provider_check_classifies_and_captures_provider_defense(
    tmp_path: Path,
) -> None:
    service, http, incidents = _service(
        tmp_path,
        CheckProvider(state=AccessState.BLOCKED),
    )

    result = service.provider_check("fixture")

    assert result.failure is ProviderCheckFailure.PROVIDER_DEFENSE
    assert result.reason == "interactive_challenge"
    assert http.calls == [SEARCH_URL, ARTICLE_URL]
    capsule = next(incidents.iter_capsules())
    assert result.incident_id == capsule.incident_id
    assert capsule.operation is TimingOperation.GET
    assert capsule.assessment.access_state is AccessState.BLOCKED


class InvalidSearchProvider(CheckProvider):
    def search_page(
        self,
        http,
        session,
        query: str,
        filters: SearchFilters,
        *,
        next_url=None,
        metadata_fetch_budget=None,
    ) -> ProviderSearchPage:
        del query, filters, next_url, metadata_fetch_budget
        http.get(SEARCH_URL, session=session)
        return ProviderSearchPage(
            results=(
                SearchResult(
                    provider="other",
                    url=ARTICLE_URL,
                    headline="Invalid owner",
                ),
            )
        )


def test_provider_check_distinguishes_search_contract_failure(
    tmp_path: Path,
) -> None:
    service, _, incidents = _service(tmp_path, InvalidSearchProvider())

    result = service.provider_check("fixture")

    assert result.failure is ProviderCheckFailure.SEARCH_CONTRACT
    capsule = next(incidents.iter_capsules())
    assert result.incident_id == capsule.incident_id
    assert capsule.search_failure is SearchFailureKind.CONTRACT


class HttpFailureProvider(CheckProvider):
    def assess(
        self,
        requested_url: str,
        fetch: RawFetch,
        extraction: ExtractedArticle,
    ) -> ArticleAssessment:
        del requested_url
        return ArticleAssessment(
            access_state=AccessState.UNKNOWN,
            canonical_url=ARTICLE_URL,
            provider_article_id="article",
            identity_match=False,
            word_count=extraction.word_count,
            session_cookie_present=fetch.session_cookie_present,
            reason=(
                "http_forbidden" if fetch.http_status == 403 else "http_server_error"
            ),
        )


@pytest.mark.parametrize(
    ("status", "failure"),
    (
        (403, ProviderCheckFailure.PROVIDER_DEFENSE),
        (503, ProviderCheckFailure.RETRIEVAL_TRANSPORT),
    ),
)
def test_provider_check_holds_direct_http_provider_conditions(
    tmp_path: Path,
    status: int,
    failure: ProviderCheckFailure,
) -> None:
    service, http, incidents = _service(
        tmp_path,
        HttpFailureProvider(),
        status=status,
    )

    result = service.provider_check("fixture")

    assert result.failure is failure
    assert http.calls == [SEARCH_URL, ARTICLE_URL]
    capsule = next(incidents.iter_capsules())
    assert result.incident_id == capsule.incident_id


class DefendedSearchProvider(CheckProvider):
    """Search observes the provider's refusal, then reports it as transport."""

    def search_page(
        self,
        http,  # noqa: ANN001
        session,  # noqa: ANN001
        query: str,
        filters: SearchFilters,
        *,
        next_url=None,  # noqa: ANN001
        metadata_fetch_budget=None,  # noqa: ANN001
    ) -> ProviderSearchPage:
        del query, filters, next_url, metadata_fetch_budget
        http.get(SEARCH_URL, session=session)
        raise ProviderTransportError(
            "search response rejected",
            category=TransportFailure.TRANSPORT,
        )


@pytest.mark.parametrize(
    ("status", "failure"),
    (
        (403, ProviderCheckFailure.PROVIDER_DEFENSE),
        (429, ProviderCheckFailure.PROVIDER_DEFENSE),
        (503, ProviderCheckFailure.SEARCH_TRANSPORT),
    ),
)
def test_provider_check_reports_search_leg_defense_as_defense(
    tmp_path: Path,
    status: int,
    failure: ProviderCheckFailure,
) -> None:
    defense = DefenseState(tmp_path / "defense", utc_now=lambda: NOW)
    service, _, incidents = _service(
        tmp_path,
        DefendedSearchProvider(),
        status=status,
        defense=defense,
    )

    result = service.provider_check("fixture")

    assert result.failure is failure
    capsule = next(incidents.iter_capsules())
    assert result.incident_id == capsule.incident_id
    record = defense.status("fixture")
    if failure is ProviderCheckFailure.PROVIDER_DEFENSE:
        assert record is not None
        assert record.origin == "guard"
    else:
        assert record is None


class FailOnceHttp(CheckHttp):
    def get(self, url: str, *, session=None, timeout: float = 40) -> RawFetch:
        del session, timeout
        self.calls.append(url)
        raise ProviderTransportError(
            "one request only",
            category=TransportFailure.TRANSPORT,
        )


def test_provider_check_does_not_use_product_transport_retry(
    tmp_path: Path,
) -> None:
    transport = FailOnceHttp()
    service, _, _ = _service(
        tmp_path,
        CheckProvider(),
        http_override=transport,
    )

    result = service.provider_check("fixture")

    assert result.failure is ProviderCheckFailure.SEARCH_TRANSPORT
    assert transport.calls == [SEARCH_URL]


class DeadRecipe:
    def verify(self, http, artifact) -> SessionVerification:
        del http, artifact
        return SessionVerification(
            verified=False,
            access_state=AccessState.AUTH_REQUIRED,
            reason="authentication_required",
            verified_at=NOW,
        )


class SessionCheckProvider(CheckProvider):
    capabilities = ProviderCapabilities(
        requires_session_for_retrieve=True,
        session_kind="cookie",
    )
    login_recipe = DeadRecipe()


class ReadOnlySessions:
    def __init__(self) -> None:
        self.marks = 0
        self.artifact = SessionArtifact(
            generation_id=uuid4(),
            provider="fixture",
            created_at=NOW,
            verified_at=NOW,
            cookies=(
                PortableCookie(
                    name="session",
                    value="private",
                    domain="fixture.test",
                ),
            ),
        )

    def get_valid_session(self, provider: str, account_key: str = "default"):
        del provider, account_key
        return self.artifact

    def mark_required(self, provider, account_key="default", *, generation_id=None):
        del provider, account_key, generation_id
        self.marks += 1


def test_provider_check_reports_dead_session_without_mutating_or_incident(
    tmp_path: Path,
) -> None:
    sessions = ReadOnlySessions()
    service, _, incidents = _service(
        tmp_path,
        SessionCheckProvider(state=AccessState.TEASER),
        sessions=sessions,
    )

    result = service.provider_check("fixture")

    assert result.failure is ProviderCheckFailure.SESSION_DEAD
    assert result.session_disposition == "session_dead"
    assert sessions.marks == 0
    assert tuple(incidents.iter_capsules()) == ()


class ChallengeVerificationRecipe:
    def verify(self, http, artifact) -> SessionVerification:
        http.get(ARTICLE_URL, session=artifact)
        raise AssertionError("unsupported challenge must stop verification")


class ChallengeVerificationProvider(CheckProvider):
    capabilities = ProviderCapabilities(
        requires_session_for_retrieve=True,
        session_kind="cookie",
    )
    login_recipe = ChallengeVerificationRecipe()

    def __init__(self) -> None:
        super().__init__(state=AccessState.TEASER)
        self._article_observations = 0

    def is_interactive_challenge(self, fetch: RawFetch) -> bool:
        if str(fetch.requested_url) != ARTICLE_URL:
            return False
        self._article_observations += 1
        return self._article_observations == 2


def test_provider_check_classifies_verification_challenge_as_defense(
    tmp_path: Path,
) -> None:
    service, http, incidents = _service(
        tmp_path,
        ChallengeVerificationProvider(),
        sessions=ReadOnlySessions(),
    )

    result = service.provider_check("fixture")

    assert result.failure is ProviderCheckFailure.PROVIDER_DEFENSE
    assert result.search_result_count == 1
    assert http.calls == [SEARCH_URL, ARTICLE_URL, ARTICLE_URL]
    assert result.incident_id is not None
    capsule = incidents.load(result.incident_id)
    assert tuple(incidents.iter_capsules()) == (capsule,)
    assert capsule.screenshot_status == "not_browser"
    assert (
        incidents.capture_path(capsule).read_bytes()
        == b"<html><body>bounded fixture</body></html>"
    )
    assert str(incidents.load_context(capsule).requested_url) == ARTICLE_URL


class CliCheckService:
    def __init__(self, result: ProviderCheckResult) -> None:
        self.result = result
        self.closed = False

    def requires_browser_for_provider(self, provider: str) -> bool:
        del provider
        return False

    def provider_check(self, provider: str) -> ProviderCheckResult:
        del provider
        return self.result

    def close(self) -> None:
        self.closed = True


def test_provider_check_cli_returns_closed_json_and_nonzero_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = CliCheckService(
        ProviderCheckResult(
            provider="ft",
            ok=False,
            failure=ProviderCheckFailure.PROVIDER_DEFENSE,
            search_result_count=1,
            http_status=403,
            access_state=AccessState.BLOCKED,
            reason="interactive_challenge",
            identity_match=False,
            word_count=8,
        )
    )
    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: service)

    invocation = CliRunner().invoke(
        app,
        ["provider-check", "--provider", "ft", "--json"],
    )

    assert invocation.exit_code == 1
    assert json.loads(invocation.stdout)["failure"] == "provider_defense"
    assert "http" not in invocation.stderr.lower()
    assert service.closed is True


class TeaserRecipe:
    """The pinned paid probe is itself short — an independent shortfall."""

    def verify(self, http, artifact) -> SessionVerification:  # noqa: ANN001
        del http, artifact
        return SessionVerification(
            verified=False,
            access_state=AccessState.TEASER,
            reason="paywall_teaser",
            verified_at=NOW,
        )


class UnentitledCheckProvider(SessionCheckProvider):
    login_recipe = TeaserRecipe()


def test_provider_check_names_a_session_wide_shortfall(tmp_path: Path) -> None:
    sessions = ReadOnlySessions()
    service, _, _ = _service(
        tmp_path,
        UnentitledCheckProvider(state=AccessState.TEASER),
        sessions=sessions,
    )

    result = service.provider_check("fixture")

    assert result.failure is ProviderCheckFailure.CONTENT_NOT_FULL
    assert result.session_disposition == "not_entitled"
    assert sessions.marks == 0


class VerifiedRecipe:
    def verify(self, http, artifact) -> SessionVerification:  # noqa: ANN001
        del http, artifact
        return SessionVerification(
            verified=True,
            access_state=AccessState.FULL,
            reason="full_article_verified",
            verified_at=NOW,
        )


class RenderTimeoutProvider(CheckProvider):
    capabilities = ProviderCapabilities(
        requires_session_for_retrieve=True,
        session_kind="cookie",
        retrieval_transport="browser",
    )
    login_recipe = VerifiedRecipe()


def test_provider_check_reports_a_rejected_render_as_content_not_full(
    tmp_path: Path,
) -> None:
    """A readiness veto must be classified, not raised past the guard.

    The snapshot's own assessment is promotable — that is what
    ``promotable_incomplete_timeout`` means — so this also pins that the veto
    outranks the assessment rather than reporting the check as healthy.
    """

    rejected_fetch = RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=b"<html><body>partially rendered fixture</body></html>",
    )
    snapshot = BrowserSemanticSnapshot(
        document_url=ARTICLE_URL,
        content=rejected_fetch.raw_html,
        observation=BrowserReadinessObservation(
            ready=False,
            assessment_promotable=True,
            content_fingerprint="b" * 64,
            word_count=400,
            coverage_bucket=ReadinessCoverageBucket.FROM_75_TO_89,
        ),
        stabilized=False,
        terminal_state=ReadinessTerminalState.PROMOTABLE_INCOMPLETE_TIMEOUT,
        content_change_count=3,
        last_content_change_ms=2_500,
    )

    class RejectingBrowser:
        def __init__(self) -> None:
            self.check_calls: list[str] = []

        def get(self, url: str, *, session=None, timeout: float = 40) -> RawFetch:
            del url, session, timeout
            raise AssertionError("ordinary browser retrieval must not be used")

        def get_for_check(
            self,
            url: str,
            *,
            session=None,
            timeout: float = 40,
        ) -> RawFetch:
            del session, timeout
            self.check_calls.append(url)
            raise BrowserSnapshotRejected(fetch=rejected_fetch, snapshot=snapshot)

        def release(self) -> None: ...

        def close(self) -> None: ...

    browser = RejectingBrowser()
    sessions = ReadOnlySessions()
    service, http, incidents = _service(
        tmp_path,
        RenderTimeoutProvider(),
        sessions=sessions,
        browser_retriever=browser,
    )

    result = service.provider_check("fixture")

    assert result.ok is False
    assert result.failure is ProviderCheckFailure.CONTENT_NOT_FULL
    assert result.search_result_count == 1
    assert result.session_disposition == "verified"
    assert result.incident_id is not None
    # One navigation only: the check plane never retries a rejected render.
    assert browser.check_calls == [ARTICLE_URL]
    assert http.calls == [SEARCH_URL]
    # The session was proven live and must not be downgraded by a render timeout.
    assert sessions.marks == 0

    (capsule,) = tuple(incidents.iter_capsules())
    assert capsule.incident_id == result.incident_id
    assert capsule.operation is TimingOperation.GET
    assert capsule.readiness is not None
    assert capsule.readiness.state is (
        ReadinessTerminalState.PROMOTABLE_INCOMPLETE_TIMEOUT
    )
    assert capsule.readiness.coverage_bucket is ReadinessCoverageBucket.FROM_75_TO_89
    assert capsule.readiness.content_change_count == 3
    assert capsule.readiness.last_content_change_ms == 2_500


class _ChallengeClassifier(CheckProvider):
    def is_interactive_challenge(self, fetch: RawFetch) -> bool:
        return b"challenge" in fetch.raw_html


def _search_fetch(*, status: int = 200, body: bytes = b"<html></html>") -> RawFetch:
    return RawFetch(
        requested_url=SEARCH_URL,
        final_url=SEARCH_URL,
        http_status=status,
        content_type="text/html",
        retrieved_at=NOW,
        raw_html=body,
    )


@pytest.mark.parametrize(
    ("fetch", "otherwise", "expected"),
    (
        # No observation at all keeps the caller's own verdict.
        (
            None,
            ProviderCheckFailure.SEARCH_TRANSPORT,
            ProviderCheckFailure.SEARCH_TRANSPORT,
        ),
        (
            _search_fetch(status=403),
            ProviderCheckFailure.SEARCH_TRANSPORT,
            ProviderCheckFailure.PROVIDER_DEFENSE,
        ),
        # An escalated challenge can answer 200 and simply carry no results,
        # which must not read as provider contract drift.
        (
            _search_fetch(body=b"<html>challenge</html>"),
            ProviderCheckFailure.SEARCH_CONTRACT,
            ProviderCheckFailure.PROVIDER_DEFENSE,
        ),
        (
            _search_fetch(body=b"<html>challenge</html>"),
            ProviderCheckFailure.EXPECTED_RESULT_MISSING,
            ProviderCheckFailure.PROVIDER_DEFENSE,
        ),
        (
            _search_fetch(),
            ProviderCheckFailure.EXPECTED_RESULT_MISSING,
            ProviderCheckFailure.EXPECTED_RESULT_MISSING,
        ),
    ),
)
def test_search_leg_failure_prefers_defense_over_the_callers_verdict(
    fetch: RawFetch | None,
    otherwise: ProviderCheckFailure,
    expected: ProviderCheckFailure,
) -> None:
    assert (
        _search_leg_failure(_ChallengeClassifier(), fetch, otherwise=otherwise)
        is expected
    )


class ForbiddenSessionProvider(CheckProvider):
    """A session provider whose origin answers a bare 403 with no challenge."""

    capabilities = ProviderCapabilities(
        requires_session_for_retrieve=True,
        session_kind="cookie",
    )

    def __init__(self, login_recipe) -> None:  # noqa: ANN001
        super().__init__(state=AccessState.UNKNOWN)
        self.login_recipe = login_recipe

    def assess(
        self,
        requested_url: str,
        fetch: RawFetch,
        extraction: ExtractedArticle,
    ) -> ArticleAssessment:
        del requested_url
        return ArticleAssessment(
            access_state=AccessState.UNKNOWN,
            canonical_url=ARTICLE_URL,
            provider_article_id="article",
            identity_match=False,
            word_count=extraction.word_count,
            session_cookie_present=fetch.session_cookie_present,
            reason="http_forbidden",
        )


def test_provider_check_reads_a_bare_forbidden_on_a_dead_session_as_dead(
    tmp_path: Path,
) -> None:
    """Economist 2026-08-25: 403 carrying the full article, ``loggedIn: false``.

    Filing that as defense parks the provider in the one hold class the keeper
    may never renew under, so the verdict has to come from the session probe.
    """

    defense = DefenseState(tmp_path / "defense", utc_now=lambda: NOW)
    sessions = ReadOnlySessions()
    service, http, incidents = _service(
        tmp_path,
        ForbiddenSessionProvider(DeadRecipe()),
        status=403,
        sessions=sessions,
        defense=defense,
    )

    result = service.provider_check("fixture")

    assert result.failure is ProviderCheckFailure.SESSION_DEAD
    assert result.session_disposition == "session_dead"
    assert result.http_status == 403
    assert http.calls == [SEARCH_URL, ARTICLE_URL]
    assert defense.status("fixture") is None
    assert sessions.marks == 0
    assert tuple(incidents.iter_capsules()) == ()


def test_provider_check_keeps_a_bare_forbidden_on_a_live_session_as_defense(
    tmp_path: Path,
) -> None:
    defense = DefenseState(tmp_path / "defense", utc_now=lambda: NOW)
    service, http, incidents = _service(
        tmp_path,
        ForbiddenSessionProvider(VerifiedRecipe()),
        status=403,
        sessions=ReadOnlySessions(),
        defense=defense,
    )

    result = service.provider_check("fixture")

    assert result.failure is ProviderCheckFailure.PROVIDER_DEFENSE
    assert result.http_status == 403
    assert http.calls == [SEARCH_URL, ARTICLE_URL]
    record = defense.status("fixture")
    assert record is not None
    assert record.origin == "guard"
    capsule = next(incidents.iter_capsules())
    assert result.incident_id == capsule.incident_id
    assert capsule.operation is TimingOperation.GET
