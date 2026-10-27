"""Shared core browser-retrieval plane: transport selection and RawFetch synthesis.

Proves that a ``retrieval_transport='browser'`` provider retrieves through the
injected browser plane (not the HTTP client), that assess/archive stay
transport-agnostic, and that the Patchright retriever synthesizes a ``RawFetch``
from a cookie artifact plus provider-owned retained profile.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing
from datetime import UTC, datetime
from pathlib import Path
from threading import get_ident
from uuid import uuid4

import pytest

from newsclip.browser_readiness import (
    ReadinessCoverageBucket,
    ReadinessTerminalState,
    sample_semantic_snapshot,
)
from newsclip.browser_retrieval import (
    BrowserReadinessObservation,
    BrowserSnapshotRejected,
    PatchrightBrowserRetriever,
)
from newsclip.browser_runtime import (
    BrowserLaunchConfig,
    BrowserRuntimeError,
    HttpOperationRole,
    InfrastructureCategory,
    LeaseBusyError,
    LeaseManager,
    PatchrightRuntime,
    RuntimeTrace,
)
from newsclip.challenge_resolver import (
    ChallengeBlockReason,
    ChallengeResolution,
    ChallengeResolutionStatus,
)
from newsclip.challenges import (
    ChallengeAcceptance,
    ChallengeAcceptanceSource,
    ChallengeDetection,
    ChallengeInfrastructureError,
    ChallengeMode,
    ChallengeState,
    ChallengeVendor,
)
from newsclip.connection_controls import ConnectionControls
from newsclip.errors import (
    ContentNotFullError,
    PersistenceError,
    ProviderDefenseError,
    ProviderTransportError,
    SessionRequiredError,
)
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
)
from newsclip.network import ProviderNetworkPolicy
from newsclip.provider_config import (
    BrowserRetrievalSpec,
    BrowserSemanticReadinessSpec,
    load_provider_spec,
)
from newsclip.providers import ProviderRegistry
from newsclip.results import public_error
from newsclip.service import NewsclipService
from newsclip.timing import (
    StepFinishedEvent,
    TimingOperation,
    TimingRecorder,
    TimingStep,
    TimingTransport,
    iter_timing_runs,
    read_timing_file,
)

NOW = datetime(2026, 7, 17, tzinfo=UTC)
CONTENT_PREFIX = "https://browser.test/story/"
ARTICLE_URL = f"{CONTENT_PREFIX}full-1a2b3c4d"


def _session() -> SessionArtifact:
    return SessionArtifact(
        generation_id=uuid4(),
        provider="browserish",
        created_at=NOW,
        verified_at=NOW,
        cookies=(
            PortableCookie(name="session", value="value", domain=".browser.test"),
        ),
    )


class RecordingHttp:
    """Must never be used for a browser-transport provider's fetch."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url, *, session=None, timeout: float = 40) -> RawFetch:
        self.calls.append(url)
        raise AssertionError("HTTP client used for a browser-transport provider")


class FakeBrowserRetriever:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def get(self, url, *, session=None, timeout: float = 40) -> RawFetch:
        self.calls.append((url, session))
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=True,
            raw_html=b"FULL browser body",
        )


class FakeExtractor:
    name = "fixture-extractor"
    version = "1"

    def extract(
        self,
        fetch: RawFetch,
        *,
        scope_xpath: tuple[str, ...] | None = None,
    ) -> ExtractedArticle:
        return ExtractedArticle(
            body_markdown="Generated browser body.",
            metadata={"title": "Browser article"},
            word_count=250,
        )


class BrowserProvider:
    key = "browserish"
    capabilities = ProviderCapabilities(
        requires_session_for_search=True,
        retrieval_transport="browser",
        search_transport="browser",
    )
    login_recipe = None
    assessment_policy_version = "browserish-v1"
    extraction_scope: tuple[str, ...] | None = None

    def owns_url(self, url: str) -> bool:
        return url.startswith(CONTENT_PREFIX)

    def search(self, http, session, query, filters: SearchFilters):
        fetch = http.get(f"https://browser.test/search?q={query}", session=session)
        return [SearchResult(provider=self.key, url=ARTICLE_URL, headline="Result")][
            : filters.limit if b"FULL" in fetch.raw_html else 0
        ]

    def search_page(
        self,
        http,
        session,
        query,
        filters: SearchFilters,
        *,
        next_url=None,
        metadata_fetch_budget=None,
    ) -> ProviderSearchPage:
        assert next_url is None
        return ProviderSearchPage(
            results=tuple(self.search(http, session, query, filters))
        )

    def fetch(self, http, session, url: str) -> RawFetch:
        return http.get(url, session=session)

    def assess(self, requested_url, fetch, extraction) -> ArticleAssessment:
        full = b"FULL" in fetch.raw_html
        return ArticleAssessment(
            access_state=AccessState.FULL if full else AccessState.TEASER,
            provider_article_id=requested_url.rsplit("/", 1)[-1],
            canonical_url=requested_url,
            identity_match=full,
            structural_signals=("article_body",) if full else (),
            word_count=250,
            reason="full_fixture" if full else "teaser_fixture",
        )

    def rate_budget(self) -> RateBudget:
        return RateBudget(requests_per_second=1000, burst=1000)


class ProfileSource:
    def __init__(self) -> None:
        self.artifact = _session()

    def get_valid_session(self, provider, account_key="default"):
        return self.artifact

    def mark_required(
        self, provider, account_key="default"
    ) -> None:  # pragma: no cover
        self.artifact = None


def _service(**kwargs) -> NewsclipService:
    return NewsclipService(
        ProviderRegistry((BrowserProvider(),)),
        RecordingHttp(),
        FakeExtractor(),
        sessions=ProfileSource(),
        network_sleep=lambda _s: None,
        **kwargs,
    )


def test_browser_transport_provider_retrieves_through_the_plane() -> None:
    retriever = FakeBrowserRetriever()
    service = _service(browser_retriever=retriever)

    article = service.get(ARTICLE_URL)

    assert str(article.url) == ARTICLE_URL
    assert article.provider == "browserish"
    # retrieval went through the browser plane, carrying the cookie authority
    assert len(retriever.calls) == 1
    url, session = retriever.calls[0]
    assert url == ARTICLE_URL
    assert isinstance(session, SessionArtifact)


def test_browser_transport_without_a_plane_fails_closed() -> None:
    service = _service()  # no browser_retriever configured

    with pytest.raises(PersistenceError, match="browser retrieval plane"):
        service.get(ARTICLE_URL)


def test_missing_profile_session_never_reaches_the_plane() -> None:
    class MissingProfiles:
        def get_valid_session(self, provider, account_key="default"):
            raise SessionRequiredError("profile login required")

        def mark_required(self, provider, account_key="default") -> None: ...

    retriever = FakeBrowserRetriever()
    service = NewsclipService(
        ProviderRegistry((BrowserProvider(),)),
        RecordingHttp(),
        FakeExtractor(),
        sessions=MissingProfiles(),
        browser_retriever=retriever,
    )

    with pytest.raises(SessionRequiredError):
        service.get(ARTICLE_URL)
    assert retriever.calls == []


# --- PatchrightBrowserRetriever synthesis ---------------------------------


class FakeResponse:
    status = 200


class FakePage:
    def __init__(self, context) -> None:
        self._context = context

    def goto(self, url, *, wait_until, timeout):
        self._context.goto_calls.append((url, wait_until, timeout))
        self._context.url = url
        return FakeResponse()

    @property
    def url(self) -> str:
        return self._context.url

    def content(self) -> str:
        return "<html><body>FULL browser body</body></html>"


class FakeContext:
    def __init__(self, *, user_data_dir, headless) -> None:
        self.user_data_dir = user_data_dir
        self.headless = headless
        self.url = "about:blank"
        self.goto_calls: list[tuple[str, str, float]] = []
        self.closed = False

    def new_page(self):
        return FakePage(self)

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize("final_status", [200, 206, 403])
def test_challenge_handoff_uses_committed_main_document_response(
    tmp_path, final_status
):
    from types import SimpleNamespace

    class Response:
        def __init__(self, page, status, media, body, *, main=True, navigation=True):
            self.url = page.url
            self.status = status
            self.headers = {"content-type": media}
            self.frame = page.main_frame if main else object()
            self.request = SimpleNamespace(is_navigation_request=lambda: navigation)
            self._body = body

        def body(self):
            return self._body

    class HandoffPage(FakePage):
        def __init__(self, context):
            super().__init__(context)
            self.main_frame = self
            self.handlers = {}

        def on(self, event, callback):
            self.handlers.setdefault(event, []).append(callback)

        def remove_listener(self, event, callback):
            self.handlers[event].remove(callback)

        def emit(self, event, value):
            for callback in self.handlers.get(event, ()):
                callback(value)

        def goto(self, *args, **kwargs):
            super().goto(*args, **kwargs)
            response = Response(self, 403, "text/html", b"interstitial")
            self.emit("response", response)
            self.emit("framenavigated", self)
            return response

    pages = []

    class Context(FakeContext):
        def new_page(self):
            page = HandoffPage(self)
            pages.append(page)
            return page

    class Resolver:
        def resolve(self, browser, mode):
            page = browser.page
            page.emit(
                "response",
                Response(page, final_status, "application/json", b'{"stories":[]}'),
            )
            page.emit("framenavigated", page)
            # None of these is a new committed main document, even at the same URL.
            page.emit(
                "response", Response(page, 500, "text/html", b"iframe", main=False)
            )
            page.emit(
                "response", Response(page, 500, "text/html", b"xhr", navigation=False)
            )
            page.emit("response", Response(page, 500, "text/html", b"uncommitted"))
            return ChallengeResolution(
                status=ChallengeResolutionStatus.CLEARED,
                detection=ChallengeDetection(
                    vendor=ChallengeVendor.HCAPTCHA, state=ChallengeState.INTERACTIVE
                ),
                acceptance=ChallengeAcceptance(
                    accepted=True, source=ChallengeAcceptanceSource.SURFACE_CLEAR
                ),
            )

    retriever = PatchrightBrowserRetriever(
        context_factory=Context,
        profile_resolver=lambda *_: tmp_path / "profile",
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={"publicish": BrowserRetrievalSpec()},
        challenge_resolvers={"publicish": Resolver()},
        challenge_mode=ChallengeMode.AUTO,
        retain_profile=False,
    )
    fetch = retriever.for_provider("publicish").get(ARTICLE_URL)
    assert fetch.content_type == "application/json"
    assert fetch.raw_html == b'{"stories":[]}'
    assert fetch.http_status == final_status
    assert len(pages[0]._context.goto_calls) == 1
    assert all(not callbacks for callbacks in pages[0].handlers.values())


class FakeMonotonicClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _content_readiness(fetch: RawFetch) -> BrowserReadinessObservation:
    promotable = b"FULL" in fetch.raw_html
    return BrowserReadinessObservation(
        ready=promotable,
        assessment_promotable=promotable,
        content_fingerprint=hashlib.sha256(fetch.raw_html).hexdigest(),
        word_count=321 if promotable else 12,
        coverage_bucket=(
            ReadinessCoverageBucket.AT_LEAST_90
            if promotable
            else ReadinessCoverageBucket.UNDER_25
        ),
    )


def _acquire_profile_in_process(
    lock_root: str,
    profile: str,
    acquired,
) -> None:  # noqa: ANN001
    with LeaseManager(Path(lock_root)).profile(
        Path(profile),
        timeout_seconds=1,
    ):
        acquired.set()


def test_semantic_readiness_retains_minimal_incomplete_terminal_evidence() -> None:
    clock = FakeMonotonicClock()

    class ChangingIncompletePage:
        url = ARTICLE_URL
        snapshot = "first promotable body"

        def wait_for_timeout(self, milliseconds: float) -> None:
            clock.advance(milliseconds / 1000)
            self.snapshot = "second promotable body"

        def content(self) -> str:
            return self.snapshot

    def incomplete(fetch: RawFetch) -> BrowserReadinessObservation:
        return BrowserReadinessObservation(
            ready=False,
            assessment_promotable=True,
            content_fingerprint=hashlib.sha256(fetch.raw_html).hexdigest(),
            word_count=412,
            coverage_bucket=ReadinessCoverageBucket.FROM_75_TO_89,
        )

    sampled = sample_semantic_snapshot(
        ChangingIncompletePage(),
        initial_content=b"first promotable body",
        readiness=BrowserSemanticReadinessSpec(
            timeout_seconds=0.2,
            stable_seconds=0.1,
            poll_seconds=0.1,
        ),
        evaluator=lambda current_url, content: incomplete(
            RawFetch(
                requested_url=ARTICLE_URL,
                final_url=current_url,
                http_status=200,
                content_type="text/html",
                retrieved_at=NOW,
                session_cookie_present=True,
                raw_html=content,
            )
        ),
        monotonic_clock=clock,
    )

    assert sampled.terminal_state is (
        ReadinessTerminalState.PROMOTABLE_INCOMPLETE_TIMEOUT
    )
    assert sampled.observation is not None
    assert sampled.observation.word_count == 412
    assert sampled.observation.coverage_bucket is (
        ReadinessCoverageBucket.FROM_75_TO_89
    )
    assert sampled.content_change_count == 1
    assert sampled.last_content_change_ms == 100


def test_semantic_readiness_waits_for_a_stable_promotable_snapshot(
    tmp_path: Path,
) -> None:
    clock = FakeMonotonicClock()

    class IncrementalPage(FakePage):
        snapshots = (
            "TEASER initial",
            "FULL intermediate",
            "FULL final",
            "FULL final",
            "FULL final",
        )

        def __init__(self, context) -> None:
            super().__init__(context)
            self.index = 0
            self.waits: list[float] = []

        def content(self) -> str:
            return self.snapshots[self.index]

        def wait_for_timeout(self, milliseconds: float) -> None:
            self.waits.append(milliseconds)
            clock.advance(milliseconds / 1000)
            self.index = min(self.index + 1, len(self.snapshots) - 1)

    class IncrementalContext(FakeContext):
        def new_page(self):
            self.page = IncrementalPage(self)
            return self.page

    created: list[IncrementalContext] = []

    def factory(**options):
        context = IncrementalContext(**options)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={
            "browserish": BrowserRetrievalSpec(
                semantic_readiness=BrowserSemanticReadinessSpec(
                    timeout_seconds=1,
                    stable_seconds=0.2,
                    poll_seconds=0.1,
                )
            )
        },
        readiness_evaluators={"browserish": _content_readiness},
        clock=lambda: NOW,
        monotonic_clock=clock,
    )

    fetch = retriever.get(ARTICLE_URL, session=_session())

    assert fetch.raw_html == b"FULL final"
    assert created[0].goto_calls == [
        (ARTICLE_URL, "domcontentloaded", 40_000),
    ]
    assert created[0].page.waits == [100.0, 100.0, 100.0, 100.0]
    retriever.close()


def test_semantic_readiness_timeout_returns_latest_snapshot_for_final_assessment(
    tmp_path: Path,
) -> None:
    clock = FakeMonotonicClock()

    class TeaserPage(FakePage):
        snapshots = ("TEASER initial", "TEASER later", "TEASER latest")

        def __init__(self, context) -> None:
            super().__init__(context)
            self.index = 0
            self.waits: list[float] = []

        def content(self) -> str:
            return self.snapshots[self.index]

        def wait_for_timeout(self, milliseconds: float) -> None:
            self.waits.append(milliseconds)
            clock.advance(milliseconds / 1000)
            self.index = min(self.index + 1, len(self.snapshots) - 1)

    class TeaserContext(FakeContext):
        def new_page(self):
            self.page = TeaserPage(self)
            return self.page

    created: list[TeaserContext] = []

    def factory(**options):
        context = TeaserContext(**options)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={
            "browserish": BrowserRetrievalSpec(
                semantic_readiness=BrowserSemanticReadinessSpec(
                    timeout_seconds=0.25,
                    stable_seconds=0.1,
                    poll_seconds=0.1,
                )
            )
        },
        readiness_evaluators={"browserish": _content_readiness},
        clock=lambda: NOW,
        monotonic_clock=clock,
    )

    fetch = retriever.get(ARTICLE_URL, session=_session())

    assert fetch.raw_html == b"TEASER latest"
    assert created[0].goto_calls == [
        (ARTICLE_URL, "domcontentloaded", 40_000),
    ]
    assert created[0].page.waits == [100.0, 100.0, pytest.approx(50.0)]
    retriever.close()


def test_semantic_readiness_timeout_rejects_promotable_incomplete_snapshot(
    tmp_path: Path,
) -> None:
    clock = FakeMonotonicClock()

    class IncompletePage(FakePage):
        def content(self) -> str:
            return "FULL according to assessment but incomplete for provider"

        def wait_for_timeout(self, milliseconds: float) -> None:
            clock.advance(milliseconds / 1000)

    class IncompleteContext(FakeContext):
        def new_page(self):
            self.page = IncompletePage(self)
            return self.page

    created: list[IncompleteContext] = []

    def factory(**options):
        context = IncompleteContext(**options)
        created.append(context)
        return context

    def incomplete_readiness(fetch: RawFetch) -> BrowserReadinessObservation:
        return BrowserReadinessObservation(
            ready=False,
            assessment_promotable=True,
            content_fingerprint=hashlib.sha256(fetch.raw_html).hexdigest(),
            word_count=380,
            coverage_bucket=ReadinessCoverageBucket.FROM_75_TO_89,
        )

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={
            "browserish": BrowserRetrievalSpec(
                semantic_readiness=BrowserSemanticReadinessSpec(
                    timeout_seconds=0.2,
                    stable_seconds=0.1,
                    poll_seconds=0.1,
                )
            )
        },
        readiness_evaluators={"browserish": incomplete_readiness},
        clock=lambda: NOW,
        monotonic_clock=clock,
    )

    with pytest.raises(
        ContentNotFullError,
        match="browser_semantic_readiness_timeout",
    ):
        retriever.get(ARTICLE_URL, session=_session())

    assert created[0].goto_calls == [(ARTICLE_URL, "domcontentloaded", 40_000)]
    assert created[0].closed is True
    retriever.close()


def test_semantic_readiness_rejects_snapshot_first_ready_at_deadline(
    tmp_path: Path,
) -> None:
    clock = FakeMonotonicClock()

    class DeadlinePage(FakePage):
        def __init__(self, context) -> None:
            super().__init__(context)
            self.snapshot = "TEASER initial"

        def content(self) -> str:
            return self.snapshot

        def wait_for_timeout(self, milliseconds: float) -> None:
            clock.advance(milliseconds / 1000)
            self.snapshot = "FULL first seen at deadline"

    class DeadlineContext(FakeContext):
        def new_page(self):
            self.page = DeadlinePage(self)
            return self.page

    created: list[DeadlineContext] = []

    def factory(**options):
        context = DeadlineContext(**options)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={
            "browserish": BrowserRetrievalSpec(
                semantic_readiness=BrowserSemanticReadinessSpec(
                    timeout_seconds=0.1,
                    stable_seconds=0.1,
                    poll_seconds=0.1,
                )
            )
        },
        readiness_evaluators={"browserish": _content_readiness},
        clock=lambda: NOW,
        monotonic_clock=clock,
    )

    with pytest.raises(
        ContentNotFullError,
        match="browser_semantic_readiness_timeout",
    ):
        retriever.get(ARTICLE_URL, session=_session())

    assert created[0].goto_calls == [(ARTICLE_URL, "domcontentloaded", 40_000)]
    assert created[0].closed is True
    retriever.close()


def test_semantic_readiness_requires_an_injected_evaluator(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing=\\['browserish'\\]"):
        PatchrightBrowserRetriever(
            context_factory=lambda **options: FakeContext(**options),
            profile_resolver=lambda provider, account: (
                tmp_path / "profiles" / provider / account
            ),
            lease_manager=LeaseManager(tmp_path / "leases"),
            policies={
                "browserish": BrowserRetrievalSpec(
                    semantic_readiness=BrowserSemanticReadinessSpec(timeout_seconds=1)
                )
            },
            clock=lambda: NOW,
        )


def test_semantic_readiness_rejects_an_unused_evaluator() -> None:
    with pytest.raises(ValueError, match="unused=\\['browserish'\\]"):
        PatchrightBrowserRetriever(
            readiness_evaluators={"browserish": _content_readiness}
        )


def test_semantic_readiness_rejects_an_unused_verification_evaluator() -> None:
    with pytest.raises(
        ValueError, match="semantic browser readiness configuration mismatch"
    ):
        PatchrightBrowserRetriever(
            verification_readiness_evaluators={"browserish": _content_readiness}
        )


def test_browser_challenge_resolvers_must_match_configured_providers() -> None:
    with pytest.raises(ValueError, match="missing=\\['browserish'\\]"):
        PatchrightBrowserRetriever(
            policies={"browserish": BrowserRetrievalSpec()},
            challenge_resolvers={},
        )

    with pytest.raises(ValueError, match="unused=\\['other'\\]"):
        PatchrightBrowserRetriever(
            challenge_resolvers={  # type: ignore[dict-item]
                "other": object()
            }
        )


def test_invalid_browser_response_metadata_is_transport_and_releases_context(
    tmp_path: Path,
) -> None:
    class InvalidFinalUrlPage(FakePage):
        def goto(self, url, *, wait_until, timeout):
            response = super().goto(url, wait_until=wait_until, timeout=timeout)
            self._context.url = "about:blank"
            return response

    class InvalidFinalUrlContext(FakeContext):
        def new_page(self):
            return InvalidFinalUrlPage(self)

    created: list[InvalidFinalUrlContext] = []

    def factory(*, user_data_dir, headless):
        context = InvalidFinalUrlContext(
            user_data_dir=user_data_dir,
            headless=headless,
        )
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        clock=lambda: NOW,
    )

    with pytest.raises(ProviderTransportError, match="metadata is invalid"):
        retriever.get(ARTICLE_URL, session=_session())

    assert created[0].closed is True


def test_required_virtual_display_rejects_factory_only_retriever(
    tmp_path: Path,
) -> None:
    launches = 0
    leases = LeaseManager(tmp_path / "leases")
    profile = tmp_path / "profiles/browserish/default"

    def factory(*, user_data_dir, headless):  # noqa: ANN001
        nonlocal launches
        launches += 1
        return FakeContext(user_data_dir=user_data_dir, headless=headless)

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda _provider, _account: profile,
        lease_manager=leases,
        require_virtual_display=True,
        clock=lambda: NOW,
    )

    with pytest.raises(ProviderTransportError) as caught:
        retriever.get(ARTICLE_URL, session=_session())

    # The plane must not leak the runtime's bare RuntimeError: the public
    # adapters re-raise anything the classifier does not map.
    envelope = public_error(caught.value)
    assert envelope is not None
    assert envelope.exit_code == 5
    cause = caught.value.__cause__
    assert isinstance(cause, BrowserRuntimeError)
    assert cause.category is InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
    assert launches == 0
    with leases.profile(profile, timeout_seconds=0):
        pass


def test_profile_ownership_failure_is_a_local_state_fault(
    tmp_path: Path,
) -> None:
    """A runtime failure on the production path must stay publicly mappable."""

    leases = LeaseManager(tmp_path / "leases")
    profile = tmp_path / "profiles/browserish/default"
    profile.parent.mkdir(parents=True)
    profile.symlink_to(tmp_path / "elsewhere")

    retriever = PatchrightBrowserRetriever(
        runtime=PatchrightRuntime(context_factory=FakeContext),
        profile_resolver=lambda _provider, _account: profile,
        lease_manager=leases,
        clock=lambda: NOW,
    )

    with pytest.raises(PersistenceError) as caught:
        retriever.get(ARTICLE_URL, session=_session())

    envelope = public_error(caught.value)
    assert envelope is not None
    assert envelope.exit_code == 6
    assert envelope.reason == "profile_invalid"
    assert envelope.action == "repair_local_infrastructure"
    cause = caught.value.__cause__
    assert isinstance(cause, BrowserRuntimeError)
    assert cause.category is InfrastructureCategory.PROFILE_INVALID
    with leases.profile(profile, timeout_seconds=0):
        pass


def test_runtime_infrastructure_failure_is_not_retried(tmp_path: Path) -> None:
    """A second launch fails identically, so the policy must not spend one."""

    leases = LeaseManager(tmp_path / "leases")
    profile = tmp_path / "profiles/browserish/default"
    profile.parent.mkdir(parents=True)
    profile.symlink_to(tmp_path / "elsewhere")

    retriever = PatchrightBrowserRetriever(
        runtime=PatchrightRuntime(context_factory=FakeContext),
        profile_resolver=lambda _provider, _account: profile,
        lease_manager=leases,
        clock=lambda: NOW,
    )
    slept: list[float] = []
    client = ProviderNetworkPolicy(retriever, sleep=slept.append).for_provider(
        "browserish",
        RateBudget(requests_per_second=1000, burst=1000),
        http=retriever,
        role=HttpOperationRole.FETCH,
    )

    with pytest.raises(PersistenceError) as caught:
        client.get(ARTICLE_URL, session=_session())

    # The policy sleeps 1.0s between attempts, so an empty log is proof that
    # the second launch was never spent.
    assert slept == []
    assert public_error(caught.value).retryable is False


def test_target_closed_at_browser_startup_retries_once_then_succeeds(
    tmp_path: Path,
) -> None:
    launches = 0

    class RetryContext(FakeContext):
        def add_cookies(self, _cookies) -> None:  # noqa: ANN001
            pass

    def factory(**options):  # noqa: ANN003
        nonlocal launches
        launches += 1
        if launches == 1:
            raise RuntimeError("Target closed")
        return RetryContext(
            user_data_dir=options["user_data_dir"],
            headless=options["headless"],
        )

    retriever = PatchrightBrowserRetriever(
        runtime=PatchrightRuntime(context_factory=factory),
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        clock=lambda: NOW,
    )
    slept: list[float] = []
    client = ProviderNetworkPolicy(retriever, sleep=slept.append).for_provider(
        "browserish",
        RateBudget(requests_per_second=1000, burst=1000),
        http=retriever,
        role=HttpOperationRole.FETCH,
    )

    fetch = client.get(ARTICLE_URL, session=_session())

    assert fetch.http_status == 200
    assert launches == 2
    assert slept == [1.0]
    retriever.close()


def test_repeated_target_closed_at_browser_startup_remains_retryable(
    tmp_path: Path,
) -> None:
    launches = 0

    def factory(**_options):  # noqa: ANN003
        nonlocal launches
        launches += 1
        raise RuntimeError("Target closed")

    retriever = PatchrightBrowserRetriever(
        runtime=PatchrightRuntime(context_factory=factory),
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        clock=lambda: NOW,
    )
    slept: list[float] = []
    client = ProviderNetworkPolicy(retriever, sleep=slept.append).for_provider(
        "browserish",
        RateBudget(requests_per_second=1000, burst=1000),
        http=retriever,
        role=HttpOperationRole.FETCH,
    )

    with pytest.raises(ProviderTransportError) as caught:
        client.get(ARTICLE_URL, session=_session())

    envelope = public_error(caught.value)
    assert envelope is not None
    assert envelope.retryable is True
    assert envelope.action.value == "retry_later"
    assert launches == 2
    assert slept == [1.0]
    retriever.close()


def test_runtime_foreign_close_invalidates_retriever_profile_owner(
    tmp_path: Path,
) -> None:
    created: list[FakeContext] = []
    leases = LeaseManager(tmp_path / "leases")
    profile = tmp_path / "profiles/browserish/default"

    class RuntimeContext(FakeContext):
        def __init__(self, **options) -> None:  # noqa: ANN003
            super().__init__(
                user_data_dir=options["user_data_dir"],
                headless=options["headless"],
            )
            self.pages = [FakePage(self)]
            created.append(self)

        def add_cookies(self, _cookies) -> None:  # noqa: ANN001
            pass

        def close(self) -> None:
            if self is created[0]:
                with (
                    pytest.raises(LeaseBusyError),
                    leases.profile(profile, timeout_seconds=0),
                ):
                    pass
            super().close()

    runtime = PatchrightRuntime(context_factory=RuntimeContext)
    retriever = PatchrightBrowserRetriever(
        runtime=runtime,
        profile_resolver=lambda _provider, _account: profile,
        lease_manager=leases,
        clock=lambda: NOW,
    )

    assert retriever.get(ARTICLE_URL, session=_session()).http_status == 200
    first = created[0]
    assert retriever._held is not None

    with runtime.open(
        tmp_path / "profiles/other/default",
        require_virtual_display=False,
    ):
        pass

    assert first.closed is True
    assert retriever._held is None
    with leases.profile(profile, timeout_seconds=0):
        pass

    assert retriever.get(ARTICLE_URL, session=_session()).http_status == 200
    assert len(created) == 3
    retriever.close()


def test_patchright_retriever_synthesizes_rawfetch_and_closes_context(
    tmp_path: Path,
) -> None:
    created: list[FakeContext] = []

    def factory(*, user_data_dir, headless):
        context = FakeContext(user_data_dir=user_data_dir, headless=headless)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        clock=lambda: NOW,
    )
    fetch = retriever.get(ARTICLE_URL, session=_session())

    assert fetch.http_status == 200
    assert str(fetch.final_url) == ARTICLE_URL
    assert b"FULL browser body" in fetch.raw_html
    assert fetch.session_cookie_present is True
    # R8 provenance: a browser-served fetch names its transport, so the
    # archive can tell it from a curl profile and from a pre-provenance row.
    assert fetch.serving_transport == "browser"
    assert created[0].user_data_dir == str(tmp_path / "profiles/browserish/default")
    # Keep-alive: context stays open across warm gets until explicit close.
    assert created[0].closed is False
    retriever.close()
    assert created[0].closed is True


def test_public_profile_solves_once_without_reloading(
    tmp_path: Path,
) -> None:
    class ChallengePage(FakePage):
        def __init__(self, context) -> None:
            super().__init__(context)
            self.body = "interactive challenge"

        def content(self) -> str:
            return f"<html><body>{self.body}</body></html>"

    class ChallengeContext(FakeContext):
        def new_page(self):
            self.page = ChallengePage(self)
            return self.page

    class ClearingResolver:
        def __init__(self) -> None:
            self.calls: list[tuple[object, ChallengeMode]] = []

        def resolve(self, browser, mode):  # noqa: ANN001
            self.calls.append((browser, mode))
            browser.page.body = "FULL cleared browser body"
            return ChallengeResolution(
                status=ChallengeResolutionStatus.CLEARED,
                detection=ChallengeDetection(
                    vendor=ChallengeVendor.HCAPTCHA,
                    state=ChallengeState.INTERACTIVE,
                ),
                acceptance=ChallengeAcceptance(
                    accepted=True,
                    source=ChallengeAcceptanceSource.SURFACE_CLEAR,
                ),
            )

    created: list[ChallengeContext] = []

    def factory(**options):
        context = ChallengeContext(**options)
        created.append(context)
        return context

    resolver = ClearingResolver()
    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={"publicish": BrowserRetrievalSpec()},
        challenge_resolvers={"publicish": resolver},  # type: ignore[dict-item]
        challenge_mode=ChallengeMode.AUTO,
        clock=lambda: NOW,
    )

    fetch = retriever.for_provider("publicish").get(ARTICLE_URL)

    assert fetch.http_status == 200
    assert fetch.session_cookie_present is False
    assert b"FULL cleared browser body" in fetch.raw_html
    assert created[0].user_data_dir == str(tmp_path / "profiles/publicish/public")
    assert created[0].goto_calls == [(ARTICLE_URL, "domcontentloaded", 40_000)]
    assert len(resolver.calls) == 1
    assert resolver.calls[0][1] is ChallengeMode.AUTO
    retriever.close()


@pytest.mark.parametrize("status", [200, 403, 503])
def test_browser_search_error_response_is_captured_before_handoff(tmp_path, status):
    from types import SimpleNamespace

    created = []
    visits = []

    class Page:
        url = "about:blank"

        def goto(self, url, **kwargs):
            visits.append(url)
            self.url = url
            return SimpleNamespace(status=status)

        def content(self):
            return "<html><body>Inert search response</body></html>"

        def screenshot(self, **kwargs):
            assert not created[0].closed
            return b"private search viewport"

    class Context:
        def __init__(self, **kwargs):
            self.pages = [Page()]
            self.closed = False
            created.append(self)

        def close(self):
            self.closed = True

    trace_path = tmp_path / "trace.jsonl"
    retriever = PatchrightBrowserRetriever(
        runtime=PatchrightRuntime(
            context_factory=Context,
            trace=RuntimeTrace(trace_path, run_id="search-response"),
        ),
        profile_resolver=lambda *_: tmp_path / "profile",
        lease_manager=LeaseManager(tmp_path / "locks"),
        policies={"publicish": BrowserRetrievalSpec()},
    )
    fetch = retriever.for_provider("publicish", role=HttpOperationRole.SEARCH).get(
        ARTICLE_URL
    )
    assert fetch.http_status == status
    assert visits == [ARTICLE_URL]
    assert created[0].closed
    rows = [json.loads(line) for line in trace_path.read_text().splitlines()]
    artifacts = [row["facts"] for row in rows if row["event"] == "diagnostic_artifact"]
    if status < 400:
        assert artifacts == []
    else:
        assert len(artifacts) == 1
        artifact = artifacts[0]
        attempt = next(
            row["facts"] for row in rows if row["event"] == "attempt_started"
        )
        assert artifact["attempt_id"] == attempt["attempt_id"]
        assert artifact["terminal"]
        assert (tmp_path / artifact["path"]).read_bytes() == b"private search viewport"


def test_search_fallback_skips_article_readiness_policy(tmp_path: Path) -> None:
    policy = BrowserRetrievalSpec(
        ready_selectors=("article",),
        ready_timeout_seconds=1,
    )
    created: list[FakeContext] = []

    def factory(**options):
        context = FakeContext(**options)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={"browserish": policy},
        clock=lambda: NOW,
    )

    fetch = retriever.for_provider(
        "browserish",
        role=HttpOperationRole.SEARCH,
    ).get(ARTICLE_URL, session=_session())

    assert b"FULL browser body" in fetch.raw_html
    assert created[0].goto_calls == [(ARTICLE_URL, "domcontentloaded", 40_000)]
    retriever.close()


def test_federated_browser_search_does_not_cross_thread_retained_contexts(
    tmp_path: Path,
) -> None:
    """A CLI-style read/search/read sequence keeps Patchright thread-affine.

    Federated provider pages run in worker threads. A browser retained by the
    caller must be closed before that fan-out, and a browser used by a search
    worker must be closed there before control returns to the caller.
    """

    class ThreadBoundPage(FakePage):
        def goto(self, url, *, wait_until, timeout):
            assert get_ident() == self._context.owner_thread
            return super().goto(url, wait_until=wait_until, timeout=timeout)

    class ThreadBoundContext(FakeContext):
        def __init__(self, **options) -> None:  # noqa: ANN003
            super().__init__(
                user_data_dir=options["user_data_dir"],
                headless=options["headless"],
            )
            self.owner_thread = get_ident()

        def new_page(self):
            return ThreadBoundPage(self)

        def add_cookies(self, _cookies) -> None:  # noqa: ANN001
            assert get_ident() == self.owner_thread

        def close(self) -> None:
            assert get_ident() == self.owner_thread
            super().close()

    created: list[ThreadBoundContext] = []

    def factory(**options):  # noqa: ANN003
        context = ThreadBoundContext(**options)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        runtime=PatchrightRuntime(context_factory=factory),
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={"browserish": BrowserRetrievalSpec()},
        clock=lambda: NOW,
    )
    service = _service(browser_retriever=retriever)

    first = service.get(ARTICLE_URL)
    pager = service.search_pager("markets", SearchFilters(limit=1))
    response = pager.next_batch(1)
    selected = service.get(ARTICLE_URL)
    exhausted = pager.next_batch(1)
    second = service.get(ARTICLE_URL)

    assert str(first.url) == ARTICLE_URL
    assert [str(result.url) for result in response.results] == [ARTICLE_URL]
    assert str(selected.url) == ARTICLE_URL
    assert exhausted.results == ()
    assert str(second.url) == ARTICLE_URL
    assert len(created) == 4
    assert all(context.closed for context in created[:3])
    service.close()
    assert created[3].closed is True


def test_blocked_browser_challenge_is_a_defense_event(
    tmp_path: Path,
) -> None:
    class BlockingResolver:
        def resolve(self, browser, mode):  # noqa: ANN001
            return ChallengeResolution(
                status=ChallengeResolutionStatus.BLOCKED,
                detection=ChallengeDetection(
                    vendor=ChallengeVendor.TURNSTILE,
                    state=ChallengeState.INTERACTIVE,
                ),
                reason=ChallengeBlockReason.UNSUPPORTED,
            )

    retriever = PatchrightBrowserRetriever(
        context_factory=lambda **options: FakeContext(**options),
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={"publicish": BrowserRetrievalSpec()},
        challenge_resolvers={  # type: ignore[dict-item]
            "publicish": BlockingResolver()
        },
        challenge_mode=ChallengeMode.AUTO,
        clock=lambda: NOW,
    )

    with pytest.raises(
        ProviderDefenseError,
        match="turnstile/unsupported",
    ) as captured:
        retriever.for_provider("publicish").get(ARTICLE_URL)

    assert captured.value.provider == "publicish"
    assert captured.value.reason_code == "challenge_challenge_blocked"
    assert retriever._held is None


def test_challenge_infrastructure_failure_is_non_retryable_transport(
    tmp_path: Path,
) -> None:
    class FailingResolver:
        def resolve(self, browser, mode):  # noqa: ANN001
            raise ChallengeInfrastructureError("fixture")

    retriever = PatchrightBrowserRetriever(
        context_factory=lambda **options: FakeContext(**options),
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={"publicish": BrowserRetrievalSpec()},
        challenge_resolvers={"publicish": FailingResolver()},  # type: ignore[dict-item]
        challenge_mode=ChallengeMode.AUTO,
        clock=lambda: NOW,
    )

    with pytest.raises(
        ProviderTransportError,
        match="challenge handling failed",
    ) as caught:
        retriever.for_provider("publicish").get(ARTICLE_URL)

    assert caught.value.retryable is False
    assert retriever._held is None


def test_provider_check_navigation_skips_recovery_warmups(tmp_path: Path) -> None:
    created: list[FakeContext] = []

    def factory(*, user_data_dir, headless):
        context = FakeContext(user_data_dir=user_data_dir, headless=headless)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={
            "browserish": BrowserRetrievalSpec(
                warmup_urls=("https://browser.test/warm",),
                recovery_warmup_urls=("https://browser.test/recover",),
            )
        },
        clock=lambda: NOW,
    )

    fetch = retriever.get_for_check(ARTICLE_URL, session=_session())

    assert fetch.http_status == 200
    assert [url for url, _, _ in created[0].goto_calls] == [ARTICLE_URL]
    retriever.close()


def test_browser_retrieval_timing_exposes_lease_navigation_and_content(
    tmp_path: Path,
) -> None:
    retriever = PatchrightBrowserRetriever(
        context_factory=lambda **kwargs: FakeContext(**kwargs),
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        clock=lambda: NOW,
    )
    recorder = TimingRecorder(tmp_path / "timings")

    with recorder.operation(
        TimingOperation.GET,
        provider="browserish",
        transport=TimingTransport.BROWSER,
    ) as operation:
        retriever.get(ARTICLE_URL, session=_session())

    assert operation.path is not None
    run = read_timing_file(operation.path)
    steps = [
        event.step
        for record in run.records
        if isinstance((event := record.event), StepFinishedEvent)
    ]
    assert steps == [
        TimingStep.PROFILE_LEASE_WAIT,
        TimingStep.BROWSER_OPEN,
        TimingStep.ARTICLE_NAVIGATION,
        TimingStep.CONTENT_READ,
    ]
    retriever.close()


def test_verification_navigation_is_not_counted_as_an_article_attempt(
    tmp_path: Path,
) -> None:
    """A session probe after a failed article read is its own step, not
    ``article_navigation`` attempt 2."""

    retriever = PatchrightBrowserRetriever(
        context_factory=lambda **kwargs: FakeContext(**kwargs),
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={"browserish": BrowserRetrievalSpec()},
        clock=lambda: NOW,
    )
    recorder = TimingRecorder(tmp_path / "timings")

    with recorder.operation(
        TimingOperation.GET,
        provider="browserish",
        transport=TimingTransport.BROWSER,
    ) as operation:
        retriever.get(ARTICLE_URL, session=_session())
        # The anonymous verification form isolates the navigation label from
        # the candidate-authority export checks covered elsewhere.
        retriever._get_for_provider(
            "browserish",
            ARTICLE_URL,
            session=None,
            timeout=40,
            role=HttpOperationRole.VERIFICATION,
            allow_warmups=False,
        )

    assert operation.path is not None
    run = read_timing_file(operation.path)
    navigations = [
        (event.step, event.attempt)
        for record in run.records
        if isinstance((event := record.event), StepFinishedEvent)
        and event.step
        in {TimingStep.ARTICLE_NAVIGATION, TimingStep.VERIFICATION_NAVIGATION}
    ]
    assert navigations == [
        (TimingStep.ARTICLE_NAVIGATION, 1),
        (TimingStep.VERIFICATION_NAVIGATION, 1),
    ]
    retriever.close()


def test_patchright_retriever_preserves_non_html_response_body(
    tmp_path: Path,
) -> None:
    class UnexpectedResolver:
        def resolve(self, browser, mode):  # noqa: ANN001
            raise AssertionError("non-HTML responses must not invoke challenges")

    class JsonResponse:
        status = 200
        headers = {"content-type": "application/json; charset=utf-8"}

        def body(self) -> bytes:
            return b'{"results": []}'

    class JsonPage(FakePage):
        def goto(self, url, *, wait_until, timeout):
            super().goto(url, wait_until=wait_until, timeout=timeout)
            return JsonResponse()

        def content(self) -> str:  # pragma: no cover - must use response body
            raise AssertionError("JSON retrieval must not use the DOM wrapper")

    class JsonContext(FakeContext):
        def new_page(self):
            return JsonPage(self)

    retriever = PatchrightBrowserRetriever(
        context_factory=lambda **kwargs: JsonContext(**kwargs),
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={"browserish": BrowserRetrievalSpec()},
        challenge_resolvers={  # type: ignore[dict-item]
            "browserish": UnexpectedResolver()
        },
        clock=lambda: NOW,
    )

    fetch = retriever.get(ARTICLE_URL, session=_session())

    assert fetch.content_type == "application/json; charset=utf-8"
    assert fetch.raw_html == b'{"results": []}'
    retriever.close()


def test_cookie_artifact_seeds_fresh_browser_recovery_profile(
    tmp_path: Path,
) -> None:
    created: list[object] = []
    readiness_clock = FakeMonotonicClock()

    class RuntimePage:
        def __init__(self) -> None:
            self.url = "about:blank"
            self.visits: list[str] = []
            self.waits: list[float] = []
            self.load_waits: list[tuple[str, float]] = []
            self.routes: list[str] = []
            self.selector_waits: list[tuple[str, float, str]] = []

        def goto(self, url, *, wait_until, timeout):
            self.url = url
            self.visits.append(url)
            return FakeResponse()

        def wait_for_timeout(self, milliseconds: float) -> None:
            self.waits.append(milliseconds)
            readiness_clock.advance(milliseconds / 1000)

        def wait_for_load_state(self, state: str, *, timeout: float) -> None:
            self.load_waits.append((state, timeout))

        def route(self, pattern: str, _handler) -> None:  # noqa: ANN001
            self.routes.append(pattern)

        def wait_for_selector(
            self, selector: str, *, timeout: float, state: str
        ) -> None:
            self.selector_waits.append((selector, timeout, state))

        def content(self) -> str:
            return "<html><body>FULL seeded browser body</body></html>"

    class RuntimeContext:
        def __init__(self, **options) -> None:
            self.options = options
            self.pages = [RuntimePage()]
            self.seeded: list[dict[str, object]] = []
            self.closed = False
            created.append(self)

        def add_cookies(self, cookies) -> None:
            self.seeded.extend(cookies)

        def close(self) -> None:
            self.closed = True

    trace_path = tmp_path / "traces/runtime.jsonl"
    runtime = PatchrightRuntime(
        context_factory=RuntimeContext,
        trace=RuntimeTrace(trace_path, run_id="readiness-terminal"),
    )
    retriever = PatchrightBrowserRetriever(
        runtime=runtime,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "locks"),
        policies={"bloomberg": load_provider_spec("bloomberg").browser_retrieval},
        readiness_evaluators={"bloomberg": _content_readiness},
        launch_configs={
            "bloomberg": BrowserLaunchConfig(
                locale="en-US",
                timezone_id="America/New_York",
                accept_language="en-US,en;q=0.9",
                args=("--provider-browser-argument",),
            )
        },
        clock=lambda: NOW,
        monotonic_clock=readiness_clock,
    )
    session = SessionArtifact(
        generation_id=uuid4(),
        provider="bloomberg",
        created_at=NOW,
        verified_at=NOW,
        cookies=(
            PortableCookie(
                name="_user-token",
                value="PORTABLE_COOKIE_VALUE",
                domain=".bloomberg.com",
                secure=True,
                http_only=True,
                same_site="Lax",
            ),
        ),
    )

    fetch = retriever.get(ARTICLE_URL, session=session)

    context = created[0]
    assert isinstance(context, RuntimeContext)
    assert context.options["user_data_dir"] == str(
        tmp_path / "profiles/bloomberg/default"
    )
    assert context.seeded == [
        {
            "name": "_user-token",
            "value": "PORTABLE_COOKIE_VALUE",
            "domain": ".bloomberg.com",
            "path": "/",
            "secure": True,
            "httpOnly": True,
            "sameSite": "Lax",
        }
    ]
    assert b"FULL seeded browser body" in fetch.raw_html
    assert context.closed is False
    assert context.options["locale"] == "en-US"
    assert context.options["timezone_id"] == "America/New_York"
    assert context.options["args"] == ["--provider-browser-argument"]
    readiness_rows = [
        row
        for line in trace_path.read_text(encoding="utf-8").splitlines()
        if (row := json.loads(line))["event"] == "semantic_readiness_terminal"
    ]
    assert [row["facts"]["state"] for row in readiness_rows] == ["stabilized"]
    assert readiness_rows[0]["facts"]["word_count"] == 321
    assert readiness_rows[0]["facts"]["coverage_bucket"] == "at_least_90"
    assert readiness_rows[0]["facts"]["content_change_count"] == 0
    # Recovery warms owned-host affinity URLs; semantic readiness waits on the
    # same document rather than adding another navigation.
    assert context.pages[0].visits == [
        "https://www.bloomberg.com/",
        "https://www.bloomberg.com/account/profile",
        "https://www.bloomberg.com/subscriptions",
        "https://www.bloomberg.com/",
        ARTICLE_URL,
    ]
    assert context.pages[0].waits == [100.0, 100.0, 100.0]
    assert context.pages[0].load_waits == []
    assert context.pages[0].routes == ["**/*"]
    assert context.pages[0].selector_waits == []

    profile = tmp_path / "profiles/bloomberg/default"
    (profile / "retained-device-state").write_text("warm", encoding="utf-8")
    # Warm reuse keeps the same context; no second launch.
    retriever.get(ARTICLE_URL, session=session)
    assert len(created) == 1
    assert context.pages[0].visits[-1] == ARTICLE_URL
    assert context.pages[0].routes == ["**/*"]  # configured once per page
    assert context.pages[0].selector_waits == []
    assert context.pages[0].waits == [100.0] * 6
    assert context.seeded  # cookies only injected on the empty-profile open
    retriever.close()
    assert context.closed is True


@pytest.mark.parametrize("stable_negative", [False, True])
def test_failed_retained_browser_retrieval_captures_screenshot_before_release(
    tmp_path: Path,
    stable_negative: bool,
) -> None:
    clock = FakeMonotonicClock()
    created: list[object] = []

    class RuntimePage:
        url = "about:blank"

        def goto(self, url, *, wait_until, timeout):
            self.url = url
            return FakeResponse()

        def wait_for_timeout(self, milliseconds: float) -> None:
            clock.advance(milliseconds / 1000)

        def route(self, pattern: str, _handler) -> None:  # noqa: ANN001
            assert pattern == "**/*"

        def content(self) -> str:
            return "<html><body>FULL but incomplete</body></html>"

        def screenshot(self, *, full_page: bool, timeout: int) -> bytes:
            assert full_page is False
            assert timeout == (2_000 if stable_negative else 5_000)
            return b"PRIVATE_SCREENSHOT_BYTES"

    class RuntimeContext:
        def __init__(self, **options) -> None:
            self.options = options
            self.pages = [RuntimePage()]
            self.closed = False
            created.append(self)

        def add_cookies(self, cookies) -> None:  # noqa: ANN001
            assert cookies

        def close(self) -> None:
            self.closed = True

    def incomplete(fetch: RawFetch) -> BrowserReadinessObservation:
        return BrowserReadinessObservation(
            ready=stable_negative,
            assessment_promotable=not stable_negative,
            content_fingerprint=hashlib.sha256(fetch.raw_html).hexdigest(),
            word_count=410,
            coverage_bucket=ReadinessCoverageBucket.FROM_75_TO_89,
        )

    trace_path = tmp_path / "traces/runtime.jsonl"
    retriever = PatchrightBrowserRetriever(
        runtime=PatchrightRuntime(
            context_factory=RuntimeContext,
            trace=RuntimeTrace(trace_path, run_id="retrieval-failure"),
        ),
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "locks"),
        policies={
            "browserish": BrowserRetrievalSpec(
                semantic_readiness=BrowserSemanticReadinessSpec(
                    timeout_seconds=0.2,
                    stable_seconds=0.1,
                    poll_seconds=0.1,
                )
            )
        },
        readiness_evaluators={"browserish": incomplete},
        clock=lambda: NOW,
        monotonic_clock=clock,
    )

    if stable_negative:
        # A native payload can make a DOM teaser ready while its final paid
        # assessment still runs after the browser response is returned.
        fetch = retriever.get(ARTICLE_URL, session=_session())
        assert fetch.raw_html == b"<html><body>FULL but incomplete</body></html>"
        retriever.close()
    else:
        with pytest.raises(
            ContentNotFullError,
            match="browser_semantic_readiness_timeout",
        ) as captured:
            retriever.get(ARTICLE_URL, session=_session())
        assert isinstance(captured.value, BrowserSnapshotRejected)
        assert captured.value.snapshot.terminal_state is (
            ReadinessTerminalState.PROMOTABLE_INCOMPLETE_TIMEOUT
        )
    context = created[0]
    assert isinstance(context, RuntimeContext)
    assert context.closed is True
    label = "content-snapshot" if stable_negative else "failure"
    assert trace_path.with_suffix(f".{label}.png").read_bytes() == (
        b"PRIVATE_SCREENSHOT_BYTES"
    )
    rows = [json.loads(line) for line in trace_path.read_text().splitlines()]
    assert [row["event"] for row in rows] == [
        "browser_started",
        "attempt_started",
        "semantic_readiness_terminal",
        "diagnostic_artifact",
        "attempt_finished",
        "browser_closed",
    ]
    assert rows[2]["facts"]["state"] == (
        "stabilized" if stable_negative else "promotable_incomplete_timeout"
    )


def test_recovery_profile_is_checked_after_acquiring_its_lease(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profiles/browserish/default"
    profile.mkdir(parents=True)
    marker = profile / "retained-device-state"
    marker.write_text("warm", encoding="utf-8")

    class ResetBeforeHeldLease(LeaseManager):
        def hold_profile(self, selected: Path, *, timeout_seconds: float = 10):
            with self.profile(selected, timeout_seconds=timeout_seconds):
                marker.unlink()
            return super().hold_profile(
                selected,
                timeout_seconds=timeout_seconds,
            )

    class SeedingContext(FakeContext):
        def __init__(self, **options) -> None:
            super().__init__(**options)
            self.seeded: list[dict[str, object]] = []

        def add_cookies(self, cookies) -> None:
            self.seeded.extend(cookies)

    created: list[SeedingContext] = []

    def factory(**options):
        context = SeedingContext(**options)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: profile,
        lease_manager=ResetBeforeHeldLease(tmp_path / "locks"),
        clock=lambda: NOW,
    )

    retriever.get(ARTICLE_URL, session=_session())

    assert not marker.exists()
    assert created[0].seeded == [
        {
            "name": "session",
            "value": "value",
            "domain": ".browser.test",
            "path": "/",
            "secure": False,
            "httpOnly": False,
        }
    ]
    retriever.close()


def test_patchright_retriever_requires_session_identity_and_profile_resolver() -> None:
    retriever = PatchrightBrowserRetriever(context_factory=lambda **_: None)

    with pytest.raises(ValueError, match="verified session artifact"):
        retriever.get(ARTICLE_URL, session=None)
    with pytest.raises(ValueError, match="profile resolver"):
        retriever.get(ARTICLE_URL, session=_session())


def test_browser_transport_search_carries_the_profile_session() -> None:
    """Search on the browser plane resolves the profile session up front —
    the retriever refuses to launch without one, so ``session=None`` search
    would be dead on arrival."""

    retriever = FakeBrowserRetriever()
    service = _service(browser_retriever=retriever)

    results = service.search("browserish", "chipmaker")

    assert [str(result.url) for result in results] == [ARTICLE_URL]
    assert len(retriever.calls) == 1
    _, session = retriever.calls[0]
    assert isinstance(session, SessionArtifact)


def test_browser_transport_search_without_session_is_session_required() -> None:
    class MissingProfiles:
        def get_valid_session(self, provider, account_key="default"):
            raise SessionRequiredError("profile login required")

        def mark_required(
            self, provider, account_key="default", *, generation_id=None
        ) -> None: ...

    retriever = FakeBrowserRetriever()
    service = NewsclipService(
        ProviderRegistry((BrowserProvider(),)),
        RecordingHttp(),
        FakeExtractor(),
        sessions=MissingProfiles(),
        browser_retriever=retriever,
    )

    with pytest.raises(SessionRequiredError):
        service.search("browserish", "chipmaker")
    assert retriever.calls == []


def test_public_search_stays_on_http_for_a_browser_article_provider(
    tmp_path: Path,
) -> None:
    class PublicBrowserProvider(BrowserProvider):
        capabilities = ProviderCapabilities(
            retrieval_transport="browser",
            search_transport="http",
        )

    class PublicHttp:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def get(self, url, *, session=None, timeout: float = 40) -> RawFetch:
            self.calls.append(url)
            return RawFetch(
                requested_url=url,
                final_url=url,
                http_status=200,
                content_type="text/html",
                retrieved_at=NOW,
                session_cookie_present=session is not None,
                raw_html=b"FULL public search",
            )

    http = PublicHttp()
    retriever = FakeBrowserRetriever()
    recorder = TimingRecorder(tmp_path / "timings")
    service = NewsclipService(
        ProviderRegistry((PublicBrowserProvider(),)),
        http,
        FakeExtractor(),
        sessions=ProfileSource(),
        browser_retriever=retriever,
        network_sleep=lambda _seconds: None,
        timing=recorder,
    )

    results = service.search("browserish", "chipmaker")
    article = service.get(ARTICLE_URL)

    assert [str(result.url) for result in results] == [ARTICLE_URL]
    assert str(article.url) == ARTICLE_URL
    assert http.calls == ["https://browser.test/search?q=chipmaker"]
    assert [call[0] for call in retriever.calls] == [ARTICLE_URL]
    transports = {
        run.started.operation: run.started.transport
        for run in iter_timing_runs(recorder.root)
    }
    assert transports == {
        TimingOperation.SEARCH: TimingTransport.HTTP,
        TimingOperation.GET: TimingTransport.BROWSER,
    }


def test_patchright_retriever_wraps_driver_failures_as_transport(
    tmp_path: Path,
) -> None:
    class ExplodingContext(FakeContext):
        def new_page(self):
            raise RuntimeError("Target page, context or browser has been closed")

    retriever = PatchrightBrowserRetriever(
        context_factory=lambda **kw: ExplodingContext(**kw),
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        clock=lambda: NOW,
    )

    with pytest.raises(ProviderTransportError, match="RuntimeError"):
        retriever.get(ARTICLE_URL, session=_session())
    assert retriever._held is None
    retriever.close()


def test_patchright_retriever_treats_missing_response_as_transport(
    tmp_path: Path,
) -> None:
    class NoResponsePage(FakePage):
        def goto(self, url, *, wait_until, timeout):
            super().goto(url, wait_until=wait_until, timeout=timeout)
            return None

    class NoResponseContext(FakeContext):
        def new_page(self):
            return NoResponsePage(self)

    created: list[NoResponseContext] = []

    def factory(*, user_data_dir, headless):
        context = NoResponseContext(user_data_dir=user_data_dir, headless=headless)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        clock=lambda: NOW,
    )

    with pytest.raises(ProviderTransportError, match="no HTTP response"):
        retriever.get(ARTICLE_URL, session=_session())
    # A failed page is never reused: target/context failures tend to be sticky,
    # and retaining the profile lease would block repair/login operations.
    assert created[0].closed is True
    assert retriever._held is None
    with pytest.raises(ProviderTransportError, match="no HTTP response"):
        retriever.get(ARTICLE_URL, session=_session())
    assert len(created) == 2
    assert created[1].closed is True
    retriever.close()


def test_failed_retrieval_preserves_primary_error_when_cleanup_also_fails(
    tmp_path: Path,
) -> None:
    class NoResponsePage(FakePage):
        def goto(self, url, *, wait_until, timeout):
            super().goto(url, wait_until=wait_until, timeout=timeout)
            return None

    class CleanupFailureContext(FakeContext):
        def new_page(self):
            return NoResponsePage(self)

        def close(self) -> None:
            self.closed = True
            raise RuntimeError("fixture cleanup failure")

    retriever = PatchrightBrowserRetriever(
        context_factory=lambda **kwargs: CleanupFailureContext(**kwargs),
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        clock=lambda: NOW,
    )

    with pytest.raises(ProviderTransportError, match="no HTTP response"):
        retriever.get(ARTICLE_URL, session=_session())
    assert retriever._held is None


def test_successful_read_survives_cleanup_fault(
    tmp_path: Path,
) -> None:
    class CleanupFailureContext(FakeContext):
        def close(self) -> None:
            raise RuntimeError("PRIVATE_CLEANUP_DETAIL")

    retriever = PatchrightBrowserRetriever(
        context_factory=CleanupFailureContext,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        retain_profile=False,
        clock=lambda: NOW,
    )
    fetch = retriever.get(ARTICLE_URL, session=_session())
    assert fetch.http_status == 200
    assert fetch.raw_html
    assert retriever._held is None


def test_ready_selector_timeout_is_nonfatal_but_other_driver_errors_release(
    tmp_path: Path,
) -> None:
    class SelectorPage(FakePage):
        def __init__(self, context, error: Exception) -> None:
            super().__init__(context)
            self._error = error

        def wait_for_selector(self, *_args, **_kwargs) -> None:  # noqa: ANN002, ANN003
            raise self._error

    class SelectorContext(FakeContext):
        def __init__(self, *, error: Exception, **kwargs) -> None:  # noqa: ANN003
            super().__init__(**kwargs)
            self.error = error

        def new_page(self):
            return SelectorPage(self, self.error)

    errors: list[Exception] = [TimeoutError(), ValueError("invalid selector")]
    created: list[SelectorContext] = []

    def factory(**kwargs):  # noqa: ANN003
        context = SelectorContext(error=errors[len(created)], **kwargs)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        policies={"browserish": BrowserRetrievalSpec(ready_selectors=("article",))},
        clock=lambda: NOW,
    )

    assert retriever.get(ARTICLE_URL, session=_session()).http_status == 200
    retriever.release()
    with pytest.raises(ProviderTransportError, match="ValueError"):
        retriever.get(ARTICLE_URL, session=_session())
    assert all(context.closed for context in created)
    assert retriever._held is None


def test_keep_alive_skips_relaunch_on_second_warm_get(tmp_path: Path) -> None:
    """Second get on the same profile must not pay browser_open again."""

    created: list[FakeContext] = []

    def factory(*, user_data_dir, headless):
        context = FakeContext(user_data_dir=user_data_dir, headless=headless)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=LeaseManager(tmp_path / "leases"),
        clock=lambda: NOW,
    )
    recorder = TimingRecorder(tmp_path / "timings")
    with recorder.operation(
        TimingOperation.GET,
        provider="browserish",
        transport=TimingTransport.BROWSER,
    ):
        retriever.get(ARTICLE_URL, session=_session())
    with recorder.operation(
        TimingOperation.GET,
        provider="browserish",
        transport=TimingTransport.BROWSER,
    ) as second:
        retriever.get(ARTICLE_URL + "-b", session=_session())

    assert len(created) == 1
    assert second.path is not None
    second_steps = [
        event.step
        for record in read_timing_file(second.path).records
        if isinstance((event := record.event), StepFinishedEvent)
    ]
    assert TimingStep.BROWSER_OPEN not in second_steps
    assert TimingStep.ARTICLE_NAVIGATION in second_steps
    retriever.close()
    assert created[0].closed is True


def test_stale_admitted_session_cannot_reopen_browser_after_disconnect(tmp_path):
    controls = ConnectionControls(tmp_path)
    created = []

    def factory(**options):
        context = FakeContext(**options)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda _provider, _account: tmp_path / "profile",
        lease_manager=LeaseManager(tmp_path / "leases"),
        authorize_session=lambda artifact: controls.require_active(
            artifact.provider, artifact.account_key
        ),
        clock=lambda: NOW,
    )
    admitted = _session()
    retriever.warm(admitted)
    assert len(created) == 1
    controls.suspend(admitted.provider)
    retriever.release()
    assert created[0].closed
    with pytest.raises(SessionRequiredError):
        retriever.get(ARTICLE_URL, session=admitted)
    with pytest.raises(SessionRequiredError):
        retriever.warm(admitted)
    assert len(created) == 1
    retriever.close()


def test_request_scoped_retrieval_releases_profile_before_return(
    tmp_path: Path,
) -> None:
    created: list[FakeContext] = []
    profile = tmp_path / "profiles/browserish/default"
    lock_root = tmp_path / "leases"

    def factory(*, user_data_dir, headless):
        context = FakeContext(user_data_dir=user_data_dir, headless=headless)
        created.append(context)
        return context

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda _provider, _account: profile,
        lease_manager=LeaseManager(lock_root),
        retain_profile=False,
        clock=lambda: NOW,
    )

    retriever.warm(_session())
    assert created == []

    assert retriever.get(ARTICLE_URL, session=_session()).http_status == 200
    assert retriever._held is None
    assert created[0].closed is True

    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    process = context.Process(
        target=_acquire_profile_in_process,
        args=(str(lock_root), str(profile), acquired),
    )
    process.start()
    try:
        assert acquired.wait(timeout=5)
        process.join(timeout=5)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)

    retriever.close()


def test_profile_lock_serializes_retrievals_on_one_profile(tmp_path) -> None:
    """Keep-alive reuses one live context; concurrent gets never double-launch."""

    profile_dir = tmp_path / "profile"
    profile_dir.mkdir()
    session = _session()
    launches: list[int] = []
    live = {"count": 0}

    class ObservingContext(FakeContext):
        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            live["count"] += 1
            launches.append(live["count"])

        def close(self) -> None:
            live["count"] -= 1
            super().close()

    import threading

    retriever = PatchrightBrowserRetriever(
        context_factory=lambda **kw: ObservingContext(**kw),
        profile_resolver=lambda provider, account: profile_dir,
        clock=lambda: NOW,
    )
    threads = [
        threading.Thread(target=lambda: retriever.get(ARTICLE_URL, session=session))
        for _ in range(4)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert launches == [1]  # single keep-alive context for the profile
    retriever.close()
    assert live["count"] == 0


@pytest.mark.parametrize(
    "promotable,capture_fails", [(True, False), (False, False), (False, True)]
)
def test_http_200_terminal_evidence_precedes_teardown_without_readiness_policy(
    tmp_path, promotable, capture_fails
):
    contexts = []
    captures = []

    class Page:
        url = "about:blank"

        def route(self, *_):
            pass

        def goto(self, url, **kwargs):
            self.url = url
            return FakeResponse()

        def content(self):
            return "<html><body>inert terminal response</body></html>"

        def screenshot(self, **kwargs):
            assert not contexts[0].closed
            captures.append(self.url)
            if capture_fails:
                raise RuntimeError("inert capture failure")
            return b"private terminal viewport"

    class Context:
        def __init__(self, **kwargs):
            self.pages = [Page()]
            self.closed = False
            contexts.append(self)

        def add_cookies(self, cookies):
            pass

        def close(self):
            self.closed = True

    retriever = PatchrightBrowserRetriever(
        runtime=PatchrightRuntime(
            context_factory=Context,
            trace=RuntimeTrace(tmp_path / "trace.jsonl", run_id="terminal-fixture"),
        ),
        profile_resolver=lambda *_: tmp_path / "profile",
        lease_manager=LeaseManager(tmp_path / "locks"),
        retain_profile=False,
        policies={"browserish": BrowserRetrievalSpec()},
        readiness_evaluators={
            "browserish": lambda fetch: BrowserReadinessObservation(
                ready=promotable,
                assessment_promotable=promotable,
                content_fingerprint="inert",
                word_count=400,
                coverage_bucket=ReadinessCoverageBucket.UNAVAILABLE,
            )
        },
    )
    try:
        fetch = retriever.get(ARTICLE_URL, session=_session())
        assert contexts[0].closed
        assert fetch.http_status == 200
        assert fetch.raw_html == b"<html><body>inert terminal response</body></html>"
        assert "diagnostics" not in fetch.model_dump()
        from newsclip.live_reporting import collect_live_evidence

        attempt = collect_live_evidence(tmp_path).attempts[0]
        assert attempt.last_navigation.status == 200
        assert attempt.last_navigation.destination == "unknown"  # fixture has no URL
        assert attempt.last_navigation.elapsed_ms >= 0
        if promotable:
            assert captures == []
            assert fetch.diagnostics.screenshot_status == "not_requested"
        else:
            assert captures == [ARTICLE_URL]
            assert fetch.diagnostics.screenshot_status == (
                "capture_failed" if capture_fails else "captured"
            )
            assert fetch.diagnostics.trace
            if not capture_fails:
                assert fetch.diagnostics.screenshot == b"private terminal viewport"
    finally:
        retriever.close()


@pytest.mark.parametrize(
    "operation", ["get", "save", "provider_check", "provider_check_search"]
)
@pytest.mark.parametrize("capture_fails", [False, True])
def test_browser_defense_exception_preserves_protected_terminal_evidence(
    tmp_path, operation, capture_fails
):
    from test_defense_service import FakeArchive, _Clock
    from test_incidents import _identity

    from newsclip.defense import BASE_COOLDOWN_SECONDS, DefenseState
    from newsclip.incidents import IncidentStore
    from newsclip.provider_config import ProviderCheckSpec

    clock = _Clock()
    contexts, navigations, captures = [], [], []
    blocked = True

    class Page:
        url = "about:blank"

        def route(self, *_):
            pass

        def goto(self, url, **kwargs):
            self.url = url
            navigations.append(url)
            return FakeResponse()

        def content(self):
            return "<html>inert challenge</html>" if blocked else "<html>FULL</html>"

        def screenshot(self, **kwargs):
            assert not contexts[-1].closed
            captures.append(self.url)
            if capture_fails:
                raise RuntimeError("inert capture failure")
            return b"private challenge viewport"

    class Context:
        def __init__(self, **kwargs):
            self.pages = [Page()]
            self.closed = False
            contexts.append(self)

        def add_cookies(self, cookies):
            pass

        def close(self):
            self.closed = True

    class Resolver:
        def resolve(self, browser, mode):
            return ChallengeResolution(
                status=(
                    ChallengeResolutionStatus.BLOCKED
                    if blocked
                    else ChallengeResolutionStatus.NOT_PRESENT
                ),
                detection=ChallengeDetection(
                    vendor=ChallengeVendor.TURNSTILE
                    if blocked
                    else ChallengeVendor.NONE,
                    state=ChallengeState.INTERACTIVE
                    if blocked
                    else ChallengeState.NONE,
                ),
                reason=ChallengeBlockReason.UNSUPPORTED if blocked else None,
            )

    class Provider(BrowserProvider):
        check = ProviderCheckSpec(query="canary", canonical_url=ARTICLE_URL)
        capabilities = ProviderCapabilities(
            requires_session_for_retrieve=False,
            retrieval_transport="browser",
            search_transport="browser",
        )

        def search_page(self, http, *args, **kwargs):
            if operation == "provider_check_search":
                http.get(ARTICLE_URL)
            return ProviderSearchPage(
                results=(
                    SearchResult(provider=self.key, url=ARTICLE_URL, headline="Inert"),
                )
            )

    defense = DefenseState(
        tmp_path / "defense", utc_now=clock, incident_root=tmp_path / "incidents"
    )
    incidents = IncidentStore(tmp_path / "incidents", build_identity=_identity())
    retriever = PatchrightBrowserRetriever(
        runtime=PatchrightRuntime(
            context_factory=Context,
            trace=RuntimeTrace(tmp_path / "trace.jsonl", run_id="defense-fixture"),
        ),
        profile_resolver=lambda *_: tmp_path / "profile",
        lease_manager=LeaseManager(tmp_path / "locks"),
        policies={"browserish": BrowserRetrievalSpec()},
        challenge_resolvers={"browserish": Resolver()},
        retain_profile=False,
    )
    service = NewsclipService(
        ProviderRegistry((Provider(),)),
        RecordingHttp(),
        FakeExtractor(),
        archive=FakeArchive(),
        browser_retriever=retriever,
        defense=defense,
        incidents=incidents,
        wall_clock=clock,
    )
    try:
        if operation.startswith("provider_check"):
            result = service.provider_check("browserish")
            incident_id = result.incident_id
            assert result.defense_observation == "observed"
        else:
            with pytest.raises(ProviderDefenseError) as captured:
                getattr(service, operation)(ARTICLE_URL)
            incident_id = captured.value.incident_id
        assert incident_id is not None
        assert contexts[-1].closed
        assert defense.status("browserish").incident_id == incident_id
        capsule = incidents.load(incident_id)
        assert capsule.screenshot_status == (
            "capture_failed" if capture_fails else "captured"
        )
        assert (
            incidents.capture_path(capsule).read_bytes()
            == b"<html>inert challenge</html>"
        )
        assert incidents.diagnostic_bytes(capsule, "trace")
        assert incidents.evidence_health(incident_id).status == (
            "partial" if capture_fails else "complete"
        )
        assert captures == [ARTICLE_URL] * (2 if capture_fails else 1)
        with pytest.raises(ProviderDefenseError):
            service.get(ARTICLE_URL)
        assert navigations == [ARTICLE_URL]
        blocked = False
        clock.advance(BASE_COOLDOWN_SECONDS + 1)
        assert str(service.get(ARTICLE_URL).url) == ARTICLE_URL
        assert defense.status("browserish") is None
    finally:
        service.close()
