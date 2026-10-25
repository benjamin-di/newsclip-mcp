"""Bounds on one browser read: lock wait, total deadline and retry boundary.

A browser read may be retried by the network policy only while no provider
navigation has happened (startup target closure). Once the provider has been
contacted, or when the plane or profile is held by another owner, a second
launch would repeat the navigation or queue behind the same holder.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from newsclip import browser_retrieval
from newsclip.browser_readiness import (
    BrowserReadinessObservation,
    ReadinessCoverageBucket,
)
from newsclip.browser_retrieval import PatchrightBrowserRetriever
from newsclip.browser_runtime import HttpOperationRole, LeaseBusyError, LeaseManager
from newsclip.errors import ProviderTransportError, TransportFailure
from newsclip.models import PortableCookie, RateBudget, RawFetch, SessionArtifact
from newsclip.network import ProviderNetworkPolicy
from newsclip.provider_config import (
    BrowserRetrievalSpec,
    BrowserSemanticReadinessSpec,
)
from newsclip.results import public_error

NOW = datetime(2026, 7, 17, tzinfo=UTC)
ARTICLE_URL = "https://browser.test/story/full-1a2b3c4d"
WARMUP_URL = "https://browser.test/"


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


class Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class Response:
    status = 200


class Page:
    def __init__(self, context: Context) -> None:
        self._context = context

    @property
    def url(self) -> str:
        return self._context.url

    def goto(self, url, *, wait_until, timeout):  # noqa: ANN001
        self._context.goto_calls.append((url, timeout))
        self._context.url = url
        return self._context.on_goto(url)

    def content(self) -> str:
        return "<html><body>FULL browser body</body></html>"

    def wait_for_timeout(self, milliseconds: float) -> None:
        self._context.clock.value += milliseconds / 1000


class Context:
    def __init__(self, clock: Clock, on_goto) -> None:  # noqa: ANN001
        self.clock = clock
        self.on_goto = on_goto
        self.url = "about:blank"
        self.goto_calls: list[tuple[str, float]] = []
        self.closed = False

    def new_page(self) -> Page:
        return Page(self)

    def close(self) -> None:
        self.closed = True


def _retriever(
    tmp_path: Path,
    clock: Clock,
    on_goto,  # noqa: ANN001
    *,
    policy: BrowserRetrievalSpec | None = None,
    readiness: bool = False,
    lease_manager: object | None = None,
) -> tuple[PatchrightBrowserRetriever, list[Context]]:
    contexts: list[Context] = []

    def factory(**_options) -> Context:  # noqa: ANN003
        context = Context(clock, on_goto)
        contexts.append(context)
        return context

    def ready(fetch: RawFetch) -> BrowserReadinessObservation:
        return BrowserReadinessObservation(
            ready=True,
            assessment_promotable=True,
            content_fingerprint="fixed",
            word_count=321,
            coverage_bucket=ReadinessCoverageBucket.AT_LEAST_90,
        )

    retriever = PatchrightBrowserRetriever(
        context_factory=factory,
        profile_resolver=lambda provider, account: (
            tmp_path / "profiles" / provider / account
        ),
        lease_manager=lease_manager or LeaseManager(tmp_path / "leases"),
        policies={"browserish": policy or BrowserRetrievalSpec()},
        readiness_evaluators={"browserish": ready} if readiness else None,
        clock=lambda: NOW,
        monotonic_clock=clock,
    )
    return retriever, contexts


def _policy_client(retriever: PatchrightBrowserRetriever, slept: list[float]):
    return ProviderNetworkPolicy(retriever, sleep=slept.append).for_provider(
        "browserish",
        RateBudget(requests_per_second=1000, burst=1000),
        http=retriever,
        role=HttpOperationRole.FETCH,
    )


def test_failure_after_navigation_is_not_relaunched(tmp_path: Path) -> None:
    class DriverFailure(Exception):
        pass

    def fail(_url: str) -> Response:
        raise DriverFailure("navigation failed")

    retriever, contexts = _retriever(tmp_path, Clock(), fail)
    slept: list[float] = []

    with pytest.raises(ProviderTransportError) as caught:
        _policy_client(retriever, slept).get(ARTICLE_URL, session=_session())

    # One launch and one navigation: the policy sleeps before a retry, so an
    # empty log proves no second launch was spent.
    assert len(contexts) == 1
    assert contexts[0].goto_calls == [(ARTICLE_URL, 40_000)]
    assert slept == []
    assert caught.value.retryable is False
    assert str(caught.value) == "browser retrieval failed: DriverFailure"
    retriever.close()


def test_missing_response_after_navigation_is_not_relaunched(tmp_path: Path) -> None:
    retriever, contexts = _retriever(tmp_path, Clock(), lambda _url: None)
    slept: list[float] = []

    with pytest.raises(ProviderTransportError) as caught:
        _policy_client(retriever, slept).get(ARTICLE_URL, session=_session())

    assert str(caught.value) == "browser navigation produced no HTTP response"
    assert caught.value.retryable is False
    assert len(contexts) == 1
    assert slept == []
    retriever.close()


def test_busy_profile_lease_is_not_retried(tmp_path: Path) -> None:
    class BusyLeases:
        calls = 0

        def hold_profile(self, _profile: Path, **_kwargs):  # noqa: ANN003
            BusyLeases.calls += 1
            raise LeaseBusyError("lease acquisition timed out")

    retriever, contexts = _retriever(
        tmp_path, Clock(), lambda _url: Response(), lease_manager=BusyLeases()
    )
    slept: list[float] = []

    with pytest.raises(ProviderTransportError) as caught:
        _policy_client(retriever, slept).get(ARTICLE_URL, session=_session())

    assert str(caught.value) == "browser profile is busy"
    assert caught.value.retryable is False
    assert BusyLeases.calls == 1
    assert contexts == []
    assert slept == []


def test_plane_lock_wait_is_bounded_and_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(browser_retrieval, "BROWSER_LOCK_WAIT_SECONDS", 0.05)
    retriever, contexts = _retriever(tmp_path, Clock(), lambda _url: Response())
    holding = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with retriever._lock:
            holding.set()
            release.wait(5)

    holder = threading.Thread(target=hold)
    holder.start()
    assert holding.wait(1)
    slept: list[float] = []
    try:
        with pytest.raises(ProviderTransportError) as caught:
            _policy_client(retriever, slept).get(ARTICLE_URL, session=_session())
    finally:
        release.set()
        holder.join(5)

    assert str(caught.value) == "browser retrieval plane is busy"
    assert caught.value.retryable is False
    envelope = public_error(caught.value)
    assert envelope is not None
    assert envelope.category.value == "transport"
    assert contexts == []
    assert slept == []
    # Once the holder leaves, the plane serves normally.
    assert retriever.get(ARTICLE_URL, session=_session()).http_status == 200
    retriever.close()


def test_article_navigation_is_clamped_to_the_operation_deadline(
    tmp_path: Path,
) -> None:
    clock = Clock()

    def slow_warmup(url: str) -> Response:
        if url == WARMUP_URL:
            clock.value += 80
        return Response()

    retriever, contexts = _retriever(
        tmp_path,
        clock,
        slow_warmup,
        policy=BrowserRetrievalSpec(warmup_urls=(WARMUP_URL,)),
    )

    fetch = retriever.get(ARTICLE_URL, session=_session())

    assert fetch.http_status == 200
    # The warm-up keeps its full configured timeout; the article navigation
    # gets only what is left of the 100 s ceiling.
    assert contexts[0].goto_calls == [
        (WARMUP_URL, 40_000),
        (ARTICLE_URL, pytest.approx(20_000)),
    ]
    retriever.close()


def test_exhausted_deadline_skips_navigation_and_is_a_timeout(
    tmp_path: Path,
) -> None:
    clock = Clock()

    def exhausting_warmup(url: str) -> Response:
        clock.value += browser_retrieval.BROWSER_OPERATION_CEILING_SECONDS
        return Response()

    retriever, contexts = _retriever(
        tmp_path,
        clock,
        exhausting_warmup,
        policy=BrowserRetrievalSpec(warmup_urls=(WARMUP_URL, WARMUP_URL)),
    )
    slept: list[float] = []

    with pytest.raises(ProviderTransportError) as caught:
        _policy_client(retriever, slept).get(ARTICLE_URL, session=_session())

    assert str(caught.value) == "browser operation deadline exceeded"
    assert caught.value.category is TransportFailure.TIMEOUT
    assert caught.value.retryable is False
    # The second warm-up and the article navigation were never dispatched.
    assert [url for url, _ in contexts[0].goto_calls] == [WARMUP_URL]
    assert slept == []
    retriever.close()


def test_semantic_readiness_is_refused_rather_than_truncated(
    tmp_path: Path,
) -> None:
    clock = Clock()

    def slow_article(_url: str) -> Response:
        clock.value += 95
        return Response()

    retriever, contexts = _retriever(
        tmp_path,
        clock,
        slow_article,
        policy=BrowserRetrievalSpec(
            semantic_readiness=BrowserSemanticReadinessSpec(
                timeout_seconds=8, stable_seconds=0.5, poll_seconds=0.1
            )
        ),
        readiness=True,
    )

    with pytest.raises(ProviderTransportError) as caught:
        retriever.get(ARTICLE_URL, session=_session())

    # A truncated sample would report a slow render as a content verdict.
    assert caught.value.category is TransportFailure.TIMEOUT
    assert caught.value.retryable is False
    assert len(contexts[0].goto_calls) == 1
    retriever.close()


def test_readiness_keeps_its_full_budget_while_time_remains(tmp_path: Path) -> None:
    clock = Clock()

    def article(_url: str) -> Response:
        clock.value += 90
        return Response()

    retriever, _contexts = _retriever(
        tmp_path,
        clock,
        article,
        policy=BrowserRetrievalSpec(
            semantic_readiness=BrowserSemanticReadinessSpec(
                timeout_seconds=8, stable_seconds=0.5, poll_seconds=0.1
            )
        ),
        readiness=True,
    )

    fetch = retriever.get(ARTICLE_URL, session=_session())

    assert fetch.raw_html == b"<html><body>FULL browser body</body></html>"
    retriever.close()
