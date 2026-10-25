"""Service-level defense containment: gate, arm, clear across retrieval."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from newsclip.defense import BASE_COOLDOWN_SECONDS, DefenseState
from newsclip.errors import ContentNotFullError, ProviderDefenseError
from newsclip.incidents import IncidentStore
from newsclip.models import (
    AccessState,
    ArticleAssessment,
    ExtractedArticle,
    ProviderCapabilities,
    ProviderSearchPage,
    RateBudget,
    RawFetch,
    SearchFilters,
    SearchResult,
    SessionArtifact,
    SourceSearchState,
)
from newsclip.provenance import BuildIdentity, BuildIdentitySource
from newsclip.providers import ProviderRegistry
from newsclip.service import NewsclipService

NOW = datetime(2026, 7, 28, tzinfo=UTC)
ARTICLE_ID = "fixture-article"
ARTICLE_URL = f"https://fixture.test/content/{ARTICLE_ID}"


class FakeHttp:
    def __init__(self, *, challenge: bool = False, http_status: int = 200) -> None:
        self.challenge = challenge
        self.http_status = http_status
        self.calls: list[str] = []

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.calls.append(url)
        if self.challenge:
            raise ProviderDefenseError(
                "fixture returned an unsupported interactive challenge",
                provider="fixture",
            )
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=self.http_status,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=False,
            raw_html=b"FULL_FIXTURE_BODY",
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
            body_markdown="Generated fixture article body.",
            metadata={"title": "Fixture article"},
            word_count=4,
        )


class FakeArchive:
    def __init__(self) -> None:
        self.saved: list[tuple[object, ...]] = []

    def save(self, *values) -> None:  # noqa: ANN002
        self.saved.append(values)


class FakeProvider:
    key = "fixture"
    capabilities = ProviderCapabilities(requires_session_for_retrieve=False)
    login_recipe = None
    assessment_policy_version = "fixture-v1"
    extraction_scope: tuple[str, ...] | None = None

    def __init__(self, *, assessed_challenge: bool = False) -> None:
        self.assessed_challenge = assessed_challenge

    def owns_url(self, url: str) -> bool:
        return url.startswith("https://fixture.test/content/")

    def search_page(
        self,
        http: FakeHttp,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
        *,
        next_url: str | None = None,
        metadata_fetch_budget: int | None = None,
    ) -> ProviderSearchPage:
        return ProviderSearchPage(
            results=(
                SearchResult(
                    provider=self.key,
                    url=ARTICLE_URL,
                    headline=f"Fixture result for {query}",
                ),
            )
        )

    def fetch(
        self,
        http: FakeHttp,
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
        if self.assessed_challenge:
            return ArticleAssessment(
                access_state=AccessState.BLOCKED,
                provider_article_id=ARTICLE_ID,
                canonical_url=ARTICLE_URL,
                identity_match=False,
                negative_markers=("interactive_challenge",),
                structural_signals=(),
                word_count=extraction.word_count,
                reason="interactive_challenge",
            )
        return ArticleAssessment(
            access_state=AccessState.FULL,
            provider_article_id=ARTICLE_ID,
            canonical_url=ARTICLE_URL,
            identity_match=True,
            negative_markers=(),
            structural_signals=("fixture_article",),
            word_count=extraction.word_count,
            reason="full_fixture",
        )

    def rate_budget(self) -> RateBudget:
        return RateBudget(requests_per_second=100, burst=100)


class _Clock:
    def __init__(self) -> None:
        self.now = NOW

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)

    def __call__(self) -> datetime:
        return self.now


class _CountingIncidents:
    """Wrap the real store so a de-duplicated re-record stays observable.

    ``_commit`` returns the existing capsule when an identical incident is
    committed a second time, so counting capsules on disk cannot tell "never
    recorded" from "recorded twice and merged" — which is exactly the
    distinction first-arm-only retention is about.
    """

    def __init__(self, inner: IncidentStore) -> None:
        self.inner = inner
        self.assessed_calls = 0

    def record_assessed_retrieval(self, **kwargs):  # noqa: ANN003
        self.assessed_calls += 1
        return self.inner.record_assessed_retrieval(**kwargs)

    def __getattr__(self, name: str):  # noqa: ANN204
        return getattr(self.inner, name)


def _incidents(tmp_path: Path) -> IncidentStore:
    return IncidentStore(
        tmp_path / "incidents",
        build_identity=BuildIdentity(
            revision="a" * 40,
            dirty=False,
            source_fingerprint="a" * 64,
            source=BuildIdentitySource.ENVIRONMENT,
        ),
        utc_now=lambda: NOW,
    )


def _service(
    tmp_path: Path,
    *,
    challenge: bool = False,
    assessed_challenge: bool = False,
    http_status: int = 200,
    defense_now: datetime | None = None,
    wall_clock=None,
    archive=None,
    incidents: object | None = None,
    defense_clock: Callable[[], datetime] | None = None,
) -> tuple[NewsclipService, FakeHttp, DefenseState]:
    http = FakeHttp(challenge=challenge, http_status=http_status)
    defense = DefenseState(
        tmp_path / "provider-defense",
        utc_now=(
            defense_clock
            or ((lambda: defense_now) if defense_now is not None else None)
        ),
    )
    service = NewsclipService(
        ProviderRegistry((FakeProvider(assessed_challenge=assessed_challenge),)),
        http,
        FakeExtractor(),
        archive=archive,
        defense=defense,
        wall_clock=wall_clock,
        incidents=incidents,
    )
    return service, http, defense


def test_observed_challenge_arms_and_publishes_retry_hint(tmp_path: Path) -> None:
    service, http, defense = _service(tmp_path, challenge=True)
    with pytest.raises(ProviderDefenseError) as caught:
        service.get(ARTICLE_URL)
    assert caught.value.retry_after_seconds == pytest.approx(
        BASE_COOLDOWN_SECONDS, abs=2
    )
    assert defense.status("fixture") is not None


def test_retry_hint_uses_the_armed_interval_not_a_second_clock(
    tmp_path: Path,
) -> None:
    service, _http, _defense = _service(
        tmp_path,
        challenge=True,
        defense_now=NOW,
        wall_clock=lambda: datetime(2030, 1, 1, tzinfo=UTC),
    )

    with pytest.raises(ProviderDefenseError) as caught:
        service.get(ARTICLE_URL)

    assert caught.value.retry_after_seconds == pytest.approx(BASE_COOLDOWN_SECONDS)


def test_assessed_challenge_stops_with_the_armed_retry_hint(tmp_path: Path) -> None:
    service, http, defense = _service(
        tmp_path,
        assessed_challenge=True,
        http_status=403,
    )

    with pytest.raises(ProviderDefenseError) as caught:
        service.get(ARTICLE_URL)

    assert caught.value.reason_code == "interactive_challenge"
    assert caught.value.retry_after_seconds == pytest.approx(
        BASE_COOLDOWN_SECONDS,
    )
    assert http.calls == [ARTICLE_URL]
    assert defense.status("fixture") is not None


def test_save_archives_assessed_challenge_then_stops_for_cooldown(
    tmp_path: Path,
) -> None:
    archive = FakeArchive()
    service, http, defense = _service(
        tmp_path,
        assessed_challenge=True,
        http_status=403,
        archive=archive,
    )

    with pytest.raises(ProviderDefenseError) as caught:
        service.save(ARTICLE_URL)

    assert caught.value.retry_after_seconds == pytest.approx(BASE_COOLDOWN_SECONDS)
    assert http.calls == [ARTICLE_URL]
    assert len(archive.saved) == 1
    assert defense.status("fixture") is not None


@pytest.mark.parametrize("operation", ("get", "save"))
def test_success_status_assessed_challenge_does_not_arm_or_raise_defense(
    tmp_path: Path,
    operation: str,
) -> None:
    archive = FakeArchive()
    service, http, defense = _service(
        tmp_path,
        assessed_challenge=True,
        http_status=200,
        archive=archive,
    )

    with pytest.raises(ContentNotFullError, match="interactive_challenge"):
        getattr(service, operation)(ARTICLE_URL)

    assert http.calls == [ARTICLE_URL]
    assert defense.status("fixture") is None
    assert len(archive.saved) == (1 if operation == "save" else 0)


def test_armed_provider_fails_fast_without_network(tmp_path: Path) -> None:
    service, http, defense = _service(tmp_path)
    defense.arm("fixture", origin="retrieval")
    with pytest.raises(ProviderDefenseError) as caught:
        service.get(ARTICLE_URL)
    assert http.calls == []  # never touched the provider
    assert caught.value.retry_after_seconds is not None


def test_full_success_clears_containment(tmp_path: Path) -> None:
    service, http, defense = _service(tmp_path)
    record = defense.arm("fixture", origin="retrieval")
    # Simulate expiry by rewriting the record as already elapsed.
    defense._write(  # noqa: SLF001 - deliberate state surgery for the fixture
        "fixture",
        record.model_copy(update={"active_until": datetime(2020, 1, 1, tzinfo=UTC)}),
    )
    article = service.get(ARTICLE_URL)
    assert article.headline
    assert defense.status("fixture") is None  # cleared by the full success


def test_service_without_defense_state_is_unchanged(tmp_path: Path) -> None:
    http = FakeHttp()
    service = NewsclipService(
        ProviderRegistry((FakeProvider(),)), http, FakeExtractor()
    )
    assert service.get(ARTICLE_URL).headline


def test_first_refusal_of_an_episode_retains_evidence(tmp_path: Path) -> None:
    """The informative refusal is the one that opened the episode."""

    incidents = _CountingIncidents(_incidents(tmp_path))
    service, _http, defense = _service(
        tmp_path,
        assessed_challenge=True,
        http_status=403,
        incidents=incidents,
    )

    with pytest.raises(ProviderDefenseError):
        service.get(ARTICLE_URL)

    assert incidents.assessed_calls == 1
    capsules = list(incidents.inner.iter_capsules())
    assert len(capsules) == 1
    assert capsules[0].provider == "fixture"
    assert capsules[0].assessment is not None
    assert capsules[0].assessment.reason == "interactive_challenge"
    assert defense.status("fixture") is not None


def test_failed_incident_write_preserves_original_defense_error(tmp_path, monkeypatch):
    from newsclip.incidents import IncidentPersistenceError
    from newsclip.results import public_error

    incidents = _incidents(tmp_path)
    service, http, defense = _service(tmp_path, incidents=incidents)
    error = ProviderDefenseError(
        "inert defense", provider="fixture", fetch=FakeHttp().get(ARTICLE_URL)
    )

    def refuse(url, **kwargs):
        http.calls.append(url)
        raise error

    def broken_store(**kwargs):
        raise IncidentPersistenceError("inert persistence failure")

    monkeypatch.setattr(http, "get", refuse)
    monkeypatch.setattr(incidents, "record_assessed_retrieval", broken_store)
    with pytest.raises(ProviderDefenseError) as caught:
        service.get(ARTICLE_URL)
    assert caught.value is error
    assert error.incident_id is None
    assert defense.status("fixture") is not None
    assert http.calls == [ARTICLE_URL]
    envelope = public_error(error).public_dict()
    assert envelope["category"] == "provider_defense"
    assert "fetch" not in envelope
    assert "FULL_FIXTURE_BODY" not in str(envelope)


def test_repeat_refusals_in_one_episode_retain_nothing_further(
    tmp_path: Path,
) -> None:
    """A capsule per challenged canary would pile up through an episode.

    The second refusal is the same configuration failing the same way; only
    the first carries information the operator did not already have.
    """

    clock = _Clock()
    incidents = _CountingIncidents(_incidents(tmp_path))
    service, _http, defense = _service(
        tmp_path,
        assessed_challenge=True,
        http_status=403,
        incidents=incidents,
        defense_clock=clock,
    )

    with pytest.raises(ProviderDefenseError):
        service.get(ARTICLE_URL)
    assert incidents.assessed_calls == 1

    # Expire the cooldown so the second call runs as the post-expiry canary and
    # is refused again. Without this the gate would fail fast and never reach
    # the arm at all, and the assertion below would hold for the wrong reason.
    clock.advance(BASE_COOLDOWN_SECONDS + 1)

    with pytest.raises(ProviderDefenseError):
        service.get(ARTICLE_URL)

    record = defense.status("fixture")
    assert record is not None
    assert len(record.arms) == 2
    assert incidents.assessed_calls == 1


def test_search_discloses_that_a_contained_provider_cannot_serve_articles(
    tmp_path: Path,
) -> None:
    """Search answering is not retrieval answering.

    The sitemap surface keeps returning rows through an episode, so without
    this the picker offers selections it already knows the gate will refuse.
    """

    clock = _Clock()
    service, _http, defense = _service(
        tmp_path,
        defense_clock=clock,
        wall_clock=clock,
    )
    defense.arm("fixture", origin="retrieval")

    pager = service.search_pager("fixture query")
    response = pager.next_batch(5)

    assert [result.headline for result in response.results] != []
    report = next(s for s in response.sources if s.provider == "fixture")
    assert report.state is SourceSearchState.OK
    assert report.retrieval_contained_until is not None
    assert report.retrieval_contained_until == defense.status("fixture").active_until


def test_search_claims_no_containment_once_the_cooldown_has_expired(
    tmp_path: Path,
) -> None:
    """An expired record is not containment: the next caller is the canary."""

    clock = _Clock()
    service, _http, defense = _service(
        tmp_path,
        defense_clock=clock,
        wall_clock=clock,
    )
    defense.arm("fixture", origin="retrieval")
    clock.advance(BASE_COOLDOWN_SECONDS + 1)

    response = service.search_pager("fixture query").next_batch(5)

    report = next(s for s in response.sources if s.provider == "fixture")
    assert report.retrieval_contained_until is None


def test_search_claims_no_containment_when_nothing_is_armed(tmp_path: Path) -> None:
    service, _http, _defense = _service(tmp_path)

    response = service.search_pager("fixture query").next_batch(5)

    report = next(s for s in response.sources if s.provider == "fixture")
    assert report.retrieval_contained_until is None


def test_guard_suppression_does_not_dispatch_or_rearm(tmp_path):
    service, http, defense = _service(tmp_path, defense_now=NOW, wall_clock=lambda: NOW)
    first = defense.arm("fixture", origin="retrieval")
    result = service.provider_check("fixture")
    assert result.defense_observation == "suppressed"
    assert result.defense_retry_after_seconds == BASE_COOLDOWN_SECONDS
    assert http.calls == []
    assert defense.status("fixture") == first


def test_guarded_defense_recovers_through_existing_controller(tmp_path):
    from test_incidents import _identity
    from test_provider_check import CheckExtractor, CheckHttp, CheckProvider

    from newsclip.composition import _protected_incidents
    from newsclip.provider_guard import GuardAction, ProviderGuard, ProviderGuardStore

    clock = _Clock()
    provider = CheckProvider(state=AccessState.BLOCKED)
    registry = ProviderRegistry((provider,))
    http = CheckHttp()
    defense = DefenseState(
        tmp_path / "provider-defense",
        utc_now=clock,
        incident_root=tmp_path / "incidents",
    )
    incidents = IncidentStore(
        tmp_path / "incidents",
        build_identity=_identity(),
        protected_incidents=lambda key: _protected_incidents(
            tmp_path, key, _identity()
        ),
    )
    service = NewsclipService(
        registry,
        http,
        CheckExtractor(),
        defense=defense,
        incidents=incidents,
        wall_clock=clock,
    )
    guard = ProviderGuard(
        registry=registry,
        store=ProviderGuardStore(
            tmp_path / "provider-guard",
            build_identity=_identity(),
            utc_now=clock,
            incident_root=incidents.root,
        ),
    )
    first = guard.run("fixture", lambda: service.provider_check("fixture"))
    assert first.action is GuardAction.TRANSIENT_FAILURE
    assert first.check.defense_observation == "observed"
    assert guard.peek("fixture") is None
    incident_id = defense.status("fixture").incident_id
    assert incident_id is not None
    assert incidents.load(incident_id).assessment.access_state is AccessState.BLOCKED
    original_observation = guard.last_check("fixture")
    calls = len(http.calls)
    suppressed = guard.run("fixture", lambda: service.provider_check("fixture"))
    assert suppressed.check.defense_observation == "suppressed"
    assert len(http.calls) == calls
    assert guard.last_check("fixture") == original_observation
    clock.advance(BASE_COOLDOWN_SECONDS + 1)
    provider.state = AccessState.FULL
    recovered = guard.run("fixture", lambda: service.provider_check("fixture"))
    assert recovered.action is GuardAction.HEALTHY
    assert defense.status("fixture") is None
    assert guard.peek("fixture") is None
    assert incidents.load(incident_id)  # recovery never erases the first failure


class _SearchOverHttp(FakeProvider):
    """Search through the transport, so a refused search page is observable."""

    def search_page(
        self,
        http,
        session,
        query,
        filters,
        *,
        next_url=None,
        metadata_fetch_budget=None,
    ):
        http.get("https://fixture.test/search?q=" + query, session=session)
        return super().search_page(
            http,
            session,
            query,
            filters,
            next_url=next_url,
            metadata_fetch_budget=metadata_fetch_budget,
        )


class _Healthy(FakeProvider):
    key = "healthy"  # a second source keeps the batch from failing as a whole


def _search_service(
    tmp_path: Path, clock: _Clock
) -> tuple[NewsclipService, FakeHttp, DefenseState]:
    http = FakeHttp(challenge=True)
    defense = DefenseState(tmp_path / "provider-defense", utc_now=clock)
    service = NewsclipService(
        ProviderRegistry((_SearchOverHttp(), _Healthy())),
        http,
        FakeExtractor(),
        defense=defense,
        wall_clock=clock,
    )
    return service, http, defense


def _fixture_report(service: NewsclipService):
    response = service.search_pager("fixture query").next_batch(5)
    return next(s for s in response.sources if s.provider == "fixture")


def test_a_search_refused_during_a_cooldown_is_not_retried_until_it_ends(
    tmp_path: Path,
) -> None:
    """An IP-level restriction refuses search too (Economist, 2026-10-19): each
    further search is more of the traffic it cites, so one per cooldown."""

    clock = _Clock()
    service, http, defense = _search_service(tmp_path, clock)
    defense.arm("fixture", origin="guard")

    first = _fixture_report(service)
    assert first.state is not SourceSearchState.OK and len(http.calls) == 1
    second = _fixture_report(service)
    assert second.state is first.state and second.reason is first.reason
    assert second.retrieval_contained_until == defense.status("fixture").active_until
    assert len(http.calls) == 1  # paused: no request

    clock.advance(
        BASE_COOLDOWN_SECONDS + 1
    )  # the cooldown ended: the next search asks again
    _fixture_report(service)
    assert len(http.calls) == 2


def test_a_cleared_defense_resumes_search_at_once(tmp_path: Path) -> None:
    clock = _Clock()
    service, http, defense = _search_service(tmp_path, clock)
    defense.arm("fixture", origin="guard")
    _fixture_report(service)
    defense.clear("fixture")  # a FULL retrieval ended the episode
    http.challenge = False
    assert _fixture_report(service).state is SourceSearchState.OK
    assert len(http.calls) == 2


def test_a_refused_search_without_a_cooldown_pauses_nothing(tmp_path: Path) -> None:
    clock = _Clock()
    service, http, _defense = _search_service(tmp_path, clock)
    _fixture_report(service)
    _fixture_report(service)
    assert len(http.calls) == 2
