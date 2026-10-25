"""Behavioural tests for the lazy session classification (ARCHITECTURE, retrieval).

The cheap common path performs a single fetch of the caller's URL; a fixed probe
is issued only when that target is not ``FULL``, and only a positively
authenticated/teaser probe is allowed to conclude the session is dead.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from newsclip.archive import ArchiveStore
from newsclip.errors import (
    ContentNotFullError,
    ProviderTransportError,
    SessionRequiredError,
)
from newsclip.incidents import IncidentStore
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
    SessionDisposition,
    SessionVerification,
)
from newsclip.provenance import BuildIdentity, BuildIdentitySource
from newsclip.providers import ProviderRegistry
from newsclip.results import public_error
from newsclip.service import NewsclipService
from newsclip.timing import (
    SessionProbeOutcome,
    TimingRecorder,
    TimingStep,
    iter_timing_runs,
)

NOW = datetime(2026, 7, 17, tzinfo=UTC)
ARTICLE_ID = "target-article"
ARTICLE_URL = f"https://fixture.test/content/{ARTICLE_ID}"
PROBE_URL = "https://fixture.test/content/fixed-probe-article"


def _artifact() -> SessionArtifact:
    return SessionArtifact(
        generation_id=uuid4(),
        provider="fixture",
        created_at=NOW,
        verified_at=NOW,
        cookies=(
            PortableCookie(
                name="Session",
                value="COOKIE_VALUE_SENTINEL",
                domain="fixture.test",
                expires=(NOW + timedelta(days=30)).timestamp(),
            ),
        ),
    )


class ScriptedHttp:
    """Return canned bodies keyed by URL; raise on URLs marked as transport
    failures. Records every requested URL for single-fetch assertions."""

    def __init__(
        self,
        bodies: dict[str, bytes],
        *,
        transport_failures: frozenset[str] = frozenset(),
    ) -> None:
        self._bodies = bodies
        self._transport_failures = transport_failures
        self.calls: list[str] = []

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.calls.append(url)
        if url in self._transport_failures:
            raise ProviderTransportError("scripted transport failure")
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=session is not None,
            raw_html=self._bodies[url],
        )


class SessionAwareHttp:
    def __init__(
        self,
        full_generation,
        *,
        probe_body: bytes = b"auth wall",
    ) -> None:
        self._full_generation = full_generation
        self._probe_body = probe_body
        self.calls: list[str] = []

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.calls.append(url)
        if url == PROBE_URL:
            body = self._probe_body
        else:
            body = (
                b"FULL body"
                if session is not None
                and session.generation_id == self._full_generation
                else b"teaser body"
            )
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=session is not None,
            raw_html=body,
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
            body_markdown="Generated fixture body.",
            metadata={"title": "Fixture article", "author": ["Fixture Author"]},
            word_count=250,
        )


def _assess(url: str, fetch: RawFetch) -> ArticleAssessment:
    if b"FULL" in fetch.raw_html:
        state, reason = AccessState.FULL, "full_fixture"
    elif b"paywall" in fetch.raw_html:
        state, reason = AccessState.TEASER, "paywall_teaser"
    elif b"opaque" in fetch.raw_html:
        state, reason = AccessState.UNKNOWN, "opaque_fixture"
    else:
        state, reason = AccessState.AUTH_REQUIRED, "auth_required_fixture"
    article_id = url.rsplit("/", 1)[-1]
    full = state is AccessState.FULL
    return ArticleAssessment(
        access_state=state,
        provider_article_id=article_id,
        canonical_url=url,
        identity_match=True,
        negative_markers=("auth_wall",) if state is AccessState.AUTH_REQUIRED else (),
        structural_signals=("fixture_article",) if full else (),
        word_count=250,
        reason=reason,
    )


class FixtureRecipe:
    """Probe the fixed URL and translate its assessment to a verification."""

    provider = "fixture"
    allowed_origins = frozenset({"https://fixture.test"})
    allowed_cookie_domains = frozenset({"fixture.test"})
    secret_ref = "fixture-secret"

    def verify(self, http, artifact: SessionArtifact) -> SessionVerification:
        fetch = http.get(PROBE_URL, session=artifact)
        assessment = _assess(PROBE_URL, fetch)
        return SessionVerification(
            verified=assessment.promotable,
            access_state=assessment.access_state,
            reason=assessment.reason,
            verified_at=NOW,
        )


class FixtureProvider:
    key = "fixture"
    capabilities = ProviderCapabilities(requires_session_for_retrieve=True)
    assessment_policy_version = "fixture-v1"
    extraction_scope: tuple[str, ...] | None = None

    def __init__(self) -> None:
        self.login_recipe = FixtureRecipe()

    def owns_url(self, url: str) -> bool:
        return url.startswith("https://fixture.test/content/")

    def search(
        self, http, session, query: str, filters: SearchFilters
    ) -> list[SearchResult]:  # pragma: no cover - unused
        return []

    def fetch(self, http, session, url: str) -> RawFetch:
        return http.get(url, session=session)

    def assess(self, requested_url, fetch, extraction) -> ArticleAssessment:
        return _assess(requested_url, fetch)

    def rate_budget(self) -> RateBudget:
        return RateBudget(requests_per_second=1000, burst=1000)


class FakeStore:
    """Minimal session source that tracks downgrades."""

    def __init__(self) -> None:
        self.artifact: SessionArtifact | None = _artifact()
        self.downgrades = 0
        self.downgraded_generation = None

    def get_valid_session(
        self, provider: str, account_key: str = "default"
    ) -> SessionArtifact:
        if self.artifact is None:
            raise SessionRequiredError("fixture session is not verified")
        return self.artifact

    def mark_required(
        self,
        provider: str,
        account_key: str = "default",
        *,
        generation_id=None,
    ) -> None:
        self.downgrades += 1
        self.downgraded_generation = generation_id
        self.artifact = None


def _service(
    http: ScriptedHttp,
    store: FakeStore,
    *,
    timing: TimingRecorder | None = None,
    incidents: IncidentStore | None = None,
) -> NewsclipService:
    return NewsclipService(
        ProviderRegistry((FixtureProvider(),)),
        http,
        FakeExtractor(),
        sessions=store,
        timing=timing,
        incidents=incidents,
        network_sleep=lambda _seconds: None,
    )


def test_happy_path_get_performs_single_fetch_without_probe() -> None:
    http = ScriptedHttp({ARTICLE_URL: b"FULL body"})
    store = FakeStore()
    service = _service(http, store)

    article = service.get(ARTICLE_URL)

    assert str(article.url) == ARTICLE_URL
    assert http.calls == [ARTICLE_URL]  # no probe on the happy path
    assert store.downgrades == 0


def test_missing_session_auto_acquires_before_the_first_target_fetch() -> None:
    fresh = _artifact()
    http = SessionAwareHttp(fresh.generation_id)
    store = FakeStore()
    store.artifact = None
    acquisitions: list[str] = []

    def acquire(provider: str) -> None:
        acquisitions.append(provider)
        store.artifact = fresh

    article = _service(http, store).get(ARTICLE_URL, acquire_session=acquire)

    assert article.provider == "fixture"
    assert acquisitions == ["fixture"]
    assert http.calls == [ARTICLE_URL]


def test_proven_dead_session_auto_acquires_and_retries_target_once() -> None:
    fresh = _artifact()
    http = SessionAwareHttp(fresh.generation_id)
    store = FakeStore()
    acquisitions: list[str] = []

    def acquire(provider: str) -> None:
        acquisitions.append(provider)
        store.artifact = fresh

    article = _service(http, store).get(ARTICLE_URL, acquire_session=acquire)

    assert article.provider == "fixture"
    assert acquisitions == ["fixture"]
    assert http.calls == [ARTICLE_URL, PROBE_URL, ARTICLE_URL]
    assert store.downgrades == 1


def test_successful_session_recovery_does_not_create_repair_incident(
    tmp_path: Path,
) -> None:
    fresh = _artifact()
    http = SessionAwareHttp(fresh.generation_id)
    store = FakeStore()
    incidents = IncidentStore(
        tmp_path / "incidents",
        build_identity=BuildIdentity(
            revision="a" * 40,
            dirty=False,
            source_fingerprint="a" * 64,
            source=BuildIdentitySource.ENVIRONMENT,
        ),
    )

    def acquire(_provider: str) -> None:
        store.artifact = fresh

    article = _service(http, store, incidents=incidents).get(
        ARTICLE_URL,
        acquire_session=acquire,
    )

    assert article.provider == "fixture"
    assert tuple(incidents.iter_capsules()) == ()


def test_successful_retry_replaces_dead_probe_with_final_full_target(
    tmp_path: Path,
) -> None:
    fresh = _artifact()
    http = SessionAwareHttp(fresh.generation_id)
    store = FakeStore()
    recorder = TimingRecorder(tmp_path / "timings")

    def acquire(_provider: str) -> None:
        store.artifact = fresh

    article = _service(http, store, timing=recorder).get(
        ARTICLE_URL,
        acquire_session=acquire,
    )

    assert article.provider == "fixture"
    run = next(iter_timing_runs(recorder.root))
    assert run.finished is not None
    content = run.finished.content_assessment
    assert content is not None
    assert content.access_state is AccessState.FULL
    assert content.reason == "unavailable"
    assert content.session_probe is None


def test_auto_acquire_retry_is_bounded_to_one_attempt() -> None:
    unreachable_generation = uuid4()
    http = SessionAwareHttp(unreachable_generation)
    store = FakeStore()
    acquisitions: list[str] = []

    def acquire(provider: str) -> None:
        acquisitions.append(provider)
        store.artifact = _artifact()

    with pytest.raises(SessionRequiredError):
        _service(http, store).get(ARTICLE_URL, acquire_session=acquire)

    assert acquisitions == ["fixture"]
    assert http.calls == [ARTICLE_URL, PROBE_URL, ARTICLE_URL, PROBE_URL]


def test_inconclusive_probe_never_calls_auto_acquirer() -> None:
    http = SessionAwareHttp(uuid4(), probe_body=b"opaque maintenance page")
    store = FakeStore()
    acquisitions: list[str] = []

    with pytest.raises(ContentNotFullError):
        _service(http, store).get(
            ARTICLE_URL,
            acquire_session=acquisitions.append,
        )

    assert acquisitions == []
    assert http.calls == [ARTICLE_URL, PROBE_URL]


def test_missing_session_auto_acquires_for_save(tmp_path: Path) -> None:
    fresh = _artifact()
    http = SessionAwareHttp(fresh.generation_id)
    store = FakeStore()
    store.artifact = None
    archive = ArchiveStore(tmp_path / "archive.sqlite3")
    service = NewsclipService(
        ProviderRegistry((FixtureProvider(),)),
        http,
        FakeExtractor(),
        sessions=store,
        archive=archive,
        network_sleep=lambda _seconds: None,
    )

    def acquire(provider: str) -> None:
        assert provider == "fixture"
        store.artifact = fresh

    saved = service.save(ARTICLE_URL, acquire_session=acquire)

    assert saved.provider == "fixture"
    assert http.calls == [ARTICLE_URL]
    assert archive.inspect_schema()["counts"]["articles"] == 1


def test_non_full_target_with_dead_session_downgrades_and_requires_login() -> None:
    http = ScriptedHttp({ARTICLE_URL: b"teaser body", PROBE_URL: b"auth wall"})
    store = FakeStore()
    service = _service(http, store)

    with pytest.raises(SessionRequiredError, match="no longer valid"):
        service.get(ARTICLE_URL)

    assert http.calls == [ARTICLE_URL, PROBE_URL]
    assert store.downgrades == 1
    assert store.artifact is None


def test_non_full_target_with_healthy_session_is_content_not_full() -> None:
    http = ScriptedHttp({ARTICLE_URL: b"teaser body", PROBE_URL: b"FULL body"})
    store = FakeStore()
    service = _service(http, store)

    with pytest.raises(ContentNotFullError, match="auth_required_fixture"):
        service.get(ARTICLE_URL)

    assert http.calls == [ARTICLE_URL, PROBE_URL]
    assert store.downgrades == 0
    assert store.artifact is not None


def test_non_full_target_records_healthy_probe_verdict(tmp_path: Path) -> None:
    http = ScriptedHttp({ARTICLE_URL: b"teaser body", PROBE_URL: b"FULL body"})
    store = FakeStore()
    recorder = TimingRecorder(tmp_path / "timings")

    with pytest.raises(ContentNotFullError):
        _service(http, store, timing=recorder).get(ARTICLE_URL)

    run = next(iter_timing_runs(recorder.root))
    assert run.finished is not None
    content = run.finished.content_assessment
    assert content is not None
    assert content.access_state is AccessState.AUTH_REQUIRED
    assert content.reason == "unavailable"
    assert content.identity_match is True
    assert content.word_count == 250
    assert content.session_cookie_present is False
    assert content.session_probe is not None
    assert content.session_probe.outcome is SessionProbeOutcome.VERIFIED
    assert content.session_probe.access_state is AccessState.FULL
    assert content.session_probe.reason == "unavailable"
    assert any(
        record.event.step is TimingStep.SESSION_VERIFY
        for record in run.records
        if hasattr(record.event, "step")
    )


def test_non_full_target_records_inconclusive_probe_verdict(tmp_path: Path) -> None:
    http = ScriptedHttp({ARTICLE_URL: b"teaser body", PROBE_URL: b"opaque page"})
    store = FakeStore()
    recorder = TimingRecorder(tmp_path / "timings")

    with pytest.raises(ContentNotFullError):
        _service(http, store, timing=recorder).get(ARTICLE_URL)

    run = next(iter_timing_runs(recorder.root))
    assert run.finished is not None
    content = run.finished.content_assessment
    assert content is not None
    assert content.session_probe is not None
    assert content.session_probe.outcome is SessionProbeOutcome.INCONCLUSIVE
    assert content.session_probe.access_state is AccessState.UNKNOWN
    assert content.session_probe.reason == "unavailable"
    assert store.artifact is not None


def test_non_full_target_records_probe_transport_failure(tmp_path: Path) -> None:
    http = ScriptedHttp(
        {ARTICLE_URL: b"teaser body"},
        transport_failures=frozenset({PROBE_URL}),
    )
    store = FakeStore()
    recorder = TimingRecorder(tmp_path / "timings")

    with pytest.raises(ContentNotFullError):
        _service(http, store, timing=recorder).get(ARTICLE_URL)

    run = next(iter_timing_runs(recorder.root))
    assert run.finished is not None
    content = run.finished.content_assessment
    assert content is not None
    assert content.session_probe is not None
    assert content.session_probe.outcome is SessionProbeOutcome.TRANSPORT_ERROR
    assert content.session_probe.access_state is None
    assert content.session_probe.reason is None
    assert store.artifact is not None


def test_dead_session_verdict_is_retained_before_login_requirement(
    tmp_path: Path,
) -> None:
    http = ScriptedHttp({ARTICLE_URL: b"teaser body", PROBE_URL: b"auth wall"})
    store = FakeStore()
    recorder = TimingRecorder(tmp_path / "timings")

    with pytest.raises(SessionRequiredError):
        _service(http, store, timing=recorder).get(ARTICLE_URL)

    run = next(iter_timing_runs(recorder.root))
    assert run.finished is not None
    content = run.finished.content_assessment
    assert content is not None
    assert content.session_probe is not None
    assert content.session_probe.outcome is SessionProbeOutcome.SESSION_DEAD
    assert content.session_probe.access_state is AccessState.AUTH_REQUIRED
    assert store.artifact is None


def test_probe_transport_failure_never_downgrades_or_reminds() -> None:
    http = ScriptedHttp(
        {ARTICLE_URL: b"teaser body"},
        transport_failures=frozenset({PROBE_URL}),
    )
    store = FakeStore()
    service = _service(http, store)

    with pytest.raises(ContentNotFullError, match="auth_required_fixture"):
        service.get(ARTICLE_URL)

    # target once, probe retried once by the network policy, then given up on
    assert http.calls == [ARTICLE_URL, PROBE_URL, PROBE_URL]
    assert store.downgrades == 0
    assert store.artifact is not None


def test_non_full_save_downgrades_dead_session_after_recording_diagnostic() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        http = ScriptedHttp({ARTICLE_URL: b"teaser body", PROBE_URL: b"auth wall"})
        store = FakeStore()
        archive = ArchiveStore(Path(tmp) / "archive.sqlite3")
        service = NewsclipService(
            ProviderRegistry((FixtureProvider(),)),
            http,
            FakeExtractor(),
            sessions=store,
            archive=archive,
            network_sleep=lambda _seconds: None,
        )

        with pytest.raises(SessionRequiredError, match="no longer valid"):
            service.save(ARTICLE_URL)

        assert store.downgrades == 1
        # the non-FULL fetch is still retained as diagnostic evidence
        assert archive.inspect_schema()["counts"]["fetches"] == 1
        assert archive.inspect_schema()["counts"]["articles"] == 0


def test_checkpoint_eagerly_probes_and_downgrades_dead_session() -> None:
    http = ScriptedHttp({PROBE_URL: b"auth wall"})
    store = FakeStore()
    service = _service(http, store)

    with pytest.raises(SessionRequiredError, match="failed verification"):
        service.session_checkpoint("fixture")

    assert http.calls == [PROBE_URL]  # eager probe, no target fetch
    assert store.downgrades == 1


def test_checkpoint_passes_when_probe_is_full() -> None:
    http = ScriptedHttp({PROBE_URL: b"FULL body"})
    store = FakeStore()
    service = NewsclipService(
        ProviderRegistry((FixtureProvider(),)),
        http,
        FakeExtractor(),
        sessions=store,
        network_sleep=lambda _seconds: None,
        wall_clock=lambda: NOW + timedelta(hours=1),
    )

    checkpoint = service.session_checkpoint("fixture")

    assert http.calls == [PROBE_URL]
    assert store.downgrades == 0
    assert checkpoint.session_age_seconds == 60 * 60


def test_checkpoint_inconclusive_probe_is_transport_not_session_failure() -> None:
    """SV1.3: an UNKNOWN probe proves nothing about the session, so checkpoint
    reports infrastructure (exit 5) instead of steering toward a re-login."""

    http = ScriptedHttp({PROBE_URL: b"opaque maintenance page"})
    store = FakeStore()
    service = _service(http, store)

    with pytest.raises(ProviderTransportError, match="inconclusive"):
        service.session_checkpoint("fixture")

    assert store.downgrades == 0
    assert store.artifact is not None


def test_teaser_verification_is_inconclusive_and_preserves_session() -> None:
    verification = SessionVerification(
        verified=False,
        access_state=AccessState.TEASER,
        reason="paywall_teaser",
        verified_at=NOW,
    )

    assert verification.disposition is SessionDisposition.INCONCLUSIVE


def test_teaser_probe_is_inconclusive_and_preserves_session() -> None:
    http = ScriptedHttp(
        {
            ARTICLE_URL: b"teaser body",
            PROBE_URL: b"paywall body",
        }
    )
    store = FakeStore()

    with pytest.raises(ContentNotFullError):
        _service(http, store).get(ARTICLE_URL)

    assert store.downgrades == 0
    assert store.artifact is not None


def test_non_full_target_with_inconclusive_probe_never_downgrades() -> None:
    http = ScriptedHttp({ARTICLE_URL: b"teaser body", PROBE_URL: b"opaque page"})
    store = FakeStore()
    service = _service(http, store)

    with pytest.raises(ContentNotFullError, match="auth_required_fixture"):
        service.get(ARTICLE_URL)

    assert store.downgrades == 0
    assert store.artifact is not None


def test_dead_session_downgrade_names_the_probed_generation() -> None:
    """The downgrade names the generation the probe judged, so a concurrently
    re-minted session cannot be erased by a stale verdict."""

    http = ScriptedHttp({ARTICLE_URL: b"teaser body", PROBE_URL: b"auth wall"})
    store = FakeStore()
    probed = store.artifact
    service = _service(http, store)

    with pytest.raises(SessionRequiredError):
        service.get(ARTICLE_URL)

    assert store.downgrades == 1
    assert store.downgraded_generation == probed.generation_id


class MeteredFixtureProvider(FixtureProvider):
    def rate_budget(self) -> RateBudget:
        return RateBudget(requests_per_second=1.0, burst=1)


def test_probe_and_target_draw_from_one_token_bucket() -> None:
    """SV1.4: the classify probe is paced by the bucket the target fetch just
    drained — a separate bucket would grant the probe its own burst."""

    clock = {"now": 0.0}
    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock["now"] += seconds

    http = ScriptedHttp({ARTICLE_URL: b"teaser body", PROBE_URL: b"FULL body"})
    store = FakeStore()
    service = NewsclipService(
        ProviderRegistry((MeteredFixtureProvider(),)),
        http,
        FakeExtractor(),
        sessions=store,
        network_clock=lambda: clock["now"],
        network_sleep=fake_sleep,
    )

    with pytest.raises(ContentNotFullError):
        service.get(ARTICLE_URL)

    assert http.calls == [ARTICLE_URL, PROBE_URL]
    assert sleeps == [1.0]  # the probe waited for the token the target consumed


def test_content_failure_names_its_retained_incident(tmp_path: Path) -> None:
    """A client failure must be correlatable with the evidence kept for it."""

    http = ScriptedHttp({ARTICLE_URL: b"teaser body", PROBE_URL: b"FULL body"})
    store = FakeStore()
    incidents = IncidentStore(
        tmp_path / "incidents",
        build_identity=BuildIdentity(
            revision="a" * 40,
            dirty=False,
            source_fingerprint="a" * 64,
            source=BuildIdentitySource.ENVIRONMENT,
        ),
    )

    with pytest.raises(ContentNotFullError) as raised:
        _service(http, store, incidents=incidents).get(ARTICLE_URL)

    capsule = next(incidents.iter_capsules())
    assert raised.value.incident_id == capsule.incident_id
    envelope = public_error(raised.value)
    assert envelope is not None
    assert envelope.public_dict()["incident_id"] == capsule.incident_id
