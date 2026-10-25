from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from lxml import html

from newsclip.archive import ArchiveStore
from newsclip.errors import ContentNotFullError, SessionRequiredError
from newsclip.extraction import TrafilaturaExtractor
from newsclip.live_reporting import (
    LiveOperationEvidence,
    RuntimeEvidence,
    RuntimeProviderEvidence,
    provider_evidence_gaps,
)
from newsclip.models import (
    AccessState,
    PortableCookie,
    RawFetch,
    SessionArtifact,
    SessionDisposition,
    SessionVerification,
)
from newsclip.providers import BloombergProvider, ProviderRegistry
from newsclip.service import NewsclipService
from newsclip.timing import (
    ContentAssessmentEvidence,
    SessionProbeOutcome,
    TimingOperation,
    TimingRecorder,
    TimingRunMode,
    TimingTransport,
    iter_timing_runs,
)

NOW = datetime(2026, 7, 24, tzinfo=UTC)
ARTICLE_URL = (
    "https://www.bloomberg.com/news/articles/2026-07-16/"
    "fixture-chipmaker-beats-estimates"
)
FIXTURES = Path(__file__).parent / "fixtures/bloomberg"


def _story_page(
    rendered_fixture: str,
    *,
    duplicate_last_paragraph: bool = False,
    invalid_component: bool = False,
) -> bytes:
    full = html.fromstring((FIXTURES / "full.html").read_bytes())
    values = [
        " ".join(paragraph.text_content().split())
        for paragraph in full.xpath("//article/p")
    ]
    content: list[dict[str, object]] = [
        {
            "type": "paragraph",
            "content": [{"type": "text", "value": value}],
        }
        for value in values
    ]
    if invalid_component:
        content.append(
            {
                "type": "interactive-chart",
                "content": [
                    {
                        "type": "text",
                        "value": "Generated unrecognized narrative component.",
                    }
                ],
            }
        )
    payload = {
        "props": {
            "pageProps": {
                "story": {
                    "seoCanonical": ARTICLE_URL,
                    "headline": "Fixture chipmaker beats estimates",
                    "publishedAt": "2026-07-16T09:30:00Z",
                    "authors": [{"name": "Fixture Reporter"}],
                    "body": {"type": "document", "content": content},
                }
            }
        }
    }
    rendered = html.fromstring((FIXTURES / rendered_fixture).read_bytes())
    if duplicate_last_paragraph:
        paragraphs = rendered.xpath("//article/p")
        paragraphs[-1].text = paragraphs[-2].text
    script = html.Element("script", id="__NEXT_DATA__", type="application/json")
    script.text = json.dumps(payload)
    rendered.xpath("//head")[0].append(script)
    return html.tostring(rendered)


def _artifact() -> SessionArtifact:
    return SessionArtifact(
        generation_id=uuid4(),
        provider="bloomberg",
        created_at=NOW,
        verified_at=NOW,
        cookies=(
            PortableCookie(
                name="_user-token",
                value="fixture",
                domain=".bloomberg.com",
            ),
        ),
    )


class FixtureSessions:
    def __init__(self) -> None:
        self.artifact = _artifact()
        self.downgrades = 0

    def get_valid_session(
        self,
        provider: str,
        account_key: str = "default",
    ) -> SessionArtifact:
        assert provider == "bloomberg"
        assert account_key == "default"
        return self.artifact

    def mark_required(
        self,
        provider: str,
        account_key: str = "default",
        *,
        generation_id=None,  # noqa: ANN001
    ) -> None:
        self.downgrades += 1


class FixtureBrowserRetriever:
    def __init__(self, raw_html: bytes) -> None:
        self.raw_html = raw_html
        self.calls: list[str] = []

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        assert session is not None
        self.calls.append(url)
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=True,
            raw_html=self.raw_html,
        )

    def release(self) -> None:
        return None

    def close(self) -> None:
        return None


class FixtureVerificationRecipe:
    provider = "bloomberg"

    def __init__(self, disposition: SessionDisposition) -> None:
        self.disposition = disposition
        self.calls = 0

    def verify(self, _http, _artifact: SessionArtifact) -> SessionVerification:  # noqa: ANN001
        self.calls += 1
        return SessionVerification(
            verified=self.disposition is SessionDisposition.VERIFIED,
            access_state={
                SessionDisposition.VERIFIED: AccessState.FULL,
                SessionDisposition.DEAD: AccessState.AUTH_REQUIRED,
                SessionDisposition.INCONCLUSIVE: AccessState.UNKNOWN,
            }[self.disposition],
            reason={
                SessionDisposition.VERIFIED: "full_article_verified",
                SessionDisposition.DEAD: "authentication_required",
                SessionDisposition.INCONCLUSIVE: "insufficient_article_structure",
            }[self.disposition],
            verified_at=NOW,
        )


def _service(
    tmp_path: Path,
    raw_html: bytes,
    *,
    disposition: SessionDisposition = SessionDisposition.VERIFIED,
    timing: TimingRecorder | None = None,
) -> tuple[
    NewsclipService,
    FixtureVerificationRecipe,
    FixtureSessions,
    ArchiveStore,
]:
    provider = BloombergProvider()
    recipe = FixtureVerificationRecipe(disposition)
    provider.login_recipe = recipe  # type: ignore[assignment]
    registry = ProviderRegistry((provider,))
    extractor = TrafilaturaExtractor()
    archive = ArchiveStore(
        tmp_path / "archive.sqlite3",
        registry=registry,
        extractor=extractor,
    )
    sessions = FixtureSessions()
    return (
        NewsclipService(
            registry,
            FixtureBrowserRetriever(raw_html),
            extractor,
            sessions=sessions,
            archive=archive,
            browser_retriever=FixtureBrowserRetriever(raw_html),
            network_sleep=lambda _seconds: None,
            timing=timing,
        ),
        recipe,
        sessions,
        archive,
    )


def test_promotable_partial_dom_saves_valid_structured_story(
    tmp_path: Path,
) -> None:
    raw_html = _story_page("full.html", duplicate_last_paragraph=True)
    service, recipe, sessions, archive = _service(tmp_path, raw_html)

    article = service.save(ARTICLE_URL)

    assert article.word_count > 250
    assert article.extraction.extractor_name == "bloomberg-next-story"
    assert "A fourth generated paragraph closes the body" in article.body_markdown
    assert recipe.calls == 0
    assert sessions.downgrades == 0
    reextracted = archive.reextract(article.id)
    assert reextracted.body_markdown == article.body_markdown
    assert reextracted.extraction.extractor_name == "bloomberg-next-story"
    assert service.archive_drift(provider="bloomberg").is_clean


def test_teaser_dom_promotes_only_after_current_session_verifies(
    tmp_path: Path,
) -> None:
    service, recipe, sessions, _archive = _service(
        tmp_path,
        _story_page("teaser.html"),
    )

    article = service.save(ARTICLE_URL)

    assert article.extraction.extractor_name == "bloomberg-next-story"
    assert article.word_count > 250
    assert recipe.calls == 1
    assert sessions.downgrades == 0


def test_teaser_dom_stays_closed_when_session_probe_is_inconclusive(
    tmp_path: Path,
) -> None:
    service, recipe, sessions, _archive = _service(
        tmp_path,
        _story_page("teaser.html"),
        disposition=SessionDisposition.INCONCLUSIVE,
    )

    with pytest.raises(ContentNotFullError, match="paywall_teaser"):
        service.save(ARTICLE_URL)

    assert recipe.calls == 1
    assert sessions.downgrades == 0


def _assert_complete_native_evidence(
    content: ContentAssessmentEvidence,
    *,
    operation: TimingOperation,
    outcome: str,
) -> None:
    evidence = LiveOperationEvidence(
        provider="bloomberg",
        mode=TimingRunMode.WARM,
        operation=operation,
        transport=TimingTransport.BROWSER,
        outcome=outcome,
        assessment_reached=True,
        content_assessment=content,
        duration_ms=1,
    )
    assert (
        provider_evidence_gaps(
            diagnostic_contract_version=3,
            provider="bloomberg",
            operations=(evidence,),
            attempts=(),
            global_runtime=RuntimeEvidence(),
            runtime=RuntimeProviderEvidence(
                provider="bloomberg",
                event_counts={"fixture_event": 1},
            ),
            http_attempts=(),
        )
        == ()
    )


@pytest.mark.parametrize(
    ("method_name", "operation"),
    [
        ("get", TimingOperation.GET),
        ("save", TimingOperation.SAVE),
    ],
)
def test_native_inconclusive_probe_survives_to_live_evidence(
    tmp_path: Path,
    method_name: str,
    operation: TimingOperation,
) -> None:
    recorder = TimingRecorder(
        tmp_path / "timings",
        run_mode=TimingRunMode.WARM,
    )
    service, recipe, sessions, _archive = _service(
        tmp_path,
        _story_page("teaser.html"),
        disposition=SessionDisposition.INCONCLUSIVE,
        timing=recorder,
    )

    with pytest.raises(ContentNotFullError, match="paywall_teaser"):
        getattr(service, method_name)(ARTICLE_URL)

    run = next(iter_timing_runs(recorder.root))
    assert run.finished is not None
    content = run.finished.content_assessment
    assert content is not None
    assert content.access_state is AccessState.TEASER
    assert content.session_probe is not None
    assert content.session_probe.outcome is SessionProbeOutcome.INCONCLUSIVE
    _assert_complete_native_evidence(content, operation=operation, outcome="error")
    assert recipe.calls == 1
    assert sessions.downgrades == 0


@pytest.mark.parametrize(
    ("method_name", "operation"),
    [
        ("get", TimingOperation.GET),
        ("save", TimingOperation.SAVE),
    ],
)
def test_native_dead_probe_survives_session_required_error(
    tmp_path: Path,
    method_name: str,
    operation: TimingOperation,
) -> None:
    recorder = TimingRecorder(
        tmp_path / "timings",
        run_mode=TimingRunMode.WARM,
    )
    service, recipe, sessions, _archive = _service(
        tmp_path,
        _story_page("teaser.html"),
        disposition=SessionDisposition.DEAD,
        timing=recorder,
    )

    with pytest.raises(SessionRequiredError, match="session is no longer valid"):
        getattr(service, method_name)(ARTICLE_URL)

    run = next(iter_timing_runs(recorder.root))
    assert run.finished is not None
    content = run.finished.content_assessment
    assert content is not None
    assert content.access_state is AccessState.TEASER
    assert content.session_probe is not None
    assert content.session_probe.outcome is SessionProbeOutcome.SESSION_DEAD
    _assert_complete_native_evidence(content, operation=operation, outcome="error")
    assert recipe.calls == 1
    assert sessions.downgrades == 1


@pytest.mark.parametrize(
    ("method_name", "operation"),
    [
        ("get", TimingOperation.GET),
        ("save", TimingOperation.SAVE),
    ],
)
def test_native_verified_promotion_records_final_full_assessment(
    tmp_path: Path,
    method_name: str,
    operation: TimingOperation,
) -> None:
    recorder = TimingRecorder(
        tmp_path / "timings",
        run_mode=TimingRunMode.WARM,
    )
    service, recipe, sessions, _archive = _service(
        tmp_path,
        _story_page("teaser.html"),
        timing=recorder,
    )

    article = getattr(service, method_name)(ARTICLE_URL)

    assert article.word_count > 250
    run = next(iter_timing_runs(recorder.root))
    assert run.finished is not None
    content = run.finished.content_assessment
    assert content is not None
    assert content.access_state is AccessState.FULL
    assert content.identity_match is True
    assert content.session_probe is None
    _assert_complete_native_evidence(content, operation=operation, outcome="success")
    assert recipe.calls == 1
    assert sessions.downgrades == 0


def test_teaser_dom_downgrades_only_after_session_is_proven_dead(
    tmp_path: Path,
) -> None:
    service, recipe, sessions, archive = _service(
        tmp_path,
        _story_page("teaser.html"),
        disposition=SessionDisposition.DEAD,
    )

    with pytest.raises(SessionRequiredError, match="session is no longer valid"):
        service.save(ARTICLE_URL)

    assert recipe.calls == 1
    assert sessions.downgrades == 1
    assert archive.search("Fixture chipmaker") == []


def test_unknown_text_component_fails_closed_even_with_full_dom_and_session(
    tmp_path: Path,
) -> None:
    service, recipe, sessions, archive = _service(
        tmp_path,
        _story_page("full.html", invalid_component=True),
    )

    with pytest.raises(ContentNotFullError, match="insufficient_article_structure"):
        service.save(ARTICLE_URL)

    assert recipe.calls == 1
    assert sessions.downgrades == 0
    assert archive.search("Fixture chipmaker") == []


SHORT_STORY_URL = (
    "https://www.bloomberg.com/news/articles/2026-07-22/"
    "fixture-supplier-gave-maker-significant-allocation"
)
STUB_STORY_URL = (
    "https://www.bloomberg.com/news/articles/2026-07-22/"
    "fixture-stub-payload-below-body-floor"
)


def test_short_wire_story_saves_whole_from_its_own_payload(
    tmp_path: Path,
) -> None:
    """A complete Bloomberg brief is shorter than the rendered teaser floor.

    The rendered body cannot distinguish a 231-word article from a truncated
    one by size, so the DOM path calls it a teaser. The payload can: it arrives
    whole, clears the structural block floor, and clears the payload word floor
    that exists only to reject a stub. The session probe then confirms the
    caller is entitled before anything is promoted.
    """

    service, recipe, sessions, archive = _service(
        tmp_path,
        (FIXTURES / "short-wire-story.html").read_bytes(),
    )

    article = service.save(SHORT_STORY_URL)

    assert article.extraction.extractor_name == "bloomberg-next-story"
    assert article.word_count < 250  # below the rendered floor, still complete
    assert "did not respond to a generated request for comment" in article.body_markdown
    assert recipe.calls == 1
    assert sessions.downgrades == 0
    assert service.archive_drift(provider="bloomberg").is_clean


def test_stub_payload_stays_closed_even_with_a_verified_session(
    tmp_path: Path,
) -> None:
    """The payload floor still rejects a stub that clears the block floor."""

    service, recipe, sessions, archive = _service(
        tmp_path,
        (FIXTURES / "thin-stub-payload.html").read_bytes(),
    )

    with pytest.raises(ContentNotFullError, match="insufficient_article_structure"):
        service.save(STUB_STORY_URL)

    assert sessions.downgrades == 0
    assert archive.search("Fixture stub payload") == []
