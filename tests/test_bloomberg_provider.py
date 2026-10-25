"""Bloomberg provider gates on the promoted browser retrieval plane.

These tests cover the browser-transport provider that retrieves through the
shared core plane with a cookie artifact and retained profile.
Assessment keeps identity + structure gating, with independent body-size and
paragraph-shape floors separating a full article from a truncated teaser —
never body size before identity.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from lxml import html

from newsclip.composition import build_registry
from newsclip.errors import PersistenceError, ProviderContractError
from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import (
    AccessState,
    ExtractedArticle,
    PortableCookie,
    RawFetch,
    SearchFilters,
    SessionArtifact,
)
from newsclip.provider_config import load_provider_spec
from newsclip.providers import BloombergProvider, ProviderRegistry
from newsclip.providers.base import ProviderNativeExtractionState
from newsclip.providers.bloomberg import (
    BloombergLoginRecipe,
    article_id,
    normalize_article_url,
)
from newsclip.providers.bloomberg_story import extract_bloomberg_story
from newsclip.service import NewsclipService

NOW = datetime(2026, 7, 17, tzinfo=UTC)
ARTICLE_ID = "fixture-chipmaker-beats-estimates"
ARTICLE_URL = f"https://www.bloomberg.com/news/articles/2026-07-16/{ARTICLE_ID}"
FIXTURES = Path(__file__).parent / "fixtures" / "bloomberg"


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _fetch(name, *, final_url=ARTICLE_URL, status=200, session_cookie_present=False):
    return RawFetch(
        requested_url=ARTICLE_URL,
        final_url=final_url,
        http_status=status,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=session_cookie_present,
        raw_html=_fixture(name),
    )


def _assess(name: str, **opts):
    fetch = _fetch(name, **opts)
    extraction = TrafilaturaExtractor().extract(fetch)
    return BloombergProvider().assess(ARTICLE_URL, fetch, extraction), extraction


def _with_full_story_bootstrap(*, duplicate_third_paragraph: bool = False) -> bytes:
    document = html.fromstring(_fixture("full.html"))
    paragraphs = document.xpath("//article/p")
    values = [" ".join(paragraph.text_content().split()) for paragraph in paragraphs]
    payload = {
        "props": {
            "pageProps": {
                "story": {
                    "seoCanonical": ARTICLE_URL,
                    "headline": "Fixture Chipmaker Beats Estimates",
                    "body": {
                        "type": "doc",
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [{"type": "text", "value": value}],
                            }
                            for value in values
                        ],
                    },
                }
            }
        }
    }
    script = html.Element("script", id="__NEXT_DATA__", type="application/json")
    script.text = json.dumps(payload)
    document.xpath("//head")[0].append(script)
    if duplicate_third_paragraph:
        paragraphs[-1].text = paragraphs[-2].text
    return html.tostring(document)


def test_provider_preserves_the_public_login_recipe_type() -> None:
    assert BloombergProvider().login_recipe is None
    assert isinstance(
        BloombergProvider(verification_url=ARTICLE_URL).login_recipe,
        BloombergLoginRecipe,
    )


@pytest.mark.parametrize(
    ("fixture", "opts", "expected"),
    [
        ("full.html", {}, AccessState.FULL),
        ("teaser.html", {}, AccessState.TEASER),
        ("padded_teaser.html", {}, AccessState.TEASER),
        ("paywall.html", {}, AccessState.TEASER),
        (
            "auth.html",
            {"final_url": "https://www.bloomberg.com/account/signin"},
            AccessState.AUTH_REQUIRED,
        ),
        ("interstitial.html", {}, AccessState.BLOCKED),
        ("long_nonarticle.html", {"session_cookie_present": True}, AccessState.UNKNOWN),
        ("wrong_canonical.html", {}, AccessState.UNKNOWN),
        ("malformed_metadata.html", {}, AccessState.UNKNOWN),
        ("http_error.html", {"status": 503}, AccessState.UNKNOWN),
    ],
)
def test_assessment_fixture_matrix(fixture, opts, expected) -> None:
    assessment, _ = _assess(fixture, **opts)

    assert assessment.access_state is expected
    assert assessment.promotable is (expected is AccessState.FULL)


def test_body_floor_separates_full_from_truncated_teaser() -> None:
    full, _ = _assess("full.html")
    teaser, _ = _assess("teaser.html")

    assert full.access_state is AccessState.FULL
    assert "article_word_floor" in full.structural_signals
    assert "article_paragraph_floor" in full.structural_signals
    assert teaser.access_state is AccessState.TEASER
    assert teaser.identity_match is True  # same identity, only the body is short


def test_two_substantial_and_several_short_paragraphs_can_be_full() -> None:
    """Bloomberg market stories can concentrate text in two long paragraphs."""

    body = _fixture("full.html")
    article_start = body.index(b"<article>")
    article_end = body.index(b"</article>", article_start) + len(b"</article>")
    long_paragraph = ("generated evidence " * 130).strip()
    short_paragraphs = "".join(
        f"<p>Short generated transition {index}.</p>" for index in range(5)
    )
    replacement = (
        "<article><h1>Fixture chipmaker beats estimates</h1>"
        f"<p>{long_paragraph}</p><p>{long_paragraph}</p>"
        f"{short_paragraphs}</article>"
    ).encode()
    body = body[:article_start] + replacement + body[article_end:]
    fetch = RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=body,
    )

    assessment = BloombergProvider().assess(
        ARTICLE_URL, fetch, TrafilaturaExtractor().extract(fetch)
    )

    assert assessment.access_state is AccessState.FULL
    assert "article_word_floor" in assessment.structural_signals
    assert "article_paragraph_floor" in assessment.structural_signals


def test_paragraph_shape_cannot_bypass_the_word_floor() -> None:
    fetch = _fetch("full.html", session_cookie_present=True)
    extraction = (
        TrafilaturaExtractor().extract(fetch).model_copy(update={"word_count": 249})
    )

    assessment = BloombergProvider().assess(ARTICLE_URL, fetch, extraction)

    assert assessment.access_state is AccessState.TEASER
    assert "article_paragraph_floor" in assessment.structural_signals
    assert "article_word_floor" not in assessment.structural_signals


def test_four_rendered_paragraphs_do_not_prove_snapshot_readiness() -> None:
    assessment, extraction = _assess("incremental-four-paragraphs.html")

    assert extraction.word_count < 250
    assert assessment.access_state is AccessState.TEASER
    assert "article_paragraph_floor" not in assessment.structural_signals
    assert "article_word_floor" not in assessment.structural_signals


def test_valid_story_payload_makes_partial_dom_coverage_diagnostic() -> None:
    provider = BloombergProvider()

    def evaluate(raw_html: bytes):
        fetch = RawFetch(
            requested_url=ARTICLE_URL,
            final_url=ARTICLE_URL,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=True,
            raw_html=raw_html,
        )
        extraction = TrafilaturaExtractor().extract(fetch)
        assessment = provider.assess(ARTICLE_URL, fetch, extraction)
        return (
            assessment,
            provider.browser_snapshot_complete(fetch, extraction, assessment),
        )

    partial_assessment, partial_complete = evaluate(
        _with_full_story_bootstrap(duplicate_third_paragraph=True)
    )
    full_assessment, full_complete = evaluate(_with_full_story_bootstrap())

    assert partial_assessment.access_state is AccessState.FULL
    assert partial_complete.complete is True
    assert partial_complete.coverage is not None
    assert 0.75 <= partial_complete.coverage < 0.9
    assert full_assessment.access_state is AccessState.FULL
    assert full_complete.complete is True
    assert full_complete.coverage is not None
    assert full_complete.coverage >= 0.9


def test_bulleted_wrap_payload_is_a_complete_entitled_article() -> None:
    """A list-structured Bloomberg wrap is a whole article, not a truncated one.

    Bloomberg publishes market wraps as an intro paragraph, a bulleted list
    carrying most of the prose, a data table, and a closing paragraph. Counting
    only ``paragraph`` components sees two blocks, rejects the payload as
    ``story_body_below_floor``, and takes the rendered article down with it.
    """

    provider = BloombergProvider()
    fetch = _fetch("bulleted-wrap.html", session_cookie_present=True)
    extraction = TrafilaturaExtractor().extract(fetch)
    assessment = provider.assess(ARTICLE_URL, fetch, extraction)
    story = extract_bloomberg_story(fetch.raw_html)
    candidate = story.candidate
    floor = BloombergProvider().spec.assessment.paragraph_floor
    assert candidate is not None and floor is not None

    # The rendered article is unambiguously a full, entitled article.
    assert assessment.access_state is AccessState.FULL
    assert assessment.promotable is True
    # The payload clears the word floor, so body size is not the objection.
    assert candidate.extraction.word_count >= 250
    # Only the paragraph-shaped structure count falls short.
    assert candidate.paragraph_count < floor.minimum_count
    assert candidate.narrative_block_count >= floor.minimum_count

    native = provider.native_extraction(ARTICLE_URL, fetch)

    assert native.state is ProviderNativeExtractionState.VALID
    assert native.reason == "story_valid"


def test_bulleted_wrap_completes_both_completeness_contracts() -> None:
    """Rejecting the payload previously failed the read path and paid proof alike."""

    provider = BloombergProvider()
    fetch = _fetch("bulleted-wrap.html", session_cookie_present=True)
    extraction = TrafilaturaExtractor().extract(fetch)
    assessment = provider.assess(ARTICLE_URL, fetch, extraction)

    read_path = provider.browser_snapshot_complete(fetch, extraction, assessment)
    paid_proof = provider.browser_paid_proof_complete(fetch, extraction, assessment)

    assert read_path.complete is True
    assert paid_proof.complete is True


def test_a_thin_payload_still_fails_the_body_floor() -> None:
    """The floor must still reject a payload that carries almost no article."""

    document = html.fromstring(_fixture("bulleted-wrap.html"))
    script = document.xpath("//script[@id='__NEXT_DATA__']")[0]
    payload = json.loads(script.text)
    payload["props"]["pageProps"]["story"]["body"]["content"] = [
        {
            "type": "paragraph",
            "content": [{"type": "text", "value": "One short generated line."}],
        }
    ]
    script.text = json.dumps(payload)
    raw = html.tostring(document)
    fetch = RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=raw,
    )

    native = BloombergProvider().native_extraction(ARTICLE_URL, fetch)

    assert native.state is ProviderNativeExtractionState.INVALID
    assert native.reason == "story_body_below_floor"


def _paid_proof(raw_html: bytes, **opts):
    provider = BloombergProvider()
    fetch = RawFetch(
        requested_url=ARTICLE_URL,
        final_url=opts.get("final_url", ARTICLE_URL),
        http_status=opts.get("status", 200),
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=opts.get("session_cookie_present", True),
        raw_html=raw_html,
    )
    extraction = TrafilaturaExtractor().extract(fetch)
    assessment = provider.assess(ARTICLE_URL, fetch, extraction)
    return assessment, provider.browser_paid_proof_complete(
        fetch, extraction, assessment
    )


def test_paid_proof_accepts_a_partially_rendered_entitled_article() -> None:
    """Requiring rendered coverage made cold minting deterministically impossible.

    Bloomberg delivers the whole story beside a partly rendered DOM, so demanding
    the DOM cover it kept the readiness sampler from ever reporting ready — a
    perfectly static page timed out identically to a churning one.
    """

    partial_assessment, partial = _paid_proof(
        _with_full_story_bootstrap(duplicate_third_paragraph=True)
    )

    assert partial_assessment.access_state is AccessState.FULL
    assert partial_assessment.promotable is True
    assert partial.complete is True
    # Coverage is retained as evidence, and it is below the floor that used to
    # gate the proof.
    assert partial.coverage is not None
    assert 0.75 <= partial.coverage < 0.9


def test_paid_proof_still_accepts_a_fully_rendered_entitled_article() -> None:
    assessment, complete = _paid_proof(_with_full_story_bootstrap())

    assert assessment.access_state is AccessState.FULL
    assert complete.complete is True
    assert complete.coverage is not None
    assert complete.coverage >= 0.9


@pytest.mark.parametrize(
    ("fixture", "opts"),
    [
        ("teaser.html", {}),
        ("padded_teaser.html", {}),
        ("paywall.html", {}),
        ("auth.html", {"final_url": "https://www.bloomberg.com/account/signin"}),
        ("interstitial.html", {}),
        ("wrong_canonical.html", {}),
    ],
    ids=[
        "teaser",
        "padded_teaser",
        "paywall",
        "auth",
        "interstitial",
        "wrong_canonical",
    ],
)
def test_paid_proof_refuses_every_unentitled_surface(fixture, opts) -> None:
    """The entitlement guard must survive dropping the coverage requirement."""

    assessment, complete = _paid_proof(_fixture(fixture), **opts)

    assert assessment.promotable is False
    assert complete.complete is False


def test_paid_proof_refuses_a_complete_payload_behind_a_rendered_paywall() -> None:
    """The exact retained teaser/full pair: same payload, different rendered DOM.

    The read path may treat that payload as the content source. Session minting
    may not: a rendered paywall means this session is not entitled, whatever the
    response delivered.
    """

    document = html.fromstring(_fixture("paywall.html"))
    donor = html.fromstring(_with_full_story_bootstrap())
    script = donor.xpath("//script[@id='__NEXT_DATA__']")[0]
    document.xpath("//head")[0].append(script)
    raw = html.tostring(document)

    assessment, paid = _paid_proof(raw)
    provider = BloombergProvider()
    fetch = RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=raw,
    )
    extraction = TrafilaturaExtractor().extract(fetch)
    read_path = provider.browser_snapshot_complete(fetch, extraction, assessment)

    assert assessment.access_state is AccessState.TEASER
    assert paid.complete is False
    # The read path is deliberately laxer here; paid proof must not follow it.
    assert read_path.complete is True


def test_paid_proof_refuses_an_invalid_story_payload() -> None:
    document = html.fromstring(_with_full_story_bootstrap())
    script = document.xpath("//script[@id='__NEXT_DATA__']")[0]
    payload = json.loads(script.text)
    payload["props"]["pageProps"]["story"]["seoCanonical"] = (
        "https://www.bloomberg.com/news/articles/2026-07-16/some-other-story"
    )
    script.text = json.dumps(payload)

    _, complete = _paid_proof(html.tostring(document))

    assert complete.complete is False


def test_snapshot_readiness_falls_back_to_assessment_without_bootstrap() -> None:
    fetch = _fetch("full.html", session_cookie_present=True)
    extraction = TrafilaturaExtractor().extract(fetch)
    provider = BloombergProvider()
    assessment = provider.assess(ARTICLE_URL, fetch, extraction)

    completeness = provider.browser_snapshot_complete(fetch, extraction, assessment)

    assert completeness.complete is True
    assert completeness.coverage is None


@pytest.mark.parametrize(
    "replacement",
    [
        b"",
        b'<script type="application/ld+json">'
        b'{"@type":"WebPage","name":"Fixture page"}</script>',
    ],
)
def test_html_headline_supports_pages_without_newsarticle_jsonld(
    replacement: bytes,
) -> None:
    """Current Bloomberg pages may omit NewsArticle but retain strong HTML."""

    body = _fixture("full.html")
    start = body.index(b'<script type="application/ld+json">')
    end = body.index(b"</script>", start) + len(b"</script>")
    body = body[:start] + replacement + body[end:]
    fetch = RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=body,
    )

    assessment = BloombergProvider().assess(
        ARTICLE_URL, fetch, TrafilaturaExtractor().extract(fetch)
    )

    assert assessment.access_state is AccessState.FULL
    assert "page_headline" in assessment.structural_signals
    assert "article_paragraph_floor" in assessment.structural_signals


def test_html_metadata_fallback_requires_a_page_headline() -> None:
    body = _fixture("full.html")
    start = body.index(b'<script type="application/ld+json">')
    end = body.index(b"</script>", start) + len(b"</script>")
    body = body[:start] + body[end:]
    body = body.replace(
        b"<h1>Fixture chipmaker beats estimates</h1>",
        b"<div>Fixture chipmaker beats estimates</div>",
    )
    fetch = RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=body,
    )

    assessment = BloombergProvider().assess(
        ARTICLE_URL, fetch, TrafilaturaExtractor().extract(fetch)
    )

    assert assessment.access_state is AccessState.UNKNOWN
    assert assessment.reason == "insufficient_article_structure"


def test_related_story_rail_cannot_pad_a_teaser_past_the_floor() -> None:
    """The floor counts substantial paragraphs inside one <article>; unrelated
    modules and short promo lines must not add up to a promotion."""

    padded, _ = _assess("padded_teaser.html")

    assert padded.access_state is AccessState.TEASER
    assert "article_paragraph_floor" not in padded.structural_signals


def test_long_related_story_rail_cannot_supply_the_main_body_floor() -> None:
    body = _fixture("padded_teaser.html")
    long_related = ("generated related summary " * 70).strip().encode()
    for index, label in enumerate(("one", "two", "three", "four"), start=1):
        body = body.replace(
            f"Related story {label}".encode(),
            long_related + f" {index}".encode(),
        )
    fetch = RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=body,
    )

    assessment = BloombergProvider().assess(
        ARTICLE_URL, fetch, TrafilaturaExtractor().extract(fetch)
    )

    assert assessment.word_count >= 250
    assert assessment.access_state is AccessState.TEASER
    assert "article_paragraph_floor" not in assessment.structural_signals


def test_benign_google_signin_link_does_not_flip_full_to_auth() -> None:
    body = _fixture("full.html").replace(
        b"</main>",
        b'<footer><a href="https://accounts.google.com/signin">Sign in</a>'
        b"</footer></main>",
    )
    fetch = RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=body,
    )
    extraction = TrafilaturaExtractor().extract(fetch)
    assessment = BloombergProvider().assess(ARTICLE_URL, fetch, extraction)

    assert assessment.access_state is AccessState.FULL


@pytest.mark.parametrize(
    "fixture",
    [
        "teaser.html",
        "padded_teaser.html",
        "wrong_canonical.html",
        "interstitial.html",
        "malformed_metadata.html",
    ],
)
def test_session_cookie_and_body_size_cannot_promote_a_negative(fixture: str) -> None:
    opts: dict[str, object] = {"session_cookie_present": True}
    assessment, _ = _assess(fixture, **opts)
    assert assessment.access_state is not AccessState.FULL


def test_word_count_alone_cannot_override_identity_or_block() -> None:
    fetch = _fetch("wrong_canonical.html", session_cookie_present=True)
    extraction = ExtractedArticle(
        body_markdown="generated " * 10_000,
        metadata={"title": "Generated headline"},
        word_count=10_000,
    )
    assessment = BloombergProvider().assess(ARTICLE_URL, fetch, extraction)
    assert assessment.access_state is not AccessState.FULL


def test_reasons_and_signals_are_normalized_and_redaction_safe() -> None:
    assessment, _ = _assess("paywall.html")
    serialized = json.dumps(assessment.model_dump(mode="json"))

    assert assessment.reason == "paywall_teaser"
    assert "subscribe to continue reading" not in serialized.lower()
    assert "generated preview sentence" not in serialized.lower()


class SearchHttp:
    def __init__(self, pages: dict[int, dict[str, object]] | None = None) -> None:
        self.urls: list[str] = []
        self.pages = pages or {
            1: {
                "results": [
                    {
                        "resourceId": "story-one",
                        "url": ARTICLE_URL,
                        "headline": "Fixture chip plans",
                        "summary": "First fixture summary",
                        "publishedAt": "2026-07-16T09:00:00Z",
                    },
                    {
                        "resourceId": "story-two",
                        "url": "https://www.bloomberg.com/news/features/2026-07-15/second-fixture-feature",
                        "headline": "Second fixture result",
                        "publishedAt": "2026-07-15T09:00:00Z",
                    },
                ],
                "queryMetadata": {},
                "page": 1,
                "total": 2,
            }
        }

    def get(self, url, *, session=None, timeout: float = 40) -> RawFetch:
        self.urls.append(url)
        page = int(url.rsplit("page=", 1)[-1].split("&", 1)[0]) if "page=" in url else 1
        payload = self.pages.get(
            page,
            {"results": [], "queryMetadata": {}, "page": page, "total": 0},
        )
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="application/json",
            retrieved_at=NOW,
            raw_html=json.dumps(payload).encode(),
        )


def test_search_uses_result_list_and_strict_bloomberg_urls() -> None:
    http = SearchHttp()
    provider = build_registry().get("bloomberg")

    assert isinstance(provider, BloombergProvider)
    results = provider.search(http, None, "chips", SearchFilters(limit=10))

    assert http.urls == [
        "https://www.bloomberg.com/nemo-next/api/search/query?query=chips"
    ]
    assert [str(result.url) for result in results] == [
        ARTICLE_URL,
        "https://www.bloomberg.com/news/features/2026-07-15/second-fixture-feature",
    ]
    assert [result.published for result in results] == [
        datetime(2026, 7, 16, 9, tzinfo=UTC),
        datetime(2026, 7, 15, 9, tzinfo=UTC),
    ]
    assert all(result.provider == "bloomberg" for result in results)

    filtered = provider.search(
        http,
        None,
        "chips",
        SearchFilters(published_after=datetime(2026, 7, 16, tzinfo=UTC)),
    )
    assert [str(result.url) for result in filtered] == [ARTICLE_URL]


def test_search_request_endpoint_comes_from_adapter_definition() -> None:
    spec = load_provider_spec("bloomberg")
    search = type(spec.search).model_validate(
        {
            "kind": "adapter",
            "endpoint": "https://www.bloomberg.com/configured-nemo-search",
        }
    )
    provider = BloombergProvider(spec=spec.model_copy(update={"search": search}))
    http = SearchHttp()

    provider.search(http, None, "chips", SearchFilters(limit=1))

    assert http.urls == ["https://www.bloomberg.com/configured-nemo-search?query=chips"]


def test_search_fans_out_page_window_without_exclude_chain() -> None:
    """Default limit=20 needs two API pages; product path fans them out."""

    def _story(index: int, page: int) -> dict[str, object]:
        day = 10 + index
        return {
            "resourceId": f"story-{page}-{index}",
            "url": (
                f"https://www.bloomberg.com/news/articles/2026-07-{day:02d}/"
                f"story-page-{page}-item-{index}"
            ),
            "headline": f"Page {page} result {index}",
            "publishedAt": f"2026-07-{day:02d}T09:00:00Z",
        }

    pages = {
        1: {
            "results": [_story(i, 1) for i in range(10)],
            "queryMetadata": {},
            "page": 1,
            "total": 25,
        },
        2: {
            "results": [_story(i, 2) for i in range(10)],
            "queryMetadata": {},
            "page": 2,
            "total": 25,
        },
        3: {
            "results": [_story(i, 3) for i in range(5)],
            "queryMetadata": {},
            "page": 3,
            "total": 25,
        },
    }
    http = SearchHttp(pages)

    results = BloombergProvider().search(
        http, None, "European banks", SearchFilters(limit=20)
    )

    assert len(results) == 20
    assert [result.headline for result in results[:2]] == [
        "Page 1 result 0",
        "Page 1 result 1",
    ]
    assert results[10].headline == "Page 2 result 0"
    # Parallel fan-out: page-number URLs, no sequential exclude chain.
    assert set(http.urls) == {
        "https://www.bloomberg.com/nemo-next/api/search/query?query=European+banks",
        "https://www.bloomberg.com/nemo-next/api/search/query?query=European+banks&page=2",
    }
    assert all("exclude=" not in url for url in http.urls)


def test_search_falls_back_to_exclude_chain_beyond_parallel_window() -> None:
    def story(index: int, page: int) -> dict[str, object]:
        return {
            "resourceId": f"story-{page}-{index}",
            "url": (
                "https://www.bloomberg.com/news/articles/2026-07-16/"
                f"story-page-{page}-item-{index}"
            ),
            "headline": f"Page {page} result {index}",
            "publishedAt": "2026-07-16T09:00:00Z",
        }

    pages = {
        page: {
            "results": [story(index, page) for index in range(10)],
            "queryMetadata": {},
            "page": page,
            "total": 100,
        }
        for page in range(1, 11)
    }
    http = SearchHttp(pages)

    results = BloombergProvider().search(
        http,
        None,
        "European banks",
        SearchFilters(limit=100),
    )

    assert len(results) == 100
    assert len({str(result.url) for result in results}) == 100
    assert any("exclude=" in url for url in http.urls)
    assert any("page=10" in url for url in http.urls)


def test_search_beyond_parallel_window_skips_the_discarded_fan_out() -> None:
    """A limit the window cannot satisfy must not pay for the fan-out first."""

    def story(index: int, page: int) -> dict[str, object]:
        return {
            "resourceId": f"story-{page}-{index}",
            "url": (
                "https://www.bloomberg.com/news/articles/2026-07-16/"
                f"story-page-{page}-item-{index}"
            ),
            "headline": f"Page {page} result {index}",
            "publishedAt": "2026-07-16T09:00:00Z",
        }

    pages = {
        page: {
            "results": [story(index, page) for index in range(10)],
            "queryMetadata": {},
            "page": page,
            "total": 100,
        }
        for page in range(1, 11)
    }
    http = SearchHttp(pages)

    results = BloombergProvider().search(
        http,
        None,
        "European banks",
        SearchFilters(limit=31),
    )

    assert len(results) == 31
    # The exclude chain opens with one bare page=1; every later page it
    # requests carries an exclude chain. A fan-out page carries none, so a
    # second exclude-free URL would prove the discarded window was fetched.
    assert sum("exclude=" not in url for url in http.urls) == 1


def test_search_default_window_does_not_replay_exclude_chain() -> None:
    pages = {
        page: {
            "results": [
                {
                    "resourceId": f"story-{page}",
                    "url": (
                        "https://www.bloomberg.com/news/articles/2026-07-16/"
                        f"story-page-{page}"
                    ),
                    "headline": f"Page {page} result",
                    "publishedAt": "2026-07-16T09:00:00Z",
                }
            ],
            "queryMetadata": {},
            "page": page,
            "total": 100,
        }
        for page in (1, 2)
    }
    http = SearchHttp(pages)

    results = BloombergProvider().search(
        http,
        None,
        "European banks",
        SearchFilters(limit=20),
    )

    assert len(results) == 2
    assert len(http.urls) == 2
    assert all("exclude=" not in url for url in http.urls)


def test_search_page_continues_with_resource_exclusions() -> None:
    pages = {
        1: {
            "results": [
                {
                    "resourceId": "story-one",
                    "url": ARTICLE_URL,
                    "headline": "First result",
                    "publishedAt": "2026-07-16T09:00:00Z",
                }
            ],
            "queryMetadata": {},
            "page": 1,
            "total": 2,
        },
        2: {
            "results": [
                {
                    "resourceId": "story-two",
                    "url": "https://www.bloomberg.com/news/features/2026-07-15/second-fixture-feature",
                    "headline": "Second result",
                    "publishedAt": "2026-07-15T09:00:00Z",
                }
            ],
            "queryMetadata": {},
            "page": 2,
            "total": 2,
        },
    }
    http = SearchHttp(pages)
    provider = BloombergProvider()

    first = provider.search_page(http, None, "European banks", SearchFilters(limit=2))
    second = provider.search_page(
        http,
        None,
        "European banks",
        SearchFilters(limit=2),
        next_url=first.next_url,
    )

    assert [result.headline for result in first.results] == ["First result"]
    assert [result.headline for result in second.results] == ["Second result"]
    assert http.urls == [
        "https://www.bloomberg.com/nemo-next/api/search/query?query=European+banks",
        "https://www.bloomberg.com/nemo-next/api/search/query?query=European+banks&page=2&exclude=story-one",
    ]


def test_search_deduplicates_exclusions_and_stops_without_progress() -> None:
    pages = {
        1: {
            "results": [
                {
                    "resourceId": "story-one",
                    "url": ARTICLE_URL,
                    "headline": "First result",
                },
                {
                    "resourceId": "story-one",
                    "url": ARTICLE_URL,
                    "headline": "Repeated first result",
                },
            ],
            "page": 1,
            "total": 3,
        },
        2: {
            "results": [
                {
                    "resourceId": "story-one",
                    "url": ARTICLE_URL,
                    "headline": "Repeated first result",
                }
            ],
            "page": 2,
            "total": 3,
        },
    }
    http = SearchHttp(pages)
    provider = BloombergProvider()

    first = provider.search_page(http, None, "chips", SearchFilters())
    second = provider.search_page(
        http,
        None,
        "chips",
        SearchFilters(),
        next_url=first.next_url,
    )

    assert first.next_url == (
        "https://www.bloomberg.com/nemo-next/api/search/query?"
        "query=chips&page=2&exclude=story-one"
    )
    assert second.next_url is None


def test_search_uses_url_date_when_timestamp_is_missing() -> None:
    http = SearchHttp(
        {
            1: {
                "results": [
                    {
                        "resourceId": "story-one",
                        "url": "https://www.bloomberg.com/news/articles/2026-07-06/europe-s-bank-woes",
                        "headline": "European bank woes",
                    }
                ],
                "page": 1,
                "total": 1,
            }
        }
    )

    results = BloombergProvider().search(
        http, None, "European banks", SearchFilters(limit=10)
    )

    assert [result.published for result in results] == [
        datetime(2026, 7, 6, tzinfo=UTC)
    ]


def test_search_prefers_card_timestamp_over_url_date() -> None:
    results = BloombergProvider().search(
        SearchHttp(), None, "chips", SearchFilters(limit=10)
    )

    assert results[0].published == datetime(2026, 7, 16, 9, tzinfo=UTC)


def test_search_rejects_json_schema_drift() -> None:
    http = SearchHttp({1: {"results": {}, "page": 1, "total": 1}})

    with pytest.raises(ProviderContractError, match="schema changed"):
        BloombergProvider().search(http, None, "chips", SearchFilters())


@pytest.mark.parametrize(
    "raw",
    [
        "http://www.bloomberg.com/news/articles/2026-07-16/slug",
        "https://bloomberg.com/news/articles/2026-07-16/slug",
        "https://www.bloomberg.com/account/signin",
        "https://www.bloomberg.com/news/articles/slug-without-date",
        "https://www.bloomberg.com/news/articles/2026-07-16/slug/extra",
    ],
)
def test_url_normalization_rejects_unowned_or_malformed_urls(raw: str) -> None:
    assert normalize_article_url(raw) is None


def test_url_normalization_canonicalizes_owned_relative_url() -> None:
    assert (
        normalize_article_url(f"/news/articles/2026-07-16/{ARTICLE_ID}?srnd=x")
        == ARTICLE_URL
    )
    assert article_id(ARTICLE_URL) == ARTICLE_ID


# --- Browser-plane integration -------------------------------------------


def _session() -> SessionArtifact:
    return SessionArtifact(
        generation_id=uuid4(),
        provider="bloomberg",
        created_at=NOW,
        verified_at=NOW,
        cookies=(
            PortableCookie(
                name="_user-token",
                value="COOKIE_VALUE_SENTINEL",
                domain=".bloomberg.com",
            ),
        ),
    )


class FixtureBrowserRetriever:
    def __init__(self, name: str) -> None:
        self.name = name
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
            raw_html=_fixture(self.name),
        )


class ForbiddenHttp:
    def get(self, url, *, session=None, timeout: float = 40) -> RawFetch:
        raise AssertionError("Bloomberg must not use the HTTP plane")


class ProfileSource:
    def get_valid_session(self, provider, account_key="default"):
        return _session()

    def mark_required(self, provider, account_key="default") -> None: ...


def test_bloomberg_retrieves_full_article_through_the_browser_plane() -> None:
    retriever = FixtureBrowserRetriever("full.html")
    service = NewsclipService(
        ProviderRegistry((BloombergProvider(),)),
        ForbiddenHttp(),
        TrafilaturaExtractor(),
        sessions=ProfileSource(),
        browser_retriever=retriever,
        network_sleep=lambda _s: None,
    )

    article = service.get(ARTICLE_URL)

    assert str(article.url) == ARTICLE_URL
    assert article.provider == "bloomberg"
    assert isinstance(retriever.calls[0][1], SessionArtifact)


def test_bloomberg_without_a_browser_plane_fails_closed() -> None:
    service = NewsclipService(
        ProviderRegistry((BloombergProvider(),)),
        ForbiddenHttp(),
        TrafilaturaExtractor(),
        sessions=ProfileSource(),
    )
    with pytest.raises(PersistenceError, match="browser retrieval plane"):
        service.get(ARTICLE_URL)


def test_bloomberg_is_in_the_default_composition_registry() -> None:
    from newsclip.composition import build_registry

    assert "bloomberg" in [provider.key for provider in build_registry()]


class VerifyRetriever:
    def __init__(self, name: str) -> None:
        self.name = name

    def get(self, url, *, session=None, timeout: float = 40) -> RawFetch:
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=session is not None,
            raw_html=_fixture(self.name),
        )


def test_recipe_verifier_uses_full_assessment_over_the_browser_plane() -> None:
    recipe = BloombergLoginRecipe(verification_url=ARTICLE_URL)

    full = recipe.verify(VerifyRetriever("full.html"), _session())
    teaser = recipe.verify(VerifyRetriever("teaser.html"), _session())

    assert full.verified is True
    assert full.access_state is AccessState.FULL
    assert teaser.verified is False
    assert teaser.access_state is AccessState.TEASER


def test_recipe_requires_owned_verification_url() -> None:
    with pytest.raises(ValueError, match="owned article URL"):
        BloombergLoginRecipe(verification_url="https://evil.test/news/articles/x")


SHORT_STORY_ID = "fixture-supplier-gave-maker-significant-allocation"
SHORT_STORY_URL = f"https://www.bloomberg.com/news/articles/2026-07-22/{SHORT_STORY_ID}"


def test_the_two_body_floors_judge_the_same_short_article_differently() -> None:
    """One response, two floors, and only the payload can prove completeness.

    A complete Bloomberg brief is shorter than the rendered teaser floor. The
    rendered path has no way to tell it apart from a truncated body, so it must
    keep calling it a teaser. The payload arrives whole, so its floor is free to
    sit lower and still reject a stub. Collapsing the two — the state before
    this split — rejected the complete article outright.
    """

    provider = BloombergProvider()
    raw = _fixture("short-wire-story.html")
    fetch = RawFetch(
        requested_url=SHORT_STORY_URL,
        final_url=SHORT_STORY_URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=raw,
    )
    extraction = TrafilaturaExtractor().extract(fetch)

    rendered = provider.assess(SHORT_STORY_URL, fetch, extraction)
    assert rendered.access_state is AccessState.TEASER
    assert rendered.reason == "paywall_teaser"
    assert rendered.identity_match is True  # only the size is in question

    native = provider.native_extraction(SHORT_STORY_URL, fetch)
    assert native.state is ProviderNativeExtractionState.VALID
    assert native.assessment is not None
    assert native.assessment.access_state is AccessState.FULL

    spec = load_provider_spec("bloomberg").assessment
    assert native.assessment.word_count < spec.minimum_words
    assert native.assessment.word_count >= spec.effective_story_minimum_words


def test_payload_floor_still_rejects_a_stub_that_clears_the_block_floor() -> None:
    """Four blocks and two substantial ones are not an article on their own."""

    provider = BloombergProvider()
    url = (
        "https://www.bloomberg.com/news/articles/2026-07-22/"
        "fixture-stub-payload-below-body-floor"
    )
    fetch = RawFetch(
        requested_url=url,
        final_url=url,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=_fixture("thin-stub-payload.html"),
    )

    story = extract_bloomberg_story(fetch.raw_html)
    assert story.candidate is not None
    floor = load_provider_spec("bloomberg").assessment.paragraph_floor
    assert floor is not None
    assert story.candidate.narrative_block_count >= floor.minimum_count
    assert (
        sum(
            length >= floor.substantial_minimum_characters
            for length in story.candidate.narrative_character_counts
        )
        >= floor.minimum_substantial_count
    )

    native = provider.native_extraction(url, fetch)
    assert native.state is ProviderNativeExtractionState.INVALID
    assert native.reason == "story_body_below_floor"
