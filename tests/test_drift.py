"""Drift detection: detect fixture/archive divergence, stay redacted, never write."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from newsclip.archive import ArchiveStore
from newsclip.drift import (
    FixtureExpectation,
    detect_archive_drift,
    detect_fixture_drift,
)
from newsclip.models import (
    AccessState,
    ArticleAssessment,
    ExtractedArticle,
    ProviderCapabilities,
    RateBudget,
    RawFetch,
    SearchFilters,
    SearchResult,
)
from newsclip.providers import ProviderRegistry
from newsclip.providers.base import (
    ProviderNativeExtractionResult,
    ProviderNativeExtractionState,
)
from newsclip.service import NewsclipService

CONTENT_PREFIX = "https://fixture.test/content/"
SECRET_BODY = "SUBSCRIBER_ONLY_BODY_SENTINEL"
SECRET_DRIFTED_ID = "PRIVATE_DRIFTED_ID_SENTINEL"
SECRET_DRIFTED_URL = f"{CONTENT_PREFIX}PRIVATE_DRIFTED_URL_SENTINEL"


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
            body_markdown=SECRET_BODY,
            metadata={"title": "Fixture article", "author": ["Fixture Author"]},
            word_count=250,
        )


def _assess(url: str, raw: bytes, *, signal: str = "article_body") -> ArticleAssessment:
    full = b"FULL" in raw
    article_id = url.rsplit("/", 1)[-1]
    return ArticleAssessment(
        access_state=AccessState.FULL if full else AccessState.TEASER,
        provider_article_id=article_id,
        canonical_url=url,
        identity_match=True,
        negative_markers=() if full else ("paywall",),
        structural_signals=(signal,) if full else (),
        word_count=250,
        reason="full_fixture" if full else "teaser_fixture",
    )


class FakeProvider:
    key = "fixture"
    capabilities = ProviderCapabilities(requires_session_for_retrieve=False)
    login_recipe = None
    assessment_policy_version = "fixture-v1"
    extraction_scope: tuple[str, ...] | None = None

    def __init__(self, *, signal: str = "article_body") -> None:
        self._signal = signal

    def owns_url(self, url: str) -> bool:
        return url.startswith(CONTENT_PREFIX)

    def search(
        self, http, session, query, filters: SearchFilters
    ) -> list[SearchResult]:  # pragma: no cover - unused
        return []

    def fetch(self, http, session, url: str) -> RawFetch:
        return http.get(url, session=session)

    def assess(self, requested_url, fetch, extraction) -> ArticleAssessment:
        return _assess(requested_url, fetch.raw_html, signal=self._signal)

    def rate_budget(self) -> RateBudget:
        return RateBudget(requests_per_second=1000, burst=1000)


def _expectation(name: str, *, state: AccessState, signals: frozenset[str]):
    return FixtureExpectation(
        name=name,
        requested_url=f"{CONTENT_PREFIX}{name}",
        expected_state=state,
        expected_signals=signals,
    )


def test_fixture_drift_is_clean_when_assessment_matches_expectations() -> None:
    provider = FakeProvider()
    cases = [
        (
            b"FULL body",
            _expectation(
                "full", state=AccessState.FULL, signals=frozenset({"article_body"})
            ),
        ),
        (
            b"teaser body",
            _expectation("teaser", state=AccessState.TEASER, signals=frozenset()),
        ),
    ]

    report = detect_fixture_drift(provider, FakeExtractor(), cases)

    assert report.is_clean
    assert report.checked == 2
    assert report.findings == ()


def test_fixture_drift_detects_state_and_signal_changes() -> None:
    # The provider now emits a renamed signal and no longer promotes the teaser.
    provider = FakeProvider(signal="article_body_v2")
    cases = [
        (
            b"FULL body",
            _expectation(
                "full", state=AccessState.FULL, signals=frozenset({"article_body"})
            ),
        ),
        (
            b"FULL body",
            _expectation("was_teaser", state=AccessState.TEASER, signals=frozenset()),
        ),
    ]

    report = detect_fixture_drift(provider, FakeExtractor(), cases)

    assert not report.is_clean
    kinds = {(f.scope, f.kind) for f in report.findings}
    assert ("full", "structural_signals") in kinds
    assert ("was_teaser", "access_state") in kinds
    signal_finding = next(
        f
        for f in report.findings
        if f.kind == "structural_signals" and f.scope == "full"
    )
    assert signal_finding.expected == "article_body"
    assert signal_finding.actual == "article_body_v2"


def test_drift_report_is_redaction_safe() -> None:
    provider = FakeProvider()
    cases = [
        (
            b"FULL " + SECRET_BODY.encode(),
            _expectation("full", state=AccessState.TEASER, signals=frozenset()),
        )
    ]

    report = detect_fixture_drift(provider, FakeExtractor(), cases)
    serialized = json.dumps(report.public_dict())

    assert not report.is_clean  # a finding exists...
    assert SECRET_BODY not in serialized  # ...but it carries no body text


def _service(tmp_path: Path, provider: FakeProvider) -> NewsclipService:
    registry = ProviderRegistry((provider,))
    extractor = FakeExtractor()
    archive = ArchiveStore(
        tmp_path / "archive.sqlite3", registry=registry, extractor=extractor
    )
    return NewsclipService(registry, _StoreHttp(), extractor, archive=archive)


class _StoreHttp:
    def get(self, url, *, session=None, timeout: float = 40) -> RawFetch:
        from datetime import UTC, datetime

        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=datetime.now(UTC),
            session_cookie_present=session is not None,
            raw_html=b"FULL body " + SECRET_BODY.encode(),
        )


def test_archive_drift_detects_reassessment_change_without_moving_pointer(
    tmp_path: Path,
) -> None:
    provider = FakeProvider()
    service = _service(tmp_path, provider)
    saved = service.save(f"{CONTENT_PREFIX}archived-one")
    archive = service._archive
    assert isinstance(archive, ArchiveStore)
    before = archive.get(saved.id)

    # A drifted provider assesses the same archived bytes as a teaser.
    class DriftedProvider(FakeProvider):
        def assess(self, requested_url, fetch, extraction) -> ArticleAssessment:
            base = _assess(requested_url, fetch.raw_html)
            return base.model_copy(
                update={
                    "access_state": AccessState.TEASER,
                    "identity_match": False,
                    "structural_signals": (),
                }
            )

    drifted_registry = ProviderRegistry((DriftedProvider(),))
    report = detect_archive_drift(archive, drifted_registry, FakeExtractor())

    assert report.checked == 1
    assert not report.is_clean
    assert any(f.kind == "access_state" for f in report.findings)

    # The current pointer and archive contents are unchanged (read-only).
    after = archive.get(saved.id)
    assert after == before
    assert archive.inspect_schema()["counts"]["articles"] == 1
    assert archive.inspect_schema()["counts"]["extractions"] == 1


def test_archive_drift_is_clean_for_the_same_provider(tmp_path: Path) -> None:
    provider = FakeProvider()
    service = _service(tmp_path, provider)
    service.save(f"{CONTENT_PREFIX}archived-two")
    archive = service._archive
    assert isinstance(archive, ArchiveStore)

    report = detect_archive_drift(
        archive, ProviderRegistry((FakeProvider(),)), FakeExtractor()
    )

    assert report.checked == 1
    assert report.is_clean


@pytest.mark.parametrize(
    "access_state",
    [AccessState.AUTH_REQUIRED, AccessState.BLOCKED],
)
def test_archive_drift_does_not_hide_native_access_failure(
    tmp_path: Path,
    access_state: AccessState,
) -> None:
    service = _service(tmp_path, FakeProvider())
    service.save(f"{CONTENT_PREFIX}native-access")
    archive = service._archive
    assert isinstance(archive, ArchiveStore)

    class NativeAccessFailureProvider(FakeProvider):
        def assess(self, requested_url, fetch, extraction) -> ArticleAssessment:
            return _assess(requested_url, fetch.raw_html).model_copy(
                update={
                    "access_state": access_state,
                    "reason": (
                        "authentication_required"
                        if access_state is AccessState.AUTH_REQUIRED
                        else "interactive_challenge"
                    ),
                }
            )

        def native_extraction(
            self,
            requested_url: str,
            fetch: RawFetch,
        ) -> ProviderNativeExtractionResult:
            extraction = FakeExtractor().extract(fetch)
            return ProviderNativeExtractionResult(
                state=ProviderNativeExtractionState.VALID,
                reason="valid_fixture",
                extraction=extraction,
                assessment=_assess(requested_url, fetch.raw_html),
                extractor_name="native-fixture",
                extractor_version="1",
            )

    report = detect_archive_drift(
        archive,
        ProviderRegistry((NativeAccessFailureProvider(),)),
        FakeExtractor(),
    )

    access_finding = next(
        finding for finding in report.findings if finding.kind == "access_state"
    )
    assert access_finding.expected == AccessState.FULL
    assert access_finding.actual == access_state


def test_archive_drift_skips_unregistered_providers_without_aborting(
    tmp_path: Path,
) -> None:
    """Rows saved under an opt-in provider must not abort a later sweep run
    with a narrower registry; they are reported as skipped instead."""

    service = _service(tmp_path, FakeProvider())
    service.save(f"{CONTENT_PREFIX}archived-three")
    archive = service._archive
    assert isinstance(archive, ArchiveStore)

    class OtherProvider(FakeProvider):
        key = "other"

        def owns_url(self, url: str) -> bool:
            return False

    report = detect_archive_drift(
        archive, ProviderRegistry((OtherProvider(),)), FakeExtractor()
    )

    assert report.checked == 0
    assert report.skipped_providers == ("fixture",)
    assert report.is_clean
    assert json.loads(json.dumps(report.public_dict()))["skipped_providers"] == [
        "fixture"
    ]


def test_archive_drift_flags_identity_flip_and_body_collapse(tmp_path: Path) -> None:
    """Drift that keeps the assessment shape — an identity flip or a fresh
    extraction losing most of the stored body — must still be reported."""

    service = _service(tmp_path, FakeProvider())
    service.save(f"{CONTENT_PREFIX}archived-four")
    archive = service._archive
    assert isinstance(archive, ArchiveStore)

    class CollapsedProvider(FakeProvider):
        def assess(self, requested_url, fetch, extraction) -> ArticleAssessment:
            base = _assess(requested_url, fetch.raw_html, signal=self._signal)
            return base.model_copy(update={"identity_match": False, "word_count": 40})

    report = detect_archive_drift(
        archive, ProviderRegistry((CollapsedProvider(),)), FakeExtractor()
    )

    kinds = {finding.kind for finding in report.findings}
    assert "identity_match" in kinds
    assert "word_count_collapse" in kinds


def test_archive_drift_flags_exact_identity_changes_without_exposing_values(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path, FakeProvider())
    service.save(f"{CONTENT_PREFIX}archived-five")
    archive = service._archive
    assert isinstance(archive, ArchiveStore)

    class IdentityChangedProvider(FakeProvider):
        def assess(self, requested_url, fetch, extraction) -> ArticleAssessment:
            base = _assess(requested_url, fetch.raw_html, signal=self._signal)
            values = base.model_dump(mode="python")
            values.update(
                {
                    "provider_article_id": SECRET_DRIFTED_ID,
                    "canonical_url": SECRET_DRIFTED_URL,
                }
            )
            return ArticleAssessment.model_validate(values)

    report = detect_archive_drift(
        archive, ProviderRegistry((IdentityChangedProvider(),)), FakeExtractor()
    )
    serialized = json.dumps(report.public_dict())

    assert not report.is_clean
    assert {finding.kind for finding in report.findings} == {
        "provider_article_id",
        "canonical_url",
    }
    assert all(
        (finding.expected, finding.actual) == ("stored", "changed")
        for finding in report.findings
    )
    assert SECRET_DRIFTED_ID not in serialized
    assert SECRET_DRIFTED_URL not in serialized
