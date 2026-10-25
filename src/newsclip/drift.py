"""Read-only provider/extraction drift detection.

Drift detection compares what the provider *now* assesses against a trusted
baseline — a versioned fixture expectation or the assessment stored alongside an
archived raw fetch — and reports differences as normalized signal names only. It
holds no write path: it can neither edit provider source nor move a current
extraction pointer, so a detected regression yields a report for human review,
never an auto-applied patch (see ARCHITECTURE, "Provider containment and
repair").
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from .contracts import ExtractionEngine
from .errors import UnknownProviderError
from .models import AccessState, ArticleAssessment, RawFetch
from .providers.base import (
    Provider,
    ProviderNativeExtraction,
    ProviderNativeExtractionState,
)
from .providers.registry import ProviderRegistry


@runtime_checkable
class ArchiveSnapshots(Protocol):
    """The read-only slice of the archive that drift detection depends on."""

    def current_raw_snapshots(
        self, *, provider: str | None = None
    ) -> list[tuple[str, str, RawFetch, ArticleAssessment]]: ...


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class FixtureExpectation(_Frozen):
    """A versioned expectation for one provider fixture."""

    name: str
    requested_url: str
    expected_state: AccessState
    expected_signals: frozenset[str] = frozenset()


class DriftFinding(_Frozen):
    """One normalized difference. Carries no page or body text."""

    scope: str
    kind: str
    expected: str
    actual: str

    def public_dict(self) -> dict[str, str]:
        return {
            "scope": self.scope,
            "kind": self.kind,
            "expected": self.expected,
            "actual": self.actual,
        }


class DriftReport(_Frozen):
    source: str
    checked: int
    findings: tuple[DriftFinding, ...] = ()
    #: Archived providers not in the current registry (e.g. saved under an
    #: opt-in that is now off). They are reported, never silently dropped, and
    #: never abort the rest of the sweep.
    skipped_providers: tuple[str, ...] = ()

    @property
    def is_clean(self) -> bool:
        return not self.findings

    def public_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "checked": self.checked,
            "is_clean": self.is_clean,
            "findings": [finding.public_dict() for finding in self.findings],
            "skipped_providers": list(self.skipped_providers),
        }


def _synthetic_fetch(raw_html: bytes, requested_url: str) -> RawFetch:
    return RawFetch.model_validate(
        {
            "requested_url": requested_url,
            "final_url": requested_url,
            "http_status": 200,
            "content_type": "text/html",
            "retrieved_at": datetime.now(UTC),
            "session_cookie_present": False,
            "raw_html": raw_html,
        }
    )


def _compare(
    scope: str,
    expected_state: AccessState,
    expected_signals: frozenset[str],
    actual: ArticleAssessment,
) -> list[DriftFinding]:
    findings: list[DriftFinding] = []
    if actual.access_state is not expected_state:
        findings.append(
            DriftFinding(
                scope=scope,
                kind="access_state",
                expected=expected_state.value,
                actual=actual.access_state.value,
            )
        )
    actual_signals = frozenset(actual.structural_signals)
    if actual_signals != expected_signals:
        findings.append(
            DriftFinding(
                scope=scope,
                kind="structural_signals",
                expected=",".join(sorted(expected_signals)),
                actual=",".join(sorted(actual_signals)),
            )
        )
    return findings


def detect_fixture_drift(
    provider: Provider,
    extractor: ExtractionEngine,
    cases: Sequence[tuple[bytes, FixtureExpectation]],
) -> DriftReport:
    """Assess each fixture and report where it diverges from its expectation."""

    findings: list[DriftFinding] = []
    for raw_html, expectation in cases:
        fetch = _synthetic_fetch(raw_html, expectation.requested_url)
        extraction = extractor.extract(fetch, scope_xpath=provider.extraction_scope)
        assessment = provider.assess(expectation.requested_url, fetch, extraction)
        findings.extend(
            _compare(
                expectation.name,
                expectation.expected_state,
                expectation.expected_signals,
                assessment,
            )
        )
    return DriftReport(
        source=f"fixtures:{provider.key}",
        checked=len(cases),
        findings=tuple(findings),
    )


def detect_archive_drift(
    archive: ArchiveSnapshots,
    registry: ProviderRegistry,
    extractor: ExtractionEngine,
    *,
    provider: str | None = None,
) -> DriftReport:
    """Re-assess archived raw fetches with ``extractor`` and report where the
    fresh assessment diverges from the one stored at save time.

    The candidate extractor is exercised against archived bytes only; the current
    extraction pointer is never moved here (that stays an explicit ``reextract``
    decision), so this is safe to run against a live archive.
    """

    snapshots = archive.current_raw_snapshots(provider=provider)
    findings: list[DriftFinding] = []
    skipped: list[str] = []
    checked = 0
    for article_id, provider_key, fetch, stored in snapshots:
        try:
            candidate_provider = registry.get(provider_key)
        except UnknownProviderError:
            if provider_key not in skipped:
                skipped.append(provider_key)
            continue
        checked += 1
        extraction = extractor.extract(
            fetch, scope_xpath=candidate_provider.extraction_scope
        )
        fresh = candidate_provider.assess(str(fetch.requested_url), fetch, extraction)
        if isinstance(candidate_provider, ProviderNativeExtraction):
            native = candidate_provider.native_extraction(
                str(fetch.requested_url),
                fetch,
            )
            if (
                native.state is ProviderNativeExtractionState.VALID
                and native.assessment is not None
                and fresh.access_state
                not in {AccessState.AUTH_REQUIRED, AccessState.BLOCKED}
            ):
                fresh = native.assessment
            elif (
                native.state is ProviderNativeExtractionState.INVALID
                and fresh.access_state
                not in {AccessState.AUTH_REQUIRED, AccessState.BLOCKED}
            ):
                fresh = fresh.model_copy(
                    update={
                        "access_state": AccessState.UNKNOWN,
                        "negative_markers": tuple(
                            dict.fromkeys(
                                (*fresh.negative_markers, "embedded_story_invalid")
                            )
                        ),
                        "reason": "insufficient_article_structure",
                    }
                )
        findings.extend(
            _compare(
                article_id,
                stored.access_state,
                frozenset(stored.structural_signals),
                fresh,
            )
        )
        findings.extend(_compare_archive_body(article_id, stored, fresh))
    return DriftReport(
        source="archive",
        checked=checked,
        findings=tuple(findings),
        skipped_providers=tuple(skipped),
    )


def _compare_archive_body(
    scope: str,
    stored: ArticleAssessment,
    fresh: ArticleAssessment,
) -> list[DriftFinding]:
    """Catch identity or body drift that keeps the broad assessment shape."""

    findings: list[DriftFinding] = []
    if fresh.provider_article_id != stored.provider_article_id:
        findings.append(
            DriftFinding(
                scope=scope,
                kind="provider_article_id",
                expected="stored",
                actual="changed",
            )
        )
    if fresh.canonical_url != stored.canonical_url:
        findings.append(
            DriftFinding(
                scope=scope,
                kind="canonical_url",
                expected="stored",
                actual="changed",
            )
        )
    if fresh.identity_match is not stored.identity_match:
        findings.append(
            DriftFinding(
                scope=scope,
                kind="identity_match",
                expected=str(stored.identity_match).lower(),
                actual=str(fresh.identity_match).lower(),
            )
        )
    if stored.word_count and fresh.word_count < stored.word_count / 2:
        findings.append(
            DriftFinding(
                scope=scope,
                kind="word_count_collapse",
                expected=str(stored.word_count),
                actual=str(fresh.word_count),
            )
        )
    return findings


__all__ = [
    "ArchiveSnapshots",
    "DriftFinding",
    "DriftReport",
    "FixtureExpectation",
    "detect_archive_drift",
    "detect_fixture_drift",
]
