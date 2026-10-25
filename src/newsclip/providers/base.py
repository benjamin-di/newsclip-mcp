"""Provider protocol and explicit registry."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from ..contracts import HttpClient, LoginRecipe
from ..models import (
    ArticleAssessment,
    ExtractedArticle,
    ProviderCapabilities,
    ProviderSearchPage,
    RateBudget,
    RawFetch,
    SearchFilters,
    SearchResult,
    SessionArtifact,
)
from ..provider_config import ProviderCheckSpec


@dataclass(frozen=True)
class BrowserSnapshotCompletenessResult:
    """Provider-owned completion verdict plus optional normalized coverage."""

    complete: bool
    coverage: float | None = None

    def __post_init__(self) -> None:
        if self.coverage is not None and (
            not math.isfinite(self.coverage) or not 0 <= self.coverage <= 1
        ):
            raise ValueError("browser snapshot coverage must be between zero and one")


class ProviderNativeExtractionState(StrEnum):
    """Closed availability state for an optional provider-native extraction."""

    ABSENT = "absent"
    INVALID = "invalid"
    VALID = "valid"


@dataclass(frozen=True)
class ProviderNativeExtractionResult:
    """Provider-owned extraction and assessment from embedded article data."""

    state: ProviderNativeExtractionState
    reason: str
    extraction: ExtractedArticle | None = None
    assessment: ArticleAssessment | None = None
    extractor_name: str | None = None
    extractor_version: str | None = None

    def __post_init__(self) -> None:
        candidate_fields = (
            self.extraction,
            self.assessment,
            self.extractor_name,
            self.extractor_version,
        )
        valid = self.state is ProviderNativeExtractionState.VALID
        if valid != all(value is not None for value in candidate_fields):
            raise ValueError("native extraction state and candidate are inconsistent")
        if not valid and any(value is not None for value in candidate_fields):
            raise ValueError("unavailable native extraction cannot carry a candidate")


@runtime_checkable
class Provider(Protocol):
    key: str
    capabilities: ProviderCapabilities
    check: ProviderCheckSpec
    assessment_policy_version: str
    # Bounds body extraction to a provider-declared subtree; ``None`` keeps the
    # engine's full-document behavior. Sits beside assessment_policy_version
    # because both are extraction-time policy the provider owns.
    extraction_scope: tuple[str, ...] | None

    @property
    def login_recipe(self) -> LoginRecipe | None: ...

    def owns_url(self, url: str) -> bool: ...

    def is_interactive_challenge(self, fetch: RawFetch) -> bool: ...

    def search(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
    ) -> list[SearchResult]: ...

    def search_page(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
        *,
        next_url: str | None = None,
        metadata_fetch_budget: int | None = None,
    ) -> ProviderSearchPage: ...

    def fetch(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        url: str,
    ) -> RawFetch: ...

    def assess(
        self,
        requested_url: str,
        fetch: RawFetch,
        extraction: ExtractedArticle,
    ) -> ArticleAssessment: ...

    def rate_budget(self) -> RateBudget: ...


@runtime_checkable
class BrowserSnapshotCompleteness(Protocol):
    """Optional provider-owned completion oracle for rendered browser pages."""

    def browser_snapshot_complete(
        self,
        fetch: RawFetch,
        extraction: ExtractedArticle,
        assessment: ArticleAssessment,
    ) -> BrowserSnapshotCompletenessResult: ...


@runtime_checkable
class BrowserPaidProofCompleteness(Protocol):
    """Optional verification readiness when story delivery cannot prove access."""

    def browser_paid_proof_complete(
        self,
        fetch: RawFetch,
        extraction: ExtractedArticle,
        assessment: ArticleAssessment,
    ) -> BrowserSnapshotCompletenessResult: ...


@runtime_checkable
class ProviderNativeExtraction(Protocol):
    """Optional provider-owned extraction from embedded structured article data."""

    def native_extraction(
        self,
        requested_url: str,
        fetch: RawFetch,
    ) -> ProviderNativeExtractionResult: ...
