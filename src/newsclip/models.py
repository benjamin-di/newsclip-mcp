"""Typed product contracts and explicit public serializers."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, get_args
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)
from signin_window.automation.auth import AuthOutcome as _AuthOutcome

from .account_keys import ACCOUNT_KEY_PATTERN

MintOutcome = _AuthOutcome


class FrozenModel(BaseModel):
    """Immutable value object with strict validation."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class AccessState(StrEnum):
    FULL = "full"
    TEASER = "teaser"
    AUTH_REQUIRED = "auth_required"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class TerminalFailure(StrEnum):
    CREDENTIAL_REJECTED = "credential_rejected"
    SECOND_FACTOR_REQUIRED = "second_factor_required"
    ACCOUNT_ALERT = "account_alert"
    CHALLENGE_BLOCKED = "challenge_blocked"
    UNKNOWN_FLOW = "unknown_flow"
    INFRASTRUCTURE_ERROR = "infrastructure_error"


class SessionStatus(StrEnum):
    VERIFIED = "verified"
    REQUIRED = "required"
    COOLDOWN = "cooldown"
    OPERATOR_ACTION = "operator_action"


class SessionHealthState(StrEnum):
    """Derived session freshness: fresh (verified within the renewal policy
    age), stale (verified but overdue for renewal) or degraded (not
    currently provable as healthy)."""

    # This docstring is the schema description every MCP client loads with
    # session_status, so it stays short. Why a derived state: raw ``verified``
    # proved deceptive, reporting the last positive verification while every
    # scheduled renewal failed; this state folds renewal reality in.

    FRESH = "fresh"
    STALE = "stale"
    DEGRADED = "degraded"


class SearchSort(StrEnum):
    """Presentation order for one bounded search result batch."""

    BALANCED = "balanced"
    NEWEST = "newest"


#: The typed allowlist of HTTP impersonation profiles. This is the safety
#: boundary the runtime pin (ARCHITECTURE, "Transport pins") selects within:
#: automation may promote among measured names, never invent one.
#:
#: Every name is a versioned curl_cffi target. The bare ``"chrome"`` alias is
#: deliberately absent: it means whatever the installed curl_cffi considers
#: current. Explicit names make provider behavior reproducible across upgrades.
HttpImpersonation = Literal[
    "safari", "chrome131_android", "chrome146", "chrome150", "safari2601"
]

#: The same allowlist as a value, so the runtime pin resolver validates
#: against one source of truth rather than a second hand-kept list.
HTTP_IMPERSONATION_PROFILES: frozenset[str] = frozenset(get_args(HttpImpersonation))

#: The profile every session route and every undeclared host presents.
#: Session routes cannot be re-pinned at runtime (their TLS must stay a
#: browser the stored artifact could have come from), so this name is the
#: only fingerprint FT's reads, renewals and canaries use. Move it to the
#: newest desktop Chrome target when curl_cffi is upgraded; a test enforces
#: that, and health's ``http_challenges`` shows when it starts to age.
DEFAULT_HTTP_IMPERSONATION: HttpImpersonation = "chrome150"


class ProviderCapabilities(FrozenModel):
    requires_session_for_retrieve: bool = True
    requires_session_for_search: bool = False
    # Durable authority and retrieval transport are independent. Bloomberg can
    # carry a portable cookie artifact while retrieving through a browser.
    session_kind: Literal["none", "cookie"] = "cookie"
    # "http": retrieve the caller's URL with the shared curl_cffi client.
    # "browser": retrieve through the shared core browser plane (a
    # profile-bound browser that synthesizes a RawFetch). Assess/archive stay
    # transport-agnostic either way (see ARCHITECTURE, "Retrieval and
    # assessment").
    retrieval_transport: Literal["http", "browser"] = "http"
    search_transport: Literal["http", "browser"] = "http"
    # A public provider may need a declared TLS/browser fingerprint while
    # remaining anonymous. Challenges still fail closed; this changes only
    # the ordinary HTTP handshake.
    #
    # An allowlist, not a passthrough to curl_cffi's 53 profiles: a pinned
    # fingerprint is a measurement of an adaptive edge and decays, so every
    # entry here is one somebody characterized against a live provider.
    # `chrome131_android` (refused 2026-07-28) and `chrome146` (refused
    # 2026-08-01) stay listed as names a definition may still carry, but
    # neither should be pinned again without fresh evidence. `safari2601`
    # was measured full 5/5 plus a second-article confirmation on 2026-08-01.
    http_impersonate: HttpImpersonation = DEFAULT_HTTP_IMPERSONATION
    # When an HTTP fetch is classified as the provider's interactive
    # challenge, escalate that one retrieval to a single bounded browser
    # fetch through the existing retrieval plane (ARCHITECTURE, "Transport
    # pins"). Declared per provider and off by default: the browser fallback is
    # an expensive measured answer to a measured refusal, not a default. The
    # same declaration shape as the Economist search escalation, which is
    # keyed off its approved challenge vendors instead.
    retrieval_challenge_escalation: Literal["none", "browser"] = "none"


class RateBudget(FrozenModel):
    requests_per_second: float = Field(gt=0, allow_inf_nan=False)
    burst: int = Field(ge=1)
    rate_limit_fallback_seconds: float = Field(
        default=0,
        ge=0,
        le=3600,
        allow_inf_nan=False,
    )


class SearchFilters(FrozenModel):
    limit: int = Field(default=20, ge=1, le=100)
    published_after: AwareDatetime | None = None
    published_before: AwareDatetime | None = None
    sort: SearchSort = SearchSort.BALANCED

    @model_validator(mode="after")
    def validate_date_order(self) -> SearchFilters:
        if (
            self.published_after is not None
            and self.published_before is not None
            and self.published_after > self.published_before
        ):
            raise ValueError("published_after must not exceed published_before")
        return self

    def includes_published(self, published: datetime | None) -> bool:
        """Return whether a known result date satisfies the requested bounds."""

        if self.published_after is None and self.published_before is None:
            return True
        if published is None:
            return False
        return not (
            (self.published_after is not None and published < self.published_after)
            or (self.published_before is not None and published > self.published_before)
        )

    def excludes_undated(self, published: datetime | None) -> bool:
        """Return whether a date bound drops this result only for lacking a date.

        Such a result might satisfy the bounds; it cannot be shown to. Sources
        count these so an empty or short answer is not read as exhaustive.
        """

        return published is None and (
            self.published_after is not None or self.published_before is not None
        )


class CaptureFailure(FrozenModel):
    """Closed facts about evidence collection, separate from provider failure."""

    stage: Literal[
        "response",
        "document_identity",
        "content_read",
        "capture_validation",
        "persistence",
    ]
    reason: Literal["unavailable", "changed", "failed", "too_large", "not_configured"]


class RetrievalDiagnostics(FrozenModel):
    """Private, bounded browser evidence carried to deferred assessment."""

    screenshot_status: Literal[
        "captured", "capture_failed", "too_large", "not_requested"
    ]
    screenshot: bytes | None = Field(
        default=None, repr=False, exclude=True, max_length=4 * 1024 * 1024
    )
    trace: bytes | None = Field(
        default=None, repr=False, exclude=True, max_length=1024 * 1024
    )


class RawFetch(FrozenModel):
    requested_url: HttpUrl
    final_url: HttpUrl
    http_status: int = Field(ge=100, le=599)
    content_type: str | None = None
    retry_after: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    retrieved_at: AwareDatetime
    session_cookie_present: bool = False
    # Which transport actually served these bytes: an impersonation profile
    # name, or "browser". Until R8 the pin was release-static, so the profile
    # was recoverable from the definition's git history plus retrieved_at. A
    # runtime pin and a per-fetch browser escalation both break that
    # inference, so the fact is recorded on the fetch itself and folded into
    # the archive's evidence hash. None means a fetch stored before this was
    # recorded, or a transport that does not declare one.
    serving_transport: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]*$",
    )
    raw_html: bytes
    diagnostics: RetrievalDiagnostics | None = Field(
        default=None, repr=False, exclude=True
    )


class ExtractedArticle(FrozenModel):
    body_markdown: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    word_count: int = Field(ge=0)


class ArticleAssessment(FrozenModel):
    access_state: AccessState
    provider_article_id: str | None = None
    canonical_url: HttpUrl | None = None
    identity_match: bool = False
    negative_markers: tuple[str, ...] = ()
    structural_signals: tuple[str, ...] = ()
    word_count: int = Field(ge=0)
    session_cookie_present: bool = False
    reason: str

    @property
    def promotable(self) -> bool:
        return self.access_state is AccessState.FULL and self.identity_match


class TransportProbeResult(FrozenModel):
    """Closed result from evaluating one injected retrieval transport."""

    provider: str = Field(min_length=1)
    http_status: int = Field(ge=100, le=599)
    access_state: AccessState
    word_count: int = Field(ge=0)
    identity_match: bool
    session_cookie_present: bool
    reason: str

    @property
    def promotable(self) -> bool:
        return self.access_state is AccessState.FULL and self.identity_match


class ExtractionMeta(FrozenModel):
    extractor_name: str
    extractor_version: str
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assessment_schema_version: int = Field(ge=1)
    policy_version: str


class Article(FrozenModel):
    id: str
    provider_article_id: str
    url: HttpUrl
    canonical_url: HttpUrl
    provider: str
    headline: str
    authors: tuple[str, ...] = ()
    published: AwareDatetime | None = None
    section: str | None = None
    word_count: int = Field(ge=0)
    body_markdown: str
    retrieved_at: AwareDatetime
    extraction: ExtractionMeta

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class SearchResult(FrozenModel):
    provider: str
    url: HttpUrl
    headline: str
    snippet: str | None = None
    published: AwareDatetime | None = None

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ConnectionInfo(FrozenModel):
    """A human Connections link; permanent owner pages have no expiry."""

    url: HttpUrl
    expires_at: AwareDatetime | None = None
    provider: str

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ArchiveSearchHit(FrozenModel):
    """Bounded archive discovery metadata without the full article body."""

    id: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    url: HttpUrl
    headline: str = Field(min_length=1)
    published: AwareDatetime | None = None
    section: str | None = None
    word_count: int = Field(ge=0)
    retrieved_at: AwareDatetime

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ProviderSearchPage(FrozenModel):
    """One provider-ranked search page plus its validated continuation URL."""

    results: tuple[SearchResult, ...]
    next_url: str | None = None
    remaining_metadata_fetches: int = Field(default=0, ge=0, le=10)
    # The oldest instant this page could have matched, for a provider whose
    # searchable surface is a moving window rather than an archive. ``None``
    # means the provider makes no coverage claim.
    coverage_start: AwareDatetime | None = None
    # Results a date bound dropped only because their date was unknown.
    undated_excluded_count: int = Field(default=0, ge=0)


class SourceSearchState(StrEnum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    NEEDS_ATTENTION = "needs_attention"


class SourceSearchReason(StrEnum):
    SESSION_REQUIRED = "session_required"
    OPERATOR_ACTION = "operator_action"
    TIMEOUT = "timeout"
    DNS = "dns"
    CONTRACT = "contract"
    PERSISTENCE = "persistence"
    TRANSPORT = "transport"
    # Distinct from TRANSPORT: the route reached the provider and the provider
    # answered. RATE_LIMITED means it asked for less traffic; PROVIDER_ERROR
    # means it refused or failed. Reporting either as TRANSPORT sends an
    # operator hunting a network fault that does not exist.
    RATE_LIMITED = "rate_limited"
    PROVIDER_ERROR = "provider_error"
    # Distinct from CONTRACT: the provider is healthy and its page contract
    # intact; this query simply carried nothing it could rank against. Reporting
    # it as a contract failure would send an operator hunting for parser drift.
    UNSEARCHABLE_QUERY = "unsearchable_query"


class SourceSearchReport(FrozenModel):
    provider: str = Field(min_length=1)
    state: SourceSearchState
    result_count: int = Field(ge=0)
    missing_published_count: int = Field(default=0, ge=0)
    # Distinct from missing_published_count, which counts undated results that
    # were returned: under a date bound an undated result cannot be shown to
    # match, so it is withheld and counted here instead of vanishing silently.
    undated_excluded_count: int = Field(default=0, ge=0)
    reason: SourceSearchReason | None = None
    # Silent coverage truncation reads as exhaustive coverage. A provider whose
    # only searchable surface is a moving window sets this to the oldest instant
    # the window reached, so "1 result" can be read as "one hit in the last ten
    # hours" rather than "this provider has almost nothing". Providers that
    # search an archive leave it unset and make no claim.
    coverage_start: AwareDatetime | None = None
    # Search and retrieval fail independently: an anonymous sitemap surface
    # keeps answering right through a defense episode that refuses every
    # article fetch. Reporting only the search leg let a contained provider
    # list results under a bare tick that no selection could open. Carries the
    # containment expiry while a cooldown is armed, so the offer and the thing
    # being offered agree.
    retrieval_contained_until: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_state(self) -> SourceSearchReport:
        if self.state is SourceSearchState.OK:
            if self.reason is not None:
                raise ValueError("successful source report cannot contain a reason")
            if self.missing_published_count > self.result_count:
                raise ValueError("missing publication count cannot exceed results")
            return self
        if self.coverage_start is not None:
            raise ValueError("failed source report cannot claim search coverage")
        if (
            self.result_count != 0
            or self.missing_published_count != 0
            or self.undated_excluded_count != 0
            or self.reason is None
        ):
            raise ValueError(
                "failed source report requires a reason and zero result counts"
            )
        needs_attention = self.reason in {
            SourceSearchReason.SESSION_REQUIRED,
            SourceSearchReason.OPERATOR_ACTION,
        }
        if needs_attention != (self.state is SourceSearchState.NEEDS_ATTENTION):
            raise ValueError("source state does not match its failure reason")
        return self

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class SearchResponse(FrozenModel):
    query: str = Field(min_length=1)
    results: tuple[SearchResult, ...]
    sources: tuple[SourceSearchReport, ...]
    has_more: bool = False

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class LoginRequirement(StrEnum):
    CREDENTIAL_READER = "credential_reader"
    MAIL_GATEWAY = "mail_gateway"
    OP_CLI = "op_cli"
    OP_SERVICE_TOKEN = "op_service_token"
    VISION_CLI = "vision_cli"
    VISION_AUTH = "vision_auth"
    #: The XTEST client library, without which no real X11 input event can be
    #: synthesized. A provider fronted by defenses that reject debug-protocol
    #: input cannot be minted on such a host, and the symptom is otherwise
    #: silent: the click simply never registers and the flow times out waiting
    #: for a page transition it will never see.
    NATIVE_INPUT = "native_input"


class ProviderReadiness(FrozenModel):
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    missing: tuple[LoginRequirement, ...] = ()

    @property
    def ready(self) -> bool:
        return not self.missing

    def public_dict(self) -> dict[str, Any]:
        value = self.model_dump(mode="json")
        value["ready"] = self.ready
        return value


class DoctorReport(FrozenModel):
    providers: tuple[str, ...]
    browser_providers: tuple[str, ...]
    provider_readiness: tuple[ProviderReadiness, ...] = ()
    virtual_display_active: bool
    host_xvfb_available: bool
    docker_fallback_available: bool
    browser_engine_available: bool = False

    @property
    def browser_ready(self) -> bool:
        return self.browser_engine_available and (
            self.virtual_display_active
            or self.host_xvfb_available
            or self.docker_fallback_available
        )

    def public_dict(self) -> dict[str, Any]:
        value = self.model_dump(mode="json")
        value["provider_readiness"] = [
            readiness.public_dict() for readiness in self.provider_readiness
        ]
        value["browser_ready"] = self.browser_ready
        return value


SameSite = Literal["Strict", "Lax", "None"]


class PortableCookie(FrozenModel):
    name: str = Field(min_length=1)
    value: str
    domain: str = Field(min_length=1)
    path: str = "/"
    expires: float | None = None
    secure: bool = False
    http_only: bool = False
    same_site: SameSite | None = None

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, value: str) -> str:
        value = value.strip().lower()
        if not value or any(char.isspace() for char in value):
            raise ValueError("cookie domain must be a non-empty hostname")
        return value

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("cookie path must start with /")
        return value


class SessionArtifact(FrozenModel):
    schema_version: Literal[1, 2] = 1
    generation_id: UUID
    provider: str = Field(min_length=1)
    account_key: str = Field(default="default", pattern=ACCOUNT_KEY_PATTERN)
    created_at: AwareDatetime
    verified_at: AwareDatetime
    user_agent: str | None = Field(default=None, min_length=1, max_length=512)
    cookies: tuple[PortableCookie, ...] = Field(min_length=1)
    # Private, host-local locator. Imports never trust a supplied locator.
    browser_profile_id: UUID | None = None

    @model_validator(mode="after")
    def validate_profile_version(self) -> SessionArtifact:
        if (self.schema_version == 2) != (self.browser_profile_id is not None):
            raise ValueError("profile-bound sessions require schema version 2")
        return self

    @field_validator("user_agent")
    @classmethod
    def validate_user_agent(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized or any(
            ord(character) < 32 or ord(character) == 127 for character in normalized
        ):
            raise ValueError("session user agent must be a single line")
        return normalized

    def assert_identity(self, provider: str, account_key: str = "default") -> None:
        if self.provider != provider or self.account_key != account_key:
            raise ValueError("session artifact provider/account mismatch")


class StoredSession(FrozenModel):
    schema_version: Literal[1] = 1
    artifact: SessionArtifact | None = None
    status: SessionStatus = SessionStatus.REQUIRED
    last_failure: TerminalFailure | None = None
    failure_reason_code: str | None = Field(
        default=None, pattern=r"^[a-z]+(?:_[a-z]+)+$"
    )
    retry_not_before: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_status(self) -> StoredSession:
        if self.status is SessionStatus.VERIFIED and self.artifact is None:
            raise ValueError("verified stored session requires an artifact")
        if self.status is SessionStatus.COOLDOWN and self.retry_not_before is None:
            raise ValueError("cooldown requires retry_not_before")
        return self


class RecoveryStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class RecoveryAttempt(FrozenModel):
    """Bounded dispatch history; no article text, URLs or credential details."""

    request_id: str = Field(pattern=r"^recovery-[a-f0-9]{32}$")
    diagnostic_id: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$"
    )
    started_at: AwareDatetime
    completed_at: AwareDatetime | None = None
    reason: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    article_verified: bool = False


class RecoveryHealth(FrozenModel):
    request_id: str = Field(pattern=r"^recovery-[a-f0-9]{32}$")
    status: RecoveryStatus
    requested_at: AwareDatetime
    next_attempt_at: AwareDatetime | None = None
    attempts: int = Field(ge=0, le=3)
    # `attempts` retains its v1 meaning: provider-wide window usage. Unknown
    # legacy episode counts stay unknown rather than being guessed from it.
    episode_attempts: int | None = Field(default=None, ge=0)
    budget_reset_at: AwareDatetime | None = None
    incident_id: str | None = Field(default=None, pattern=r"^incident-[a-f0-9]{24}$")
    recent_attempts: tuple[RecoveryAttempt, ...] = Field(default=(), max_length=6)
    reason: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    diagnostic_id: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$"
    )
    session_verified: bool = False
    article_verified: bool = False


class SessionHealth(FrozenModel):
    provider: str
    account_key: str = Field(default="default", pattern=ACCOUNT_KEY_PATTERN)
    status: SessionStatus
    last_verified_at: AwareDatetime | None = None
    retry_not_before: AwareDatetime | None = None
    last_failure: TerminalFailure | None = None
    failure_reason_code: str | None = Field(
        default=None, pattern=r"^[a-z]+(?:_[a-z]+)+$"
    )
    # Derived freshness (additive; populated by the service layer from the
    # keeper's persisted outcomes). None when derivation has not run — the
    # raw store never writes these.
    verified_age_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    consecutive_renewal_failures: int | None = Field(default=None, ge=0)
    last_renewal_error: str | None = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$"
    )
    renewal_incident_id: str | None = Field(
        default=None, pattern=r"^incident-[0-9a-f]{24}$"
    )
    renewal_diagnostic_id: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$"
    )
    health: SessionHealthState | None = None
    recovery: RecoveryHealth | None = None

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            exclude={
                field
                for field in (
                    "recovery",
                    "renewal_incident_id",
                    "renewal_diagnostic_id",
                )
                if getattr(self, field) is None
            },
        )


class SessionCheckpoint(FrozenModel):
    provider: str
    account_key: str = Field(default="default", pattern=ACCOUNT_KEY_PATTERN)
    status: Literal[SessionStatus.VERIFIED] = SessionStatus.VERIFIED
    generation_fingerprint: str = Field(pattern=r"^[0-9a-f]{12}$")
    created_at: AwareDatetime
    verified_at: AwareDatetime
    checked_at: AwareDatetime
    session_age_seconds: float = Field(ge=0)

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


INCIDENT_ID_PATTERN = r"^incident-[0-9a-f]{24}$"
"""Shape of a retained private incident capsule identifier."""


class SessionDisposition(StrEnum):
    """What a verification response proves about existing session authority."""

    VERIFIED = "verified"
    DEAD = "session_dead"
    NOT_ENTITLED = "not_entitled"
    INCONCLUSIVE = "inconclusive"


class SessionVerification(FrozenModel):
    verified: bool
    access_state: AccessState
    reason: str
    verified_at: AwareDatetime

    @property
    def disposition(self) -> SessionDisposition:
        """Classify only direct authentication evidence as a dead session."""

        if self.verified and self.access_state is AccessState.FULL:
            return SessionDisposition.VERIFIED
        if self.access_state is AccessState.AUTH_REQUIRED:
            return SessionDisposition.DEAD
        return SessionDisposition.INCONCLUSIVE


class ArchiveIntegrityStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"


class ArchiveIntegrity(FrozenModel):
    """Closed public result for archive verification and maintenance."""

    ok: bool
    integrity: ArchiveIntegrityStatus
    foreign_key_violations: int = Field(ge=0)
    user_version: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_status(self) -> ArchiveIntegrity:
        expected = (
            ArchiveIntegrityStatus.OK if self.ok else ArchiveIntegrityStatus.FAILED
        )
        if self.integrity is not expected:
            raise ValueError("archive integrity status does not match result")
        if self.ok and self.foreign_key_violations:
            raise ValueError("successful archive integrity cannot have violations")
        return self

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ArchiveBackupResult(FrozenModel):
    """Path-free acknowledgement for an explicitly requested backup."""

    ok: Literal[True] = True

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
