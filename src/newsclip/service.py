"""Synchronous provider-neutral use-case orchestration."""

from __future__ import annotations

import hashlib
import time
from collections import deque
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor, wait
from contextlib import AbstractContextManager, contextmanager, nullcontext
from contextvars import copy_context
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Literal, NoReturn, cast
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from curl_cffi.requests import BrowserTypeLiteral

if TYPE_CHECKING:
    from .subscription_routing import SubscriptionRouting

from .acquisition import (
    ChallengeMode,
    LoginResult,
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
    session_wide_verdict,
    verification_verdict,
)
from .articles import build_article
from .browser_readiness import BrowserSemanticSnapshot
from .browser_retrieval import (
    BrowserSnapshotRejected,
    SingleNavigationBrowserClient,
    SingleNavigationBrowserRetriever,
)
from .browser_runtime.events import HttpOperationRole
from .challenge_transport import ChallengeAwareHttpClient
from .contracts import (
    Archive,
    BrowserRetriever,
    ExtractionEngine,
    HttpClient,
    HttpClientScopeFactory,
    SessionManager,
    SessionSource,
)
from .defense import DefenseGateDecision, DefenseState
from .drift import DriftReport, detect_archive_drift
from .errors import (
    NOT_ENTITLED_REASON,
    AccountAlertError,
    BrowserAuthorityChangedError,
    ContentNotFullError,
    NewsclipError,
    OperatorActionRequiredError,
    PersistenceError,
    ProviderContractError,
    ProviderDefenseError,
    ProviderTransportError,
    SessionRequiredError,
    TransportFailure,
    UnsearchableQueryError,
    UsageError,
    retryable_read_reason,
)
from .http import CurlCffiHttpClient
from .incidents import (
    IncidentEvidenceHealth,
    IncidentPersistenceError,
    IncidentStore,
    SearchFailureKind,
)
from .keeper_outcomes import KeeperOutcomeStore, enrich_session_health
from .models import (
    HTTP_IMPERSONATION_PROFILES,
    AccessState,
    ArchiveBackupResult,
    ArchiveIntegrity,
    Article,
    ArticleAssessment,
    CaptureFailure,
    ExtractedArticle,
    ProviderSearchPage,
    RawFetch,
    RecoveryStatus,
    SearchFilters,
    SearchResponse,
    SearchResult,
    SearchSort,
    SessionArtifact,
    SessionCheckpoint,
    SessionDisposition,
    SessionHealth,
    SessionHealthState,
    SessionStatus,
    SourceSearchReason,
    SourceSearchReport,
    SourceSearchState,
    TransportProbeResult,
)
from .network import ProviderNetworkPolicy
from .provider_check import ProviderCheckFailure, ProviderCheckResult
from .providers.base import (
    Provider,
    ProviderNativeExtraction,
    ProviderNativeExtractionResult,
    ProviderNativeExtractionState,
)
from .providers.registry import ProviderRegistry
from .recovery import RecoveryStore
from .renewal_observation import current_revision, observe_renewal
from .session_proofs import SessionProofMemory
from .timing import (
    ContentAssessmentEvidence,
    IncidentEvidence,
    RecoveryHandoffEvidence,
    SessionProbeOutcome,
    TimingOperation,
    TimingOperationContext,
    TimingRecorder,
    TimingStep,
    TimingTransport,
    clear_timing_content_assessment,
    content_assessment_evidence,
    current_timing_incident,
    current_timing_invocation_id,
    current_timing_operation,
    current_timing_session_probe,
    set_timing_acquisition_mode,
    set_timing_content_assessment,
    set_timing_failure,
    set_timing_incident,
    set_timing_recovery,
    set_timing_session_probe,
    timing_step,
)

SessionAcquirer = Callable[[str], None]
_SEARCH_FAILURES = (
    SessionRequiredError,
    OperatorActionRequiredError,
    ProviderDefenseError,
    ProviderTransportError,
    PersistenceError,
)


class _ObservedHttpClient:
    """Passively retain the last completed search response for incident capture."""

    def __init__(self, delegate: HttpClient) -> None:
        self._delegate = delegate
        self.last_fetch: RawFetch | None = None

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        try:
            fetch = self._delegate.get(url, session=session, timeout=timeout)
        except ProviderDefenseError as error:
            self.last_fetch = error.fetch
            raise
        self.last_fetch = fetch
        return fetch


@dataclass(frozen=True)
class _SessionProbe:
    disposition: SessionDisposition | None
    recovery_eligible: bool = False


def _content_failure(
    assessment: ArticleAssessment,
    probe: _SessionProbe | None,
    incident_id: str | None,
) -> ContentNotFullError:
    """Name a non-promotable target by what its session probe proved.

    A teaser behind a session that verified paid access is an article outside
    the subscription: ``not_entitled`` rather than ``paywall_teaser``, which
    would send the operator to renew a working session. A verified probe is
    never recovery-eligible, so neither verdict can request renewal here.
    """

    reason = assessment.reason
    if (
        assessment.access_state is AccessState.TEASER
        and probe is not None
        and probe.disposition is SessionDisposition.VERIFIED
    ):
        reason = NOT_ENTITLED_REASON
    failure = ContentNotFullError(reason, incident_id=incident_id)
    failure.recovery_eligible = probe is not None and probe.recovery_eligible
    return failure


@dataclass(frozen=True)
class _RetrievalEvaluation:
    fetch: RawFetch
    extraction: ExtractedArticle
    assessment: ArticleAssessment
    extractor_name: str
    extractor_version: str
    session_probe_performed: bool = False
    session_probe: _SessionProbe | None = None


@dataclass(frozen=True)
class _DefenseObservation:
    """What arming the record after an observed challenge produced."""

    retry_after_seconds: float
    #: True when this arm opened the episode, so a caller holding evidence
    #: knows this refusal is the informative one and the repeats after it
    #: are not.
    first_of_episode: bool


def _default_candidate_client(profile: str) -> AbstractContextManager[HttpClient]:
    """One short-lived client speaking exactly the candidate fingerprint."""

    return CurlCffiHttpClient(impersonate=cast(BrowserTypeLiteral, profile))


class NewsclipService:
    def __init__(
        self,
        registry: ProviderRegistry,
        http: HttpClient,
        extractor: ExtractionEngine,
        sessions: SessionSource | None = None,
        archive: Archive | None = None,
        browser_retriever: BrowserRetriever | None = None,
        network: ProviderNetworkPolicy | None = None,
        verification_client_factory: HttpClientScopeFactory | None = None,
        provider_check_verification_client_factory: (
            HttpClientScopeFactory | None
        ) = None,
        timing: TimingRecorder | None = None,
        incidents: IncidentStore | None = None,
        network_clock=None,
        network_sleep=None,
        wall_clock=None,
        keeper_outcomes: KeeperOutcomeStore | None = None,
        recovery_store: RecoveryStore | None = None,
        defense: DefenseState | None = None,
        session_evidence_target: Callable[[str], str | None] | None = None,
        on_session_verified: Callable[[str, str], None] | None = None,
        on_challenge_escalation_served: (
            Callable[[str, str | None], None] | None
        ) = None,
        transport_browser_first: Callable[[str], bool] | None = None,
        candidate_client_factory: (
            Callable[[str], AbstractContextManager[HttpClient]] | None
        ) = None,
    ) -> None:
        self._subscription_routing: SubscriptionRouting | None = None
        self._registry = registry
        self._http = http
        self._extractor = extractor
        self._sessions = sessions
        self._archive = archive
        self._browser_retriever = browser_retriever
        self._verification_client_factory = verification_client_factory
        self._provider_check_verification_client_factory = (
            provider_check_verification_client_factory
        )
        self._timing = timing
        self._incidents = incidents
        # A policy may be injected so every plane that talks to a provider —
        # retrieval, probes, and SessionStore verification — draws from the
        # same per-provider token bucket, as required by the network-policy
        # boundary.
        self._network = network or ProviderNetworkPolicy(
            http, clock=network_clock, sleep=network_sleep
        )
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._keeper_outcomes = keeper_outcomes
        self._recovery_store = recovery_store
        self._defense = defense
        # Provider -> end of the cooldown during which its search was refused
        # (see _search_paused). In-process: a restart costs one more refusal.
        self._search_refused_until: dict[str, datetime] = {}
        # Fired after every positive live session verification (mint, cookie
        # promotion, checkpoint) so session-evidence holds can clear on the
        # evidence itself (ARCHITECTURE, "Session upkeep"). Injected as a callback to
        # keep the guard's store out of this class's dependencies.
        self._on_session_verified = on_session_verified
        self._session_evidence_target = session_evidence_target
        # Fired when an HTTP challenge escalated to the browser and the
        # browser served (R8): the rot signal for a pinned fingerprint.
        # Injected as a callback to keep the pin store out of this class's
        # dependencies, mirroring on_session_verified.
        self._on_challenge_escalation_served = on_challenge_escalation_served
        # While that rot signal stands, reads skip the refused transport.
        self._transport_browser_first = transport_browser_first
        # The candidate probe opens its own short-lived client so a measured
        # fingerprint never touches the shared routes. Injectable so an
        # offline test can measure the policy without a network request.
        self._candidate_client_factory = (
            candidate_client_factory or _default_candidate_client
        )
        # Lets a teaser reuse this process's recent verified probe of the same
        # session generation instead of relaunching a browser to repeat it.
        self._session_proofs = SessionProofMemory()
        self._closed = False

    def _session_evidence_verified(
        self, provider_key: str, *, hold_id: str | None = None
    ) -> None:
        if self._keeper_outcomes is not None and not self._keeper_outcomes.verified(
            provider_key, revision=current_revision(provider_key)
        ):
            return
        if self._on_session_verified is not None and hold_id is not None:
            self._on_session_verified(provider_key, hold_id)

    def _verification_hold(self, provider_key: str) -> str | None:
        return (
            self._session_evidence_target(provider_key)
            if self._session_evidence_target is not None
            else None
        )

    # -- provider defense containment (ARCHITECTURE) ---------------------
    #
    # One state machine for every plane: retrieval and the guard canary feed
    # the same record; only a full-access success clears it. probe_transport
    # is deliberately exempt — it is the injected diagnostic seam.

    @contextmanager
    def _defense_scope(self, provider_key: str) -> Iterator[None]:
        scope = (
            self._defense.probe(provider_key)
            if self._defense is not None
            else nullcontext(DefenseGateDecision(allowed=True))
        )
        with scope as decision:
            if not decision.allowed:
                raise ProviderDefenseError(
                    f"{provider_key} defense cooldown is active",
                    provider=provider_key,
                    retry_after_seconds=decision.retry_after_seconds,
                )
            yield

    def session_recovery_scope(self, provider_key: str) -> AbstractContextManager[None]:
        """Bound a proven session-renewal remedy by the same defense controller."""
        return self._defense_scope(provider_key)

    def incident_evidence(self, incident_id: str) -> IncidentEvidenceHealth:
        if self._incidents is None:
            return IncidentEvidenceHealth(incident_id=incident_id, status="missing")
        return self._incidents.evidence_health(incident_id)

    def _attach_defense_incident(self, provider: str, incident_id: str) -> bool:
        if self._defense is not None:
            try:
                self._defense.attach_incident(provider, incident_id)
            except PersistenceError:
                set_timing_incident(
                    IncidentEvidence(incident_id=incident_id, omission="write_failed")
                )
                return False
        return True

    def defense_pending(self, provider_key: str) -> bool:
        """An unresolved retrieval episode needs a read-only canary first."""
        return (
            self._defense is not None and self._defense.status(provider_key) is not None
        )

    def _defense_observed(
        self, provider_key: str, *, origin: str
    ) -> _DefenseObservation | None:
        """Arm (or re-arm, doubled) after an observed challenge."""

        if self._defense is None:
            return None
        armed = self._defense.arm_observed(provider_key, origin=origin)
        record = armed.record
        return _DefenseObservation(
            retry_after_seconds=(record.active_until - record.armed_at).total_seconds(),
            first_of_episode=armed.first_of_episode,
        )

    def defense_contained_until(self, provider_key: str) -> datetime | None:
        """When retrieval containment expires, or None if nothing is armed.

        Read against the service's wall clock rather than the record's writer:
        an expired record is not containment, because the next caller through
        the gate proceeds as the canary and may well succeed. Only a cooldown
        that is still running would refuse a selection made right now.
        """

        if self._defense is None:
            return None
        record = self._defense.status(provider_key)
        if record is None:
            return None
        return record.active_until if record.active_until > self._wall_clock() else None

    def _search_paused(self, provider: Provider) -> None:
        """Refuse a search the provider already refused during this cooldown.

        Search normally keeps answering through a retrieval episode (invariant
        5), so it is not gated by the defense itself. But when the search leg
        is refused too (an IP-level restriction), every further search is more
        of the automated traffic the restriction cites, and nothing it learns
        is new: one refusal per cooldown is enough. The guard canary searches
        through ``provider_check``, not here, and the gate lapses with the
        cooldown or when a FULL retrieval clears it.
        """

        if self._defense is None:
            return
        until = self._search_refused_until.get(provider.key)
        if until is None:
            return
        contained = self.defense_contained_until(provider.key)
        if contained is None or until <= self._wall_clock():
            self._search_refused_until.pop(provider.key, None)
            return
        raise ProviderDefenseError(
            f"{provider.key} search was refused during the active defense cooldown;"
            f" not retried before {until:%Y-%m-%dT%H:%MZ}",
            provider=provider.key,
            retry_after_seconds=(until - self._wall_clock()).total_seconds(),
        )

    def _note_search_refusal(
        self,
        provider: Provider,
        fetch: RawFetch | None,
        error: ProviderTransportError,
    ) -> None:
        refused = isinstance(error, ProviderDefenseError) or (
            _search_leg_failure(provider, fetch)
            is ProviderCheckFailure.PROVIDER_DEFENSE
        )
        contained = self.defense_contained_until(provider.key) if refused else None
        if contained is not None:
            self._search_refused_until[provider.key] = contained

    def _defense_cleared(self, provider_key: str) -> None:
        """A full-access retrieval success ends containment."""

        if self._defense is not None:
            self._defense.clear(provider_key)

    def close(self) -> None:
        """Close process-owned transports; safe to call more than once."""

        if self._closed:
            return
        self._closed = True
        try:
            if self._browser_retriever is not None:
                self._browser_retriever.close()
        finally:
            close_http = getattr(self._http, "close", None)
            if callable(close_http):
                close_http()

    @property
    def archive_path(self) -> Path:
        return self._require_archive().path

    def login(
        self,
        provider_key: str,
        *,
        headless: bool = False,
        cookie_payload: object | None = None,
        challenge_mode: ChallengeMode = ChallengeMode.DETECT_ONLY,
        before_browser: Callable[[], None] | None = None,
        allow_credential_mint: bool = True,
    ) -> LoginResult | SessionHealth:
        with observe_renewal(
            provider_key,
            self._keeper_outcomes.issue_observation if self._keeper_outcomes else None,
        ):
            return self._login(
                provider_key,
                headless=headless,
                cookie_payload=cookie_payload,
                challenge_mode=challenge_mode,
                before_browser=before_browser,
                allow_credential_mint=allow_credential_mint,
            )

    def _login(
        self,
        provider_key: str,
        *,
        headless: bool = False,
        cookie_payload: object | None = None,
        challenge_mode: ChallengeMode = ChallengeMode.DETECT_ONLY,
        before_browser: Callable[[], None] | None = None,
        allow_credential_mint: bool = True,
    ) -> LoginResult | SessionHealth:
        provider = self._session_provider(provider_key)
        hold_id = self._verification_hold(provider_key)
        self._release_browser()
        if provider.login_recipe is None:  # pragma: no cover - provider invariant
            raise UsageError(f"{provider_key} has no login recipe")
        with self._timing_operation(TimingOperation.LOGIN, (provider,)):
            manager = self._session_manager()
            if cookie_payload is not None:
                if (
                    provider.capabilities.retrieval_transport == "browser"
                    and before_browser is not None
                ):
                    before_browser()
                manager.import_cookies(provider_key, cookie_payload)
                imported = manager.status(provider_key)
                if imported.status is SessionStatus.VERIFIED:
                    self._session_evidence_verified(provider_key, hold_id=hold_id)
                return imported
            try:
                acquired = manager.explicit_login(
                    provider_key,
                    headless=headless,
                    challenge_mode=challenge_mode,
                    before_browser=before_browser,
                    allow_credential_mint=allow_credential_mint,
                )
            except AccountAlertError as error:
                self._record_account_alert(provider, None, error, TimingOperation.GET)
                raise
            except ProviderDefenseError as error:
                set_timing_failure(
                    MintFailureEvidence(
                        stage=MintFailureStage.PAID_PROBE,
                        category=MintFailureCategory.CHALLENGE_BLOCKED,
                    )
                )
                self._record_defense_error(provider, error, TimingOperation.GET)
                raise
            set_timing_acquisition_mode(acquired.evidence.mode)
            health = manager.status(provider_key)
            if health.status is SessionStatus.VERIFIED:
                self._session_evidence_verified(provider_key, hold_id=hold_id)
            return LoginResult(
                health=health,
                acquisition=acquired.evidence,
                refresh_failure=acquired.refresh_failure,
            )

    def session_status(self, provider_key: str) -> SessionHealth:
        if self._subscription_routing is not None:
            reader = self._subscription_routing.reader(provider_key)
            if reader is not self:
                return reader.session_status(provider_key).model_copy(
                    update={
                        "renewal_incident_id": None,
                        "renewal_diagnostic_id": None,
                        "recovery": None,
                    }
                )
        self._session_provider(provider_key)
        if self._sessions is None:
            raise PersistenceError("session source is not configured")
        health = self._sessions.status(provider_key)
        # Fold the keeper's persisted renewal reality into the answer, so a
        # session whose renewals keep failing cannot read as plain "verified"
        # (the stale-verified deception; ARCHITECTURE, "Session upkeep"). Enrichment is
        # unconditional: readers may rely on `health` being present.
        outcome = (
            self._keeper_outcomes.load(provider_key)
            if self._keeper_outcomes is not None
            else None
        )
        health = enrich_session_health(health, outcome, now=self._wall_clock())
        recovery = (
            self._recovery_store.load(provider_key) if self._recovery_store else None
        )
        if recovery is not None:
            update: dict[str, object] = {"recovery": recovery.health}
            if (
                not recovery.health.session_verified
                and not recovery.health.article_verified
                and (
                    health.last_verified_at is None
                    or health.last_verified_at <= recovery.health.requested_at
                )
            ):
                update["health"] = SessionHealthState.DEGRADED
            health = health.model_copy(update=update)
        return health

    def session_checkpoint(
        self,
        provider_key: str,
        *,
        minimum_age_hours: float = 0,
        expected_generation_fingerprint: str | None = None,
    ) -> SessionCheckpoint:
        if minimum_age_hours < 0:
            raise UsageError("minimum checkpoint age must not be negative")
        self._session_provider(provider_key)
        if self._sessions is None:
            raise PersistenceError("session source is not configured")
        with observe_renewal(
            provider_key,
            self._keeper_outcomes.issue_observation if self._keeper_outcomes else None,
        ) as observation:
            # Checkpoints verify a snapshot outside the account lock. Claim
            # before loading it; intervening renewal observations invalidate
            # its ability to clear newer failure evidence, even on one generation.
            if observation is not None:
                observation.stamp()
            return self._session_checkpoint(
                provider_key,
                minimum_age_hours=minimum_age_hours,
                expected_generation_fingerprint=expected_generation_fingerprint,
            )

    def _session_checkpoint(
        self,
        provider_key: str,
        *,
        minimum_age_hours: float = 0,
        expected_generation_fingerprint: str | None = None,
    ) -> SessionCheckpoint:
        if minimum_age_hours < 0:
            raise UsageError("minimum checkpoint age must not be negative")
        provider = self._session_provider(provider_key)
        if self._sessions is None:
            raise PersistenceError("session source is not configured")
        hold_id = self._verification_hold(provider_key)
        artifact = self._sessions.get_valid_session(provider_key)
        self._verify_session_or_downgrade(provider, artifact)
        # _verify_session_or_downgrade raises on anything but a positive live
        # verification, so reaching here is delivered session evidence.
        self._session_evidence_verified(provider_key, hold_id=hold_id)
        checked_at = self._wall_clock()
        if checked_at.tzinfo is None:
            raise PersistenceError("checkpoint clock must be timezone aware")
        fingerprint = hashlib.sha256(
            str(artifact.generation_id).encode("ascii")
        ).hexdigest()[:12]
        checkpoint = SessionCheckpoint(
            provider=artifact.provider,
            account_key=artifact.account_key,
            generation_fingerprint=fingerprint,
            created_at=artifact.created_at,
            verified_at=artifact.verified_at,
            checked_at=checked_at,
            session_age_seconds=max(
                0.0, (checked_at - artifact.created_at).total_seconds()
            ),
        )
        if (
            expected_generation_fingerprint is not None
            and checkpoint.generation_fingerprint
            != expected_generation_fingerprint.lower()
        ):
            raise SessionRequiredError(
                "session generation does not match the durability baseline"
            )
        if checkpoint.session_age_seconds < minimum_age_hours * 60 * 60:
            raise SessionRequiredError(
                "session has not reached the required checkpoint age"
            )
        return checkpoint

    def session_reset(self, provider_key: str) -> SessionHealth:
        self._session_provider(provider_key)
        self._release_browser()
        manager = self._session_manager()
        manager.reset(provider_key)
        return manager.status(provider_key)

    def session_clear(self, provider_key: str) -> SessionHealth:
        self._session_provider(provider_key)
        self._release_browser()
        manager = self._session_manager()
        manager.clear(provider_key)
        return manager.status(provider_key)

    def session_acknowledge(self, provider_key: str) -> SessionHealth:
        self._session_provider(provider_key)
        self._release_browser()
        manager = self._session_manager()
        manager.acknowledge(provider_key)
        return manager.status(provider_key)

    def browser_profile_reset(self, provider_key: str) -> SessionHealth:
        self._session_provider(provider_key)
        self._release_browser()
        manager = self._session_manager()
        manager.reset_browser_profile(provider_key)
        return manager.status(provider_key)

    def search(
        self,
        provider_key: str,
        query: str,
        filters: SearchFilters | None = None,
    ) -> list[SearchResult]:
        if not query.strip():
            raise UsageError("search query must not be empty")
        provider = self._registry.get(provider_key)
        if self._subscription_routing is not None:
            reader = self._subscription_routing.reader(provider.key)
            if reader is not self:
                return reader.search(provider_key, query, filters)
        resolved = filters or SearchFilters()
        with self._timing_operation(TimingOperation.SEARCH, (provider,)):
            results, session = self._search_provider(
                provider,
                query.strip(),
                resolved,
            )
            results = list(_ordered_search_batch(results, resolved.sort))
        # Outside search timing so Chromium launch is not charged to discovery.
        self._prewarm_browser_for_retrieve(provider, session)
        return results

    def search_many(
        self,
        query: str,
        filters: SearchFilters | None = None,
        *,
        provider_keys: Sequence[str] | None = None,
        acquire_session: SessionAcquirer | None = None,
    ) -> SearchResponse:
        """Return the first bounded batch from a federated search pager."""

        resolved_filters = filters or SearchFilters()
        pager = self.search_pager(
            query,
            resolved_filters,
            provider_keys=provider_keys,
            acquire_session=acquire_session,
        )
        return pager.next_batch(resolved_filters.limit)

    def search_pager(
        self,
        query: str,
        filters: SearchFilters | None = None,
        *,
        provider_keys: Sequence[str] | None = None,
        acquire_session: SessionAcquirer | None = None,
    ) -> FederatedSearchPager:
        """Create an in-process, forward-only federated search session."""

        normalized_query = query.strip()
        if not normalized_query:
            raise UsageError("search query must not be empty")
        selected_keys = self._selected_provider_keys(provider_keys)
        selected = tuple(self._registry.get(key) for key in selected_keys)
        preflight_errors: dict[str, NewsclipError] = {}

        readers: dict[str, NewsclipService] | None = None
        validations: list[Callable[[], None]] = []
        if self._subscription_routing is not None:
            readers = {}
            routing = self._subscription_routing
            for provider in selected:
                try:
                    reader, admission = routing.capture(provider.key)
                    readers[provider.key] = reader
                    if admission is not None:
                        validations.append(
                            partial(routing.access.revalidate, admission)
                        )
                        session = reader._search_session_for(provider)
                        validations.append(
                            partial(
                                reader._revalidate_search_session,
                                provider,
                                session.generation_id if session else None,
                            )
                        )
                except _SEARCH_FAILURES as error:
                    preflight_errors[provider.key] = error

        if acquire_session is not None:
            for provider in selected:
                if not provider.capabilities.requires_session_for_search:
                    continue
                try:
                    self._search_session_for(provider)
                except SessionRequiredError:
                    try:
                        acquire_session(provider.key)
                        self._search_session_for(provider)
                    except _SEARCH_FAILURES as exc:
                        preflight_errors[provider.key] = exc
                except _SEARCH_FAILURES as exc:
                    preflight_errors[provider.key] = exc

        return FederatedSearchPager(
            self,
            normalized_query,
            filters or SearchFilters(),
            selected,
            preflight_errors=preflight_errors,
            readers=readers,
            validations=validations,
        )

    def provider_check(self, provider_key: str) -> ProviderCheckResult:
        """Run one existing-session check under shared retrieval containment."""
        self._registry.get(provider_key)
        entered = False
        try:
            with self._defense_scope(provider_key):
                entered = True
                result = self._provider_check_once(provider_key)
        except ProviderDefenseError as error:
            if entered:
                raise
            return ProviderCheckResult(
                provider=provider_key,
                ok=False,
                failure=ProviderCheckFailure.PROVIDER_DEFENSE,
                defense_observation="suppressed",
                defense_retry_after_seconds=error.retry_after_seconds,
            )
        if result.failure is ProviderCheckFailure.PROVIDER_DEFENSE and self._defense:
            if result.incident_id is not None:
                self._attach_defense_incident(provider_key, result.incident_id)
            record = self._defense.status(provider_key)
            if record is not None:
                return result.model_copy(
                    update={
                        "defense_observation": "observed",
                        "defense_retry_after_seconds": max(
                            1.0,
                            (record.active_until - self._wall_clock()).total_seconds(),
                        ),
                    }
                )
        return result

    def _provider_check_once(self, provider_key: str) -> ProviderCheckResult:
        provider = self._registry.get(provider_key)
        check = provider.check
        expected_url = str(check.canonical_url)
        try:
            session = self._session_for(provider)
        except SessionRequiredError:
            return _provider_check_failure(
                provider.key,
                ProviderCheckFailure.SESSION_REQUIRED,
            )
        except OperatorActionRequiredError:
            return _provider_check_failure(
                provider.key,
                ProviderCheckFailure.OPERATOR_ACTION,
            )
        except PersistenceError:
            return _provider_check_failure(
                provider.key,
                ProviderCheckFailure.LOCAL_STATE,
            )

        try:
            observed_http = _ObservedHttpClient(
                self._provider_check_search_http(provider)
            )
            page = provider.search_page(
                observed_http,
                session,
                check.query,
                SearchFilters(limit=20),
                metadata_fetch_budget=0,
            )
            if not isinstance(page, ProviderSearchPage) or any(
                result.provider != provider.key
                or not provider.owns_url(str(result.url))
                for result in page.results
            ):
                raise ProviderContractError(
                    f"{provider.key} search returned an invalid page"
                )
            expected_present = any(
                str(result.url) == expected_url for result in page.results
            )
            empty_search_allowed = (
                check.allow_empty_search and page.coverage_start is not None
            )
            # A valid, non-empty page that no longer ranks the pinned canary
            # is ordinary aging, not a search failure: the article can still
            # serve (FT, 2026-09-28, held at expected_result_missing while it
            # did). Only an empty page, or one that is a served challenge,
            # stops the check here; otherwise retrieval decides, and the
            # absence rides along as a non-durable advisory.
            canary_missing = check.require_canonical_result and not expected_present
            search_failed = not page.results and not empty_search_allowed
            if canary_missing and not search_failed:
                search_failed = (
                    _search_leg_failure(
                        provider,
                        observed_http.last_fetch,
                        otherwise=ProviderCheckFailure.EXPECTED_RESULT_MISSING,
                    )
                    is ProviderCheckFailure.PROVIDER_DEFENSE
                )
            if search_failed:
                incident_id = self._record_search_incident(
                    provider,
                    observed_http.last_fetch,
                    ProviderContractError(
                        f"{provider.key} provider-check result is unavailable"
                    ),
                )
                failure = _search_leg_failure(
                    provider,
                    observed_http.last_fetch,
                    otherwise=ProviderCheckFailure.EXPECTED_RESULT_MISSING,
                )
                if failure is ProviderCheckFailure.PROVIDER_DEFENSE:
                    self._defense_observed(provider.key, origin="guard")
                return _provider_check_failure(
                    provider.key,
                    failure,
                    search_result_count=len(page.results),
                    incident_id=incident_id,
                )
        except PersistenceError:
            return _provider_check_failure(
                provider.key,
                ProviderCheckFailure.LOCAL_STATE,
            )
        except OperatorActionRequiredError:
            return _provider_check_failure(
                provider.key,
                ProviderCheckFailure.OPERATOR_ACTION,
            )
        except ProviderDefenseError as error:
            # Before its transport parent: a challenge on the search leg is a
            # defense event and must be classified as one, not as transport.
            self._defense_observed(provider.key, origin="guard")
            return _provider_check_failure(
                provider.key,
                ProviderCheckFailure.PROVIDER_DEFENSE,
                incident_id=self._record_defense_error(
                    provider, error, TimingOperation.SEARCH
                ),
            )
        except ProviderContractError as error:
            incident_id = self._record_search_incident(
                provider,
                observed_http.last_fetch,
                error,
            )
            failure = _search_leg_failure(
                provider,
                observed_http.last_fetch,
                otherwise=ProviderCheckFailure.SEARCH_CONTRACT,
            )
            if failure is ProviderCheckFailure.PROVIDER_DEFENSE:
                self._defense_observed(provider.key, origin="guard")
            return _provider_check_failure(
                provider.key,
                failure,
                incident_id=incident_id,
            )
        except ProviderTransportError as error:
            incident_id = self._record_search_incident(
                provider,
                observed_http.last_fetch,
                error,
            )
            failure = _search_leg_failure(provider, observed_http.last_fetch)
            if failure is ProviderCheckFailure.PROVIDER_DEFENSE:
                self._defense_observed(provider.key, origin="guard")
            return _provider_check_failure(
                provider.key,
                failure,
                incident_id=incident_id,
            )

        result = self._provider_check_retrieval(provider, session, page)
        if not check.require_canonical_result:
            return result
        return result.model_copy(update={"canary_in_search": expected_present})

    def _provider_check_retrieval(
        self,
        provider: Provider,
        session: SessionArtifact | None,
        page: ProviderSearchPage,
    ) -> ProviderCheckResult:
        """Retrieve and assess the pinned canary after a usable search leg."""

        expected_url = str(provider.check.canonical_url)
        try:
            evaluation = self._evaluate_retrieval(
                provider,
                expected_url,
                self._provider_check_http(provider),
                session,
            )
        except BrowserSnapshotRejected as error:
            return self._provider_check_render_timeout(
                provider,
                session,
                error,
                requested_url=expected_url,
                search_result_count=len(page.results),
            )
        except ProviderDefenseError as error:
            self._defense_observed(provider.key, origin="guard")
            return _provider_check_failure(
                provider.key,
                ProviderCheckFailure.PROVIDER_DEFENSE,
                search_result_count=len(page.results),
                incident_id=self._record_defense_error(
                    provider, error, TimingOperation.GET
                ),
            )
        except ProviderTransportError:
            return _provider_check_failure(
                provider.key,
                ProviderCheckFailure.RETRIEVAL_TRANSPORT,
                search_result_count=len(page.results),
            )
        except OperatorActionRequiredError as error:
            return _provider_check_failure(
                provider.key,
                ProviderCheckFailure.OPERATOR_ACTION,
                search_result_count=len(page.results),
                incident_id=error.incident_id,
            )
        except PersistenceError:
            return _provider_check_failure(
                provider.key,
                ProviderCheckFailure.LOCAL_STATE,
                search_result_count=len(page.results),
            )

        fetch = evaluation.fetch
        assessment = evaluation.assessment
        evidence = content_assessment_evidence(assessment)
        if assessment.promotable:
            self._defense_cleared(provider.key)
            return _provider_check_assessed_result(
                provider.key,
                evidence,
                http_status=fetch.http_status,
                search_result_count=len(page.results),
            )
        if evidence.access_state is AccessState.BLOCKED or fetch.http_status == 429:
            return self._provider_check_defended(
                provider,
                page,
                fetch,
                assessment,
                evidence,
            )
        if 500 <= fetch.http_status < 600:
            incident_id = self._record_retrieval_incident(
                provider,
                TimingOperation.GET,
                fetch,
                assessment,
            )
            return _provider_check_assessed_result(
                provider.key,
                evidence,
                failure=ProviderCheckFailure.RETRIEVAL_TRANSPORT,
                http_status=fetch.http_status,
                search_result_count=len(page.results),
                incident_id=incident_id,
            )

        try:
            disposition = self._provider_check_session_disposition(
                provider,
                session,
                target_access_state=assessment.access_state,
            )
        except ProviderDefenseError as error:
            # A challenge during the verification probe is the same defense
            # event as one on the target itself: classify it honestly.
            self._defense_observed(provider.key, origin="guard")
            return _provider_check_assessed_result(
                provider.key,
                evidence,
                failure=ProviderCheckFailure.PROVIDER_DEFENSE,
                http_status=fetch.http_status,
                search_result_count=len(page.results),
                incident_id=self._record_defense_error(
                    provider, error, TimingOperation.GET
                ),
            )
        except OperatorActionRequiredError as error:
            return _provider_check_assessed_result(
                provider.key,
                evidence,
                failure=ProviderCheckFailure.OPERATOR_ACTION,
                http_status=fetch.http_status,
                search_result_count=len(page.results),
                incident_id=error.incident_id,
            )
        except PersistenceError:
            return _provider_check_assessed_result(
                provider.key,
                evidence,
                failure=ProviderCheckFailure.LOCAL_STATE,
                http_status=fetch.http_status,
                search_result_count=len(page.results),
            )
        if disposition is SessionDisposition.DEAD:
            return _provider_check_assessed_result(
                provider.key,
                evidence,
                failure=ProviderCheckFailure.SESSION_DEAD,
                http_status=fetch.http_status,
                search_result_count=len(page.results),
                session_disposition=disposition,
            )
        if fetch.http_status == 403:
            # A bare 403 — no challenge markers — is ambiguous on a session
            # provider: the origin may be refusing a dead subscriber cookie
            # rather than defending against the client. Economist did exactly
            # that from 2026-08-25 (403 carrying the full server-rendered
            # article and ``auth.loggedIn: false``), and filing it as defense
            # blocked the one remedy — the hold class that stops the keeper
            # renewing — for ten days. So the session verdict above runs
            # first; only a 403 on a session that still verifies is defense.
            # Challenges and 429 never reach here: they are classified before
            # any further request into a provider that is already refusing.
            return self._provider_check_defended(
                provider,
                page,
                fetch,
                assessment,
                evidence,
            )
        if fetch.http_status == 401:
            incident_id = self._record_retrieval_incident(
                provider,
                TimingOperation.GET,
                fetch,
                assessment,
            )
            return _provider_check_assessed_result(
                provider.key,
                evidence,
                failure=ProviderCheckFailure.PROVIDER_DEFENSE,
                http_status=fetch.http_status,
                search_result_count=len(page.results),
                session_disposition=disposition,
                incident_id=incident_id,
            )
        incident_id = self._record_retrieval_incident(
            provider,
            TimingOperation.GET,
            fetch,
            assessment,
        )
        return _provider_check_assessed_result(
            provider.key,
            evidence,
            failure=ProviderCheckFailure.CONTENT_NOT_FULL,
            http_status=fetch.http_status,
            search_result_count=len(page.results),
            session_disposition=disposition,
            incident_id=incident_id,
        )

    def _provider_check_render_timeout(
        self,
        provider: Provider,
        session: SessionArtifact | None,
        error: BrowserSnapshotRejected,
        *,
        requested_url: str,
        search_result_count: int,
    ) -> ProviderCheckResult:
        """Classify a rejected browser snapshot as bounded content evidence.

        The read path aborts on this rejection because a partially rendered
        article must never be promoted. A scheduled check instead has to report
        it, so the guard can contain the provider and an operator can review the
        retained evidence; re-raising leaves no hold and no incident.

        Only the ``CONTENT_NOT_FULL`` tail applies. A snapshot is rejected solely
        from the promotable-incomplete or complete-unstable terminals, both of
        which require the assessment to have been promotable or the provider's
        completeness oracle to have been satisfied, so the document is neither a
        challenge nor an error page and the status-based defense branches cannot
        match. The incident is recorded before the session probe because its
        terminal readiness evidence, not the probe, is what explains the failure.
        """

        fetch = error.fetch
        with timing_step(TimingStep.EXTRACT, provider=provider.key):
            extraction = self._extractor.extract(
                fetch, scope_xpath=provider.extraction_scope
            )
        with timing_step(TimingStep.ASSESS, provider=provider.key):
            assessment = provider.assess(requested_url, fetch, extraction)
        evidence = content_assessment_evidence(assessment)
        incident_id = self._record_retrieval_incident(
            provider,
            TimingOperation.GET,
            fetch,
            assessment,
            readiness=error.snapshot,
        )
        try:
            disposition = self._provider_check_session_disposition(
                provider,
                session,
                target_access_state=assessment.access_state,
            )
        except ProviderDefenseError as defense_error:
            self._defense_observed(provider.key, origin="guard")
            self._record_defense_error(provider, defense_error, TimingOperation.GET)
            return _provider_check_assessed_result(
                provider.key,
                evidence,
                failure=ProviderCheckFailure.PROVIDER_DEFENSE,
                http_status=fetch.http_status,
                search_result_count=search_result_count,
                incident_id=incident_id,
            )
        except OperatorActionRequiredError:
            return _provider_check_assessed_result(
                provider.key,
                evidence,
                failure=ProviderCheckFailure.OPERATOR_ACTION,
                http_status=fetch.http_status,
                search_result_count=search_result_count,
                incident_id=incident_id,
            )
        except PersistenceError:
            return _provider_check_assessed_result(
                provider.key,
                evidence,
                failure=ProviderCheckFailure.LOCAL_STATE,
                http_status=fetch.http_status,
                search_result_count=search_result_count,
                incident_id=incident_id,
            )
        return _provider_check_assessed_result(
            provider.key,
            evidence,
            failure=ProviderCheckFailure.CONTENT_NOT_FULL,
            http_status=fetch.http_status,
            search_result_count=search_result_count,
            session_disposition=disposition,
            incident_id=incident_id,
        )

    def _provider_check_defended(
        self,
        provider: Provider,
        page: ProviderSearchPage,
        fetch: RawFetch,
        assessment: ArticleAssessment,
        evidence: ContentAssessmentEvidence,
    ) -> ProviderCheckResult:
        """Record a retrieval-leg defense observation and its capsule."""

        self._defense_observed(provider.key, origin="guard")
        incident_id = self._record_retrieval_incident(
            provider,
            TimingOperation.GET,
            fetch,
            assessment,
        )
        return _provider_check_assessed_result(
            provider.key,
            evidence,
            failure=ProviderCheckFailure.PROVIDER_DEFENSE,
            http_status=fetch.http_status,
            search_result_count=len(page.results),
            incident_id=incident_id,
        )

    def _provider_check_session_disposition(
        self,
        provider: Provider,
        session: SessionArtifact | None,
        *,
        target_access_state: AccessState,
    ) -> SessionDisposition | None:
        if session is None or provider.login_recipe is None:
            return None
        try:
            with self._provider_check_verification_client(provider) as client:
                verification = provider.login_recipe.verify(client, session)
        except AccountAlertError as error:
            self._record_account_alert(provider, session, error, TimingOperation.GET)
            raise
        except ProviderDefenseError:
            # A challenged probe is a definite defense observation, not an
            # inconclusive one; callers classify it as such.
            raise
        except ProviderTransportError:
            return SessionDisposition.INCONCLUSIVE
        return session_wide_verdict(
            verification,
            target_access_state=target_access_state,
        )

    def _selected_provider_keys(
        self,
        provider_keys: Sequence[str] | None,
    ) -> tuple[str, ...]:
        keys = (
            self._registry.keys()
            if provider_keys is None
            else tuple(dict.fromkeys(provider_keys))
        )
        if not keys:
            raise UsageError("search requires at least one provider")
        for key in keys:
            self._registry.get(key)
        return keys

    def _search_provider(
        self,
        provider: Provider,
        query: str,
        filters: SearchFilters,
    ) -> tuple[list[SearchResult], SessionArtifact | None]:
        self._search_paused(provider)
        with timing_step(TimingStep.SESSION_LOAD, provider=provider.key):
            session = self._search_session_for(provider)
        observed_http = _ObservedHttpClient(self._provider_search_http(provider))
        try:
            with timing_step(TimingStep.PROVIDER_SEARCH, provider=provider.key):
                results = provider.search(
                    observed_http,
                    session,
                    query,
                    filters,
                )
            if any(
                result.provider != provider.key
                or not provider.owns_url(str(result.url))
                for result in results
            ):
                raise ProviderContractError(
                    f"{provider.key} search returned invalid result ownership"
                )
        except ProviderTransportError as error:
            self._record_search_incident(provider, observed_http.last_fetch, error)
            self._note_search_refusal(provider, observed_http.last_fetch, error)
            raise
        return results, session

    def _search_provider_page(
        self,
        provider: Provider,
        query: str,
        filters: SearchFilters,
        *,
        next_url: str | None,
        metadata_fetch_budget: int | None,
    ) -> ProviderSearchPage:
        self._search_paused(provider)
        with timing_step(TimingStep.SESSION_LOAD, provider=provider.key):
            session = self._search_session_for(provider)
        observed_http = _ObservedHttpClient(self._provider_search_http(provider))
        try:
            with timing_step(TimingStep.PROVIDER_SEARCH, provider=provider.key):
                page = provider.search_page(
                    observed_http,
                    session,
                    query,
                    filters,
                    next_url=next_url,
                    metadata_fetch_budget=metadata_fetch_budget,
                )
            if not isinstance(page, ProviderSearchPage):
                raise ProviderContractError(
                    f"{provider.key} search returned an invalid page"
                )
            if any(
                result.provider != provider.key
                or not provider.owns_url(str(result.url))
                for result in page.results
            ):
                raise ProviderContractError(
                    f"{provider.key} search returned invalid result ownership"
                )
        except ProviderTransportError as error:
            self._record_search_incident(provider, observed_http.last_fetch, error)
            self._note_search_refusal(provider, observed_http.last_fetch, error)
            raise
        return page

    def _revalidate_search_session(
        self, provider: Provider, generation: UUID | None
    ) -> None:
        current = self._search_session_for(provider)
        if (current.generation_id if current else None) != generation:
            raise SessionRequiredError("account_changed")

    def _search_session_for(self, provider: Provider) -> SessionArtifact | None:
        if provider.capabilities.session_kind == "none":
            return None
        if self._sessions is None:
            if not provider.capabilities.requires_session_for_search:
                return None
            raise SessionRequiredError(
                f"{provider.key} search requires an explicit login"
            )
        if provider.capabilities.requires_session_for_search:
            return self._sessions.get_valid_session(provider.key)
        try:
            # Public search stays available without authentication, but a
            # verified jar may carry provider edge-risk affinity needed to
            # avoid a challenge on the otherwise anonymous endpoint.
            return self._sessions.get_valid_session(provider.key)
        except (
            SessionRequiredError,
            OperatorActionRequiredError,
            PersistenceError,
        ):
            return None

    def requires_browser_for_url(self, url: str) -> bool:
        provider = self._registry.for_url(url)
        return (
            provider.capabilities.retrieval_transport == "browser"
            or self._allows_http_challenge_fallback(provider)
        )

    def requires_browser_for_provider(self, provider_key: str) -> bool:
        provider = self._registry.get(provider_key)
        return (
            provider.capabilities.retrieval_transport == "browser"
            or self._allows_http_challenge_fallback(provider)
        )

    def requires_browser_for_search(
        self,
        provider_keys: Sequence[str] | None = None,
    ) -> bool:
        keys = self._selected_provider_keys(provider_keys)
        return any(
            self._registry.get(key).capabilities.search_transport == "browser"
            or self._allows_http_challenge_fallback(self._registry.get(key))
            for key in keys
        )

    def requires_browser_runtime(
        self,
        provider_keys: Sequence[str] | None = None,
    ) -> bool:
        """True when search or retrieve for the selection needs a browser plane.

        Federated interactive search is HTTP-only for discovery, but selecting a
        WSJ/Economist/Bloomberg result still opens browser retrieval. Prepare the
        virtual display before the search loop so selection does not fail with
        transport after results are already shown.
        """

        keys = self._selected_provider_keys(provider_keys)
        return any(
            self._registry.get(key).capabilities.search_transport == "browser"
            or self._registry.get(key).capabilities.retrieval_transport == "browser"
            or self._allows_http_challenge_fallback(self._registry.get(key))
            for key in keys
        )

    def get(
        self,
        url: str,
        *,
        acquire_session: SessionAcquirer | None = None,
        request_recovery: bool = True,
    ) -> Article:
        request_recovery = request_recovery and acquire_session is None
        provider = self._registry.for_url(url)
        if self._subscription_routing is not None:
            reader = self._subscription_routing.reader(provider.key)
            if reader is not self:
                return reader.get(url, request_recovery=False)
        with self._timing_operation(TimingOperation.GET, (provider,)):
            try:
                return self._get_once(provider, url, request_recovery=request_recovery)
            except SessionRequiredError:
                if acquire_session is None:
                    raise
                with timing_step(TimingStep.SESSION_ACQUIRE, provider=provider.key):
                    acquire_session(provider.key)
                return self._get_once(provider, url, request_recovery=request_recovery)

    def validate_recovery_url(self, provider_key: str, url: str) -> None:
        if self._registry.for_url(url).key != provider_key:
            raise UsageError("recovery URL does not belong to provider")

    def verify_recovery_article(self, provider_key: str, url: str) -> None:
        self.validate_recovery_url(provider_key, url)
        self.get(url, request_recovery=False)

    def verify_recovery_session(self, provider_key: str) -> None:
        self.session_checkpoint(provider_key)

    def recovery_generation(self, provider_key: str) -> UUID | None:
        provider = self._session_provider(provider_key)
        try:
            session = self._session_for(provider)
        except SessionRequiredError:
            return None
        return session.generation_id if session is not None else None

    @contextmanager
    def _recovery_scope(
        self, provider: Provider, url: str, *, enabled: bool = True
    ) -> Iterator[SessionArtifact | None]:
        clear_timing_content_assessment()
        session = None
        try:
            with timing_step(TimingStep.SESSION_LOAD, provider=provider.key):
                session = self._session_for(provider)
            yield session
        except (
            SessionRequiredError,
            ContentNotFullError,
            ProviderTransportError,
        ) as error:
            read_failure_reason = retryable_read_reason(error)
            if (
                enabled
                and self._recovery_store is not None
                and (
                    isinstance(error, SessionRequiredError)
                    or error.recovery_eligible
                    or read_failure_reason is not None
                )
                and self.requires_session_for_provider(provider.key)
            ):
                try:
                    # No maintenance actor can own the profile while this
                    # serving operation still holds its lease.
                    self._release_browser()
                    record = self._recovery_store.request(
                        provider.key,
                        generation_id=session.generation_id if session else None,
                        session_required=isinstance(error, SessionRequiredError),
                        url=url,
                        incident_id=getattr(error, "incident_id", None),
                        diagnostic_id=current_timing_invocation_id(),
                        read_failure_reason=read_failure_reason,
                    )
                    set_timing_recovery(
                        RecoveryHandoffEvidence(
                            request_id=record.health.request_id,
                            status=record.health.status,
                        )
                    )
                    if record.health.status in {
                        RecoveryStatus.PENDING,
                        RecoveryStatus.RUNNING,
                    }:
                        error.recovery_id = record.health.request_id
                except Exception:
                    # The original serving failure remains authoritative even
                    # if lease release or durable handoff itself fails.
                    error.recovery_omission = "handoff_failed"
                    set_timing_recovery(
                        RecoveryHandoffEvidence(omission="handoff_failed")
                    )
            raise

    def _get_once(
        self, provider: Provider, url: str, *, request_recovery: bool = True
    ) -> Article:
        with (
            self._defense_scope(provider.key),
            self._recovery_scope(provider, url, enabled=request_recovery) as session,
        ):
            return self._get_attempt(provider, url, session)

    def _recovery_article_verified(
        self, provider: str, url: str, verified_at: datetime
    ) -> None:
        if self._recovery_store is None:
            return
        try:
            record = self._recovery_store.article_verified(
                provider,
                url,
                verified_at=verified_at,
                diagnostic_id=current_timing_invocation_id(),
            )
            if record is not None:
                set_timing_recovery(
                    RecoveryHandoffEvidence(
                        request_id=record.health.request_id, status=record.health.status
                    )
                )
        except PersistenceError:
            # A verified article remains usable if diagnostic state cannot be
            # updated. Preserve the failure latch and record the omission.
            set_timing_recovery(RecoveryHandoffEvidence(omission="resolution_failed"))

    def _get_attempt(
        self, provider: Provider, url: str, session: SessionArtifact | None
    ) -> Article:
        try:
            evaluation = self._evaluate_retrieval(
                provider,
                url,
                self._provider_http(provider),
                session,
                incident_operation=TimingOperation.GET,
                allow_native_session_probe=True,
            )
        except ProviderDefenseError as error:
            observed = self._defense_observed(provider.key, origin="retrieval")
            error.provider = provider.key
            error.retry_after_seconds = (
                observed.retry_after_seconds if observed is not None else None
            )
            self._record_defense_error(provider, error, TimingOperation.GET)
            raise
        fetch = evaluation.fetch
        extraction = evaluation.extraction
        assessment = evaluation.assessment
        if not evaluation.session_probe_performed or assessment.promotable:
            set_timing_content_assessment(assessment)
        if not assessment.promotable:
            if _assessed_challenge_is_corroborated(fetch, assessment):
                observed = self._defense_observed(
                    provider.key,
                    origin="retrieval",
                )
                if observed is not None:
                    if observed.first_of_episode:
                        self._record_retrieval_incident(
                            provider,
                            TimingOperation.GET,
                            fetch,
                            assessment,
                        )
                    _record_content_failure(assessment)
                    raise ProviderDefenseError(
                        f"{provider.key} returned an interactive challenge",
                        provider=provider.key,
                        retry_after_seconds=observed.retry_after_seconds,
                        reason_code=assessment.reason,
                    )
            probe = self._non_full_session_probe(
                provider, session, evaluation, TimingOperation.GET
            )
            incident_id = self._record_retrieval_incident(
                provider, TimingOperation.GET, fetch, assessment
            )
            _record_content_failure(assessment)
            raise _content_failure(assessment, probe, incident_id)
        if assessment.access_state is AccessState.FULL:
            self._defense_cleared(provider.key)
        with timing_step(TimingStep.BUILD_ARTICLE, provider=provider.key):
            article = build_article(
                provider,
                fetch,
                extraction,
                assessment,
                extractor_name=evaluation.extractor_name,
                extractor_version=evaluation.extractor_version,
            )
        if assessment.access_state is AccessState.FULL:
            self._recovery_article_verified(provider.key, url, fetch.retrieved_at)
        return article

    def probe_transport(
        self,
        url: str,
        transport: HttpClient,
    ) -> TransportProbeResult:
        """Evaluate one injected transport without product read-path side effects."""

        provider = self._registry.for_url(url)
        session = self._session_for(provider)
        evaluation = self._evaluate_retrieval(
            provider,
            url,
            transport,
            session,
        )
        fetch = evaluation.fetch
        assessment = evaluation.assessment
        return TransportProbeResult(
            provider=provider.key,
            http_status=fetch.http_status,
            access_state=assessment.access_state,
            word_count=assessment.word_count,
            identity_match=assessment.identity_match,
            session_cookie_present=fetch.session_cookie_present,
            reason=assessment.reason,
        )

    def probe_transport_candidate(self, provider_key: str, profile: str) -> bool:
        """Measure one candidate fingerprint against the canary article (R8).

        A measurement, not an episode. A refused candidate is the *expected*
        outcome of measuring a decayed pool, so this path deliberately runs
        outside the defense and guard machinery: it never gates, never arms,
        writes no capsule and no observation. Routed through the ordinary
        client instead, every hourly refusal would arm and re-double the
        cooldown, containing a provider the escalation is demonstrably
        serving — the exact inversion R8 exists to prevent.

        One request. Returns whether the candidate served full, matching
        content; anything else is a failure, including a transport error.
        """

        if profile not in HTTP_IMPERSONATION_PROFILES:
            raise UsageError("transport candidate is outside the allowlist")
        provider = self._registry.get(provider_key)
        if provider.capabilities.retrieval_challenge_escalation != "browser":
            raise UsageError("provider does not declare transport candidates")
        url = str(provider.check.canonical_url)
        try:
            with self._candidate_client_factory(profile) as candidate:
                probe = self._network.for_provider(
                    provider.key,
                    provider.rate_budget(),
                    candidate,
                    role=HttpOperationRole.FETCH,
                    max_attempts=1,
                )
                result = self.probe_transport(url, probe)
        except (ProviderTransportError, ProviderContractError, PersistenceError):
            return False
        return result.access_state is AccessState.FULL and result.identity_match

    def save(
        self,
        url: str,
        *,
        out: Path | None = None,
        acquire_session: SessionAcquirer | None = None,
    ) -> Article:
        provider = self._registry.for_url(url)
        if self._subscription_routing is not None:
            reader = self._subscription_routing.reader(provider.key)
            if reader is not self:
                return reader.save(url, out=out)
        with self._timing_operation(TimingOperation.SAVE, (provider,)):
            try:
                return self._save_once(
                    provider, url, out=out, request_recovery=acquire_session is None
                )
            except SessionRequiredError:
                if acquire_session is None:
                    raise
                with timing_step(TimingStep.SESSION_ACQUIRE, provider=provider.key):
                    acquire_session(provider.key)
                return self._save_once(
                    provider, url, out=out, request_recovery=acquire_session is None
                )

    def _save_once(
        self,
        provider: Provider,
        url: str,
        *,
        out: Path | None,
        request_recovery: bool = True,
    ) -> Article:
        self._require_archive()
        with (
            self._defense_scope(provider.key),
            self._recovery_scope(provider, url, enabled=request_recovery) as session,
        ):
            return self._save_attempt(provider, url, session, out=out)

    def _save_attempt(
        self,
        provider: Provider,
        url: str,
        session: SessionArtifact | None,
        *,
        out: Path | None,
    ) -> Article:
        archive = self._require_archive()
        try:
            evaluation = self._evaluate_retrieval(
                provider,
                url,
                self._provider_http(provider),
                session,
                incident_operation=TimingOperation.SAVE,
                allow_native_session_probe=True,
            )
        except ProviderDefenseError as error:
            observed = self._defense_observed(provider.key, origin="retrieval")
            error.provider = provider.key
            error.retry_after_seconds = (
                observed.retry_after_seconds if observed is not None else None
            )
            self._record_defense_error(provider, error, TimingOperation.SAVE)
            raise
        fetch = evaluation.fetch
        extraction = evaluation.extraction
        assessment = evaluation.assessment
        if not evaluation.session_probe_performed or assessment.promotable:
            set_timing_content_assessment(assessment)
        if assessment.promotable and assessment.access_state is AccessState.FULL:
            self._defense_cleared(provider.key)
        if not assessment.promotable:
            observed = None
            if _assessed_challenge_is_corroborated(fetch, assessment):
                observed = self._defense_observed(
                    provider.key,
                    origin="retrieval",
                )
            with timing_step(TimingStep.ARCHIVE, provider=provider.key):
                archive.save(provider.key, None, fetch, assessment, extraction)
            if observed is not None:
                if observed.first_of_episode:
                    self._record_retrieval_incident(
                        provider,
                        TimingOperation.SAVE,
                        fetch,
                        assessment,
                    )
                _record_content_failure(assessment)
                raise ProviderDefenseError(
                    f"{provider.key} returned an interactive challenge",
                    provider=provider.key,
                    retry_after_seconds=observed.retry_after_seconds,
                    reason_code=assessment.reason,
                )
            probe = self._non_full_session_probe(
                provider, session, evaluation, TimingOperation.SAVE
            )
            incident_id = self._record_retrieval_incident(
                provider, TimingOperation.SAVE, fetch, assessment
            )
            _record_content_failure(assessment)
            raise _content_failure(assessment, probe, incident_id)
        with timing_step(TimingStep.BUILD_ARTICLE, provider=provider.key):
            article = build_article(
                provider,
                fetch,
                extraction,
                assessment,
                extractor_name=evaluation.extractor_name,
                extractor_version=evaluation.extractor_version,
            )
        if assessment.access_state is AccessState.FULL:
            self._recovery_article_verified(provider.key, url, fetch.retrieved_at)
        with timing_step(TimingStep.ARCHIVE, provider=provider.key):
            saved = archive.save(provider.key, article, fetch, assessment, extraction)
        if saved is None:  # pragma: no cover - guarded by assessment
            raise PersistenceError("accepted article was not archived")
        if out is not None:
            with timing_step(TimingStep.EXPORT, provider=provider.key):
                archive.export_markdown(saved, out)
        return saved

    def _evaluate_retrieval(
        self,
        provider: Provider,
        url: str,
        transport: HttpClient,
        session: SessionArtifact | None,
        *,
        incident_operation: TimingOperation | None = None,
        allow_native_session_probe: bool = False,
    ) -> _RetrievalEvaluation:
        try:
            with timing_step(TimingStep.FETCH, provider=provider.key):
                fetch = provider.fetch(transport, session, url)
        except AccountAlertError as error:
            self._record_account_alert(
                provider, session, error, incident_operation or TimingOperation.GET
            )
            raise
        except BrowserSnapshotRejected as error:
            if incident_operation is None:
                raise
            fetch = error.fetch
            with timing_step(TimingStep.EXTRACT, provider=provider.key):
                extraction = self._extractor.extract(
                    fetch, scope_xpath=provider.extraction_scope
                )
            with timing_step(TimingStep.ASSESS, provider=provider.key):
                assessment = provider.assess(url, fetch, extraction)
            set_timing_content_assessment(assessment)
            incident_id = self._record_retrieval_incident(
                provider,
                incident_operation,
                fetch,
                assessment,
                readiness=error.snapshot,
            )
            _record_content_failure(assessment)
            raise ContentNotFullError(str(error), incident_id=incident_id) from error
        with timing_step(TimingStep.EXTRACT, provider=provider.key):
            extraction = self._extractor.extract(
                fetch, scope_xpath=provider.extraction_scope
            )
        with timing_step(TimingStep.ASSESS, provider=provider.key):
            assessment = provider.assess(url, fetch, extraction)
        evaluation = _RetrievalEvaluation(
            fetch=fetch,
            extraction=extraction,
            assessment=assessment,
            extractor_name=self._extractor.name,
            extractor_version=self._extractor.version,
        )
        if not isinstance(provider, ProviderNativeExtraction):
            return evaluation
        native = provider.native_extraction(url, fetch)
        if native.state is ProviderNativeExtractionState.ABSENT:
            return evaluation
        if native.state is ProviderNativeExtractionState.INVALID:
            if assessment.access_state in {
                AccessState.AUTH_REQUIRED,
                AccessState.BLOCKED,
            }:
                return evaluation
            return _RetrievalEvaluation(
                fetch=fetch,
                extraction=extraction,
                assessment=assessment.model_copy(
                    update={
                        "access_state": AccessState.UNKNOWN,
                        "negative_markers": tuple(
                            dict.fromkeys(
                                (*assessment.negative_markers, "embedded_story_invalid")
                            )
                        ),
                        "reason": "insufficient_article_structure",
                    }
                ),
                extractor_name=self._extractor.name,
                extractor_version=self._extractor.version,
            )
        if assessment.access_state in {
            AccessState.AUTH_REQUIRED,
            AccessState.BLOCKED,
        }:
            return evaluation
        if assessment.promotable:
            return _native_evaluation(fetch, native)
        if not allow_native_session_probe:
            return evaluation
        set_timing_content_assessment(assessment)
        try:
            probe = self._classify_session(provider, session)
        except SessionRequiredError as error:
            if incident_operation is not None and self._recovery_store is not None:
                error.incident_id = self._record_retrieval_incident(
                    provider, incident_operation, fetch, assessment
                )
            raise
        if probe.disposition is SessionDisposition.VERIFIED:
            return _native_evaluation(
                fetch,
                native,
                session_probe_performed=True,
            )
        return replace(evaluation, session_probe_performed=True, session_probe=probe)

    def _record_account_alert(
        self,
        provider: Provider,
        session: SessionArtifact | None,
        error: AccountAlertError,
        operation: TimingOperation,
    ) -> None:
        fetch = error.fetch
        extraction = self._extractor.extract(
            fetch, scope_xpath=provider.extraction_scope
        )
        assessment = provider.assess(str(fetch.requested_url), fetch, extraction)
        if current_timing_operation() in {TimingOperation.GET, TimingOperation.SAVE}:
            set_timing_content_assessment(assessment)
        set_timing_failure(
            MintFailureEvidence(
                stage=MintFailureStage.PAID_PROBE,
                category=MintFailureCategory.ACCOUNT_ALERT,
            )
        )
        error.incident_id = self._record_retrieval_incident(
            provider, operation, fetch, assessment
        )
        if self._sessions is not None and session is not None:
            self._sessions.mark_account_alert(
                provider.key,
                session.account_key,
                generation_id=session.generation_id,
            )

    def _record_retrieval_incident(
        self,
        provider: Provider,
        operation: TimingOperation,
        fetch: RawFetch,
        assessment: ArticleAssessment,
        *,
        readiness: BrowserSemanticSnapshot | None = None,
    ) -> str | None:
        """Retain private evidence without replacing the product failure."""

        if self._incidents is None:
            set_timing_incident(
                IncidentEvidence(
                    omission="not_configured",
                    capture_failure=CaptureFailure(
                        stage="persistence", reason="not_configured"
                    ),
                )
            )
            return None
        try:
            capsule = self._incidents.record_assessed_retrieval(
                provider=provider.key,
                operation=operation,
                fetch=fetch,
                assessment=assessment,
                readiness=readiness,
                session_probe=current_timing_session_probe(
                    assessment, provider=provider.key, operation=operation
                ),
            )
            self._incidents.retain_evidence(capsule)
            reference_available = True
            if self._defense is not None and (
                assessment.access_state is AccessState.BLOCKED
                or fetch.http_status == 429
            ):
                reference_available = self._attach_defense_incident(
                    provider.key, capsule.incident_id
                )
            set_timing_incident(
                IncidentEvidence(
                    incident_id=capsule.incident_id,
                    omission=(
                        "write_failed"
                        if not reference_available
                        else None
                        if capsule.capture_available
                        else "capture_too_large"
                    ),
                    capture_failure=(
                        CaptureFailure(stage="persistence", reason="failed")
                        if not reference_available
                        else None
                        if capsule.capture_available
                        else CaptureFailure(stage="persistence", reason="too_large")
                    ),
                )
            )
            return capsule.incident_id
        except (IncidentPersistenceError, OSError, ValueError):
            set_timing_incident(
                IncidentEvidence(
                    omission="write_failed",
                    capture_failure=CaptureFailure(
                        stage="persistence", reason="failed"
                    ),
                )
            )
            return None

    def _record_defense_error(
        self,
        provider: Provider,
        error: ProviderDefenseError,
        operation: TimingOperation,
    ) -> str | None:
        """Link the observed terminal response after containment has been armed."""
        fetch = error.fetch
        if operation is TimingOperation.SEARCH:
            incident_id = self._record_search_incident(provider, fetch, error)
            if incident_id is not None:
                self._attach_defense_incident(provider.key, incident_id)
        else:
            if fetch is None:
                # Keep the screenshot without manufacturing a response.
                set_timing_incident(
                    IncidentEvidence(
                        capture_failure=(
                            error.capture_failure
                            or CaptureFailure(stage="response", reason="unavailable")
                        )
                    )
                )
                return error.incident_id
            incident_id = self._record_retrieval_incident(
                provider,
                operation,
                fetch,
                ArticleAssessment(
                    access_state=AccessState.BLOCKED,
                    identity_match=False,
                    word_count=0,
                    reason="interactive_challenge",
                    session_cookie_present=fetch.session_cookie_present,
                ),
            )
        error.incident_id = incident_id
        return incident_id

    def _record_http_challenge(self, provider: Provider, fetch: RawFetch) -> None:
        """Retain a challenged primary response the browser leg did not recover."""

        operation = current_timing_operation()
        if operation not in {
            TimingOperation.SEARCH,
            TimingOperation.GET,
            TimingOperation.SAVE,
        }:
            return
        set_timing_incident(IncidentEvidence(omission="write_failed"))
        if operation is TimingOperation.SEARCH:
            self._record_search_incident(
                provider,
                fetch,
                ProviderTransportError("interactive_challenge"),
                primary=True,
            )
        else:
            self._record_retrieval_incident(
                provider,
                operation,
                fetch,
                ArticleAssessment(
                    access_state=AccessState.BLOCKED,
                    identity_match=False,
                    word_count=0,
                    reason="interactive_challenge",
                    session_cookie_present=fetch.session_cookie_present,
                ),
            )

    def _record_search_incident(
        self,
        provider: Provider,
        fetch: RawFetch | None,
        error: ProviderTransportError,
        *,
        primary: bool = False,
    ) -> str | None:
        prior = current_timing_incident()

        def unavailable(evidence: IncidentEvidence) -> str | None:
            # A failed terminal capture must not orphan the HTTP response
            # retained before browser fallback. Keep the gap explicit.
            if (
                not primary
                and prior is not None
                and prior.response_role == "primary"
                and prior.incident_id is not None
                and prior.omission is None
            ):
                evidence = prior.model_copy(
                    update={"capture_failure": evidence.capture_failure}
                )
            set_timing_incident(evidence)
            return evidence.incident_id

        if self._incidents is None:
            set_timing_incident(
                IncidentEvidence(
                    omission="not_configured",
                    capture_failure=CaptureFailure(
                        stage="persistence", reason="not_configured"
                    ),
                )
            )
            return None
        if fetch is None:
            failure = (
                error.capture_failure
                if isinstance(error, ProviderDefenseError)
                else None
            )
            return unavailable(
                IncidentEvidence(
                    capture_failure=(
                        failure
                        or CaptureFailure(stage="response", reason="unavailable")
                    )
                )
            )
        try:
            capsule = self._incidents.record_search(
                provider=provider.key,
                fetch=fetch,
                failure=(
                    SearchFailureKind.CONTRACT
                    if isinstance(error, ProviderContractError)
                    else SearchFailureKind.RESPONSE_REJECTED
                ),
            )
            self._incidents.retain_evidence(capsule)
            set_timing_incident(
                IncidentEvidence(
                    incident_id=capsule.incident_id,
                    response_role="primary" if primary else "terminal",
                    omission=None if capsule.capture_available else "capture_too_large",
                    capture_failure=(
                        None
                        if capsule.capture_available
                        else CaptureFailure(stage="persistence", reason="too_large")
                    ),
                )
            )
            return capsule.incident_id
        except (IncidentPersistenceError, OSError, ValueError):
            return unavailable(
                IncidentEvidence(
                    omission="write_failed",
                    capture_failure=CaptureFailure(
                        stage="persistence", reason="failed"
                    ),
                )
            )

    def archive_search(
        self,
        query: str,
        *,
        provider: str | None = None,
        limit: int | None = None,
    ) -> list[Article]:
        if provider is not None:
            self._registry.get(provider)
        if limit is not None and not 1 <= limit <= 100:
            raise UsageError("archive search limit must be between 1 and 100")
        return self._require_archive().search(
            query,
            provider=provider,
            limit=limit,
        )

    def archive_get(self, article_id: str) -> Article:
        if not article_id.strip():
            raise UsageError("archive article ID must not be empty")
        return self._require_archive().get(article_id)

    def reextract(self, article_id: str) -> Article:
        return self._require_archive().reextract(article_id)

    def archive_integrity(self) -> ArchiveIntegrity:
        return self._require_archive().integrity_check()

    def archive_rebuild_fts(self) -> ArchiveIntegrity:
        archive = self._require_archive()
        archive.rebuild_fts()
        return archive.integrity_check()

    def archive_backup(self, destination: Path) -> ArchiveBackupResult:
        self._require_archive().backup(destination)
        return ArchiveBackupResult()

    def archive_restore(self, source: Path) -> ArchiveIntegrity:
        archive = self._require_archive()
        archive.restore(source)
        return archive.integrity_check()

    def archive_drift(self, provider: str | None = None) -> DriftReport:
        """Re-assess archived raw fetches against their stored assessments.

        Read-only: reports drift for human review and never moves an
        extraction pointer (that stays an explicit ``reextract`` decision)."""

        if provider is not None:
            self._registry.get(provider)
        return detect_archive_drift(
            self._require_archive(),
            self._registry,
            self._extractor,
            provider=provider,
        )

    def _session_for(self, provider: Provider) -> SessionArtifact | None:
        if not provider.capabilities.requires_session_for_retrieve:
            return None
        if self._sessions is None:
            raise SessionRequiredError(
                f"{provider.key} retrieval requires an explicit login"
            )
        return self._sessions.get_valid_session(provider.key)

    def _session_manager(self) -> SessionManager:
        if self._sessions is None or not isinstance(self._sessions, SessionManager):
            raise PersistenceError("session manager is not configured")
        return self._sessions

    def requires_session_for_provider(self, provider_key: str) -> bool:
        """Whether this provider has an authenticated session at all.

        Scheduled upkeep asks first: a provider with no session has nothing to
        renew, and every session verb raises for it. Answering here keeps that
        knowledge with the capabilities rather than in the scheduler.
        """

        return self._registry.get(provider_key).capabilities.session_kind != "none"

    def _session_provider(self, provider_key: str) -> Provider:
        provider = self._registry.get(provider_key)
        if provider.capabilities.session_kind == "none":
            raise UsageError(f"{provider_key} does not use authenticated sessions")
        return provider

    def _require_archive(self) -> Archive:
        if self._archive is None:
            raise PersistenceError("archive is not configured")
        return self._archive

    def _prewarm_browser_for_retrieve(
        self,
        provider: Provider,
        session: SessionArtifact | None,
    ) -> None:
        """Open a keep-alive browser after search timing has closed."""

        if (
            session is None
            or provider.capabilities.retrieval_transport != "browser"
            or self._browser_retriever is None
            or not hasattr(self._browser_retriever, "warm")
        ):
            return
        try:
            self._browser_retriever.warm(session)
        except Exception:
            # Prewarm is opportunistic; the later save path opens if needed.
            return

    def _release_browser(self) -> None:
        if self._browser_retriever is not None:
            self._browser_retriever.release()

    def _provider_http(self, provider: Provider) -> HttpClient:
        """Return the rate-limited retrieval client for the provider.

        The transport is chosen by the provider's capability: the shared
        ``curl_cffi`` client for ``http``, or the shared core browser plane for
        ``browser`` (a profile-bound retriever that synthesizes a ``RawFetch``).
        Either way the returned object is rate-limited and HttpClient-shaped, so
        ``search``/``fetch``/``verify`` stay transport-agnostic.
        """

        return self._provider_transport(
            provider,
            transport=provider.capabilities.retrieval_transport,
            role=HttpOperationRole.FETCH,
        )

    def _provider_search_http(self, provider: Provider) -> HttpClient:
        """Return the provider-selected discovery transport."""

        return self._provider_transport(
            provider,
            transport=provider.capabilities.search_transport,
            role=HttpOperationRole.SEARCH,
        )

    def _provider_check_http(self, provider: Provider) -> HttpClient:
        return self._provider_transport(
            provider,
            transport=provider.capabilities.retrieval_transport,
            role=HttpOperationRole.FETCH,
            max_attempts=1,
            single_navigation=True,
        )

    def _provider_check_search_http(self, provider: Provider) -> HttpClient:
        return self._provider_transport(
            provider,
            transport=provider.capabilities.search_transport,
            role=HttpOperationRole.SEARCH,
            max_attempts=1,
            single_navigation=True,
        )

    def _provider_transport(
        self,
        provider: Provider,
        *,
        transport: str,
        role: HttpOperationRole,
        max_attempts: Literal[1, 2] = 2,
        single_navigation: bool = False,
    ) -> HttpClient:
        base = self._http
        if transport == "browser":
            if self._browser_retriever is None:
                raise PersistenceError(
                    f"browser retrieval plane is not configured for {provider.key}"
                )
            binder = getattr(self._browser_retriever, "for_provider", None)
            base = (
                binder(provider.key, role=role)
                if callable(binder)
                else self._browser_retriever
            )
            if single_navigation:
                if not isinstance(
                    base,
                    SingleNavigationBrowserRetriever,
                ):
                    raise PersistenceError(
                        "browser provider-check plane does not support "
                        "single navigation"
                    )
                base = SingleNavigationBrowserClient(base)
            return self._network.for_provider(
                provider.key,
                provider.rate_budget(),
                base,
                retry_response=getattr(provider, "retry_response", None),
                role=role,
                max_attempts=max_attempts,
            )
        primary = self._network.for_provider(
            provider.key,
            provider.rate_budget(),
            base,
            retry_response=getattr(provider, "retry_response", None),
            role=role,
            max_attempts=max_attempts,
        )
        classifier = getattr(provider, "is_interactive_challenge", None)
        if not callable(classifier):
            return primary
        fallback = self._challenge_browser_fallback(
            provider,
            role=role,
            single_navigation=single_navigation,
        )
        recorder = self._on_challenge_escalation_served
        browser_first = self._transport_browser_first
        provider_key = provider.key
        return ChallengeAwareHttpClient(
            provider_key,
            primary,
            is_challenge=classifier,
            browser_fallback=fallback,
            on_challenge_observed=lambda fetch: self._record_http_challenge(
                provider, fetch
            ),
            on_escalation_served=(
                # The refused fetch names the profile that was actually
                # refused. After a promotion the runtime pin differs from
                # the declared one, so reporting the declaration would
                # record rot against a profile that never served and leave
                # the dead pin governing every later fetch.
                (lambda fetch: recorder(provider_key, fetch.serving_transport))
                if recorder is not None
                else None
            ),
            # Rot is measured on article fetches; discovery (Reuters' sitemap)
            # keeps serving over HTTP, so only the fetch leg skips ahead.
            browser_first=(
                (lambda: browser_first(provider_key))
                if browser_first is not None and role is HttpOperationRole.FETCH
                else None
            ),
        )

    def _allows_http_challenge_fallback(self, provider: Provider) -> bool:
        if self._browser_retriever is None:
            return False
        if provider.capabilities.retrieval_challenge_escalation == "browser":
            return True
        predicate = getattr(self._browser_retriever, "allows_http_fallback", None)
        return bool(callable(predicate) and predicate(provider.key))

    def _challenge_browser_fallback(
        self,
        provider: Provider,
        *,
        role: HttpOperationRole,
        single_navigation: bool,
    ) -> HttpClient | None:
        if not self._allows_http_challenge_fallback(provider):
            return None
        if self._browser_retriever is None:  # pragma: no cover - predicate invariant
            return None
        binder = getattr(self._browser_retriever, "for_provider", None)
        if not callable(binder):
            raise PersistenceError(
                f"browser challenge fallback is not configured for {provider.key}"
            )
        browser: HttpClient = binder(provider.key, role=role)
        if single_navigation:
            if not isinstance(browser, SingleNavigationBrowserRetriever):
                raise PersistenceError(
                    "browser provider-check fallback does not support single navigation"
                )
            browser = SingleNavigationBrowserClient(browser)
        return self._network.for_provider(
            provider.key,
            provider.rate_budget(),
            browser,
            role=role,
            max_attempts=1,
        )

    def _timing_operation(
        self,
        operation: TimingOperation,
        providers: Sequence[Provider],
    ) -> AbstractContextManager[TimingOperationContext | None]:
        if self._timing is None:
            return nullcontext()
        provider = providers[0].key if len(providers) == 1 else "all"
        transports = {
            TimingTransport(
                item.capabilities.search_transport
                if operation is TimingOperation.SEARCH
                else item.capabilities.retrieval_transport
            )
            for item in providers
        }
        transport = (
            next(iter(transports)) if len(transports) == 1 else TimingTransport.MIXED
        )
        return self._timing.operation(
            operation,
            provider=provider,
            transport=transport,
        )

    def _non_full_session_probe(
        self,
        provider: Provider,
        session: SessionArtifact | None,
        evaluation: _RetrievalEvaluation,
        operation: TimingOperation,
    ) -> _SessionProbe | None:
        """Classify the session behind a non-``FULL`` target at most once.

        A teaser only asks whether the session is dead or the article is
        outside the subscription. A verified probe of this same session
        generation moments ago already answers that, so it is reused instead
        of relaunching a browser. Every other non-``FULL`` state still probes.
        """

        if evaluation.session_probe_performed:
            return evaluation.session_probe
        assessment = evaluation.assessment
        reusable = self._session_proofs.recent(provider.key, session)
        if assessment.access_state is AccessState.TEASER and reusable:
            set_timing_session_probe(SessionProbeOutcome.REUSED_VERIFIED)
            return _SessionProbe(SessionDisposition.VERIFIED)
        try:
            return self._classify_session(provider, session)
        except SessionRequiredError as error:
            if self._recovery_store is not None:
                error.incident_id = self._record_retrieval_incident(
                    provider, operation, evaluation.fetch, assessment
                )
            raise

    def _classify_session(
        self, provider: Provider, session: SessionArtifact | None
    ) -> _SessionProbe:
        """Probe once after a non-``FULL`` target to tell a dead session from a
        genuinely paywalled article (see ARCHITECTURE, "Sessions and
        authentication").

        Only a probe that positively resolves to ``AUTH_REQUIRED`` proves the
        session is dead; that downgrades the store under lock and raises
        ``SessionRequiredError``. A ``FULL`` probe proves the session is healthy
        (the target itself is not full). A teaser or any other inconclusive
        result (``UNKNOWN``/``BLOCKED``/HTTP-error) never proves a dead session.
        A teaser may request bounded warm recovery; unavailable and defended
        probes cannot request login recovery.
        """

        if session is None:
            set_timing_session_probe(SessionProbeOutcome.NOT_APPLICABLE)
            return _SessionProbe(None)
        recipe = getattr(provider, "login_recipe", None)
        if recipe is None:
            set_timing_session_probe(SessionProbeOutcome.NOT_APPLICABLE)
            return _SessionProbe(None)
        try:
            with (
                timing_step(TimingStep.SESSION_VERIFY, provider=provider.key),
                self._verification_client(provider) as client,
            ):
                verification = recipe.verify(client, session)
        except AccountAlertError as error:
            self._record_account_alert(provider, session, error, TimingOperation.GET)
            raise
        except ProviderTransportError as error:
            set_timing_session_probe(
                SessionProbeOutcome.TRANSPORT_ERROR,
                failure_reason=(
                    "authority_changed"
                    if isinstance(error, BrowserAuthorityChangedError)
                    else "transport_error"
                ),
            )
            return _SessionProbe(SessionDisposition.INCONCLUSIVE)
        verdict = verification_verdict(verification)
        set_timing_session_probe(
            SessionProbeOutcome(verdict.value),
            verification,
        )
        if verdict is SessionDisposition.VERIFIED:
            self._session_proofs.record(provider.key, session)
            return _SessionProbe(verdict)
        if verdict is SessionDisposition.DEAD:
            self._session_proofs.forget(provider.key)
            if self._sessions is not None:
                self._sessions.mark_required(
                    provider.key,
                    generation_id=getattr(session, "generation_id", None),
                )
            raise SessionRequiredError(f"{provider.key} session is no longer valid")
        # An unavailable or defended probe is not an entitlement signal.
        # Only a rendered teaser permits the bounded warm/profile recovery.
        return _SessionProbe(
            verdict, recovery_eligible=verification.access_state is AccessState.TEASER
        )

    def _verify_session_or_downgrade(
        self, provider: Provider, session: SessionArtifact
    ) -> None:
        """Eager probe for ``session-checkpoint``: proving access is the point,
        so any non-``FULL`` verification fails the checkpoint. A proven-dead
        result downgrades the stored status under lock; an inconclusive probe
        (``UNKNOWN``/``BLOCKED``) is an infrastructure signal, not a session
        verdict, so it surfaces as transport rather than steering the operator
        toward a needless re-login, as required by the session-verdict
        boundary."""

        recipe = getattr(provider, "login_recipe", None)
        if recipe is None:
            return
        try:
            with self._verification_client(provider) as client:
                verification = recipe.verify(client, session)
        except AccountAlertError as error:
            self._record_account_alert(provider, session, error, TimingOperation.GET)
            raise
        verdict = verification_verdict(verification)
        if verdict is SessionDisposition.VERIFIED:
            self._session_proofs.record(provider.key, session)
            return
        if verdict is SessionDisposition.DEAD:
            self._session_proofs.forget(provider.key)
            if self._sessions is not None:
                self._sessions.mark_required(
                    provider.key,
                    generation_id=getattr(session, "generation_id", None),
                )
            raise SessionRequiredError(
                f"{provider.key} session failed verification: {verification.reason}"
            )
        raise ProviderTransportError(
            f"{provider.key} session verification was inconclusive: "
            f"{verification.reason}"
        )

    @contextmanager
    def _verification_client(self, provider: Provider) -> Iterator[HttpClient]:
        if self._verification_client_factory is not None:
            with self._verification_client_factory(provider.key) as client:
                yield client
            return
        yield self._provider_http(provider)

    @contextmanager
    def _provider_check_verification_client(
        self,
        provider: Provider,
    ) -> Iterator[HttpClient]:
        if self._provider_check_verification_client_factory is not None:
            with self._provider_check_verification_client_factory(
                provider.key
            ) as client:
                yield client
            return
        yield self._provider_check_http(provider)


@dataclass
class _ProviderPagerState:
    provider: Provider
    buffer: deque[SearchResult] = field(default_factory=deque)
    next_url: str | None = None
    metadata_fetch_budget: int | None = None
    started: bool = False
    exhausted: bool = False
    terminal_error: NewsclipError | None = None
    retryable_error: NewsclipError | None = None
    fetched_urls: set[str] = field(default_factory=set)
    result_urls: set[str] = field(default_factory=set)
    result_count: int = 0
    missing_published_count: int = 0
    undated_excluded_count: int = 0
    coverage_start: datetime | None = None


class FederatedSearchPager:
    """Lazily merge provider-ranked streams for one in-process search."""

    _MAX_PROVIDER_FETCHES_PER_BATCH = 10
    #: Wall-clock budget for provider page fetches in one batch. Provider
    #: search requests time out at 8-10 s and the network policy may retry
    #: once after 1 s, so 45 s covers two fully retried requests (a result
    #: page plus a metadata fetch) while answering well inside the 120 s
    #: client timeout of the public-route watchdog. A slower source is
    #: reported as a retryable timeout rather than holding the response.
    _BATCH_DEADLINE_SECONDS = 45.0

    def __init__(
        self,
        service: NewsclipService,
        query: str,
        filters: SearchFilters,
        providers: Sequence[Provider],
        *,
        preflight_errors: dict[str, NewsclipError] | None = None,
        readers: dict[str, NewsclipService] | None = None,
        validations: Sequence[Callable[[], None]] = (),
    ) -> None:
        self._service = service
        self._readers = (
            {provider.key: service for provider in providers}
            if readers is None
            else readers
        )
        self._validations = validations
        self._query = query
        self._filters = filters
        errors = preflight_errors or {}
        self._states = tuple(
            _ProviderPagerState(
                provider=provider,
                exhausted=provider.key in errors,
                terminal_error=errors.get(provider.key),
            )
            for provider in providers
        )
        self._pending_band: deque[SearchResult] = deque()
        self._emitted_urls: set[str] = set()

    def next_batch(self, size: int) -> SearchResponse:
        for validate in self._validations:
            validate()
        # Provider pages run in worker threads. A Patchright context retained
        # by an interactive read between batches belongs to the caller thread
        # and must be closed here before search challenge fallback can enter
        # the browser plane.
        self._service._release_browser()
        providers = tuple(state.provider for state in self._states)
        with self._service._timing_operation(TimingOperation.SEARCH, providers):
            return self._next_batch(size)

    def _next_batch(self, size: int) -> SearchResponse:
        if size < 1 or size > 100:
            raise UsageError("search batch size must be between 1 and 100")

        for state in self._states:
            state.retryable_error = None
        fetch_counts = {state.provider.key: 0 for state in self._states}
        results: list[SearchResult] = []
        deadline = time.monotonic() + self._BATCH_DEADLINE_SECONDS

        while len(results) < size:
            if self._pending_band:
                candidate = self._pending_band.popleft()
                key = _exact_url_key(str(candidate.url))
                if key in self._emitted_urls:
                    continue
                self._emitted_urls.add(key)
                results.append(candidate)
                continue

            waiting = tuple(
                state
                for state in self._states
                if self._needs_fetch(state)
                and fetch_counts[state.provider.key]
                < self._MAX_PROVIDER_FETCHES_PER_BATCH
            )
            if waiting and time.monotonic() < deadline:
                self._fetch_pages(waiting, fetch_counts, deadline=deadline)
                continue

            band = [
                (state.provider.key, state.buffer.popleft())
                for state in self._states
                if state.buffer
            ]
            if band:
                band.sort(key=_search_band_key)
                self._pending_band.extend(result for _, result in band)
                continue
            break

        self._raise_if_every_source_failed()
        return SearchResponse(
            query=self._query,
            results=_ordered_search_batch(results, self._filters.sort),
            sources=self._source_reports(),
            has_more=self.has_more,
        )

    @property
    def has_more(self) -> bool:
        return bool(self._pending_band) or any(
            state.buffer
            or (
                not state.exhausted
                and state.terminal_error is None
                and (not state.started or state.next_url is not None)
            )
            for state in self._states
        )

    @staticmethod
    def _needs_fetch(state: _ProviderPagerState) -> bool:
        return (
            not state.buffer
            and not state.exhausted
            and state.terminal_error is None
            and state.retryable_error is None
            and (not state.started or state.next_url is not None)
        )

    def _fetch_pages(
        self,
        states: Sequence[_ProviderPagerState],
        fetch_counts: dict[str, int],
        *,
        deadline: float,
    ) -> None:
        def run(
            state: _ProviderPagerState,
            next_url: str | None,
            metadata_fetch_budget: int | None,
        ) -> tuple[ProviderSearchPage | None, NewsclipError | None]:
            try:
                return (
                    self._readers[state.provider.key]._search_provider_page(
                        state.provider,
                        self._query,
                        self._filters,
                        next_url=next_url,
                        metadata_fetch_budget=metadata_fetch_budget,
                    ),
                    None,
                )
            except _SEARCH_FAILURES as error:
                return None, error

        # Not a context manager: leaving one joins every worker, which is
        # exactly the wait the deadline exists to bound.
        executor = ThreadPoolExecutor(max_workers=len(states))
        try:
            futures = {
                state.provider.key: executor.submit(
                    copy_context().run,
                    run,
                    state,
                    state.next_url,
                    state.metadata_fetch_budget,
                )
                for state in states
            }
            wait(
                futures.values(),
                timeout=max(0.0, deadline - time.monotonic()),
            )
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        for state in states:
            key = state.provider.key
            fetch_counts[key] += 1
            future = futures[key]
            if not future.done() or future.cancelled():
                # A straggler is abandoned, never collected: its worker keeps
                # running to its own transport timeouts, but only this caller
                # thread applies a page to pager state, and it never reads
                # this future again. The request keeps its continuation, so
                # the next batch re-requests the same page; nothing a late
                # result carries can advance, duplicate, or reorder it.
                state.retryable_error = ProviderTransportError(
                    f"{key} search page exceeded the batch deadline",
                    category=TransportFailure.TIMEOUT,
                )
                continue
            page, error = future.result()
            if error is not None:
                if state.started and not isinstance(error, ProviderContractError):
                    state.retryable_error = error
                else:
                    state.terminal_error = error
                    state.exhausted = True
                    state.next_url = None
                continue
            assert page is not None
            self._accept_page(state, page)

    def _accept_page(
        self,
        state: _ProviderPagerState,
        page: ProviderSearchPage,
    ) -> None:
        requested_url = state.next_url
        if requested_url is not None:
            state.fetched_urls.add(requested_url)
        if page.next_url is not None and (
            page.next_url == requested_url or page.next_url in state.fetched_urls
        ):
            state.terminal_error = ProviderContractError(
                f"{state.provider.key} search continuation loop detected"
            )
            state.retryable_error = None
            state.exhausted = True
            state.next_url = None
            return

        state.started = True
        state.retryable_error = None
        state.next_url = page.next_url
        state.metadata_fetch_budget = page.remaining_metadata_fetches
        state.undated_excluded_count += page.undated_excluded_count
        # Later pages can only reach further back, so the earliest claim across
        # the pages actually fetched is the coverage the caller was served.
        if page.coverage_start is not None:
            state.coverage_start = (
                page.coverage_start
                if state.coverage_start is None
                else min(state.coverage_start, page.coverage_start)
            )
        for result in page.results:
            key = _exact_url_key(str(result.url))
            if key in state.result_urls:
                continue
            state.result_urls.add(key)
            state.result_count += 1
            state.missing_published_count += result.published is None
            state.buffer.append(result)
        if page.next_url is None:
            state.exhausted = True

    def _source_reports(self) -> tuple[SourceSearchReport, ...]:
        reports: list[SourceSearchReport] = []
        for state in self._states:
            reader = self._readers.get(state.provider.key)
            contained = (
                reader.defense_contained_until(state.provider.key) if reader else None
            )
            error = state.terminal_error or state.retryable_error
            if error is not None:
                reports.append(
                    _source_failure_report(
                        state.provider.key,
                        error,
                        retrieval_contained_until=contained,
                    )
                )
                continue
            reports.append(
                SourceSearchReport(
                    provider=state.provider.key,
                    state=SourceSearchState.OK,
                    result_count=state.result_count,
                    missing_published_count=state.missing_published_count,
                    undated_excluded_count=state.undated_excluded_count,
                    coverage_start=state.coverage_start,
                    retrieval_contained_until=contained,
                )
            )
        return tuple(reports)

    def _raise_if_every_source_failed(self) -> None:
        if any(state.started for state in self._states):
            return
        errors = tuple(
            error
            for state in self._states
            if (error := state.terminal_error or state.retryable_error) is not None
        )
        if len(errors) == len(self._states):
            _raise_aggregate_search_failure(errors)


def _search_leg_failure(
    provider: Provider,
    fetch: RawFetch | None,
    *,
    otherwise: ProviderCheckFailure = ProviderCheckFailure.SEARCH_TRANSPORT,
) -> ProviderCheckFailure:
    """Classify a failed search leg, honoring provider-defense evidence.

    The retrieval leg already reads a 403/429 or a challenge-classified
    response as provider defense. The same evidence must not degrade merely
    because the search leg observed it first. A transient failure records no
    hold, so a scheduled check would keep requesting from a provider that is
    actively refusing; a contract failure would instead route an operator to
    hunt for parser drift. A challenge page can produce either, because a
    served challenge may parse cleanly and simply carry no results.
    """

    if fetch is None:
        return otherwise
    if fetch.http_status in {403, 429}:
        return ProviderCheckFailure.PROVIDER_DEFENSE
    classifier = getattr(provider, "is_interactive_challenge", None)
    if callable(classifier) and classifier(fetch):
        return ProviderCheckFailure.PROVIDER_DEFENSE
    return otherwise


def _provider_check_failure(
    provider: str,
    failure: ProviderCheckFailure,
    *,
    search_result_count: int = 0,
    incident_id: str | None = None,
) -> ProviderCheckResult:
    return ProviderCheckResult(
        provider=provider,
        ok=False,
        failure=failure,
        search_result_count=search_result_count,
        incident_id=incident_id,
    )


def _provider_check_assessed_result(
    provider: str,
    evidence: ContentAssessmentEvidence,
    *,
    http_status: int,
    search_result_count: int,
    failure: ProviderCheckFailure | None = None,
    session_disposition: SessionDisposition | None = None,
    incident_id: str | None = None,
) -> ProviderCheckResult:
    return ProviderCheckResult(
        provider=provider,
        ok=failure is None,
        failure=failure,
        search_result_count=search_result_count,
        http_status=http_status,
        access_state=evidence.access_state,
        reason=evidence.reason,
        identity_match=evidence.identity_match,
        word_count=evidence.word_count,
        session_disposition=session_disposition,
        incident_id=incident_id,
    )


def _source_failure_report(
    provider: str,
    error: NewsclipError,
    *,
    retrieval_contained_until: datetime | None = None,
) -> SourceSearchReport:
    if isinstance(error, OperatorActionRequiredError):
        state = SourceSearchState.NEEDS_ATTENTION
        reason = SourceSearchReason.OPERATOR_ACTION
    elif isinstance(error, SessionRequiredError):
        state = SourceSearchState.NEEDS_ATTENTION
        reason = SourceSearchReason.SESSION_REQUIRED
    elif isinstance(error, UnsearchableQueryError):
        state = SourceSearchState.UNAVAILABLE
        reason = SourceSearchReason.UNSEARCHABLE_QUERY
    elif isinstance(error, ProviderContractError):
        state = SourceSearchState.UNAVAILABLE
        reason = SourceSearchReason.CONTRACT
    elif isinstance(error, PersistenceError):
        state = SourceSearchState.UNAVAILABLE
        reason = SourceSearchReason.PERSISTENCE
    elif isinstance(error, ProviderDefenseError):
        state = SourceSearchState.UNAVAILABLE
        reason = SourceSearchReason.PROVIDER_DEFENSE
    elif isinstance(error, ProviderTransportError):
        state = SourceSearchState.UNAVAILABLE
        reason = {
            TransportFailure.TIMEOUT: SourceSearchReason.TIMEOUT,
            TransportFailure.DNS: SourceSearchReason.DNS,
            TransportFailure.TRANSPORT: SourceSearchReason.TRANSPORT,
            TransportFailure.RATE_LIMITED: SourceSearchReason.RATE_LIMITED,
            TransportFailure.PROVIDER_ERROR: SourceSearchReason.PROVIDER_ERROR,
        }[error.category]
    else:  # pragma: no cover - private caller invariant
        raise AssertionError("unsupported search failure")
    return SourceSearchReport(
        provider=provider,
        state=state,
        result_count=0,
        reason=reason,
        retrieval_contained_until=retrieval_contained_until,
    )


def _native_evaluation(
    fetch: RawFetch,
    native: ProviderNativeExtractionResult,
    *,
    session_probe_performed: bool = False,
) -> _RetrievalEvaluation:
    extraction = native.extraction
    assessment = native.assessment
    extractor_name = native.extractor_name
    extractor_version = native.extractor_version
    if (
        extraction is None
        or assessment is None
        or extractor_name is None
        or extractor_version is None
    ):
        raise AssertionError("valid native extraction omitted candidate fields")
    return _RetrievalEvaluation(
        fetch=fetch,
        extraction=extraction,
        assessment=assessment,
        extractor_name=extractor_name,
        extractor_version=extractor_version,
        session_probe_performed=session_probe_performed,
    )


def _record_content_failure(assessment: ArticleAssessment) -> None:
    """Promote closed assessment facts into the active operation trace."""

    if (
        assessment.access_state is AccessState.BLOCKED
        and assessment.reason == "interactive_challenge"
    ):
        failure = MintFailureEvidence(
            stage=MintFailureStage.CHALLENGE,
            category=MintFailureCategory.CHALLENGE_BLOCKED,
        )
    else:
        failure = MintFailureEvidence(
            stage=MintFailureStage.PAID_PROBE,
            category=MintFailureCategory.ARTICLE_NOT_FULL,
        )
    set_timing_failure(failure)


def _assessed_challenge_is_corroborated(
    fetch: RawFetch,
    assessment: ArticleAssessment,
) -> bool:
    """Require transport refusal before an assessed challenge arms containment."""

    return (
        assessment.reason == "interactive_challenge"
        and not 200 <= fetch.http_status < 300
    )


def _raise_aggregate_search_failure(errors: tuple[NewsclipError, ...]) -> NoReturn:
    for error in errors:
        if isinstance(error, OperatorActionRequiredError):
            raise error
    for error in errors:
        if isinstance(error, SessionRequiredError):
            raise error
    if errors and all(isinstance(error, PersistenceError) for error in errors):
        raise errors[0]
    # Only when *every* selected source rejected the query is the query itself
    # the answer. If one source merely timed out, that failure is the story and
    # the generic aggregate below is still right.
    if errors and all(isinstance(error, UnsearchableQueryError) for error in errors):
        raise errors[0]

    category = TransportFailure.TRANSPORT
    if errors and all(isinstance(error, ProviderTransportError) for error in errors):
        transport_errors = [
            error for error in errors if isinstance(error, ProviderTransportError)
        ]
        categories = {error.category for error in transport_errors}
        if len(categories) == 1:
            candidate = categories.pop()
            if candidate in (TransportFailure.TIMEOUT, TransportFailure.DNS):
                category = candidate
    raise ProviderTransportError(
        "search failed for all selected providers",
        category=category,
    )


def _search_band_key(item: tuple[str, SearchResult]) -> tuple[bool, float, str]:
    provider, result = item
    published = result.published
    return (
        published is None,
        -published.timestamp() if published is not None else 0.0,
        provider,
    )


def _ordered_search_batch(
    results: Sequence[SearchResult],
    order: SearchSort,
) -> tuple[SearchResult, ...]:
    """Return one presentation-ordered batch without changing its selection."""

    if order is SearchSort.NEWEST:
        return tuple(sorted(results, key=_newest_search_key))
    return tuple(results)


def _newest_search_key(result: SearchResult) -> tuple[bool, float, str, str]:
    published = result.published
    return (
        published is None,
        -published.timestamp() if published is not None else 0.0,
        result.provider,
        _exact_url_key(str(result.url)),
    )


def _exact_url_key(url: str) -> str:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    default_port = (scheme == "https" and port == 443) or (
        scheme == "http" and port == 80
    )
    netloc = host if port is None or default_port else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
