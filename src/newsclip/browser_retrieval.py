"""Shared core browser-retrieval plane (optional browser extra).

A profile-bound Patchright context retrieves the caller's URL and synthesizes a
``RawFetch`` so the rest of the core — ``assess``, archive, redaction — treats
browser retrieval exactly like an HTTP retrieval. The provider decides
*whether* to use this plane via
``ProviderCapabilities.retrieval_transport``; it never encodes provider page
knowledge here.

This concrete adapter needs a real browser and a durable profile directory, so
it is exercised by live promotion gates, not the offline suite. The plane's
transport-agnostic wiring (selection, rate-limiting, RawFetch synthesis) is
covered offline through an injected fake retriever.

Warm retrieval can keep one live Chromium context at a time, keyed by durable
profile. Chromium's ProcessSingleton cannot open the same profile twice, so the
profile lease is held for as long as that context stays open. Long-lived server
processes can instead disable retention; each browser operation then closes its
context and releases the profile lease before leaving the retriever lock.
"""

from __future__ import annotations

import atexit
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from pydantic import ValidationError

from .acquisition import (
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
)
from .browser_readiness import (
    BrowserReadinessObservation,
    BrowserSemanticSnapshot,
    ReadinessCoverageBucket,
    SemanticReadinessRejected,
    await_semantic_snapshot,
)
from .browser_runtime import (
    AttemptPurpose,
    BrowserLaunchConfig,
    BrowserRuntimeError,
    HeldProfileLease,
    HttpOperationRole,
    InfrastructureCategory,
    LeaseBusyError,
    LeaseManager,
    PatchrightMintContext,
    PatchrightRuntime,
    ensure_virtual_display,
)
from .browser_verification import MainDocumentResponse
from .challenge_resolver import (
    ChallengeResolutionStatus,
    ChallengeResolver,
)
from .challenges import ChallengeInfrastructureError, ChallengeMode
from .errors import (
    BrowserAuthorityChangedError,
    ContentNotFullError,
    NewsclipError,
    PersistenceError,
    ProviderDefenseError,
    ProviderTransportError,
    TransportFailure,
)
from .models import (
    CaptureFailure,
    PortableCookie,
    RawFetch,
    RetrievalDiagnostics,
    SessionArtifact,
)
from .provider_config import BrowserRetrievalSpec, BrowserSemanticReadinessSpec
from .session_cookies import (
    is_challenge_vendor_cookie,
    normalize_browser_cookie_export,
)
from .timing import TimingStep, timing_step

_DEFAULT_POLICY = BrowserRetrievalSpec()

#: Wall-clock ceiling for one browser read, from entry (including the wait for
#: the plane lock) to its result. The public-route watchdog gives each ``get``
#: 120 s; 100 s leaves room for session load, rate-budget waits, assessment,
#: archive and the bounded failure screenshot around the browser work. It is a
#: ceiling only: every step keeps its configured budget while time remains.
#: Challenge mechanics keep their own wall budgets (DataDome 60 s, PerimeterX
#: 45 s, Cloudflare 15 s) and are not interrupted; one started before the
#: ceiling can overrun it by at most that budget, and the next step then fails.
BROWSER_OPERATION_CEILING_SECONDS = 100.0
#: Longest one read waits for another thread's browser operation. The plane
#: runs one operation at a time; a normal warm read finishes well inside this,
#: while a holder still busy after it is in a challenge or a slow recovery,
#: and waiting further would spend the MCP worker and the caller's budget.
BROWSER_LOCK_WAIT_SECONDS = 30.0


@runtime_checkable
class SingleNavigationBrowserRetriever(Protocol):
    def get_for_check(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch: ...


@dataclass
class _HeldProfile:
    profile: Path
    lease: HeldProfileLease
    page: Any
    factory_context: Any = None
    browser: PatchrightMintContext | None = None


@dataclass(frozen=True)
class _DirectChallengeBrowser:
    """Minimal challenge surface for injected non-runtime browser factories."""

    page: Any

    def dispatch_challenge_action(self, dispatch: Callable[[], Any]) -> Any:
        return dispatch()


class _OperationBudget:
    """One read's deadline plus whether provider navigation has begun.

    Navigation is the retry boundary: before it, no request reached the
    provider and a relaunch is safe; after it, a second launch would repeat
    the provider navigation.
    """

    def __init__(self, clock: Callable[[], float], ceiling_seconds: float) -> None:
        self._clock = clock
        self._deadline = clock() + ceiling_seconds
        self.navigation_started = False

    def remaining(self) -> float:
        return self._deadline - self._clock()

    def bound(self, seconds: float) -> float:
        """Clamp one step's own timeout to the time left, never lengthen it."""

        remaining = self.remaining()
        if remaining <= 0:
            raise _deadline_exceeded()
        return min(seconds, remaining)

    def require(self, seconds: float) -> None:
        """Refuse to start a step whose truncation would change its verdict."""

        if self.remaining() < seconds:
            raise _deadline_exceeded()


def _deadline_exceeded() -> ProviderTransportError:
    return ProviderTransportError(
        "browser operation deadline exceeded",
        category=TransportFailure.TIMEOUT,
        retryable=False,
    )


BrowserReadinessEvaluator = Callable[[RawFetch], BrowserReadinessObservation]


class BrowserSnapshotRejected(ContentNotFullError):
    """Private terminal browser snapshot rejected by semantic readiness."""

    def __init__(
        self,
        *,
        fetch: RawFetch,
        snapshot: BrowserSemanticSnapshot,
    ) -> None:
        super().__init__("browser_semantic_readiness_timeout")
        self.fetch = fetch
        self.snapshot = snapshot


@dataclass
class _ProfileVerificationCapture:
    """Private authority exported from the context that supplied one paid probe."""

    cookies: tuple[PortableCookie, ...] | None = field(default=None, repr=False)
    used: bool = False


class ProviderBoundBrowserClient:
    """Bind the shared browser plane to one provider, including public profiles."""

    def __init__(
        self,
        retriever: PatchrightBrowserRetriever,
        provider: str,
        role: HttpOperationRole,
        *,
        profile_capture: _ProfileVerificationCapture | None = None,
    ) -> None:
        self._retriever = retriever
        self.provider = provider
        self._role = role
        self._profile_capture = profile_capture

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        return self._retriever._get_for_provider(
            self.provider,
            url,
            session=session,
            timeout=timeout,
            role=self._role,
            allow_warmups=True,
            profile_capture=self._profile_capture,
        )

    def get_for_check(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        """Navigate once to the requested canary without recovery warm-ups."""

        return self._retriever._get_for_provider(
            self.provider,
            url,
            session=session,
            timeout=timeout,
            role=self._role,
            allow_warmups=False,
            profile_capture=self._profile_capture,
        )


class PatchrightBrowserRetriever:
    """Retrieve one URL through a profile-bound browser context."""

    def __init__(
        self,
        *,
        headless: bool = True,
        context_factory: Callable[..., object] | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        lease_manager: LeaseManager | None = None,
        runtime: PatchrightRuntime | None = None,
        profile_resolver: Callable[..., Path] | None = None,
        policies: Mapping[str, BrowserRetrievalSpec] | None = None,
        readiness_evaluators: Mapping[str, BrowserReadinessEvaluator] | None = None,
        verification_readiness_evaluators: Mapping[str, BrowserReadinessEvaluator]
        | None = None,
        launch_configs: Mapping[str, BrowserLaunchConfig] | None = None,
        challenge_resolvers: Mapping[str, ChallengeResolver] | None = None,
        challenge_mode: ChallengeMode = ChallengeMode.DETECT_ONLY,
        require_virtual_display: bool = False,
        retain_profile: bool = True,
        session_cookie_domains: Mapping[str, frozenset[str]] | None = None,
        authorize_session: Callable[[SessionArtifact], None] | None = None,
    ) -> None:
        self._headless = headless
        self._context_factory = context_factory
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._leases = lease_manager or LeaseManager(
            Path.home() / ".local/state/newsclip/locks"
        )
        self._runtime = runtime
        self._profile_resolver = profile_resolver
        self._policies = dict(policies or {})
        self._readiness_evaluators = dict(readiness_evaluators or {})
        self._verification_readiness_evaluators = dict(
            verification_readiness_evaluators or {}
        )
        semantic_providers = {
            provider
            for provider, policy in self._policies.items()
            if policy.semantic_readiness is not None
        }
        missing_evaluators = semantic_providers - self._readiness_evaluators.keys()
        unused_evaluators = (
            self._readiness_evaluators.keys()
            | self._verification_readiness_evaluators.keys()
        ) - self._policies.keys()
        if missing_evaluators or unused_evaluators:
            raise ValueError(
                "semantic browser readiness configuration mismatch: "
                f"missing={sorted(missing_evaluators)}, "
                f"unused={sorted(unused_evaluators)}"
            )
        self._launch_configs = dict(launch_configs or {})
        self._challenge_resolvers = dict(challenge_resolvers or {})
        if challenge_resolvers is not None:
            missing_resolvers = self._policies.keys() - self._challenge_resolvers.keys()
            unused_resolvers = self._challenge_resolvers.keys() - self._policies.keys()
            if missing_resolvers or unused_resolvers:
                raise ValueError(
                    "browser challenge resolver configuration mismatch: "
                    f"missing={sorted(missing_resolvers)}, "
                    f"unused={sorted(unused_resolvers)}"
                )
        self._challenge_mode = challenge_mode
        self._require_virtual_display = require_virtual_display
        self._retain_profile = retain_profile
        self._session_cookie_domains = dict(session_cookie_domains or {})
        self._authorize_session = authorize_session
        self._lock = threading.RLock()
        self._held: _HeldProfile | None = None
        self._closed = False
        atexit.register(self.close)

    def close(self) -> None:
        """Release any kept-alive browser and its profile lease."""

        with self._lock:
            self._closed = True
            self._release_held()
        with suppress(Exception):
            atexit.unregister(self.close)

    def warm(
        self,
        session: SessionArtifact,
        *,
        affinity_url: str | None = None,
    ) -> None:
        """Open (or reuse) the durable profile so a later get skips browser_open.

        When ``affinity_url`` is set, perform a bounded first navigation so the
        subsequent article get is not the cold first paint for Chromium.
        """

        with self._lock:
            if self._closed or not self._retain_profile:
                return
            if self._authorize_session is not None:
                self._authorize_session(session)
            page, _recovery = self._ensure_page(
                Path(self._profile_ref(session.provider, session)),
                provider=session.provider,
                portable_cookies=tuple(session.cookies),
            )
            # Affinity navigation is intentionally omitted: a homepage hop can
            # cost more than it saves on the subsequent article get.

    def release(self) -> None:
        """Release retained browser state without permanently closing the plane."""

        with self._lock:
            self._release_held()

    def for_provider(
        self,
        provider: str,
        *,
        role: HttpOperationRole = HttpOperationRole.FETCH,
    ) -> ProviderBoundBrowserClient:
        """Return an HTTP-compatible view with explicit provider ownership."""

        if provider not in self._policies:
            raise ValueError(f"browser retrieval policy is unavailable: {provider}")
        return ProviderBoundBrowserClient(self, provider, role)

    def allows_http_fallback(self, provider: str) -> bool:
        resolver = self._challenge_resolvers.get(provider)
        return resolver is not None and bool(resolver.supported_vendors)

    def profile_verification_client(
        self, provider: str
    ) -> tuple[ProviderBoundBrowserClient, _ProfileVerificationCapture]:
        """One explicit warm probe; imports keep the strict candidate client."""
        if provider not in self._policies:
            raise ValueError("browser verification policy is unavailable")
        capture = _ProfileVerificationCapture()
        return ProviderBoundBrowserClient(
            self, provider, HttpOperationRole.VERIFICATION, profile_capture=capture
        ), capture

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        if session is None:
            raise ValueError("browser retrieval requires a verified session artifact")
        return self._get_for_provider(
            session.provider,
            url,
            session=session,
            timeout=timeout,
            role=HttpOperationRole.FETCH,
            allow_warmups=True,
        )

    def get_for_check(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        """Navigate only to the requested canary, without recovery warm-ups."""

        if session is None:
            raise ValueError("browser retrieval requires a verified session artifact")
        return self._get_for_provider(
            session.provider,
            url,
            session=session,
            timeout=timeout,
            role=HttpOperationRole.FETCH,
            allow_warmups=False,
        )

    def _get_for_provider(
        self,
        provider: str,
        url: str,
        *,
        session: SessionArtifact | None,
        timeout: float,
        role: HttpOperationRole,
        allow_warmups: bool,
        profile_capture: _ProfileVerificationCapture | None = None,
    ) -> RawFetch:
        if profile_capture is not None and (
            role is not HttpOperationRole.VERIFICATION or profile_capture.used
        ):
            raise ProviderTransportError(
                "browser profile verification must navigate once"
            )
        if profile_capture is not None:
            profile_capture.used = True
        profile_ref = self._profile_ref(provider, session)
        portable_cookies = tuple(getattr(session, "cookies", ()))
        policy = (
            _DEFAULT_POLICY
            if role is HttpOperationRole.SEARCH
            else self._policies.get(provider, _DEFAULT_POLICY)
        )
        budget = _OperationBudget(
            self._monotonic_clock, BROWSER_OPERATION_CEILING_SECONDS
        )
        # One live persistent context per profile: Chromium's ProcessSingleton
        # fails (and can corrupt the account-bearing profile) on a concurrent
        # second launch, which the MCP worker pool would otherwise permit.
        try:
            with self._operation_lock(budget):
                try:
                    if session is not None and self._authorize_session is not None:
                        self._authorize_session(session)
                    if self._closed:
                        raise ProviderTransportError(
                            "browser retrieval plane is closed"
                        )
                    page, recovery = self._ensure_page(
                        Path(profile_ref),
                        provider=provider,
                        portable_cookies=portable_cookies,
                    )
                    held_browser = (
                        self._held.browser if self._held is not None else None
                    )
                    if (
                        role is HttpOperationRole.VERIFICATION
                        and session is not None
                        and profile_capture is None
                    ):
                        self._assert_candidate_authority(session)
                    attempt = (
                        held_browser.attempt(
                            provider,
                            _attempt_purpose(role),
                            profile_scope="account"
                            if session is not None
                            else "public",
                        )
                        if held_browser is not None and provider
                        else nullcontext()
                    )
                    with attempt, MainDocumentResponse(page) as document:
                        response = None
                        try:
                            response = self._navigate_with_policy(
                                page,
                                url=url,
                                timeout_seconds=timeout,
                                policy=policy,
                                recovery=recovery,
                                allow_warmups=allow_warmups,
                                budget=budget,
                                navigation_step=(
                                    TimingStep.VERIFICATION_NAVIGATION
                                    if role is HttpOperationRole.VERIFICATION
                                    else TimingStep.ARTICLE_NAVIGATION
                                ),
                            )
                            if response is None:
                                raise ProviderTransportError(
                                    "browser navigation produced no HTTP response"
                                )
                            response_content_type = _response_content_type(response)
                            budget.require(0)
                            (
                                self._resolve_challenge(
                                    provider,
                                    held_browser or _DirectChallengeBrowser(page),
                                )
                                if _is_html(response_content_type)
                                else ChallengeResolutionStatus.NOT_PRESENT
                            )
                            response = document.select(response)
                            status = response.status
                            with timing_step(TimingStep.CONTENT_READ):
                                content_type, content = _response_content(
                                    response,
                                    page,
                                )
                                readiness = policy.semantic_readiness
                                if readiness is not None and _is_html(content_type):
                                    evaluator = self._readiness_evaluators[provider]
                                    if role is HttpOperationRole.VERIFICATION:
                                        # Delivered content can be ready before
                                        # its rendered entitlement proof.
                                        evaluator = (
                                            self._verification_readiness_evaluators.get(
                                                provider, evaluator
                                            )
                                        )
                                    # Truncated sampling would turn a
                                    # slow render into a content verdict.
                                    budget.require(readiness.timeout_seconds)
                                    content = self._await_semantic_readiness(
                                        page,
                                        requested_url=url,
                                        status=status,
                                        content_type=content_type,
                                        initial_content=content,
                                        session_cookie_present=session is not None,
                                        readiness=readiness,
                                        evaluator=evaluator,
                                        browser=held_browser,
                                    )
                            document.assert_current(response)
                            result = _raw_fetch(
                                requested_url=url,
                                final_url=page.url,
                                status=status,
                                content_type=content_type,
                                retrieved_at=self._clock(),
                                content=content,
                                session_cookie_present=session is not None,
                            )
                            result = self._attach_terminal_evidence(
                                provider,
                                result,
                                held_browser,
                                assess=role is not HttpOperationRole.SEARCH,
                            )
                            if profile_capture is not None:
                                profile_capture.cookies = self._export_profile_cookies(
                                    provider
                                )
                            if (
                                role is HttpOperationRole.VERIFICATION
                                and held_browser is not None
                            ):
                                # The recipe assesses this response after the context
                                # closes. Preserve its viewport before that handoff.
                                held_browser.capture_diagnostic_screenshot("paid-proof")
                        except BaseException as error:
                            if isinstance(error, ProviderDefenseError):
                                diagnostics = (
                                    held_browser.capture_incident_evidence(
                                        "failure", timeout_ms=5_000
                                    )
                                    if held_browser
                                    else RetrievalDiagnostics(
                                        screenshot_status="capture_failed"
                                    )
                                )
                                # Inspect the already committed document only.
                                # Never invent status/identity or navigate again
                                # to obtain a diagnostic response.
                                failure: CaptureFailure | None = CaptureFailure(
                                    stage="response", reason="unavailable"
                                )
                                try:
                                    if response is not None:
                                        failure = CaptureFailure(
                                            stage="document_identity", reason="failed"
                                        )
                                        terminal = document.select(response)
                                        failure = CaptureFailure(
                                            stage="content_read", reason="failed"
                                        )
                                        content_type, content = _response_content(
                                            terminal, page
                                        )
                                        failure = CaptureFailure(
                                            stage="document_identity", reason="failed"
                                        )
                                        document.assert_current(terminal)
                                        failure = CaptureFailure(
                                            stage="capture_validation", reason="failed"
                                        )
                                        error.fetch = _raw_fetch(
                                            requested_url=url,
                                            final_url=page.url,
                                            status=terminal.status,
                                            content_type=content_type,
                                            retrieved_at=self._clock(),
                                            content=content,
                                            session_cookie_present=session is not None,
                                        ).model_copy(
                                            update={"diagnostics": diagnostics}
                                        )
                                        failure = None
                                except Exception as capture_error:
                                    if (
                                        failure is not None
                                        and failure.stage == "document_identity"
                                        and isinstance(
                                            capture_error, ProviderTransportError
                                        )
                                        and str(capture_error)
                                        == "browser response document changed"
                                    ):
                                        failure = CaptureFailure(
                                            stage="document_identity", reason="changed"
                                        )
                                if failure is not None:
                                    error.capture_failure = failure
                                    if held_browser is not None:
                                        with suppress(Exception):
                                            held_browser.record_capture_failure(failure)
                            elif (
                                isinstance(error, BrowserSnapshotRejected)
                                and held_browser
                            ):
                                evidence = held_browser.capture_incident_evidence(
                                    "failure", timeout_ms=5_000
                                )
                                error.fetch = error.fetch.model_copy(
                                    update={"diagnostics": evidence}
                                )
                            elif held_browser is not None:
                                held_browser.capture_diagnostic_screenshot(
                                    "failure",
                                    timeout_ms=5_000,
                                )
                            raise
                except BaseException:
                    # Cleanup stays inside the operation lock so a failing
                    # request cannot release a later request's context.
                    with suppress(Exception):
                        self._release_held()
                    raise
                if role is HttpOperationRole.SEARCH:
                    # Federated provider pages run in short-lived worker
                    # threads. Patchright's synchronous driver is thread-bound,
                    # so a search browser cannot survive that worker and later
                    # be reused by the interactive caller. Cleanup is part of
                    # the successful handoff and must surface if it fails.
                    self._release_held()
                elif not self._retain_profile:
                    # The MCP singleton uses request-scoped profile ownership.
                    # Release before another worker can enter this retriever.
                    if role is HttpOperationRole.VERIFICATION:
                        self._release_held()
                    else:
                        with suppress(Exception):
                            self._release_held()
                return result
        except ChallengeInfrastructureError as error:
            raise ProviderTransportError(
                "browser challenge handling failed",
                retryable=False,
            ) from error
        except LeaseBusyError as error:
            # Another owner holds the profile or attempt. A relaunch a second
            # later meets the same owner, so the policy must not spend one.
            raise ProviderTransportError(
                "browser profile is busy", retryable=False
            ) from error
        except BrowserRuntimeError as error:
            if error.profile_ownership_failure:
                raise PersistenceError(error.category.value) from error
            # The runtime raises a bare RuntimeError that no public classifier
            # maps, so it must join the transport taxonomy before it can leave
            # this plane. Only the bounded infrastructure category is carried.
            # A target that closes before the first page opens is transient and
            # safe to retry because no provider navigation occurred. Every
            # other runtime category describes deterministic local
            # infrastructure and must not spend a second launch.
            raise ProviderTransportError(
                f"browser runtime unavailable: {error.category.value}",
                retryable=(
                    error.category
                    is InfrastructureCategory.BROWSER_STARTUP_TARGET_CLOSED
                    and not budget.navigation_started
                ),
            ) from error
        except NewsclipError as error:
            if (
                budget.navigation_started
                and type(error) is ProviderTransportError
                and error.retryable
            ):
                # The provider was already contacted; a policy retry would
                # relaunch and navigate again. Keep the classification.
                raise ProviderTransportError(
                    str(error), category=error.category, retryable=False
                ) from error
            raise
        except ValidationError as error:
            raise ProviderTransportError(
                "browser response metadata is invalid",
                retryable=not budget.navigation_started,
            ) from error
        except Exception as error:
            # Browser/driver failures join the transport taxonomy so the
            # read-path classify rule ("infrastructure never downgrades")
            # holds on this plane too. Only the exception class is carried;
            # driver messages may embed page content. Once navigation began,
            # a retry would repeat it, so only earlier failures stay
            # retryable.
            raise ProviderTransportError(
                f"browser retrieval failed: {type(error).__name__}",
                retryable=not budget.navigation_started,
            ) from error

    @contextmanager
    def _operation_lock(self, budget: _OperationBudget) -> Iterator[None]:
        wait_seconds = min(BROWSER_LOCK_WAIT_SECONDS, max(0.0, budget.remaining()))
        if not self._lock.acquire(timeout=wait_seconds):
            # Not retryable: the policy's retry would queue behind the same
            # holder. The caller learns the plane is occupied, now.
            raise ProviderTransportError(
                "browser retrieval plane is busy", retryable=False
            )
        try:
            yield
        finally:
            self._lock.release()

    def _attach_terminal_evidence(
        self,
        provider: str,
        fetch: RawFetch,
        browser: PatchrightMintContext | None,
        *,
        assess: bool,
    ) -> RawFetch:
        diagnostics = RetrievalDiagnostics(screenshot_status="not_requested")
        evaluator = self._readiness_evaluators.get(provider)
        capture = fetch.http_status >= 400
        if assess and evaluator is not None:
            try:
                observation = evaluator(fetch)
                capture = (
                    capture
                    or not observation.assessment_promotable
                    or not observation.ready
                )
            except Exception:
                # Assessment still owns the product verdict after handoff.
                capture = True
        if capture:
            diagnostics = (
                browser.capture_incident_evidence(
                    "http-failure" if fetch.http_status >= 400 else "content-snapshot"
                )
                if browser
                else RetrievalDiagnostics(screenshot_status="capture_failed")
            )
        return fetch.model_copy(update={"diagnostics": diagnostics})

    def _await_semantic_readiness(
        self,
        page: Any,
        *,
        requested_url: str,
        status: int,
        content_type: str,
        initial_content: bytes,
        session_cookie_present: bool,
        readiness: BrowserSemanticReadinessSpec,
        evaluator: BrowserReadinessEvaluator,
        browser: PatchrightMintContext | None,
    ) -> bytes:
        """Return one stable snapshot or a genuinely non-promotable timeout."""

        def evaluate_snapshot(
            current_url: str,
            content: bytes,
        ) -> BrowserReadinessObservation:
            fetch = _raw_fetch(
                requested_url=requested_url,
                final_url=current_url,
                status=status,
                content_type=content_type,
                retrieved_at=self._clock(),
                content=content,
                session_cookie_present=session_cookie_present,
            )
            return evaluator(fetch)

        def record_terminal(sampled: BrowserSemanticSnapshot) -> None:
            if browser is None:
                return
            observation = sampled.observation
            browser.record_semantic_readiness_terminal(
                state=sampled.terminal_state,
                word_count=observation.word_count if observation is not None else 0,
                coverage_bucket=(
                    observation.coverage_bucket
                    if observation is not None
                    else ReadinessCoverageBucket.UNAVAILABLE
                ),
                content_change_count=sampled.content_change_count,
                last_content_change_ms=sampled.last_content_change_ms,
            )

        try:
            return await_semantic_snapshot(
                page,
                initial_content=initial_content,
                readiness=readiness,
                evaluator=evaluate_snapshot,
                monotonic_clock=self._monotonic_clock,
                terminal_observer=record_terminal,
            )
        except SemanticReadinessRejected as error:
            snapshot = error.snapshot
            raise BrowserSnapshotRejected(
                fetch=_raw_fetch(
                    requested_url=requested_url,
                    final_url=snapshot.document_url,
                    status=status,
                    content_type=content_type,
                    retrieved_at=self._clock(),
                    content=snapshot.content,
                    session_cookie_present=session_cookie_present,
                ),
                snapshot=snapshot,
            ) from error

    def _ensure_page(
        self,
        profile: Path,
        *,
        provider: str,
        portable_cookies: tuple[PortableCookie, ...],
    ) -> tuple[Any, bool]:
        if self._require_virtual_display and self._runtime is None:
            raise BrowserRuntimeError(
                InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
            )
        held = self._held
        if held is not None and held.profile == profile:
            return held.page, False
        if held is not None:
            self._release_held()

        profile = Path(profile)
        lease = self._leases.hold_profile(profile)
        factory_context = None
        try:
            seed_recovery_profile = bool(portable_cookies) and (
                not profile.exists() or not any(profile.iterdir())
            )
            if self._runtime is None:
                with timing_step(TimingStep.BROWSER_OPEN):
                    factory_context = self._launch(str(profile))
                if seed_recovery_profile:
                    add_cookies = getattr(factory_context, "add_cookies", None)
                    if callable(add_cookies):
                        add_cookies(
                            [_browser_cookie(cookie) for cookie in portable_cookies]
                        )
                page = factory_context.new_page()
                self._configure_page(page, provider)
                self._held = _HeldProfile(
                    profile=profile,
                    lease=lease,
                    page=page,
                    factory_context=factory_context,
                )
                return page, seed_recovery_profile

            if self._require_virtual_display:
                ensure_virtual_display()
            launch_config = self._launch_configs.get(
                provider,
                BrowserLaunchConfig(
                    locale="en-US",
                    timezone_id="America/New_York",
                    accept_language="en-US,en;q=0.9",
                ),
            )
            with self._runtime.open(
                profile,
                require_virtual_display=self._require_virtual_display,
                launch_config=launch_config,
                keep_alive=True,
                on_forced_close=self._invalidate_held_profile,
            ) as browser:
                if seed_recovery_profile:
                    browser.context.add_cookies(
                        [_browser_cookie(cookie) for cookie in portable_cookies]
                    )
                self._configure_page(browser.page, provider)
                self._held = _HeldProfile(
                    profile=profile,
                    lease=lease,
                    page=browser.page,
                    browser=browser,
                )
                return browser.page, seed_recovery_profile
        except BaseException:
            if factory_context is not None and self._held is None:
                with suppress(Exception), timing_step(TimingStep.BROWSER_CLOSE):
                    factory_context.close()
            lease.release()
            raise

    def _configure_page(self, page: Any, provider: str) -> None:
        blocked = frozenset(
            self._policies.get(provider, _DEFAULT_POLICY).block_resource_types
        )
        if not blocked:
            return
        page.route(
            "**/*",
            lambda route: (
                route.abort()
                if route.request.resource_type in blocked
                else route.continue_()
            ),
        )

    def _release_held(self) -> None:
        held = self._held
        if held is None:
            return
        self._held = None
        try:
            if held.factory_context is not None:
                with timing_step(TimingStep.BROWSER_CLOSE):
                    held.factory_context.close()
            elif self._runtime is not None:
                self._runtime.close_kept(held.profile, notify_owner=False)
        finally:
            held.lease.release()

    def _invalidate_held_profile(
        self,
        profile: Path,
    ) -> Callable[[], None] | None:
        """Drop the page now and return lease cleanup for after browser close."""

        with self._lock:
            held = self._held
            if held is None or held.profile != profile:
                return None
            self._held = None
            return held.lease.release

    def _navigate_with_policy(
        self,
        page,
        url: str,
        *,
        timeout_seconds: float,
        policy: BrowserRetrievalSpec,
        recovery: bool,
        allow_warmups: bool,
        budget: _OperationBudget,
        navigation_step: TimingStep = TimingStep.ARTICLE_NAVIGATION,
    ) -> Any | None:
        warmups = policy.warmup_urls[:0]
        if allow_warmups:
            warmups = (
                policy.recovery_warmup_urls
                if recovery and policy.recovery_warmup_urls
                else policy.warmup_urls
            )
        for warmup_url in warmups:
            if budget.remaining() <= 0:
                # Warm-ups are optional; the article navigation below reports
                # the exhausted deadline.
                break
            budget.navigation_started = True
            try:
                with timing_step(TimingStep.BROWSER_WARMUP):
                    page.goto(
                        str(warmup_url),
                        wait_until="domcontentloaded",
                        timeout=budget.bound(timeout_seconds) * 1000,
                    )
                    _settle(page, budget.bound(policy.warmup_settle_seconds))
            except Exception:
                # Warm-up is bounded affinity/session hydration. Only the
                # requested article navigation is authoritative transport.
                continue

        with timing_step(navigation_step):
            navigation_timeout = budget.bound(timeout_seconds)
            budget.navigation_started = True

            def navigate():
                return page.goto(
                    url,
                    wait_until=policy.navigation_wait_until,
                    timeout=navigation_timeout * 1000,
                )

            browser = self._held.browser if self._held is not None else None
            response = (
                browser.observe_navigation(url, navigate)
                if browser is not None
                else navigate()
            )
            if policy.ready_selectors:
                combined = ", ".join(policy.ready_selectors)
                try:
                    page.wait_for_selector(
                        combined,
                        timeout=budget.bound(policy.ready_timeout_seconds) * 1000,
                        state="attached",
                    )
                except Exception as error:
                    if not _is_browser_timeout(error):
                        raise
            _settle(page, budget.bound(policy.article_settle_seconds))
            if policy.network_idle_timeout_seconds:
                idle_timeout = budget.bound(policy.network_idle_timeout_seconds)
                with suppress(Exception):
                    page.wait_for_load_state(
                        "networkidle",
                        timeout=idle_timeout * 1000,
                    )
        return response

    def _profile_ref(
        self,
        provider: str,
        session: SessionArtifact | None,
    ) -> str:
        if self._profile_resolver is None:
            raise ValueError("browser retrieval requires a profile resolver")
        if session is not None and session.provider != provider:
            raise ValueError("browser session provider does not match its route")
        account_key = session.account_key if session is not None else "public"
        if session is not None and session.browser_profile_id is not None:
            return str(
                self._profile_resolver(
                    provider, account_key, profile_id=session.browser_profile_id
                )
            )
        return str(self._profile_resolver(provider, account_key))

    def _assert_candidate_authority(self, session: SessionArtifact) -> None:
        observed = self._export_profile_cookies(session.provider)

        def publisher_jar(
            items: tuple[PortableCookie, ...],
        ) -> set[tuple[str, str, str, str]]:
            return {
                (c.name, c.domain, c.path, c.value)
                for c in items
                if not is_challenge_vendor_cookie(c.name)
                and (c.expires is None or c.expires > self._clock().timestamp())
            }

        expected = publisher_jar(session.cookies)
        if not expected or publisher_jar(observed) != expected:
            raise BrowserAuthorityChangedError()

    def _export_profile_cookies(self, provider: str) -> tuple[PortableCookie, ...]:
        """Export the currently owned context; never seed or mutate its cookies."""
        held = self._held
        if held is None:  # pragma: no cover - called after _ensure_page
            raise BrowserAuthorityChangedError()
        context = held.browser.context if held.browser else held.factory_context
        cookies = getattr(context, "cookies", None)
        if not callable(cookies):
            raise ProviderTransportError(
                "browser cookie observation unavailable", retryable=False
            )
        # Inspect the entire provider-owned scope, including cookies absent
        # from the candidate. A narrow candidate cannot hide ambient authority.
        domains = self._session_cookie_domains.get(provider)
        if domains is None:
            raise ProviderTransportError(
                "browser verification cookie scope unavailable", retryable=False
            )
        try:
            return normalize_browser_cookie_export(
                cookies(), allowed_domains=domains, now=self._clock()
            )
        except ValueError as error:
            raise ProviderTransportError(
                "browser verification authority unavailable", retryable=False
            ) from error

    def _resolve_challenge(
        self,
        provider: str,
        browser: PatchrightMintContext | _DirectChallengeBrowser,
    ) -> ChallengeResolutionStatus:
        resolver = self._challenge_resolvers.get(provider)
        if resolver is None:
            return ChallengeResolutionStatus.NOT_PRESENT
        resolution = resolver.resolve(browser, self._challenge_mode)
        if resolution.status is ChallengeResolutionStatus.BLOCKED:
            reason = (
                resolution.reason.value if resolution.reason is not None else "unknown"
            )
            # A blocked challenge on the retrieval plane is the provider's
            # edge defense refusing this request; no operator action changes
            # it, and backing off is what does. Mint flows keep their own
            # operator escalation in the login plane.
            raise ProviderDefenseError(
                "interactive challenge blocked retrieval "
                f"({resolution.detection.vendor.value}/{reason})",
                provider=provider,
                reason_code=MintFailureEvidence(
                    stage=MintFailureStage.CHALLENGE,
                    category=MintFailureCategory.CHALLENGE_BLOCKED,
                ).reason_code,
            )
        return resolution.status

    def _launch(self, profile_ref: str):
        if self._context_factory is not None:
            return self._context_factory(
                user_data_dir=profile_ref, headless=self._headless
            )
        # Optional dependency stays out of base imports and CLI help.
        from patchright.sync_api import sync_playwright

        manager = sync_playwright().start()
        try:
            context = manager.chromium.launch_persistent_context(
                profile_ref, headless=self._headless
            )
        except Exception:
            manager.stop()
            raise
        return _ManagedContext(manager, context)


class SingleNavigationBrowserClient:
    """Expose the browser's check-only navigation through ``HttpClient``."""

    def __init__(self, retriever: SingleNavigationBrowserRetriever) -> None:
        self._retriever = retriever

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        return self._retriever.get_for_check(
            url,
            session=session,
            timeout=timeout,
        )


class _ManagedContext:
    """Close the persistent context and stop its playwright manager together."""

    def __init__(self, manager, context) -> None:
        self._manager = manager
        self._context = context

    def new_page(self):
        return self._context.new_page()

    @property
    def pages(self):
        return getattr(self._context, "pages", [])

    @property
    def url(self) -> str:  # pragma: no cover - convenience only
        return self._context.pages[0].url if self._context.pages else ""

    def close(self) -> None:
        first_error: Exception | None = None
        for closer in (self._context.close, self._manager.stop):
            try:
                closer()
            except Exception as error:  # cleanup must not mask the primary result
                first_error = first_error or error
        if first_error is not None:
            raise first_error


def _settle(page, seconds: float) -> None:
    if seconds <= 0:
        return
    page.wait_for_timeout(seconds * 1000)


def _is_browser_timeout(error: Exception) -> bool:
    """Recognize Playwright's timeout without importing the optional driver."""

    return type(error).__name__ == "TimeoutError"


def _attempt_purpose(role: HttpOperationRole) -> AttemptPurpose:
    if role is HttpOperationRole.SEARCH:
        return AttemptPurpose.SEARCH
    if role is HttpOperationRole.VERIFICATION:
        return AttemptPurpose.VERIFICATION
    return AttemptPurpose.RETRIEVE


def _response_content(response, page) -> tuple[str, bytes]:  # noqa: ANN001
    """Preserve rendered HTML while retaining raw bodies for JSON endpoints."""

    content_type = _response_content_type(response)
    if _is_html(content_type):
        return content_type, page.content().encode("utf-8", "replace")
    body = getattr(response, "body", None)
    if not callable(body):
        raise ProviderTransportError("browser response body is unavailable")
    return content_type, bytes(body())


def _response_content_type(response: object) -> str:
    headers = getattr(response, "headers", {})
    return (
        str(headers.get("content-type", "text/html"))
        if isinstance(headers, Mapping)
        else "text/html"
    )


def _is_html(content_type: str) -> bool:
    media_type = content_type.partition(";")[0].strip().lower()
    return media_type in {"text/html", "application/xhtml+xml"}


def _raw_fetch(
    *,
    requested_url: str,
    final_url: str,
    status: int,
    content_type: str,
    retrieved_at: datetime,
    content: bytes,
    session_cookie_present: bool = True,
) -> RawFetch:
    return RawFetch.model_validate(
        {
            "requested_url": requested_url,
            "final_url": final_url,
            "http_status": status,
            "content_type": content_type,
            "retrieved_at": retrieved_at,
            "session_cookie_present": session_cookie_present,
            # One name for every browser-served fetch: the profile that
            # matters for a browser is its retained state, not a curl
            # impersonation string (R8 provenance).
            "serving_transport": "browser",
            "raw_html": content,
        }
    )


def _browser_cookie(cookie: PortableCookie) -> dict[str, object]:
    value: dict[str, object] = {
        "name": cookie.name,
        "value": cookie.value,
        "domain": cookie.domain,
        "path": cookie.path,
        "secure": cookie.secure,
        "httpOnly": cookie.http_only,
    }
    expires = cookie.expires
    if expires is not None:
        value["expires"] = float(expires)
    same_site = cookie.same_site
    if same_site is not None:
        value["sameSite"] = str(same_site)
    return value
