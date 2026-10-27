"""Validated cookie imports and atomic, single-writer session persistence."""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager, nullcontext, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import ValidationError

from .account_keys import require_account_key
from .acquisition import (
    AcquiredSession,
    AcquisitionEvidence,
    AcquisitionFailure,
    AcquisitionMode,
    CandidateVerificationMode,
    ChallengeMode,
    FlowCandidate,
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
    verification_verdict,
)
from .browser_runtime.events import AttemptPurpose, RuntimeTrace
from .browser_runtime.leases import (
    LeaseBusyError,
    LeaseKind,
    LeaseManager,
    ordered_file_lease,
)
from .browser_runtime.surface import BrowserRuntimeError
from .connection_controls import ConnectionControls
from .contracts import (
    AuthBrowserSession,
    BrowserProfileAccess,
    HttpClient,
    HttpClientScopeFactory,
    LoginRecipe,
    SessionAcquisitionAdapter,
)
from .errors import (
    AccountAlertError,
    BrowserAuthorityChangedError,
    OperatorActionRequiredError,
    PersistenceError,
    ProviderTransportError,
    SessionRequiredError,
    UsageError,
)
from .models import (
    AccessState,
    MintOutcome,
    PortableCookie,
    ProviderReadiness,
    RawFetch,
    SessionArtifact,
    SessionDisposition,
    SessionHealth,
    SessionStatus,
    SessionVerification,
    StoredSession,
    TerminalFailure,
)
from .provider_keys import is_provider_key
from .renewal_observation import renewal_observation_point
from .results import PublicErrorReason
from .session_cookies import (
    SessionCookiesMissing,
    cookie_domain_allowed,
    is_challenge_vendor_cookie,
    normalize_cookie_import,
)
from .timing import (
    TimingStep,
    set_timing_acquisition_mode,
    set_timing_failure,
    timing_step,
)

Clock = Callable[[], datetime]
FaultHook = Callable[[str], None]
_COOLDOWN = timedelta(minutes=15)
#: The classifier publishes a reason by matching the exception's text against
#: the closed vocabulary, so this is taken from the enum rather than repeated:
#: a divergent copy would not fail, it would silently publish no reason.
_IMPORT_VERIFICATION_INCONCLUSIVE = (
    PublicErrorReason.IMPORT_VERIFICATION_INCONCLUSIVE.value
)
_OPERATOR_FAILURES = {
    MintOutcome.CREDENTIAL_REJECTED: TerminalFailure.CREDENTIAL_REJECTED,
    MintOutcome.SECOND_FACTOR_REQUIRED: TerminalFailure.SECOND_FACTOR_REQUIRED,
    MintOutcome.ACCOUNT_ALERT: TerminalFailure.ACCOUNT_ALERT,
    MintOutcome.CHALLENGE_BLOCKED: TerminalFailure.CHALLENGE_BLOCKED,
    MintOutcome.UNKNOWN_FLOW: TerminalFailure.UNKNOWN_FLOW,
}
_SAFE_PROBE_FAILURE_REASONS = frozenset(
    {
        "article_identity_mismatch",
        "http_client_error",
        "http_error",
        "http_forbidden",
        "http_rate_limited",
        "http_redirect_error",
        "http_server_error",
        "http_unauthorized",
        "insufficient_article_structure",
        "interactive_challenge",
        "invalid_html",
        "verification_body_too_short",
    }
)


def _capture_candidate_proof(
    browser: AuthBrowserSession, candidate: FlowCandidate | None
) -> None:
    if candidate is not None and candidate.verification_fetch is not None:
        capture = getattr(browser, "capture_diagnostic_screenshot", None)
        if callable(capture):
            with suppress(Exception):
                capture("paid-proof")


def _browser_attempt(
    browser: object, provider: str, purpose: AttemptPurpose
) -> AbstractContextManager[object | None]:
    attempt = getattr(browser, "attempt", None)
    if callable(attempt):
        return attempt(provider, purpose, profile_scope="account")
    return nullcontext()


def _require_credential_mint(allowed: bool) -> None:
    """Stop warm-only acquisition before any credential is read.

    A scheduled keeper runs warm by default. Refusing here rather than at the
    caller keeps the guarantee at the single point where a secret would
    otherwise be resolved, whatever path reached it.
    """

    if not allowed:
        raise SessionRequiredError("credential_mint_not_permitted")


def _probe_failure_reason_code(reason: str | None) -> str:
    safe_reason = reason if reason in _SAFE_PROBE_FAILURE_REASONS else "unknown"
    return f"paid_probe_{safe_reason}"


class ServingSessions:
    """Existing authority and safety writes, without operator actions."""

    def __init__(self, store: SessionStore) -> None:
        if store._adapters or store._credential_readiness_probes:
            raise ValueError(
                "serving sessions cannot contain acquisition collaborators"
            )
        self._store = store

    def status(self, provider: str, account_key: str = "default") -> SessionHealth:
        return self._store.status(provider, account_key)

    def get_valid_session(
        self, provider: str, account_key: str = "default"
    ) -> SessionArtifact:
        return self._store.get_valid_session(provider, account_key)

    def mark_required(
        self,
        provider: str,
        account_key: str = "default",
        *,
        generation_id: UUID | None = None,
    ) -> None:
        self._store.mark_required(provider, account_key, generation_id=generation_id)

    def mark_account_alert(
        self,
        provider: str,
        account_key: str = "default",
        *,
        generation_id: UUID | None = None,
    ) -> None:
        self._store.mark_account_alert(
            provider, account_key, generation_id=generation_id
        )


class SessionStore:
    """Own one versioned session file per provider/account under an OS lock."""

    def __init__(
        self,
        root: Path,
        *,
        recipes: Mapping[str, LoginRecipe],
        adapters: Mapping[str, SessionAcquisitionAdapter] | None = None,
        credential_readiness_probes: (
            Mapping[str, Callable[[], ProviderReadiness]] | None
        ) = None,
        http: HttpClient,
        client_factory: HttpClientScopeFactory | None = None,
        clock: Clock | None = None,
        fault_hook: FaultHook | None = None,
        lease_manager: LeaseManager | None = None,
        profile_access: BrowserProfileAccess | None = None,
        session_lock_timeout_seconds: float = 900,
        verification_requires_browser: Callable[[str], bool] | None = None,
        diagnostic_trace: RuntimeTrace | None = None,
        profile_verifier: Callable[
            [LoginRecipe, SessionArtifact],
            tuple[SessionVerification, tuple[PortableCookie, ...]],
        ]
        | None = None,
    ) -> None:
        self.root = Path(root)
        self._diagnostic_trace = diagnostic_trace
        self._profile_verifier = profile_verifier
        self._recipes = dict(recipes)
        self._adapters = dict(adapters or {})
        # Whether proving an existing session opens a browser. Product
        # composition knows this from the provider's retrieval transport; the
        # store itself holds no registry.
        self._verification_requires_browser = verification_requires_browser
        self._credential_readiness_probes = dict(credential_readiness_probes or {})
        if self._adapters and profile_access is None:
            raise ValueError("session acquisition adapters require browser profiles")
        self._http = http
        # Product composition supplies fresh, scoped HTTP verification clients
        # wrapped by the shared ProviderNetworkPolicy. Probes therefore share
        # the provider token bucket without inheriting operational cookies.
        # ``http`` remains the fallback for direct library use.
        self._client_factory = client_factory
        self._clock = clock or (lambda: datetime.now(UTC))
        self.connection_controls = ConnectionControls(
            self.root, clock=lambda: self._now().timestamp()
        )
        self._fault_hook = fault_hook
        self._leases = lease_manager or LeaseManager(
            Path.home() / ".local/state/newsclip/locks"
        )
        self._profiles = profile_access
        self._session_lock_timeout_seconds = session_lock_timeout_seconds
        self._ensure_private_directory(self.root)

    @contextmanager
    def _client_scope(self, provider: str) -> Iterator[HttpClient]:
        if self._client_factory is not None:
            with self._client_factory(provider) as client:
                yield client
            return
        yield self._http

    def current_generation(
        self, provider: str, account_key: str = "default"
    ) -> UUID | None:
        """Snapshot the generation a manual sign-in is allowed to replace."""

        self._recipe(provider)
        stored = self._load(provider, account_key)
        return stored.artifact.generation_id if stored and stored.artifact else None

    def promote_browser_session(
        self,
        artifact: SessionArtifact,
        verification_fetch: RawFetch,
        *,
        expected_generation: UUID | None,
        connection_revision: str | None = None,
    ) -> None:
        """Publish a human-created profile only after independent paid proof.

        The browser is closed before this call. Its new profile is never a
        reader's profile until the atomic session write succeeds. A late
        window cannot overwrite authority published since it opened.
        """

        recipe = self._recipe(artifact.provider)
        candidate = self._validate_artifact(artifact, recipe, artifact.account_key)
        if (
            candidate.browser_profile_id is None
            or verification_fetch.serving_transport != "browser"
        ):
            raise PersistenceError("manual sign-in requires a browser-bound candidate")
        verification = recipe.verify_fetch(verification_fetch)
        if not verification.verified:
            raise OperatorActionRequiredError(
                "sign-in did not prove subscription access"
            )
        candidate = candidate.model_copy(
            update={"verified_at": verification.verified_at}
        )
        with self._lock(candidate.provider, candidate.account_key):
            current = self._load(candidate.provider, candidate.account_key)
            generation = (
                current.artifact.generation_id if current and current.artifact else None
            )
            if generation != expected_generation:
                raise OperatorActionRequiredError(
                    "session changed; start a new sign-in"
                )
            self._write(
                candidate.provider,
                candidate.account_key,
                StoredSession(status=SessionStatus.VERIFIED, artifact=candidate),
                connection_revision=connection_revision,
            )

    def get_valid_session(
        self, provider: str, account_key: str = "default"
    ) -> SessionArtifact:
        """Return the stored session after structural checks only.

        This is the cheap common path: no provider probe is issued here, so a
        happy-path ``get``/``save`` performs a single fetch of the caller's URL
        (its ``FULL`` assessment is the session proof). Callers that must prove
        access up front — ``login`` and ``session-checkpoint`` — probe
        explicitly; see ARCHITECTURE, "Sessions and authentication".
        """

        recipe = self._recipe(provider)
        account_key = self._validated_account_key(account_key)
        self.connection_controls.require_active(provider, account_key)
        stored = self._load(provider, account_key)
        artifact = self._structural_artifact(stored, recipe, account_key)
        if artifact is None:
            raise SessionRequiredError(f"{provider} session is not verified")
        return artifact

    def mark_required(
        self,
        provider: str,
        account_key: str = "default",
        *,
        generation_id: UUID | None = None,
    ) -> None:
        """Downgrade a stored ``VERIFIED`` session to ``REQUIRED`` under lock.

        Used by the read path when a probe proves the session is dead. It never
        clobbers an ``OPERATOR_ACTION``/``COOLDOWN`` state, so a downgrade cannot
        erase an outstanding operator obligation. When ``generation_id`` is
        given, only that exact generation is downgraded: a probe verdict about
        an old artifact must not erase a session re-minted concurrently.
        """

        self._recipe(provider)
        with self._lock(provider, account_key):
            stored = self._load_locked(provider, account_key)
            if stored is None or stored.status is not SessionStatus.VERIFIED:
                return
            if generation_id is not None and (
                stored.artifact is None
                or stored.artifact.generation_id != generation_id
            ):
                return
            self._write(
                provider,
                account_key,
                StoredSession(
                    status=SessionStatus.REQUIRED,
                    # Keep a staged profile reachable for warm recovery.
                    # REQUIRED prevents this inactive artifact serving reads.
                    artifact=stored.artifact
                    if stored.artifact is not None
                    and stored.artifact.browser_profile_id is not None
                    else None,
                ),
            )

    def mark_account_alert(
        self,
        provider: str,
        account_key: str = "default",
        *,
        generation_id: UUID | None = None,
    ) -> None:
        """Retain terminal account evidence without erasing newer authority."""

        self._recipe(provider)
        with self._lock(provider, account_key):
            stored = self._load_locked(provider, account_key)
            artifact = stored.artifact if stored is not None else None
            if generation_id is not None and (
                artifact is None or artifact.generation_id != generation_id
            ):
                return
            if stored is not None and stored.status is SessionStatus.OPERATOR_ACTION:
                return
            self._persist_failure(
                provider,
                account_key,
                MintOutcome.ACCOUNT_ALERT,
                prior_artifact=artifact,
                reason_code="account_alert",
            )

    def explicit_login(
        self,
        provider: str,
        *,
        headless: bool = False,
        challenge_mode: ChallengeMode = ChallengeMode.DETECT_ONLY,
        account_key: str = "default",
        before_browser: Callable[[], None] | None = None,
        allow_credential_mint: bool = True,
    ) -> AcquiredSession:
        with (
            self._diagnostic_trace.acquisition(provider)
            if self._diagnostic_trace is not None
            else nullcontext()
        ):
            return self._explicit_login(
                provider,
                headless=headless,
                challenge_mode=challenge_mode,
                account_key=account_key,
                before_browser=before_browser,
                allow_credential_mint=allow_credential_mint,
            )

    def _explicit_login(
        self,
        provider: str,
        *,
        headless: bool,
        challenge_mode: ChallengeMode,
        account_key: str,
        before_browser: Callable[[], None] | None,
        allow_credential_mint: bool,
    ) -> AcquiredSession:
        recipe = self._recipe(provider)
        account_key = self._validated_account_key(account_key)
        self.connection_controls.require_maintenance(provider, account_key)
        adapter = self._adapter(provider)

        # Environment preparation may re-exec this command. Check the cheapest
        # warm tier first, and never hold the session lock while a delegated
        # child starts (the child must be able to acquire the same lock).
        #
        # "Cheapest" is not "browser-free", though. A provider whose retrieval
        # transport is the browser verifies through it too, so the warm probe
        # below opens a browser itself — and preparing the environment after
        # that probe is too late, because the probe is what dies. On a host
        # with no inherited display that surfaced as a bare transport failure
        # from a verb that never said it wanted a browser. Prepare ahead of the
        # warm tier for exactly those providers, still outside the lock.
        prepared = False
        if before_browser is not None and self._verification_opens_a_browser(provider):
            self._prepare_browser_environment(before_browser)
            prepared = True

        with self._lock(provider, account_key), renewal_observation_point(provider):
            stored = self._load_locked(provider, account_key)
            with timing_step(TimingStep.ARTIFACT_VERIFY, provider=provider):
                acquired = self._reuse_verified(stored, recipe, account_key)
            if acquired is not None:
                set_timing_acquisition_mode(acquired.evidence.mode)
                return acquired
            self._assert_attempt_allowed(provider, stored)
            initial_generation = (
                stored.artifact.generation_id
                if stored is not None and stored.artifact is not None
                else None
            )

        # Never twice: the CLI's preparation re-execs the process, so a second
        # call would be a second re-exec.
        if before_browser is not None and not prepared:
            self._prepare_browser_environment(before_browser)

        # Reload after preparation: another process (or the delegated child)
        # may have committed a generation while this caller held no lock.
        with self._lock(provider, account_key), renewal_observation_point(provider):
            stored = self._load_locked(provider, account_key)
            current_generation = (
                stored.artifact.generation_id
                if stored is not None and stored.artifact is not None
                else None
            )
            if current_generation != initial_generation:
                with timing_step(TimingStep.ARTIFACT_VERIFY, provider=provider):
                    acquired = self._reuse_verified(stored, recipe, account_key)
                if acquired is not None:
                    set_timing_acquisition_mode(acquired.evidence.mode)
                    return acquired
            self._assert_attempt_allowed(provider, stored)
            prior_artifact = stored.artifact if stored is not None else None
            prior_status = stored.status if stored is not None else None
            profile_id = prior_artifact.browser_profile_id if prior_artifact else None
            profile_options = (
                {"profile_id": profile_id} if profile_id is not None else {}
            )
            try:
                profiles = self._profile_access()
                profile = profiles.path(provider, account_key, **profile_options)
                with self._leases.attempt(
                    provider,
                    account_key,
                    timeout_seconds=self._session_lock_timeout_seconds,
                ):
                    with (
                        self._leases.profile(
                            profile,
                            timeout_seconds=self._session_lock_timeout_seconds,
                        ),
                        profiles.open(
                            provider,
                            account_key,
                            require_virtual_display=headless,
                            **profile_options,
                        ) as browser,
                    ):
                        with (
                            timing_step(
                                TimingStep.PROFILE_REHYDRATE, provider=provider
                            ),
                            _browser_attempt(
                                browser, provider, AttemptPurpose.PROFILE_REHYDRATE
                            ),
                        ):
                            candidate = adapter.rehydrate_profile(
                                browser,
                                account_key=account_key,
                                challenge_mode=challenge_mode,
                            )
                            _capture_candidate_proof(browser, candidate)
                        if candidate is None:
                            _require_credential_mint(allow_credential_mint)
                            candidate = self._mint_credentials(
                                provider,
                                adapter,
                                browser,
                                account_key=account_key,
                                challenge_mode=challenge_mode,
                            )
                        set_timing_acquisition_mode(candidate.evidence.mode)

                    candidate = self._bind_profile(candidate, profile_id)

                    # Browser-backed verification may need to open this same
                    # persistent profile. The acquisition context and its
                    # profile lease must be closed first; the account attempt
                    # lease remains held so no competing mint can interleave.
                    with timing_step(TimingStep.SESSION_VERIFY, provider=provider):
                        verdict, artifact, probe_reason = self._candidate_verdict(
                            provider,
                            candidate,
                            recipe,
                            account_key,
                        )
                    if (
                        verdict is SessionDisposition.DEAD
                        and candidate.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
                    ):
                        with (
                            self._leases.profile(
                                profile,
                                timeout_seconds=self._session_lock_timeout_seconds,
                            ),
                            profiles.open(
                                provider,
                                account_key,
                                require_virtual_display=headless,
                                **profile_options,
                            ) as browser,
                        ):
                            _require_credential_mint(allow_credential_mint)
                            candidate = self._mint_credentials(
                                provider,
                                adapter,
                                browser,
                                account_key=account_key,
                                challenge_mode=challenge_mode,
                            )
                            set_timing_acquisition_mode(candidate.evidence.mode)
                        candidate = self._bind_profile(candidate, profile_id)
                        with timing_step(TimingStep.SESSION_VERIFY, provider=provider):
                            verdict, artifact, probe_reason = self._candidate_verdict(
                                provider,
                                candidate,
                                recipe,
                                account_key,
                            )
            except AccountAlertError:
                self._persist_account_alert(provider, account_key, prior_artifact)
                raise
            except ProviderTransportError:
                failure = MintFailureEvidence(
                    stage=MintFailureStage.TRANSPORT,
                    category=MintFailureCategory.TRANSPORT_FAILURE,
                )
                set_timing_failure(failure)
                self._persist_failure(
                    provider,
                    account_key,
                    MintOutcome.INFRASTRUCTURE_ERROR,
                    prior_artifact=prior_artifact,
                )
                raise
            except AcquisitionFailure as error:
                set_timing_failure(error.evidence)
                self._persist_failure(
                    provider,
                    account_key,
                    error.outcome,
                    prior_artifact=prior_artifact,
                    evidence=error.evidence,
                )
                if error.outcome in _OPERATOR_FAILURES:
                    raise OperatorActionRequiredError(
                        error.evidence.reason_code,
                        provider=provider,
                        reason_code=error.evidence.reason_code,
                    ) from error
                raise SessionRequiredError(error.evidence.reason_code) from error
            except (BrowserRuntimeError, LeaseBusyError, OSError) as error:
                if (
                    isinstance(error, BrowserRuntimeError)
                    and error.profile_ownership_failure
                ):
                    # Ownership uncertainty is local state, never evidence
                    # against the account or permission to submit credentials.
                    raise PersistenceError(error.category.value) from error
                failure = MintFailureEvidence(
                    stage=MintFailureStage.PROFILE,
                    category=MintFailureCategory.INFRASTRUCTURE,
                )
                set_timing_failure(failure)
                self._persist_failure(
                    provider,
                    account_key,
                    MintOutcome.INFRASTRUCTURE_ERROR,
                    prior_artifact=prior_artifact,
                )
                raise SessionRequiredError(failure.reason_code) from error

            if verdict is SessionDisposition.DEAD:
                failure = MintFailureEvidence(
                    stage=(
                        MintFailureStage.PAID_PROBE
                        if artifact is not None
                        else MintFailureStage.SESSION
                    ),
                    category=(
                        MintFailureCategory.ARTICLE_NOT_FULL
                        if artifact is not None
                        else MintFailureCategory.SESSION_MISSING
                    ),
                )
                self._persist_failure(
                    provider,
                    account_key,
                    MintOutcome.UNKNOWN_FLOW,
                    prior_artifact=prior_artifact,
                    evidence=failure,
                )
                set_timing_failure(failure)
                raise OperatorActionRequiredError(
                    failure.reason_code,
                    provider=provider,
                    reason_code=failure.reason_code,
                )
            if verdict is SessionDisposition.INCONCLUSIVE:
                failure = MintFailureEvidence(
                    stage=MintFailureStage.PAID_PROBE,
                    category=MintFailureCategory.TRANSPORT_FAILURE,
                )
                reason_code = _probe_failure_reason_code(probe_reason)
                self._persist_failure(
                    provider,
                    account_key,
                    MintOutcome.INFRASTRUCTURE_ERROR,
                    prior_artifact=prior_artifact,
                    evidence=failure,
                    reason_code=reason_code,
                )
                set_timing_failure(failure)
                raise ProviderTransportError(failure.reason_code)
            if artifact is None:  # pragma: no cover - verdict invariant
                raise PersistenceError("verified session candidate is missing")
            verified_artifact = artifact
            verified_evidence = candidate.evidence.model_copy(
                update={"session_proof_observed": True}
            )
            if (
                candidate.refresh_failure is not None
                and prior_artifact is not None
                and prior_status is SessionStatus.VERIFIED
                and prior_artifact.cookies == artifact.cookies
                and prior_artifact.browser_profile_id == artifact.browser_profile_id
            ):
                # A failed refresh cannot replace a still-usable verified
                # generation. An expired or otherwise unusable generation is
                # not authority, so keep service available with the
                # independently FULL retained-profile candidate instead.
                with suppress(ValueError, SessionRequiredError):
                    verified_artifact = self._validate_artifact(
                        prior_artifact,
                        recipe,
                        account_key,
                    )
            self._write(
                provider,
                account_key,
                StoredSession(
                    status=SessionStatus.VERIFIED,
                    artifact=verified_artifact,
                ),
            )
            return AcquiredSession(
                artifact=verified_artifact,
                evidence=verified_evidence,
                refresh_failure=candidate.refresh_failure,
            )

    def _reuse_verified(
        self,
        stored: StoredSession | None,
        recipe: LoginRecipe,
        account_key: str,
    ) -> AcquiredSession | None:
        try:
            verification, artifact = self._verified_artifact(
                stored, recipe, account_key
            )
        except BrowserAuthorityChangedError as error:
            raise ProviderTransportError(
                "browser profile verification unavailable", retryable=False
            ) from error
        except AccountAlertError:
            self._persist_account_alert(
                recipe.provider,
                account_key,
                stored.artifact if stored is not None else None,
            )
            raise
        except (ProviderTransportError, OperatorActionRequiredError):
            raise
        except Exception as error:
            failure = MintFailureEvidence(
                stage=MintFailureStage.PAID_PROBE,
                category=MintFailureCategory.TRANSPORT_FAILURE,
            )
            raise ProviderTransportError(failure.reason_code) from error
        if verification is None or artifact is None:
            return None
        verdict = verification_verdict(verification)
        if verdict is SessionDisposition.INCONCLUSIVE:
            reason = (
                "paid_probe_inconclusive"
                if verification.access_state is AccessState.TEASER
                and verification.reason
                in {"paywall_teaser", "verification_body_too_short"}
                else _probe_failure_reason_code(verification.reason)
            )
            raise ProviderTransportError(reason)
        if verdict is SessionDisposition.DEAD:
            return None
        recovered = (
            stored is not None
            and stored.artifact is not None
            and artifact.generation_id != stored.artifact.generation_id
        )
        if recovered:
            # A different jar is new authority, so publication is mandatory.
            # Unlike updating a proof timestamp, a failed write cannot be ignored.
            self._write(
                recipe.provider,
                account_key,
                StoredSession(status=SessionStatus.VERIFIED, artifact=artifact),
            )
            return AcquiredSession(
                artifact=artifact,
                evidence=AcquisitionEvidence(
                    mode=AcquisitionMode.PROFILE_REHYDRATE,
                    session_proof_observed=True,
                ),
            )
        # Re-proving a session is a verification, so record when it happened.
        # Scheduled upkeep decides staleness from this field; leaving it at the
        # generation's mint time makes every proven session look equally stale
        # for ever, and upkeep then re-proves it on every cycle without end.
        # The generation itself is untouched: a proof does not mint anything,
        # and durability age is measured from ``created_at``.
        # Recording it must not be able to fail the proof itself: a working
        # session should still be usable when the state volume is full, even
        # though upkeep will then keep re-proving it.
        proven_at = self._now()
        if proven_at != artifact.verified_at:
            dated = artifact.model_copy(update={"verified_at": proven_at})
            try:
                self._write(
                    recipe.provider,
                    account_key,
                    StoredSession(status=SessionStatus.VERIFIED, artifact=dated),
                )
            except PersistenceError:
                pass
            else:
                artifact = dated
        return AcquiredSession(
            artifact=artifact,
            evidence=AcquisitionEvidence(
                mode=AcquisitionMode.ARTIFACT_REUSE,
                session_proof_observed=True,
            ),
        )

    def reset_browser_profile(
        self, provider: str, account_key: str = "default"
    ) -> None:
        """Explicitly reinitialize only the retained profile under its lease."""

        self._adapter(provider)
        stored = self._load(provider, account_key)
        artifact = stored.artifact if stored is not None else None
        profile_options = (
            {"profile_id": artifact.browser_profile_id}
            if artifact is not None and artifact.browser_profile_id is not None
            else {}
        )
        profile = self._profile_access().path(provider, account_key, **profile_options)
        try:
            with self._leases.profile(
                profile,
                timeout_seconds=self._session_lock_timeout_seconds,
            ):
                if profile.is_symlink():
                    raise UsageError("browser profile must not be a symlink")
                if profile.exists():
                    if not profile.is_dir():
                        raise UsageError("browser profile path is not a directory")
                    shutil.rmtree(profile)
                profile.mkdir(mode=0o700, parents=True)
                os.chmod(profile, 0o700)
        except LeaseBusyError as error:
            raise PersistenceError("browser profile is busy") from error
        except OSError as error:
            raise PersistenceError("browser profile reset failed") from error

    def import_cookies(
        self,
        provider: str,
        payload: object,
        *,
        account_key: str = "default",
    ) -> SessionArtifact:
        with (
            self._diagnostic_trace.acquisition(provider)
            if self._diagnostic_trace is not None
            else nullcontext()
        ):
            return self._import_cookies(provider, payload, account_key=account_key)

    def _import_cookies(
        self, provider: str, payload: object, *, account_key: str
    ) -> SessionArtifact:
        recipe = self._recipe(provider)
        account_key = self._validated_account_key(account_key)
        self.connection_controls.require_maintenance(provider, account_key)
        now = self._now()
        cookies = normalize_cookie_import(
            payload,
            allowed_domains=recipe.allowed_cookie_domains,
            now=now,
        )
        # Dropped on import, kept on mint. A challenge-vendor cookie attests
        # that one particular host was found acceptable, so replaying another
        # host's is never right — and is worse than sending nothing: importing
        # a workstation's PerimeterX cookies onto the NAS made Bloomberg's
        # verification page smaller than an anonymous fetch (49 words against
        # 245), because the import itself tripped the defense. The mint path
        # normalizes through `normalize_browser_cookie_export` and is
        # deliberately untouched: there the cookies belong to this host, and
        # HTTP replay may still need them.
        cookies = tuple(
            cookie for cookie in cookies if not is_challenge_vendor_cookie(cookie.name)
        )
        if not cookies:
            raise SessionCookiesMissing(
                "cookie import contains no publisher-owned cookies"
            )
        candidate = SessionArtifact(
            generation_id=uuid4(),
            provider=provider,
            account_key=account_key,
            created_at=now,
            verified_at=now,
            cookies=cookies,
        )
        if self._verification_opens_a_browser(provider) or (
            recipe.candidate_verification_mode
            is CandidateVerificationMode.BROWSER_PAID_PROBE
        ):
            # A unique, empty profile prevents existing account authority
            # from supplying an import's proof. The session write below is
            # the sole publication point; old profiles remain usable by
            # readers that already loaded their previous artifact.
            candidate = candidate.model_copy(
                update={
                    "schema_version": 2,
                    "browser_profile_id": uuid4(),
                }
            )
        candidate = self._validate_artifact(candidate, recipe, account_key)
        with self._lock(provider, account_key), renewal_observation_point(provider):
            try:
                with (
                    timing_step(TimingStep.SESSION_VERIFY, provider=provider),
                    self._client_scope(provider) as client,
                ):
                    verification = recipe.verify(client, candidate)
            except (ProviderTransportError, OperatorActionRequiredError):
                raise
            except Exception as error:
                raise ProviderTransportError(
                    "imported cookie verification transport failure"
                ) from error
            verdict = verification_verdict(verification)
            if verdict is SessionDisposition.DEAD:
                raise SessionRequiredError("imported cookies failed verification")
            if verdict is SessionDisposition.INCONCLUSIVE:
                # Not a transport failure. The provider answered; the answer
                # simply did not prove paid access, so retrying the network
                # resolves nothing and "retry_later" sends the operator in a
                # circle (observed 2026-07-28: two identical retries of a
                # Bloomberg promotion, each reported retryable). The same
                # distinction the keeper's paid probe already draws.
                raise OperatorActionRequiredError(
                    _IMPORT_VERIFICATION_INCONCLUSIVE,
                    provider=provider,
                    reason_code=_IMPORT_VERIFICATION_INCONCLUSIVE,
                )
            candidate = candidate.model_copy(
                update={"verified_at": verification.verified_at}
            )
            self._write(
                provider,
                account_key,
                StoredSession(status=SessionStatus.VERIFIED, artifact=candidate),
            )
        return candidate

    def reset(self, provider: str, account_key: str = "default") -> None:
        self._recipe(provider)
        with self._lock(provider, account_key):
            self._write(
                provider,
                account_key,
                StoredSession(status=SessionStatus.REQUIRED),
            )

    def clear(self, provider: str, account_key: str = "default") -> None:
        """Explicitly discard any artifact or failure state."""

        self.reset(provider, account_key)

    def disconnect(
        self,
        provider: str,
        account_key: str = "default",
        *,
        connection_revision: str | None = None,
        drain: Callable[[], None] | None = None,
    ) -> None:
        """Block admission before draining and removing this account's credentials."""
        self._recipe(provider)
        account_key = self._validated_account_key(account_key)
        revision = (
            self.connection_controls.suspend(provider, account_key)
            if connection_revision is None
            else connection_revision
        )
        with self._lock(provider, account_key, timeout_seconds=2):
            if not self.connection_controls.disconnect_current(
                provider, account_key, revision
            ):
                return
            if drain is not None:
                drain()
            stored = self._load_locked(provider, account_key) or StoredSession()
            base = (
                self._profiles.path(provider, account_key)
                if self._profiles is not None
                else self.root / "browser-profiles" / provider / account_key
            )
            if base.parent.is_symlink():
                raise PersistenceError(
                    "browser profile directory must not be a symlink"
                )
            paths = []
            if base.parent.exists():
                for path in base.parent.iterdir():
                    suffix = path.name.removeprefix(base.name + "--")
                    if path.name == base.name or (
                        path.name.startswith(base.name + "--")
                        and len(suffix) == 32
                        and all(c in "0123456789abcdef" for c in suffix)
                    ):
                        paths.append(path)
            for profile in paths:
                try:
                    with self._leases.profile(profile, timeout_seconds=1):
                        if profile.is_symlink() or not profile.is_dir():
                            raise PersistenceError(
                                "browser profile cannot be safely removed"
                            )
                        shutil.rmtree(profile)
                except (LeaseBusyError, OSError):
                    raise PersistenceError(
                        "browser profile cleanup is still pending"
                    ) from None
            cleared = stored.model_copy(
                update={
                    "artifact": None,
                    "status": SessionStatus.REQUIRED
                    if stored.status is SessionStatus.VERIFIED
                    else stored.status,
                }
            )
            self._write(provider, account_key, cleared)
            self.connection_controls.disconnected(
                provider, account_key, revision=revision
            )

    def acknowledge(self, provider: str, account_key: str = "default") -> None:
        """Acknowledge a terminal/cooldown state without reading credentials."""

        self._recipe(provider)
        with self._lock(provider, account_key):
            stored = self._load_locked(provider, account_key)
            if stored is None or stored.status not in {
                SessionStatus.OPERATOR_ACTION,
                SessionStatus.COOLDOWN,
            }:
                raise UsageError("session has no failure state to acknowledge")
            self._write(
                provider,
                account_key,
                StoredSession(
                    status=SessionStatus.REQUIRED,
                    artifact=stored.artifact,
                ),
            )

    def status(self, provider: str, account_key: str = "default") -> SessionHealth:
        recipe = self._recipe(provider)
        account_key = self._validated_account_key(account_key)
        stored = self._inspect(provider, account_key) or StoredSession()
        status = stored.status
        blocker = self.connection_controls.maintenance_blocker(provider, account_key)
        if blocker:
            return SessionHealth(
                provider=provider,
                account_key=account_key,
                status=SessionStatus.OPERATOR_ACTION,
                failure_reason_code=blocker,
                last_verified_at=stored.artifact.verified_at
                if stored.artifact
                else None,
            )
        if (
            status is SessionStatus.VERIFIED
            and self._structural_artifact(stored, recipe, account_key) is None
        ):
            status = SessionStatus.REQUIRED
        return SessionHealth(
            provider=provider,
            account_key=account_key,
            status=status,
            last_verified_at=(
                stored.artifact.verified_at if stored.artifact is not None else None
            ),
            retry_not_before=stored.retry_not_before,
            last_failure=stored.last_failure,
            failure_reason_code=stored.failure_reason_code,
        )

    def _structural_artifact(
        self,
        stored: StoredSession | None,
        recipe: LoginRecipe,
        account_key: str,
    ) -> SessionArtifact | None:
        """Return the artifact if it is stored ``VERIFIED`` and structurally
        sound (identity, cookie domains, unexpired). No provider probe."""

        if (
            stored is None
            or stored.status is not SessionStatus.VERIFIED
            or stored.artifact is None
        ):
            return None
        try:
            return self._validate_artifact(stored.artifact, recipe, account_key)
        except (ValueError, SessionRequiredError):
            return None

    def _verified_artifact(
        self,
        stored: StoredSession | None,
        recipe: LoginRecipe,
        account_key: str,
    ) -> tuple[SessionVerification | None, SessionArtifact | None]:
        """Structural checks plus an eager provider probe. Used by the explicit
        ``login`` reuse check, where proving access before minting is the point."""

        artifact = self._structural_artifact(stored, recipe, account_key)
        if artifact is None:
            return None, None
        if self._profile_verifier is not None and self._verification_opens_a_browser(
            recipe.provider
        ):
            verification, cookies = self._profile_verifier(recipe, artifact)
            # Compare complete normalized cookies, independent of export order.
            # A proven rotation, including one during the probe, is new authority.
            if set(cookies) != set(artifact.cookies):
                artifact = self._validate_artifact(
                    artifact.model_copy(
                        update={
                            "cookies": cookies,
                            "generation_id": uuid4(),
                            "created_at": self._now(),
                            "verified_at": verification.verified_at,
                        }
                    ),
                    recipe,
                    account_key,
                )
        else:
            with self._client_scope(recipe.provider) as client:
                verification = recipe.verify(client, artifact)
        return verification, artifact

    @staticmethod
    def _bind_profile(
        candidate: FlowCandidate, profile_id: UUID | None
    ) -> FlowCandidate:
        if profile_id is None:
            return candidate
        return candidate.model_copy(
            update={
                "artifact": candidate.artifact.model_copy(
                    update={"schema_version": 2, "browser_profile_id": profile_id}
                )
            }
        )

    def _candidate_verdict(
        self,
        provider: str,
        candidate: FlowCandidate,
        recipe: LoginRecipe,
        account_key: str,
    ) -> tuple[SessionDisposition, SessionArtifact | None, str | None]:
        """Validate and probe a browser candidate before it can be persisted."""

        try:
            artifact = self._validate_artifact(
                candidate.artifact,
                recipe,
                account_key,
            )
        except (ValueError, SessionRequiredError):
            return SessionDisposition.DEAD, None, None
        if (
            candidate.candidate_verification_mode
            is not recipe.candidate_verification_mode
        ):
            raise AcquisitionFailure(
                MintOutcome.INFRASTRUCTURE_ERROR,
                MintFailureEvidence(
                    stage=MintFailureStage.SESSION,
                    category=MintFailureCategory.INFRASTRUCTURE,
                ),
            )
        if (
            candidate.candidate_verification_mode
            is CandidateVerificationMode.BROWSER_PAID_PROBE
        ):
            fetch = candidate.verification_fetch
            if fetch is None:  # pragma: no cover - candidate schema invariant
                raise PersistenceError("browser candidate proof is missing")
            try:
                verification = recipe.verify_fetch(fetch)
            except (ProviderTransportError, OperatorActionRequiredError):
                raise
            except Exception as error:
                raise ProviderTransportError(
                    "session verification transport failure"
                ) from error
            verdict = verification_verdict(verification)
            if verdict is not SessionDisposition.VERIFIED:
                return verdict, artifact, verification.reason
            return (
                verdict,
                artifact.model_copy(update={"verified_at": verification.verified_at}),
                None,
            )
        try:
            with self._client_scope(provider) as client:
                verification = recipe.verify(client, artifact)
        except (ProviderTransportError, OperatorActionRequiredError):
            raise
        except Exception as error:
            raise ProviderTransportError(
                "session verification transport failure"
            ) from error
        verdict = verification_verdict(verification)
        if verdict is not SessionDisposition.VERIFIED:
            return verdict, artifact, verification.reason
        return (
            verdict,
            artifact.model_copy(update={"verified_at": verification.verified_at}),
            None,
        )

    def _validate_artifact(
        self,
        artifact: SessionArtifact,
        recipe: LoginRecipe,
        account_key: str,
    ) -> SessionArtifact:
        artifact.assert_identity(recipe.provider, account_key)
        now = self._now().timestamp()
        for cookie in artifact.cookies:
            if not cookie_domain_allowed(cookie.domain, recipe.allowed_cookie_domains):
                raise ValueError("session cookie domain is not allowed")
        usable = tuple(
            cookie
            for cookie in artifact.cookies
            if cookie.expires is None or cookie.expires > now
        )
        if not usable:
            raise SessionRequiredError("session contains no usable cookies")
        if usable == artifact.cookies:
            return artifact
        return artifact.model_copy(update={"cookies": usable})

    def _assert_attempt_allowed(
        self,
        provider: str,
        stored: StoredSession | None,
    ) -> None:
        if stored is None:
            return
        if stored.status is SessionStatus.OPERATOR_ACTION:
            raise OperatorActionRequiredError(
                "session is blocked pending an explicit reset",
                provider=provider,
                reason_code=stored.failure_reason_code,
            )
        if (
            stored.status is SessionStatus.COOLDOWN
            and stored.retry_not_before is not None
            and self._now() < stored.retry_not_before
        ):
            raise SessionRequiredError("session login is in cooldown")

    def _persist_account_alert(
        self, provider: str, account_key: str, artifact: SessionArtifact | None
    ) -> None:
        evidence = MintFailureEvidence(
            stage=MintFailureStage.PAID_PROBE,
            category=MintFailureCategory.ACCOUNT_ALERT,
        )
        set_timing_failure(evidence)
        self._persist_failure(
            provider,
            account_key,
            MintOutcome.ACCOUNT_ALERT,
            prior_artifact=artifact,
            reason_code="account_alert",
        )

    def _persist_failure(
        self,
        provider: str,
        account_key: str,
        outcome: MintOutcome,
        *,
        prior_artifact: SessionArtifact | None = None,
        evidence: MintFailureEvidence | None = None,
        reason_code: str | None = None,
    ) -> None:
        stored_reason_code = reason_code or (
            evidence.reason_code if evidence is not None else None
        )
        terminal = _OPERATOR_FAILURES.get(outcome)
        if terminal is not None:
            stored = StoredSession(
                status=SessionStatus.OPERATOR_ACTION,
                artifact=prior_artifact,
                last_failure=terminal,
                failure_reason_code=stored_reason_code,
            )
        else:
            stored = StoredSession(
                status=SessionStatus.COOLDOWN,
                artifact=prior_artifact,
                last_failure=TerminalFailure.INFRASTRUCTURE_ERROR,
                failure_reason_code=stored_reason_code,
                retry_not_before=self._now() + _COOLDOWN,
            )
        self._write(provider, account_key, stored)

    def _load(self, provider: str, account_key: str) -> StoredSession | None:
        path = self._state_path(provider, account_key)
        try:
            return self._read_stored_session(path, provider, account_key)
        except (OSError, ValidationError, ValueError):
            # A writer may have replaced the invalid generation after this
            # read. Recheck under the generation lock before moving anything.
            with self._lock(provider, account_key):
                return self._load_locked(provider, account_key)

    def _inspect(self, provider: str, account_key: str) -> StoredSession | None:
        """Read status state without creating directories, locks, or quarantine."""

        path = self._read_only_state_path(provider, account_key)
        try:
            return self._read_stored_session(path, provider, account_key)
        except (ValidationError, ValueError):
            # Status is advisory: malformed or mismatched state is reported as
            # requiring a session. Mutating consumers retain the quarantine path.
            return None
        except OSError as error:
            raise PersistenceError("session state read failed") from error

    def _load_locked(self, provider: str, account_key: str) -> StoredSession | None:
        path = self._state_path(provider, account_key)
        try:
            return self._read_stored_session(path, provider, account_key)
        except (OSError, ValidationError, ValueError):
            self._quarantine(path)
            return None

    @staticmethod
    def _read_stored_session(
        path: Path, provider: str, account_key: str
    ) -> StoredSession | None:
        try:
            payload = path.read_bytes()
        except FileNotFoundError:
            return None
        stored = StoredSession.model_validate_json(payload)
        if stored.artifact is not None:
            stored.artifact.assert_identity(provider, account_key)
        return stored

    def _write(
        self,
        provider: str,
        account_key: str,
        stored: StoredSession,
        *,
        connection_revision: str | None = None,
    ) -> None:
        with (
            timing_step(TimingStep.SESSION_PERSIST, provider=provider),
            self.connection_controls.publication(
                provider,
                account_key,
                revision=connection_revision,
                authority=stored.artifact is not None,
            ),
        ):
            self._write_untimed(provider, account_key, stored)

    def _write_untimed(
        self, provider: str, account_key: str, stored: StoredSession
    ) -> None:
        directory = self._provider_directory(provider)
        destination = self._state_path(provider, account_key)
        # Do not add a new field to legacy artifacts: schema-1 readers must
        # remain compatible until the first explicit profile-bound import.
        payload = (
            stored.model_dump_json(
                indent=2,
                exclude={"artifact": {"browser_profile_id"}}
                if stored.artifact is not None
                and stored.artifact.browser_profile_id is None
                else None,
            ).encode("utf-8")
            + b"\n"
        )
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{account_key}.", suffix=".tmp", dir=directory
            )
        except OSError as error:
            raise PersistenceError("session state write failed") from error
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            self._fault("before_session_replace")
            os.replace(temporary, destination)
            self._fault("after_session_replace")
            os.chmod(destination, 0o600)
            _fsync_directory(directory)
        except OSError as error:
            temporary.unlink(missing_ok=True)
            raise PersistenceError("session state write failed") from error

    @contextmanager
    def _lock(
        self, provider: str, account_key: str, *, timeout_seconds: float | None = None
    ):
        directory = self._provider_directory(provider)
        path = directory / f"{account_key}.lock"
        lease = ordered_file_lease(
            path,
            kind=LeaseKind.SESSION_GENERATION,
            timeout_seconds=self._session_lock_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds,
        )
        try:
            lease.__enter__()
        except (LeaseBusyError, OSError) as error:
            raise PersistenceError("session lock failed") from error
        try:
            yield
        finally:
            try:
                lease.__exit__(None, None, None)
            except OSError as error:
                raise PersistenceError("session lock failed") from error

    def _quarantine(self, path: Path) -> None:
        timestamp = self._now().strftime("%Y%m%dT%H%M%S%fZ")
        quarantine = path.with_name(f"{path.stem}.invalid.{timestamp}.json")
        try:
            os.replace(path, quarantine)
            os.chmod(quarantine, 0o600)
            _fsync_directory(path.parent)
        except FileNotFoundError:
            return
        except OSError as error:
            raise PersistenceError(
                "invalid session state could not be quarantined"
            ) from error

    def _provider_directory(self, provider: str) -> Path:
        if not is_provider_key(provider):
            raise UsageError("invalid provider key")
        directory = self.root / "sessions" / provider
        self._ensure_private_directory(self.root / "sessions")
        self._ensure_private_directory(directory)
        return directory

    def _state_path(self, provider: str, account_key: str) -> Path:
        account_key = self._validated_account_key(account_key)
        return self._provider_directory(provider) / f"{account_key}.json"

    def _read_only_state_path(self, provider: str, account_key: str) -> Path:
        if not is_provider_key(provider):
            raise UsageError("invalid provider key")
        account_key = self._validated_account_key(account_key)
        return self.root / "sessions" / provider / f"{account_key}.json"

    @staticmethod
    def _validated_account_key(account_key: str) -> str:
        try:
            return require_account_key(account_key)
        except ValueError:
            raise UsageError("invalid session account key") from None

    def _verification_opens_a_browser(self, provider: str) -> bool:
        """Whether proving an existing session needs the browser plane.

        Defaults to False when nothing was injected, so a store built without
        the predicate keeps preparing only for acquisition.
        """

        if self._verification_requires_browser is None:
            return False
        return self._verification_requires_browser(provider)

    def _prepare_browser_environment(self, before_browser: Callable[[], None]) -> None:
        """Run the caller's environment preparation, keeping its failure class.

        A host that cannot supply a display has not failed to log in; it is
        missing infrastructure, and reporting it as a login failure would send
        the operator at the credentials instead of the host.
        """

        try:
            before_browser()
        except BrowserRuntimeError as error:
            failure = MintFailureEvidence(
                stage=MintFailureStage.PROFILE,
                category=MintFailureCategory.INFRASTRUCTURE,
            )
            set_timing_failure(failure)
            raise SessionRequiredError(failure.reason_code) from error

    def _recipe(self, provider: str) -> LoginRecipe:
        if not is_provider_key(provider):
            raise UsageError("invalid provider key")
        try:
            return self._recipes[provider]
        except KeyError as error:
            raise UsageError(f"no login recipe registered for {provider}") from error

    def _adapter(self, provider: str) -> SessionAcquisitionAdapter:
        try:
            return self._adapters[provider]
        except KeyError as error:
            raise UsageError(
                f"no session acquisition adapter registered for {provider}"
            ) from error

    def _mint_credentials(
        self,
        provider: str,
        adapter: SessionAcquisitionAdapter,
        browser: AuthBrowserSession,
        *,
        account_key: str,
        challenge_mode: ChallengeMode,
    ) -> FlowCandidate:
        self.connection_controls.require_maintenance(provider, account_key)
        self._assert_credential_ready(provider)
        if self._diagnostic_trace is not None:
            self._diagnostic_trace.require_write_ready(provider)
        with (
            timing_step(TimingStep.CREDENTIAL_FLOW, provider=provider),
            _browser_attempt(browser, provider, AttemptPurpose.LOGIN),
        ):
            candidate = adapter.mint_credentials(
                browser,
                account_key=account_key,
                challenge_mode=challenge_mode,
            )
            _capture_candidate_proof(browser, candidate)
            return candidate

    def _assert_credential_ready(self, provider: str) -> None:
        probe = self._credential_readiness_probes.get(provider)
        if probe is None:
            return
        failure = MintFailureEvidence(
            stage=MintFailureStage.CREDENTIAL,
            category=MintFailureCategory.INFRASTRUCTURE,
        )
        try:
            readiness = probe()
        except Exception as error:
            set_timing_failure(failure)
            raise SessionRequiredError(failure.reason_code) from error
        if readiness.provider != provider or not readiness.ready:
            set_timing_failure(failure)
            raise SessionRequiredError(failure.reason_code)

    def _profile_access(self) -> BrowserProfileAccess:
        if self._profiles is None:
            raise RuntimeError("browser profile access is unavailable")
        return self._profiles

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise PersistenceError("session clock must return an aware datetime")
        return now

    def _fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    @staticmethod
    def _ensure_private_directory(path: Path) -> None:
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(path, 0o700)
        except OSError as error:
            raise PersistenceError("session state directory is unavailable") from error


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
