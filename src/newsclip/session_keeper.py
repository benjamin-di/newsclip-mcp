"""Scheduled session upkeep with an explicit credential budget.

The keeper is the only actor allowed to renew a session without a human
present. It exists because the serving process deliberately cannot log in:
holding that capability in a long-running, publicly routed process would put
subscription credentials behind the same attack surface as article retrieval.

Its decisions are bounded rather than adaptive. It spends at most a fixed
number of credential attempts per day and treats every terminal login verdict
as an operator escalation instead of a reason to try again. Nothing here
clears a hold, and nothing retries a provider that has just refused.

It refuses to touch a held provider with one deliberate exception: a hold
whose named remedy *is* session renewal or promotion. Blocking the renewer on
those created a closed loop — the keeper refused to act, so nothing verified,
so the hold that clears on verification never cleared. Attempting under such a
hold stays bounded by warm-first reuse, readiness gating, and the same daily
credential budget; success clears the hold through the guard's evidence path.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext, suppress
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import UUID

from pydantic import Field
from signin_window.sessions import AttemptBudget

from .acquisition import (
    ChallengeMode,
    LoginResult,
)
from .errors import (
    NOT_ENTITLED_REASON,
    RETRYABLE_READ_FAILURES,
    ContentNotFullError,
    OperatorActionRequiredError,
    PersistenceError,
    ProviderDefenseError,
    ProviderTransportError,
    SessionRequiredError,
    retryable_read_reason,
)
from .keeper_outcomes import PAID_PROBE_INCONCLUSIVE, KeeperOutcome, RenewalDecision
from .models import (
    FrozenModel,
    ProviderReadiness,
    RecoveryHealth,
    RecoveryStatus,
    SessionHealth,
    SessionStatus,
)
from .provider_check import (
    ProviderCheckFailure,
    ProviderCheckObservation,
    ProviderCheckResult,
)
from .provider_guard import (
    SESSION_EVIDENCE_ACTIONS,
    GuardAction,
    GuardResult,
    ProviderGuardBusyError,
    ProviderHold,
)
from .provider_keys import PROVIDER_KEY_PATTERN, is_provider_key
from .recovery import RecoveryBusyError, RecoveryRecord, RecoveryStore
from .results import classify_error

_MAX_BUDGET_BYTES = 64 * 1024
_CREDENTIAL_MINT_NOT_PERMITTED = "credential_mint_not_permitted"
_CREDENTIAL_HOST_NOT_READY = "credential_host_not_ready"
_CREDENTIAL_BUDGET_SPENT = "credential_budget_spent"
_UNCLASSIFIED = "unclassified_error"
_DIAGNOSTIC_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,127}$"
_LOCK_TIMEOUT_SECONDS = 5.0
#: The budget is expressed per day; nothing has needed a second period.
_WINDOW = timedelta(hours=24)

#: Repeated inconclusive probes justify diagnostic review and reduced probe
#: frequency. Repetition of one article is not evidence of an account problem.
_PAID_PROBE_INCONCLUSIVE = PAID_PROBE_INCONCLUSIVE
_INCONCLUSIVE_STREAK = 3
#: The escalation's own reason: the action that actually resolves this.
_VERIFICATION_UNRESOLVED = "session_verification_unresolved"
#: The deployed keeper's cadence: the soonest a scheduled cycle can clear a
#: hold that blocks recovery, and so the watcher's floor for re-looking.
_HELD_RECOVERY_RECHECK = timedelta(hours=1)


#: A reason code is a short internal token such as ``account_alert``. Anything
#: else is dropped rather than written to a scheduler log, so no provider text
#: or secret material can ride out on this field.
_REASON_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _reason_code_value(candidate: str | None) -> str | None:
    if candidate is None:
        return None
    return candidate if _REASON_CODE.fullmatch(candidate) else None


def _reason_code(error: BaseException) -> str | None:
    return _reason_code_value(str(error))


def _failure_reason(error: BaseException) -> str:
    """Name every failure, so silence and "I do not know" cannot look alike.

    The shared classifier is the repository's single answer to "what class of
    failure is this", and exists so adapters do not each re-derive it. A
    specific bounded code from the error itself is kept when there is one;
    otherwise the shared category names it, and anything unrecognized is
    labelled rather than left empty.
    """

    # An article outside the subscription is a settled verdict, not a content
    # failure the automatic retry could change.
    if isinstance(error, ContentNotFullError) and str(error) == NOT_ENTITLED_REASON:
        return NOT_ENTITLED_REASON
    if isinstance(error, (ProviderTransportError, SessionRequiredError)):
        code = _reason_code(error)
        if code is not None and code not in {
            *RETRYABLE_READ_FAILURES,
            "content_not_full",
        }:
            return code
    classified = classify_error(error)
    if classified is not None:
        category, _ = classified
        return category.value
    return _UNCLASSIFIED


class KeeperAction(StrEnum):
    """What the keeper did, or why it deliberately did nothing."""

    IDLE = "idle"
    BUSY = "busy"
    FRESH = "fresh"
    RENEWED = "renewed"
    HELD = "held"
    COOLDOWN = "cooldown"
    OPERATOR_ACTION_REQUIRED = "operator_action_required"
    RENEWAL_FAILED = "renewal_failed"
    #: A sessionless provider served its canary article. Nothing was renewed
    #: because there is no session to renew; the cycle watched it instead.
    CHECKED = "checked"
    #: A sessionless provider stopped serving. Nothing here can renew its way
    #: out of that — its transport is what drifted.
    CHECK_FAILED = "check_failed"


class KeeperOverallState(StrEnum):
    """One unambiguous headline for humans and alert automation."""

    HEALTHY = "healthy"
    WAITING = "waiting"
    NEEDS_ATTENTION = "needs_attention"


class KeeperNextAction(StrEnum):
    """Stable operator action paired with the human-readable repair hint."""

    PROVIDER_CHECK_THEN_HEAL = "provider_check_then_heal"
    ALLOW_CREDENTIAL_MINT = "allow_credential_mint"
    REPAIR_KEEPER_READINESS = "repair_keeper_readiness"
    ACKNOWLEDGE_HOLD = "acknowledge_hold"
    REVIEW_ACCOUNT = "review_account"
    REVIEW_PROVIDER = "review_provider"
    HEAL = "heal"
    WAIT_FOR_RECOVERY = "wait_for_recovery"
    REVIEW_RECOVERY = "review_recovery"
    UPDATE_HTTP_FINGERPRINT = "update_http_fingerprint"


#: Actions that leave the provider usable right now.
_USABLE_ACTIONS = frozenset(
    {KeeperAction.FRESH, KeeperAction.RENEWED, KeeperAction.CHECKED}
)

#: Actions a person has to resolve. A cooldown is deliberately absent: it is
#: the system waiting exactly as designed, and paging someone for it trains
#: them to ignore the alerts that do matter.
_ATTENTION_ACTIONS = frozenset(
    {
        KeeperAction.HELD,
        KeeperAction.OPERATOR_ACTION_REQUIRED,
        KeeperAction.RENEWAL_FAILED,
        KeeperAction.CHECK_FAILED,
    }
)


class KeeperResult(FrozenModel):
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    action: KeeperAction
    status: SessionStatus | None = None
    recovery: RecoveryHealth | None = None
    recovery_blocker: str | None = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$"
    )
    recovery_retry_at: datetime | None = None
    automatic_recovery_action: (
        Literal["retry_article", "wait_for_provider_check", "blocked", "review"] | None
    ) = None
    automatic_recovery_due_at: datetime | None = None
    automatic_recovery_stalled: bool = False
    stale: bool = False
    credential_attempt: bool = False
    reason_code: str | None = None
    #: Ties this line to the run's evidence under the state root, the way the
    #: provider guard already does. Without it a scheduler log names an outcome
    #: with no way back to the trace that explains it.
    diagnostic_id: str | None = Field(default=None, pattern=_DIAGNOSTIC_ID_PATTERN)
    incident_id: str | None = Field(default=None, pattern=r"^incident-[0-9a-f]{24}$")
    renewal_unresolved: bool = False
    #: HTTP legs of this provider refused in the last 24 h while the browser
    #: served (``state/http-challenges``). Set only beside a provider_defense
    #: renewal, where it tells an aging fingerprint from an account problem.
    http_challenges_24h: int | None = Field(default=None, ge=0)
    renewal_revision: int | None = Field(default=None, ge=1, exclude=True)
    session_proof_verified: bool = Field(default=False, exclude=True)

    @property
    def usable(self) -> bool:
        """Whether the provider can serve a request right now."""

        return self.action in _USABLE_ACTIONS and not (
            self.recovery is not None
            and self.recovery.status is not RecoveryStatus.SUCCEEDED
        )

    @property
    def needs_attention(self) -> bool:
        """Whether this outcome requires a person, rather than more waiting."""

        if self.renewal_unresolved or self.automatic_recovery_stalled:
            return True
        if self.automatic_recovery_action in {
            "retry_article",
            "wait_for_provider_check",
        }:
            return False
        return self.action in _ATTENTION_ACTIONS or (
            self.recovery is not None and self.recovery.status is RecoveryStatus.FAILED
        )

    @property
    def overall_state(self) -> KeeperOverallState:
        if self.needs_attention:
            return KeeperOverallState.NEEDS_ATTENTION
        if self.usable:
            return KeeperOverallState.HEALTHY
        return KeeperOverallState.WAITING

    @property
    def next_action(self) -> KeeperNextAction | None:
        if self.automatic_recovery_stalled:
            return KeeperNextAction.REVIEW_RECOVERY
        if self.automatic_recovery_action in {
            "retry_article",
            "wait_for_provider_check",
        }:
            return KeeperNextAction.WAIT_FOR_RECOVERY
        if (
            self.recovery is not None
            and self.recovery.status is RecoveryStatus.PENDING
            and self.recovery.next_attempt_at is not None
            and not self.needs_attention
        ):
            return KeeperNextAction.WAIT_FOR_RECOVERY
        if not self.needs_attention:
            return None
        if self.recovery_blocker == "provider_held":
            return KeeperNextAction.ACKNOWLEDGE_HOLD
        if self.recovery_blocker == "account_action":
            return KeeperNextAction.REVIEW_ACCOUNT
        if self.automatic_recovery_action == "review":
            return KeeperNextAction.REVIEW_RECOVERY
        if self.recovery_blocker in {
            "recovery_budget_spent",
            "recovery_backoff",
            "provider_defense",
            "session_cooldown",
        }:
            return KeeperNextAction.WAIT_FOR_RECOVERY
        if self.recovery_blocker == "review_recovery":
            return KeeperNextAction.REVIEW_RECOVERY
        if self.recovery is not None and self.recovery.status is RecoveryStatus.FAILED:
            if self.recovery_blocker == "ready":
                return KeeperNextAction.HEAL
            return KeeperNextAction.PROVIDER_CHECK_THEN_HEAL
        if self.reason_code in {
            _VERIFICATION_UNRESOLVED,
            "session_promotion_required",
            _PAID_PROBE_INCONCLUSIVE,
        }:
            return KeeperNextAction.PROVIDER_CHECK_THEN_HEAL
        if self.reason_code == _CREDENTIAL_MINT_NOT_PERMITTED:
            return KeeperNextAction.ALLOW_CREDENTIAL_MINT
        if self.reason_code == _CREDENTIAL_HOST_NOT_READY:
            return KeeperNextAction.REPAIR_KEEPER_READINESS
        if self.action is KeeperAction.HELD:
            return KeeperNextAction.ACKNOWLEDGE_HOLD
        if self.action is KeeperAction.OPERATOR_ACTION_REQUIRED:
            return KeeperNextAction.REVIEW_ACCOUNT
        if self.action is KeeperAction.CHECK_FAILED:
            return KeeperNextAction.REVIEW_PROVIDER
        if self.reason_code == "provider_defense":
            # The edge refused the renewal probe, and it has also refused
            # reads the browser then served: the session is fine and the HTTP
            # fingerprint is what aged (2026-10-19, FT chrome146).
            if self.http_challenges_24h:
                return KeeperNextAction.UPDATE_HTTP_FINGERPRINT
            return KeeperNextAction.REVIEW_PROVIDER
        return KeeperNextAction.HEAL

    @property
    def repair_hint(self) -> str | None:
        """The one call that resolves this outcome, or None when none does.

        An alert that names only a failure makes the reader go find the
        runbook; the eight-day Bloomberg loop was not helped by knowing it
        said "transport failure". This maps the outcome to the specific
        repair, so the notification carries its own fix.

        Templated on the provider key alone — never on provider text, error
        detail, or anything read from a secret.
        """

        if self.next_action is KeeperNextAction.UPDATE_HTTP_FINGERPRINT:
            return (
                f"{self.provider}'s edge also refused "
                f"{self.http_challenges_24h} HTTP read(s) in 24 h that the "
                "browser served: the session is likely fine and the HTTP "
                "fingerprint has aged. Confirm with ops provider_check, then "
                "upgrade curl-cffi and DEFAULT_HTTP_IMPERSONATION; do not "
                "submit credentials"
            )
        if (
            self.reason_code == "provider_defense"
            and self.next_action is KeeperNextAction.REVIEW_PROVIDER
        ):
            return (
                "review the retained provider challenge and current ops health; "
                "preserve cooldowns and do not repeat credential submissions"
            )
        if self.automatic_recovery_stalled:
            if self.automatic_recovery_action == "wait_for_provider_check":
                return (
                    "the expected scheduled provider check has not arrived; inspect "
                    "the daily monitor and its evidence before retrying the article"
                )
            return (
                "automatic article recovery missed its eligible deadline; "
                "inspect the recovery watcher and keeper"
            )
        if self.automatic_recovery_action == "retry_article":
            due = (
                self.automatic_recovery_due_at.isoformat()
                if self.automatic_recovery_due_at
                else "the next eligible cycle"
            )
            return (
                "one credential-free retry of the exact article is scheduled "
                f"for {due}; "
                "no manual heal is needed"
            )
        if self.automatic_recovery_action == "wait_for_provider_check":
            return (
                "waiting for a newer healthy scheduled provider check; the keeper "
                "will consume that proof once to recheck the exact article "
                "without credentials"
            )
        if (
            self.recovery is not None
            and self.recovery.status is RecoveryStatus.PENDING
            and self.recovery.next_attempt_at is not None
            and not self.needs_attention
        ):
            return (
                f"recovery scheduled for {self.recovery.next_attempt_at.isoformat()}; "
                "inspect ops health if it remains pending after that time"
            )
        if not self.needs_attention:
            return None
        provider = self.provider
        if self.recovery_blocker == "provider_held":
            return (
                "inspect ops health and the retained incident; review the exact hold "
                "before acknowledge_hold; heal cannot bypass it"
            )
        if self.recovery_blocker == "account_action":
            return "review the account state in ops health; do not retry credentials"
        if self.automatic_recovery_action == "review":
            return (
                "automatic recovery has stopped; review the retained failure and "
                "allowance history. If a further manual retry is justified, obtain "
                "a newer healthy provider_check and run credential-free heal "
                "within current guards and budgets"
            )
        if self.recovery_blocker in {
            "recovery_budget_spent",
            "recovery_backoff",
            "provider_defense",
            "session_cooldown",
        }:
            until = (
                self.recovery_retry_at.isoformat()
                if self.recovery_retry_at
                else "the restriction is resolved"
            )
            return (
                f"recovery is blocked by {self.recovery_blocker} until {until}; "
                "then inspect ops health and obtain a new healthy provider_check "
                "before heal; the reported failure remains unresolved"
            )
        if self.recovery_blocker == "review_recovery":
            return (
                "inspect ops health and the retained recovery diagnostic; "
                "repair the worker/state failure, then run provider_check; a newer "
                "healthy check permits a bounded credential-free heal"
            )
        if self.recovery_blocker == "ready":
            return (
                f"ops heal(provider={provider!r}, allow_credential_mint=False) "
                "can consume the newer FULL check for one exact-article read"
            )
        if self.recovery is not None and self.recovery.status is RecoveryStatus.FAILED:
            return (
                f"run ops provider_check(provider={provider!r}); if healthy, "
                f"ops heal(provider={provider!r}, allow_credential_mint=False) "
                "can recheck the exact failed article once while budget, "
                "backoff and guards permit"
            )
        if self.reason_code in {
            _VERIFICATION_UNRESOLVED,
            "session_promotion_required",  # previously persisted outcomes
            _PAID_PROBE_INCONCLUSIVE,
        }:
            # Verify before promoting: the 2026-08-06 Bloomberg escalation
            # was a probe that could not read its page, not a dead session —
            # a FULL guarded canary disproves "unentitled" (its contract
            # requires full content AND an identity match), and then the
            # latch clears with one bounded renewal instead of a cookie hunt.
            return (
                f"review the retained probe and run ops provider_check("
                f"provider={provider!r}); if healthy, run ops heal("
                f"provider={provider!r}, allow_credential_mint=False). A failed "
                "check alone does not establish an account problem"
            )
        if self.reason_code == _CREDENTIAL_MINT_NOT_PERMITTED:
            return (
                f"permit one bounded credential submission: newsclip auth keep "
                f"{provider} --allow-credential-mint"
            )
        if self.reason_code == _CREDENTIAL_HOST_NOT_READY:
            return (
                f"this host cannot complete {provider}'s login; check "
                f"`newsclip health` for the missing requirement"
            )
        if self.action is KeeperAction.HELD:
            return (
                f"review the hold, then: ops acknowledge_hold("
                f"provider={provider!r}, hold_id=...)"
            )
        if self.action is KeeperAction.OPERATOR_ACTION_REQUIRED:
            # Terminal account/login verdicts are the one class where the
            # owner knows facts the system cannot; never suggest a retry.
            return (
                f"account state changed for {provider} — verify the account "
                f"manually; do not retry the login blindly"
            )
        if self.action is KeeperAction.CHECK_FAILED and self.recovery is not None:
            return "session recovery completed; review the retained article diagnostic"
        if self.action is KeeperAction.CHECK_FAILED:
            # There is no session here to renew, so the usual repairs do not
            # apply and suggesting one would send the reader in a circle. What
            # drifted is the transport, and re-characterizing it by hand is the
            # sanctioned repair (ROADMAP.md, "Reuters transport recovery").
            return (
                f"{provider} has no session to renew; its transport stopped "
                f"serving. Review `newsclip health` and the retained incident, "
                f"then re-characterize and re-pin — do not retry blindly"
            )
        return f"ops heal(provider={provider!r}) after reviewing `newsclip health`"

    def public_dict(self) -> dict[str, Any]:
        omitted = {
            name
            for name in (
                "recovery",
                "recovery_blocker",
                "recovery_retry_at",
                "automatic_recovery_action",
                "automatic_recovery_due_at",
                "incident_id",
            )
            if getattr(self, name) is None
        }
        if self.automatic_recovery_action is None:
            omitted.add("automatic_recovery_stalled")
        if not self.renewal_unresolved:
            omitted.add("renewal_unresolved")
        if self.http_challenges_24h is None:
            omitted.add("http_challenges_24h")
        payload = self.model_dump(mode="json", exclude=omitted)
        payload["overall_state"] = self.overall_state.value
        next_action = self.next_action
        if next_action is not None:
            payload["next_action"] = next_action.value
        hint = self.repair_hint
        if hint is not None:
            payload["repair_hint"] = hint
        return payload


class KeeperPolicy(FrozenModel):
    """Bounds the keeper applies to every provider it services."""

    #: How long a proven session is trusted before it is renewed. Renewal
    #: re-verifies against the provider, so this is also how often a session
    #: that died server-side is discovered.
    max_age_hours: float = Field(default=12, gt=0, le=24 * 30)
    #: How many unattended credential submissions this provider may receive
    #: in a day. Zero disables them entirely.
    credential_attempts_per_day: int = Field(default=1, ge=0, le=10)


class _Guard(Protocol):
    """The keeper may read a hold, plus run the one bounded incident canary.

    It still cannot clear a hold by decision: the canary entry point clears
    only on a FULL check, self-bounds to one canary per provider per 24h in
    the guard store, and leaves every other hold class untouched (R9).
    """

    def peek(self, provider: str) -> ProviderHold | None: ...

    def last_check(self, provider: str) -> ProviderCheckObservation | None: ...

    def incident_canary_due_at(self, provider: str) -> datetime | None: ...

    def run_incident_review_canary(
        self,
        provider: str,
        check_provider: Callable[[], ProviderCheckResult],
    ) -> GuardResult: ...


class _TransportDrip(Protocol):
    """The slow-drip re-pin, seen from the cycle that hosts it (R8).

    Deliberately narrow: the keeper starts one bounded measurement and never
    reads its verdict. Selecting candidates, counting passes, promoting, and
    parking an exhausted pool all live behind this call.
    """

    def drip(self, provider: str) -> object: ...


class _HttpChallenges(Protocol):
    """Read-only count of HTTP legs refused while the browser served."""

    def count_since(self, provider: str, since: datetime) -> int: ...


class _Outcomes(Protocol):
    """Where every keep verdict is durably recorded for status readers.

    Persisting outcomes is what lets ``session_status`` stop reporting a
    stale "verified" while renewals fail: the reader derives freshness from
    the keeper's last recorded reality instead of trusting the session file
    alone. The keeper reads it back too, so a repeated failure can be told
    apart from a first one across process restarts.
    """

    def record(
        self, result: KeeperResult, *, max_age_hours: float
    ) -> KeeperOutcome: ...

    def load(self, provider: str) -> KeeperOutcome | None: ...

    def issue_observation(self, provider: str) -> int: ...

    def spend_escalation_canary(self, provider: str) -> bool: ...


class _Sessions(Protocol):
    """The narrowest session surface upkeep needs.

    These are typed against the real models rather than left open. The one
    serious defect this module has shipped was an inverted escalation class,
    which open types could not catch and these can.
    """

    def session_status(self, provider_key: str) -> SessionHealth: ...

    def recovery_generation(self, provider_key: str) -> UUID | None: ...

    def validate_recovery_url(self, provider_key: str, url: str) -> None: ...

    def verify_recovery_article(self, provider_key: str, url: str) -> None: ...

    def verify_recovery_session(self, provider_key: str) -> None: ...

    def defense_contained_until(self, provider_key: str) -> datetime | None: ...

    def defense_pending(self, provider_key: str) -> bool: ...

    def session_recovery_scope(
        self, provider_key: str
    ) -> AbstractContextManager[None]: ...

    def login(
        self,
        provider_key: str,
        *,
        headless: bool = ...,
        allow_credential_mint: bool = ...,
        challenge_mode: ChallengeMode = ...,
    ) -> LoginResult | SessionHealth: ...

    def requires_session_for_provider(self, provider_key: str) -> bool: ...

    def provider_check(self, provider_key: str) -> ProviderCheckResult: ...


class CredentialBudget(AttemptBudget):
    """Application errors and existing ledger paths over shared accounting."""

    def __init__(
        self,
        root: Path,
        *,
        utc_now: Callable[[], datetime],
        lock_timeout_seconds: float = 5,
    ) -> None:
        super().__init__(
            root,
            utc_now=utc_now,
            lock_timeout_seconds=lock_timeout_seconds,
            error_type=PersistenceError,
            label="session keeper budget",
        )

    def _path(self, provider: str) -> Path:
        if not is_provider_key(provider):
            raise PersistenceError("session keeper provider key is invalid")
        return self.root / f"{provider}.json"


class SessionKeeper:
    """Decide and perform one bounded upkeep step for one provider."""

    def __init__(
        self,
        *,
        guard: _Guard,
        sessions: _Sessions,
        budget: CredentialBudget,
        readiness_probe: Callable[[str], ProviderReadiness | None],
        policy: KeeperPolicy,
        utc_now: Callable[[], datetime],
        diagnostic_id: str | None = None,
        outcomes: _Outcomes | None = None,
        recovery_store: RecoveryStore | None = None,
        transport_pins: _TransportDrip | None = None,
        http_challenges: _HttpChallenges | None = None,
        challenge_mode: ChallengeMode = ChallengeMode.AUTO,
    ) -> None:
        self._guard = guard
        self._sessions = sessions
        self._budget = budget
        self._readiness_probe = readiness_probe
        self._policy = policy
        self._utc_now = utc_now
        self._diagnostic_id = diagnostic_id
        self._outcomes = outcomes
        self._recovery_store = recovery_store
        self._challenge_mode = challenge_mode
        # Optional: the deployment injects it, tests mostly do not. Absent,
        # the watch behaves exactly as it did before R8.
        self._transport_pins = transport_pins
        self._http_challenges = http_challenges

    def _result(
        self,
        *,
        provider: str,
        action: KeeperAction,
        status: SessionStatus | None = None,
        stale: bool = False,
        credential_attempt: bool = False,
        reason_code: str | None = None,
        incident_id: str | None = None,
        renewal_revision: int | None = None,
    ) -> KeeperResult:
        """Build one result, always carrying the run's evidence reference."""

        return KeeperResult(
            provider=provider,
            action=action,
            status=status,
            stale=stale,
            credential_attempt=credential_attempt,
            reason_code=reason_code,
            diagnostic_id=self._diagnostic_id,
            incident_id=incident_id,
            renewal_revision=renewal_revision,
        )

    def keep(
        self,
        provider: str,
        *,
        allow_credential_mint: bool,
        ignore_escalation: bool = False,
        recovery_only: bool = False,
        reconcile_failed_recovery: bool = False,
    ) -> KeeperResult:
        store = self._recovery_store
        try:
            with store.operation(provider) if store is not None else nullcontext():
                recovery = self._recover(
                    provider,
                    allow_credential_mint=allow_credential_mint,
                    scheduled=not recovery_only,
                    reconcile_failed=reconcile_failed_recovery,
                )
                if recovery is not None:
                    return self._with_recovery(provider, recovery)
                if recovery_only:
                    return self._with_recovery(
                        provider,
                        self._result(provider=provider, action=KeeperAction.IDLE),
                    )
                result = self._keep(
                    provider,
                    allow_credential_mint=allow_credential_mint,
                    ignore_escalation=ignore_escalation,
                )
                result = self._record(result)
                return self._with_recovery(provider, result)
        except (RecoveryBusyError, ProviderGuardBusyError):
            # A guarded check in flight owns the provider's guard lock. That
            # is contention, like a competing keeper, not a worker failure:
            # reporting it as persistence would park recovery for review.
            return self._result(provider=provider, action=KeeperAction.BUSY)

    def _record(self, result: KeeperResult) -> KeeperResult:
        if self._outcomes is not None:
            outcome = self._outcomes.record(
                result, max_age_hours=self._policy.max_age_hours
            )
            if result.renewal_revision is not None:
                decision = outcome.renewal_decision(result.renewal_revision)
                status = self._sessions.session_status(result.provider).status
                if (
                    decision is RenewalDecision.VERIFIED
                    and status is SessionStatus.VERIFIED
                ):
                    return self._result(
                        provider=result.provider,
                        action=KeeperAction.RENEWED,
                        status=status,
                        credential_attempt=result.credential_attempt,
                    ).model_copy(update={"session_proof_verified": True})
                # A newer uncommitted observation also invalidates old proof.
                # Preserve an actual failure result; never copy a presentation
                # action such as FRESH or CHECKED as renewal authority.
                if (
                    decision is RenewalDecision.UNRESOLVED
                    and not result.session_proof_verified
                ):
                    return result
                return self._result(
                    provider=result.provider,
                    action=KeeperAction.RENEWAL_FAILED,
                    status=status,
                    credential_attempt=result.credential_attempt,
                    reason_code=outcome.renewal_reason_code or _VERIFICATION_UNRESOLVED,
                    incident_id=outcome.incident_id,
                )
        return result

    def inspect_recovery(self, provider: str) -> KeeperResult:
        """Read current eligibility without renewal, migration or provider I/O."""
        return self._with_recovery(
            provider, self._result(provider=provider, action=KeeperAction.IDLE)
        )

    def _recovery_restriction(
        self, record: RecoveryRecord, *, require_proof: bool = True
    ) -> tuple[str | None, datetime | None]:
        """Guard and proof eligibility, shared by heal and its public result."""
        store = self._recovery_store
        assert store is not None
        provider = record.provider
        contained = self._sessions.defense_contained_until(provider)
        if contained is not None and contained > self._utc_now():
            return "provider_defense", contained
        if self._guard.peek(provider) is not None:
            return "provider_held", None
        if self._sessions.defense_pending(provider):
            return "provider_defense", None
        health = self._sessions.session_status(provider)
        if health.status is SessionStatus.OPERATOR_ACTION:
            return "account_action", None
        if (
            health.retry_not_before is not None
            and health.retry_not_before > self._utc_now()
        ):
            return "recovery_backoff", health.retry_not_before
        observation = self._guard.last_check(provider)
        checked_at = (
            observation.checked_at
            if observation is not None and observation.check.ok
            else None
        )
        blocker = store.reconciliation_blocker(
            record, verified_check_at=checked_at, require_proof=require_proof
        )
        if blocker == "provider_check_required" and record.health.reason in {
            "recovery_worker_failed",
            "interrupted_reconciliation",
            "persistence",
            "unclassified",
        }:
            return "review_recovery", None
        retry_at = (
            record.health.budget_reset_at
            if blocker == "recovery_budget_spent"
            else record.not_before
            if blocker == "recovery_backoff"
            else None
        )
        return blocker, retry_at

    def _automatic_recovery(self, record: RecoveryRecord) -> dict[str, Any]:
        """One read-only plan used for scheduling and public diagnostics."""
        store = self._recovery_store
        assert store is not None
        if record.health.status is RecoveryStatus.SUCCEEDED:
            return {}
        pending_read = (
            record.health.status is RecoveryStatus.PENDING
            and record.reconciliation_started
        )
        running_read = (
            record.health.status is RecoveryStatus.RUNNING
            and record.reconciliation_started
        )
        transient = record.health.reason in RETRYABLE_READ_FAILURES
        if (
            not pending_read
            and not running_read
            and (
                not store.automatic_retry_available(record)
                or not (transient or record.health.reason == "content_not_full")
            )
        ):
            return (
                {"automatic_recovery_action": "review"}
                if record.health.status is RecoveryStatus.FAILED
                else {}
            )
        blocker, retry_at = self._recovery_restriction(
            record, require_proof=not (transient or pending_read or running_read)
        )
        if blocker in {
            "provider_held",
            "account_action",
            "provider_defense",
            "review_recovery",
        }:
            return {"automatic_recovery_action": "blocked"}
        observation = self._guard.last_check(record.provider)
        proof_retry = not (transient or pending_read or running_read)
        if proof_retry and not store.valid_reconciliation_proof(
            record,
            observation.checked_at
            if observation is not None and observation.check.ok
            else None,
        ):
            # Missing monitor activity has a bounded expectation. A newer
            # failed observation is an unmet dependency, not a stuck worker.
            floor = record.last_failed_at or record.health.requested_at
            due = (
                floor + timedelta(hours=25)
                if observation is None
                or observation.checked_at <= floor
                or observation.checked_at > self._utc_now()
                else None
            )
            if due is not None and retry_at is not None:
                due = max(due, retry_at)
            return {
                "automatic_recovery_action": "wait_for_provider_check",
                "automatic_recovery_due_at": due,
                "automatic_recovery_stalled": due is not None
                and self._utc_now() > due + timedelta(minutes=16)
                and blocker not in {"recovery_budget_spent", "recovery_backoff"},
            }
        due = store.retry_not_before(record)
        if retry_at is not None:
            due = max(due, retry_at)
        if proof_retry and observation is not None:
            due = max(due, observation.checked_at)
        grace = timedelta(minutes=76 if proof_retry else 16)
        if running_read and record.health.recent_attempts:
            due = record.health.recent_attempts[-1].started_at
        return {
            "automatic_recovery_action": "retry_article",
            "automatic_recovery_due_at": due,
            "automatic_recovery_stalled": self._utc_now() > due + grace
            and (blocker is None or running_read),
        }

    def _with_recovery(self, provider: str, result: KeeperResult) -> KeeperResult:
        result = self._with_http_challenges(
            provider, self._with_renewal(provider, result)
        )
        store = self._recovery_store
        record = store.load(provider) if store is not None else None
        if record is None:
            return result
        update: dict[str, Any] = {"recovery": record.health}
        if record.health.status is RecoveryStatus.FAILED:
            blocker, retry_at = self._recovery_restriction(record)
            update.update(
                recovery_blocker=blocker or "ready", recovery_retry_at=retry_at
            )
        update.update(self._automatic_recovery(record))
        return result.model_copy(update=update)

    def _with_http_challenges(
        self, provider: str, result: KeeperResult
    ) -> KeeperResult:
        """Attach recent refused HTTP reads to a provider_defense outcome.

        Read-only and best effort: an unreadable log leaves the outcome as it
        was (review_provider), never hides it.
        """
        if self._http_challenges is None or result.reason_code != "provider_defense":
            return result
        try:
            count = self._http_challenges.count_since(
                provider, self._utc_now() - timedelta(days=1)
            )
        except PersistenceError:
            return result
        return result.model_copy(update={"http_challenges_24h": count})

    def _with_renewal(self, provider: str, result: KeeperResult) -> KeeperResult:
        """Project the same unresolved renewal and eligibility in both interfaces."""
        if self._outcomes is not None and result.action in {
            KeeperAction.FRESH,
            KeeperAction.CHECKED,
            KeeperAction.RENEWED,
            KeeperAction.IDLE,
        }:
            outcome = self._outcomes.load(provider)
            if outcome is not None and outcome.consecutive_renewal_failures:
                result = result.model_copy(
                    update={
                        "renewal_unresolved": True,
                        "reason_code": outcome.renewal_reason_code
                        or outcome.reason_code,
                        "incident_id": outcome.incident_id,
                    }
                )
        if not result.renewal_unresolved:
            return result
        blocker, retry_at = self._renewal_blocker(provider)
        return result.model_copy(
            update={"recovery_blocker": blocker, "recovery_retry_at": retry_at}
        )

    def _renewal_blocker(self, provider: str) -> tuple[str | None, datetime | None]:
        """Current brakes on using renewal proof, without claiming any budget."""
        if self._guard.peek(provider) is not None:
            return "provider_held", None
        health = self._sessions.session_status(provider)
        if health.status is SessionStatus.OPERATOR_ACTION:
            return "account_action", None
        contained = self._sessions.defense_contained_until(provider)
        if self._sessions.defense_pending(provider) or (
            contained is not None and contained > self._utc_now()
        ):
            return "provider_defense", contained
        if health.status is SessionStatus.COOLDOWN and not self._cooldown_elapsed(
            health
        ):
            return "session_cooldown", health.retry_not_before
        return None, None

    def _held_recovery_not_before(
        self, provider: str, hold: object, now: datetime
    ) -> datetime:
        """When the watcher should next look at a request a hold blocks.

        A hold cannot clear inside the 30-second watcher: only the scheduled
        keeper cycle (the daily canary, verified renewal) or an operator
        acknowledgement clears it, and that cycle re-reads the hold and
        releases this deferral itself. Polling every 20 minutes merely
        respawned an ``auth keep --recovery-only`` child (and display) about
        72 times a day while held. Wait at least one keeper cycle, and for an
        incident-review hold until its next permitted canary.
        """
        until = now + _HELD_RECOVERY_RECHECK
        if getattr(hold, "action", None) is GuardAction.INCIDENT_REVIEW_REQUIRED:
            due_at = self._guard.incident_canary_due_at(provider)
            if due_at is not None:
                until = max(until, due_at)
        return until

    def _recover(
        self,
        provider: str,
        *,
        allow_credential_mint: bool,
        scheduled: bool,
        reconcile_failed: bool,
    ) -> KeeperResult | None:
        store = self._recovery_store
        if store is None:
            return None
        pending = store.refresh(provider)
        if pending is None or pending.health.status is RecoveryStatus.SUCCEEDED:
            return None
        hold = self._guard.peek(provider)
        if pending.health.status is RecoveryStatus.FAILED:
            if reconcile_failed:
                if self._recovery_restriction(pending)[0] is not None:
                    return None
                observation = self._guard.last_check(provider)
                if observation is None or not observation.check.ok:
                    return None
                record = store.claim_verified_reconciliation(
                    provider,
                    self._diagnostic_id,
                    verified_check_at=observation.checked_at,
                )
            else:
                plan = self._automatic_recovery(pending)
                if plan.get("automatic_recovery_action") == "blocked":
                    if store.automatic_retry_due(pending) is not None:
                        store.defer_read_retry(
                            provider, until=self._utc_now() + timedelta(minutes=20)
                        )
                    return None
                due = plan.get("automatic_recovery_due_at")
                if (
                    plan.get("automatic_recovery_action") == "retry_article"
                    and due is not None
                    and due > self._utc_now()
                    and store.automatic_retry_due(pending) is not None
                ):
                    store.defer_read_retry(provider, until=due)
                if (
                    plan.get("automatic_recovery_action") != "retry_article"
                    or due is None
                    or due > self._utc_now()
                ):
                    return None
                if pending.health.reason in RETRYABLE_READ_FAILURES:
                    record = store.claim_read_retry(provider, self._diagnostic_id)
                elif scheduled:
                    observation = self._guard.last_check(provider)
                    if observation is None or not observation.check.ok:
                        return None
                    record = store.claim_verified_reconciliation(
                        provider,
                        self._diagnostic_id,
                        verified_check_at=observation.checked_at,
                        automatic=True,
                    )
                else:
                    return None
            if record is None:
                return None
            # A successful guarded canary proves the current authority can
            # serve FULL content. Recheck only the original URL; never turn
            # this evidence into permission to submit credentials.
            return self._execute_recovery(record, allow_credential_mint=False)
        if (
            scheduled
            and getattr(hold, "action", None) is GuardAction.INCIDENT_REVIEW_REQUIRED
            and not pending.reconciliation_started
        ):
            # A queued request must not suppress the existing bounded canary
            # that can clear this hold. The 30-second watcher never runs it.
            result = self._incident_review_canary(provider)
            self._record(result)
            return result
        now = self._utc_now()
        blocked_by_hold = hold is not None and (
            pending.reconciliation_started
            or getattr(hold, "action", None) not in SESSION_EVIDENCE_ACTIONS
        )
        if (
            scheduled
            and not blocked_by_hold
            and pending.health.status is RecoveryStatus.PENDING
            and pending.health.reason == "provider_held"
            and pending.health.next_attempt_at is not None
            and pending.health.next_attempt_at > now
        ):
            # The hold that deferred the watcher is gone (or now names this
            # renewal as its remedy). The scheduled cycle owns that re-read,
            # so the watcher's long deferral never delays recovery past it.
            pending = store.release_hold_deferral(provider) or pending
        if pending.health.status is RecoveryStatus.PENDING and (
            pending.health.next_attempt_at is not None
            and pending.health.next_attempt_at > now
        ):
            return self._result(provider=provider, action=KeeperAction.COOLDOWN)
        # Guards precede claim: a denied action consumes no recovery attempt.
        if blocked_by_hold:
            store.defer(
                provider,
                until=self._held_recovery_not_before(provider, hold, now),
                reason="provider_held",
            )
            return self._result(provider=provider, action=KeeperAction.HELD)
        contained = self._sessions.defense_contained_until(provider)
        if contained is not None and contained > now:
            store.defer(provider, until=contained, reason="provider_defense")
            return self._result(provider=provider, action=KeeperAction.COOLDOWN)
        if self._sessions.defense_pending(provider) and pending.reconciliation_started:
            store.defer(
                provider, until=now + timedelta(minutes=20), reason="provider_defense"
            )
            return self._result(provider=provider, action=KeeperAction.COOLDOWN)
        if self._sessions.defense_pending(provider) and (
            hold is None
            or getattr(hold, "action", None) not in SESSION_EVIDENCE_ACTIONS
        ):
            return self._defense_canary(provider)
        # Session-evidence remedies proceed through the normal durable claim:
        # it preserves the request's warm-only vs credential-required boundary.
        health = self._sessions.session_status(provider)
        if health.status is SessionStatus.OPERATOR_ACTION:
            final = store.finish(pending, reason="account_action")
            return self._result(
                provider=provider, action=KeeperAction.OPERATOR_ACTION_REQUIRED
            ).model_copy(update={"recovery": final.health})
        if health.status is SessionStatus.COOLDOWN and not self._cooldown_elapsed(
            health
        ):
            if health.retry_not_before is not None:
                store.defer(
                    provider, until=health.retry_not_before, reason="session_cooldown"
                )
            return self._result(provider=provider, action=KeeperAction.COOLDOWN)
        record = store.claim(provider, self._diagnostic_id)
        if record is None:
            settled = store.load(provider)
            if (
                settled is not None
                and settled.health.status is RecoveryStatus.SUCCEEDED
            ):
                return self._result(
                    provider=provider, action=KeeperAction.CHECKED
                ).model_copy(update={"recovery": settled.health})
            if settled is not None and settled.health.status is RecoveryStatus.PENDING:
                return self._result(provider=provider, action=KeeperAction.COOLDOWN)
            return self._result(
                provider=provider,
                action=KeeperAction.RENEWAL_FAILED,
                reason_code=settled.health.reason
                if settled
                else "recovery_unavailable",
            )
        return self._execute_recovery(
            record, allow_credential_mint=allow_credential_mint
        )

    def _execute_recovery(
        self, record: RecoveryRecord, *, allow_credential_mint: bool
    ) -> KeeperResult:
        store = self._recovery_store
        assert store is not None
        provider = record.provider
        session_verified = False
        result: KeeperResult | None = None
        reading_article = False
        try:
            self._sessions.validate_recovery_url(provider, str(record.url))
            current = self._sessions.recovery_generation(provider)
            read_only = record.reconciliation_started or (
                current is not None and current != record.generation_id
            )
            if not record.session_required or read_only:
                # A teaser is content evidence, not a request to renew. Let
                # the ordinary identity/FULL contract prove this exact URL.
                # Reconciliation never replays an interrupted login, even if
                # the read now establishes session loss.
                try:
                    reading_article = True
                    self._sessions.verify_recovery_article(provider, str(record.url))
                except SessionRequiredError:
                    reading_article = False
                    if read_only:
                        raise
                    record = store.require_session(record)
                else:
                    final = store.finish(record, reason=None, article_verified=True)
                    return self._result(
                        provider=provider, action=KeeperAction.CHECKED
                    ).model_copy(update={"recovery": final.health})
            result = self._keep(
                provider,
                allow_credential_mint=allow_credential_mint and record.session_required,
                force_due=True,
            )
            if (
                result.action is KeeperAction.RENEWED
                and result.status is not SessionStatus.VERIFIED
            ):
                result = self._result(
                    provider=provider,
                    action=KeeperAction.RENEWAL_FAILED,
                    reason_code="session_verification_unresolved",
                    credential_attempt=result.credential_attempt,
                )
            result = self._record(result)
            if not result.session_proof_verified:
                final = store.finish(
                    record, reason=result.reason_code or result.action.value
                )
                return result.model_copy(update={"recovery": final.health})
            session_verified = True
            store.session_verified(record)
            blocker, _ = self._renewal_blocker(provider)
            if blocker is not None:
                final = store.finish(record, reason=blocker, session_verified=True)
                return self._result(
                    provider=provider,
                    action=KeeperAction.CHECK_FAILED,
                    reason_code=blocker,
                    credential_attempt=result.credential_attempt,
                ).model_copy(update={"recovery": final.health})
            # Record authentication proof before content verification. A
            # malformed article cannot count as another failed login.
            reading_article = True
            self._sessions.verify_recovery_article(provider, str(record.url))
        except PersistenceError:
            # Leave RUNNING for bounded reconciliation after a state-write
            # fault. Do not claim this dispatch is safe to replay.
            raise
        except Exception as error:
            final = store.finish(
                record,
                reason=(retryable_read_reason(error) if reading_article else None)
                or _failure_reason(error),
                session_verified=session_verified,
            )
            failure = self._result(
                provider=provider,
                action=KeeperAction.CHECK_FAILED
                if session_verified or not record.session_required
                else KeeperAction.RENEWAL_FAILED,
                credential_attempt=result.credential_attempt
                if result is not None
                else False,
                reason_code=final.health.reason,
            )
            if not session_verified:
                failure = self._record(failure)
            return failure.model_copy(update={"recovery": final.health})
        final = store.finish(
            record, reason=None, session_verified=True, article_verified=True
        )
        assert result is not None
        return result.model_copy(update={"recovery": final.health})

    def _keep(
        self,
        provider: str,
        *,
        allow_credential_mint: bool,
        ignore_escalation: bool = False,
        force_due: bool = False,
    ) -> KeeperResult:
        # A hold is the repository's brake, and the keeper still never clears
        # one. It does distinguish *which* brake, though, because two hold
        # classes name session renewal or promotion as their own remedy:
        # blocking the renewer on them created a closed loop — the keeper
        # refused to act, so nothing verified, so the hold that clears on
        # verification never cleared. FT sat in exactly that loop for days
        # (2026-07-25 → 2026-07-28) reporting `held` hourly.
        #
        # Attempting renewal under such a hold is bounded by the same guards
        # as any other attempt: warm reuse first, readiness gating, and the
        # once-per-day credential budget. A success verifies the session,
        # which clears the hold through the guard's evidence path; a failure
        # is recorded and the day's attempt is spent. Defense, operator,
        # local-state, and incident-review holds still stop the keeper dead —
        # renewal is not their remedy and cannot be.
        hold = self._guard.peek(provider)
        if hold is not None:
            # Fail closed: only a hold that positively identifies itself as a
            # session-evidence class is renewable. An unreadable or unexpected
            # action blocks, so a future hold kind is never silently treated as
            # "the keeper may act on this".
            action = getattr(hold, "action", None)
            if action is GuardAction.INCIDENT_REVIEW_REQUIRED:
                # R9: renewal stays blocked dead, but the hold permits the
                # one daily canary that could produce the contradicting
                # evidence a content incident can never otherwise get — a
                # held provider performs no provider I/O, so without this it
                # can never clear. The guard bounds the cadence; an hourly
                # cycle still yields one canary per day.
                return self._incident_review_canary(provider)
            if action not in SESSION_EVIDENCE_ACTIONS:
                return self._result(provider=provider, action=KeeperAction.HELD)

        # A provider with no session has nothing to renew, and every session
        # verb raises for it — which is why these never entered a cycle at all
        # and their transports rotted unwatched. Watch them instead.
        if not self._sessions.requires_session_for_provider(provider):
            return self._watch(provider)

        # A retrieval defense needs proof of article recovery, not a login.
        # The existing controller bounds this check and refuses it in cooldown.
        if self._sessions.defense_pending(provider):
            if (
                hold is None
                or getattr(hold, "action", None) not in SESSION_EVIDENCE_ACTIONS
            ):
                return self._defense_canary(provider)
            # A previous read-only canary proved that authority needs renewal.
            # On a later eligible cycle, keep the ordinary warm-first remedy
            # (and its existing credential budget) under the same probe lock.
            # Reserving backoff spans BOTH warm and credential tiers.
            try:
                with self._sessions.session_recovery_scope(provider):
                    renewed = self._keep_session(
                        provider,
                        allow_credential_mint=allow_credential_mint,
                        ignore_escalation=ignore_escalation,
                        force_due=True,
                    )
                    if renewed.action is KeeperAction.RENEWED:
                        proof = self._defense_canary(provider)
                        if proof.action is not KeeperAction.CHECKED:
                            return proof.model_copy(
                                update={
                                    "status": renewed.status,
                                    "credential_attempt": renewed.credential_attempt,
                                }
                            )
                    return renewed
            except ProviderDefenseError:
                return self._result(provider=provider, action=KeeperAction.COOLDOWN)
        return self._keep_session(
            provider,
            allow_credential_mint=allow_credential_mint,
            ignore_escalation=ignore_escalation,
            force_due=force_due,
        )

    def _keep_session(
        self,
        provider: str,
        *,
        allow_credential_mint: bool,
        ignore_escalation: bool,
        force_due: bool,
    ) -> KeeperResult:
        health = self._sessions.session_status(provider)
        status = health.status
        if status is SessionStatus.OPERATOR_ACTION:
            return self._result(
                provider=provider,
                action=KeeperAction.OPERATOR_ACTION_REQUIRED,
                status=status,
                reason_code=_reason_code_value(health.failure_reason_code),
            )
        if status is SessionStatus.COOLDOWN and not self._cooldown_elapsed(health):
            return self._result(
                provider=provider,
                action=KeeperAction.COOLDOWN,
                status=status,
                reason_code=_reason_code_value(health.failure_reason_code),
            )

        stale = self._is_stale(health)
        if not stale and not force_due:
            return self._result(
                provider=provider,
                action=KeeperAction.FRESH,
                status=status,
            )
        if not ignore_escalation:
            escalation = self._inconclusive_escalation(provider)
            if escalation is not None and not self._escalation_canary_clears(provider):
                return escalation
            # A FULL canary contradicts "unentitled" with live evidence, so
            # the latch admits this one renewal instead of an operator page —
            # the 2026-08-06 Bloomberg escalation was a probe that could not
            # read its page while the session served full articles. A
            # renewal that succeeds resets the streak; one that fails again
            # re-latches with the canary spent for a day.
        return self._renew(
            provider,
            status=status,
            allow_credential_mint=allow_credential_mint,
        )

    def _defense_canary(self, provider: str) -> KeeperResult:
        result = self._guard.run_incident_review_canary(
            provider, lambda: self._sessions.provider_check(provider)
        )
        action = (
            KeeperAction.CHECKED
            if result.action is GuardAction.HEALTHY
            else KeeperAction.COOLDOWN
            if result.action is GuardAction.TRANSIENT_FAILURE
            else KeeperAction.HELD
        )
        return self._result(
            provider=provider, action=action, reason_code=result.action.value
        )

    def _incident_review_canary(self, provider: str) -> KeeperResult:
        """Run the guard's bounded canary under an incident-review hold (R9).

        A FULL result clears the hold through the guard's evidence path —
        the same principle as session-evidence holds clearing on verified
        renewal, not an acknowledgement. Anything else leaves the hold for
        review exactly as before.
        """

        result = self._guard.run_incident_review_canary(
            provider,
            lambda: self._sessions.provider_check(provider),
        )
        if result.action is GuardAction.HEALTHY:
            return self._result(
                provider=provider,
                action=KeeperAction.CHECKED,
                reason_code="incident_hold_cleared",
            )
        # Carry the guard's verdict: a suppressed canary, a contended store,
        # and a local-state fault must stay distinguishable in the outcome
        # record, or a persistence fault reads as normal bounded cadence.
        return self._result(
            provider=provider,
            action=KeeperAction.HELD,
            reason_code=result.action.value,
        )

    def _drip_one_candidate(self, provider: str) -> None:
        """Measure at most one candidate fingerprint this cycle (R8).

        Advisory work beside the watch, never its verdict: the drip heals the
        fast path, while the watch reports whether the provider is serving.
        A drip failure therefore changes no keeper action — it is swallowed
        so a pin-store fault cannot turn a healthy watch into an alert.
        """

        if self._transport_pins is None:
            return
        # Broad by design: this is advisory background work riding a
        # scheduled cycle whose real job is session upkeep, and a keeper
        # cycle must not die because a pin file was strange. A wiring
        # mistake cannot hide behind it, though — composition's conformance
        # test pins the injected object against the protocol, and a drip
        # that never progresses leaves a standing rot signal visible in
        # `newsclip health`.
        with suppress(Exception):
            self._transport_pins.drip(provider)

    def _watch(self, provider: str) -> KeeperResult:
        """Drift watch for a provider that has no session to keep.

        A pinned transport is a measurement of an adaptive edge, and it decays
        without anything in the product noticing: Reuters' pinned fingerprint
        was characterized on 2026-07-24, was refused four times on 2026-07-28,
        and nothing reported it because a sessionless provider entered no
        cycle. One bounded `provider_check` per cycle is what makes that
        visible the next day instead of the next time someone reads.

        No new scheduled actor: this runs inside the cycle that already exists.
        `provider_check` gates on the defense record before touching anything,
        so a watch can never feed a contained edge.

        When a rot signal stands and the provider is not contained, the same
        cycle also measures **one** candidate fingerprint (R8) — one request
        per hour, far below the volume that degraded this host's standing,
        and it stops entirely once a pin is healthy or the pool is exhausted.
        """

        result = self._sessions.provider_check(provider)
        if result.ok:
            # Drip after the check, never before: the defense gate lives
            # inside `provider_check`, and probing ahead of it would feed a
            # contained edge for a whole cooldown — the one thing this
            # watch has always promised not to do.
            self._drip_one_candidate(provider)
            return self._result(provider=provider, action=KeeperAction.CHECKED)
        if result.failure is ProviderCheckFailure.PROVIDER_DEFENSE:
            # Containment is the system waiting exactly as designed, and the
            # check declined to contact the provider at all. Paging for it
            # would train the reader to ignore the alerts that do matter —
            # the same reason a session cooldown is not an attention action.
            return self._result(
                provider=provider,
                action=KeeperAction.COOLDOWN,
                reason_code=result.failure.value,
            )
        # A failed check that is not containment is exactly when a rotted
        # fingerprint shows: the provider stopped serving and no cooldown is
        # armed. Measure one candidate so the drip can heal it.
        self._drip_one_candidate(provider)
        return self._result(
            provider=provider,
            action=KeeperAction.CHECK_FAILED,
            reason_code=result.failure.value if result.failure is not None else None,
        )

    def _renew(
        self,
        provider: str,
        *,
        status: SessionStatus,
        allow_credential_mint: bool,
    ) -> KeeperResult:
        # Warm first, without permission to spend anything. Only a warm
        # attempt that reports it needed credentials can justify claiming one,
        # so the budget counts submissions rather than intentions and needs no
        # way to hand an unused claim back.
        warm = self._attempt(provider, status=status, credential_attempt=False)
        if warm.reason_code != _CREDENTIAL_MINT_NOT_PERMITTED:
            return warm

        # Being unable to submit credentials and having already spent the day's
        # attempt are different things. The first needs a person; the second is
        # the window waiting to roll, and paging for it every cycle until then
        # is indistinguishable from a real account lockout.
        if not allow_credential_mint or self._policy.credential_attempts_per_day <= 0:
            return self._result(
                provider=provider,
                action=KeeperAction.OPERATOR_ACTION_REQUIRED,
                status=status,
                stale=True,
                reason_code=_CREDENTIAL_MINT_NOT_PERMITTED,
                renewal_revision=warm.renewal_revision,
            )
        if not self._credentials_usable(provider):
            return self._result(
                provider=provider,
                action=KeeperAction.OPERATOR_ACTION_REQUIRED,
                status=status,
                stale=True,
                reason_code=_CREDENTIAL_HOST_NOT_READY,
                renewal_revision=warm.renewal_revision,
            )
        if not self._budget.reserve(
            provider,
            limit=self._policy.credential_attempts_per_day,
        ):
            return self._result(
                provider=provider,
                action=KeeperAction.COOLDOWN,
                status=status,
                stale=True,
                reason_code=_CREDENTIAL_BUDGET_SPENT,
            )
        # Claimed before dispatch: a crash after this point must still consume
        # the attempt, because credentials may already have been submitted.
        return self._attempt(provider, status=status, credential_attempt=True)

    def _attempt(
        self,
        provider: str,
        *,
        status: SessionStatus,
        credential_attempt: bool,
    ) -> KeeperResult:
        from .renewal_observation import observe_renewal

        with observe_renewal(
            provider,
            self._outcomes.issue_observation if self._outcomes else None,
        ) as observation:
            result = self._attempt_observed(
                provider,
                status=status,
                credential_attempt=credential_attempt,
            )
            if result is None:
                result = self._renewed(provider, credential_attempt=credential_attempt)
            if observation is not None:
                # Local failures before any authority observation still have
                # an ordered outcome. Real verification stamps inside its lock.
                if observation.revision is None:
                    observation.stamp()
                result = result.model_copy(
                    update={"renewal_revision": observation.revision}
                )
            return result

    def _attempt_observed(
        self,
        provider: str,
        *,
        status: SessionStatus,
        credential_attempt: bool,
    ) -> KeeperResult | None:
        """Run one acquisition, returning its failure or None on success.

        A failure re-reads session state rather than echoing what was read
        before the attempt: acquisition can move a session on as it fails —
        to a cooldown, for instance — and reporting the earlier value would
        describe a state the provider is no longer in.
        """

        try:
            self._sessions.login(
                provider,
                headless=True,
                allow_credential_mint=credential_attempt,
                challenge_mode=self._challenge_mode,
            )
        except OperatorActionRequiredError as error:
            # A terminal account or login verdict, never retried here.
            return self._result(
                provider=provider,
                action=KeeperAction.OPERATOR_ACTION_REQUIRED,
                status=self._settled_status(provider, status),
                stale=True,
                credential_attempt=credential_attempt,
                reason_code=_reason_code_value(error.reason_code),
            )
        except PersistenceError:
            raise
        except Exception as error:
            # Local infrastructure often clears itself, but upkeep that fails
            # every cycle still ends in a dead session, so it is reported
            # rather than left silent.
            return self._result(
                provider=provider,
                action=KeeperAction.RENEWAL_FAILED,
                status=self._settled_status(provider, status),
                stale=True,
                credential_attempt=credential_attempt,
                reason_code=_failure_reason(error),
                incident_id=getattr(error, "incident_id", None),
            )
        return None

    def _settled_status(
        self,
        provider: str,
        fallback: SessionStatus,
    ) -> SessionStatus:
        """Read where the session ended up, falling back to where it began."""

        try:
            return self._sessions.session_status(provider).status
        except PersistenceError:
            raise
        except Exception:
            return fallback

    def _renewed(self, provider: str, *, credential_attempt: bool) -> KeeperResult:
        status = self._sessions.session_status(provider).status
        if status is not SessionStatus.VERIFIED:
            return self._result(
                provider=provider,
                action=KeeperAction.RENEWAL_FAILED,
                status=status,
                stale=True,
                credential_attempt=credential_attempt,
                reason_code=_VERIFICATION_UNRESOLVED,
            )
        return self._result(
            provider=provider,
            action=KeeperAction.RENEWED,
            status=status,
            stale=True,
            credential_attempt=credential_attempt,
        ).model_copy(update={"session_proof_verified": True})

    def _credentials_usable(self, provider: str) -> bool:
        """Report whether this host could complete the login at all.

        Readiness is the honest gate: a provider whose login can present a
        visual challenge reports its solver as a missing requirement when the
        host lacks it, so the keeper escalates instead of burning an attempt
        it cannot finish. Whether the day still has room is asked separately,
        because that answer is a wait rather than a person's problem.
        """

        readiness = self._readiness_probe(provider)
        return readiness is not None and not readiness.missing

    def _inconclusive_escalation(self, provider: str) -> KeeperResult | None:
        """Stop an unresolved probe streak without diagnosing the account.

        Preserve the existing bounded daily canary and operator-reviewed exit.
        Neither repetition nor a failed canary proves entitlement is missing.
        Historical counters remain diagnostic history, not account evidence.
        """

        if self._outcomes is None:
            return None
        try:
            prior = self._outcomes.load(provider)
        except PersistenceError:
            raise
        except Exception:  # noqa: BLE001 - a missing history is not an error
            return None
        if prior is None:
            return None
        # Counted on its own streak, not on the latest reason: Bloomberg was
        # observed alternating inconclusive probes with genuine transport
        # failures, and a latest-reason check never accumulates through that.
        streak = getattr(prior, "consecutive_inconclusive", 0)
        if streak < _INCONCLUSIVE_STREAK:
            return None
        return self._result(
            provider=provider,
            action=KeeperAction.OPERATOR_ACTION_REQUIRED,
            stale=True,
            reason_code=_VERIFICATION_UNRESOLVED,
        )

    def _escalation_canary_clears(self, provider: str) -> bool:
        """Whether live contradicting evidence should let a renewal through.

        The escalation's exit used to be exclusively manual
        (``ignore_escalation``), which converted every transient probe flake
        into an operator page. This is the R9 doctrine applied to the latch:
        at most one guarded canary per provider per 24h — spent before
        dispatch in the outcome store, so a crash cannot refund it — and only
        a FULL check (full content and an identity match, by
        ``ProviderCheckResult``'s own contract) clears. A containment
        verdict, any failure, or spent budget keeps the latch exactly as
        before; the defense gate lives inside ``provider_check``, so a
        contained edge is never contacted.
        """

        if self._outcomes is None:
            return False
        if not self._outcomes.spend_escalation_canary(provider):
            return False
        try:
            check = self._sessions.provider_check(provider)
        except PersistenceError:
            raise
        except Exception:  # noqa: BLE001 - no evidence keeps the latch
            return False
        return check.ok

    def _cooldown_elapsed(self, health: SessionHealth) -> bool:
        retry_not_before = health.retry_not_before
        return retry_not_before is None or retry_not_before <= self._utc_now()

    def _is_stale(self, health: SessionHealth) -> bool:
        if health.status is not SessionStatus.VERIFIED:
            return True
        verified_at = health.last_verified_at
        if verified_at is None:
            return True
        age = self._utc_now() - verified_at
        return age >= timedelta(hours=self._policy.max_age_hours)


__all__ = [
    "CredentialBudget",
    "KeeperAction",
    "KeeperNextAction",
    "KeeperOverallState",
    "KeeperPolicy",
    "KeeperResult",
    "SessionKeeper",
]
