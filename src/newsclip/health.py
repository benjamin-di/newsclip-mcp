"""One read-only snapshot of every provider's operational health.

The per-provider answers already existed but were scattered across four
stores and three commands, so "is the fleet healthy?" meant running
`auth status`, `provider-guard`, and reading keeper logs per provider — the
shape of question that went unanswered for eight days in the 2026-07-28
audit. This composes them once, contacting no provider.

Deliberately shared: the CLI `health` command and the ops MCP `health` tool
both call this, so the operator over SSH and the agent over MCP get the same
answer from one implementation.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal

from pydantic import AwareDatetime, Field

from .defense import DefenseRecord
from .errors import PersistenceError
from .http_challenges import HttpChallengeError, HttpChallengeSummary
from .incidents import IncidentEvidenceHealth
from .models import FrozenModel
from .provider_check import (
    ProviderCheckFailure,
    ProviderCheckObservation,
)
from .provider_guard import ProviderGuardPersistenceError
from .provider_keys import PROVIDER_KEY_PATTERN
from .transport_pins import TransportPinError, TransportPinState

_SERVING_EVIDENCE_MAX_AGE = timedelta(hours=30)


class ServingStatus(StrEnum):
    """What recent controlled evidence says about article retrieval."""

    AVAILABLE = "available"
    FAILED = "failed"
    CONTAINED = "contained"
    UNKNOWN = "unknown"


class HealthStateError(StrEnum):
    """A bounded local reason one health dimension could not be read."""

    SESSION_UNREADABLE = "session_unreadable"
    SERVING_EVIDENCE_UNREADABLE = "serving_evidence_unreadable"
    DEFENSE_UNREADABLE = "defense_unreadable"
    HOLD_UNREADABLE = "hold_unreadable"
    TRANSPORT_PIN_UNREADABLE = "transport_pin_unreadable"
    HTTP_CHALLENGES_UNREADABLE = "http_challenges_unreadable"
    RECOVERY_UNREADABLE = "recovery_unreadable"


class ServingHealth(FrozenModel):
    """Recent article-serving evidence, independent of session maintenance."""

    status: ServingStatus = ServingStatus.UNKNOWN
    checked_at: AwareDatetime | None = None
    check_age_seconds: float | None = Field(
        default=None,
        ge=0,
        allow_inf_nan=False,
    )
    failure: ProviderCheckFailure | None = None
    #: Non-durable advisory from the same canary: ``False`` when a required
    #: canary URL was missing from the first search page. It never changes
    #: ``status``; retrieval decides serving (and a FULL article is healthy).
    canary_in_search: bool | None = None


class ProviderHealth(FrozenModel):
    """Everything known locally about one provider's ability to serve."""

    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    recovery_action: dict[str, Any] | None = None
    #: The last controlled article canary, kept separate from session renewal.
    serving: ServingHealth = Field(default_factory=ServingHealth)
    #: The last canary may be healthy while a different article still needs
    #: recovery. It must not be read as proof that this episode is resolved.
    article_recovery_unresolved: bool = False
    #: Whether this provider uses durable session authority.
    session_backed: bool = False
    #: Redacted session health including the derived fresh/stale/degraded
    #: state; None for providers that need no session.
    session: dict[str, Any] | None = None
    #: Active defense containment, when a cooldown is armed.
    defense: dict[str, Any] | None = None
    #: Whether the defense cooldown or its expiry-canary lease is active now.
    defense_active: bool = False
    #: The durable guard hold suppressing scheduled checks, when one exists.
    hold: dict[str, Any] | None = None
    #: Arms recorded in the rolling 24 h ending now, counted against the
    #: reader's clock. `defense` alone says a cooldown exists; it does not say
    #: whether this is a first refusal or a provider that has refused every
    #: canary all day, and those want opposite responses.
    defense_arms_24h: int = Field(default=0, ge=0)
    #: Login requirements this host cannot satisfy (e.g. a missing vision
    #: CLI), so a rotted solver reads as "solver missing", never as a
    #: mysteriously broken provider.
    readiness_missing: tuple[str, ...] = ()
    #: Runtime transport-pin state for a provider that declares the browser
    #: challenge escalation: the active pin, a standing rot signal, and
    #: whether the candidate pool is exhausted. None for every other
    #: provider, which has no pin to heal (R8).
    transport_pin: dict[str, Any] | None = None
    #: Every measurable candidate has failed, so the slow drip has parked
    #: and the fast path will not restore itself. Escalation keeps serving;
    #: what is needed is a human characterizing new profiles or accepting
    #: the browser path. Named here because an hourly probe that has run out
    #: of things to try is otherwise indistinguishable from one still
    #: working (R8).
    transport_pin_pool_exhausted: bool = False
    #: HTTP legs this session provider's edge refused while the browser
    #: served, over the retained week: the newest refused profile and the
    #: 24 h / 7 d counts. Readers never notice these (the browser answers),
    #: so a rising count on the default profile is the visible sign that the
    #: HTTP fingerprint is aging. None for providers outside that path or
    #: with nothing refused in the window.
    http_challenges: dict[str, Any] | None = None
    #: Local state dimensions that could not be read. One damaged provider
    #: remains visible and does not suppress the rest of the fleet.
    state_errors: tuple[HealthStateError, ...] = ()
    blocking_reason: Literal["guard_hold", "provider_defense", "local_state"] | None = (
        None
    )
    next_probe_not_before: AwareDatetime | None = None
    evidence: IncidentEvidenceHealth = Field(default_factory=IncidentEvidenceHealth)

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class FleetHealth(FrozenModel):
    providers: tuple[ProviderHealth, ...] = ()

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def collect_fleet_health(
    *,
    utc_now: Callable[[], datetime] | None = None,
) -> FleetHealth:
    """Read every provider's stored health. Contacts no provider."""

    now = (utc_now or (lambda: datetime.now(UTC)))()

    from .composition import (
        build_auth_service,
        build_defense_state,
        build_http_challenge_store,
        build_provider_guard,
        build_registry,
        build_session_keeper,
        build_transport_pin_store,
    )
    from .providers.builtins import BUILTIN_PROVIDER_REGISTRATIONS

    service = build_auth_service()
    try:
        guard = build_provider_guard()
        defense = build_defense_state()
        pins = build_transport_pin_store()
        http_challenge_log = build_http_challenge_store()
        entries: list[ProviderHealth] = []
        registry = build_registry()
        for provider in sorted(registry, key=lambda item: item.key):
            key = provider.key
            registration = BUILTIN_PROVIDER_REGISTRATIONS.get(key)
            state_errors: list[HealthStateError] = []
            session_backed = provider.capabilities.session_kind != "none"
            session: dict[str, Any] | None
            if not session_backed:
                session = None
            else:
                try:
                    session = service.session_status(key).public_dict()
                except PersistenceError:
                    session = None
                    state_errors.append(HealthStateError.SESSION_UNREADABLE)

            observation: ProviderCheckObservation | None
            try:
                observation = guard.last_check(key)
            except ProviderGuardPersistenceError:
                observation = None
                state_errors.append(HealthStateError.SERVING_EVIDENCE_UNREADABLE)

            try:
                record = defense.status(key)
            except PersistenceError:
                record = None
                state_errors.append(HealthStateError.DEFENSE_UNREADABLE)

            try:
                hold = guard.peek(key)
            except ProviderGuardPersistenceError:
                hold = None
                state_errors.append(HealthStateError.HOLD_UNREADABLE)

            pin: TransportPinState | None = None
            if provider.capabilities.retrieval_challenge_escalation == "browser":
                try:
                    pin = pins.load(key)
                except TransportPinError:
                    pin = None
                    state_errors.append(HealthStateError.TRANSPORT_PIN_UNREADABLE)

            http_challenges: HttpChallengeSummary | None = None
            if session_backed and provider.capabilities.retrieval_transport == "http":
                try:
                    http_challenges = http_challenge_log.summary(key)
                except HttpChallengeError:
                    state_errors.append(HealthStateError.HTTP_CHALLENGES_UNREADABLE)

            defense_active = _defense_is_active(record, now=now)
            serving_state_unreadable = any(
                error
                in {
                    HealthStateError.SERVING_EVIDENCE_UNREADABLE,
                    HealthStateError.DEFENSE_UNREADABLE,
                    HealthStateError.HOLD_UNREADABLE,
                }
                for error in state_errors
            )
            readiness = (
                registration.check_credential_readiness()
                if registration is not None
                and registration.check_credential_readiness is not None
                else None
            )
            recovery = (session or {}).get("recovery")
            recovery_unresolved = (
                recovery is not None and recovery.get("status") != "succeeded"
            )
            incident_id = (
                getattr(hold, "incident_id", None)
                or getattr(record, "incident_id", None)
                or (
                    (recovery or {}).get("incident_id") if recovery_unresolved else None
                )
                or (session or {}).get("renewal_incident_id")
            )
            evidence = (
                service.incident_evidence(incident_id)
                if incident_id is not None
                else IncidentEvidenceHealth()
            )
            recovery_action = None
            if (
                recovery_unresolved
                or (session_backed and session is None)
                or (session or {}).get("consecutive_renewal_failures", 0) > 0
            ):
                try:
                    inspected = build_session_keeper(service).inspect_recovery(key)
                    recovery_action = {
                        field: value
                        for field, value in inspected.public_dict().items()
                        if field
                        in {
                            "next_action",
                            "repair_hint",
                            "recovery_blocker",
                            "recovery_retry_at",
                            "automatic_recovery_action",
                            "automatic_recovery_due_at",
                            "automatic_recovery_stalled",
                        }
                    }
                except (PersistenceError, ProviderGuardPersistenceError):
                    state_errors.append(HealthStateError.RECOVERY_UNREADABLE)
            entries.append(
                ProviderHealth(
                    provider=key,
                    recovery_action=recovery_action,
                    article_recovery_unresolved=recovery_unresolved,
                    serving=_derive_serving_health(
                        observation,
                        now=now,
                        contained=record is not None or hold is not None,
                        state_unreadable=serving_state_unreadable,
                    ),
                    session_backed=session_backed,
                    session=session,
                    defense=record.public_dict() if record is not None else None,
                    defense_active=defense_active,
                    defense_arms_24h=(
                        record.arms_within_day(now) if record is not None else 0
                    ),
                    hold=(hold.model_dump(mode="json") if hold is not None else None),
                    transport_pin=(
                        pin.model_dump(mode="json") if pin is not None else None
                    ),
                    transport_pin_pool_exhausted=(
                        pin is not None and pin.pool_exhausted_at is not None
                    ),
                    http_challenges=(
                        http_challenges.model_dump(mode="json")
                        if http_challenges is not None
                        else None
                    ),
                    readiness_missing=(
                        tuple(item.value for item in readiness.missing)
                        if readiness is not None
                        else ()
                    ),
                    state_errors=tuple(state_errors),
                    blocking_reason=(
                        "local_state"
                        if state_errors
                        else "guard_hold"
                        if hold is not None
                        else "provider_defense"
                        if record is not None
                        else None
                    ),
                    next_probe_not_before=(
                        max(
                            record.active_until,
                            record.probe_lease_until or record.active_until,
                        )
                        if record is not None and hold is None and not state_errors
                        else None
                    ),
                    evidence=evidence,
                )
            )
        return FleetHealth(providers=tuple(entries))
    finally:
        service.close()


def _derive_serving_health(
    observation: ProviderCheckObservation | None,
    *,
    now: datetime,
    contained: bool,
    state_unreadable: bool,
) -> ServingHealth:
    if observation is None:
        return ServingHealth(
            status=ServingStatus.CONTAINED if contained else ServingStatus.UNKNOWN
        )

    raw_age = (now - observation.checked_at).total_seconds()
    age = max(0.0, raw_age)
    if contained:
        return ServingHealth(
            status=ServingStatus.CONTAINED,
            checked_at=observation.checked_at,
            check_age_seconds=age,
            failure=observation.check.failure,
            canary_in_search=observation.check.canary_in_search,
        )
    if (
        state_unreadable
        or raw_age < 0
        or age > _SERVING_EVIDENCE_MAX_AGE.total_seconds()
    ):
        return ServingHealth(
            status=ServingStatus.UNKNOWN,
            checked_at=observation.checked_at,
            check_age_seconds=age,
            failure=observation.check.failure,
            canary_in_search=observation.check.canary_in_search,
        )
    return ServingHealth(
        status=(
            ServingStatus.AVAILABLE if observation.check.ok else ServingStatus.FAILED
        ),
        checked_at=observation.checked_at,
        check_age_seconds=age,
        failure=observation.check.failure,
        canary_in_search=observation.check.canary_in_search,
    )


def _defense_is_active(record: DefenseRecord | None, *, now: datetime) -> bool:
    if record is None:
        return False
    return record.active_until > now or (
        record.probe_lease_until is not None and record.probe_lease_until > now
    )


__all__ = [
    "FleetHealth",
    "HealthStateError",
    "ProviderHealth",
    "ServingHealth",
    "ServingStatus",
    "collect_fleet_health",
]
