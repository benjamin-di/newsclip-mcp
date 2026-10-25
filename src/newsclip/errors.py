"""Stable error categories shared by the library and adapters."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import TYPE_CHECKING

from .provider_keys import is_provider_key

if TYPE_CHECKING:
    from .models import CaptureFailure, RawFetch

_REASON_CODE = re.compile(r"^[a-z]+(?:_[a-z]+)+$")


class NewsclipError(RuntimeError):
    """Base class for expected product failures."""

    incident_id: str | None = None
    recovery_id: str | None = None
    recovery_eligible: bool = False
    recovery_omission: str | None = None


class UsageError(NewsclipError):
    """The caller supplied an invalid provider, URL, or argument combination."""


class UnknownProviderError(UsageError):
    """No registered provider owns the requested operation."""


class SessionRequiredError(NewsclipError):
    """Retrieval requires an explicit login or cookie import."""


class OperatorActionRequiredError(NewsclipError):
    """A terminal account/login state needs explicit operator action."""

    def __init__(
        self,
        message: str,
        *,
        provider: str | None = None,
        reason_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.provider = provider if is_provider_key(provider) else None
        self.reason_code = (
            reason_code
            if isinstance(reason_code, str) and _REASON_CODE.fullmatch(reason_code)
            else None
        )


class AccountAlertError(OperatorActionRequiredError):
    """A publisher response explicitly requires account recovery."""

    def __init__(self, provider: str, fetch: RawFetch) -> None:
        super().__init__(
            f"{provider} requires account recovery before another login",
            provider=provider,
            reason_code="account_alert",
        )
        self.fetch = fetch  # Private evidence, excluded from public serializers.


class ContentNotFullError(NewsclipError):
    """The fetched page did not positively verify as a full article.

    ``incident_id`` names the retained private capsule for this failure when
    one was written, so a client failure can be correlated with the evidence
    without the adapter re-deriving it.
    """

    def __init__(self, message: str, *, incident_id: str | None = None) -> None:
        super().__init__(message)
        self.incident_id = incident_id


#: A teaser served while the same session generation independently proved paid
#: access. The article lies outside this account's entitlement, so renewing the
#: session, recovery, or a retry cannot change the outcome.
NOT_ENTITLED_REASON = "not_entitled"


class TransportFailure(StrEnum):
    TIMEOUT = "timeout"
    DNS = "dns"
    TRANSPORT = "transport"
    # A provider that *answered* is not a broken route. Collapsing its refusal
    # into TRANSPORT sends an operator to inspect tunnels and DNS while the
    # provider is simply throttling or erroring, which is what happened to the
    # 2026-08-10 FT page: eleven capsules of 429/500/502/403 all reported as
    # "transport". RATE_LIMITED is separated from PROVIDER_ERROR because the
    # two carry opposite instructions — back off, versus the provider is down.
    RATE_LIMITED = "rate_limited"
    PROVIDER_ERROR = "provider_error"


class ProviderTransportError(NewsclipError):
    """The selected provider route could not complete its network operation."""

    def __init__(
        self,
        message: str,
        *,
        category: TransportFailure = TransportFailure.TRANSPORT,
        retryable: bool = True,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.retryable = retryable


_RETRYABLE_READ_REASONS = {
    TransportFailure.TIMEOUT: "read_timeout",
    TransportFailure.DNS: "read_dns",
    TransportFailure.PROVIDER_ERROR: "read_provider_error",
}
RETRYABLE_READ_FAILURES = frozenset(_RETRYABLE_READ_REASONS.values())


def retryable_read_reason(error: BaseException) -> str | None:
    """Classify only explicit transient reads, never defense/authority errors.

    Exact type is intentional: provider contract and defense subclasses carry
    different remedies even when they inherit the transport retryable default.
    """
    if type(error) is not ProviderTransportError or not error.retryable:
        return None
    return _RETRYABLE_READ_REASONS.get(error.category)


class BrowserAuthorityChangedError(ProviderTransportError):
    """A retained profile cannot prove the supplied portable candidate."""

    def __init__(self) -> None:
        super().__init__("browser_session_authority_changed", retryable=False)


class ProviderDefenseError(ProviderTransportError):
    """A provider's edge defense refused the request with a challenge.

    Distinct from ``OperatorActionRequiredError`` deliberately: no operator
    action exists or helps here. The honest semantics are "transient, back
    off" — the caller should retry after ``retry_after_seconds`` when one is
    known (a defense cooldown is active) and otherwise later. Subclassing the
    transport error keeps every containment path (per-source search reports,
    aggregate-failure ordering, keeper classification) treating it as the
    retryable per-provider failure it is.
    """

    def __init__(
        self,
        message: str,
        *,
        provider: str | None = None,
        retry_after_seconds: float | None = None,
        reason_code: str | None = None,
        fetch: RawFetch | None = None,
    ) -> None:
        super().__init__(message, retryable=True)
        # Private response evidence, never included in the exception message
        # or public error envelope. Transport exceptions still own the verdict.
        self.fetch = fetch
        self.provider = provider if is_provider_key(provider) else None
        self.capture_failure: CaptureFailure | None = None
        self.retry_after_seconds = (
            retry_after_seconds
            if isinstance(retry_after_seconds, int | float) and retry_after_seconds >= 0
            else None
        )
        self.reason_code = (
            reason_code
            if isinstance(reason_code, str) and _REASON_CODE.fullmatch(reason_code)
            else None
        )


class ProviderContractError(ProviderTransportError):
    """A provider response no longer satisfies its configured page contract."""


class UnsearchableQueryError(ProviderContractError):
    """The caller's query carries nothing a provider could rank against.

    A sitemap provider scores informative-token overlap, so a query made only of
    English closed-class words leaves nothing to match and the provider fails
    closed rather than returning its whole window ordered by recency.

    It stays a ``ProviderContractError`` so one provider rejecting the query
    remains contained to that source in a federated search, exactly like any
    other per-source failure. It is separated only so the *caller-facing*
    classification can say the query was unusable instead of blaming the
    provider's route: the fault is in the request, and no retry or provider
    repair can change the outcome.
    """

    def __init__(self, message: str) -> None:
        # Never retryable: the same query yields the same empty token set, so a
        # retry wrapper would spend attempts that cannot succeed.
        super().__init__(message, retryable=False)


class PersistenceError(NewsclipError):
    """Session or archive state could not be read or committed safely."""
