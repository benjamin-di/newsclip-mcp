"""Shared public serialization and error classification for adapters.

Both the CLI and the local MCP adapter present the same synchronous core, so
they must agree on exactly two things: how a public model is serialized (never
leaking raw HTML, cookies, secret refs, or profile paths) and how a raised error
maps to a stable category/exit code. Keeping that mapping here is what lets the
adapters stay thin — they do not each re-derive the contract.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from .errors import (
    NOT_ENTITLED_REASON,
    ContentNotFullError,
    OperatorActionRequiredError,
    PersistenceError,
    ProviderDefenseError,
    ProviderTransportError,
    SessionRequiredError,
    TransportFailure,
    UnsearchableQueryError,
    UsageError,
)
from .models import INCIDENT_ID_PATTERN as _INCIDENT_ID_PATTERN
from .models import FrozenModel


class PublicErrorMessage(StrEnum):
    INVALID_REQUEST = "invalid request"
    OPERATOR_ACTION_REQUIRED = "operator action required"
    SESSION_REQUIRED = "session required"
    CONTENT_NOT_FULL = "content did not verify as full"
    TRANSPORT_FAILED = "provider transport failed"
    PERSISTENCE_FAILED = "persistence operation failed"
    PROVIDER_DEFENSE_ACTIVE = "provider defense active"


class PublicErrorAction(StrEnum):
    """The one machine-usable next step a caller should take.

    Categories alone made agents invent policy ("operator action" for a
    transient edge challenge sent people hunting runbooks). The action field
    is the closed answer to "so what do I do": wait and retry, wait for the
    keeper's renewal, involve the account owner, or nothing (the request
    itself was at fault).
    """

    RETRY_LATER = "retry_later"
    RENEWAL_PENDING = "renewal_pending"
    RECOVERY_PENDING = "recovery_pending"
    HUMAN_ACCOUNT_CHECK = "human_account_check"
    NONE = "none"
    REPAIR_LOCAL_INFRASTRUCTURE = "repair_local_infrastructure"


class PublicErrorReason(StrEnum):
    """Closed refinements a client can act on differently.

    A category alone cannot separate an unentitled teaser from an edge
    challenge, which are the same category but need opposite responses:
    renew or promote a session, versus stop and preserve the first failure.
    Only these exact reasons are published; anything else stays unnamed
    rather than risking arbitrary internal text on a public surface.
    """

    PAYWALL_TEASER = "paywall_teaser"
    #: The session verified paid access, yet this article stayed a teaser: the
    #: account is not entitled to it. Unlike ``paywall_teaser``, renewing the
    #: session cannot help, and no recovery is requested.
    NOT_ENTITLED = NOT_ENTITLED_REASON
    INTERACTIVE_CHALLENGE = "interactive_challenge"
    AUTHENTICATION_REQUIRED = "authentication_required"
    CONNECTION_DISCONNECTED = "connection_disconnected"
    CONNECTION_INTERACTIVE = "connection_interactive"
    RENDER_TIMEOUT = "browser_semantic_readiness_timeout"
    UNSEARCHABLE_QUERY = "unsearchable_query"
    #: An imported session reached the provider but could not prove access.
    #: Distinct from a transport failure, which is what it used to be reported
    #: as: the request completed, so retrying the network resolves nothing.
    IMPORT_VERIFICATION_INCONCLUSIVE = "import_verification_inconclusive"
    PROFILE_INVALID = "profile_invalid"
    PROFILE_IN_USE = "profile_in_use"
    PROFILE_OWNER_UNVERIFIED = "profile_owner_unverified"
    PROFILE_EXIT_UNCONFIRMED = "profile_exit_unconfirmed"


class PublicErrorCategory(StrEnum):
    USAGE = "usage"
    OPERATOR_ACTION = "operator_action"
    SESSION_REQUIRED = "session_required"
    CONTENT_NOT_FULL = "content_not_full"
    PROVIDER_DEFENSE = "provider_defense"
    TIMEOUT = "timeout"
    DNS = "dns"
    TRANSPORT = "transport"
    PERSISTENCE = "persistence"


_PUBLIC_ERROR_SPEC: dict[
    PublicErrorCategory, tuple[Literal[2, 3, 4, 5, 6], PublicErrorMessage]
] = {
    PublicErrorCategory.USAGE: (2, PublicErrorMessage.INVALID_REQUEST),
    PublicErrorCategory.OPERATOR_ACTION: (
        3,
        PublicErrorMessage.OPERATOR_ACTION_REQUIRED,
    ),
    PublicErrorCategory.SESSION_REQUIRED: (3, PublicErrorMessage.SESSION_REQUIRED),
    PublicErrorCategory.CONTENT_NOT_FULL: (4, PublicErrorMessage.CONTENT_NOT_FULL),
    # Exit code 5 deliberately: defense refusals are transient per-provider
    # failures, so scripts that already treat 5 as "retry later" keep doing
    # the right thing without knowing the new category.
    PublicErrorCategory.PROVIDER_DEFENSE: (
        5,
        PublicErrorMessage.PROVIDER_DEFENSE_ACTIVE,
    ),
    PublicErrorCategory.TIMEOUT: (5, PublicErrorMessage.TRANSPORT_FAILED),
    PublicErrorCategory.DNS: (5, PublicErrorMessage.TRANSPORT_FAILED),
    PublicErrorCategory.TRANSPORT: (5, PublicErrorMessage.TRANSPORT_FAILED),
    PublicErrorCategory.PERSISTENCE: (6, PublicErrorMessage.PERSISTENCE_FAILED),
}

#: The closed category → next-step mapping. Two categories refine per error:
#: a content_not_full caused by an interactive challenge is a defense event
#: (retry), not a session event, and transport retryability follows the
#: error's own flag.
_CATEGORY_ACTION: dict[PublicErrorCategory, tuple[bool, PublicErrorAction]] = {
    PublicErrorCategory.USAGE: (False, PublicErrorAction.NONE),
    PublicErrorCategory.OPERATOR_ACTION: (
        False,
        PublicErrorAction.HUMAN_ACCOUNT_CHECK,
    ),
    PublicErrorCategory.SESSION_REQUIRED: (
        False,
        PublicErrorAction.NONE,
    ),
    PublicErrorCategory.CONTENT_NOT_FULL: (
        False,
        PublicErrorAction.NONE,
    ),
    PublicErrorCategory.PROVIDER_DEFENSE: (True, PublicErrorAction.RETRY_LATER),
    PublicErrorCategory.TIMEOUT: (True, PublicErrorAction.RETRY_LATER),
    PublicErrorCategory.DNS: (True, PublicErrorAction.RETRY_LATER),
    PublicErrorCategory.TRANSPORT: (True, PublicErrorAction.RETRY_LATER),
    PublicErrorCategory.PERSISTENCE: (False, PublicErrorAction.NONE),
}


class PublicErrorEnvelope(FrozenModel):
    ok: Literal[False] = False
    category: PublicErrorCategory
    exit_code: Literal[2, 3, 4, 5, 6]
    message: PublicErrorMessage
    reason: PublicErrorReason | None = None
    incident_id: str | None = Field(default=None, pattern=_INCIDENT_ID_PATTERN)
    recovery_id: str | None = Field(default=None, pattern=r"^recovery-[a-f0-9]{32}$")
    recovery_omission: Literal["handoff_failed"] | None = None
    # Self-description (additive; ARCHITECTURE, "MCP boundary"): what a caller should
    # do next, without reading runbooks. ``retry_after_seconds`` is published
    # only when a concrete wait is known (an active defense cooldown).
    retryable: bool = False
    retry_after_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    action: PublicErrorAction = PublicErrorAction.NONE
    # The MCP invocation that failed; it names the private timing records and
    # the server log line an operator correlates (additive, MCP only).
    diagnostic_id: str | None = Field(default=None, pattern=r"^mcp-[a-f0-9]{32}$")

    @model_validator(mode="after")
    def validate_correlated_fields(self) -> PublicErrorEnvelope:
        if (self.exit_code, self.message) != _PUBLIC_ERROR_SPEC[self.category]:
            raise ValueError("public error fields do not match category")
        if self.retry_after_seconds is not None and not self.retryable:
            raise ValueError("a retry hint requires a retryable error")
        return self

    def public_dict(self) -> dict[str, object]:
        # Unnamed refinements are omitted, so the envelope a client already
        # handles keeps exactly its established shape.
        return self.model_dump(mode="json", exclude_none=True)


def public_value(value: object) -> object:
    """Serialize a core return value through explicit public allowlists only.

    Lists recurse; models expose their curated ``public_dict``; a model without
    one is a bug (fail closed rather than risk dumping internal fields).
    """

    if isinstance(value, list):
        return [public_value(item) for item in value]
    public_dict = getattr(value, "public_dict", None)
    if callable(public_dict):
        return public_dict()
    if isinstance(value, BaseModel):
        raise PersistenceError("model has no explicit public serializer")
    raise PersistenceError("value has no explicit public serializer")


def _public_transport_category(category: TransportFailure) -> PublicErrorCategory:
    """Narrow an internal transport category to the published contract.

    The public categories are a deliberately smaller, stable set than the
    internal ones: callers branch on them and their exit codes. Resolving by
    value alone silently required the two enums to stay identical, so adding
    an internal category raised ``ValueError`` from the envelope that exists
    to keep failures legible. Anything without a published counterpart is
    reported as TRANSPORT, which is what such a failure already meant.
    """

    try:
        return PublicErrorCategory(category.value)
    except ValueError:
        return PublicErrorCategory.TRANSPORT


def classify_error(
    error: BaseException,
) -> tuple[PublicErrorCategory, Literal[2, 3, 4, 5, 6]] | None:
    """Map a raised error to ``(category, exit_code)`` or ``None`` if unmapped.

    ``None`` means "not a known product error" — adapters let it propagate
    rather than inventing a category for it.
    """

    if isinstance(error, (UsageError, ValueError)):
        return (PublicErrorCategory.USAGE, 2)
    # Checked before the transport branch it inherits from: the request, not the
    # provider route, is what failed, so a caller must not be told to retry or
    # to go repair a provider.
    if isinstance(error, UnsearchableQueryError):
        return (PublicErrorCategory.USAGE, 2)
    if isinstance(error, OperatorActionRequiredError):
        return (PublicErrorCategory.OPERATOR_ACTION, 3)
    if isinstance(error, SessionRequiredError):
        return (PublicErrorCategory.SESSION_REQUIRED, 3)
    if isinstance(error, ContentNotFullError):
        return (PublicErrorCategory.CONTENT_NOT_FULL, 4)
    # Before its transport parent: a defense refusal is transient like
    # transport, but carries its own category so callers stop being told
    # "operator action" for an edge challenge no operator can influence.
    if isinstance(error, ProviderDefenseError):
        return (PublicErrorCategory.PROVIDER_DEFENSE, 5)
    if isinstance(error, ProviderTransportError):
        return (_public_transport_category(error.category), 5)
    if isinstance(error, PersistenceError):
        return (PublicErrorCategory.PERSISTENCE, 6)
    return None


def public_error(error: BaseException) -> PublicErrorEnvelope | None:
    """Map a known failure to a closed envelope.

    Exception text is never published. A reason is named only when the text
    matches a published constant exactly, so the surface stays closed.
    """

    mapped = classify_error(error)
    if mapped is None:
        return None
    category, exit_code = mapped
    expected_code, message = _PUBLIC_ERROR_SPEC[category]
    if exit_code != expected_code:  # pragma: no cover - guards future mappings
        raise AssertionError("public error classifier returned inconsistent code")
    reason = _public_reason(error)
    retryable, action = _CATEGORY_ACTION[category]
    if category is PublicErrorCategory.PERSISTENCE and reason in {
        PublicErrorReason.PROFILE_INVALID,
        PublicErrorReason.PROFILE_IN_USE,
        PublicErrorReason.PROFILE_OWNER_UNVERIFIED,
        PublicErrorReason.PROFILE_EXIT_UNCONFIRMED,
    }:
        action = PublicErrorAction.REPAIR_LOCAL_INFRASTRUCTURE
    candidate = getattr(error, "recovery_id", None)
    recovery_id = (
        candidate
        if isinstance(candidate, str)
        and re.fullmatch(r"recovery-[a-f0-9]{32}", candidate)
        else None
    )
    if recovery_id is not None and category in {
        PublicErrorCategory.SESSION_REQUIRED,
        PublicErrorCategory.CONTENT_NOT_FULL,
    }:
        action = PublicErrorAction.RENEWAL_PENDING
    if recovery_id is not None and category in {
        PublicErrorCategory.TIMEOUT,
        PublicErrorCategory.DNS,
        PublicErrorCategory.TRANSPORT,
    }:
        action = PublicErrorAction.RECOVERY_PENDING
    # A content failure caused by an interactive challenge is a defense event
    # wearing the content category: renewal cannot help, waiting can.
    if (
        category is PublicErrorCategory.CONTENT_NOT_FULL
        and reason is PublicErrorReason.INTERACTIVE_CHALLENGE
    ):
        retryable, action = (True, PublicErrorAction.RETRY_LATER)
    # Transport errors carry their own retryability (an unsearchable query
    # is permanently unretryable and already classified as usage above).
    if isinstance(error, ProviderTransportError) and not error.retryable:
        retryable, action = (False, PublicErrorAction.NONE)
    retry_after = (
        error.retry_after_seconds
        if retryable and isinstance(error, ProviderDefenseError)
        else None
    )
    return PublicErrorEnvelope(
        category=category,
        exit_code=exit_code,
        message=message,
        reason=reason,
        incident_id=_public_incident_id(error),
        recovery_id=recovery_id,
        recovery_omission="handoff_failed"
        if getattr(error, "recovery_omission", None) == "handoff_failed"
        else None,
        retryable=retryable,
        retry_after_seconds=retry_after,
        action=action,
    )


def _public_reason(error: BaseException) -> PublicErrorReason | None:
    """Publish only an exactly recognized reason; never arbitrary text."""

    try:
        return PublicErrorReason(str(error))
    except ValueError:
        return None


def _public_incident_id(error: BaseException) -> str | None:
    """Accept only a well-formed reference; this path must never itself raise."""

    candidate = getattr(error, "incident_id", None)
    if isinstance(candidate, str) and re.fullmatch(_INCIDENT_ID_PATTERN, candidate):
        return candidate
    return None
