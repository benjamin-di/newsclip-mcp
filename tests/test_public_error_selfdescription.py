"""Self-describing error envelopes (ARCHITECTURE, "MCP boundary").

Every non-ok result must tell the caller what to do next — retry, wait for
renewal, involve the account owner, or nothing — without runbooks. The
challenge-with-no-fallback path must never again read "operator action".
"""

from __future__ import annotations

import pytest

from newsclip.errors import (
    ContentNotFullError,
    OperatorActionRequiredError,
    ProviderDefenseError,
    ProviderTransportError,
    SessionRequiredError,
    UnsearchableQueryError,
)
from newsclip.results import (
    PublicErrorAction,
    PublicErrorCategory,
    PublicErrorEnvelope,
    PublicErrorMessage,
    public_error,
)


def _envelope(error: BaseException) -> PublicErrorEnvelope:
    envelope = public_error(error)
    assert envelope is not None
    return envelope


def test_defense_error_is_its_own_retryable_category() -> None:
    envelope = _envelope(
        ProviderDefenseError(
            "reuters returned an unsupported interactive challenge",
            provider="reuters",
        )
    )
    assert envelope.category is PublicErrorCategory.PROVIDER_DEFENSE
    assert envelope.exit_code == 5
    assert envelope.message is PublicErrorMessage.PROVIDER_DEFENSE_ACTIVE
    assert envelope.retryable is True
    assert envelope.action is PublicErrorAction.RETRY_LATER


def test_defense_error_publishes_known_cooldown() -> None:
    envelope = _envelope(
        ProviderDefenseError("held", provider="reuters", retry_after_seconds=1200)
    )
    assert envelope.retry_after_seconds == 1200
    assert envelope.public_dict()["retry_after_seconds"] == 1200.0


def test_defense_error_without_cooldown_omits_hint() -> None:
    envelope = _envelope(ProviderDefenseError("held", provider="reuters"))
    assert envelope.retry_after_seconds is None
    assert "retry_after_seconds" not in envelope.public_dict()


def test_operator_action_pages_the_account_owner() -> None:
    envelope = _envelope(OperatorActionRequiredError("terminal", provider="ft"))
    assert envelope.category is PublicErrorCategory.OPERATOR_ACTION
    assert envelope.retryable is False
    assert envelope.action is PublicErrorAction.HUMAN_ACCOUNT_CHECK


def test_session_required_does_not_invent_pending_renewal() -> None:
    envelope = _envelope(SessionRequiredError("session required"))
    assert envelope.action is PublicErrorAction.NONE
    assert envelope.retryable is False


def test_content_not_full_does_not_invent_pending_renewal() -> None:
    envelope = _envelope(ContentNotFullError("paywall_teaser"))
    assert envelope.category is PublicErrorCategory.CONTENT_NOT_FULL
    assert envelope.action is PublicErrorAction.NONE
    assert envelope.retryable is False


def test_content_challenge_is_a_defense_event_in_disguise() -> None:
    """interactive_challenge wearing content_not_full: renewal cannot help."""
    envelope = _envelope(ContentNotFullError("interactive_challenge"))
    assert envelope.category is PublicErrorCategory.CONTENT_NOT_FULL
    assert envelope.retryable is True
    assert envelope.action is PublicErrorAction.RETRY_LATER


def test_transport_retryability_follows_the_error_flag() -> None:
    retryable = _envelope(ProviderTransportError("t"))
    assert retryable.retryable is True
    assert retryable.action is PublicErrorAction.RETRY_LATER


def test_unsearchable_query_stays_unretryable_usage() -> None:
    envelope = _envelope(UnsearchableQueryError("nothing to rank"))
    assert envelope.category is PublicErrorCategory.USAGE
    assert envelope.retryable is False
    assert envelope.action is PublicErrorAction.NONE


def test_retry_hint_requires_retryable() -> None:
    with pytest.raises(ValueError, match="retry hint"):
        PublicErrorEnvelope(
            category=PublicErrorCategory.PERSISTENCE,
            exit_code=6,
            message=PublicErrorMessage.PERSISTENCE_FAILED,
            retryable=False,
            retry_after_seconds=10,
        )


def test_defense_error_never_publishes_exception_text() -> None:
    envelope = _envelope(
        ProviderDefenseError("PRIVATE_SENTINEL_TEXT", provider="reuters")
    )
    assert "PRIVATE_SENTINEL_TEXT" not in str(envelope.public_dict())


def test_durable_handoff_reference_is_required_for_pending_renewal():
    error = SessionRequiredError("session required")
    error.recovery_id = "recovery-" + "a" * 32
    assert _envelope(error).action is PublicErrorAction.RENEWAL_PENDING
    error.recovery_id = "PRIVATE_INVALID_REFERENCE"
    envelope = _envelope(error)
    assert envelope.action is PublicErrorAction.NONE
    assert "PRIVATE" not in str(envelope.public_dict())
