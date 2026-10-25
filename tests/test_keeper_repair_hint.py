"""Every outcome needing a person carries the call that fixes it (R4).

An alert naming only the failure sends the reader hunting runbooks — knowing
Bloomberg said "transport failure" helped nobody for eight days. The hint is
templated on the provider key alone, so no provider text or secret can ride
out on an alert.
"""

from __future__ import annotations

import pytest

from newsclip.session_keeper import KeeperAction, KeeperResult


def _result(action: KeeperAction, reason: str | None = None) -> KeeperResult:
    return KeeperResult(provider="bloomberg", action=action, reason_code=reason)


def test_healthy_outcomes_carry_no_hint() -> None:
    for action in (KeeperAction.FRESH, KeeperAction.RENEWED, KeeperAction.COOLDOWN):
        result = _result(action)
        assert result.repair_hint is None
        assert "repair_hint" not in result.public_dict()
        assert "next_action" not in result.public_dict()
        assert result.public_dict()["overall_state"] in {"healthy", "waiting"}


def test_promotion_escalation_leads_with_verification() -> None:
    """Verify-then-heal comes before promote: a latched escalation can be a
    probe that could not read its page (2026-08-06 Bloomberg), and promoting
    a working session is the wrong repair."""

    result = _result(
        KeeperAction.OPERATOR_ACTION_REQUIRED, "session_promotion_required"
    )
    hint = result.repair_hint
    assert hint is not None
    assert "provider_check" in hint
    assert "session_promote" not in hint
    assert "does not establish an account problem" in hint
    assert "bloomberg" in hint
    assert result.public_dict()["repair_hint"] == hint
    assert result.public_dict()["next_action"] == "provider_check_then_heal"
    assert result.public_dict()["overall_state"] == "needs_attention"


def test_inconclusive_probe_leads_with_verification() -> None:
    hint = _result(KeeperAction.RENEWAL_FAILED, "paid_probe_inconclusive").repair_hint
    assert hint is not None
    assert "provider_check" in hint
    assert "session_promote" not in hint
    assert "does not establish an account problem" in hint


def test_mint_not_permitted_names_the_bounded_keeper_call() -> None:
    hint = _result(
        KeeperAction.OPERATOR_ACTION_REQUIRED, "credential_mint_not_permitted"
    ).repair_hint
    assert hint is not None
    assert "auth keep bloomberg --allow-credential-mint" in hint
    assert "newsclip health" not in hint


def test_unusable_host_points_at_health_not_a_retry() -> None:
    hint = _result(
        KeeperAction.OPERATOR_ACTION_REQUIRED, "credential_host_not_ready"
    ).repair_hint
    assert hint is not None
    assert "newsclip health" in hint
    assert "retry" not in hint.lower()


def test_held_points_at_acknowledge() -> None:
    hint = _result(KeeperAction.HELD).repair_hint
    assert hint is not None and "acknowledge_hold" in hint


def test_terminal_account_verdict_never_suggests_a_retry() -> None:
    """The one class where a human knows facts the system cannot."""

    hint = _result(
        KeeperAction.OPERATOR_ACTION_REQUIRED, "credential_credential_rejected"
    ).repair_hint
    assert hint is not None
    assert "do not retry" in hint.lower()
    assert "heal(" not in hint


def test_generic_failure_falls_back_to_heal() -> None:
    hint = _result(KeeperAction.RENEWAL_FAILED, "unclassified_error").repair_hint
    assert hint is not None and "heal(" in hint


@pytest.mark.parametrize(
    "reason",
    [None, "session_promotion_required", "paid_probe_inconclusive", "account_alert"],
)
def test_hint_never_contains_anything_but_the_provider_key(reason: str | None) -> None:
    """No provider text, error detail, or secret material may reach an alert."""

    result = KeeperResult(
        provider="ft", action=KeeperAction.RENEWAL_FAILED, reason_code=reason
    )
    hint = result.repair_hint or ""
    assert "SECRET" not in hint and "http" not in hint
    assert "ft" in hint


def test_challenged_renewal_with_refused_reads_names_the_fingerprint_repair() -> None:
    """2026-10-19: FT's renewal probe and reads were refused while the browser
    served — the session was fine and chrome146 had aged."""

    result = KeeperResult(
        provider="ft",
        action=KeeperAction.RENEWAL_FAILED,
        reason_code="provider_defense",
        http_challenges_24h=3,
    )
    payload = result.public_dict()

    assert payload["next_action"] == "update_http_fingerprint"
    assert payload["http_challenges_24h"] == 3
    hint = payload["repair_hint"]
    assert "curl-cffi" in hint
    assert "provider_check" in hint
    assert "do not submit credentials" in hint
    assert payload["overall_state"] == "needs_attention"


@pytest.mark.parametrize("count", [None, 0])
def test_challenged_renewal_without_refused_reads_stays_a_provider_review(
    count: int | None,
) -> None:
    result = KeeperResult(
        provider="ft",
        action=KeeperAction.RENEWAL_FAILED,
        reason_code="provider_defense",
        http_challenges_24h=count,
    )
    payload = result.public_dict()

    assert payload["next_action"] == "review_provider"
    assert ("http_challenges_24h" in payload) is (count is not None)
