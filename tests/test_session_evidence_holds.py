"""Session-evidence holds clear on the verification event (P1b).

A hold whose named remedy is session renewal or promotion must clear the
moment a session positively verifies live — keeping it manual blocked the
keeper hourly for days (the 2026-07-25 FT trap). Defense, operator,
local-state, and incident-review holds never clear this way.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from newsclip.models import (
    AccessState,
    ProviderCapabilities,
    SessionDisposition,
)
from newsclip.provenance import BuildIdentity, BuildIdentitySource
from newsclip.provider_check import ProviderCheckFailure, ProviderCheckResult
from newsclip.provider_guard import (
    GuardAction,
    ProviderGuard,
    ProviderGuardStore,
)

NOW = datetime(2026, 7, 28, tzinfo=UTC)


class _Provider:
    key = "ft"
    capabilities = ProviderCapabilities(
        requires_session_for_retrieve=True,
        session_kind="cookie",
    )


def _check(
    *,
    failure: ProviderCheckFailure | None,
    disposition: SessionDisposition | None = None,
    incident_id: str | None = None,
) -> ProviderCheckResult:
    assessed = failure in {
        ProviderCheckFailure.CONTENT_NOT_FULL,
        ProviderCheckFailure.PROVIDER_DEFENSE,
        ProviderCheckFailure.SESSION_DEAD,
    }
    return ProviderCheckResult(
        provider="ft",
        ok=False,
        failure=failure,
        search_result_count=1,
        http_status=200 if assessed else None,
        access_state=AccessState.TEASER if assessed else None,
        reason="paywall_teaser" if assessed else None,
        identity_match=True if assessed else None,
        word_count=8 if assessed else None,
        session_disposition=disposition,
        incident_id=incident_id,
    )


def _guard(tmp_path: Path) -> ProviderGuard:
    from newsclip.providers.registry import ProviderRegistry

    store = ProviderGuardStore(
        tmp_path / "provider-guard",
        build_identity=BuildIdentity(
            revision="a" * 40,
            dirty=False,
            source_fingerprint="a" * 64,
            source=BuildIdentitySource.ENVIRONMENT,
        ),
        diagnostic_id="cli-evidence-fixture",
        utc_now=lambda: NOW,
    )
    return ProviderGuard(registry=ProviderRegistry((_Provider(),)), store=store)


def _hold_with(
    guard: ProviderGuard,
    *,
    failure: ProviderCheckFailure,
    disposition: SessionDisposition | None = None,
    incident_id: str | None = None,
) -> GuardAction:
    result = guard.run(
        "ft",
        lambda: _check(
            failure=failure, disposition=disposition, incident_id=incident_id
        ),
    )
    assert result.hold_id is not None
    return result.action


def test_wait_for_session_evidence_clears_on_verification(tmp_path: Path) -> None:
    guard = _guard(tmp_path)
    action = _hold_with(
        guard,
        failure=ProviderCheckFailure.CONTENT_NOT_FULL,
        disposition=SessionDisposition.INCONCLUSIVE,
    )
    assert action is GuardAction.WAIT_FOR_SESSION_EVIDENCE
    cleared = guard.clear_session_evidence(
        "ft", hold_id=guard.session_evidence_target("ft")
    )
    assert cleared is not None and cleared.action is action
    assert guard.peek("ft") is None  # the keeper proceeds next cycle


def test_session_promotion_hold_clears_on_verification(tmp_path: Path) -> None:
    guard = _guard(tmp_path)
    action = _hold_with(guard, failure=ProviderCheckFailure.SESSION_DEAD)
    assert action is GuardAction.SESSION_PROMOTION_REQUIRED
    assert (
        guard.clear_session_evidence("ft", hold_id=guard.session_evidence_target("ft"))
        is not None
    )
    assert guard.peek("ft") is None


@pytest.mark.parametrize(
    ("failure", "expected_action"),
    [
        (ProviderCheckFailure.PROVIDER_DEFENSE, GuardAction.PROVIDER_HOLD),
        (ProviderCheckFailure.OPERATOR_ACTION, GuardAction.OPERATOR_ACTION),
        (ProviderCheckFailure.LOCAL_STATE, GuardAction.LOCAL_REPAIR_REQUIRED),
    ],
)
def test_non_session_holds_never_clear_on_verification(
    tmp_path: Path,
    failure: ProviderCheckFailure,
    expected_action: GuardAction,
) -> None:
    guard = _guard(tmp_path)
    action = _hold_with(guard, failure=failure)
    assert action is expected_action
    assert guard.clear_session_evidence("ft", hold_id=guard.peek("ft").hold_id) is None
    held = guard.peek("ft")
    assert held is not None and held.action is expected_action


def test_clear_without_hold_is_a_noop(tmp_path: Path) -> None:
    guard = _guard(tmp_path)
    assert guard.clear_session_evidence("ft", hold_id=None) is None


def test_service_fires_evidence_callback_only_on_verified_import() -> None:
    """The service-side trigger: cookie promotion fires iff status verified."""

    from newsclip.models import SessionHealth, SessionStatus
    from newsclip.service import NewsclipService

    fired: list[str] = []

    class _Manager:
        def __init__(self, status: SessionStatus) -> None:
            self._status = status

        def import_cookies(self, provider: str, payload: object) -> None:
            del provider, payload

        def status(self, provider: str) -> SessionHealth:
            return SessionHealth(provider=provider, status=self._status)

    class _Recipe:
        provider = "ft"

    class _SessionProvider(_Provider):
        login_recipe = _Recipe()

    def _service(status: SessionStatus) -> NewsclipService:
        from newsclip.providers.registry import ProviderRegistry

        service = NewsclipService(
            ProviderRegistry((_SessionProvider(),)),
            http=None,  # type: ignore[arg-type] - never touched by this path
            extractor=None,  # type: ignore[arg-type]
            session_evidence_target=lambda provider: "guard-" + "a" * 32,
            on_session_verified=lambda provider, hold_id: fired.append(provider),
        )
        service._session_manager = lambda: _Manager(status)  # type: ignore[method-assign]
        return service

    verified = _service(SessionStatus.VERIFIED)
    verified.login("ft", cookie_payload={"cookies": []})
    assert fired == ["ft"]

    fired.clear()
    unverified = _service(SessionStatus.REQUIRED)
    unverified.login("ft", cookie_payload={"cookies": []})
    assert fired == []


def test_keeper_renews_under_a_session_evidence_hold(tmp_path: Path) -> None:
    """The FT trap: a hold whose remedy IS renewal must not block the renewer.

    Blocking it closed the loop — nothing verified, so the hold that clears on
    verification never cleared, and FT reported `held` hourly for days.
    """

    from newsclip.models import SessionHealth, SessionStatus
    from newsclip.provider_guard import GuardAction
    from newsclip.session_keeper import (
        CredentialBudget,
        KeeperAction,
        KeeperPolicy,
        SessionKeeper,
    )

    class _Hold:
        action = GuardAction.WAIT_FOR_SESSION_EVIDENCE

    class _HeldGuard:
        def current_hold_health(self, provider: str):
            return None

        def peek(self, provider: str):
            return _Hold()

    class _Sessions:
        def __init__(self) -> None:
            self.logins = 0

        def defense_pending(self, provider_key: str) -> bool:
            return False

        def requires_session_for_provider(self, provider_key: str) -> bool:
            del provider_key
            return True

        def provider_check(self, provider_key: str):  # noqa: ANN202
            raise AssertionError("a session provider must not be watched")

        def session_status(self, provider_key: str) -> SessionHealth:
            return SessionHealth(provider=provider_key, status=SessionStatus.REQUIRED)

        def login(self, provider_key: str, **kwargs: object) -> SessionHealth:
            self.logins += 1
            return SessionHealth(provider=provider_key, status=SessionStatus.VERIFIED)

    sessions = _Sessions()
    keeper = SessionKeeper(
        guard=_HeldGuard(),
        sessions=sessions,
        budget=CredentialBudget(tmp_path / "budget", utc_now=lambda: NOW),
        readiness_probe=lambda provider: None,
        policy=KeeperPolicy(),
        utc_now=lambda: NOW,
    )
    result = keeper.keep("ft", allow_credential_mint=False)
    assert result.action is not KeeperAction.HELD
    assert sessions.logins == 1  # it actually attempted the remedy


def test_keeper_still_blocks_on_every_other_hold_class(tmp_path: Path) -> None:
    from newsclip.provider_guard import GuardAction
    from newsclip.session_keeper import (
        CredentialBudget,
        KeeperAction,
        KeeperPolicy,
        SessionKeeper,
    )

    for blocking in (
        GuardAction.PROVIDER_HOLD,
        GuardAction.OPERATOR_ACTION,
        GuardAction.LOCAL_REPAIR_REQUIRED,
    ):

        class _Hold:
            action = blocking

        class _Guard:
            def current_hold_health(self, provider: str):
                return None

            def peek(self, provider: str):
                return _Hold()

        class _Sessions:
            def session_status(self, provider_key: str):
                raise AssertionError("a blocking hold must stop the keeper dead")

            def login(self, provider_key: str, **kwargs: object):
                raise AssertionError("a blocking hold must never reach login")

        keeper = SessionKeeper(
            guard=_Guard(),
            sessions=_Sessions(),
            budget=CredentialBudget(
                tmp_path / f"budget-{blocking.value}", utc_now=lambda: NOW
            ),
            readiness_probe=lambda provider: None,
            policy=KeeperPolicy(),
            utc_now=lambda: NOW,
        )
        assert keeper.keep("ft", allow_credential_mint=True).action is (
            KeeperAction.HELD
        ), blocking


def test_keeper_routes_incident_review_hold_to_the_bounded_canary(
    tmp_path: Path,
) -> None:
    """R9: renewal stays dead under an incident hold; only the canary runs."""

    from newsclip.provider_guard import GuardAction, GuardResult
    from newsclip.session_keeper import (
        CredentialBudget,
        KeeperAction,
        KeeperPolicy,
        SessionKeeper,
    )

    class _Hold:
        action = GuardAction.INCIDENT_REVIEW_REQUIRED

    outcomes: list[GuardResult] = []

    class _Guard:
        def current_hold_health(self, provider: str):
            return None

        def __init__(self, cleared: bool) -> None:
            self.cleared = cleared
            self.canaries = 0

        def peek(self, provider: str):
            return _Hold()

        def run_incident_review_canary(self, provider: str, check_provider):
            self.canaries += 1
            result = GuardResult(
                provider=provider,
                action=(
                    GuardAction.HEALTHY
                    if self.cleared
                    else GuardAction.CHECK_IN_PROGRESS
                ),
            )
            outcomes.append(result)
            return result

    class _Sessions:
        def session_status(self, provider_key: str):
            raise AssertionError("an incident hold must never reach renewal")

        def login(self, provider_key: str, **kwargs: object):
            raise AssertionError("an incident hold must never reach login")

    for cleared, expected_action in (
        (True, KeeperAction.CHECKED),
        (False, KeeperAction.HELD),
    ):
        guard = _Guard(cleared)
        keeper = SessionKeeper(
            guard=guard,
            sessions=_Sessions(),
            budget=CredentialBudget(
                tmp_path / f"budget-{cleared}", utc_now=lambda: NOW
            ),
            readiness_probe=lambda provider: None,
            policy=KeeperPolicy(),
            utc_now=lambda: NOW,
        )
        result = keeper.keep("ft", allow_credential_mint=True)
        assert guard.canaries == 1
        assert result.action is expected_action
        if cleared:
            assert result.reason_code == "incident_hold_cleared"
