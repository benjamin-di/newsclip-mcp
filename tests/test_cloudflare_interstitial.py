from __future__ import annotations

import pytest

from newsclip.challenge_resolver import (
    ChallengeBlockReason,
    ChallengeResolutionStatus,
    ChallengeResolver,
)
from newsclip.challenges import (
    ChallengeAcceptance,
    ChallengeAcceptanceSource,
    ChallengeDetection,
    ChallengeMode,
    ChallengeState,
    ChallengeVendor,
)
from newsclip.cloudflare_interstitial import CloudflareInterstitialMechanic


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class Page:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self.waits: list[float] = []

    def wait_for_timeout(self, milliseconds: float) -> None:
        self.waits.append(milliseconds)
        self._clock.now += milliseconds / 1000


class Browser:
    def __init__(self, clock: Clock) -> None:
        self.page = Page(clock)
        self.actions = 0

    def dispatch_challenge_action(self, dispatch: object) -> object:
        self.actions += 1
        raise AssertionError("passive Cloudflare passage must not dispatch an action")


class Probe:
    def __init__(self, clock: Clock, *, clears_at: float | None) -> None:
        self._clock = clock
        self._clears_at = clears_at
        self.observations = 0

    def observe(self) -> ChallengeAcceptance:
        self.observations += 1
        accepted = self._clears_at is not None and self._clock.now >= self._clears_at
        return ChallengeAcceptance(
            accepted=accepted,
            source=(
                ChallengeAcceptanceSource.SURFACE_CLEAR
                if accepted
                else ChallengeAcceptanceSource.NONE
            ),
        )


def test_waits_for_browser_native_passage_without_dispatching_an_action() -> None:
    clock = Clock()
    browser = Browser(clock)
    probe = Probe(clock, clears_at=0.75)

    result = CloudflareInterstitialMechanic(clock=clock).solve(browser, probe)

    assert result.accepted is True
    assert result.source is ChallengeAcceptanceSource.SURFACE_CLEAR
    assert browser.page.waits == [250.0, 250.0, 250.0]
    assert browser.actions == 0


def test_stops_at_the_wall_budget_when_passage_does_not_clear() -> None:
    clock = Clock()
    browser = Browser(clock)
    probe = Probe(clock, clears_at=None)

    result = CloudflareInterstitialMechanic(
        wall_budget_seconds=1,
        poll_seconds=0.4,
        clock=clock,
    ).solve(browser, probe)

    assert result.accepted is False
    assert browser.page.waits == pytest.approx([400.0, 400.0, 200.0])
    assert clock.now == pytest.approx(1)
    assert browser.actions == 0


@pytest.mark.parametrize(
    ("clears_at", "expected_status", "expected_reason"),
    [
        (0.75, ChallengeResolutionStatus.CLEARED, None),
        (
            None,
            ChallengeResolutionStatus.BLOCKED,
            ChallengeBlockReason.ACCEPTANCE_UNCONFIRMED,
        ),
    ],
)
def test_resolver_requires_stable_passage_clearance(
    monkeypatch: pytest.MonkeyPatch,
    clears_at: float | None,
    expected_status: ChallengeResolutionStatus,
    expected_reason: ChallengeBlockReason | None,
) -> None:
    clock = Clock()
    browser = Browser(clock)
    monkeypatch.setattr("newsclip.challenge_resolver.time.monotonic", clock)

    def detector(raw_browser: object) -> ChallengeDetection:
        assert raw_browser is browser
        active = clears_at is None or clock.now < clears_at
        return ChallengeDetection(
            vendor=(
                ChallengeVendor.CLOUDFLARE_INTERSTITIAL
                if active
                else ChallengeVendor.NONE
            ),
            state=ChallengeState.INTERACTIVE if active else ChallengeState.NONE,
        )

    resolver = ChallengeResolver(
        {
            ChallengeVendor.CLOUDFLARE_INTERSTITIAL: (
                CloudflareInterstitialMechanic(
                    wall_budget_seconds=1.5,
                    clock=clock,
                )
            )
        },
        detector=detector,
    )

    result = resolver.resolve(browser, ChallengeMode.AUTO)

    assert result.status is expected_status
    assert result.reason is expected_reason
    assert browser.actions == 0
    if expected_status is ChallengeResolutionStatus.CLEARED:
        assert result.acceptance is not None
        assert result.acceptance.source is ChallengeAcceptanceSource.SURFACE_CLEAR


@pytest.mark.parametrize(
    ("budget", "poll"),
    [
        (0, 0.25),
        (31, 0.25),
        (float("inf"), 0.25),
        (6, 0),
        (6, 1.1),
        (0.2, 0.25),
    ],
)
def test_rejects_invalid_budgets(budget: float, poll: float) -> None:
    with pytest.raises(ValueError, match="Cloudflare interstitial"):
        CloudflareInterstitialMechanic(
            wall_budget_seconds=budget,
            poll_seconds=poll,
        )
