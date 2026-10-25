"""Bounded native passage and one checkbox action on a Cloudflare interstitial."""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from contextlib import suppress
from functools import partial
from typing import Any
from urllib.parse import urlsplit

from patchright.sync_api import Error as BrowserError

from .challenge_detection import detect_challenge
from .challenges import (
    ChallengeAcceptance,
    ChallengeAcceptanceProbe,
    ChallengeBrowser,
    ChallengeMechanicError,
    ChallengeState,
    ChallengeVendor,
    run_challenge_action,
)


class CloudflareInterstitialMechanic:
    """Wait for native clearance, clicking at most one verified checkbox."""

    vendor = ChallengeVendor.CLOUDFLARE_INTERSTITIAL

    def __init__(
        self,
        *,
        wall_budget_seconds: float = 15,
        poll_seconds: float = 0.25,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if (
            not math.isfinite(wall_budget_seconds)
            or wall_budget_seconds <= 0
            or wall_budget_seconds > 30
        ):
            raise ValueError(
                "Cloudflare interstitial wall budget must be within (0, 30] seconds"
            )
        if (
            not math.isfinite(poll_seconds)
            or poll_seconds <= 0
            or poll_seconds > min(1, wall_budget_seconds)
        ):
            raise ValueError(
                "Cloudflare interstitial poll interval must be positive, "
                "at most one second, and no longer than the wall budget"
            )
        self._wall_budget = wall_budget_seconds
        self._poll_seconds = poll_seconds
        self._clock = clock or time.monotonic

    def has_actionable_surface(self, browser: ChallengeBrowser) -> bool:
        """Whether this is an interstitial we can await or act on."""

        detection = detect_challenge(browser)
        return (
            detection.vendor is self.vendor
            and detection.state is ChallengeState.INTERACTIVE
        )

    def solve(
        self,
        browser: ChallengeBrowser,
        acceptance: ChallengeAcceptanceProbe,
    ) -> ChallengeAcceptance:
        """A click is an attempt, never evidence that Cloudflare accepted it."""

        deadline = self._clock() + self._wall_budget
        dispatched = False
        observed = acceptance.observe()
        while not observed.accepted:
            remaining = deadline - self._clock()
            if remaining <= 0:
                break
            target = None if dispatched else self._checkbox(browser)
            if target is not None:
                frame, element = target
                try:
                    # Bind the action to this element, never a replacement locator.
                    observed = acceptance.observe()
                    if observed.accepted:
                        break
                    if (
                        self._clock() < deadline
                        and self.has_actionable_surface(browser)
                        and not frame.is_detached()
                        and self._cloudflare_frame(frame)
                        and element.is_visible()
                        and element.is_enabled()
                        and not element.is_checked()
                    ):
                        capture = getattr(
                            browser, "capture_diagnostic_screenshot", None
                        )
                        if callable(capture):
                            capture("cloudflare-checkbox", timeout_ms=500)
                        observed = acceptance.observe()
                        if observed.accepted:
                            break
                        remaining = deadline - self._clock()
                        if remaining <= 0:
                            break
                        dispatched = True
                        run_challenge_action(
                            browser,
                            partial(element.click, timeout=min(1000, remaining * 1000)),
                        )
                except BrowserError as error:
                    if dispatched:
                        # A timeout after dispatch is ambiguous; do not try again.
                        raise ChallengeMechanicError(
                            "Cloudflare checkbox action did not complete"
                        ) from error
                finally:
                    with suppress(BrowserError):
                        element.dispose()
            remaining = deadline - self._clock()
            if remaining <= 0:
                break
            browser.page.wait_for_timeout(min(self._poll_seconds, remaining) * 1000)
            observed = acceptance.observe()
        return observed

    @staticmethod
    def _cloudflare_frame(frame: Any) -> bool:
        url = urlsplit(frame.url)
        return (
            url.scheme == "https"
            and url.hostname == "challenges.cloudflare.com"
            and url.path.startswith("/cdn-cgi/challenge-platform/")
        )

    def _checkbox(self, browser: ChallengeBrowser) -> tuple[Any, Any] | None:
        """Use native shadow-piercing selectors, never guessed page coordinates."""

        frames = getattr(browser.page, "frames", ())
        candidates: list[tuple[Any, Any]] = []
        try:
            for frame in frames:
                if frame.is_detached() or not self._cloudflare_frame(frame):
                    continue
                for element in frame.locator(
                    'input[type="checkbox"], [role="checkbox"]'
                ).element_handles():
                    if (
                        element.is_visible()
                        and element.is_enabled()
                        and not element.is_checked()
                    ):
                        candidates.append((frame, element))
                    else:
                        element.dispose()
            if len(candidates) == 1:
                return candidates.pop()
            return None
        except BrowserError:
            # Native passage can replace a frame while it is being inspected.
            return None
        finally:
            for _, element in candidates:
                with suppress(BrowserError):
                    element.dispose()


__all__ = ["CloudflareInterstitialMechanic"]
