"""Bounded DataDome passage: native Device Check wait, optional slider drags."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from typing import Protocol
from urllib.parse import urlsplit

from .challenges import (
    ChallengeAcceptance,
    ChallengeAcceptanceProbe,
    ChallengeBrowser,
    ChallengeVendor,
    run_challenge_action,
)


class _SliderControl(Protocol):
    def bounding_box(self) -> Mapping[str, float] | None: ...


class DataDomeSliderMechanic:
    """Wait for native passage, dragging at most ``max_drags`` sliders.

    DataDome serves two blocking surfaces in the same captcha-delivery frame:
    the Device Check interstitial (``rt: 'i'``, "Verifying the device...")
    that clears itself once its script accepts the browser, and the slider
    captcha. With no slider in view this mechanic only polls, so the Device
    Check gets its native passage. ``max_drags=0`` is the passive form: a
    provider approved for passage only never touches a captcha and fails
    closed as soon as one appears (Reuters, 2026-10-12).
    """

    vendor = ChallengeVendor.DATADOME

    def __init__(
        self,
        *,
        wall_budget_seconds: float = 60,
        max_drags: int = 2,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if not math.isfinite(wall_budget_seconds) or wall_budget_seconds <= 0:
            raise ValueError("DataDome wall budget must be positive")
        if max_drags < 0 or max_drags > 3:
            raise ValueError("DataDome drag budget must be between 0 and 3")
        self._wall_budget = wall_budget_seconds
        self._max_drags = max_drags
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep

    @property
    def passive_only(self) -> bool:
        """True when this mechanic only awaits native passage."""

        return self._max_drags == 0

    def has_actionable_surface(self, browser: ChallengeBrowser) -> bool:
        """A slider this mechanic could drag, found without dragging it.

        False on a hard block, which serves a contact-support page carrying no
        slider at all — the shape that made `solve` spend its whole budget
        polling and dispatch nothing (NYT, 2026-07-28).
        """

        return _find_slider_geometry(browser.page) is not None

    def solve(
        self,
        browser: ChallengeBrowser,
        acceptance: ChallengeAcceptanceProbe,
    ) -> ChallengeAcceptance:
        page = browser.page
        started = self._clock()
        drags = 0
        while self._clock() - started < self._wall_budget:
            observed = acceptance.observe()
            if observed.accepted:
                return observed
            geometry = _find_slider_geometry(page)
            with suppress(Exception):
                recorder = getattr(browser, "record_challenge_surface", None)
                if callable(recorder):
                    recorder(actionable=geometry is not None)
            if geometry is None:
                page.wait_for_timeout(250)
                continue
            if drags >= self._max_drags:
                break
            start_box, track_box = geometry
            start_x = float(start_box["x"] + start_box["width"] / 2)
            start_y = float(start_box["y"] + start_box["height"] / 2)
            end_x = float(track_box["x"] + track_box["width"] - 8)
            end_y = float(track_box["y"] + track_box["height"] / 2)
            path = (start_x, start_y, end_x, end_y)

            def drag(
                coordinates: tuple[float, float, float, float] = path,
            ) -> None:
                drag_start_x, drag_start_y, drag_end_x, drag_end_y = coordinates
                page.mouse.move(drag_start_x, drag_start_y, steps=8)
                page.mouse.down()
                try:
                    for index in range(1, 31):
                        progress = index / 30
                        eased = 1 - (1 - progress) ** 2
                        x = drag_start_x + (drag_end_x - drag_start_x) * eased
                        y = (
                            drag_start_y
                            + (drag_end_y - drag_start_y) * eased
                            + ((index % 5) - 2) * 0.3
                        )
                        page.mouse.move(x, y, steps=1)
                        self._sleep(0.02)
                finally:
                    page.mouse.up()

            run_challenge_action(browser, drag)
            drags += 1
            page.wait_for_timeout(2500)
        return acceptance.observe()


def _find_slider_geometry(
    page,
) -> tuple[Mapping[str, float], Mapping[str, float]] | None:
    for frame in tuple(getattr(page, "frames", ())):
        if not _is_datadome_frame(frame):
            continue
        try:
            knob = _visible(frame, (".slider", ".sliderIcon"))
            track = _visible(frame, (".sliderContainer", ".sliderbg"))
            start_box = knob.bounding_box() if knob is not None else None
            track_box = track.bounding_box() if track is not None else None
            if (
                start_box is not None
                and track_box is not None
                and _valid_box(start_box)
                and _valid_box(track_box, minimum_width=9)
            ):
                return start_box, track_box
        except Exception:
            # DataDome can replace its frame during lookup or geometry reads.
            continue
    return None


def _is_datadome_frame(frame) -> bool:
    try:
        hostname = (urlsplit(str(getattr(frame, "url", ""))).hostname or "").lower()
    except Exception:
        return False
    return hostname == "captcha-delivery.com" or hostname.endswith(
        ".captcha-delivery.com"
    )


def _valid_box(
    box: Mapping[str, float] | None,
    *,
    minimum_width: float = 1,
) -> bool:
    return bool(
        box
        and box["width"] >= minimum_width
        and box["height"] > 0
        and box["x"] + box["width"] > 0
        and box["y"] + box["height"] > 0
    )


def _visible(frame, selectors: tuple[str, ...]) -> _SliderControl | None:
    for selector in selectors:
        locator = frame.locator(selector)
        for index in range(locator.count()):
            candidate = locator.nth(index)
            if candidate.is_visible():
                return candidate
    return None
