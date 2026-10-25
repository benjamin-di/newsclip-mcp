"""Bounded PerimeterX press-and-hold mechanic."""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from random import SystemRandom

from .challenges import (
    ChallengeAcceptance,
    ChallengeAcceptanceProbe,
    ChallengeAcceptanceSource,
    ChallengeBrowser,
    ChallengeVendor,
    run_challenge_action,
)

_POST_HOLD_SETTLE_SECONDS = 12
# Prior attempt residual "Please try again" text must not abort a fresh hold
# before PerimeterX has evaluated the new press.
_REJECTION_GRACE_SECONDS = 1.5
# Residual "Human Challenge completed" copy from a prior hold must not force an
# immediate release on the next press before PerimeterX has re-evaluated it.
_COMPLETION_GRACE_SECONDS = 2.0
# Mid-hold diagnostics: capture while the pointer is still down so operators can
# see progress-fill vs spinner vs no reaction (pointer miss).
_MID_HOLD_CAPTURE_SECONDS = 2.0


class _HoldReleaseReason(StrEnum):
    ACCEPTED = "accepted"
    COMPLETED = "completed"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    INTERRUPTED = "interrupted"


@dataclass(slots=True)
class _HoldEvidence:
    index: int
    generation: str
    pointer_backend: str = "other"
    started: bool = False
    started_at: float | None = None
    release_reason: _HoldReleaseReason = _HoldReleaseReason.INTERRUPTED
    post_settle_acceptance_source: str | None = None
    retry_invited: bool | None = None
    control_still_present: bool | None = None
    generation_relation: str = "unavailable"
    final_surface_state: str = "unknown"


class PerimeterXHoldMechanic:
    vendor = ChallengeVendor.PERIMETERX

    def __init__(
        self,
        *,
        wall_budget_seconds: float = 45,
        max_holds: int = 2,
        hold_seconds: float = 10,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
        random_source: Callable[[], float] | None = None,
    ) -> None:
        if not math.isfinite(wall_budget_seconds) or wall_budget_seconds <= 0:
            raise ValueError("PerimeterX wall budget must be positive")
        if max_holds < 1 or max_holds > 3:
            raise ValueError("PerimeterX hold budget must be between 1 and 3")
        if not math.isfinite(hold_seconds) or hold_seconds <= 0:
            raise ValueError("PerimeterX hold duration must be positive")
        self._wall_budget = wall_budget_seconds
        self._max_holds = max_holds
        self._hold_seconds = hold_seconds
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self._random = random_source or SystemRandom().random

    def has_actionable_surface(self, browser: ChallengeBrowser) -> bool:
        """A press-and-hold control this mechanic could press, without pressing."""

        _frame, control = _hold_control(browser.page)
        return control is not None

    def solve(
        self,
        browser: ChallengeBrowser,
        acceptance: ChallengeAcceptanceProbe,
    ) -> ChallengeAcceptance:
        page = browser.page
        started = self._clock()
        holds_used = 0
        # Generations that already received a settled non-retry hold. A surface
        # that explicitly rejects ("please try again") stays open for another
        # press until the hold budget is exhausted.
        closed_generations: set[str] = set()
        while self._clock() - started < self._wall_budget:
            observed = acceptance.observe()
            if observed.accepted:
                return observed
            frame, control = _hold_control(page)
            if control is None:
                page.wait_for_timeout(250)
                continue
            generation = _generation(frame)
            if generation in closed_generations:
                # The current document already settled without inviting a
                # retry. Give the acceptance probe one final stability window,
                # then return control so the provider can cross the required
                # navigation boundary.
                page.wait_for_timeout(500)
                break
            if holds_used >= self._max_holds:
                break
            box = control.bounding_box()
            if not box or box["width"] <= 0 or box["height"] <= 0:
                page.wait_for_timeout(250)
                continue
            holds_used += 1
            attempt = holds_used
            x = float(box["x"] + box["width"] / 2)
            y = float(box["y"] + box["height"] / 2)
            geometry = (
                f"x{int(round(x))}y{int(round(y))}"
                f"w{int(round(float(box['width'])))}"
                f"h{int(round(float(box['height'])))}"
            )
            _capture(browser, f"px-{attempt}-before-{geometry}")
            evidence = _HoldEvidence(index=attempt, generation=generation)
            try:
                with _challenge_pointer(browser, page) as pointer:
                    pointer_kind = _pointer_kind(pointer)
                    evidence.pointer_backend = _pointer_backend(pointer_kind)
                    control_box = box
                    capture_label = f"px-{attempt}-armed-{pointer_kind}-{geometry}"

                    def arm_and_press(
                        *,
                        target_box=control_box,
                        target_x: float = x,
                        target_y: float = y,
                        label: str = capture_label,
                        hold_evidence: _HoldEvidence = evidence,
                    ) -> None:
                        self._approach_control(
                            pointer,
                            box=target_box,
                            x=target_x,
                            y=target_y,
                        )
                        _capture(browser, label)
                        pointer.down()
                        hold_evidence.started = True

                    run_challenge_action(browser, arm_and_press)
                    release_reason = _HoldReleaseReason.TIMEOUT
                    try:
                        hold_started = self._clock()
                        evidence.started_at = time.monotonic()
                        next_drift = hold_started + 0.2 + self._unit_random() * 0.25
                        next_mid_capture = hold_started + _MID_HOLD_CAPTURE_SECONDS
                        deadline = min(
                            hold_started + self._hold_seconds,
                            started + self._wall_budget,
                        )
                        _capture(
                            browser,
                            f"px-{attempt}-down-{pointer_kind}-{geometry}",
                        )
                        while self._clock() < deadline:
                            observed = acceptance.observe()
                            if observed.accepted:
                                release_reason = _HoldReleaseReason.ACCEPTED
                                break
                            signal = _hold_release_signal(frame, control)
                            # A retry surface still shows "Please try again" from
                            # the previous attempt; only honor rejection after the
                            # new hold has been under evaluation. The same grace
                            # applies to residual completion copy so a checkmark
                            # from the last round cannot end the fresh press early.
                            if (
                                signal is _HoldReleaseReason.REJECTED
                                and self._clock() - hold_started
                                < _REJECTION_GRACE_SECONDS
                            ):
                                signal = None
                            if (
                                signal is _HoldReleaseReason.COMPLETED
                                and self._clock() - hold_started
                                < _COMPLETION_GRACE_SECONDS
                            ):
                                signal = None
                            if signal is not None:
                                release_reason = signal
                                break
                            now = self._clock()
                            if now >= next_mid_capture:
                                elapsed = int(max(0.0, now - hold_started))
                                _capture(
                                    browser,
                                    f"px-{attempt}-holding-{elapsed}s-{pointer_kind}",
                                )
                                next_mid_capture = now + _MID_HOLD_CAPTURE_SECONDS
                            if now >= next_drift:
                                drift_x = (self._unit_random() - 0.5) * min(
                                    2.4, float(box["width"]) * 0.02
                                )
                                drift_y = (self._unit_random() - 0.5) * min(
                                    1.6, float(box["height"]) * 0.04
                                )
                                pointer.move(x + drift_x, y + drift_y, steps=1)
                                next_drift = now + 0.18 + self._unit_random() * 0.32
                            self._sleep(min(0.1, max(0.0, deadline - self._clock())))
                    finally:
                        _capture(
                            browser,
                            (
                                f"px-{attempt}-pre-up-"
                                f"{release_reason.value}-{pointer_kind}"
                            ),
                        )
                        pointer.up()
                _capture(
                    browser,
                    f"px-{attempt}-released-{release_reason.value}-{pointer_kind}",
                )
                settle_deadline = min(
                    self._clock() + _POST_HOLD_SETTLE_SECONDS,
                    started + self._wall_budget,
                )
                post_settle_acceptance = ChallengeAcceptance(
                    accepted=False,
                    source=ChallengeAcceptanceSource.NONE,
                )
                while self._clock() < settle_deadline:
                    observed = acceptance.observe()
                    post_settle_acceptance = observed
                    if observed.accepted:
                        evidence.release_reason = _HoldReleaseReason.ACCEPTED
                        _complete_hold_evidence(
                            evidence,
                            page=page,
                            frame=frame,
                            acceptance=observed,
                            cleared=True,
                        )
                        _capture(browser, f"px-{attempt}-after-accepted")
                        return observed
                    page.wait_for_timeout(250)
                _capture(browser, f"px-{attempt}-after")
                retry_invited = _page_invites_retry(frame)
                if release_reason is _HoldReleaseReason.REJECTED or retry_invited:
                    evidence.release_reason = release_reason
                    _complete_hold_evidence(
                        evidence,
                        page=page,
                        frame=frame,
                        acceptance=post_settle_acceptance,
                        retry_invited=retry_invited,
                    )
                    # Keep the generation open so a budgeted re-press can honor
                    # the provider's explicit "try again" invitation.
                    continue
                # A visual completion (checkmark) without surface clearance often
                # returns to the spinner / hold control. Keep the generation open
                # so a remaining hold budget can re-press instead of giving up.
                control_still_present: bool | None = None
                if release_reason is _HoldReleaseReason.COMPLETED:
                    control_still_present = _hold_control(page)[1] is not None
                evidence.release_reason = release_reason
                _complete_hold_evidence(
                    evidence,
                    page=page,
                    frame=frame,
                    acceptance=post_settle_acceptance,
                    retry_invited=False,
                    control_still_present=control_still_present,
                )
                if control_still_present is True:
                    continue
                closed_generations.add(generation)
            finally:
                _record_hold_evidence(browser, evidence)
        return acceptance.observe()

    def _approach_control(self, pointer, *, box, x: float, y: float) -> None:
        """Move along a short curved path with observable pointer cadence."""

        direction = -1 if self._unit_random() < 0.5 else 1
        distance = min(90.0, max(30.0, float(box["width"]) * 0.6))
        start_x = x + direction * distance
        start_y = y + (self._unit_random() - 0.5) * min(
            50.0, float(box["height"]) * 1.2
        )
        curve = (self._unit_random() - 0.5) * min(24.0, float(box["height"]) * 0.6)
        pointer.move(start_x, start_y, steps=3)
        self._sleep(0.03 + self._unit_random() * 0.04)
        for index in range(1, 19):
            progress = index / 18
            eased = progress * progress * (3 - 2 * progress)
            next_x = start_x + (x - start_x) * eased
            next_y = (
                start_y + (y - start_y) * eased + math.sin(math.pi * progress) * curve
            )
            pointer.move(next_x, next_y, steps=1)
            self._sleep(0.008 + self._unit_random() * 0.014)

    def _unit_random(self) -> float:
        value = float(self._random())
        if not math.isfinite(value) or value < 0 or value > 1:
            raise ValueError("PerimeterX random source must return values in [0, 1]")
        return value


def _complete_hold_evidence(
    evidence: _HoldEvidence,
    *,
    page,
    frame,
    acceptance: ChallengeAcceptance,
    cleared: bool = False,
    retry_invited: bool | None = None,
    control_still_present: bool | None = None,
) -> None:
    """Fill terminal facts without allowing observation to affect the mechanic."""

    evidence.post_settle_acceptance_source = acceptance.source.value
    if retry_invited is None:
        try:
            retry_invited = _page_invites_retry(frame)
        except Exception:
            retry_invited = False
    evidence.retry_invited = retry_invited

    current_root = None
    try:
        current_root, current_control = _hold_control(page)
        if control_still_present is None:
            control_still_present = current_control is not None
    except Exception:
        if control_still_present is None:
            control_still_present = False
    evidence.control_still_present = control_still_present

    if current_root is not None:
        try:
            evidence.generation_relation = (
                "same"
                if _generation(current_root) == evidence.generation
                else "changed"
            )
        except Exception:
            evidence.generation_relation = "unavailable"

    if cleared:
        evidence.final_surface_state = "cleared"
    elif evidence.release_reason is _HoldReleaseReason.REJECTED or retry_invited:
        evidence.final_surface_state = "rejected"
    elif (
        evidence.release_reason is _HoldReleaseReason.COMPLETED
        and control_still_present
    ):
        evidence.final_surface_state = "completed_control_present"
    elif evidence.release_reason is _HoldReleaseReason.TIMEOUT or control_still_present:
        evidence.final_surface_state = "spinner_or_loading"


def _record_hold_evidence(
    browser: object,
    evidence: _HoldEvidence,
) -> None:
    """Emit one best-effort event after every successfully started hold."""

    if not evidence.started:
        return
    recorder = getattr(browser, "record_perimeterx_hold", None)
    if not callable(recorder):
        return
    try:
        duration_seconds = (
            max(0.0, time.monotonic() - evidence.started_at)
            if evidence.started_at is not None
            else 0.0
        )
        recorder(
            hold_index=evidence.index,
            pointer_backend=evidence.pointer_backend,
            duration_seconds=duration_seconds,
            release_reason=evidence.release_reason.value,
            post_settle_acceptance_source=(
                evidence.post_settle_acceptance_source
                if evidence.release_reason is not _HoldReleaseReason.INTERRUPTED
                else None
            ),
            retry_invited=(
                evidence.retry_invited
                if evidence.release_reason is not _HoldReleaseReason.INTERRUPTED
                else None
            ),
            control_still_present=(
                evidence.control_still_present
                if evidence.release_reason is not _HoldReleaseReason.INTERRUPTED
                else None
            ),
            generation_relation=evidence.generation_relation,
            final_surface_state=evidence.final_surface_state,
        )
    except Exception:
        # Challenge evidence must never change challenge behavior.
        return


def _hold_control(page):
    roots = [page, *tuple(getattr(page, "frames", ()))]
    for root in roots:
        for selector in (
            "button:has-text('Press & Hold')",
            "button:has-text('Press and Hold')",
            "[role='button']:has-text('Press & Hold')",
            "[role='button']:has-text('Press and Hold')",
        ):
            locator = root.locator(selector)
            for index in range(locator.count()):
                candidate = locator.nth(index)
                if candidate.is_visible():
                    return root, candidate
        for selector in (
            "[data-px-captcha]",
            "#px-captcha",
        ):
            locator = root.locator(selector)
            for index in range(locator.count()):
                candidate = locator.nth(index)
                if candidate.is_visible() and _control_requires_hold(candidate):
                    return root, candidate
    return None, None


@contextmanager
def _challenge_pointer(browser, page):
    native_scope = getattr(browser, "challenge_pointer", None)
    if callable(native_scope):
        with native_scope() as pointer:
            yield pointer
        return
    yield page.mouse


def _pointer_kind(pointer: object) -> str:
    """Label diagnostic captures with the pointer backend in use."""

    name = type(pointer).__name__.casefold()
    if "x11" in name:
        return "x11"
    if "mouse" in name or name in {"mouse", "_mouse"}:
        return "cdp"
    return "pointer"


def _pointer_backend(pointer_kind: str) -> str:
    return pointer_kind if pointer_kind in {"x11", "cdp"} else "other"


def _control_requires_hold(control) -> bool:
    try:
        text = str(control.inner_text(timeout=1_000)).casefold()
        return "press and hold" in text or "press & hold" in text
    except Exception:
        return False


def _hold_release_signal(root, control) -> _HoldReleaseReason | None:
    """Recognize only explicit challenge completion or rejection states.

    PerimeterX blanks the "Press & Hold" label while the hold is still being
    evaluated (spinner). A text-scoped locator then reports not-visible, and an
    iframe root may not include the parent page's "unusual activity" copy. That
    processing state must keep the pointer down. Early release is reserved for
    explicit rejection/completion text; surface clearance is observed by the
    acceptance probe while the pointer remains down, otherwise the hold budget
    ends the press.
    """

    page_text = _combined_page_text(root)
    control_text = _visible_text(control)
    combined = f"{control_text}\n{page_text}".casefold()
    if _is_rejection_text(combined):
        return _HoldReleaseReason.REJECTED
    if _is_completion_text(combined):
        return _HoldReleaseReason.COMPLETED
    normalized_control = " ".join(control_text.casefold().split())
    if normalized_control in {"done", "complete", "completed", "please wait"}:
        return _HoldReleaseReason.COMPLETED
    # Invisible / replaced controls are not completion by themselves. Keep
    # holding through the processing spinner until acceptance clears the
    # surface, an explicit terminal phrase appears, or the hold budget ends.
    return None


def _page_invites_retry(root) -> bool:
    return _is_rejection_text(_combined_page_text(root).casefold())


def _is_rejection_text(combined: str) -> bool:
    return any(
        marker in combined
        for marker in ("please try again", "try again", "press again")
    )


def _is_completion_text(combined: str) -> bool:
    return any(
        marker in combined
        for marker in (
            "human challenge completed",
            "challenge completed",
            "completed, please wait",
        )
    )


def _combined_page_text(root) -> str:
    """Collect body text from the challenge root and its owning page if any."""

    chunks: list[str] = []
    seen: set[int] = set()
    for candidate in (root, getattr(root, "page", None)):
        if candidate is None or id(candidate) in seen:
            continue
        seen.add(id(candidate))
        text = _page_text(candidate)
        if text:
            chunks.append(text)
    return "\n".join(chunks)


def _page_text(root) -> str:
    try:
        body = root.locator("body")
        if body.count():
            return _visible_text(body.nth(0))
    except Exception:
        pass
    return ""


def _visible_text(locator) -> str:
    try:
        return str(locator.inner_text(timeout=250))
    except Exception:
        return ""


def _capture(browser: object, label: str) -> None:
    capture = getattr(browser, "capture_diagnostic_screenshot", None)
    if not callable(capture):
        return
    try:
        capture(label, timeout_ms=750)
    except Exception:
        # Challenge evidence must never change challenge behavior.
        return


def _generation(root) -> str:
    url = str(getattr(root, "url", ""))
    # Processing animation changes the control's geometry without creating a
    # new challenge. A replaced frame has a new wrapper identity; an explicit
    # rejection may still retry the same generation within the hold budget.
    material = f"{id(root)}|{url}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
