"""Provider-bound orchestration for detected interactive challenges."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from enum import StrEnum

from pydantic import model_validator

from .challenge_detection import detect_challenge
from .challenges import (
    ChallengeAcceptance,
    ChallengeAcceptanceProbe,
    ChallengeAcceptanceSource,
    ChallengeBrowser,
    ChallengeDetection,
    ChallengeInfrastructureError,
    ChallengeMechanic,
    ChallengeMechanicError,
    ChallengeMode,
    ChallengeState,
    ChallengeVendor,
)
from .models import FrozenModel
from .timing import TimingStep, timing_step


class ChallengeResolutionStatus(StrEnum):
    NOT_PRESENT = "not_present"
    NON_INTERACTIVE = "non_interactive"
    CLEARED = "cleared"
    BLOCKED = "blocked"


class ChallengeBlockReason(StrEnum):
    DETECT_ONLY = "detect_only"
    UNSUPPORTED = "unsupported"
    MECHANIC_FAILED = "mechanic_failed"
    ACCEPTANCE_UNCONFIRMED = "acceptance_unconfirmed"


class ChallengeResolution(FrozenModel):
    status: ChallengeResolutionStatus
    detection: ChallengeDetection
    acceptance: ChallengeAcceptance | None = None
    reason: ChallengeBlockReason | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> ChallengeResolution:
        if self.status is ChallengeResolutionStatus.NOT_PRESENT:
            if self.detection.state is not ChallengeState.NONE or self.reason:
                raise ValueError("not-present resolution requires no challenge")
        elif self.status is ChallengeResolutionStatus.NON_INTERACTIVE:
            if (
                self.detection.state
                not in {
                    ChallengeState.ASSET_ONLY,
                    ChallengeState.SOLVED,
                }
                or self.reason
            ):
                raise ValueError("non-interactive resolution requires a passive state")
        elif self.status is ChallengeResolutionStatus.CLEARED:
            if (
                self.detection.state is not ChallengeState.INTERACTIVE
                or not self.acceptance
                or not self.acceptance.accepted
                or self.reason
            ):
                raise ValueError("cleared resolution requires accepted evidence")
        elif (
            self.detection.state is not ChallengeState.INTERACTIVE
            or self.reason is None
        ):
            raise ValueError("blocked resolution requires an interactive challenge")
        return self

    @property
    def allows_continuation(self) -> bool:
        return self.status is not ChallengeResolutionStatus.BLOCKED


class StableSurfaceClearProbe:
    """Require repeated detector agreement before accepting a vanished surface."""

    def __init__(
        self,
        browser: object,
        vendor: ChallengeVendor,
        *,
        detector: Callable[[object], ChallengeDetection] = detect_challenge,
        required_observations: int = 2,
        minimum_clear_seconds: float = 0.5,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if vendor in {ChallengeVendor.NONE, ChallengeVendor.UNSUPPORTED}:
            raise ValueError("surface-clear probe requires a supported vendor")
        if required_observations < 2 or required_observations > 5:
            raise ValueError("stable-clear observations must be between 2 and 5")
        if (
            not math.isfinite(minimum_clear_seconds)
            or minimum_clear_seconds <= 0
            or minimum_clear_seconds > 5
        ):
            raise ValueError("stable-clear duration must be within (0, 5] seconds")
        self._browser = browser
        self._detector = detector
        self._required = required_observations
        self._minimum_clear_seconds = minimum_clear_seconds
        self._clock = clock if clock is not None else time.monotonic
        self._clear_observations = 0
        self._clear_started_at: float | None = None

    def observe(self) -> ChallengeAcceptance:
        detection = self._detector(self._browser)
        observed_at = self._clock()
        if not math.isfinite(observed_at):
            raise ValueError("surface-clear clock must return a finite value")
        # Publisher pages can load another vendor's passive assets after the
        # blocking surface clears. Vendor identity is not evidence of a gate;
        # any interactive or unclassified surface still resets stable proof.
        clear = (
            detection.state is not ChallengeState.INTERACTIVE
            and detection.vendor is not ChallengeVendor.UNSUPPORTED
        )
        if clear:
            if self._clear_started_at is None:
                self._clear_started_at = observed_at
                self._clear_observations = 1
            else:
                self._clear_observations += 1
        else:
            self._clear_observations = 0
            self._clear_started_at = None
        accepted = (
            self._clear_started_at is not None
            and self._clear_observations >= self._required
            and observed_at - self._clear_started_at >= self._minimum_clear_seconds
        )
        return ChallengeAcceptance(
            accepted=accepted,
            source=(
                ChallengeAcceptanceSource.SURFACE_CLEAR
                if accepted
                else ChallengeAcceptanceSource.NONE
            ),
        )


class ChallengeResolver:
    """Detect once, dispatch a provider-approved mechanic, and re-verify."""

    def __init__(
        self,
        mechanics: Mapping[ChallengeVendor, ChallengeMechanic],
        *,
        detector: Callable[[object], ChallengeDetection] = detect_challenge,
    ) -> None:
        selected = dict(mechanics)
        for vendor, mechanic in selected.items():
            if vendor in {ChallengeVendor.NONE, ChallengeVendor.UNSUPPORTED}:
                raise ValueError("challenge mechanics require a supported vendor")
            if mechanic.vendor is not vendor:
                raise ValueError("challenge mechanic is bound under the wrong vendor")
        self._mechanics = selected
        self._detector = detector

    @property
    def supported_vendors(self) -> frozenset[ChallengeVendor]:
        """The promoted mechanics this provider explicitly approved."""

        return frozenset(self._mechanics)

    def resolve(
        self,
        browser: ChallengeBrowser,
        mode: ChallengeMode,
        *,
        acceptance: ChallengeAcceptanceProbe | None = None,
        acceptance_vendor: ChallengeVendor | None = None,
    ) -> ChallengeResolution:
        resolution = self._resolve(
            browser, mode, acceptance=acceptance, acceptance_vendor=acceptance_vendor
        )
        recorder = getattr(browser, "record_challenge_resolution", None)
        if callable(recorder):
            mechanic = self._mechanics.get(resolution.detection.vendor)
            capability = (
                "detect_only"
                if mode is ChallengeMode.DETECT_ONLY
                else "unsupported"
                if mechanic is None
                else "passive_wait"
                if getattr(mechanic, "passive_only", False)
                else "interactive_mechanic"
            )
            with suppress(Exception):
                recorder(resolution=resolution, mode=mode, capability=capability)
        return resolution

    def _resolve(
        self,
        browser: ChallengeBrowser,
        mode: ChallengeMode,
        *,
        acceptance: ChallengeAcceptanceProbe | None,
        acceptance_vendor: ChallengeVendor | None,
    ) -> ChallengeResolution:
        if acceptance_vendor is not None and acceptance is None:
            raise ValueError("vendor-scoped acceptance requires a probe")
        if acceptance_vendor in {ChallengeVendor.NONE, ChallengeVendor.UNSUPPORTED}:
            raise ValueError("acceptance probe requires a supported vendor")
        detection = self._detect(browser)
        if detection.state is ChallengeState.NONE:
            return self._passive(
                ChallengeResolutionStatus.NOT_PRESENT, detection, acceptance
            )
        if detection.state in {ChallengeState.ASSET_ONLY, ChallengeState.SOLVED}:
            return self._passive(
                ChallengeResolutionStatus.NON_INTERACTIVE,
                detection,
                (
                    acceptance
                    if acceptance_vendor is None
                    or acceptance_vendor is detection.vendor
                    else None
                ),
            )
        # Observe the first blocking surface before the existing mechanic can
        # change it. Diagnostic hooks cannot change the resolution policy.
        with suppress(Exception):
            recorder = getattr(browser, "record_challenge_started", None)
            if callable(recorder):
                recorder()
        active_acceptance = (
            acceptance
            if acceptance_vendor is None or acceptance_vendor is detection.vendor
            else None
        )
        if active_acceptance is not None:
            existing = self._observe_acceptance(active_acceptance)
            if existing.accepted:
                return ChallengeResolution(
                    status=ChallengeResolutionStatus.CLEARED,
                    detection=detection,
                    acceptance=existing,
                )
        if mode is ChallengeMode.DETECT_ONLY:
            return self._blocked(detection, ChallengeBlockReason.DETECT_ONLY)
        mechanic = self._mechanics.get(detection.vendor)
        if mechanic is None:
            return self._blocked(detection, ChallengeBlockReason.UNSUPPORTED)
        probe = active_acceptance or StableSurfaceClearProbe(
            browser,
            detection.vendor,
            detector=self._detector,
        )
        try:
            with timing_step(TimingStep.CHALLENGE):
                mechanic.solve(browser, probe)
        except ChallengeMechanicError:
            return self._blocked(detection, ChallengeBlockReason.MECHANIC_FAILED)
        except ChallengeInfrastructureError:
            raise
        except Exception as error:
            raise ChallengeInfrastructureError(
                "challenge mechanic failed operationally"
            ) from error
        verified = self._observe_acceptance(probe)
        if not verified.accepted:
            return ChallengeResolution(
                status=ChallengeResolutionStatus.BLOCKED,
                detection=detection,
                acceptance=verified,
                reason=ChallengeBlockReason.ACCEPTANCE_UNCONFIRMED,
            )
        return ChallengeResolution(
            status=ChallengeResolutionStatus.CLEARED,
            detection=detection,
            acceptance=verified,
        )

    def _detect(self, browser: object) -> ChallengeDetection:
        try:
            detection = self._detector(browser)
            if not isinstance(detection, ChallengeDetection):
                raise TypeError("challenge detector returned the wrong type")
            return detection
        except ChallengeInfrastructureError:
            raise
        except Exception as error:
            raise ChallengeInfrastructureError("challenge detection failed") from error

    @staticmethod
    def _observe_acceptance(
        acceptance: ChallengeAcceptanceProbe,
    ) -> ChallengeAcceptance:
        try:
            observed = acceptance.observe()
            if not isinstance(observed, ChallengeAcceptance):
                raise TypeError("challenge acceptance probe returned the wrong type")
            return observed
        except ChallengeInfrastructureError:
            raise
        except Exception as error:
            raise ChallengeInfrastructureError(
                "challenge acceptance probe failed"
            ) from error

    def _passive(
        self,
        status: ChallengeResolutionStatus,
        detection: ChallengeDetection,
        acceptance: ChallengeAcceptanceProbe | None,
    ) -> ChallengeResolution:
        evidence = (
            self._observe_acceptance(acceptance) if acceptance is not None else None
        )
        return ChallengeResolution(
            status=status,
            detection=detection,
            acceptance=evidence,
        )

    @staticmethod
    def _blocked(
        detection: ChallengeDetection,
        reason: ChallengeBlockReason,
    ) -> ChallengeResolution:
        return ChallengeResolution(
            status=ChallengeResolutionStatus.BLOCKED,
            detection=detection,
            reason=reason,
        )
