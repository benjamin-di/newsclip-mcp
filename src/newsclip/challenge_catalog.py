"""Promoted interactive-challenge mechanics available to provider composition."""

from __future__ import annotations

from collections.abc import Callable, Collection

from .challenge_detection import detect_challenge
from .challenge_resolver import ChallengeResolver
from .challenges import (
    ChallengeDetection,
    ChallengeMechanic,
    ChallengeMechanicError,
    ChallengeVendor,
)
from .cloudflare_interstitial import CloudflareInterstitialMechanic
from .datadome import DataDomeSliderMechanic
from .extensions import local_extensions
from .perimeterx import PerimeterXHoldMechanic

MechanicFactory = Callable[[], ChallengeMechanic]


def _hcaptcha() -> ChallengeMechanic:
    extension = local_extensions()
    if extension is not None:
        return extension.hcaptcha_mechanic()
    return HumanChallenge()


class HumanChallenge:
    """Preserve challenge detection while requiring a person's action."""

    vendor = ChallengeVendor.HCAPTCHA

    def solve(self, browser, acceptance):
        raise ChallengeMechanicError("human challenge action required")

    def has_actionable_surface(self, browser) -> bool:
        return detect_challenge(browser).vendor is self.vendor


def _perimeterx() -> ChallengeMechanic:
    return PerimeterXHoldMechanic(hold_seconds=12)


_PROMOTED_MECHANICS: dict[ChallengeVendor, MechanicFactory] = {
    ChallengeVendor.HCAPTCHA: _hcaptcha,
    ChallengeVendor.DATADOME: DataDomeSliderMechanic,
    ChallengeVendor.PERIMETERX: _perimeterx,
    ChallengeVendor.CLOUDFLARE_INTERSTITIAL: CloudflareInterstitialMechanic,
}


def _datadome_passage() -> ChallengeMechanic:
    # A Device Check clears in seconds when it accepts the browser; past this
    # budget the wait is not converging and the edge's verdict stands.
    return DataDomeSliderMechanic(wall_budget_seconds=15, max_drags=0)


# Passage-only forms: wait for the vendor's own surface to clear, never act on
# it. A provider approved here gets this form instead of the promoted one.
_PASSIVE_MECHANICS: dict[ChallengeVendor, MechanicFactory] = {
    ChallengeVendor.DATADOME: _datadome_passage,
}


def build_promoted_mechanics(
    approved_vendors: Collection[ChallengeVendor],
    *,
    passive_vendors: Collection[ChallengeVendor] = (),
) -> dict[ChallengeVendor, ChallengeMechanic]:
    """Build only the mechanics explicitly approved by one provider.

    ``passive_vendors`` must be a subset of ``approved_vendors``; those get
    the passage-only form. Exposed separately from the resolver because a
    mechanic answers one read-only question — `has_actionable_surface` —
    that needs no resolution and must not perform one.
    """

    approved = set(approved_vendors)
    passive = set(passive_vendors)
    if not passive <= approved:
        names = ", ".join(sorted(vendor.value for vendor in passive - approved))
        raise RuntimeError(f"passive challenge vendors are not approved: {names}")
    invalid = {
        vendor
        for vendor in approved
        if vendor
        not in (_PASSIVE_MECHANICS if vendor in passive else _PROMOTED_MECHANICS)
    }
    if invalid:
        names = ", ".join(sorted(vendor.value for vendor in invalid))
        raise RuntimeError(f"challenge mechanics are not promoted: {names}")
    return {
        vendor: (
            _PASSIVE_MECHANICS[vendor]
            if vendor in passive
            else _PROMOTED_MECHANICS[vendor]
        )()
        for vendor in sorted(approved, key=lambda item: item.value)
    }


def build_challenge_resolver(
    approved_vendors: Collection[ChallengeVendor],
    *,
    passive_vendors: Collection[ChallengeVendor] = (),
    detector: Callable[[object], ChallengeDetection] = detect_challenge,
) -> ChallengeResolver:
    """Build one resolver over a provider's approved mechanics."""

    return ChallengeResolver(
        build_promoted_mechanics(approved_vendors, passive_vendors=passive_vendors),
        detector=detector,
    )


__all__ = ["build_challenge_resolver", "build_promoted_mechanics"]
