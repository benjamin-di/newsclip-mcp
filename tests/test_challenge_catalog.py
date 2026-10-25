"""Promoted challenge-mechanic composition."""

from __future__ import annotations

import pytest

from newsclip.challenge_catalog import build_challenge_resolver
from newsclip.challenges import ChallengeVendor


@pytest.mark.parametrize(
    "vendor",
    [
        ChallengeVendor.HCAPTCHA,
        ChallengeVendor.DATADOME,
        ChallengeVendor.PERIMETERX,
        ChallengeVendor.CLOUDFLARE_INTERSTITIAL,
    ],
)
def test_promoted_vendor_builds_only_its_approved_mechanic(
    vendor: ChallengeVendor,
) -> None:
    resolver = build_challenge_resolver({vendor})

    assert resolver.supported_vendors == frozenset({vendor})


@pytest.mark.parametrize(
    "vendor",
    [
        ChallengeVendor.RECAPTCHA,
        ChallengeVendor.TURNSTILE,
        ChallengeVendor.UNSUPPORTED,
    ],
)
def test_unpromoted_vendor_fails_at_composition(vendor: ChallengeVendor) -> None:
    with pytest.raises(
        RuntimeError,
        match=f"challenge mechanics are not promoted: {vendor.value}",
    ):
        build_challenge_resolver({vendor})


def test_resolver_uses_the_injected_detector() -> None:
    from newsclip.challenges import ChallengeDetection, ChallengeState

    calls: list[object] = []

    def detector(browser: object) -> ChallengeDetection:
        calls.append(browser)
        return ChallengeDetection(
            vendor=ChallengeVendor.NONE, state=ChallengeState.NONE
        )

    resolver = build_challenge_resolver({ChallengeVendor.PERIMETERX}, detector=detector)
    from newsclip.challenges import ChallengeMode

    resolution = resolver.resolve(object(), ChallengeMode.AUTO)

    assert calls
    assert resolution.status.value == "not_present"


def test_passive_datadome_never_drags() -> None:
    from newsclip.challenge_catalog import build_promoted_mechanics

    passive = build_promoted_mechanics(
        {ChallengeVendor.DATADOME}, passive_vendors={ChallengeVendor.DATADOME}
    )[ChallengeVendor.DATADOME]
    promoted = build_promoted_mechanics({ChallengeVendor.DATADOME})[
        ChallengeVendor.DATADOME
    ]

    assert passive.passive_only is True
    assert promoted.passive_only is False


@pytest.mark.parametrize(
    ("approved", "passive", "message"),
    [
        (
            set(),
            {ChallengeVendor.DATADOME},
            "passive challenge vendors are not approved",
        ),
        (
            {ChallengeVendor.PERIMETERX},
            {ChallengeVendor.PERIMETERX},
            "challenge mechanics are not promoted: perimeterx",
        ),
    ],
)
def test_passive_approval_is_bounded(approved, passive, message) -> None:  # noqa: ANN001
    with pytest.raises(RuntimeError, match=message):
        build_challenge_resolver(approved, passive_vendors=passive)


def test_passive_capability_is_recorded() -> None:
    from newsclip.challenges import ChallengeDetection, ChallengeMode, ChallengeState

    recorded: list[str] = []

    class Page:
        frames: list[object] = []

        def wait_for_timeout(self, milliseconds: float) -> None: ...

    class Browser:
        page = Page()

        def record_challenge_resolution(self, *, resolution, mode, capability) -> None:  # noqa: ANN001
            recorded.append(capability)

    detections = iter(
        [
            ChallengeDetection(
                vendor=ChallengeVendor.DATADOME, state=ChallengeState.INTERACTIVE
            )
        ]
    )

    def detector(_browser: object) -> ChallengeDetection:
        return next(
            detections,
            ChallengeDetection(
                vendor=ChallengeVendor.DATADOME, state=ChallengeState.ASSET_ONLY
            ),
        )

    resolver = build_challenge_resolver(
        {ChallengeVendor.DATADOME},
        passive_vendors={ChallengeVendor.DATADOME},
        detector=detector,
    )
    resolution = resolver.resolve(Browser(), ChallengeMode.AUTO)

    assert resolution.status.value == "cleared"
    assert recorded == ["passive_wait"]
