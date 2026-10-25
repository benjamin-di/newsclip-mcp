"""Provider/mechanic boundary for bounded interactive challenge handling."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from pydantic import model_validator

from .models import FrozenModel


class ChallengeAcceptanceSource(StrEnum):
    EXACT_WIDGET_API = "exact_widget_api"
    EXISTING_FORM_FIELD = "existing_form_field"
    SURFACE_CLEAR = "surface_clear"
    NONE = "none"


class ChallengeMode(StrEnum):
    DETECT_ONLY = "detect-only"
    AUTO = "auto"


class ChallengeVendor(StrEnum):
    NONE = "none"
    HCAPTCHA = "hcaptcha"
    DATADOME = "datadome"
    PERIMETERX = "perimeterx"
    CLOUDFLARE_INTERSTITIAL = "cloudflare_interstitial"
    RECAPTCHA = "recaptcha"
    TURNSTILE = "turnstile"
    UNSUPPORTED = "unsupported"


class ChallengeState(StrEnum):
    NONE = "none"
    ASSET_ONLY = "asset_only"
    INTERACTIVE = "interactive"
    SOLVED = "solved"


class ChallengeDetection(FrozenModel):
    vendor: ChallengeVendor
    state: ChallengeState

    @model_validator(mode="after")
    def validate_none_pair(self) -> ChallengeDetection:
        if (self.vendor is ChallengeVendor.NONE) is not (
            self.state is ChallengeState.NONE
        ):
            raise ValueError("none challenge vendor and state must agree")
        return self


class ChallengeAcceptance(FrozenModel):
    accepted: bool
    source: ChallengeAcceptanceSource

    @model_validator(mode="after")
    def validate_source(self) -> ChallengeAcceptance:
        if self.accepted is (self.source is ChallengeAcceptanceSource.NONE):
            raise ValueError("acceptance and source must agree")
        return self


@runtime_checkable
class ChallengeAcceptanceProbe(Protocol):
    def observe(self) -> ChallengeAcceptance: ...


@runtime_checkable
class ChallengeBrowser(Protocol):
    @property
    def page(self) -> Any: ...

    def dispatch_challenge_action(self, dispatch: Callable[[], Any]) -> Any: ...


@runtime_checkable
class ChallengeMechanic(Protocol):
    vendor: ChallengeVendor

    def solve(
        self,
        browser: ChallengeBrowser,
        acceptance: ChallengeAcceptanceProbe,
    ) -> ChallengeAcceptance: ...

    def has_actionable_surface(self, browser: ChallengeBrowser) -> bool:
        """Whether this mechanic has something it could act on *right now*.

        **Read-only.** An implementation may look, and must not click, drag,
        open, or otherwise change the page — this is the one question that can
        be asked of a live challenge without spending an attempt on it.

        The distinction it draws is the one a challenged flow cannot otherwise
        report. A mechanic that finds no surface waits out its whole budget and
        dispatches nothing, which reads in a trace exactly like a mechanic that
        was never approved: NYT's 2026-07-28 cold gate charged 61.5 s to a
        challenge and dispatched no action, and separating "no surface" from
        "broken" needed someone to read mechanic internals. False here is a
        fact about the page, not a verdict about the mechanic.
        """
        ...


class ChallengeMechanicError(RuntimeError):
    """A supported mechanic could not complete its bounded solve attempt."""


class ChallengeInfrastructureError(RuntimeError):
    """A challenge dependency was unavailable or failed operationally."""


def run_challenge_action(
    browser: ChallengeBrowser | object,
    dispatch: Callable[[], Any],
) -> Any:
    """Use the production ledger while keeping isolated mechanic fakes lightweight."""

    traced_dispatch = getattr(browser, "dispatch_challenge_action", None)
    if callable(traced_dispatch):
        return traced_dispatch(dispatch)
    return dispatch()
