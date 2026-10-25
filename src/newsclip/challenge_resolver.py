"""Application compatibility over shared challenge mechanics."""

from signin_window.automation.resolver import (
    ChallengeBlockReason as ChallengeBlockReason,
)
from signin_window.automation.resolver import ChallengeResolution as ChallengeResolution
from signin_window.automation.resolver import (
    ChallengeResolutionStatus as ChallengeResolutionStatus,
)
from signin_window.automation.resolver import ChallengeResolver as _Resolver
from signin_window.automation.resolver import (
    StableSurfaceClearProbe as StableSurfaceClearProbe,
)

from .timing import TimingStep, timing_step


class ChallengeResolver(_Resolver):
    def __init__(self, mechanics, **kwargs):
        super().__init__(
            mechanics, step=lambda: timing_step(TimingStep.CHALLENGE), **kwargs
        )
