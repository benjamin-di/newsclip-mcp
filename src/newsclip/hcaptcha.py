"""Application defaults around shared hCaptcha mechanics."""

from signin_window.automation.hcaptcha import (
    ChallengeActionBoundary as _ActionBoundary,
)
from signin_window.automation.hcaptcha import (
    HCaptchaOutcomeObserver as _HCaptchaOutcomeObserver,
)
from signin_window.automation.hcaptcha import HCaptchaVisualMechanic as _Mechanic
from signin_window.automation.hcaptcha import (
    PromptFamily as PromptFamily,
)
from signin_window.automation.hcaptcha import (
    classify_prompt_family as classify_prompt_family,
)
from signin_window.automation.hcaptcha import (
    hcaptcha_instruction as _hcaptcha_instruction,
)

__all__ = [
    "HCaptchaVisualMechanic",
    "PromptFamily",
    "classify_prompt_family",
    "_ActionBoundary",
    "_HCaptchaOutcomeObserver",
    "_hcaptcha_instruction",
]

from .vision_planning import LocalCliVisionPlanner


class HCaptchaVisualMechanic(_Mechanic):
    def __init__(self, *, planner=None, **kwargs):
        super().__init__(planner=planner or LocalCliVisionPlanner(), **kwargs)
