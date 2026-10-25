"""Application defaults around shared hCaptcha mechanics."""

from signin_window.automation.hcaptcha import HCaptchaVisualMechanic as _Mechanic
from signin_window.automation.hcaptcha import (
    PromptFamily as PromptFamily,
)
from signin_window.automation.hcaptcha import (
    _ActionBoundary as _ActionBoundary,
)
from signin_window.automation.hcaptcha import (
    _hcaptcha_instruction as _hcaptcha_instruction,
)
from signin_window.automation.hcaptcha import (
    _HCaptchaOutcomeObserver as _HCaptchaOutcomeObserver,
)
from signin_window.automation.hcaptcha import (
    classify_prompt_family as classify_prompt_family,
)

from .vision_planning import LocalCliVisionPlanner


class HCaptchaVisualMechanic(_Mechanic):
    def __init__(self, *, planner=None, **kwargs):
        super().__init__(planner=planner or LocalCliVisionPlanner(), **kwargs)
