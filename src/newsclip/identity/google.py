"""News authentication evidence around the shared Google sign-in driver."""

from signin_window.automation.auth import AuthFlowFailure
from signin_window.automation.google import GoogleIdentityConfig as GoogleIdentityConfig
from signin_window.automation.google import GoogleIdentityDriver as _Driver
from signin_window.automation.google import (
    GoogleIdentityObservation as GoogleIdentityObservation,
)
from signin_window.automation.google import GoogleIdentityResult as GoogleIdentityResult
from signin_window.automation.google import GoogleIdentityStep as GoogleIdentityStep
from signin_window.automation.google import GoogleLoopDirective as GoogleLoopDirective
from signin_window.automation.google import google_identity_step as google_identity_step

from ..acquisition import (
    AcquisitionFailure,
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
)
from ..timing import TimingStep, timing_step


class GoogleIdentityDriver(_Driver):
    def __init__(self, config, **kwargs):
        super().__init__(
            config,
            step=lambda name: timing_step(
                TimingStep(name), provider=config.provider_key
            ),
            **kwargs,
        )

    @staticmethod
    def _translate(work):
        try:
            return work()
        except AuthFlowFailure as error:
            raise AcquisitionFailure(
                error.outcome,
                MintFailureEvidence(
                    stage=MintFailureStage(error.evidence.stage),
                    category=MintFailureCategory(error.evidence.category),
                ),
            ) from error

    def drive(self, browser, **kwargs):
        return self._translate(
            lambda: super(GoogleIdentityDriver, self).drive(browser, **kwargs)
        )

    def resume_cached_callback(self, browser, **kwargs):
        return self._translate(
            lambda: super(GoogleIdentityDriver, self).resume_cached_callback(
                browser, **kwargs
            )
        )
