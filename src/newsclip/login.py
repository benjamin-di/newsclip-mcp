"""Application timing around shared, origin-scoped secret delivery."""

from signin_window.automation.auth import SecretDeliveryError as _SecretDeliveryError
from signin_window.automation.secret_filler import OpSecretFiller as _Filler
from signin_window.automation.secret_filler import configured_credential_filler

from .maintenance import credential_reader_factory
from .timing import TimingStep, timing_step

LoginInfrastructureError = _SecretDeliveryError


class OpSecretFiller(_Filler):
    def __init__(self, **kwargs):
        super().__init__(step=lambda name: timing_step(TimingStep(name)), **kwargs)


def credential_filler():
    return configured_credential_filler(
        credential_reader_factory(), step=lambda name: timing_step(TimingStep(name))
    )
