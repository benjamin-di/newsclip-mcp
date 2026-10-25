"""Optional secret-store resolution behind the deployment boundary."""

from __future__ import annotations

from signin_window.automation.secrets import (
    SecretResolutionError as SecretResolutionError,
)


class ConfiguredSecretReader:
    def read(self, reference: str) -> str:
        from .secret_reference import OpSecretReader

        return OpSecretReader().read(reference)
