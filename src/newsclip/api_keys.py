"""Optional secret-store resolution behind the deployment boundary."""

from __future__ import annotations


class SecretResolutionError(RuntimeError):
    """A configured API key could not be resolved."""


class ConfiguredSecretReader:
    def read(self, reference: str) -> str:
        from .extensions import local_extensions

        extension = local_extensions()
        if extension is None:
            raise SecretResolutionError("configure the provider API key")
        return extension.resolve_api_key(reference)
