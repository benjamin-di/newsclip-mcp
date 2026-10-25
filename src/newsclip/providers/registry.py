"""Small explicit registry for built-in providers."""

from __future__ import annotations

from collections.abc import Iterable

from ..errors import UnknownProviderError, UsageError
from ..provider_keys import is_provider_key
from .base import Provider


class ProviderRegistry:
    def __init__(self, providers: Iterable[Provider] = ()) -> None:
        self._providers: dict[str, Provider] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: Provider) -> None:
        if not is_provider_key(provider.key):
            raise ValueError("invalid provider key")
        if provider.key in self._providers:
            raise ValueError(f"duplicate provider key: {provider.key}")
        self._providers[provider.key] = provider

    def get(self, key: str) -> Provider:
        try:
            return self._providers[key]
        except KeyError as exc:
            raise UnknownProviderError(f"unknown provider: {key}") from exc

    def for_url(self, url: str) -> Provider:
        matches = [
            provider for provider in self._providers.values() if provider.owns_url(url)
        ]
        if len(matches) != 1:
            raise UsageError("URL must be owned by exactly one registered provider")
        return matches[0]

    def keys(self) -> tuple[str, ...]:
        return tuple(self._providers)

    def __iter__(self):
        return iter(self._providers.values())
