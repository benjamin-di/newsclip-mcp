"""Configured Economist provider and password-login recipe."""

from __future__ import annotations

from ..configured_provider import (
    ConfiguredLoginRecipe,
    ConfiguredProvider,
    normalize_url,
    provider_article_id,
)
from ..provider_config import ProviderSpec, load_provider_spec


class EconomistProvider(ConfiguredProvider):
    def __init__(
        self,
        *,
        verification_url: str | None = None,
        spec: ProviderSpec | None = None,
    ) -> None:
        selected_spec = spec or load_provider_spec("economist")
        super().__init__(selected_spec)
        self.login_recipe = (
            EconomistLoginRecipe(verification_url=verification_url, spec=selected_spec)
            if verification_url is not None
            else None
        )


class EconomistLoginRecipe(ConfiguredLoginRecipe):
    def __init__(
        self, *, verification_url: str, spec: ProviderSpec | None = None
    ) -> None:
        selected_spec = spec or load_provider_spec("economist")
        super().__init__(
            ConfiguredProvider(selected_spec),
            verification_url=verification_url,
            label="Economist",
        )


def build_economist_provider(
    spec: ProviderSpec, verification_url: str | None
) -> EconomistProvider:
    if verification_url is None:
        raise RuntimeError("Economist registration requires a verification URL")
    return EconomistProvider(verification_url=verification_url, spec=spec)


def normalize_article_url(raw: str) -> str | None:
    return normalize_url(load_provider_spec("economist"), raw)


def article_id(url: str) -> str | None:
    return provider_article_id(load_provider_spec("economist"), url)


__all__ = [
    "EconomistLoginRecipe",
    "EconomistProvider",
    "article_id",
    "build_economist_provider",
    "normalize_article_url",
]
