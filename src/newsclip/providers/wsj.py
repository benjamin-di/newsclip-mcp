"""Configured Wall Street Journal provider and compatibility constructors."""

from __future__ import annotations

from ..configured_provider import (
    ConfiguredLoginRecipe,
    ConfiguredProvider,
    normalize_url,
    provider_article_id,
)
from ..contracts import HttpClient
from ..models import ProviderSearchPage, SearchFilters, SessionArtifact
from ..provider_config import ProviderSpec, load_provider_spec


class WSJProvider(ConfiguredProvider):
    # The retained September 14 opinion-page failures use this exact subtype.
    # Keep it provider-local; WebPage and generic Article remain insufficient.
    _jsonld_article_types = ("NewsArticle", "OpinionNewsArticle")

    def __init__(
        self,
        *,
        verification_url: str | None = None,
        spec: ProviderSpec | None = None,
    ) -> None:
        selected_spec = spec or load_provider_spec("wsj")
        super().__init__(selected_spec)
        self.assessment_policy_version += "-opinion-v1"
        self.login_recipe = (
            WSJLoginRecipe(verification_url=verification_url, spec=selected_spec)
            if verification_url is not None
            else None
        )

    def search_page(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
        *,
        next_url: str | None = None,
        metadata_fetch_budget: int | None = None,
    ) -> ProviderSearchPage:
        # WSJ search is public and rejects an otherwise valid paid-article jar
        # with HTTP 401. Keep discovery anonymous; apply the verified session
        # only to the paid article retrieval boundary.
        return super().search_page(
            http,
            None,
            query,
            filters,
            next_url=next_url,
            metadata_fetch_budget=metadata_fetch_budget,
        )


class WSJLoginRecipe(ConfiguredLoginRecipe):
    def __init__(
        self, *, verification_url: str, spec: ProviderSpec | None = None
    ) -> None:
        selected_spec = spec or load_provider_spec("wsj")
        super().__init__(
            WSJProvider(spec=selected_spec),
            verification_url=verification_url,
            label="WSJ",
        )


def build_wsj_provider(spec: ProviderSpec, verification_url: str | None) -> WSJProvider:
    if verification_url is None:
        raise RuntimeError("WSJ registration requires a verification URL")
    return WSJProvider(verification_url=verification_url, spec=spec)


def normalize_article_url(raw: str) -> str | None:
    return normalize_url(load_provider_spec("wsj"), raw)


def article_id(url: str) -> str | None:
    return provider_article_id(load_provider_spec("wsj"), url)


__all__ = [
    "WSJLoginRecipe",
    "WSJProvider",
    "build_wsj_provider",
    "article_id",
    "normalize_article_url",
]
