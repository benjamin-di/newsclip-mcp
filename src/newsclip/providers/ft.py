"""Configured Financial Times provider and compatibility constructors."""

from __future__ import annotations

from urllib.parse import urlsplit

from lxml import etree, html

from ..configured_provider import (
    ConfiguredLoginRecipe,
    ConfiguredProvider,
    normalize_url,
    provider_article_id,
)
from ..contracts import HttpClient
from ..errors import AccountAlertError
from ..models import (
    ArticleAssessment,
    ExtractedArticle,
    RawFetch,
    SessionArtifact,
    SessionVerification,
)
from ..provider_config import ProviderDefinitionError, ProviderSpec, load_provider_spec


class FTProvider(ConfiguredProvider):
    def __init__(
        self,
        *,
        verification_url: str | None = None,
        spec: ProviderSpec | None = None,
    ) -> None:
        selected_spec = spec or load_provider_spec("ft")
        selected_verification_url = (
            _default_verification_url(selected_spec)
            if verification_url is None
            else verification_url
        )
        super().__init__(selected_spec)
        self.assessment_policy_version += "-account-alert-v1"
        self.login_recipe = FTLoginRecipe(
            verification_url=selected_verification_url,
            spec=selected_spec,
        )

    def fetch(
        self, http: HttpClient, session: SessionArtifact | None, url: str
    ) -> RawFetch:
        fetch = super().fetch(http, session, url)
        if _account_security_reset(fetch):
            raise AccountAlertError(self.key, fetch)
        return fetch

    def assess(
        self, requested_url: str, fetch: RawFetch, extraction: ExtractedArticle
    ) -> ArticleAssessment:
        assessment = super().assess(requested_url, fetch, extraction)
        if _account_security_reset(fetch):
            return assessment.model_copy(
                update={
                    "reason": "account_alert",
                    "negative_markers": ("account_alert",),
                }
            )
        return assessment


class FTLoginRecipe(ConfiguredLoginRecipe):
    def __init__(
        self,
        *,
        verification_url: str | None = None,
        spec: ProviderSpec | None = None,
    ) -> None:
        selected_spec = spec or load_provider_spec("ft")
        super().__init__(
            ConfiguredProvider(selected_spec),
            verification_url=(
                _default_verification_url(selected_spec)
                if verification_url is None
                else verification_url
            ),
            label="FT",
        )

    def verify_fetch(self, fetch: RawFetch) -> SessionVerification:
        if _account_security_reset(fetch):
            raise AccountAlertError(self.provider, fetch)
        return super().verify_fetch(fetch)


def _account_security_reset(fetch: RawFetch) -> bool:
    """Recognize the retained reset notice, never a generic concurrency wall."""

    parsed = urlsplit(str(fetch.final_url))
    if (
        parsed.hostname not in {"ft.com", "www.ft.com"}
        or parsed.path.rstrip("/") != "/barrier/concurrency"
    ):
        return False
    try:
        document = html.fromstring(fetch.raw_html)
    except (ValueError, etree.ParserError):
        return False
    title = " ".join(document.xpath("string(//title)").lower().split())
    for node in document.xpath("//script|//style"):
        node.drop_tree()
    text = " ".join(document.text_content().lower().split())
    return (
        title == "account security"
        and "your password has been reset" in text
        and "you have been signed out" in text
    )


def build_ft_provider(spec: ProviderSpec, verification_url: str | None) -> FTProvider:
    if verification_url is None:
        raise RuntimeError("FT registration requires a verification URL")
    return FTProvider(verification_url=verification_url, spec=spec)


def normalize_content_url(raw: str) -> str | None:
    return normalize_url(load_provider_spec("ft"), raw)


def content_id(url: str) -> str | None:
    return provider_article_id(load_provider_spec("ft"), url)


def _default_verification_url(spec: ProviderSpec) -> str:
    configured = spec.require_session().default_verification_url
    if configured is None:  # pragma: no cover - packaged config invariant
        raise ProviderDefinitionError("FT requires a default verification URL")
    return str(configured)


__all__ = [
    "FTLoginRecipe",
    "FTProvider",
    "build_ft_provider",
    "content_id",
    "normalize_content_url",
]
