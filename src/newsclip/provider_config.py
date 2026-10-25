"""Strict, trusted configuration for built-in news providers."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from functools import cache
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from lxml import etree
from pydantic import Field, HttpUrl, field_validator, model_validator
from signin_window.automation.auth import AuthObservationSpec as AuthObservationSpec

from .acquisition import CandidateVerificationMode
from .models import (
    DEFAULT_HTTP_IMPERSONATION,
    FrozenModel,
    ProviderCapabilities,
    RateBudget,
)
from .provider_keys import PROVIDER_KEY_PATTERN, is_provider_key

NegativeRuleKind = Literal["challenge", "authentication", "paywall"]
BrowserResourceType = Literal[
    "document",
    "stylesheet",
    "image",
    "media",
    "font",
    "script",
    "texttrack",
    "xhr",
    "fetch",
    "eventsource",
    "websocket",
    "manifest",
    "ping",
    "cspreport",
    "other",
]

_STRUCTURAL_SIGNALS = {
    "newsarticle_jsonld",
    "jsonld_headline",
    "jsonld_absent",
    "jsonld_non_article",
    "jsonld_malformed",
    "article_body_structure",
    "page_headline",
    "markdown_body",
    "extracted_headline",
}
_JSONLD_STATE_SIGNALS = {"jsonld_absent", "jsonld_non_article", "jsonld_malformed"}

_DEFINITION_ROOT = Path(__file__).with_name("provider_definitions")
_ENVIRONMENT_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
_HOST_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_XPATH_NODE_PROBE = etree.XML(
    b"<html data-probe='value'><head><title>probe</title></head>"
    b"<body><main><article><p>probe</p><a href='/probe'>probe</a>"
    b"</article></main></body></html>"
)


class ProviderDefinitionError(RuntimeError):
    """A packaged provider definition is invalid or cannot be loaded."""


def _validated_xpaths(values: tuple[str, ...]) -> tuple[str, ...]:
    for expression in values:
        try:
            etree.XPath(expression)
        except etree.XPathSyntaxError as error:
            raise ValueError(f"invalid XPath expression: {expression!r}") from error
    return values


def _validated_node_xpaths(values: tuple[str, ...]) -> tuple[str, ...]:
    """Validate XPath expressions whose contract is to select elements."""

    _validated_xpaths(values)
    for expression in values:
        try:
            result = etree.XPath(expression)(_XPATH_NODE_PROBE)
        except etree.XPathError as error:
            raise ValueError(f"invalid XPath expression: {expression!r}") from error
        if not isinstance(result, list):
            raise ValueError(f"element XPath must return a node-set: {expression!r}")
        if any(not isinstance(item, etree._Element) for item in result):
            raise ValueError(f"element XPath must select elements: {expression!r}")
    return values


def _valid_hostname(value: str) -> bool:
    return bool(_HOST_PATTERN.fullmatch(value))


def _all_nonblank(values: tuple[str, ...]) -> bool:
    return all(value.strip() for value in values)


class IdentitySpec(FrozenModel):
    allowed_hosts: tuple[str, ...] = Field(min_length=1)
    canonical_host: str = Field(min_length=1)
    path_pattern: str = Field(min_length=1)
    canonical_path: str | None = None
    lowercase_groups: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_identity(self) -> IdentitySpec:
        if len(set(self.allowed_hosts)) != len(self.allowed_hosts):
            raise ValueError("identity hosts must be unique")
        if self.canonical_host not in self.allowed_hosts:
            raise ValueError("canonical host must be an allowed host")
        if any(
            host != host.lower() or not _valid_hostname(host)
            for host in self.allowed_hosts
        ):
            raise ValueError("identity hosts must be lowercase hostnames")
        try:
            pattern = re.compile(self.path_pattern)
        except re.error as error:
            raise ValueError("invalid article path pattern") from error
        if "id" not in pattern.groupindex:
            raise ValueError("article path pattern must define a named 'id' group")
        missing = set(self.lowercase_groups) - set(pattern.groupindex)
        if missing:
            raise ValueError("lowercase groups must exist in the article pattern")
        if self.canonical_path is not None:
            fields = set(
                re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", self.canonical_path)
            )
            if not fields.issubset(pattern.groupindex):
                raise ValueError("canonical path references an unknown capture group")
        return self


class EmbeddedPublishedSpec(FrozenModel):
    script_id: str = Field(min_length=1)
    url_field: str = Field(min_length=1)
    value_field: str = Field(min_length=1)


class ResponseRetrySpec(FrozenModel):
    status_code: int = Field(ge=400, le=599)
    title_equals: str = Field(min_length=1)
    required_xpath: str = Field(min_length=1)

    @field_validator("title_equals")
    @classmethod
    def normalize_title(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("response retry title cannot be blank")
        return normalized

    @field_validator("required_xpath")
    @classmethod
    def validate_required_xpath(cls, value: str) -> str:
        _validated_node_xpaths((value,))
        return value


class HtmlSearchSpec(FrozenModel):
    kind: Literal["html"] = "html"
    endpoint: HttpUrl
    query_parameter: str = Field(min_length=1)
    result_xpath: tuple[str, ...] = Field(min_length=1)
    href_attribute: str = "href"
    rejected_headline_prefixes: tuple[str, ...] = ()
    empty_result_xpath: tuple[str, ...] = Field(min_length=1)
    next_href_xpath: tuple[str, ...] = ()
    page_parameter: str | None = None
    published_container_xpath: str = "ancestor-or-self::*[self::article or self::li][1]"
    published_value_xpath: str = (
        ".//time[@datetime][1]/@datetime | .//*[@itemprop='datePublished'][1]/@content"
    )
    embedded_published: EmbeddedPublishedSpec | None = None
    published_date_identity_group: str | None = Field(
        default=None,
        pattern=r"^[a-zA-Z_][a-zA-Z0-9_]*$",
    )
    published_date_format: Literal["%Y-%m-%d", "%Y/%m/%d"] = "%Y-%m-%d"
    missing_published_fetch_limit: int = Field(default=0, ge=0, le=10)

    @field_validator("result_xpath", "empty_result_xpath", "next_href_xpath")
    @classmethod
    def validate_xpath_groups(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validated_node_xpaths(value)

    @field_validator("published_container_xpath")
    @classmethod
    def validate_node_xpath(cls, value: str) -> str:
        _validated_node_xpaths((value,))
        return value

    @field_validator("published_value_xpath")
    @classmethod
    def validate_value_xpath(cls, value: str) -> str:
        _validated_xpaths((value,))
        return value

    @model_validator(mode="after")
    def validate_search_attributes(self) -> HtmlSearchSpec:
        if (
            not self.query_parameter.strip()
            or not self.href_attribute.strip()
            or (self.page_parameter is not None and not self.page_parameter.strip())
        ):
            raise ValueError("search attributes cannot be blank")
        if not _all_nonblank(self.rejected_headline_prefixes):
            raise ValueError("search text evidence cannot be blank")
        if bool(self.next_href_xpath) != (self.page_parameter is not None):
            raise ValueError(
                "search next-link XPath and page parameter must be configured together"
            )
        if (
            self.published_date_identity_group is None
            and self.published_date_format != "%Y-%m-%d"
        ):
            raise ValueError(
                "custom publication date format requires an identity group"
            )
        return self


class AdapterSearchSpec(FrozenModel):
    kind: Literal["adapter"]
    endpoint: HttpUrl
    api_key_ref: str | None = None

    @model_validator(mode="after")
    def validate_api_key_ref(self) -> AdapterSearchSpec:
        if self.api_key_ref is not None and (
            not self.api_key_ref.startswith("op://")
            or any(marker in self.api_key_ref for marker in ("\r", "\n", "{{", "}}"))
        ):
            raise ValueError("search API key reference must use op://")
        return self


SearchSpec = Annotated[
    HtmlSearchSpec | AdapterSearchSpec,
    Field(discriminator="kind"),
]


class ProviderCheckSpec(FrozenModel):
    query: str = Field(min_length=1, max_length=256)
    canonical_url: HttpUrl
    require_canonical_result: bool = True
    # A parsed rolling feed may have coverage but no matches for today's query.
    allow_empty_search: bool = False

    @field_validator("query")
    @classmethod
    def normalize_query(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("provider-check query cannot be blank")
        return normalized


class NegativeRuleSpec(FrozenModel):
    kind: NegativeRuleKind
    final_urls: tuple[str, ...] = ()
    final_url_hosts: tuple[str, ...] = ()
    final_url_paths: tuple[str, ...] = ()
    final_url_path_prefixes: tuple[str, ...] = ()
    title_equals: tuple[str, ...] = ()
    xpath_any: tuple[str, ...] = ()
    text_any: tuple[str, ...] = ()

    @field_validator("xpath_any")
    @classmethod
    def validate_xpaths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validated_node_xpaths(value)

    @model_validator(mode="after")
    def require_evidence(self) -> NegativeRuleSpec:
        if not any(
            (
                self.final_url_hosts,
                self.final_urls,
                self.final_url_paths,
                self.final_url_path_prefixes,
                self.title_equals,
                self.xpath_any,
                self.text_any,
            )
        ):
            raise ValueError("negative rule must contain evidence")
        values = (
            self.final_urls
            + self.final_url_hosts
            + self.final_url_paths
            + self.final_url_path_prefixes
            + self.title_equals
            + self.text_any
        )
        if not _all_nonblank(values):
            raise ValueError("negative rule evidence cannot be blank")
        if any(
            host != host.lower() or not _valid_hostname(host)
            for host in self.final_url_hosts
        ):
            raise ValueError("negative rule hosts must be lowercase hostnames")
        if any(
            not path.startswith("/")
            for path in self.final_url_paths + self.final_url_path_prefixes
        ):
            raise ValueError("negative rule paths must begin with a slash")
        for url in self.final_urls:
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
                or parsed.port not in {None, 443}
            ):
                raise ValueError("negative rule URLs must be canonical HTTPS URLs")
        return self


class ParagraphFloorSpec(FrozenModel):
    root_xpath: str
    paragraph_xpath: str = ".//p"
    preferred_root_xpath: str | None = None
    minimum_count: int = Field(ge=1)
    minimum_substantial_count: int = Field(ge=1)
    substantial_minimum_characters: int = Field(ge=1)

    @field_validator("root_xpath", "paragraph_xpath")
    @classmethod
    def validate_xpath(cls, value: str) -> str:
        _validated_node_xpaths((value,))
        return value

    @field_validator("preferred_root_xpath")
    @classmethod
    def validate_optional_xpath(cls, value: str | None) -> str | None:
        if value is not None:
            _validated_node_xpaths((value,))
        return value

    @model_validator(mode="after")
    def validate_counts(self) -> ParagraphFloorSpec:
        if self.minimum_substantial_count > self.minimum_count:
            raise ValueError("substantial paragraph count cannot exceed total count")
        return self


class AssessmentSpec(FrozenModel):
    canonical_signal: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    negative_rules: tuple[NegativeRuleSpec, ...]
    article_xpath: tuple[str, ...] = Field(min_length=1)
    page_headline_xpath: tuple[str, ...] = ()
    record_jsonld_state: bool = False
    required_signals: tuple[str, ...] = Field(min_length=1)
    metadata_alternatives: tuple[tuple[str, ...], ...] = ()
    minimum_words: int | None = Field(default=None, ge=1)
    # The rendered floor and the provider-native payload floor answer different
    # questions. ``minimum_words`` bounds a *rendered* body, where a paywall
    # teaser and a complete article differ mainly by size. A native payload is
    # delivered whole or not at all, even beside a rendered teaser, so its floor only
    # has to reject a thin stub, and reusing the rendered number there rejects
    # complete short wire stories. Unset keeps the single shared floor.
    story_minimum_words: int | None = Field(default=None, ge=1)
    paragraph_floor: ParagraphFloorSpec | None = None

    @property
    def effective_story_minimum_words(self) -> int | None:
        """Return the payload floor, falling back to the rendered floor."""

        if self.story_minimum_words is not None:
            return self.story_minimum_words
        return self.minimum_words

    @field_validator("article_xpath", "page_headline_xpath")
    @classmethod
    def validate_xpaths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validated_node_xpaths(value)

    @model_validator(mode="after")
    def validate_signals(self) -> AssessmentSpec:
        if self.canonical_signal in _STRUCTURAL_SIGNALS:
            raise ValueError("canonical signal must not shadow a structural signal")
        known = _STRUCTURAL_SIGNALS | {self.canonical_signal}
        configured = set(self.required_signals)
        configured.update(
            signal
            for alternative in self.metadata_alternatives
            for signal in alternative
        )
        unknown = configured - known
        if unknown:
            raise ValueError(
                f"assessment references unknown signals: {sorted(unknown)}"
            )
        if len(set(self.required_signals)) != len(self.required_signals):
            raise ValueError("required assessment signals must be unique")
        if any(not alternative for alternative in self.metadata_alternatives):
            raise ValueError("metadata alternatives cannot be empty")
        if "page_headline" in configured and not self.page_headline_xpath:
            raise ValueError("page_headline requires a configured XPath")
        if configured & _JSONLD_STATE_SIGNALS and not self.record_jsonld_state:
            raise ValueError("JSON-LD state signals require state recording")
        if self.minimum_words is None and self.paragraph_floor is not None:
            raise ValueError("paragraph floors require a word floor")
        if self.minimum_words is not None and self.paragraph_floor is None:
            raise ValueError("word floors require paragraph floors")
        if self.story_minimum_words is not None:
            if self.minimum_words is None:
                raise ValueError("a story word floor requires a rendered word floor")
            if self.story_minimum_words > self.minimum_words:
                raise ValueError(
                    "the story word floor cannot exceed the rendered word floor"
                )
        return self


class ExtractionSpec(FrozenModel):
    """Bound body extraction to a provider-declared subtree.

    Extraction is otherwise the one provider-blind stage in a pipeline whose
    assessment, identity, search, and challenge policy are all spec-driven, so
    it reads whatever the page hands it. Reuters wraps a related-story rail in
    ``div[data-testid=MediaStoryCard]`` *outside* the page's single
    ``<article>``, and trafilatura pulls a rotating foreign teaser paragraph
    from it into the verified body — cross-article bleed that also makes word
    counts drift for byte-stable content.

    This is deliberately separate from ``assessment.article_xpath`` even though
    both are ``//article`` for Reuters today: one selects evidence that a page
    *is* an article, the other selects which bytes may become its body. They are
    free to diverge as provider markup does.

    The scope is an allowlist rather than a prune denylist. Both produce
    identical output on the audited pages, but a denylist fails open when the
    provider ships a new module, while an allowlist fails closed.
    """

    scope_xpath: tuple[str, ...] = Field(min_length=1)

    @field_validator("scope_xpath")
    @classmethod
    def validate_xpaths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validated_node_xpaths(value)


class SessionSpec(FrozenModel):
    allowed_origins: tuple[str, ...] = Field(min_length=1)
    allowed_cookie_domains: tuple[str, ...] = Field(min_length=1)
    secret_ref: str = ""
    session_cookie_name_prefixes: tuple[str, ...] = ()
    verification_minimum_words: int | None = Field(default=None, ge=1, le=10_000)
    candidate_verification_mode: CandidateVerificationMode = (
        CandidateVerificationMode.HTTP_PROBE
    )
    default_verification_url: HttpUrl | None = None
    verification_url_environment: str | None = None

    @model_validator(mode="after")
    def validate_session(self) -> SessionSpec:
        if (self.default_verification_url is None) == (
            self.verification_url_environment is None
        ):
            raise ValueError("session requires exactly one verification URL source")
        for origin in self.allowed_origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
                or parsed.port not in {None, 443}
            ):
                raise ValueError("allowed origins must be HTTPS origins")
        if len(set(self.allowed_origins)) != len(self.allowed_origins):
            raise ValueError("allowed origins must be unique")
        if any(
            domain != domain.lower() or not _valid_hostname(domain)
            for domain in self.allowed_cookie_domains
        ):
            raise ValueError("cookie domains must be lowercase hostnames")
        if len(set(self.allowed_cookie_domains)) != len(self.allowed_cookie_domains):
            raise ValueError("cookie domains must be unique")
        if self.secret_ref and not self.secret_ref.startswith("op://"):
            raise ValueError("session secret reference must use op://")
        if any(
            not prefix.strip() or prefix != prefix.lower()
            for prefix in self.session_cookie_name_prefixes
        ):
            raise ValueError(
                "session cookie prefixes must be nonblank lowercase values"
            )
        if (
            self.verification_url_environment is not None
            and not _ENVIRONMENT_PATTERN.fullmatch(self.verification_url_environment)
        ):
            raise ValueError("invalid verification URL environment name")
        return self


class BrowserSemanticReadinessSpec(FrozenModel):
    """Bounded same-document stabilization using the provider's assessment."""

    timeout_seconds: float = Field(gt=0, le=30)
    stable_seconds: float = Field(default=0.25, gt=0, le=5)
    poll_seconds: float = Field(default=0.05, gt=0, le=1)

    @model_validator(mode="after")
    def validate_intervals(self) -> BrowserSemanticReadinessSpec:
        if self.stable_seconds > self.timeout_seconds:
            raise ValueError("semantic stability cannot exceed its timeout")
        if self.poll_seconds > self.stable_seconds:
            raise ValueError("semantic poll interval cannot exceed stability interval")
        return self


class BrowserRetrievalSpec(FrozenModel):
    """Provider-owned browser hydration without provider logic in the plane."""

    warmup_urls: tuple[HttpUrl, ...] = ()
    recovery_warmup_urls: tuple[HttpUrl, ...] = ()
    warmup_settle_seconds: float = Field(default=0, ge=0, le=30)
    article_settle_seconds: float = Field(default=0, ge=0, le=30)
    network_idle_timeout_seconds: float = Field(default=0, ge=0, le=30)
    navigation_wait_until: Literal["commit", "domcontentloaded", "load"] = (
        "domcontentloaded"
    )
    ready_selectors: tuple[str, ...] = ()
    ready_timeout_seconds: float = Field(default=5, ge=0, le=30)
    semantic_readiness: BrowserSemanticReadinessSpec | None = None
    block_resource_types: tuple[BrowserResourceType, ...] = ()

    @field_validator("ready_selectors", "block_resource_types")
    @classmethod
    def _nonblank_browser_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(item.strip() for item in value if item and item.strip())
        if len(cleaned) != len(value):
            raise ValueError("browser retrieval entries cannot be blank")
        return cleaned

    @model_validator(mode="after")
    def _readiness_selectors_require_timeout(self) -> BrowserRetrievalSpec:
        if self.ready_selectors and self.ready_timeout_seconds <= 0:
            raise ValueError("browser readiness selectors require a positive timeout")
        if not self.ready_selectors and self.ready_timeout_seconds not in (0, 5):
            raise ValueError("browser readiness timeout requires selectors")
        return self

    @property
    def configured(self) -> bool:
        return bool(
            self.warmup_urls
            or self.recovery_warmup_urls
            or self.warmup_settle_seconds
            or self.article_settle_seconds
            or self.network_idle_timeout_seconds
            or self.navigation_wait_until != "domcontentloaded"
            or self.ready_selectors
            or self.semantic_readiness is not None
            or self.block_resource_types
        )


class BrowserLaunchSpec(FrozenModel):
    locale: str
    timezone_id: str
    accept_language: str
    args: tuple[str, ...] = ()

    @model_validator(mode="after")
    def require_nonblank_values(self) -> BrowserLaunchSpec:
        if not all(
            value.strip()
            for value in (self.locale, self.timezone_id, self.accept_language)
        ) or not _all_nonblank(self.args):
            raise ValueError("browser launch values cannot be blank")
        return self


class TokenProbeSpec(FrozenModel):
    password_form_selector: str
    response_field_selector: str
    widget_selector: str

    @model_validator(mode="after")
    def require_nonblank_selectors(self) -> TokenProbeSpec:
        if not all(
            value.strip()
            for value in (
                self.password_form_selector,
                self.response_field_selector,
                self.widget_selector,
            )
        ):
            raise ValueError("token probe selectors cannot be blank")
        return self


class AuthSpec(FrozenModel):
    login_url: HttpUrl
    auth_path_prefixes: tuple[str, ...] = ()
    identity_hosts: tuple[str, ...] = ()
    post_callback_urls: tuple[HttpUrl, ...] = ()
    launch: BrowserLaunchSpec
    controls: dict[str, tuple[str, ...]]
    observations: dict[str, AuthObservationSpec]
    token_probe: TokenProbeSpec | None = None

    @model_validator(mode="after")
    def validate_generic_surface(self) -> AuthSpec:
        if any(
            not prefix.startswith("/") or not prefix.strip()
            for prefix in self.auth_path_prefixes
        ):
            raise ValueError("authentication path prefixes must begin with a slash")
        if len(set(self.identity_hosts)) != len(self.identity_hosts):
            raise ValueError("authentication identity hosts must be unique")
        if any(
            host != host.lower() or not _valid_hostname(host)
            for host in self.identity_hosts
        ):
            raise ValueError(
                "authentication identity hosts must be lowercase hostnames"
            )
        if any(
            not selectors or any(not selector.strip() for selector in selectors)
            for selectors in self.controls.values()
        ):
            raise ValueError("auth controls cannot have empty selector lists")
        return self

    def control(self, name: str) -> tuple[str, ...]:
        try:
            return self.controls[name]
        except KeyError as error:  # pragma: no cover - guarded by schema validation
            raise ProviderDefinitionError(f"unknown auth control: {name}") from error


def validate_auth_surface(
    auth: AuthSpec,
    *,
    expected_controls: set[str] | frozenset[str],
    required_observations: set[str] | frozenset[str],
    token_probe: Literal["required", "forbidden"],
    require_auth_paths: bool = False,
) -> None:
    """Validate exact provider-owned IDs without redispatching by strategy."""

    controls = set(auth.controls)
    observations = set(auth.observations)
    missing_controls = expected_controls - controls
    unknown_controls = controls - expected_controls
    missing_observations = required_observations - observations
    unknown_observations = observations - required_observations
    if missing_controls:
        raise ValueError(
            f"authentication surface is missing controls: {sorted(missing_controls)}"
        )
    if unknown_controls:
        raise ValueError(
            f"authentication surface has unknown controls: {sorted(unknown_controls)}"
        )
    if missing_observations:
        raise ValueError(
            "authentication surface is missing observations: "
            f"{sorted(missing_observations)}"
        )
    if unknown_observations:
        raise ValueError(
            "authentication surface has unknown observations: "
            f"{sorted(unknown_observations)}"
        )
    if token_probe == "required" and auth.token_probe is None:
        raise ValueError("authentication surface requires token probe selectors")
    if token_probe == "forbidden" and auth.token_probe is not None:
        raise ValueError("authentication surface forbids token probe selectors")
    if require_auth_paths and not auth.auth_path_prefixes:
        raise ValueError("authentication surface requires callback path prefixes")


class ProviderSpec(FrozenModel):
    schema_version: Literal[1] = 1
    key: str = Field(pattern=PROVIDER_KEY_PATTERN)
    order: int = Field(ge=0)
    enabled_by_default: bool = False
    enable_environment: str | None = None
    capabilities: ProviderCapabilities
    rate_budget: RateBudget
    response_retry: ResponseRetrySpec | None = None
    identity: IdentitySpec
    search: SearchSpec
    check: ProviderCheckSpec
    assessment: AssessmentSpec
    extraction: ExtractionSpec | None = None
    session: SessionSpec | None = None
    browser_retrieval: BrowserRetrievalSpec = BrowserRetrievalSpec()
    auth: AuthSpec | None = None

    @model_validator(mode="before")
    @classmethod
    def default_legacy_search_kind(cls, raw: object) -> object:
        if not isinstance(raw, dict):
            return raw
        search = raw.get("search")
        if not isinstance(search, dict) or "kind" in search:
            return raw
        compatible = dict(raw)
        compatible["search"] = {"kind": "html", **search}
        return compatible

    @model_validator(mode="after")
    def validate_provider(self) -> ProviderSpec:
        if self.enable_environment is not None and not _ENVIRONMENT_PATTERN.fullmatch(
            self.enable_environment
        ):
            raise ValueError("invalid provider enablement environment name")
        if (
            self.capabilities.retrieval_challenge_escalation == "browser"
            and self.capabilities.retrieval_transport != "http"
        ):
            raise ValueError(
                "challenge escalation is a fallback for HTTP retrieval only"
            )
        anonymous = self.capabilities.session_kind == "none"
        if anonymous:
            if self.session is not None or self.auth is not None:
                raise ValueError(
                    "anonymous providers must not configure session or auth"
                )
            if (
                self.capabilities.requires_session_for_retrieve
                or self.capabilities.requires_session_for_search
            ):
                raise ValueError("anonymous providers cannot require a session")
            if (
                self.capabilities.retrieval_transport != "http"
                or self.capabilities.search_transport != "http"
            ):
                raise ValueError(
                    "anonymous providers currently require HTTP transports"
                )
        else:
            if self.session is None or self.auth is None:
                raise ValueError(
                    "session providers require session and auth configuration"
                )
            # A session-bearing route keeps the default profile so its TLS
            # fingerprint stays a browser the stored artifact could have come
            # from. Configuring one here would be silently ignored, so reject
            # it rather than imply a repair that cannot take effect; the
            # repair for an aged default is DEFAULT_HTTP_IMPERSONATION itself.
            if self.capabilities.http_impersonate != DEFAULT_HTTP_IMPERSONATION:
                raise ValueError(
                    "session providers cannot select an HTTP impersonation profile"
                )
        session = self.session
        auth = self.auth
        if (
            self.enabled_by_default
            and session is not None
            and session.default_verification_url is None
        ):
            raise ValueError(
                "default-enabled providers need a default verification URL"
            )
        if not self.enabled_by_default and self.enable_environment is None:
            raise ValueError("opt-in providers need an enablement environment")
        endpoint_host = (urlsplit(str(self.search.endpoint)).hostname or "").lower()
        parsed_endpoint = urlsplit(str(self.search.endpoint))
        if (
            parsed_endpoint.scheme != "https"
            or parsed_endpoint.query
            or parsed_endpoint.fragment
            or parsed_endpoint.username
            or parsed_endpoint.password
            or parsed_endpoint.port not in {None, 443}
        ):
            raise ValueError("search endpoint must be a canonical HTTPS URL")
        if (
            isinstance(self.search, HtmlSearchSpec)
            and endpoint_host not in self.identity.allowed_hosts
        ):
            raise ValueError("search endpoint must use an allowed provider host")
        parsed_check_url = urlsplit(str(self.check.canonical_url))
        check_path = parsed_check_url.path.rstrip("/") or "/"
        if (
            parsed_check_url.scheme != "https"
            or (parsed_check_url.hostname or "").lower()
            not in self.identity.allowed_hosts
            or parsed_check_url.query
            or parsed_check_url.fragment
            or parsed_check_url.username
            or parsed_check_url.password
            or parsed_check_url.port not in {None, 443}
            or re.fullmatch(self.identity.path_pattern, check_path) is None
        ):
            raise ValueError(
                "provider-check URL must identify a canonical provider article"
            )
        published_group = (
            self.search.published_date_identity_group
            if isinstance(self.search, HtmlSearchSpec)
            else None
        )
        if (
            published_group is not None
            and published_group not in re.compile(self.identity.path_pattern).groupindex
        ):
            raise ValueError(
                "published date identity group must exist in the article path pattern"
            )
        login_origin = _origin(str(auth.login_url)) if auth is not None else None
        if session is not None and login_origin not in session.allowed_origins:
            raise ValueError("login URL origin must be allowed for secret delivery")
        for callback_url in auth.post_callback_urls if auth is not None else ():
            parsed_callback = urlsplit(str(callback_url))
            if (
                parsed_callback.scheme != "https"
                or (parsed_callback.hostname or "").lower()
                not in self.identity.allowed_hosts
                or parsed_callback.query
                or parsed_callback.fragment
                or parsed_callback.username
                or parsed_callback.password
                or parsed_callback.port not in {None, 443}
            ):
                raise ValueError(
                    "post-callback URLs must use canonical provider HTTPS URLs"
                )
        if session is not None and session.default_verification_url is not None:
            parsed_verification = urlsplit(str(session.default_verification_url))
            verification_host = (parsed_verification.hostname or "").lower()
            if verification_host not in self.identity.allowed_hosts:
                raise ValueError("default verification URL must use an article host")
            verification_path = parsed_verification.path.rstrip("/") or "/"
            if re.fullmatch(self.identity.path_pattern, verification_path) is None:
                raise ValueError("default verification URL must identify an article")
        if (
            self.browser_retrieval.configured
            and self.capabilities.retrieval_transport != "browser"
        ):
            raise ValueError("browser retrieval policy requires browser transport")
        for warmup_url in (
            self.browser_retrieval.warmup_urls
            + self.browser_retrieval.recovery_warmup_urls
        ):
            parsed_warmup = urlsplit(str(warmup_url))
            if (
                parsed_warmup.scheme != "https"
                or (parsed_warmup.hostname or "").lower()
                not in self.identity.allowed_hosts
                or parsed_warmup.query
                or parsed_warmup.fragment
                or parsed_warmup.username
                or parsed_warmup.password
                or parsed_warmup.port not in {None, 443}
            ):
                raise ValueError(
                    "browser warm-up URLs must use canonical provider HTTPS URLs"
                )
        return self

    def assessment_policy_version(self, engine_revision: str) -> str:
        if not re.fullmatch(r"^[a-z0-9][a-z0-9._-]{0,63}$", engine_revision):
            raise ValueError("invalid assessment engine revision")
        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "engine_revision": engine_revision,
            "key": self.key,
            "identity": self.identity,
            "assessment": self.assessment,
        }
        # An extraction scope changes the stored body, so it belongs in the
        # identity that keys archived extraction rows. The key is added only
        # when a scope is configured, so every provider without one keeps its
        # existing hash and no archive churns for a change it did not receive.
        if self.extraction is not None:
            payload["extraction"] = self.extraction
        digest = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
        return f"{self.key}-cfg-{digest[:12]}"

    def require_session(self) -> SessionSpec:
        if self.session is None:
            raise ProviderDefinitionError(f"{self.key} has no session configuration")
        return self.session

    def require_html_search(self) -> HtmlSearchSpec:
        if not isinstance(self.search, HtmlSearchSpec):
            raise ProviderDefinitionError(f"{self.key} does not use HTML search")
        return self.search

    def require_adapter_search(self) -> AdapterSearchSpec:
        if not isinstance(self.search, AdapterSearchSpec):
            raise ProviderDefinitionError(f"{self.key} does not use adapter search")
        return self.search

    def require_auth(self) -> AuthSpec:
        if self.auth is None:
            raise ProviderDefinitionError(
                f"{self.key} has no authentication configuration"
            )
        return self.auth


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port not in {None, 443} else ""
    return f"{parsed.scheme}://{host}{port}"


def _canonical_json(value: object) -> str:
    def normalize(item: object) -> object:
        if isinstance(item, FrozenModel):
            return normalize(item.model_dump(mode="python"))
        if isinstance(item, dict):
            return {str(key): normalize(item[key]) for key in sorted(item)}
        if isinstance(item, (list, tuple)):
            return [normalize(element) for element in item]
        if isinstance(item, (set, frozenset)):
            normalized = [normalize(element) for element in item]
            return sorted(
                normalized,
                key=lambda element: json.dumps(element, sort_keys=True, default=str),
            )
        if isinstance(item, HttpUrl):
            return str(item)
        return item

    return json.dumps(normalize(value), sort_keys=True, separators=(",", ":"))


@cache
def _load_provider_spec(key: str) -> ProviderSpec:
    if not is_provider_key(key):
        raise ProviderDefinitionError("invalid provider definition key")
    path = _DEFINITION_ROOT / f"{key}.toml"
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
        spec = ProviderSpec.model_validate(payload)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
        raise ProviderDefinitionError(f"invalid provider definition: {key}") from error
    if spec.key != key:
        raise ProviderDefinitionError("provider definition filename/key mismatch")
    return spec


def load_provider_spec(key: str) -> ProviderSpec:
    from .maintenance import provider_settings

    base = _load_provider_spec(key)
    configured = ProviderSpec.model_validate(
        provider_settings(key, base.model_dump(mode="json"))
    )
    # Account settings affect authority, never the cached site/auth definition.
    return base.model_copy(
        update={"session": configured.session, "search": configured.search}
    )


def load_builtin_provider_specs() -> tuple[ProviderSpec, ...]:
    try:
        keys = tuple(path.stem for path in _DEFINITION_ROOT.glob("*.toml"))
    except OSError as error:  # pragma: no cover - installation corruption
        raise ProviderDefinitionError("provider definitions are unavailable") from error
    specs = tuple(
        sorted((load_provider_spec(key) for key in keys), key=lambda item: item.order)
    )
    if not specs:
        raise ProviderDefinitionError("no provider definitions are installed")
    if len({spec.key for spec in specs}) != len(specs):
        raise ProviderDefinitionError("provider definition keys must be unique")
    if len({spec.order for spec in specs}) != len(specs):
        raise ProviderDefinitionError("provider definition order values must be unique")
    return specs
