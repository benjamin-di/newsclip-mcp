"""Dependency boundaries used by the synchronous core."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, Literal, Protocol, Self, runtime_checkable
from uuid import UUID

from .acquisition import CandidateVerificationMode, ChallengeMode, FlowCandidate
from .browser_runtime.runtime import (
    MouseTarget,
    ObservedNavigation,
    PasskeyMode,
    PatchrightMintContext,
)
from .models import (
    ArchiveIntegrity,
    Article,
    ArticleAssessment,
    ExtractedArticle,
    RawFetch,
    SessionArtifact,
    SessionHealth,
    SessionVerification,
)

SecretField = Literal["username", "password", "totp"]


@runtime_checkable
class HttpClient(Protocol):
    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch: ...


@runtime_checkable
class BrowserRetriever(HttpClient, Protocol):
    """A browser transport whose retained runtime has an explicit lifecycle."""

    def release(self) -> None: ...

    def close(self) -> None: ...


HttpClientScopeFactory = Callable[[str], AbstractContextManager[HttpClient]]


@runtime_checkable
class ExtractionEngine(Protocol):
    name: str

    @property
    def version(self) -> str: ...

    def extract(
        self,
        fetch: RawFetch,
        *,
        scope_xpath: tuple[str, ...] | None = None,
    ) -> ExtractedArticle: ...


@runtime_checkable
class BrowserSession(Protocol):
    @property
    def current_url(self) -> str: ...

    def navigate(self, url: str) -> None: ...

    def navigate_loaded(self, url: str, *, timeout_seconds: float) -> None: ...

    def fill(
        self,
        selectors: tuple[str, ...],
        value: str,
        *,
        allowed_origins: frozenset[str] | None = None,
    ) -> None: ...

    def click(self, selectors: tuple[str, ...]) -> None: ...

    def click_optional(self, selectors: tuple[str, ...]) -> bool: ...

    def press(self, selectors: tuple[str, ...], key: str) -> None: ...

    def press_page(self, key: str) -> None: ...

    def wait_for_visible(
        self,
        selectors: tuple[str, ...],
        *,
        timeout_seconds: float = 10,
    ) -> bool: ...

    def suppress_passkeys(self, mode: PasskeyMode) -> bool: ...

    def evaluate(self, expression: str) -> object: ...

    def add_init_script(self, script: str) -> None: ...

    def cookies(self) -> list[dict[str, object]]: ...

    def replace_cookies(self, cookies: list[dict[str, object]]) -> None: ...

    def clear_storage(self) -> None: ...

    def user_agent(self) -> str: ...

    def wait(self, seconds: float) -> None: ...


@runtime_checkable
class AuthBrowserSession(BrowserSession, Protocol):
    """Provider-facing browser authority for authentication acquisition."""

    @property
    def page(self) -> Any: ...

    def navigate_committed(self, url: str, *, timeout_seconds: float) -> None: ...

    def navigate_observed(
        self,
        url: str,
        *,
        timeout_seconds: float,
    ) -> ObservedNavigation: ...

    def replace_page(self) -> None: ...

    def for_page(self, page: Any) -> Self: ...

    def mouse_target(self, selectors: tuple[str, ...]) -> MouseTarget: ...

    def mouse_click(self, target: MouseTarget) -> None: ...

    def native_click(self, selectors: tuple[str, ...]) -> None: ...

    def capture_diagnostic_screenshot(
        self,
        label: str,
        *,
        timeout_ms: int = 5_000,
    ) -> bool: ...

    def dispatch_challenge_action(self, dispatch: Callable[[], Any]) -> Any: ...

    def wait_for_hidden(
        self,
        selectors: tuple[str, ...],
        *,
        timeout_seconds: float = 10,
    ) -> bool: ...


@runtime_checkable
class SecretFiller(Protocol):
    def fill(
        self,
        browser: BrowserSession,
        *,
        secret_ref: str,
        field: SecretField,
        selectors: tuple[str, ...],
        allowed_origins: frozenset[str],
        all_visible: bool = False,
    ) -> None: ...

    def click_matching_choice(
        self,
        browser: BrowserSession,
        *,
        secret_ref: str,
        field: SecretField,
        selectors: tuple[str, ...],
        excluded_text: tuple[str, ...],
        allowed_origins: frozenset[str],
    ) -> bool: ...


@runtime_checkable
class LoginRecipe(Protocol):
    provider: str
    candidate_verification_mode: CandidateVerificationMode
    allowed_origins: frozenset[str]
    allowed_cookie_domains: frozenset[str]
    secret_ref: str
    verification_url: str

    def verify(
        self, http: HttpClient, artifact: SessionArtifact
    ) -> SessionVerification: ...

    def verify_fetch(self, fetch: RawFetch) -> SessionVerification: ...


@runtime_checkable
class BrowserProfileAccess(Protocol):
    """Core-owned path and launch access for persistent browser profiles."""

    def path(
        self, provider: str, account_key: str, *, profile_id: UUID | None = None
    ) -> Path: ...

    def open(
        self,
        provider: str,
        account_key: str,
        *,
        require_virtual_display: bool,
        profile_id: UUID | None = None,
    ) -> AbstractContextManager[PatchrightMintContext]: ...


@runtime_checkable
class SessionAcquisitionAdapter(Protocol):
    provider: str

    def rehydrate_profile(
        self,
        browser: AuthBrowserSession,
        *,
        account_key: str,
        challenge_mode: ChallengeMode,
    ) -> FlowCandidate | None: ...

    def mint_credentials(
        self,
        browser: AuthBrowserSession,
        *,
        account_key: str,
        challenge_mode: ChallengeMode,
    ) -> FlowCandidate: ...


@runtime_checkable
class SessionSource(Protocol):
    def status(self, provider: str, account_key: str = "default") -> SessionHealth: ...

    def mark_account_alert(
        self,
        provider: str,
        account_key: str = "default",
        *,
        generation_id: UUID | None = None,
    ) -> None: ...

    def get_valid_session(
        self, provider: str, account_key: str = "default"
    ) -> SessionArtifact: ...

    def mark_required(
        self,
        provider: str,
        account_key: str = "default",
        *,
        generation_id: UUID | None = None,
    ) -> None: ...


@runtime_checkable
class SessionManager(SessionSource, Protocol):
    def explicit_login(
        self,
        provider: str,
        *,
        headless: bool = False,
        challenge_mode: ChallengeMode = ChallengeMode.DETECT_ONLY,
        account_key: str = "default",
        before_browser: Callable[[], None] | None = None,
        allow_credential_mint: bool = True,
    ): ...

    def reset_browser_profile(
        self, provider: str, account_key: str = "default"
    ) -> None: ...

    def import_cookies(
        self,
        provider: str,
        payload: object,
        *,
        account_key: str = "default",
    ) -> SessionArtifact: ...

    def reset(self, provider: str, account_key: str = "default") -> None: ...

    def clear(self, provider: str, account_key: str = "default") -> None: ...

    def acknowledge(self, provider: str, account_key: str = "default") -> None: ...


@runtime_checkable
class Archive(Protocol):
    path: Path

    def save(
        self,
        provider_key: str,
        article: Article | None,
        fetch: RawFetch,
        assessment: ArticleAssessment,
        extraction: ExtractedArticle,
    ) -> Article | None: ...

    def get(self, article_id: str) -> Article: ...

    def search(
        self,
        query: str,
        *,
        provider: str | None = None,
        limit: int | None = None,
    ) -> list[Article]: ...

    def reextract(self, article_id: str) -> Article: ...

    def export_markdown(self, article: Article, path: Path) -> Path: ...

    def rebuild_fts(self) -> None: ...

    def integrity_check(self) -> ArchiveIntegrity: ...

    def backup(self, destination: Path) -> Path: ...

    def restore(self, source: Path) -> None: ...

    def current_raw_snapshots(
        self, *, provider: str | None = None
    ) -> list[tuple[str, str, RawFetch, ArticleAssessment]]: ...
