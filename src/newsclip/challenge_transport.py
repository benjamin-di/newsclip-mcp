"""One-shot HTTP-to-browser escalation for provider-classified challenges."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress

from .acquisition import (
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
)
from .contracts import HttpClient
from .errors import ProviderDefenseError
from .models import RawFetch, SessionArtifact
from .timing import record_timing_browser_fallback, record_timing_browser_first

ChallengeClassifier = Callable[[RawFetch], bool]


class ChallengeAwareHttpClient:
    """Return the primary GET or one browser fallback without recursion.

    ``on_challenge_observed`` receives the challenged primary response only
    when it is the evidence of an unrecovered request: there is no fallback,
    the fallback raised, or the fallback was challenged too. A challenge the
    browser answers is recorded as the timing operation's browser fallback.

    ``browser_first`` reports a standing rot signal for the primary
    transport. While it holds, the read goes straight to the browser: the
    primary profile was already refused, and asking again only adds a bot
    verdict against this host (R8, 2026-10-12).
    """

    def __init__(
        self,
        provider: str,
        primary: HttpClient,
        *,
        is_challenge: ChallengeClassifier,
        browser_fallback: HttpClient | None,
        on_escalation_served: Callable[[RawFetch], None] | None = None,
        on_challenge_observed: Callable[[RawFetch], None] | None = None,
        browser_first: Callable[[], bool] | None = None,
    ) -> None:
        self._provider = provider
        self._primary = primary
        self._is_challenge = is_challenge
        self._browser_fallback = browser_fallback
        self._on_escalation_served = on_escalation_served
        self._on_challenge_observed = on_challenge_observed
        self._browser_first = browser_first

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        if self._browser_fallback is not None and self._skip_primary():
            with suppress(Exception):
                record_timing_browser_first()
            # No primary fetch exists to hand over: a challenged browser
            # answer fails closed downstream and retains its own evidence,
            # and a served one says nothing new about the refused profile.
            return self._browser_fallback.get(url, session=session, timeout=timeout)
        fetch = self._primary.get(url, session=session, timeout=timeout)
        if not self._is_challenge(fetch):
            return fetch
        if self._browser_fallback is None:
            self._retain_challenge(fetch)
            # A stateless edge challenge with no approved fallback is a
            # defense event, not an operator matter: nothing a person does to
            # the account changes it, and telling callers "operator action
            # required" sent them hunting runbooks (2026-07-28 Reuters
            # audit). Fail closed, honestly retryable.
            raise ProviderDefenseError(
                f"{self._provider} returned an unsupported interactive challenge",
                provider=self._provider,
                fetch=fetch,
                reason_code=MintFailureEvidence(
                    stage=MintFailureStage.CHALLENGE,
                    category=MintFailureCategory.CHALLENGE_BLOCKED,
                ).reason_code,
            )
        # The attempted fallback is the timing signal for every challenge;
        # the challenged primary becomes incident evidence only below, when
        # the browser leg does not recover. Routine challenges answered by
        # the browser must not evict real failures from the bounded
        # per-provider incident store.
        with suppress(Exception):
            record_timing_browser_fallback()
        try:
            served = self._browser_fallback.get(
                url,
                session=session,
                timeout=timeout,
            )
        except Exception:
            # Retained before the caller records the terminal failure, so a
            # missing terminal capture still links the primary response.
            self._retain_challenge(fetch)
            raise
        if self._on_challenge_observed is None and self._on_escalation_served is None:
            return served
        try:
            challenged = self._is_challenge(served)
        except Exception:
            # Unclassifiable is not proof of recovery; keep the evidence.
            challenged = True
        if challenged:
            self._retain_challenge(fetch)
        elif self._on_escalation_served is not None:
            # The browser answering while the primary transport is refused
            # is the rot signal (R8): the provider is serving, the
            # fingerprint is not. A challenged browser leg records nothing —
            # that is the edge deciding what we are, and it fails closed
            # downstream exactly as before. The challenged primary fetch is
            # handed over as the evidence.
            self._on_escalation_served(fetch)
        return served

    def _skip_primary(self) -> bool:
        if self._browser_first is None:
            return False
        try:
            return bool(self._browser_first())
        except Exception:
            # An unreadable signal keeps the declared order.
            return False

    def _retain_challenge(self, fetch: RawFetch) -> None:
        if self._on_challenge_observed is not None:
            with suppress(Exception):
                self._on_challenge_observed(fetch)


__all__ = ["ChallengeAwareHttpClient", "ChallengeClassifier"]
