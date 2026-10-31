"""Small in-process provider rate and idempotent-GET retry policy."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Literal

from .browser_runtime.events import HttpOperationRole, HttpRetryReason
from .contracts import HttpClient
from .errors import ProviderDefenseError, ProviderTransportError, TransportFailure
from .http import http_attempt_context
from .models import RateBudget, RawFetch, SessionArtifact

Clock = Callable[[], float]
Sleeper = Callable[[float], None]
ResponseRetry = Callable[[RawFetch], bool]
_RETRYABLE_STATUS = {502, 503, 504}
#: Longest provider-sent ``Retry-After`` the limiter honors. The header is
#: provider-controlled and unbounded (an HTTP date can name tomorrow); honoring
#: it verbatim would refuse the provider for the life of the long-lived MCP
#: process. A minute covers every throttle window observed in practice, and a
#: provider that is still refusing afterwards answers 429 again and re-defers.
#: A configured ``rate_limit_fallback_seconds`` is operator-declared and
#: already bounded by the model, so it is not capped here.
MAX_RETRY_AFTER_DEFER_SECONDS = 60.0
#: Longest a request waits in-process for an active 429 deferral. Short
#: deferrals (the declared FT fallback is 5 s) still wait and proceed; a longer
#: one fails fast as ``rate_limited`` instead of parking one of the MCP
#: server's few worker threads until the provider relents.
MAX_RATE_LIMIT_WAIT_SECONDS = 5.0


class ProviderNetworkPolicy:
    def __init__(
        self,
        http: HttpClient,
        *,
        clock: Clock | None = None,
        sleep: Sleeper | None = None,
        authorize_session: Callable[[SessionArtifact], None] | None = None,
        budget_owner: ProviderNetworkPolicy | None = None,
    ) -> None:
        self._http = http
        self._clock: Clock = (
            budget_owner._clock if budget_owner else clock or time.monotonic
        )
        self._sleep: Sleeper = (
            budget_owner._sleep if budget_owner else sleep or time.sleep
        )
        self._limiters: dict[str, _TokenBucket] = (
            budget_owner._limiters if budget_owner else {}
        )
        self._lock: threading.Lock = (
            budget_owner._lock if budget_owner else threading.Lock()
        )
        self._authorize_session = authorize_session

    def for_provider(
        self,
        key: str,
        budget: RateBudget,
        http: HttpClient | None = None,
        *,
        retry_response: ResponseRetry | None = None,
        role: HttpOperationRole = HttpOperationRole.OTHER,
        max_attempts: Literal[1, 2] = 2,
    ) -> HttpClient:
        with self._lock:
            limiter = self._limiters.get(key)
            if limiter is None:
                limiter = _TokenBucket(
                    budget,
                    clock=self._clock,
                    sleep=self._sleep,
                )
                self._limiters[key] = limiter
        return _PolicyHttpClient(
            http or self._http,
            limiter,
            provider=key,
            role=role,
            sleep=self._sleep,
            retry_response=retry_response,
            rate_limit_fallback_seconds=budget.rate_limit_fallback_seconds,
            max_attempts=max_attempts,
            authorize_session=self._authorize_session,
        )


class _PolicyHttpClient:
    def __init__(
        self,
        http: HttpClient,
        limiter: _TokenBucket,
        *,
        provider: str,
        role: HttpOperationRole,
        sleep: Sleeper,
        retry_response: ResponseRetry | None,
        rate_limit_fallback_seconds: float,
        max_attempts: Literal[1, 2],
        authorize_session: Callable[[SessionArtifact], None] | None = None,
    ) -> None:
        self._http = http
        self._limiter = limiter
        self._provider = provider
        self._role = role
        self._sleep = sleep
        self._retry_response = retry_response
        self._rate_limit_fallback_seconds = rate_limit_fallback_seconds
        self._max_attempts = max_attempts
        self._authorize_session = authorize_session

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        retry_reason = HttpRetryReason.NONE
        for attempt in range(self._max_attempts):
            self._limiter.acquire()
            if session is not None and self._authorize_session is not None:
                self._authorize_session(session)
            try:
                with http_attempt_context(
                    self._provider,
                    self._role,
                    attempt + 1,
                    retry_reason,
                ):
                    fetch = self._http.get(url, session=session, timeout=timeout)
            except ProviderDefenseError:
                raise
            except ProviderTransportError as error:
                if error.retryable and attempt + 1 < self._max_attempts:
                    retry_reason = HttpRetryReason.TRANSPORT
                    self._sleep(1.0)
                    continue
                raise
            status_retryable = fetch.http_status in _RETRYABLE_STATUS
            provider_retryable = (
                self._retry_response is not None
                and not status_retryable
                and self._retry_response(fetch)
            )
            response_retryable = status_retryable or provider_retryable
            if response_retryable and attempt + 1 < self._max_attempts:
                retry_reason = (
                    HttpRetryReason.STATUS
                    if status_retryable
                    else HttpRetryReason.PROVIDER_RESPONSE
                )
                self._sleep(1.0)
                continue
            if fetch.http_status == 429:
                delay = (
                    min(fetch.retry_after, MAX_RETRY_AFTER_DEFER_SECONDS)
                    if fetch.retry_after is not None
                    else self._rate_limit_fallback_seconds
                )
                if delay > 0:
                    self._limiter.defer(delay)
            return fetch
        raise AssertionError("bounded GET retry exhausted without a result")


class _TokenBucket:
    def __init__(
        self,
        budget: RateBudget,
        *,
        clock: Clock,
        sleep: Sleeper,
    ) -> None:
        self._rate = budget.requests_per_second
        self._burst = float(budget.burst)
        self._tokens = float(budget.burst)
        self._clock = clock
        self._sleep = sleep
        self._updated = clock()
        self._blocked_until = self._updated
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = self._clock()
                self._refill(now)
                if now < self._blocked_until:
                    delay = self._blocked_until - now
                    if delay > MAX_RATE_LIMIT_WAIT_SECONDS:
                        # The provider asked for less traffic; waiting it out
                        # here would stall this worker (and every later
                        # request) for the whole deferral. Report it instead.
                        raise ProviderTransportError(
                            "provider rate limit deferral is active",
                            category=TransportFailure.RATE_LIMITED,
                        )
                elif self._tokens < 1.0:
                    delay = (1.0 - self._tokens) / self._rate
                else:
                    self._tokens -= 1.0
                    return
            # Do not hold the bucket mutex while waiting. An in-flight request
            # must be able to publish a Retry-After deadline before this waiter
            # consumes the next token; always recheck after the sleep.
            self._sleep(delay)

    def defer(self, seconds: float) -> None:
        with self._lock:
            self._blocked_until = max(self._blocked_until, self._clock() + seconds)

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self._updated)
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._updated = now
