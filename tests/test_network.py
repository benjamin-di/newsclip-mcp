from __future__ import annotations

import threading
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from newsclip.errors import (
    ProviderDefenseError,
    ProviderTransportError,
    TransportFailure,
)
from newsclip.http import _retry_after
from newsclip.models import RateBudget, RawFetch, SessionArtifact
from newsclip.network import (
    MAX_RATE_LIMIT_WAIT_SECONDS,
    MAX_RETRY_AFTER_DEFER_SECONDS,
    ProviderNetworkPolicy,
    _TokenBucket,
)

NOW = datetime(2026, 7, 17, tzinfo=UTC)
URL = "https://example.test/resource"


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


def _fetch(status: int = 200, *, retry_after: float | None = None) -> RawFetch:
    return RawFetch(
        requested_url=URL,
        final_url=URL,
        http_status=status,
        content_type="text/html",
        retry_after=retry_after,
        retrieved_at=NOW,
        raw_html=b"NETWORK_FIXTURE",
    )


class SequenceHttp:
    def __init__(self, clock: FakeClock, outcomes: list[object]) -> None:
        self.clock = clock
        self.outcomes = list(outcomes)
        self.call_times: list[float] = []

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.call_times.append(self.clock())
        outcome = self.outcomes.pop(0) if self.outcomes else _fetch()
        if isinstance(outcome, Exception):
            raise outcome
        assert isinstance(outcome, RawFetch)
        return outcome


def _client(
    clock: FakeClock,
    outcomes: list[object],
    *,
    rate: float = 1.0,
    burst: int = 1,
    rate_limit_fallback_seconds: float = 0,
    retry_response=None,
    max_attempts: int = 2,
):
    http = SequenceHttp(clock, outcomes)
    policy = ProviderNetworkPolicy(http, clock=clock, sleep=clock.sleep)
    client = policy.for_provider(
        "fixture",
        RateBudget(
            requests_per_second=rate,
            burst=burst,
            rate_limit_fallback_seconds=rate_limit_fallback_seconds,
        ),
        retry_response=retry_response,
        max_attempts=max_attempts,
    )
    return client, http


def test_provider_rate_budget_enforces_cadence_with_fake_clock() -> None:
    clock = FakeClock()
    client, http = _client(clock, [_fetch(), _fetch(), _fetch()])

    client.get(URL)
    client.get(URL)
    client.get(URL)

    assert http.call_times == [0.0, 1.0, 2.0]
    assert clock.sleeps == [1.0, 1.0]


def test_rate_budget_honors_burst_without_queue_or_scheduler() -> None:
    clock = FakeClock()
    client, http = _client(clock, [_fetch(), _fetch(), _fetch()], rate=2.0, burst=2)

    client.get(URL)
    client.get(URL)
    client.get(URL)

    assert http.call_times == [0.0, 0.0, 0.5]


@pytest.mark.parametrize(
    "first",
    [
        ProviderTransportError("timeout fixture", category=TransportFailure.TIMEOUT),
        ProviderTransportError("dns fixture", category=TransportFailure.DNS),
        _fetch(502),
        _fetch(503),
        _fetch(504),
    ],
)
def test_idempotent_get_retries_once_after_one_second(first: object) -> None:
    clock = FakeClock()
    client, http = _client(clock, [first, _fetch()])

    result = client.get(URL)

    assert result.http_status == 200
    assert http.call_times == [0.0, 1.0]
    assert clock.sleeps == [1.0]


def test_transport_failure_is_bounded_to_one_retry() -> None:
    clock = FakeClock()
    failure = ProviderTransportError(
        "transport fixture", category=TransportFailure.TRANSPORT
    )
    client, http = _client(clock, [failure, failure])

    with pytest.raises(ProviderTransportError) as caught:
        client.get(URL)

    assert caught.value.category is TransportFailure.TRANSPORT
    assert http.call_times == [0.0, 1.0]


def test_non_retryable_transport_failure_is_never_repeated() -> None:
    clock = FakeClock()
    failure = ProviderTransportError(
        "challenge infrastructure fixture",
        retryable=False,
    )
    client, http = _client(clock, [failure, _fetch()])

    with pytest.raises(ProviderTransportError) as caught:
        client.get(URL)

    assert caught.value.retryable is False
    assert http.call_times == [0.0]
    assert clock.sleeps == []


def test_provider_defense_error_is_never_retried_in_process() -> None:
    clock = FakeClock()
    defense = ProviderDefenseError(
        "active edge challenge",
        provider="fixture",
        retry_after_seconds=300,
    )
    client, browser_transport = _client(clock, [defense, _fetch()])

    with pytest.raises(ProviderDefenseError) as caught:
        client.get(URL)

    assert caught.value.retryable is True
    assert browser_transport.call_times == [0.0]
    assert clock.sleeps == []


def test_single_attempt_policy_never_retries_transport_or_response() -> None:
    clock = FakeClock()
    failure = ProviderTransportError(
        "transport fixture",
        category=TransportFailure.TRANSPORT,
    )
    client, transport = _client(
        clock,
        [failure, _fetch()],
        max_attempts=1,
    )

    with pytest.raises(ProviderTransportError):
        client.get(URL)

    assert transport.call_times == [0.0]
    assert clock.sleeps == []

    exact = _fetch(403).model_copy(update={"raw_html": b"EXACT_SECURITY_PAGE"})
    client, transport = _client(
        clock,
        [exact, _fetch()],
        retry_response=lambda fetch: fetch.raw_html == b"EXACT_SECURITY_PAGE",
        max_attempts=1,
    )

    assert client.get(URL).http_status == 403
    assert transport.call_times == [0.0]
    assert clock.sleeps == []


def test_429_is_not_retried_and_retry_after_defers_next_get() -> None:
    clock = FakeClock()
    client, http = _client(clock, [_fetch(429, retry_after=4), _fetch()])

    first = client.get(URL)
    second = client.get(URL)

    assert first.http_status == 429
    assert second.http_status == 200
    assert http.call_times == [0.0, 4.0]
    assert clock.sleeps == [4.0]


def test_long_retry_after_fails_fast_as_rate_limited_instead_of_sleeping() -> None:
    clock = FakeClock()
    client, http = _client(clock, [_fetch(429, retry_after=7), _fetch()])

    assert client.get(URL).http_status == 429
    with pytest.raises(ProviderTransportError) as refused:
        client.get(URL)

    # No worker thread is parked for the deferral and the provider is not
    # contacted; the caller is told why, as a retry-later rate limit.
    assert refused.value.category is TransportFailure.RATE_LIMITED
    assert refused.value.retryable is True
    assert clock.sleeps == []
    assert http.call_times == [0.0]

    clock.value = 7.0
    assert client.get(URL).http_status == 200
    assert http.call_times == [0.0, 7.0]


def test_provider_retry_after_is_capped() -> None:
    clock = FakeClock()
    client, http = _client(clock, [_fetch(429, retry_after=86_400), _fetch()])

    assert client.get(URL).http_status == 429
    clock.value = MAX_RETRY_AFTER_DEFER_SECONDS - 0.5 - MAX_RATE_LIMIT_WAIT_SECONDS
    with pytest.raises(ProviderTransportError):
        client.get(URL)
    # Inside the short-wait window of the capped deferral the request waits
    # and proceeds; a day-long header no longer refuses the provider all day.
    clock.value = MAX_RETRY_AFTER_DEFER_SECONDS - 0.5
    assert client.get(URL).http_status == 200
    assert http.call_times == [0.0, MAX_RETRY_AFTER_DEFER_SECONDS]
    assert clock.sleeps == [0.5]


def test_429_without_retry_after_uses_provider_fallback_for_later_get() -> None:
    clock = FakeClock()
    client, http = _client(
        clock,
        [_fetch(429), _fetch()],
        rate_limit_fallback_seconds=30,
    )

    first = client.get(URL)
    with pytest.raises(ProviderTransportError) as refused:
        client.get(URL)
    clock.value = 30.0
    second = client.get(URL)

    assert first.http_status == 429
    assert refused.value.category is TransportFailure.RATE_LIMITED
    assert second.http_status == 200
    assert http.call_times == [0.0, 30.0]
    assert clock.sleeps == []


def test_short_provider_fallback_still_waits_and_proceeds() -> None:
    clock = FakeClock()
    client, http = _client(
        clock,
        [_fetch(429), _fetch()],
        rate_limit_fallback_seconds=5,
    )

    assert client.get(URL).http_status == 429
    assert client.get(URL).http_status == 200
    assert http.call_times == [0.0, 5.0]
    assert clock.sleeps == [5.0]


def test_exact_provider_response_uses_the_shared_two_attempt_budget() -> None:
    clock = FakeClock()
    exact = _fetch(403).model_copy(update={"raw_html": b"EXACT_SECURITY_PAGE"})

    def predicate(fetch: RawFetch) -> bool:
        return fetch.raw_html == b"EXACT_SECURITY_PAGE"

    client, http = _client(clock, [exact, _fetch()], retry_response=predicate)

    result = client.get(URL)

    assert result.http_status == 200
    assert http.call_times == [0.0, 1.0]
    assert clock.sleeps == [1.0]


def test_arbitrary_403_is_not_retried() -> None:
    clock = FakeClock()
    client, http = _client(
        clock,
        [_fetch(403), _fetch()],
        retry_response=lambda fetch: fetch.raw_html == b"EXACT_SECURITY_PAGE",
    )

    result = client.get(URL)

    assert result.http_status == 403
    assert http.call_times == [0.0]
    assert clock.sleeps == []


def test_retry_causes_share_one_two_attempt_budget() -> None:
    clock = FakeClock()
    failure = ProviderTransportError(
        "timeout fixture",
        category=TransportFailure.TIMEOUT,
    )
    exact = _fetch(403).model_copy(update={"raw_html": b"EXACT_SECURITY_PAGE"})
    client, http = _client(
        clock,
        [failure, exact, _fetch()],
        retry_response=lambda fetch: fetch.raw_html == b"EXACT_SECURITY_PAGE",
    )

    result = client.get(URL)

    assert result.http_status == 403
    assert http.call_times == [0.0, 1.0]
    assert clock.sleeps == [1.0]


def test_waiting_request_does_not_block_concurrent_retry_after_update() -> None:
    clock = FakeClock()
    sleep_started = threading.Event()
    release_sleep = threading.Event()
    defer_completed = threading.Event()

    def controlled_sleep(seconds: float) -> None:
        clock.sleeps.append(seconds)
        if len(clock.sleeps) == 1:
            sleep_started.set()
            release_sleep.wait(2)
        clock.value += seconds

    bucket = _TokenBucket(
        RateBudget(requests_per_second=1, burst=1),
        clock=clock,
        sleep=controlled_sleep,
    )
    bucket.acquire()
    waiter = threading.Thread(target=bucket.acquire)
    waiter.start()
    assert sleep_started.wait(1)
    deferrer = threading.Thread(target=lambda: (bucket.defer(4), defer_completed.set()))
    deferrer.start()
    try:
        assert defer_completed.wait(0.5)
    finally:
        release_sleep.set()
        waiter.join(2)
        deferrer.join(2)

    assert not waiter.is_alive()
    assert not deferrer.is_alive()
    assert clock.sleeps == [1.0, 3.0]


def test_retry_after_rejects_non_finite_delays() -> None:
    assert _retry_after("inf") is None
    assert _retry_after("nan") is None
    with pytest.raises(ValidationError):
        _fetch(429, retry_after=float("inf"))


def test_waiter_fails_fast_when_a_concurrent_429_publishes_a_long_deferral() -> None:
    clock = FakeClock()
    sleep_started = threading.Event()
    release_sleep = threading.Event()
    outcome: list[BaseException | None] = []

    def controlled_sleep(seconds: float) -> None:
        clock.sleeps.append(seconds)
        sleep_started.set()
        release_sleep.wait(2)
        clock.value += seconds

    bucket = _TokenBucket(
        RateBudget(requests_per_second=1, burst=1),
        clock=clock,
        sleep=controlled_sleep,
    )
    bucket.acquire()

    def wait() -> None:
        try:
            bucket.acquire()
        except BaseException as error:  # noqa: BLE001 - asserted below
            outcome.append(error)
        else:
            outcome.append(None)

    waiter = threading.Thread(target=wait)
    waiter.start()
    assert sleep_started.wait(1)
    bucket.defer(MAX_RETRY_AFTER_DEFER_SECONDS)
    release_sleep.set()
    waiter.join(2)

    assert not waiter.is_alive()
    assert clock.sleeps == [1.0]
    assert isinstance(outcome[0], ProviderTransportError)
    assert outcome[0].category is TransportFailure.RATE_LIMITED
