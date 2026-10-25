from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from curl_cffi.const import CurlHttpVersion
from pydantic import ValidationError

from newsclip.browser_runtime import HttpAttemptEvent, HttpOperationRole, RuntimeTrace
from newsclip.errors import OperatorActionRequiredError, ProviderTransportError
from newsclip.http import CurlCffiHttpClient
from newsclip.models import (
    DEFAULT_HTTP_IMPERSONATION,
    PortableCookie,
    RateBudget,
    SessionArtifact,
)
from newsclip.network import ProviderNetworkPolicy
from newsclip.results import PublicErrorCategory, classify_error

NOW = datetime(2026, 7, 20, tzinfo=UTC)


def test_http_provenance_distinguishes_fresh_and_cookie_warmed_routes(
    monkeypatch, tmp_path
):
    from test_sessions import _artifact

    class CookieSession(FakeSession):
        def get(self, url, **kwargs):
            response = super().get(url, **kwargs)
            self.cookies.set(
                "private-edge-cookie", "PRIVATE_EDGE_VALUE", domain=".ft.com", path="/"
            )
            response.url = url + "?PRIVATE_REDIRECT_VALUE"
            response.redirect_count = 1
            return response

    monkeypatch.setattr("newsclip.http.requests.Session", CookieSession)
    path = tmp_path / "http.jsonl"
    trace = RuntimeTrace(path, run_id="provenance-fixture")
    artifact = _artifact()
    for count in (2, 1):
        with CurlCffiHttpClient(trace=trace) as http:
            client = ProviderNetworkPolicy(http).for_provider(
                "ft",
                RateBudget(requests_per_second=100, burst=4),
                role=HttpOperationRole.VERIFICATION,
            )
            for _ in range(count):
                client.get("https://www.ft.com/content/fixture", session=artifact)
    text = path.read_text()
    facts = [json.loads(line)["facts"] for line in text.splitlines()]
    assert [fact["route_request_index"] for fact in facts] == [1, 2, 1]
    assert [fact["request_cookies_changed"] for fact in facts] == [False, True, False]
    assert [fact["response_cookies_changed"] for fact in facts] == [True, False, True]
    assert all(fact["redirected"] for fact in facts)
    assert facts[0]["route_id"] == facts[1]["route_id"]
    assert facts[0]["route_id"] != facts[2]["route_id"]
    assert len({fact["session_generation_fingerprint"] for fact in facts}) == 1
    assert len(facts[0]["session_generation_fingerprint"]) == 12
    assert str(artifact.generation_id) not in text
    assert "PRIVATE" not in text and "private-edge-cookie" not in text
    assert "ft.com" not in text


class FakeResponse:
    url = "https://provider.test/article"
    status_code = 200
    headers = {"content-type": "text/html"}
    content = b"<html><body>fixture</body></html>"


class FakeSession:
    instances: list[FakeSession] = []

    def __init__(
        self,
        *,
        impersonate: str,
        cookies: object | None = None,
        headers: dict[str, str] | None = None,
        http_version: CurlHttpVersion | None = None,
        default_headers: bool = True,
    ) -> None:
        self.impersonate = impersonate
        self.cookies = cookies
        self.headers = headers
        self.http_version = http_version
        self.default_headers = default_headers
        self.urls: list[str] = []
        self.request_headers: list[dict[str, str] | None] = []
        self.allow_redirects: list[bool] = []
        self.closed = False
        type(self).instances.append(self)

    def close(self) -> None:
        self.closed = True

    def get(
        self,
        url: str,
        *,
        timeout: float,
        allow_redirects: bool,
        headers: dict[str, str] | None = None,
    ) -> FakeResponse:
        assert timeout == 40
        self.urls.append(url)
        self.request_headers.append(headers)
        self.allow_redirects.append(allow_redirects)
        return FakeResponse()


def _artifact(*, user_agent: str | None) -> SessionArtifact:
    return SessionArtifact(
        generation_id=uuid4(),
        provider="fixture",
        created_at=NOW,
        verified_at=NOW,
        user_agent=user_agent,
        cookies=(
            PortableCookie(
                name="Session",
                value="COOKIE_VALUE",
                domain="provider.test",
                expires=(NOW + timedelta(days=1)).timestamp(),
            ),
        ),
    )


def test_session_user_agent_is_replayed_with_portable_cookies(monkeypatch) -> None:
    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", FakeSession)

    client = CurlCffiHttpClient()
    artifact = _artifact(user_agent="FixtureBrowser/149")
    client.get(FakeResponse.url, session=artifact)
    client.get("https://provider.test/second", session=artifact)

    assert len(FakeSession.instances) == 1
    route = FakeSession.instances[0]
    assert route.cookies is not None
    assert route.headers == {"User-Agent": "FixtureBrowser/149"}
    assert route.urls == [FakeResponse.url, "https://provider.test/second"]


def test_legacy_artifact_without_user_agent_keeps_default_impersonation(
    monkeypatch,
) -> None:
    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", FakeSession)

    CurlCffiHttpClient().get(
        FakeResponse.url,
        session=_artifact(user_agent=None),
    )

    assert FakeSession.instances[0].headers is None
    assert FakeSession.instances[0].impersonate == DEFAULT_HTTP_IMPERSONATION


def test_anonymous_host_can_select_a_declared_http_impersonation(monkeypatch) -> None:
    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", FakeSession)
    client = CurlCffiHttpClient(impersonate_by_host={"reuters.test": "safari"})

    client.get("https://reuters.test/article")
    client.get("https://other.test/article")
    client.get("https://reuters.test/paid", session=_artifact(user_agent=None))

    assert [route.impersonate for route in FakeSession.instances] == [
        "safari",
        DEFAULT_HTTP_IMPERSONATION,
        DEFAULT_HTTP_IMPERSONATION,
    ]


def test_http_version_and_default_headers_apply_to_every_route(monkeypatch) -> None:
    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", FakeSession)
    client = CurlCffiHttpClient(
        http_version=CurlHttpVersion.V1_1,
        default_headers=False,
    )

    client.get("https://provider.test/anonymous")
    client.get(
        "https://provider.test/authenticated",
        session=_artifact(user_agent="FixtureBrowser/149"),
    )

    assert len(FakeSession.instances) == 2
    assert all(
        route.http_version is CurlHttpVersion.V1_1 for route in FakeSession.instances
    )
    assert all(route.default_headers is False for route in FakeSession.instances)


def test_http_configuration_defaults_preserve_library_defaults(monkeypatch) -> None:
    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", FakeSession)

    CurlCffiHttpClient().get("https://provider.test/article")

    route = FakeSession.instances[0]
    assert route.http_version is None
    assert route.default_headers is True


def test_session_generation_and_anonymous_origin_define_route_affinity(
    monkeypatch,
) -> None:
    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", FakeSession)
    client = CurlCffiHttpClient()
    first = _artifact(user_agent=None)
    second = _artifact(user_agent=None)

    client.get("https://provider.test/one", session=first)
    client.get("https://other.test/two", session=first)
    client.get("https://provider.test/three", session=second)
    client.get("https://provider.test/search")
    client.get("https://provider.test/article")
    client.get("https://other.test/search")

    assert len(FakeSession.instances) == 4
    assert FakeSession.instances[0].urls == [
        "https://provider.test/one",
        "https://other.test/two",
    ]
    assert FakeSession.instances[0].closed is True
    assert FakeSession.instances[1].urls == ["https://provider.test/three"]
    assert FakeSession.instances[2].urls == [
        "https://provider.test/search",
        "https://provider.test/article",
    ]
    assert FakeSession.instances[3].urls == ["https://other.test/search"]

    with pytest.raises(ProviderTransportError, match="generation is retired"):
        client.get("https://provider.test/stale", session=first)
    client.get("https://provider.test/four", session=second)
    assert len(FakeSession.instances) == 4
    assert FakeSession.instances[1].urls == [
        "https://provider.test/three",
        "https://provider.test/four",
    ]


def test_route_lock_serializes_requests_on_one_session_generation(monkeypatch) -> None:
    entered = threading.Event()
    release = threading.Event()
    active = 0
    maximum_active = 0

    class BlockingSession(FakeSession):
        def get(
            self,
            url: str,
            *,
            timeout: float,
            allow_redirects: bool,
            headers: dict[str, str] | None = None,
        ):
            nonlocal active, maximum_active
            active += 1
            maximum_active = max(maximum_active, active)
            if not entered.is_set():
                entered.set()
                assert release.wait(2)
            active -= 1
            return super().get(
                url,
                timeout=timeout,
                allow_redirects=allow_redirects,
            )

    monkeypatch.setattr("newsclip.http.requests.Session", BlockingSession)
    client = CurlCffiHttpClient()
    artifact = _artifact(user_agent=None)
    threads = [
        threading.Thread(
            target=client.get,
            args=(FakeResponse.url,),
            kwargs={"session": artifact},
        )
        for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    assert entered.wait(1)
    release.set()
    for thread in threads:
        thread.join(2)

    assert all(not thread.is_alive() for thread in threads)
    assert maximum_active == 1


def test_anonymous_article_get_is_not_blocked_by_parallel_discovery(
    monkeypatch,
) -> None:
    """Article fetch wall must not include leftover discovery serialization."""

    import time

    FakeSession.instances = []

    class SlowSession(FakeSession):
        def get(
            self,
            url: str,
            *,
            timeout: float,
            allow_redirects: bool,
            headers: dict[str, str] | None = None,
        ):
            delay = 0.12 if "sitemap" in url else 0.02
            time.sleep(delay)
            return super().get(url, timeout=timeout, allow_redirects=allow_redirects)

    monkeypatch.setattr("newsclip.http.requests.Session", SlowSession)
    client = CurlCffiHttpClient()

    def discovery(index: int) -> None:
        client.get(f"https://provider.test/sitemap?from={index}")

    started = time.perf_counter()
    threads = [threading.Thread(target=discovery, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    # Contended discovery is still in flight; article get must proceed without
    # waiting for the shared keep-alive lock to drain those workers.
    time.sleep(0.03)
    article_started = time.perf_counter()
    client.get("https://provider.test/article/example-2026-07-20")
    article_elapsed = time.perf_counter() - article_started
    for thread in threads:
        thread.join(2)
    wall = time.perf_counter() - started

    assert all(not thread.is_alive() for thread in threads)
    # Serialized discovery would make the article wait ~0.7s+; concurrent
    # contenders use ephemeral sessions so article stays near its own 0.02s.
    assert article_elapsed < 0.15, article_elapsed
    assert wall < 0.35, wall
    assert len(FakeSession.instances) >= 2


def test_anonymous_fan_out_records_shared_and_overflow_routes(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Parallel public discovery must not pin the shared route until it drains.

    Reuters sitemap fan-out used to share one locked curl session, so leftover
    discovery GETs held the lock and the following article save waited on them.
    """

    entered = threading.Barrier(3)
    release = threading.Event()
    active = 0
    maximum_active = 0
    lock = threading.Lock()

    class BlockingSession(FakeSession):
        def get(
            self,
            url: str,
            *,
            timeout: float,
            allow_redirects: bool,
            headers: dict[str, str] | None = None,
        ):
            nonlocal active, maximum_active
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
            entered.wait(2)
            assert release.wait(2)
            with lock:
                active -= 1
            return super().get(
                url,
                timeout=timeout,
                allow_redirects=allow_redirects,
            )

    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", BlockingSession)
    trace_path = tmp_path / "http-runtime.jsonl"
    client = CurlCffiHttpClient(
        http_version=CurlHttpVersion.V1_1,
        default_headers=False,
        trace=RuntimeTrace(trace_path, run_id="http-fanout"),
    )
    observed = ProviderNetworkPolicy(client).for_provider(
        "reuters",
        RateBudget(requests_per_second=100, burst=3),
        role=HttpOperationRole.SEARCH,
    )
    threads = [
        threading.Thread(
            target=observed.get,
            args=(f"https://provider.test/page-{index}",),
        )
        for index in range(3)
    ]
    for thread in threads:
        thread.start()
    release.set()
    for thread in threads:
        thread.join(2)

    assert all(not thread.is_alive() for thread in threads)
    assert maximum_active == 3
    # Shared keep-alive route plus one ephemeral Session per contending worker.
    assert len(FakeSession.instances) == 3
    assert all(
        route.http_version is CurlHttpVersion.V1_1 for route in FakeSession.instances
    )
    assert all(route.default_headers is False for route in FakeSession.instances)
    rows = [
        json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()
    ]
    facts = [row["facts"] for row in rows]
    assert {fact["provider"] for fact in facts} == {"reuters"}
    assert {fact["role"] for fact in facts} == {"search"}
    assert sorted(fact["route_mode"] for fact in facts) == [
        "overflow_ephemeral",
        "overflow_ephemeral",
        "shared_affinity",
    ]
    assert sum(fact["contention"] for fact in facts) == 2


def test_http_attempt_trace_records_retry_and_datadome_presence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class Response(FakeResponse):
        def __init__(self, status: int, headers: dict[str, str]) -> None:
            self.status_code = status
            self.headers = headers

    class SequenceSession(FakeSession):
        responses = [
            Response(503, {"content-type": "text/html"}),
            Response(
                401,
                {
                    "content-type": "text/html",
                    "x-datadome": "protected",
                    "set-cookie": "datadome=PRIVATE_VALUE; Secure",
                },
            ),
        ]

        def get(
            self,
            url: str,
            *,
            timeout: float,
            allow_redirects: bool,
            headers: dict[str, str] | None = None,
        ):
            self.urls.append(url)
            return type(self).responses.pop(0)

    monkeypatch.setattr("newsclip.http.requests.Session", SequenceSession)
    trace_path = tmp_path / "http-runtime.jsonl"
    client = CurlCffiHttpClient(
        trace=RuntimeTrace(trace_path, run_id="http-retry"),
        clock=lambda: 1.0,
    )
    observed = ProviderNetworkPolicy(client, sleep=lambda _seconds: None).for_provider(
        "reuters",
        RateBudget(requests_per_second=100, burst=2),
        role=HttpOperationRole.FETCH,
    )

    result = observed.get("https://www.reuters.com/world/example-2026-07-23")

    assert result.http_status == 401
    rows = [
        json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [row["event"] for row in rows] == ["http_attempt", "http_attempt"]
    first, second = (row["facts"] for row in rows)
    assert (first["policy_attempt"], first["retry_reason"], first["status"]) == (
        1,
        "none",
        503,
    )
    assert (second["policy_attempt"], second["retry_reason"], second["status"]) == (
        2,
        "status",
        401,
    )
    assert second["datadome_header_present"] is True
    assert second["datadome_cookie_present"] is True
    assert "PRIVATE_VALUE" not in trace_path.read_text(encoding="utf-8")


def test_http_attempt_event_rejects_inconsistent_closed_outcome() -> None:
    with pytest.raises(ValidationError, match="outcome/status"):
        HttpAttemptEvent(
            provider="reuters",
            role="fetch",
            policy_attempt=1,
            retry_reason="none",
            impersonate="chrome",
            route_mode="shared_affinity",
            contention=False,
            outcome="response",
            duration_ms=1,
        )


def test_invalid_response_metadata_retries_then_reports_transport(
    monkeypatch,
) -> None:
    class InvalidResponse(FakeResponse):
        url = "about:blank"

    class InvalidResponseSession(FakeSession):
        def get(
            self,
            url: str,
            *,
            timeout: float,
            allow_redirects: bool,
            headers: dict[str, str] | None = None,
        ):
            self.urls.append(url)
            return InvalidResponse()

    InvalidResponseSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", InvalidResponseSession)
    sleeps: list[float] = []
    client = CurlCffiHttpClient()
    observed = ProviderNetworkPolicy(client, sleep=sleeps.append).for_provider(
        "fixture",
        RateBudget(requests_per_second=100, burst=2),
    )

    with pytest.raises(ProviderTransportError, match="metadata is invalid") as caught:
        observed.get("https://provider.test/article")

    assert InvalidResponseSession.instances[0].urls == [
        "https://provider.test/article",
        "https://provider.test/article",
    ]
    assert sleeps == [1.0]
    assert classify_error(caught.value) == (PublicErrorCategory.TRANSPORT, 5)


def test_close_releases_routes_and_rejects_future_requests(monkeypatch) -> None:
    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", FakeSession)
    client = CurlCffiHttpClient()
    client.get("https://provider.test/search")
    client.get("https://other.test/search")

    client.close()
    client.close()

    assert all(route.closed for route in FakeSession.instances)
    with pytest.raises(RuntimeError, match="closed"):
        client.get("https://provider.test/again")


def test_declared_host_headers_attach_per_request_and_stay_host_scoped(
    monkeypatch,
) -> None:
    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", FakeSession)
    resolved: list[str] = []

    def resolve() -> dict[str, str]:
        resolved.append("call")
        return {"api-key": "KEY_SENTINEL"}

    client = CurlCffiHttpClient(headers_by_host={"API.test": resolve})

    client.get("https://api.test/search?q=fixture")
    client.get("https://other.test/page")

    headers = [
        header for route in FakeSession.instances for header in route.request_headers
    ]
    assert headers == [{"api-key": "KEY_SENTINEL"}, None]
    redirects = [
        follow for route in FakeSession.instances for follow in route.allow_redirects
    ]
    assert redirects == [False, True]
    # Resolved once per matching request, never at construction.
    assert resolved == ["call"]
    # The session itself keeps no default credential header between requests.
    assert all(
        not (route.headers or {}).get("api-key") for route in FakeSession.instances
    )


@pytest.mark.parametrize(
    ("origin_url", "destination_url"),
    [
        (
            "https://api.test/redirect",
            "https://api.test/destination",
        ),
        (
            "https://api.test/redirect",
            "https://other.test/destination",
        ),
        (
            "https://api.test/redirect",
            "http://other.test/destination",
        ),
    ],
)
def test_credential_bearing_requests_never_follow_redirects(
    monkeypatch,
    origin_url: str,
    destination_url: str,
) -> None:
    class RedirectResponse:
        def __init__(self, *, url: str, status_code: int) -> None:
            self.url = url
            self.status_code = status_code
            self.headers = {
                "content-type": "text/plain",
                "location": destination_url,
            }
            self.content = b"redirect"

    class RedirectSession(FakeSession):
        destination_requests: list[dict[str, str] | None] = []

        def get(
            self,
            url: str,
            *,
            timeout: float,
            allow_redirects: bool,
            headers: dict[str, str] | None = None,
        ) -> RedirectResponse:
            self.urls.append(url)
            self.request_headers.append(headers)
            self.allow_redirects.append(allow_redirects)
            if allow_redirects:
                type(self).destination_requests.append(headers)
                return RedirectResponse(url=destination_url, status_code=200)
            return RedirectResponse(url=url, status_code=302)

    RedirectSession.instances = []
    RedirectSession.destination_requests = []
    monkeypatch.setattr("newsclip.http.requests.Session", RedirectSession)
    client = CurlCffiHttpClient(
        headers_by_host={"api.test": lambda: {"api-key": "KEY_SENTINEL"}}
    )

    fetch = client.get(origin_url)

    route = RedirectSession.instances[0]
    assert route.request_headers == [{"api-key": "KEY_SENTINEL"}]
    assert route.allow_redirects == [False]
    assert RedirectSession.destination_requests == []
    assert fetch.http_status == 302
    assert str(fetch.final_url) == origin_url


def test_header_free_request_still_follows_redirects(monkeypatch) -> None:
    destination_url = "https://other.test/destination"

    class RedirectResponse:
        url = destination_url
        status_code = 200
        headers = {"content-type": "text/plain"}
        content = b"destination"

    class RedirectSession(FakeSession):
        destination_requests = 0

        def get(
            self,
            url: str,
            *,
            timeout: float,
            allow_redirects: bool,
            headers: dict[str, str] | None = None,
        ) -> RedirectResponse:
            self.urls.append(url)
            self.request_headers.append(headers)
            self.allow_redirects.append(allow_redirects)
            if allow_redirects:
                type(self).destination_requests += 1
            return RedirectResponse()

    RedirectSession.instances = []
    RedirectSession.destination_requests = 0
    monkeypatch.setattr("newsclip.http.requests.Session", RedirectSession)

    fetch = CurlCffiHttpClient().get("https://api.test/redirect")

    route = RedirectSession.instances[0]
    assert route.request_headers == [None]
    assert route.allow_redirects == [True]
    assert RedirectSession.destination_requests == 1
    assert str(fetch.final_url) == destination_url


def test_host_header_resolver_failure_propagates_before_any_request(
    monkeypatch,
) -> None:
    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", FakeSession)

    def failing() -> dict[str, str]:
        raise OperatorActionRequiredError("fixture key unavailable")

    client = CurlCffiHttpClient(headers_by_host={"api.test": failing})

    with pytest.raises(OperatorActionRequiredError, match="key unavailable"):
        client.get("https://api.test/search?q=fixture")
    assert all(not route.urls for route in FakeSession.instances)


def test_runtime_pin_governs_the_next_fetch_of_a_live_client(monkeypatch) -> None:
    """R8: a pin promoted mid-process must not wait for a restart.

    Composition builds the impersonation map once and the serving process
    keeps one client for its lifetime, so the resolver is consulted per
    fetch and a changed answer opens a new keep-alive route rather than
    reusing one still speaking the rotted fingerprint.
    """

    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", FakeSession)
    promoted: list[str | None] = [None]
    client = CurlCffiHttpClient(
        impersonate_by_host={"reuters.test": "safari2601"},
        runtime_impersonate_by_host=lambda host: (
            promoted[0] if host == "reuters.test" else None
        ),
    )

    declared = client.get("https://reuters.test/article")
    promoted[0] = "chrome146"
    runtime = client.get("https://reuters.test/second")
    again = client.get("https://reuters.test/third")

    assert [route.impersonate for route in FakeSession.instances] == [
        "safari2601",
        "chrome146",
    ]
    # The promoted route is reused for later fetches; only a *change* opens one.
    assert FakeSession.instances[1].urls == [
        "https://reuters.test/second",
        "https://reuters.test/third",
    ]
    # Provenance rides along on every fetch.
    assert declared.serving_transport == "safari2601"
    assert runtime.serving_transport == "chrome146"
    assert again.serving_transport == "chrome146"


def test_runtime_pin_resolver_failure_falls_back_to_the_declared_pin(
    monkeypatch,
) -> None:
    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", FakeSession)

    def broken(host: str) -> str | None:
        raise RuntimeError("pin state exploded")

    client = CurlCffiHttpClient(
        impersonate_by_host={"reuters.test": "safari2601"},
        runtime_impersonate_by_host=broken,
    )

    fetch = client.get("https://reuters.test/article")

    assert FakeSession.instances[0].impersonate == "safari2601"
    assert fetch.serving_transport == "safari2601"


def test_session_routes_ignore_the_runtime_pin(monkeypatch) -> None:
    FakeSession.instances = []
    monkeypatch.setattr("newsclip.http.requests.Session", FakeSession)
    client = CurlCffiHttpClient(
        runtime_impersonate_by_host=lambda host: "chrome146",
    )

    fetch = client.get(FakeResponse.url, session=_artifact(user_agent=None))

    assert FakeSession.instances[0].impersonate == DEFAULT_HTTP_IMPERSONATION
    assert fetch.serving_transport == DEFAULT_HTTP_IMPERSONATION
