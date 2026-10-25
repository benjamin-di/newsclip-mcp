"""The outer watchdog's classification: what pages, and what deliberately does not.

Guardian died on the public route for four days while every internal
monitor called it healthy. This check exists to catch that class from an
external vantage — and, just as importantly, to stay silent through the
handled conditions the deployment is designed to sit in, because a
watchdog that pages for containment is one nobody reads.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "synthetic_route_check.py"


def _load() -> ModuleType:
    name = "newsclip_synthetic_check"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    if spec is None or spec.loader is None:  # pragma: no cover - interpreter failure
        raise RuntimeError("synthetic route check cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: the script defines dataclasses, and
    # `dataclasses` resolves the defining module out of `sys.modules`.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CHECK = _load()


def _module() -> ModuleType:
    return CHECK


def _search_response(sources: list[dict[str, object]]) -> dict[str, object]:
    """The exact envelope the public MCP route returns for `search`."""

    return {
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "ok": True,
                            "result": {
                                "query": "markets",
                                "results": [],
                                "sources": sources,
                                "has_more": False,
                            },
                        }
                    ),
                }
            ],
            "isError": False,
        }
    }


def _source(
    provider: str,
    *,
    state: str = "ok",
    reason: str | None = None,
    contained: bool = False,
) -> dict[str, object]:
    return {
        "provider": provider,
        "state": state,
        "result_count": 3 if state == "ok" else 0,
        "reason": reason,
        "retrieval_contained_until": ("2026-08-02T18:00:00Z" if contained else None),
    }


def _poster(response: dict[str, object]):  # noqa: ANN202
    calls: list[dict[str, object]] = []

    def post(url, token, payload, *, timeout):  # noqa: ANN001, ANN202
        calls.append(payload)
        if payload["method"] == "initialize":
            return {"result": {"serverInfo": {"name": "newsclip"}}}
        return response

    post.calls = calls  # type: ignore[attr-defined]
    return post


def test_a_healthy_fleet_passes() -> None:
    module = _module()
    response = _search_response([_source("guardian"), _source("reuters")])

    result = module.run_check(
        "https://mcp.test/mcp",
        "token",
        post=_poster(response),
    )

    assert result.ok is True
    assert result.reason == "ok"
    assert [source.provider for source in result.sources] == ["guardian", "reuters"]


@pytest.mark.parametrize(
    "reason",
    ["operator_action", "session_required", "persistence"],
)
def test_a_local_fault_pages_immediately(reason: str) -> None:
    """Guardian's class: the deployment itself is broken, not the edge."""

    module = _module()
    response = _search_response(
        [
            _source("guardian", state="needs_attention", reason=reason),
            _source("reuters"),
        ]
    )

    result = module.run_check(
        "https://mcp.test/mcp",
        "token",
        post=_poster(response),
    )

    assert result.ok is False
    assert result.reason == "local_fault"
    # The alert names the provider, not just "something is wrong".
    assert result.failing == ["guardian"]


@pytest.mark.parametrize(
    ("state", "reason", "contained"),
    [
        ("unavailable", "transport", False),
        ("unavailable", "timeout", False),
        ("unavailable", "dns", False),
        ("ok", None, True),
        ("unavailable", "unsearchable_query", False),
    ],
)
def test_handled_conditions_never_page_on_one_run(
    state: str,
    reason: str | None,
    contained: bool,
) -> None:
    """Containment and transient edge conditions are the system working.

    Paging for them is exactly the alert fatigue that made Guardian's
    four-day outage get noticed by accident.
    """

    module = _module()
    response = _search_response(
        [
            _source("reuters", state=state, reason=reason, contained=contained),
            _source("guardian"),
        ]
    )

    result = module.run_check(
        "https://mcp.test/mcp",
        "token",
        post=_poster(response),
    )

    assert result.ok is True


def test_a_source_that_stays_degraded_eventually_pages() -> None:
    """A handled state that never resolves has stopped being handled."""

    module = _module()
    degraded = module.run_check(
        "https://mcp.test/mcp",
        "token",
        post=_poster(
            _search_response(
                [
                    _source("reuters", state="unavailable", reason="transport"),
                    _source("guardian"),
                ]
            )
        ),
    )

    streaks: dict[str, int] = {}
    verdicts = []
    for _ in range(3):
        verdict, streaks, _persistent = module.apply_persistence(
            degraded,
            previous=streaks,
            threshold=3,
        )
        verdicts.append(verdict.ok)

    assert verdicts == [True, True, False]
    assert streaks == {"reuters": 3, "guardian": 0}


def test_a_recovered_source_resets_its_streak() -> None:
    module = _module()
    healthy = module.run_check(
        "https://mcp.test/mcp",
        "token",
        post=_poster(_search_response([_source("reuters"), _source("guardian")])),
    )

    verdict, streaks, persistent = module.apply_persistence(
        healthy,
        previous={"reuters": 2},
        threshold=3,
    )

    assert verdict.ok is True
    assert streaks == {"reuters": 0, "guardian": 0}
    assert persistent == []


def test_route_faults_are_named_rather_than_blamed_on_a_provider() -> None:
    module = _module()

    def unreachable(url, token, payload, *, timeout):  # noqa: ANN001, ANN202
        raise module.CheckError("route_unreachable")

    with pytest.raises(module.CheckError, match="route_unreachable"):
        module.run_check("https://mcp.test/mcp", "token", post=unreachable)


def test_a_rejected_search_is_a_serving_fault_not_a_transport_one() -> None:
    module = _module()
    rejected = {"result": {"content": [{"text": "{}"}], "isError": True}}

    result = module.run_check(
        "https://mcp.test/mcp",
        "token",
        post=_poster(rejected),
    )

    assert result.ok is False
    assert result.reason == "search_rejected"


def test_a_route_answering_with_no_sources_is_a_fault() -> None:
    module = _module()

    with pytest.raises(module.CheckError, match="route_reported_no_sources"):
        module.run_check(
            "https://mcp.test/mcp",
            "token",
            post=_poster(_search_response([])),
        )


def test_sse_framing_is_accepted_like_a_plain_json_body() -> None:
    module = _module()
    payload = _search_response([_source("guardian")])
    framed = f"event: message\ndata: {json.dumps(payload)}\n\n".encode()

    assert module._decode(framed) == payload
    assert module._decode(json.dumps(payload).encode()) == payload


def test_streaks_survive_between_runs_and_tolerate_a_damaged_file(
    tmp_path: Path,
) -> None:
    module = _module()
    path = tmp_path / "streaks.json"

    module._store_streaks(path, {"reuters": 2})
    assert module._load_streaks(path) == {"reuters": 2}

    path.write_text("not-json")
    # A damaged file costs one cycle of memory, never a spurious page.
    assert module._load_streaks(path) == {}
    assert module._load_streaks(tmp_path / "absent.json") == {}


def test_an_unconfigured_watchdog_reports_itself_not_the_deployment(
    monkeypatch: pytest.MonkeyPatch,
    capsys,  # noqa: ANN001
) -> None:
    module = _module()
    monkeypatch.delenv("NEWSCLIP_MCP_TOKEN", raising=False)
    monkeypatch.delenv("NEWSCLIP_MCP_URL", raising=False)

    assert module.main([]) == 2
    assert "watchdog_not_configured" in capsys.readouterr().err


@pytest.mark.parametrize(
    "url",
    ["mcp.example.net/mcp", "file:///etc/passwd", "https://", ""],
)
def test_a_malformed_url_blames_the_watchdog_not_the_deployment(
    monkeypatch: pytest.MonkeyPatch,
    capsys,  # noqa: ANN001
    url: str,
) -> None:
    module = _module()
    monkeypatch.setenv("NEWSCLIP_MCP_TOKEN", "token")

    assert module.main(["--url", url]) == 2
    assert "watchdog_not_configured" in capsys.readouterr().err


def test_a_persistently_contained_source_eventually_pages() -> None:
    """Containment is handled — until it has been handled for days."""

    module = _module()
    contained = module.run_check(
        "https://mcp.test/mcp",
        "token",
        post=_poster(
            _search_response([_source("reuters", contained=True), _source("guardian")])
        ),
    )

    assert contained.ok is True  # one run never pages for containment

    streaks: dict[str, int] = {}
    verdicts = []
    for _ in range(3):
        verdict, streaks, _persistent = module.apply_persistence(
            contained,
            previous=streaks,
            threshold=3,
        )
        verdicts.append(verdict.ok)

    assert verdicts == [True, True, False]
    assert streaks == {"reuters": 3, "guardian": 0}


def test_a_rejection_carries_its_own_category_into_the_alert() -> None:
    module = _module()
    rejected = {
        "result": {
            "content": [
                {
                    "text": json.dumps(
                        {
                            "ok": False,
                            "category": "operator_action",
                            "message": "operator action required",
                        }
                    )
                }
            ],
            "isError": True,
        }
    }

    result = module.run_check(
        "https://mcp.test/mcp",
        "token",
        post=_poster(rejected),
    )

    assert result.ok is False
    assert result.reason == "search_rejected_operator_action"


def test_a_transport_blip_shorter_than_the_retry_never_pages() -> None:
    """2026-08-05: an 8-second gateway health-gate window paged a person."""

    module = _module()
    healthy = _search_response([_source("guardian")])
    blipped: list[str] = []
    naps: list[float] = []

    def flaky(url, token, payload, *, timeout):  # noqa: ANN001, ANN202
        if not blipped:
            blipped.append("route_http_503")
            raise module.CheckError("route_http_503")
        if payload["method"] == "initialize":
            return {"result": {"serverInfo": {"name": "newsclip"}}}
        return healthy

    result = module.run_check_with_retry(
        "https://mcp.test/mcp",
        "token",
        post=flaky,
        sleep=naps.append,
    )

    assert result.ok is True
    # The blip stays visible in the ping body without paging anyone.
    assert result.attempt == 2
    assert naps == [module.ROUTE_RETRY_DELAY_SECONDS]


def test_a_route_fault_that_outlives_the_retry_still_pages() -> None:
    module = _module()
    naps: list[float] = []

    def down(url, token, payload, *, timeout):  # noqa: ANN001, ANN202
        raise module.CheckError("route_http_503")

    with pytest.raises(module.CheckError, match="route_http_503") as caught:
        module.run_check_with_retry(
            "https://mcp.test/mcp",
            "token",
            post=down,
            sleep=naps.append,
        )

    assert naps == [module.ROUTE_RETRY_DELAY_SECONDS]
    # The alert says the fault survived a second look.
    assert caught.value.attempt == 2


@pytest.mark.parametrize(
    "reason",
    ["route_http_401", "route_http_302", "route_response_unparsable"],
)
def test_operator_class_faults_never_wait_for_a_retry(reason: str) -> None:
    """Auth, redirect and payload faults are conditions time cannot fix."""

    module = _module()
    naps: list[float] = []

    def failing(url, token, payload, *, timeout):  # noqa: ANN001, ANN202
        raise module.CheckError(reason)

    with pytest.raises(module.CheckError, match=reason):
        module.run_check_with_retry(
            "https://mcp.test/mcp",
            "token",
            post=failing,
            sleep=naps.append,
        )

    assert naps == []


def test_a_route_failure_never_erases_the_streak_memory(tmp_path: Path) -> None:
    module = _module()
    path = tmp_path / "streaks.json"
    module._store_streaks(path, {"reuters": 2, "guardian": 1})

    rejected = module.run_check(
        "https://mcp.test/mcp",
        "token",
        post=_poster({"result": {"content": [{"text": "{}"}], "isError": True}}),
    )
    verdict, streaks, _persistent = module.apply_persistence(
        rejected,
        previous=module._load_streaks(path),
        threshold=3,
    )

    assert verdict.ok is False
    # A run that produced no per-source verdict says nothing about streaks.
    assert rejected.sources == []
    assert module._load_streaks(path) == {"reuters": 2, "guardian": 1}


def _article_poster(
    *, failure=None, crash=False, contain=False, urls=("https://article.test/story",)
):
    calls = []
    read = []

    def post(url, token, payload, *, timeout):
        call = payload["params"]
        calls.append(call)
        if call["name"] == "search":
            provider = call["arguments"]["providers"][0]
            post.provider = provider
            value = {
                "ok": True,
                "result": {
                    "sources": [_source(provider, contained=contain)],
                    "results": [
                        {"provider": provider, "url": article_url}
                        for article_url in urls
                    ][: call["arguments"]["limit"]],
                },
            }
        else:
            assert call["name"] == "get"
            read.append(call["arguments"]["url"])
            if crash:
                raise KeyboardInterrupt
            value = failure or {
                "ok": True,
                "result": {
                    "provider": post.provider,
                    "word_count": 100,
                    "body_markdown": "Private paid article",
                },
            }
        return {"result": {"isError": not value["ok"], "structuredContent": value}}

    post.calls = calls
    post.read = read
    return post


def _native_tool_failure(envelope):
    return {
        "result": {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(envelope, separators=(",", ":")),
                }
            ],
        }
    }


def _article_check(tmp_path, post, *, now=1000, threshold=3, contained=False):
    result = CHECK.CheckResult(
        ok=True,
        reason="ok",
        sources=[
            CHECK.SourceOutcome(p, "ok", None, 1, contained)
            for p in CHECK._ARTICLE_PROVIDERS
        ],
    )
    return CHECK.check_rotating_article(
        result,
        "https://mcp.test/mcp",
        "inert-token",
        state=tmp_path / "streaks",
        post=post,
        now=lambda: now,
        threshold=threshold,
    )


def test_article_probe_requires_get_and_keeps_paid_content_out_of_logs(tmp_path):
    post = _article_poster()
    result = _article_check(tmp_path, post)
    assert [c["name"] for c in post.calls] == ["search", "get"]
    assert result.ok and result.article["reason"] == "full"
    assert result.article["word_count"] == 100
    serialized = (
        json.dumps(result.public_dict()) + (tmp_path / "streaks.articles").read_text()
    )
    assert "Private paid" not in serialized and "article.test" not in serialized


def test_successful_search_cannot_mask_article_failure(tmp_path):
    failing = _article_poster(
        failure={
            "ok": False,
            "category": "content_not_full",
            "diagnostic_id": "mcp-first",
            "message": "private detail",
        },
        urls=("https://article.test/a", "https://article.test/b"),
    )
    first = _article_check(tmp_path, failing, threshold=1)
    assert first.article["diagnostic_id"] == "mcp-first"
    assert "private detail" not in json.dumps(first.public_dict())
    # The failed read is re-sampled in the next slot, on a different article.
    result = _article_check(tmp_path, failing, now=1900, threshold=1)
    assert result.article["provider"] == "ap"
    assert failing.read == ["https://article.test/a", "https://article.test/b"]
    assert not result.ok and result.failing == ["ap"]
    assert result.reason == "article_unavailable"
    # Sampling another healthy provider cannot clear AP's failed article.
    healthy = _article_check(tmp_path, _article_poster(), now=2800, threshold=1)
    assert not healthy.ok and healthy.failing == ["ap"]
    assert healthy.article["provider"] == "axios"


def test_native_fastmcp_article_failure_keeps_only_safe_diagnosis(tmp_path):
    regular = _article_poster()
    failure = {
        "ok": False,
        "category": "content_not_full",
        "diagnostic_id": "diagnostic-abc123",
        "incident_id": "incident-abc123",
        "recovery_id": "recovery-abc123",
        "message": "private paid response detail",
        "url": "https://article.test/private-story",
    }

    def native(url, token, payload, **kwargs):
        if payload["params"]["name"] == "get":
            return _native_tool_failure(failure)
        return regular(url, token, payload, **kwargs)

    result = _article_check(tmp_path, native, threshold=1)

    # One failed article is a sample condition, not yet a provider failure.
    assert result.ok and result.article["reason"] == "content_not_full"
    assert result.notes == {"article_sample_stuck": ["ap"]}
    assert result.article["diagnostic_id"] == "diagnostic-abc123"
    assert result.article["incident_id"] == "incident-abc123"
    assert result.article["recovery_id"] == "recovery-abc123"
    serialized = json.dumps(result.public_dict())
    assert "private paid response detail" not in serialized
    assert "article.test" not in serialized


@pytest.mark.parametrize(
    ("is_error", "text"),
    [
        # FastMCP 4 sends the bare envelope; the FastMCP 3 prefix is refused.
        (True, 'Error executing tool get: {"ok":false}'),
        (True, "not-json"),
        (True, 'tool get failed: {"ok":false}'),
        (True, '{"ok":true}'),
    ],
)
def test_malformed_native_tool_failure_fails_closed(is_error, text):
    answer = {
        "result": {
            "isError": is_error,
            "content": [{"type": "text", "text": text}],
        }
    }

    with pytest.raises(CHECK.CheckError, match="article_response_unparsable"):
        CHECK._tool_envelope(answer)


@pytest.mark.parametrize(
    "provider,coverage,expect_get",
    [
        ("axios", "2026-09-07T00:00:00Z", True),
        ("axios", None, False),
        ("ap", "2026-09-07T00:00:00Z", False),
    ],
)
def test_empty_axios_search_still_requires_full_baseline(
    provider, coverage, expect_get
):
    calls = []

    def post(url, token, payload, **kwargs):
        params = payload["params"]
        calls.append(params)
        if params["name"] == "search":
            result = {
                "results": [],
                "sources": [
                    {"provider": provider, "state": "ok", "coverage_start": coverage}
                ],
            }
        else:
            assert (
                params["arguments"]["url"]
                == "https://www.axios.com/2026/09/06/chris-wright-gas-prices-labor-day"
            )
            return {
                "result": {
                    "isError": False,
                    "structuredContent": {"ok": False, "category": "content_not_full"},
                }
            }
        return {
            "result": {
                "isError": False,
                "structuredContent": {"ok": True, "result": result},
            }
        }

    result = CHECK._article_sample(
        "https://example.test", "inert", provider, "markets", 10, post
    )
    assert not result["ok"]
    assert result["reason"] == (
        "content_not_full" if expect_get else "article_search_empty"
    )
    assert [call["name"] for call in calls] == (
        ["search", "get"] if expect_get else ["search"]
    )


def test_article_selection_and_failure_survive_restart_without_replay(tmp_path):
    post = _article_poster(crash=True)
    with pytest.raises(KeyboardInterrupt):
        _article_check(tmp_path, post)
    resumed = _article_poster()
    result = _article_check(tmp_path, resumed, now=1001, threshold=1)
    assert not resumed.calls
    assert result.article["status"] == "not_due"
    assert result.article["unresolved"]["ap"]["reason"] == "interrupted"
    result = _article_check(tmp_path, resumed, now=1900, threshold=1)
    assert result.article["provider"] == "axios"


@pytest.mark.parametrize("initially_contained", [True, False])
def test_article_probe_does_not_get_during_containment(tmp_path, initially_contained):
    post = _article_poster(contain=True)
    result = _article_check(tmp_path, post, contained=initially_contained)
    assert [c["name"] for c in post.calls] == (
        [] if initially_contained else ["search"]
    )
    assert result.article["reason"] == "article_source_unavailable"
    assert result.article["observation"] == "unverified"


def test_skipped_article_is_unverified_and_gets_one_follow_up_slot(tmp_path):
    skipped = _article_check(tmp_path, _article_poster(), contained=True, threshold=1)
    assert not skipped.ok and skipped.reason == "article_unverified"
    assert skipped.article["observation"] == "unverified"
    assert skipped.article["last_full_at"] is None

    # A process restart reads the same journal. Recovery uses the next slot,
    # and then resumes the existing rotation without skipping Axios.
    post = _article_poster()
    recovered = _article_check(tmp_path, post, now=1900, threshold=1)
    assert recovered.ok and recovered.article["provider"] == "ap"
    assert recovered.article["observation"] == "full"
    assert recovered.article["last_full_at"] == 1900
    assert len(post.calls) == 2
    rotated = _article_check(tmp_path, _article_poster(), now=2800)
    assert rotated.article["provider"] == "axios"


def test_failed_follow_up_does_not_starve_the_rotation_or_repeat(tmp_path):
    _article_check(tmp_path, _article_poster(contain=True))
    still_skipped = _article_check(tmp_path, _article_poster(contain=True), now=1900)
    assert still_skipped.article["provider"] == "ap"
    regular = _article_check(tmp_path, _article_poster(), now=2800)
    assert regular.article["provider"] == "axios"
    next_regular = _article_check(tmp_path, _article_poster(), now=3700)
    assert next_regular.article["provider"] == "bloomberg"


def test_full_timestamp_survives_failed_and_skipped_checks(tmp_path):
    _article_check(tmp_path, _article_poster())
    for slot in range(1, len(CHECK._ARTICLE_PROVIDERS)):
        _article_check(tmp_path, _article_poster(), now=1000 + slot * 900)
    refusing = _article_poster(failure={"ok": False, "category": "content_not_full"})
    failed = _article_check(tmp_path, refusing, now=10000)
    assert failed.article["observation"] == "failed"
    assert failed.article["last_full_at"] == 1000
    follow_up = _article_check(tmp_path, refusing, now=10900)
    assert follow_up.article["provider"] == "ap"
    assert follow_up.article["last_full_at"] == 1000
    for slot in range(1, len(CHECK._ARTICLE_PROVIDERS)):
        _article_check(tmp_path, _article_poster(), now=10900 + slot * 900)
    skipped = _article_check(tmp_path, _article_poster(), now=19900, contained=True)
    assert skipped.article["provider"] == "ap"
    assert skipped.article["last_full_at"] == 1000
    assert skipped.article["observation"] == "unverified"
    assert skipped.article["streak"] == 3  # Three checks without FULL, two GETs.


def test_legacy_skipped_streak_keeps_alert_and_qualifies_for_follow_up(tmp_path):
    (tmp_path / "streaks.articles").write_text(
        json.dumps(
            {
                "cursor": 2,
                "next_at": 1900,
                "outcomes": {
                    "ap": {
                        "ok": False,
                        "reason": "article_source_unavailable",
                        "streak": 3,
                        "checked_at": 1000,
                    },
                },
            }
        )
    )
    waiting = _article_check(tmp_path, _article_poster(), now=1800)
    assert not waiting.ok and waiting.reason == "article_unverified"
    recovered = _article_check(tmp_path, _article_poster(), now=1900)
    assert recovered.ok and recovered.article["provider"] == "ap"


def test_follow_up_reservation_survives_interruption(tmp_path):
    _article_check(tmp_path, _article_poster(contain=True))
    with pytest.raises(KeyboardInterrupt):
        _article_check(tmp_path, _article_poster(crash=True), now=1900)
    post = _article_poster()
    _article_check(tmp_path, post, now=1901)
    assert not post.calls
    resumed = _article_check(tmp_path, post, now=2800)
    assert resumed.article["provider"] == "axios"


def test_notification_explains_unverified_article_and_next_action(
    tmp_path, monkeypatch
):
    result = _article_check(tmp_path, _article_poster(contain=True), threshold=1)
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    monkeypatch.setattr(
        CHECK.urllib.request, "urlopen", lambda r, **k: requests.append(r) or Response()
    )
    CHECK._ping("https://health.test/check", result, timeout=1)
    body = requests[0].data.decode()
    assert body.startswith("Newsclip degraded")
    assert "AP: article unverified" in body
    assert "search" in body and "No article request" in body
    assert "3 failed" not in body
    assert "Next" in body and "last FULL" in body
    assert "article.test" not in body and "Private paid" not in body
    assert requests[0].full_url == "https://health.test/check/fail"


@pytest.mark.parametrize(
    "payload",
    [
        '{"cursor": true}',
        "{bad",
        "x" * 16385,
        '{"cursor": 0, "next_at": 1e100, "outcomes": {}}',
        json.dumps(
            {
                "cursor": 0,
                "next_at": 0,
                "outcomes": {
                    "ap": {
                        "ok": False,
                        "reason": "content_not_full",
                        "streak": 1,
                        "checked_at": 1,
                        "url_hash": "https://article.test/story",
                    }
                },
            }
        ),
    ],
)
def test_corrupt_article_state_stops_without_provider_io(tmp_path, payload):
    (tmp_path / "streaks.articles").write_text(payload)
    post = _article_poster()
    result = _article_check(tmp_path, post)
    assert not result.ok and result.reason == "article_state_unavailable"
    assert not post.calls
    assert (tmp_path / "streaks.articles").read_text() == payload


def test_article_probe_lock_prevents_concurrent_dispatch(tmp_path):
    import fcntl

    with (tmp_path / "streaks.articles.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        post = _article_poster()
        result = _article_check(tmp_path, post)
        assert result.article["status"] == "busy"
        assert not post.calls


def test_only_new_full_sample_resets_failed_provider_streak(tmp_path):
    refusing = _article_poster(failure={"ok": False, "category": "content_not_full"})
    _article_check(tmp_path, refusing)
    _article_check(tmp_path, refusing, now=1900)  # the follow-up fails too
    for slot in range(1, len(CHECK._ARTICLE_PROVIDERS)):
        others = _article_check(tmp_path, _article_poster(), now=1900 + slot * 900)
        assert others.article["provider"] != "ap"
    journal = json.loads((tmp_path / "streaks.articles").read_text())
    assert journal["outcomes"]["ap"]["streak"] == 2
    result = _article_check(
        tmp_path, _article_poster(), now=1900 + len(CHECK._ARTICLE_PROVIDERS) * 900
    )
    assert result.article["provider"] == "ap" and result.article["streak"] == 0
    assert result.ok


def test_article_timeout_is_not_retried(tmp_path):
    post = _article_poster()

    def timeout(url, token, payload, **kwargs):
        if payload["params"]["name"] == "get":
            raise CHECK.CheckError("route_unreachable")
        return post(url, token, payload, **kwargs)

    result = _article_check(tmp_path, timeout)
    assert result.article["reason"] == "route_unreachable"
    assert result.article["streak"] == 1


def test_pending_automatic_renewal_uses_persistence_not_immediate_page(tmp_path):
    result = _article_check(
        tmp_path,
        _article_poster(
            failure={
                "ok": False,
                "category": "session_required",
                "action": "renewal_pending",
                "recovery_id": "recovery-abc123",
                "diagnostic_id": "bad private text",
            }
        ),
    )
    assert result.ok and result.article["reason"] == "renewal_pending"
    assert "diagnostic_id" not in result.article


@pytest.mark.parametrize(
    "article",
    [
        {"provider": "ap", "word_count": 0, "body_markdown": "teaser"},
        {"provider": "ap", "word_count": True, "body_markdown": "teaser"},
        {"provider": "bloomberg", "word_count": 100, "body_markdown": "wrong provider"},
        {"provider": "ap", "word_count": 100, "body_markdown": " "},
    ],
)
def test_malformed_success_is_not_article_proof(tmp_path, article):
    post = _article_poster()

    def malformed(url, token, payload, **kwargs):
        if payload["params"]["name"] == "get":
            return {
                "result": {
                    "isError": False,
                    "structuredContent": {"ok": True, "result": article},
                }
            }
        return post(url, token, payload, **kwargs)

    result = _article_check(tmp_path, malformed, threshold=1)
    assert not result.ok and result.article["reason"] == "article_response_unparsable"


def test_main_runs_article_probe_after_search_and_pages_its_failure(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("NEWSCLIP_MCP_TOKEN", "inert-token")
    monkeypatch.setattr(
        CHECK,
        "run_check_with_retry",
        lambda *a, **k: CHECK.CheckResult(
            ok=True,
            reason="ok",
            sources=[CHECK.SourceOutcome("ap", "ok", None, 1, False)],
        ),
    )
    calls = []

    def sample(*args, **kwargs):
        calls.append(args[2])
        return {"ok": False, "reason": "content_not_full", "diagnostic_id": "mcp-test"}

    monkeypatch.setattr(CHECK, "_article_sample", sample)
    monkeypatch.setattr(CHECK, "_ping", lambda *a, **k: None)
    assert (
        CHECK.main(
            [
                "--url",
                "https://mcp.test/mcp",
                "--state",
                str(tmp_path / "streaks"),
                "--threshold",
                "1",
            ]
        )
        == 1
    )
    output = json.loads(capsys.readouterr().out)
    assert calls == ["ap"]
    assert output["reason"] == "article_unavailable"
    assert output["article"]["diagnostic_id"] == "mcp-test"


A_URL, B_URL = "https://article.test/a", "https://article.test/b"


def _journal(tmp_path):
    return json.loads((tmp_path / "streaks.articles").read_text())


def _cycle_back_to_ap(tmp_path, start):
    """Healthy samples for every other provider; returns AP's next slot."""

    for slot in range(1, len(CHECK._ARTICLE_PROVIDERS)):
        _article_check(tmp_path, _article_poster(), now=start + slot * 900)
    return start + len(CHECK._ARTICLE_PROVIDERS) * 900


def test_sample_searches_five_and_records_only_a_url_hash(tmp_path):
    post = _article_poster(
        failure={"ok": False, "category": "content_not_full"}, urls=(A_URL, B_URL)
    )
    _article_check(tmp_path, post)
    assert post.calls[0]["arguments"]["limit"] == 5
    outcome = _journal(tmp_path)["outcomes"]["ap"]
    assert outcome["url_hash"] == CHECK._url_hash(A_URL)
    assert outcome["avoid_url_hashes"] == [CHECK._url_hash(A_URL)]
    assert len(outcome["url_hash"]) == 12
    assert outcome["follow_up_pending"] is True
    assert "article.test" not in (tmp_path / "streaks.articles").read_text()


def test_one_article_failing_every_check_is_stuck_not_down(tmp_path):
    """2026-09: one unentitled WSJ Pro top hit paged WSJ DOWN for 7.5 hours."""

    refusing = _article_poster(failure={"ok": False, "category": "content_not_full"})
    _article_check(tmp_path, refusing)
    _article_check(tmp_path, refusing, now=1900)  # follow-up; only one URL
    ap_slot = _cycle_back_to_ap(tmp_path, 1900)
    result = _article_check(tmp_path, refusing, now=ap_slot)

    assert result.article["provider"] == "ap" and result.article["streak"] == 3
    assert result.ok and result.reason == "ok" and result.failing == []
    assert result.notes == {"article_sample_stuck": ["ap"]}
    payload = result.public_dict()
    assert payload["notes"] == {"article_sample_stuck": ["ap"]}
    assert "ap" in payload["article"]["stuck"]
    assert payload["summary"].startswith("Newsclip: degradation observed")
    assert "AP: article_sample_stuck" in payload["summary"]
    assert "article.test" not in json.dumps(payload)


def test_failures_on_two_distinct_articles_page(tmp_path):
    refusing = _article_poster(
        failure={"ok": False, "category": "content_not_full"}, urls=(A_URL, B_URL)
    )
    first = _article_check(tmp_path, refusing, threshold=2)
    assert first.ok
    second = _article_check(tmp_path, refusing, now=1900, threshold=2)
    assert refusing.read == [A_URL, B_URL]
    assert not second.ok and second.failing == ["ap"]
    assert second.reason == "article_unavailable"
    assert "article_sample_stuck" not in second.notes


def _poster_failing_only(bad, urls):
    """Search returns `urls`; reads of `bad` are content_not_full, others FULL."""

    full = _article_poster(urls=urls)
    refusing = _article_poster(
        failure={"ok": False, "category": "content_not_full"}, urls=urls
    )

    def post(url, token, payload, *, timeout):
        call = payload["params"]
        if call["name"] == "get":
            post.read.append(call["arguments"]["url"])
            if call["arguments"]["url"] in bad:
                return refusing(url, token, payload, timeout=timeout)
        return full(url, token, payload, timeout=timeout)

    post.read = []
    return post


def test_sample_steps_past_every_recently_failed_article(tmp_path):
    """2026-10-15: Bloomberg's two top `markets` hits were podcast pages.

    Remembering only the last failure alternated between them, a streak on
    two distinct URLs, and paged Bloomberg DOWN while its articles read FULL.
    """

    c_url = "https://article.test/c"
    post = _poster_failing_only({A_URL, B_URL}, (A_URL, B_URL, c_url))
    _article_check(tmp_path, post)
    _article_check(tmp_path, post, now=1900)  # follow-up
    result = _article_check(tmp_path, post, now=_cycle_back_to_ap(tmp_path, 1900))

    assert post.read == [A_URL, B_URL, c_url]
    assert result.ok and result.article["provider"] == "ap"
    assert result.article["streak"] == 0
    assert result.article["avoid_url_hashes"] == [
        CHECK._url_hash(A_URL),
        CHECK._url_hash(B_URL),
    ]


def test_every_result_failed_recently_rereads_the_oldest_failure(tmp_path):
    refusing = _article_poster(
        failure={"ok": False, "category": "content_not_full"}, urls=(A_URL, B_URL)
    )
    _article_check(tmp_path, refusing)
    _article_check(tmp_path, refusing, now=1900)
    result = _article_check(tmp_path, refusing, now=_cycle_back_to_ap(tmp_path, 1900))

    assert refusing.read == [A_URL, B_URL, A_URL]
    assert not result.ok and result.failing == ["ap"]
    assert result.article["avoid_url_hashes"] == [
        CHECK._url_hash(B_URL),
        CHECK._url_hash(A_URL),
    ]


def test_legacy_single_avoided_url_is_still_stepped_past(tmp_path):
    (tmp_path / "streaks.articles").write_text(
        json.dumps(
            {
                "cursor": 0,
                "next_at": 0,
                "outcomes": {
                    "ap": {
                        "ok": False,
                        "reason": "content_not_full",
                        "streak": 1,
                        "checked_at": 900,
                        "observation": "failed",
                        "url_hash": CHECK._url_hash(A_URL),
                        "avoid_url_hash": CHECK._url_hash(A_URL),
                    },
                },
            }
        )
    )
    post = _article_poster(urls=(A_URL, B_URL))
    result = _article_check(tmp_path, post)
    assert post.read == [B_URL] and result.ok
    outcome = _journal(tmp_path)["outcomes"]["ap"]
    assert "avoid_url_hash" not in outcome
    assert outcome["avoid_url_hashes"] == [CHECK._url_hash(A_URL)]


def test_provider_wide_failures_on_one_article_still_page(tmp_path):
    """Defense, timeouts and bad replies are not caused by one article."""

    defended = _article_poster(failure={"ok": False, "category": "provider_defense"})
    _article_check(tmp_path, defended, threshold=2)
    result = _article_check(tmp_path, defended, now=1900, threshold=2)
    assert not result.ok and result.failing == ["ap"]
    assert not result.notes


@pytest.mark.parametrize("category", ["operator_action", "persistence"])
def test_account_and_local_faults_on_one_article_page_immediately(tmp_path, category):
    result = _article_check(
        tmp_path, _article_poster(failure={"ok": False, "category": category})
    )
    assert not result.ok and result.failing == ["ap"]
    assert "article_sample_stuck" not in result.notes


def test_not_entitled_article_is_a_sample_problem_never_a_failure(tmp_path):
    outside = _article_poster(
        failure={"ok": False, "category": "content_not_full", "reason": "not_entitled"},
        urls=(A_URL, B_URL),
    )
    result = _article_check(tmp_path, outside, threshold=1)
    assert result.ok and result.failing == []
    assert result.article["reason"] == "not_entitled"
    assert result.article["streak"] == 0
    assert "outside the subscription" in result.public_dict()["summary"]
    # The next slot re-samples AP on a different article.
    healthy = _article_poster(urls=(A_URL, B_URL))
    recovered = _article_check(tmp_path, healthy, now=1900, threshold=1)
    assert recovered.article["provider"] == "ap" and recovered.ok
    assert healthy.read == [B_URL]


def test_not_entitled_neither_extends_nor_clears_a_failure_streak(tmp_path):
    refusing = _article_poster(failure={"ok": False, "category": "content_not_full"})
    _article_check(tmp_path, refusing)
    outside = _article_poster(
        failure={"ok": False, "category": "content_not_full", "reason": "not_entitled"}
    )
    _article_check(tmp_path, outside, now=1900)
    outcome = _journal(tmp_path)["outcomes"]["ap"]
    assert outcome["streak"] == 1
    assert outcome["streak_url_hash"] == CHECK._url_hash("https://article.test/story")


def test_legacy_failure_streak_without_url_hashes_keeps_paging(tmp_path):
    (tmp_path / "streaks.articles").write_text(
        json.dumps(
            {
                "cursor": 1,
                "next_at": 5000,
                "outcomes": {
                    "ap": {
                        "ok": False,
                        "reason": "content_not_full",
                        "streak": 3,
                        "checked_at": 1000,
                        "observation": "failed",
                    },
                },
            }
        )
    )
    result = _article_check(tmp_path, _article_poster(), now=1900)
    assert not result.ok and result.failing == ["ap"]
    assert not result.notes


def test_interrupted_sample_keeps_the_url_to_step_past(tmp_path):
    refusing = _article_poster(
        failure={"ok": False, "category": "content_not_full"}, urls=(A_URL, B_URL)
    )
    _article_check(tmp_path, refusing)
    with pytest.raises(KeyboardInterrupt):
        _article_check(
            tmp_path, _article_poster(crash=True, urls=(A_URL, B_URL)), now=1900
        )
    outcome = _journal(tmp_path)["outcomes"]["ap"]
    assert outcome["reason"] == "interrupted"
    assert outcome["avoid_url_hashes"] == [CHECK._url_hash(A_URL)]


def _empty_axios_poster(failure=None):
    reads = []

    def post(url, token, payload, **kwargs):
        params = payload["params"]
        if params["name"] == "search":
            provider = params["arguments"]["providers"][0]
            value = {
                "ok": True,
                "result": {
                    "results": [],
                    "sources": [
                        {
                            "provider": provider,
                            "state": "ok",
                            "coverage_start": "2026-09-07T00:00:00Z",
                        }
                    ],
                },
            }
        else:
            reads.append(params["arguments"]["url"])
            value = failure or {
                "ok": True,
                "result": {
                    "provider": "axios",
                    "word_count": 100,
                    "body_markdown": "Public article",
                },
            }
        return {"result": {"isError": not value["ok"], "structuredContent": value}}

    post.read = reads
    return post


def _axios_due(tmp_path, outcomes=None):
    (tmp_path / "streaks.articles").write_text(
        json.dumps({"cursor": 1, "next_at": 0, "outcomes": outcomes or {}})
    )


def test_repeatedly_empty_search_is_a_non_paging_note(tmp_path):
    _axios_due(
        tmp_path,
        {
            "axios": {
                "ok": True,
                "reason": "full",
                "streak": 0,
                "checked_at": 500,
                "observation": "full",
                "empty_searches": 2,
            }
        },
    )
    post = _empty_axios_poster()
    result = _article_check(tmp_path, post)
    assert result.article["provider"] == "axios" and result.article["ok"]
    assert post.read == [CHECK._AXIOS_BASELINE_URL]
    assert result.ok and result.notes == {"search_empty": ["axios"]}
    summary = result.public_dict()["summary"]
    assert "AXIOS: search_empty" in summary
    assert "3 consecutive checks" in summary


def test_search_with_results_resets_the_empty_count(tmp_path):
    _axios_due(
        tmp_path,
        {
            "axios": {
                "ok": True,
                "reason": "full",
                "streak": 0,
                "checked_at": 500,
                "observation": "full",
                "empty_searches": 5,
            }
        },
    )
    result = _article_check(tmp_path, _article_poster())
    assert result.article["provider"] == "axios"
    assert "empty_searches" not in _journal(tmp_path)["outcomes"]["axios"]
    assert not result.notes


def test_failing_axios_baseline_is_provider_evidence_not_a_stuck_sample(tmp_path):
    _axios_due(
        tmp_path,
        {
            "axios": {
                "ok": False,
                "reason": "content_not_full",
                "streak": 2,
                "checked_at": 500,
                "observation": "failed",
            }
        },
    )
    post = _empty_axios_poster(failure={"ok": False, "category": "content_not_full"})
    result = _article_check(tmp_path, post)
    assert post.read == [CHECK._AXIOS_BASELINE_URL]
    assert not result.ok and result.failing == ["axios"]
    assert "article_sample_stuck" not in result.notes


def test_sample_queries_only_widen_the_previous_queries():
    """Any-token headline search: a superset query cannot match less."""

    previous = {
        "ap": "police court government state city president",
        "axios": "trump congress energy prices city government",
    }
    for provider, query in previous.items():
        assert set(query.split()) < set(CHECK._SAMPLE_QUERIES[provider].split())
