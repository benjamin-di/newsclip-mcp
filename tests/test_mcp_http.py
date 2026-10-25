"""Remote MCP transport: fail-closed auth, readiness, and protocol smoke tests."""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")
pytest.importorskip("starlette")

from starlette.testclient import TestClient  # noqa: E402

from newsclip.mcp_server import (  # noqa: E402
    BEARER_TOKEN_ENV,
    SERVER_INSTRUCTIONS,
    build_http_app,
)
from newsclip.models import RawFetch  # noqa: E402
from newsclip.providers import ProviderRegistry  # noqa: E402
from newsclip.service import NewsclipService  # noqa: E402

TOKEN = "remote-test-token"


class NullHttp:
    def get(self, url, *, session=None, timeout: float = 40) -> RawFetch:
        raise AssertionError("HTTP transport is not needed for readiness")


class NullExtractor:
    name = "null"
    version = "1"

    def extract(self, fetch, *, scope_xpath=None):  # noqa: ANN001
        raise AssertionError("extraction is not needed for readiness")


def _service() -> NewsclipService:
    return NewsclipService(ProviderRegistry(()), NullHttp(), NullExtractor())


def _client(*, token: str = TOKEN) -> TestClient:
    return TestClient(
        build_http_app(service_factory=_service, bearer_token=token),
        base_url="http://127.0.0.1",
    )


def test_remote_server_requires_a_nonempty_token(monkeypatch) -> None:
    monkeypatch.delenv(BEARER_TOKEN_ENV, raising=False)

    with pytest.raises(ValueError, match=BEARER_TOKEN_ENV):
        build_http_app(service_factory=_service)
    with pytest.raises(ValueError, match=BEARER_TOKEN_ENV):
        build_http_app(service_factory=_service, bearer_token="  ")


def test_remote_service_is_built_eagerly() -> None:
    calls = 0

    def factory() -> NewsclipService:
        nonlocal calls
        calls += 1
        return _service()

    build_http_app(service_factory=factory, bearer_token=TOKEN)

    assert calls == 1


def test_only_exact_get_health_is_unauthenticated() -> None:
    with _client() as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "service": "newsclip"}

        assert client.head("/health").status_code == 401
        assert client.get("/health?verbose=1").status_code == 401
        assert client.get("/mcp").status_code == 401


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic remote-test-token"},
        {"Authorization": "Bearer wrong"},
        [(b"Authorization", b"Bearer t\xe9l\xe9m\xe9trie")],
    ],
)
def test_mcp_rejects_missing_or_invalid_authorization(headers) -> None:  # noqa: ANN001
    with _client() as client:
        response = client.post("/mcp", headers=headers)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_query_token_is_not_authentication() -> None:
    with _client() as client:
        response = client.post(f"/mcp?token={TOKEN}")

    assert response.status_code == 401


def test_authenticated_mcp_initialize_and_tool_listing() -> None:
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "newsclip-test", "version": "1"},
        },
    }
    tools_list = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}

    with _client() as client:
        initialized = client.post("/mcp", headers=headers, json=initialize)
        listed = client.post("/mcp", headers=headers, json=tools_list)

    assert initialized.status_code == 200
    assert initialized.json()["result"]["serverInfo"]["name"] == "newsclip"
    assert initialized.json()["result"]["instructions"] == SERVER_INSTRUCTIONS
    assert listed.status_code == 200
    tools = listed.json()["result"]["tools"]
    assert {tool["name"] for tool in tools} == {
        "search",
        "get",
        "save",
        "archive_search",
        "archive_get",
        "session_status",
        "reextract",
    }
    save_tool = next(tool for tool in tools if tool["name"] == "save")
    assert "markdown_filename" in save_tool["inputSchema"]["properties"]


def test_tool_failure_is_a_native_redacted_mcp_error() -> None:
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    call = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "search",
            "arguments": {"query": "capital"},
        },
    }

    with _client() as client:
        called = client.post("/mcp", headers=headers, json=call)

    assert called.status_code == 200
    result = called.json()["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    # FastMCP 4 sends the ToolError message as-is: the bare public envelope,
    # the only form synthetic_route_check accepts.
    assert text.startswith('{"ok":false')
    assert '"ok":false' in text
    assert '"category":"usage"' in text
    assert "requires at least one provider" not in text


def test_the_external_watchdog_drives_the_real_route(tmp_path) -> None:  # noqa: ANN001
    """R11: pin the server assumption the outer watchdog is built on.

    The watchdog is stdlib-only and lives outside the package, so nothing
    else would notice if the transport stopped answering a bare
    initialize + tools/call pair — statelessness is what makes that work,
    and a stateful server would reject the second POST with 400 while
    every offline watchdog test (which stubs the transport) stayed green.
    """

    import importlib.util
    import json
    import sys
    from pathlib import Path

    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "synthetic_route_check.py"
    )
    spec = importlib.util.spec_from_file_location("newsclip_watchdog_live", script)
    assert spec is not None and spec.loader is not None
    watchdog = importlib.util.module_from_spec(spec)
    sys.modules["newsclip_watchdog_live"] = watchdog
    spec.loader.exec_module(watchdog)

    with _client() as client:

        def post(url, token, payload, *, timeout):  # noqa: ANN001, ANN202
            response = client.post(
                "/mcp",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            assert response.status_code == 200, response.text
            return watchdog._decode(response.content)

        result = watchdog.run_check(
            "http://127.0.0.1/mcp",
            TOKEN,
            query="markets",
            post=post,
        )

    # The stub registry has no providers, so the product refuses the query
    # and the watchdog reports the refusal with its own category — the
    # protocol round trip itself is what this pins.
    assert result.ok is False
    assert result.reason == "search_rejected_usage"
    assert json.dumps(result.public_dict())
