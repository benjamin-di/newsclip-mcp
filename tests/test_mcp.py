"""Local MCP adapter: contract equivalence, bounded concurrency, redaction, no listener.

Gated on the optional ``mcp`` extra (which also provides AnyIO); the module is
skipped cleanly when the extra is absent so the standard offline gate still runs.
"""

from __future__ import annotations

import json
import re
import stat
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from mcp_wire import call_tool, list_tools

pytest.importorskip("anyio")
pytest.importorskip("mcp")

import anyio  # noqa: E402

from newsclip.archive import ArchiveStore  # noqa: E402
from newsclip.errors import (  # noqa: E402
    PersistenceError,
    ProviderTransportError,
    UnsearchableQueryError,
)
from newsclip.mcp_server import (  # noqa: E402
    EXPOSED_TOOLS,
    FORBIDDEN_TOOLS,
    SERVER_INSTRUCTIONS,
    NewsclipMcp,
    WorkerDispatcher,
    build_mcp,
)
from newsclip.models import (  # noqa: E402
    AccessState,
    ArticleAssessment,
    ExtractedArticle,
    ProviderCapabilities,
    ProviderSearchPage,
    RateBudget,
    RawFetch,
    SearchFilters,
    SearchResult,
)
from newsclip.providers import ProviderRegistry  # noqa: E402
from newsclip.providers.builtins import BUILTIN_PROVIDER_KEYS_PROSE  # noqa: E402
from newsclip.service import NewsclipService  # noqa: E402
from newsclip.timing import TimingRecorder, iter_timing_runs  # noqa: E402

NOW = datetime(2026, 7, 17, tzinfo=UTC)
CONTENT_PREFIX = "https://fixture.test/content/"
FULL_URL = f"{CONTENT_PREFIX}full-article"
TEASER_URL = f"{CONTENT_PREFIX}teaser-article"
COOKIE_SENTINEL = "COOKIE_VALUE_SENTINEL"
RAW_SENTINEL = "RAW_HTML_SENTINEL"


class FakeHttp:
    def get(self, url, *, session=None, timeout: float = 40) -> RawFetch:
        teaser = "teaser" in url
        body = f"{RAW_SENTINEL} teaser" if teaser else f"{RAW_SENTINEL} FULL"
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=session is not None,
            raw_html=body.encode(),
        )


class FakeExtractor:
    name = "fixture-extractor"
    version = "1"

    def extract(
        self,
        fetch: RawFetch,
        *,
        scope_xpath: tuple[str, ...] | None = None,
    ) -> ExtractedArticle:
        return ExtractedArticle(
            body_markdown="Generated fixture body.",
            metadata={"title": "Fixture article", "author": ["Fixture Author"]},
            word_count=250,
        )


class FakeProvider:
    key = "fixture"
    capabilities = ProviderCapabilities(requires_session_for_retrieve=False)
    login_recipe = None
    assessment_policy_version = "fixture-v1"
    extraction_scope: tuple[str, ...] | None = None

    def owns_url(self, url: str) -> bool:
        return url.startswith(CONTENT_PREFIX)

    def search(self, http, session, query, filters: SearchFilters):
        return [
            SearchResult(provider=self.key, url=FULL_URL, headline=f"Result: {query}")
        ][: filters.limit]

    def search_page(
        self,
        http,
        session,
        query,
        filters: SearchFilters,
        *,
        next_url=None,
        metadata_fetch_budget=None,
    ) -> ProviderSearchPage:
        assert next_url is None
        return ProviderSearchPage(
            results=tuple(self.search(http, session, query, filters))
        )

    def fetch(self, http, session, url: str) -> RawFetch:
        return http.get(url, session=session)

    def assess(self, requested_url, fetch, extraction) -> ArticleAssessment:
        full = b"FULL" in fetch.raw_html
        return ArticleAssessment(
            access_state=AccessState.FULL if full else AccessState.TEASER,
            provider_article_id=requested_url.rsplit("/", 1)[-1],
            canonical_url=requested_url,
            identity_match=full,
            negative_markers=() if full else ("paywall",),
            structural_signals=("article_body",) if full else (),
            word_count=250,
            reason="full_fixture" if full else "paywall_teaser",
        )

    def rate_budget(self) -> RateBudget:
        return RateBudget(requests_per_second=1000, burst=1000)


class PagedFakeProvider(FakeProvider):
    def __init__(self, total: int = 65) -> None:
        self.total = total
        self.page_calls: list[int] = []

    def search_page(
        self,
        http,
        session,
        query,
        filters,
        *,
        next_url=None,
        metadata_fetch_budget=None,
    ) -> ProviderSearchPage:
        page = int(next_url) if next_url is not None else 1
        self.page_calls.append(page)
        start = (page - 1) * 10
        stop = min(start + 10, self.total)
        results = tuple(
            SearchResult(
                provider=self.key,
                url=f"{CONTENT_PREFIX}result-{index}",
                headline=f"Result {index}: {query}",
            )
            for index in range(start, stop)
        )
        return ProviderSearchPage(
            results=results,
            next_url=str(page + 1) if stop < self.total else None,
        )


class DatedSearchProvider(FakeProvider):
    def search(self, http, session, query, filters: SearchFilters):
        return [
            SearchResult(
                provider=self.key,
                url=f"{CONTENT_PREFIX}undated",
                headline="Undated",
            ),
            SearchResult(
                provider=self.key,
                url=f"{CONTENT_PREFIX}older",
                headline="Older",
                published=datetime(2026, 7, 16, tzinfo=UTC),
            ),
            SearchResult(
                provider=self.key,
                url=f"{CONTENT_PREFIX}newest",
                headline="Newest",
                published=NOW,
            ),
        ][: filters.limit]


def _service(
    tmp_path: Path,
    provider=None,
    *,
    timing: TimingRecorder | None = None,
) -> NewsclipService:
    registry = ProviderRegistry((provider or FakeProvider(),))
    extractor = FakeExtractor()
    archive = ArchiveStore(
        tmp_path / "archive.sqlite3", registry=registry, extractor=extractor
    )
    return NewsclipService(
        registry,
        FakeHttp(),
        extractor,
        archive=archive,
        timing=timing,
    )


def _public_failure(result: dict[str, object]) -> dict[str, object]:
    """Every MCP failure names its invocation; compare the rest exactly."""

    diagnostic_id = result.pop("diagnostic_id")
    assert isinstance(diagnostic_id, str)
    assert re.fullmatch(r"mcp-[a-f0-9]{32}", diagnostic_id)
    return result


def test_concurrent_mcp_calls_have_distinct_timing_invocations(tmp_path: Path) -> None:
    timing = TimingRecorder(tmp_path / "timings")
    service = _service(tmp_path, timing=timing)
    mcp = NewsclipMcp(lambda: service)

    async def run_concurrently() -> None:
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(mcp.get, FULL_URL)
            tasks.start_soon(mcp.get, FULL_URL)

    anyio.run(run_concurrently)

    runs = tuple(iter_timing_runs(timing.root))
    assert len(runs) == 2
    assert None not in {run.invocation_id for run in runs}
    assert len({run.invocation_id for run in runs}) == 2


def test_mcp_matches_library_public_models_and_error_categories(tmp_path: Path) -> None:
    service = _service(tmp_path)
    mcp = NewsclipMcp(lambda: service)

    # Success path: MCP result equals the library's public serialization.
    library_get = service.get(FULL_URL)
    mcp_get = anyio.run(mcp.get, FULL_URL)
    assert mcp_get == {"ok": True, "result": library_get.public_dict()}

    library_search = service.search_many("capital")
    mcp_search = anyio.run(lambda: mcp.search("capital"))
    assert mcp_search == {
        "ok": True,
        "result": library_search.public_dict(),
    }

    # Error path: MCP surfaces the same stable category as the CLI/library.
    mcp_teaser = anyio.run(mcp.get, TEASER_URL)
    assert mcp_teaser["ok"] is False
    assert mcp_teaser["category"] == "content_not_full"
    assert mcp_teaser["exit_code"] == 4
    # ...and the refinement the category cannot express, so a client can tell
    # an unentitled teaser from an edge challenge.
    assert mcp_teaser["reason"] == "paywall_teaser"


def test_mcp_call_tool_roundtrip_is_redaction_safe(tmp_path: Path) -> None:
    service = _service(tmp_path)
    server = NewsclipMcp(lambda: service).build_server()

    contents = anyio.run(lambda: call_tool(server, "get", {"url": FULL_URL}))
    # call_tool returns the content blocks (optionally with a structured payload).
    blocks = contents[0] if isinstance(contents, tuple) else contents
    text = blocks[0].text
    payload = json.loads(text)

    assert payload["ok"] is True
    assert RAW_SENTINEL not in text
    assert COOKIE_SENTINEL not in text


def test_exposed_tools_are_exactly_the_safe_read_surface(tmp_path: Path) -> None:
    service = _service(tmp_path)
    server = NewsclipMcp(lambda: service).build_server()

    tools = anyio.run(list_tools, server)
    names = {tool["name"] for tool in tools}
    by_name = {tool["name"]: tool for tool in tools}
    search_tool = by_name["search"]
    save_tool = by_name["save"]
    archive_search_tool = by_name["archive_search"]

    assert names == set(EXPOSED_TOOLS)
    assert names.isdisjoint(FORBIDDEN_TOOLS)
    assert server.instructions == SERVER_INSTRUCTIONS
    assert "search for current provider discovery" in SERVER_INSTRUCTIONS
    assert "archive_search and archive_get" in SERVER_INSTRUCTIONS
    assert "never performs login" in SERVER_INSTRUCTIONS
    assert "provider" not in search_tool["inputSchema"]["properties"]
    assert {
        "query",
        "providers",
        "limit",
        "published_after",
        "published_before",
        "sort",
    } <= set(search_tool["inputSchema"]["properties"])
    limit_schema = search_tool["inputSchema"]["properties"]["limit"]
    assert limit_schema["default"] == 20
    assert limit_schema["minimum"] == 1
    assert limit_schema["maximum"] == 100
    assert "current-news" in limit_schema["description"]
    sort_schema = search_tool["inputSchema"]["properties"]["sort"]
    assert sort_schema["default"] == "balanced"
    assert "bounded result batch" in sort_schema["description"]
    # The enum may be inlined or referenced via $defs depending on the
    # framework's schema generation; clients see the same values either way.
    sort_enum = (
        sort_schema.get("enum")
        or search_tool["inputSchema"]["$defs"]["SearchSort"]["enum"]
    )
    assert sort_enum == ["balanced", "newest"]
    assert (
        "Current-news"
        in search_tool["inputSchema"]["properties"]["query"]["description"]
    )
    provider_items = search_tool["inputSchema"]["properties"]["providers"]["anyOf"][0][
        "items"
    ]
    assert BUILTIN_PROVIDER_KEYS_PROSE in provider_items["description"]
    assert provider_items["pattern"] == r"^[a-z][a-z0-9_-]{0,31}$"
    assert BUILTIN_PROVIDER_KEYS_PROSE in SERVER_INSTRUCTIONS
    assert "live discovery" in search_tool["description"]
    markdown_schema = save_tool["inputSchema"]["properties"]["markdown_filename"]
    assert "server-side export" in markdown_schema["anyOf"][0]["description"]
    assert "markdown_filename" not in save_tool["inputSchema"].get("required", [])
    assert "server" in (save_tool["description"] or "").casefold()
    assert archive_search_tool["inputSchema"]["properties"]["limit"] == {
        "default": 20,
        "description": (
            "Maximum archived-article summaries to return; defaults to 20."
        ),
        "maximum": 100,
        "minimum": 1,
        # FastMCP 4 omits the auto-generated per-property "title".
        "type": "integer",
    }
    assert "without article bodies" in archive_search_tool["description"]
    assert "article bodies" not in search_tool["outputSchema"].get("description", "")
    assert "body_markdown" not in json.dumps(archive_search_tool["outputSchema"])
    assert "body_markdown" in json.dumps(by_name["archive_get"]["outputSchema"])
    assert all(tool["title"] and tool["outputSchema"] for tool in tools)
    assert all(tool["outputSchema"]["additionalProperties"] is False for tool in tools)

    expected_annotations = {
        "search": (True, False, True, True),
        "get": (False, False, True, True),
        "save": (False, True, False, True),
        "archive_search": (True, False, True, False),
        "archive_get": (True, False, True, False),
        "session_status": (True, False, True, False),
        "reextract": (False, True, True, False),
    }
    assert {
        name: (
            tool["annotations"].get("readOnlyHint"),
            tool["annotations"].get("destructiveHint"),
            tool["annotations"].get("idempotentHint"),
            tool["annotations"].get("openWorldHint"),
        )
        for name, tool in by_name.items()
    } == expected_annotations


def test_mcp_archive_search_is_bounded_summary_and_archive_get_reads_body(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    for index in range(3):
        service.save(f"{CONTENT_PREFIX}archived-{index}")
    mcp = NewsclipMcp(lambda: service)

    found = anyio.run(lambda: mcp.archive_search("fixture", limit=2))

    assert found["ok"] is True
    assert len(found["result"]) == 2
    assert all("body_markdown" not in hit for hit in found["result"])
    assert all("id" in hit and "headline" in hit for hit in found["result"])

    server = mcp.build_server()
    contents = anyio.run(
        lambda: call_tool(server, "archive_search", {"query": "fixture", "limit": 2})
    )
    blocks = contents[0] if isinstance(contents, tuple) else contents
    protocol_result = json.loads(blocks[0].text)
    assert protocol_result == found

    article_id = found["result"][0]["id"]
    retrieved = anyio.run(lambda: mcp.archive_get(article_id))

    assert retrieved["ok"] is True
    assert retrieved["result"]["id"] == article_id
    assert retrieved["result"]["body_markdown"] == "Generated fixture body."


def test_mcp_archive_search_rejects_out_of_range_limits(tmp_path: Path) -> None:
    mcp = NewsclipMcp(lambda: _service(tmp_path))

    too_small = anyio.run(lambda: mcp.archive_search("fixture", limit=0))
    too_large = anyio.run(lambda: mcp.archive_search("fixture", limit=101))

    too_small = _public_failure(too_small)
    assert too_small == {
        "category": "usage",
        "exit_code": 2,
        "message": "invalid request",
        "ok": False,
        "retryable": False,
        "action": "none",
    }
    assert _public_failure(too_large) == too_small


def test_mcp_search_limit_collects_multiple_provider_pages(tmp_path: Path) -> None:
    provider = PagedFakeProvider()
    mcp = NewsclipMcp(lambda: _service(tmp_path, provider))

    fifty = anyio.run(lambda: mcp.search("capital", limit=50))
    all_results = anyio.run(lambda: mcp.search("capital", limit=100))

    assert fifty["ok"] is True
    assert len(fifty["result"]["results"]) == 50
    assert fifty["result"]["has_more"] is True
    assert all_results["ok"] is True
    assert len(all_results["result"]["results"]) == 65
    assert all_results["result"]["has_more"] is False
    assert provider.page_calls == [1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 7]


def test_mcp_search_accepts_newest_sort_and_returns_a_page_local_order(
    tmp_path: Path,
) -> None:
    server = NewsclipMcp(
        lambda: _service(tmp_path, DatedSearchProvider())
    ).build_server()

    contents = anyio.run(
        lambda: call_tool(server, "search", {"query": "capital", "sort": "newest"})
    )

    blocks = contents[0] if isinstance(contents, tuple) else contents
    payload = json.loads(blocks[0].text)
    assert payload["ok"] is True
    assert [result["headline"] for result in payload["result"]["results"]] == [
        "Newest",
        "Older",
        "Undated",
    ]


def test_mcp_search_limit_rejects_out_of_range_values(tmp_path: Path) -> None:
    mcp = NewsclipMcp(lambda: _service(tmp_path))

    too_small = anyio.run(lambda: mcp.search("capital", limit=0))
    too_large = anyio.run(lambda: mcp.search("capital", limit=101))

    too_small = _public_failure(too_small)
    assert too_small == {
        "category": "usage",
        "exit_code": 2,
        "message": "invalid request",
        "ok": False,
        "retryable": False,
        "action": "none",
    }
    assert _public_failure(too_large) == too_small


def test_mcp_save_can_atomically_write_private_server_markdown(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    mcp = NewsclipMcp(lambda: service)

    result = anyio.run(lambda: mcp.save(FULL_URL, "fixture-article.md"))

    destination = tmp_path / "exports" / "fixture-article.md"
    assert result["ok"] is True
    assert isinstance(result["result"], dict)
    assert result["result"]["id"] == "fixture:full-article"
    assert destination.read_text(encoding="utf-8") == "Generated fixture body.\n"
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert str(tmp_path) not in json.dumps(result)


def test_mcp_save_tool_roundtrip_writes_markdown(tmp_path: Path) -> None:
    service = _service(tmp_path)
    server = NewsclipMcp(lambda: service).build_server()

    contents = anyio.run(
        lambda: call_tool(
            server,
            "save",
            {"url": FULL_URL, "markdown_filename": "tool-roundtrip.md"},
        )
    )

    blocks = contents[0] if isinstance(contents, tuple) else contents
    payload = json.loads(blocks[0].text)
    assert payload["ok"] is True
    assert (tmp_path / "exports" / "tool-roundtrip.md").read_text(
        encoding="utf-8"
    ) == "Generated fixture body.\n"


def test_mcp_save_without_filename_remains_archive_only(tmp_path: Path) -> None:
    service = _service(tmp_path)

    result = anyio.run(lambda: NewsclipMcp(lambda: service).save(FULL_URL))

    assert result["ok"] is True
    assert not (tmp_path / "exports").exists()
    assert [article.id for article in service.archive_search("fixture")] == [
        "fixture:full-article"
    ]


@pytest.mark.parametrize(
    "filename",
    [
        "",
        " article.md",
        "article.md ",
        ".",
        "..",
        "../article.md",
        "/tmp/article.md",
        r"..\article.md",
        "article.txt",
        "line\nbreak.md",
    ],
)
def test_mcp_save_rejects_unsafe_filenames_before_archive_work(
    tmp_path: Path,
    filename: str,
) -> None:
    service = _service(tmp_path)

    result = anyio.run(lambda: NewsclipMcp(lambda: service).save(FULL_URL, filename))

    assert _public_failure(result) == {
        "category": "usage",
        "exit_code": 2,
        "message": "invalid request",
        "ok": False,
        "retryable": False,
        "action": "none",
    }
    archive = service._archive
    assert isinstance(archive, ArchiveStore)
    assert archive.inspect_schema()["counts"]["fetches"] == 0
    assert not (tmp_path / "exports").exists()


def test_mcp_save_rejects_a_symlinked_export_root_before_archive_work(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "exports").symlink_to(outside, target_is_directory=True)
    service = _service(tmp_path)

    result = anyio.run(
        lambda: NewsclipMcp(lambda: service).save(FULL_URL, "article.md")
    )

    assert result["category"] == "persistence"
    assert list(outside.iterdir()) == []
    archive = service._archive
    assert isinstance(archive, ArchiveStore)
    assert archive.inspect_schema()["counts"]["fetches"] == 0


def test_mcp_export_failure_preserves_the_committed_archive(tmp_path: Path) -> None:
    export_root = tmp_path / "exports"
    export_root.mkdir()
    (export_root / "blocked.md").mkdir()
    service = _service(tmp_path)

    result = anyio.run(
        lambda: NewsclipMcp(lambda: service).save(FULL_URL, "blocked.md")
    )

    assert result["category"] == "persistence"
    assert [article.id for article in service.archive_search("fixture")] == [
        "fixture:full-article"
    ]


def test_building_the_server_opens_no_listener_and_needs_no_service(
    monkeypatch,
) -> None:
    import socket

    # Ban binding/listening (a real network listener) without breaking the
    # event loop's internal socketpair self-pipe.
    def forbidden_bind(self, *args, **kwargs):
        raise AssertionError("building the MCP server must open no network listener")

    monkeypatch.setattr(socket.socket, "bind", forbidden_bind)
    monkeypatch.setattr(socket.socket, "listen", forbidden_bind)

    def exploding_factory() -> NewsclipService:
        raise AssertionError("server construction must not build the service")

    mcp = NewsclipMcp(exploding_factory)
    server = mcp.build_server()
    tools = anyio.run(list_tools, server)

    assert {tool["name"] for tool in tools} == set(EXPOSED_TOOLS)


def test_mcp_search_surfaces_provider_failure_instead_of_empty_success() -> None:
    class FailingService:
        def search_many(self, query, filters, *, provider_keys):  # noqa: ANN001
            assert provider_keys == ("ft",)
            raise ProviderTransportError("search fixture unavailable")

    mcp = NewsclipMcp(lambda: FailingService())  # type: ignore[arg-type]

    result = anyio.run(lambda: mcp.search("capital", ["ft"]))

    assert _public_failure(result) == {
        "category": "transport",
        "exit_code": 5,
        "message": "provider transport failed",
        "ok": False,
        "retryable": True,
        "action": "retry_later",
    }


def test_mcp_search_publishes_the_coverage_window_a_source_claims(
    tmp_path: Path,
) -> None:
    """A moving-window source discloses its trailing edge on the MCP surface.

    Otherwise a truthful small result count reads as "this source has nothing"
    rather than "this source was only searchable for the last few hours".
    """

    class WindowedProvider(FakeProvider):
        def search_page(self, http, session, query, filters, **kwargs):  # noqa: ANN001
            page = super().search_page(http, session, query, filters, **kwargs)
            return page.model_copy(
                update={"coverage_start": datetime(2026, 7, 21, 10, 34, tzinfo=UTC)}
            )

    windowed = anyio.run(
        lambda: NewsclipMcp(lambda: _service(tmp_path, WindowedProvider())).search(
            "capital", None
        )
    )
    archival = anyio.run(
        lambda: NewsclipMcp(lambda: _service(tmp_path, FakeProvider())).search(
            "capital", None
        )
    )

    assert windowed["ok"] is True
    assert windowed["result"]["sources"][0]["coverage_start"] == (
        "2026-07-21T10:34:00Z"
    )
    assert archival["result"]["sources"][0]["coverage_start"] is None


def test_mcp_search_names_an_unsearchable_query_as_a_request_fault() -> None:
    """An agent must be able to tell "fix your query" from "provider is down"."""

    class RejectingService:
        def search_many(self, query, filters, *, provider_keys):  # noqa: ANN001
            raise UnsearchableQueryError("unsearchable_query")

    mcp = NewsclipMcp(lambda: RejectingService())  # type: ignore[arg-type]

    result = anyio.run(lambda: mcp.search("the and of", ["reuters"]))

    assert _public_failure(result) == {
        "ok": False,
        "retryable": False,
        "action": "none",
        "category": "usage",
        "exit_code": 2,
        "message": "invalid request",
        "reason": "unsearchable_query",
    }


def test_mcp_search_distinguishes_all_sources_from_an_empty_selection(
    tmp_path: Path,
) -> None:
    mcp = NewsclipMcp(lambda: _service(tmp_path))

    all_sources = anyio.run(lambda: mcp.search("capital", None))
    empty_selection = anyio.run(lambda: mcp.search("capital", []))

    assert all_sources["ok"] is True
    assert _public_failure(empty_selection) == {
        "category": "usage",
        "exit_code": 2,
        "message": "invalid request",
        "ok": False,
        "retryable": False,
        "action": "none",
    }


def test_worker_concurrency_never_exceeds_the_configured_bound() -> None:
    dispatcher = WorkerDispatcher(capacity=3)
    release = threading.Event()
    started = threading.Semaphore(0)
    lock = threading.Lock()
    active = {"n": 0, "peak": 0}

    def blocker() -> None:
        with lock:
            active["n"] += 1
            active["peak"] = max(active["peak"], active["n"])
        started.release()
        release.wait(5)
        with lock:
            active["n"] -= 1

    async def main() -> None:
        async with anyio.create_task_group() as group:
            for _ in range(9):
                group.start_soon(dispatcher.run, blocker)
            await anyio.to_thread.run_sync(
                lambda: [started.acquire() for _ in range(3)]
            )
            assert dispatcher.in_flight <= 3
            release.set()

    anyio.run(main)
    assert active["peak"] <= 3


def test_heartbeat_request_stays_responsive_while_a_call_blocks() -> None:
    dispatcher = WorkerDispatcher(capacity=4)
    release = threading.Event()
    entered = threading.Event()

    def blocker() -> None:
        entered.set()
        release.wait(5)

    async def main() -> str:
        result = ""
        async with anyio.create_task_group() as group:
            group.start_soon(dispatcher.run, blocker)
            await anyio.to_thread.run_sync(lambda: entered.wait(5))
            result = await dispatcher.run(lambda: "pong")
            release.set()
        return result

    assert anyio.run(main) == "pong"


def test_service_factory_does_not_block_the_event_loop() -> None:
    started = time.monotonic()
    heartbeat_at: list[float] = []

    def slow_factory() -> NewsclipService:
        time.sleep(0.2)
        raise PersistenceError("fixture factory stop")

    async def heartbeat() -> None:
        await anyio.sleep(0.01)
        heartbeat_at.append(time.monotonic() - started)

    async def main() -> None:
        mcp = NewsclipMcp(slow_factory)
        async with anyio.create_task_group() as group:
            group.start_soon(mcp.session_status, "fixture")
            group.start_soon(heartbeat)

    anyio.run(main)

    assert heartbeat_at[0] < 0.1


def test_concurrent_first_calls_build_the_service_once(tmp_path: Path) -> None:
    calls = 0
    calls_lock = threading.Lock()

    def factory() -> NewsclipService:
        nonlocal calls
        with calls_lock:
            calls += 1
        time.sleep(0.05)
        return _service(tmp_path)

    async def main() -> None:
        mcp = NewsclipMcp(factory)
        async with anyio.create_task_group() as group:
            for _ in range(8):
                group.start_soon(mcp.session_status, "fixture")

    anyio.run(main)

    assert calls == 1


def test_default_mcp_uses_request_scoped_service_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from newsclip import composition

    service = _service(tmp_path)
    monkeypatch.setattr(composition, "build_mcp_service", lambda: service)

    mcp = build_mcp()
    mcp.prepare()

    assert mcp._service is service


def test_service_factory_failure_uses_the_stable_error_envelope() -> None:
    """A broken environment must fail inside the {ok, category, exit_code}
    contract on the very first call, not leak a raw factory exception."""

    from newsclip.errors import PersistenceError

    def broken_factory() -> NewsclipService:
        raise PersistenceError("state root is not writable")

    mcp = NewsclipMcp(broken_factory)
    result = anyio.run(lambda: mcp.session_status("fixture"))

    assert _public_failure(result) == {
        "ok": False,
        "retryable": False,
        "action": "none",
        "category": "persistence",
        "exit_code": 6,
        "message": "persistence operation failed",
    }


def test_composed_mcp_status_uses_serving_authority(tmp_path, monkeypatch) -> None:
    from newsclip.composition import build_mcp_service
    from newsclip.contracts import SessionManager

    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("NEWSCLIP_DATA_HOME", str(tmp_path / "data"))
    mcp = NewsclipMcp(build_mcp_service)
    try:
        result = anyio.run(lambda: mcp.session_status("ft"))
        assert result["ok"] is True
        assert result["result"]["status"] == "required"
        assert not isinstance(mcp._service._sessions, SessionManager)
    finally:
        if mcp._service is not None:
            mcp._service.close()


def test_service_factory_error_text_is_never_public() -> None:
    from newsclip.errors import PersistenceError

    sensitive = (
        "credential@example.com COOKIE_SENTINEL CAPTCHA_TOKEN "
        "op://vault/item /private/profile paid article body"
    )

    def broken_factory() -> NewsclipService:
        raise PersistenceError(sensitive)

    result = anyio.run(lambda: NewsclipMcp(broken_factory).session_status("fixture"))
    serialized = json.dumps(result)

    assert sensitive not in serialized
    assert result["message"] == "persistence operation failed"


def test_error_envelope_is_redaction_safe(tmp_path: Path) -> None:
    from fastmcp.exceptions import ToolError

    service = _service(tmp_path)
    server = NewsclipMcp(lambda: service).build_server()

    with pytest.raises(ToolError) as caught:
        anyio.run(lambda: call_tool(server, "get", {"url": TEASER_URL}))
    text = str(caught.value)

    assert '"ok":false' in text
    assert '"category":"content_not_full"' in text
    assert RAW_SENTINEL not in text
    assert COOKIE_SENTINEL not in text


def test_tool_failure_logs_one_closed_line_instead_of_fastmcp_error(
    tmp_path: Path,
) -> None:
    import logging

    from fastmcp.exceptions import ToolError

    records: list[logging.LogRecord] = []

    class Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    # FastMCP's logger does not propagate to the root (pytest's caplog).
    fastmcp_logger = logging.getLogger("fastmcp")
    handler = Collect(level=logging.DEBUG)
    previous_level = fastmcp_logger.level
    fastmcp_logger.addHandler(handler)
    fastmcp_logger.setLevel(logging.DEBUG)
    try:
        service = _service(tmp_path)
        server = NewsclipMcp(lambda: service).build_server()
        with pytest.raises(ToolError) as caught:
            anyio.run(lambda: call_tool(server, "get", {"url": TEASER_URL}))
    finally:
        fastmcp_logger.removeHandler(handler)
        fastmcp_logger.setLevel(previous_level)

    envelope = json.loads(str(caught.value))
    diagnostic_id = envelope["diagnostic_id"]
    assert re.fullmatch(r"mcp-[a-f0-9]{32}", diagnostic_id)
    failures = [record for record in records if record.name == "fastmcp.newsclip.mcp"]
    assert len(failures) == 1
    assert failures[0].levelno == logging.WARNING
    message = failures[0].getMessage()
    assert message.startswith("tool failed tool=get category=content_not_full ")
    assert f"diagnostic_id={diagnostic_id}" in message
    for private in (TEASER_URL, RAW_SENTINEL, COOKIE_SENTINEL):
        assert private not in message
    # The product failure is not additionally reported as an ERROR.
    assert not [record for record in records if record.levelno >= logging.ERROR]


def test_forbidden_tool_names_track_real_credential_operations(
    tmp_path: Path,
) -> None:
    """Each forbidden name must be a real operation on the credential boundary
    (so the deny-list cannot rot into documentation fiction) and must never be
    exposed as a tool."""

    from newsclip.sessions import SessionStore

    service = _service(tmp_path)
    server = NewsclipMcp(lambda: service).build_server()
    names = {tool["name"] for tool in anyio.run(list_tools, server)}

    for forbidden in FORBIDDEN_TOOLS:
        assert hasattr(NewsclipService, forbidden) or hasattr(
            SessionStore, forbidden
        ), f"{forbidden} no longer names a real operation"
        assert forbidden not in names


def test_native_error_text_omits_unnamed_refinements(tmp_path: Path) -> None:
    """The native error path publishes the same trimmed envelope as the result."""

    service = _service(tmp_path)
    server = NewsclipMcp(lambda: service).build_server()

    with pytest.raises(Exception) as raised:
        anyio.run(lambda: call_tool(server, "get", {"url": "https://other.test/x"}))

    text = str(raised.value)
    assert '"category":"usage"' in text
    assert "null" not in text
    assert "reason" not in text
    assert "incident_id" not in text
