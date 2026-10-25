from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from rich.text import Text
from typer.testing import CliRunner

from newsclip.acquisition import (
    AcquisitionEvidence,
    AcquisitionMode,
    CredentialAction,
    LoginResult,
)
from newsclip.cli import (
    _page_article,
    _pager_exit_hint,
    _prompt_result_choice,
    _render_article_reader,
    _result_choice_prompt,
    app,
)
from newsclip.drift import DriftFinding, DriftReport
from newsclip.errors import ProviderDefenseError, UnsearchableQueryError
from newsclip.models import (
    Article,
    ExtractionMeta,
    SearchFilters,
    SearchResponse,
    SearchResult,
    SearchSort,
    SessionCheckpoint,
    SessionHealth,
    SessionStatus,
    SourceSearchReason,
    SourceSearchReport,
    SourceSearchState,
)

NOW = datetime(2026, 7, 20, tzinfo=UTC)
URLS = (
    "https://alpha.test/article-one",
    "https://beta.test/article-two",
    "https://beta.test/article-three",
)
ARCHIVE_PATH = Path("/tmp/newsclip/archive.sqlite3")


def _response(query: str) -> SearchResponse:
    return SearchResponse(
        query=query,
        results=(
            SearchResult(
                provider="alpha",
                url=URLS[0],
                headline="Alpha article",
                published=NOW,
            ),
            SearchResult(
                provider="beta",
                url=URLS[1],
                headline="Beta article",
            ),
        ),
        sources=(
            SourceSearchReport(
                provider="alpha",
                state=SourceSearchState.OK,
                result_count=1,
            ),
            SourceSearchReport(
                provider="beta",
                state=SourceSearchState.OK,
                result_count=1,
                missing_published_count=1,
            ),
        ),
    )


def _article(url: str) -> Article:
    provider = "alpha" if url == URLS[0] else "beta"
    return Article(
        id=f"{provider}:fixture",
        provider_article_id="fixture",
        url=url,
        canonical_url=url,
        provider=provider,
        headline=f"{provider.title()} article",
        authors=("Fixture Author",),
        published=NOW,
        word_count=4,
        body_markdown="A complete fixture article body.",
        retrieved_at=NOW,
        extraction=ExtractionMeta(
            extractor_name="fixture",
            extractor_version="1",
            raw_sha256="0" * 64,
            assessment_schema_version=1,
            policy_version="fixture-v1",
        ),
    )


class WorkflowService:
    def __init__(
        self,
        *,
        browser_required: bool = False,
        pager_batches: list[SearchResponse] | None = None,
    ) -> None:
        self.browser_required = browser_required
        self.search_calls: list[tuple[str, tuple[str, ...] | None]] = []
        self.search_filters: list[SearchFilters] = []
        self.saved: list[str] = []
        self.opened: list[str] = []
        self.archive_path = ARCHIVE_PATH
        self.pager_batches = pager_batches
        self.pager = None

    def requires_browser_for_search(self, provider_keys) -> bool:
        return self.browser_required

    def requires_browser_runtime(self, provider_keys) -> bool:
        return self.browser_required

    def requires_browser_for_url(self, url: str) -> bool:
        return self.browser_required

    def search_many(
        self,
        query,
        filters,
        *,
        provider_keys,
        acquire_session,
    ) -> SearchResponse:
        assert callable(acquire_session)
        self.search_calls.append((query, provider_keys))
        self.search_filters.append(filters)
        return _response(query)

    def search_pager(
        self,
        query,
        filters,
        *,
        provider_keys,
        acquire_session,
    ):
        assert callable(acquire_session)
        self.search_calls.append((query, provider_keys))
        self.search_filters.append(filters)
        batches = self.pager_batches or [_response(query)]
        self.pager = WorkflowPager(batches)
        return self.pager

    def save(self, url: str, *, acquire_session) -> Article:
        assert callable(acquire_session)
        self.saved.append(url)
        return _article(url)

    def get(self, url: str, *, acquire_session) -> Article:
        assert callable(acquire_session)
        self.opened.append(url)
        return _article(url)

    def login(self, provider: str, **kwargs):  # pragma: no cover - not invoked
        raise AssertionError("fixture operations do not need login")


class WorkflowPager:
    def __init__(self, batches: list[SearchResponse]) -> None:
        self.batches = iter(batches)
        self.next_calls: list[int] = []

    def next_batch(self, size: int) -> SearchResponse:
        self.next_calls.append(size)
        return next(self.batches)


def test_query_first_search_defaults_to_all_enabled_sources(monkeypatch) -> None:
    service = WorkflowService()
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)

    result = CliRunner().invoke(app, ["search", "bank capital", "--json"])

    assert result.exit_code == 0
    assert service.search_calls == [("bank capital", None)]
    assert json.loads(result.stdout) == _response("bank capital").public_dict()
    assert result.stderr == ""


def test_repeated_source_options_preserve_caller_order(monkeypatch) -> None:
    service = WorkflowService()
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)

    result = CliRunner().invoke(
        app,
        [
            "search",
            "rates",
            "--source",
            "beta",
            "-s",
            "alpha",
            "--json",
        ],
    )

    assert result.exit_code == 0
    assert service.search_calls == [("rates", ("beta", "alpha"))]


def test_search_sort_option_reaches_the_shared_search_contract(monkeypatch) -> None:
    service = WorkflowService()
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)

    result = CliRunner().invoke(
        app,
        ["search", "rates", "--sort", "newest", "--json"],
    )

    assert result.exit_code == 0
    assert service.search_filters[0].sort is SearchSort.NEWEST


@pytest.mark.parametrize(
    ("extra", "saved", "opened"),
    [([], [URLS[1]], []), (["--no-save"], [], [URLS[1]])],
)
def test_select_opens_one_result_with_save_as_the_default(
    monkeypatch,
    extra: list[str],
    saved: list[str],
    opened: list[str],
) -> None:
    service = WorkflowService()
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)

    result = CliRunner().invoke(
        app,
        ["search", "rates", "--select", "2", "--json", *extra],
    )

    assert result.exit_code == 0
    assert service.saved == saved
    assert service.opened == opened
    assert json.loads(result.stdout)["url"] == URLS[1]


def test_non_tty_search_lists_results_without_prompting(monkeypatch) -> None:
    service = WorkflowService()
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr(
        "newsclip.cli._prompt_result_choice",
        lambda count: pytest.fail("non-TTY search must not prompt"),
    )

    result = CliRunner().invoke(app, ["search", "rates"])

    assert result.exit_code == 0
    assert "Alpha article" in result.stdout
    assert "Sources:" in result.stdout
    assert "BETA ✓ (1 date unavailable)" in result.stdout


def test_search_footer_explains_failed_source_states(monkeypatch) -> None:
    service = WorkflowService()
    response = SearchResponse(
        query="rates",
        results=(_response("rates").results[0],),
        sources=(
            SourceSearchReport(
                provider="alpha",
                state=SourceSearchState.OK,
                result_count=1,
            ),
            SourceSearchReport(
                provider="beta",
                state=SourceSearchState.NEEDS_ATTENTION,
                result_count=0,
                reason=SourceSearchReason.OPERATOR_ACTION,
            ),
            SourceSearchReport(
                provider="gamma",
                state=SourceSearchState.UNAVAILABLE,
                result_count=0,
                reason=SourceSearchReason.TIMEOUT,
            ),
        ),
    )
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr(service, "search_many", lambda *args, **kwargs: response)

    result = CliRunner().invoke(app, ["search", "rates"])

    assert result.exit_code == 0
    normalized = " ".join(result.stdout.split())
    assert "BETA needs attention (authentication repair required)" in normalized
    assert "GAMMA unavailable (timed out)" in normalized


def test_unsearchable_query_blames_the_query_not_the_provider(monkeypatch) -> None:
    """The footer and the error must both point at the query.

    Reporting a healthy provider as a failed route sent the reader to
    'newsclip doctor' to diagnose nothing.
    """

    service = WorkflowService()
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)

    def reject(*args, **kwargs):
        raise UnsearchableQueryError("unsearchable_query")

    monkeypatch.setattr(service, "search_many", reject)
    result = CliRunner().invoke(app, ["search", "the and of"])

    assert result.exit_code == 2
    assert "invalid request" in result.stderr
    assert "add a distinctive term" in result.stderr
    assert "doctor" not in result.stderr

    # And the per-source footer names the query, not parser drift.
    response = _response("rates").model_copy(
        update={
            "sources": (
                SourceSearchReport(
                    provider="alpha",
                    state=SourceSearchState.UNAVAILABLE,
                    result_count=0,
                    reason=SourceSearchReason.UNSEARCHABLE_QUERY,
                ),
            )
        }
    )
    monkeypatch.setattr(service, "search_many", lambda *a, **k: response)
    footer = CliRunner().invoke(app, ["search", "rates"])

    assert footer.exit_code == 0
    normalized = " ".join(footer.stdout.split())
    assert "ALPHA unavailable (no searchable terms in the query)" in normalized


def test_search_footer_discloses_a_truncated_coverage_window(monkeypatch) -> None:
    """The default surface, not only --json, has to carry the disclosure.

    A bare "✓" beside one result reads as "this source has almost nothing"
    instead of "this source was only searchable for the last few hours".
    """

    service = WorkflowService()
    response = _response("rates")
    response = response.model_copy(
        update={
            "sources": (
                response.sources[0].model_copy(
                    update={"coverage_start": datetime(2026, 7, 21, 10, 34, tzinfo=UTC)}
                ),
                response.sources[1],
            )
        }
    )
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr(service, "search_many", lambda *args, **kwargs: response)

    result = CliRunner().invoke(app, ["search", "rates"])

    assert result.exit_code == 0
    normalized = " ".join(result.stdout.split())
    assert "ALPHA ✓ (searchable from 2026-07-21 10:34Z)" in normalized
    # A source making no coverage claim keeps its existing footer exactly.
    assert "BETA ✓ (1 date unavailable)" in normalized


def test_search_footer_discloses_undated_results_withheld_by_date_bound(
    monkeypatch,
) -> None:
    service = WorkflowService()
    response = _response("rates")
    response = response.model_copy(
        update={
            "sources": (
                response.sources[0].model_copy(update={"undated_excluded_count": 2}),
                response.sources[1],
            )
        }
    )
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr(service, "search_many", lambda *args, **kwargs: response)

    result = CliRunner().invoke(app, ["search", "rates"])

    assert result.exit_code == 0
    normalized = " ".join(result.stdout.split())
    assert "ALPHA ✓ (2 undated results withheld by date filter)" in normalized


def test_search_footer_discloses_that_articles_are_contained(monkeypatch) -> None:
    """A tick beside selectable rows the gate will refuse is a false offer.

    Search and retrieval fail independently, so a provider can answer the
    query and still refuse every article behind an armed cooldown. Without
    this the refusal is only discovered after choosing a result.
    """

    service = WorkflowService()
    response = _response("rates")
    response = response.model_copy(
        update={
            "sources": (
                response.sources[0].model_copy(
                    update={
                        "retrieval_contained_until": datetime(
                            2026, 7, 28, 18, 34, tzinfo=UTC
                        )
                    }
                ),
                response.sources[1],
            )
        }
    )
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr(service, "search_many", lambda *args, **kwargs: response)

    result = CliRunner().invoke(app, ["search", "rates"])

    assert result.exit_code == 0
    normalized = " ".join(result.stdout.split())
    assert "ALPHA ✓ (articles unavailable until 18:34Z)" in normalized
    # An uncontained source is unchanged; the note is never blanket-applied.
    assert "BETA ✓ (1 date unavailable)" in normalized


@pytest.mark.parametrize(
    ("result_count", "expected"),
    [
        (20, "Select article [1–20] · [n] New search · [q] Quit: "),
        (1, "Select article [1] · [n] New search · [q] Quit: "),
        (0, "No articles · [n] New search · [q] Quit: "),
    ],
)
def test_result_choice_prompt_renders_literal_hotkeys(
    result_count: int,
    expected: str,
) -> None:
    prompt = _result_choice_prompt(result_count)

    assert prompt.plain == expected
    assert isinstance(prompt, Text)


def test_result_choice_prompt_exposes_available_page_actions() -> None:
    prompt = _result_choice_prompt(
        40,
        selection_start=21,
        selection_end=40,
        has_more=True,
        has_previous=True,
    )

    assert prompt.plain == (
        "Select article [21–40] · [b] Previous results · [m] More results · "
        "[n] New search · [q] Quit: "
    )


@pytest.mark.parametrize(
    ("sort_order", "action"),
    [
        (SearchSort.BALANCED, "Newest first"),
        (SearchSort.NEWEST, "Balanced sources"),
    ],
)
def test_result_choice_prompt_exposes_the_other_sort_order(
    sort_order: SearchSort,
    action: str,
) -> None:
    prompt = _result_choice_prompt(20, sort_order=sort_order)

    assert prompt.plain == (
        f"Select article [1–20] · [s] {action} · [n] New search · [q] Quit: "
    )


@pytest.mark.parametrize(
    ("entered", "expected"),
    [
        ("1", "1"),
        ("N", "new"),
        ("new", "new"),
        ("Q", "quit"),
        ("quit", "quit"),
    ],
)
def test_result_choice_accepts_numbers_and_named_actions(
    monkeypatch,
    entered: str,
    expected: str,
) -> None:
    monkeypatch.setattr("rich.console.Console.input", lambda self, prompt: entered)

    assert _prompt_result_choice(2) == expected


@pytest.mark.parametrize(
    ("entered", "expected"),
    [("]", "more"), ("more", "more"), ("[", "previous"), ("back", "previous")],
)
def test_result_choice_accepts_available_page_actions(
    monkeypatch,
    entered: str,
    expected: str,
) -> None:
    monkeypatch.setattr("rich.console.Console.input", lambda self, prompt: entered)

    assert _prompt_result_choice(2, has_more=True, has_previous=True) == expected


@pytest.mark.parametrize("entered", ["s", "SORT"])
def test_result_choice_accepts_sort_action(monkeypatch, entered: str) -> None:
    monkeypatch.setattr("rich.console.Console.input", lambda self, prompt: entered)

    assert _prompt_result_choice(2, sort_order=SearchSort.BALANCED) == "sort"


def test_result_choice_reports_state_specific_validation(monkeypatch) -> None:
    entered = iter(["what", "21", "n"])
    messages: list[str] = []
    monkeypatch.setattr(
        "rich.console.Console.input",
        lambda self, prompt: next(entered),
    )
    monkeypatch.setattr(
        "rich.console.Console.print",
        lambda self, message, **kwargs: messages.append(str(message)),
    )

    assert _prompt_result_choice(20) == "new"
    assert messages == [
        "Enter 1–20, n or q.",
        "Choose an article from 1 to 20.",
    ]


def test_empty_result_choice_does_not_invite_article_selection(monkeypatch) -> None:
    entered = iter(["1", "q"])
    messages: list[str] = []
    monkeypatch.setattr(
        "rich.console.Console.input",
        lambda self, prompt: next(entered),
    )
    monkeypatch.setattr(
        "rich.console.Console.print",
        lambda self, message, **kwargs: messages.append(str(message)),
    )

    assert _prompt_result_choice(0) == "quit"
    assert messages == ["There are no articles to open; choose n or q."]


def test_article_reader_is_ansi_free_and_structured(monkeypatch) -> None:
    monkeypatch.setenv("PAGER", "vim -R -")
    monkeypatch.setattr(
        "newsclip.cli.shutil.get_terminal_size",
        lambda fallback: os.terminal_size((88, 24)),
    )

    content = _render_article_reader(
        _article(URLS[0]),
        archive_path=ARCHIVE_PATH,
    )

    assert "\x1b" not in content
    assert "ESC[" not in content
    assert all(line == line.rstrip() for line in content.splitlines())
    assert content.splitlines()[0] == (
        "NEWSCLIP READER  ·  Exit: :q  ·  Back to results"
    )
    assert "Alpha article" in content
    # Terminal-width wrapping may put the archive path on the next line.
    assert "ALPHA  ·  2026-07-20  ·  4 words  ·  Saved to archive:" in content
    assert str(ARCHIVE_PATH) in content
    assert "By Fixture Author" in content
    assert "A complete fixture article body." in content
    assert "End of article" in content


def test_article_pager_uses_safe_non_color_capability_boundary(monkeypatch) -> None:
    paged: list[tuple[str, bool | None]] = []
    monkeypatch.setattr(
        "newsclip.cli.echo_via_pager",
        lambda content, *, color: paged.append((content, color)),
    )

    _page_article(_article(URLS[0]), archive_path=ARCHIVE_PATH)

    assert len(paged) == 1
    assert paged[0][1] is False
    assert "\x1b" not in paged[0][0]


@pytest.mark.parametrize(
    ("pager", "expected"),
    [
        ("vim -R -", "Exit: :q  ·  Back to results"),
        ("/usr/bin/nvim -R -", "Exit: :q  ·  Back to results"),
        ("less -R", "Exit: q  ·  Back to results"),
        ("cat", "Returns automatically to results"),
        ('"unterminated', "Exit: q  ·  Back to results"),
    ],
)
def test_article_reader_reports_the_actual_pager_exit(
    monkeypatch, pager: str, expected: str
) -> None:
    monkeypatch.setenv("PAGER", pager)

    assert _pager_exit_hint() == expected


def test_bare_non_tty_invocation_fails_instead_of_blocking_for_input() -> None:
    result = CliRunner().invoke(app, [])

    assert result.exit_code == 2
    assert result.stderr.splitlines() == [
        "error: invalid request",
        "hint: run 'newsclip --help' for valid arguments",
    ]


def test_bare_interactive_invocation_prompts_for_the_first_query(monkeypatch) -> None:
    service = WorkflowService()
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr("newsclip.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr("newsclip.cli._prompt_search_query", lambda: "rates")
    monkeypatch.setattr(
        "newsclip.cli._prompt_result_choice",
        lambda count, **kwargs: "quit",
    )
    monkeypatch.setattr(
        "newsclip.cli._render_search_response",
        lambda response, **kwargs: None,
    )

    result = CliRunner().invoke(app, [])

    assert result.exit_code == 0
    assert service.search_calls == [("rates", None)]


def test_interactive_selection_returns_to_same_list_and_marks_clipped(
    monkeypatch,
) -> None:
    service = WorkflowService()
    choices = iter(["1", "quit"])
    rendered: list[set[str]] = []
    paged: list[str] = []
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr("newsclip.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr(
        "newsclip.cli._prompt_result_choice",
        lambda count, **kwargs: next(choices),
    )
    monkeypatch.setattr(
        "newsclip.cli._render_search_response",
        lambda response, *, clipped=None, **kwargs: rendered.append(set(clipped or ())),
    )
    monkeypatch.setattr(
        "newsclip.cli._page_article",
        lambda article, *, archive_path: paged.append(str(article.url)),
    )

    result = CliRunner().invoke(app, ["search", "rates"])

    assert result.exit_code == 0
    assert service.search_calls == [("rates", None)]
    assert service.saved == [URLS[0]]
    assert paged == [URLS[0]]
    assert rendered == [set(), {URLS[0]}]


def test_interactive_selection_error_returns_to_same_results(
    monkeypatch,
) -> None:
    service = WorkflowService()
    choices = iter(["1", "2", "quit"])
    attempts: list[str] = []
    rendered: list[set[str]] = []
    paged: list[str] = []
    original_save = service.save

    def save(url: str, *, acquire_session) -> Article:
        attempts.append(url)
        if url == URLS[0]:
            raise ProviderDefenseError(
                "PRIVATE_DEFENSE_SENTINEL",
                provider="alpha",
                retry_after_seconds=600,
            )
        return original_save(url, acquire_session=acquire_session)

    monkeypatch.setattr(service, "save", save)
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr("newsclip.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr(
        "newsclip.cli._prompt_result_choice",
        lambda count, **kwargs: next(choices),
    )
    monkeypatch.setattr(
        "newsclip.cli._render_search_response",
        lambda response, *, clipped=None, **kwargs: rendered.append(set(clipped or ())),
    )
    monkeypatch.setattr(
        "newsclip.cli._page_article",
        lambda article, *, archive_path: paged.append(str(article.url)),
    )

    result = CliRunner().invoke(app, ["search", "rates"])

    assert result.exit_code == 0
    assert attempts == [URLS[0], URLS[1]]
    assert service.saved == [URLS[1]]
    assert paged == [URLS[1]]
    assert rendered == [set(), set(), {URLS[1]}]
    assert result.stderr.splitlines() == [
        "error: ALPHA edge defense refused the request",
        (
            "hint: the provider's edge defense refused the request; wait about "
            "10m before retrying — immediate retries extend the block"
        ),
    ]


def test_interactive_selection_does_not_swallow_unexpected_error(
    monkeypatch,
) -> None:
    service = WorkflowService()
    choices = iter(["1"])
    error = RuntimeError("unexpected selection failure")

    def save(url: str, *, acquire_session) -> Article:
        del url, acquire_session
        raise error

    monkeypatch.setattr(service, "save", save)
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr("newsclip.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr(
        "newsclip.cli._prompt_result_choice",
        lambda count, **kwargs: next(choices),
    )
    monkeypatch.setattr(
        "newsclip.cli._render_search_response",
        lambda response, **kwargs: None,
    )

    result = CliRunner().invoke(app, ["search", "rates"])

    assert result.exit_code == 1
    assert result.exception is error


def test_interactive_sort_toggle_is_local_reversible_and_selects_visible_result(
    monkeypatch,
) -> None:
    response = _response("rates")
    response = response.model_copy(
        update={
            "results": (
                response.results[0].model_copy(
                    update={"published": datetime(2026, 7, 19, tzinfo=UTC)}
                ),
                response.results[1].model_copy(update={"published": NOW}),
            )
        }
    )
    service = WorkflowService(pager_batches=[response])
    choices = iter(["sort", "1", "sort", "1", "quit"])
    rendered: list[tuple[list[str], SearchSort]] = []
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr("newsclip.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr(
        "newsclip.cli._prompt_result_choice",
        lambda count, **kwargs: next(choices),
    )
    monkeypatch.setattr(
        "newsclip.cli._render_search_response",
        lambda response, *, sort_order, **kwargs: rendered.append(
            ([result.headline for result in response.results], sort_order)
        ),
    )
    monkeypatch.setattr("newsclip.cli._page_article", lambda *args, **kwargs: None)

    result = CliRunner().invoke(app, ["search", "rates"])

    assert result.exit_code == 0
    assert service.pager.next_calls == [20]
    assert service.search_filters == [SearchFilters()]
    assert service.saved == [URLS[1], URLS[0]]
    assert rendered == [
        (["Alpha article", "Beta article"], SearchSort.BALANCED),
        (["Beta article", "Alpha article"], SearchSort.NEWEST),
        (["Beta article", "Alpha article"], SearchSort.NEWEST),
        (["Alpha article", "Beta article"], SearchSort.BALANCED),
        (["Alpha article", "Beta article"], SearchSort.BALANCED),
    ]


def test_interactive_sort_option_starts_newest_from_a_balanced_canonical_page(
    monkeypatch,
) -> None:
    response = _response("rates")
    response = response.model_copy(
        update={
            "results": (
                response.results[0].model_copy(
                    update={"published": datetime(2026, 7, 19, tzinfo=UTC)}
                ),
                response.results[1].model_copy(update={"published": NOW}),
            )
        }
    )
    service = WorkflowService(pager_batches=[response])
    rendered: list[tuple[list[str], SearchSort]] = []
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr("newsclip.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr(
        "newsclip.cli._prompt_result_choice",
        lambda count, **kwargs: "quit",
    )
    monkeypatch.setattr(
        "newsclip.cli._render_search_response",
        lambda response, *, sort_order, **kwargs: rendered.append(
            ([result.headline for result in response.results], sort_order)
        ),
    )

    result = CliRunner().invoke(
        app,
        ["search", "rates", "--sort", "newest"],
    )

    assert result.exit_code == 0
    assert service.search_filters == [SearchFilters()]
    assert rendered == [
        (["Beta article", "Alpha article"], SearchSort.NEWEST),
    ]


def test_interactive_sort_applies_to_new_and_cached_pages(monkeypatch) -> None:
    first = _response("rates")
    first = first.model_copy(
        update={
            "results": (
                first.results[0].model_copy(
                    update={"published": datetime(2026, 7, 19, tzinfo=UTC)}
                ),
                first.results[1].model_copy(update={"published": NOW}),
            ),
            "has_more": True,
        }
    )
    second = SearchResponse(
        query="rates",
        results=(
            SearchResult(
                provider="alpha",
                url="https://alpha.test/article-four",
                headline="Fourth article",
                published=datetime(2026, 7, 18, tzinfo=UTC),
            ),
            SearchResult(
                provider="beta",
                url=URLS[2],
                headline="Third article",
                published=datetime(2026, 7, 20, 1, tzinfo=UTC),
            ),
        ),
        sources=first.sources,
    )
    service = WorkflowService(pager_batches=[first, second])
    choices = iter(["sort", "more", "previous", "more", "quit"])
    rendered: list[list[str]] = []
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr("newsclip.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr(
        "newsclip.cli._prompt_result_choice",
        lambda count, **kwargs: next(choices),
    )
    monkeypatch.setattr(
        "newsclip.cli._render_search_response",
        lambda response, **kwargs: rendered.append(
            [result.headline for result in response.results]
        ),
    )

    result = CliRunner().invoke(app, ["search", "rates"])

    assert result.exit_code == 0
    assert service.pager.next_calls == [20, 20]
    assert rendered == [
        ["Alpha article", "Beta article"],
        ["Beta article", "Alpha article"],
        ["Third article", "Fourth article"],
        ["Beta article", "Alpha article"],
        ["Third article", "Fourth article"],
    ]


def test_interactive_search_loads_pages_and_reuses_cached_previous_page(
    monkeypatch,
) -> None:
    first = _response("rates").model_copy(update={"has_more": True})
    second = SearchResponse(
        query="rates",
        results=(
            SearchResult(
                provider="beta",
                url=URLS[2],
                headline="Third article",
                published=NOW,
            ),
        ),
        sources=first.sources,
        has_more=False,
    )
    service = WorkflowService(pager_batches=[first, second])
    choices = iter(["more", "previous", "more", "3", "quit"])
    rendered: list[tuple[list[str], int, int]] = []
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr("newsclip.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr(
        "newsclip.cli._prompt_result_choice",
        lambda count, **kwargs: next(choices),
    )
    monkeypatch.setattr(
        "newsclip.cli._render_search_response",
        lambda response, *, start_index, total_loaded, **kwargs: rendered.append(
            (
                [result.headline for result in response.results],
                start_index,
                total_loaded,
            )
        ),
    )
    monkeypatch.setattr("newsclip.cli._page_article", lambda *args, **kwargs: None)

    result = CliRunner().invoke(app, ["search", "rates"])

    assert result.exit_code == 0
    assert service.pager.next_calls == [20, 20]
    assert service.saved == [URLS[2]]
    assert rendered == [
        (["Alpha article", "Beta article"], 1, 2),
        (["Third article"], 3, 3),
        (["Alpha article", "Beta article"], 1, 3),
        (["Third article"], 3, 3),
        (["Third article"], 3, 3),
    ]


def test_browser_search_preflights_before_search_or_prompt(monkeypatch) -> None:
    service = WorkflowService(browser_required=True)
    preparations: list[list[str]] = []
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    monkeypatch.setattr("newsclip.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr(
        "newsclip.cli._prompt_result_choice",
        lambda count: pytest.fail("delegated child owns the prompt"),
    )

    def prepare(argv, *, required: bool):  # noqa: ANN001
        preparations.append(list(argv))
        return 0

    monkeypatch.setattr("newsclip.cli.maybe_reexec_for_virtual_display", prepare)

    result = CliRunner().invoke(app, ["search", "rates"])

    assert result.exit_code == 0
    assert service.search_calls == []
    assert len(preparations) == 1


def test_auth_group_replaces_hidden_legacy_aliases(monkeypatch) -> None:
    health = SessionHealth(provider="ft", status=SessionStatus.VERIFIED)

    class AuthService:
        def session_status(self, provider: str) -> SessionHealth:
            return health

    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: AuthService())
    runner = CliRunner()

    root_help = runner.invoke(app, ["--help"])
    auth_help = runner.invoke(app, ["auth", "--help"])
    grouped = runner.invoke(app, ["auth", "status", "ft", "--json"])
    legacy = runner.invoke(app, ["session-status", "ft", "--json"])

    assert "session-status" not in root_help.stdout
    assert "login" not in root_help.stdout
    assert "login" in auth_help.stdout
    assert json.loads(grouped.stdout) == health.public_dict()
    assert json.loads(legacy.stdout) == health.public_dict()


def test_human_auth_results_name_the_completed_action(monkeypatch) -> None:
    verified = SessionHealth(
        provider="ft",
        status=SessionStatus.VERIFIED,
        last_verified_at=NOW,
    )
    required = SessionHealth(provider="ft", status=SessionStatus.REQUIRED)
    checkpoint = SessionCheckpoint(
        provider="ft",
        generation_fingerprint="1" * 12,
        created_at=NOW,
        verified_at=NOW,
        checked_at=NOW,
        session_age_seconds=3600,
    )

    class AuthService:
        def login(self, provider: str, **kwargs) -> LoginResult:  # noqa: ANN003
            assert provider == "ft"
            assert kwargs["headless"] is False
            return LoginResult(
                health=verified,
                acquisition=AcquisitionEvidence(
                    mode=AcquisitionMode.CREDENTIAL_MINT,
                    credential_action=CredentialAction.PASSWORD_SUBMIT,
                    session_proof_observed=True,
                ),
            )

        def session_status(self, provider: str) -> SessionHealth:
            return verified

        def requires_browser_for_provider(self, provider: str) -> bool:
            return False

        def session_checkpoint(self, provider: str, **kwargs) -> SessionCheckpoint:
            return checkpoint

        def session_reset(self, provider: str) -> SessionHealth:
            return required

        def session_clear(self, provider: str) -> SessionHealth:
            return required

        def session_acknowledge(self, provider: str) -> SessionHealth:
            return required

        def browser_profile_reset(self, provider: str) -> SessionHealth:
            return required

    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: AuthService())
    runner = CliRunner()

    login_result = runner.invoke(app, ["auth", "login", "ft", "--no-headless"])
    status_result = runner.invoke(app, ["auth", "status", "ft"])
    checkpoint_result = runner.invoke(app, ["auth", "checkpoint", "ft"])
    reset_result = runner.invoke(app, ["auth", "reset", "ft"])
    clear_result = runner.invoke(app, ["auth", "clear", "ft"])
    acknowledge_result = runner.invoke(app, ["auth", "acknowledge", "ft"])
    profile_result = runner.invoke(app, ["auth", "reset-profile", "ft"])

    assert login_result.exit_code == 0
    assert login_result.stdout.splitlines() == [
        "FT login complete",
        "Status: verified",
        "Last verified: 2026-07-20T00:00:00+00:00",
        "Session route: fresh credentials submitted",
    ]
    assert status_result.stdout.splitlines()[:2] == [
        "FT session",
        "Status: verified",
    ]
    assert checkpoint_result.stdout.splitlines()[:3] == [
        "FT session checkpoint passed",
        "Generation: 111111111111",
        "Age: 1.0 hours",
    ]
    assert reset_result.stdout.splitlines() == [
        "FT session state reset",
        "Status: login required",
    ]
    assert clear_result.stdout.splitlines()[0] == "FT session cleared"
    assert acknowledge_result.stdout.splitlines()[0] == (
        "FT session result acknowledged"
    )
    assert profile_result.stdout.splitlines()[0] == "FT browser profile reset"


def test_human_drift_report_summarizes_findings_and_skips(monkeypatch) -> None:
    report = DriftReport(
        source="archive",
        checked=2,
        findings=(
            DriftFinding(
                scope="ft:fixture",
                kind="access_state",
                expected="full",
                actual="teaser",
            ),
        ),
        skipped_providers=("legacy",),
    )

    class DriftService:
        def archive_drift(self, provider: str | None) -> DriftReport:
            assert provider is None
            return report

    monkeypatch.setattr("newsclip.cli.build_service", lambda: DriftService())

    result = CliRunner().invoke(app, ["drift"])

    assert result.exit_code == 0
    normalized = " ".join(result.stdout.split())
    assert "Drift check: 1 finding" in normalized
    assert "Checked: 2 archived revisions" in normalized
    assert "ft:fixture access state full teaser" in normalized
    assert "Skipped unregistered providers: LEGACY" in normalized


def test_doctor_reports_missing_browser_engine(monkeypatch) -> None:
    monkeypatch.setattr("newsclip.cli.shutil.which", lambda name: "/usr/bin/Xvfb")
    monkeypatch.setattr("newsclip.cli.display_is_usable", lambda: False)
    monkeypatch.setattr("newsclip.cli.browser_engine_available", lambda: False)
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "fixture-token")

    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "Browser runtime: Chromium unavailable" in result.stdout
    assert "Next: run `uv run patchright install chromium`." in result.stdout
