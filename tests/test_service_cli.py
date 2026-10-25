from __future__ import annotations

import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from uuid import uuid4

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from newsclip.acquisition import MintFailureCategory, MintFailureStage
from newsclip.archive import SCHEMA_VERSION, ArchiveStore
from newsclip.browser_readiness import (
    BrowserReadinessObservation,
    BrowserSemanticSnapshot,
    ReadinessCoverageBucket,
    ReadinessTerminalState,
)
from newsclip.browser_retrieval import BrowserSnapshotRejected
from newsclip.browser_runtime import BrowserRuntimeError, InfrastructureCategory
from newsclip.cli import _format_retry_delay, app
from newsclip.errors import (
    ContentNotFullError,
    OperatorActionRequiredError,
    PersistenceError,
    ProviderDefenseError,
    ProviderTransportError,
    SessionRequiredError,
    TransportFailure,
    UsageError,
)
from newsclip.incidents import IncidentStore
from newsclip.models import (
    AccessState,
    ArticleAssessment,
    ExtractedArticle,
    PortableCookie,
    ProviderCapabilities,
    ProviderSearchPage,
    RateBudget,
    RawFetch,
    SearchFilters,
    SearchResponse,
    SearchResult,
    SessionArtifact,
    SessionCheckpoint,
    SessionHealth,
    SessionStatus,
    SourceSearchReport,
    SourceSearchState,
)
from newsclip.provenance import BuildIdentity, BuildIdentitySource
from newsclip.providers import ProviderRegistry
from newsclip.providers.builtins import (
    BUILTIN_PROVIDER_KEYS_CSV,
    BUILTIN_PROVIDER_KEYS_PROSE,
)
from newsclip.results import (
    PublicErrorCategory,
    PublicErrorEnvelope,
    PublicErrorMessage,
    PublicErrorReason,
    public_error,
    public_value,
)
from newsclip.service import NewsclipService
from newsclip.timing import (
    StepFinishedEvent,
    TimingOperation,
    TimingOutcome,
    TimingRecorder,
    TimingStep,
    iter_timing_runs,
)

NOW = datetime(2026, 7, 17, tzinfo=UTC)
ARTICLE_ID = "fixture-article"
ARTICLE_URL = f"https://fixture.test/content/{ARTICLE_ID}"


class FakeHttp:
    def __init__(self, *, rejected: bool = False) -> None:
        self.rejected = rejected
        self.calls: list[str] = []

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.calls.append(url)
        marker = b"REJECTED_FIXTURE" if self.rejected else b"RAW_HTML_SENTINEL"
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=session is not None,
            raw_html=marker,
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
            body_markdown="Generated fixture article body.",
            metadata={"title": "Fixture article", "author": ["Fixture Author"]},
            word_count=4,
        )


class FakeProvider:
    key = "fixture"
    capabilities = ProviderCapabilities(requires_session_for_retrieve=False)
    login_recipe = None
    assessment_policy_version = "fixture-v1"
    extraction_scope: tuple[str, ...] | None = None

    def owns_url(self, url: str) -> bool:
        return url.startswith("https://fixture.test/content/")

    def search(
        self,
        http: FakeHttp,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
    ) -> list[SearchResult]:
        return [
            SearchResult(
                provider=self.key,
                url=ARTICLE_URL,
                headline=f"Fixture result for {query}",
            )
        ][: filters.limit]

    def search_page(
        self,
        http: FakeHttp,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
        *,
        next_url: str | None = None,
        metadata_fetch_budget: int | None = None,
    ) -> ProviderSearchPage:
        assert next_url is None
        return ProviderSearchPage(
            results=tuple(self.search(http, session, query, filters))
        )

    def fetch(
        self,
        http: FakeHttp,
        session: SessionArtifact | None,
        url: str,
    ) -> RawFetch:
        return http.get(url, session=session)

    def assess(
        self,
        requested_url: str,
        fetch: RawFetch,
        extraction: ExtractedArticle,
    ) -> ArticleAssessment:
        rejected = b"REJECTED_FIXTURE" in fetch.raw_html
        return ArticleAssessment(
            access_state=AccessState.TEASER if rejected else AccessState.FULL,
            provider_article_id=ARTICLE_ID,
            canonical_url=ARTICLE_URL,
            identity_match=not rejected,
            negative_markers=("paywall",) if rejected else (),
            structural_signals=("fixture_article",) if not rejected else (),
            word_count=extraction.word_count,
            reason="paywall_teaser" if rejected else "full_fixture",
        )

    def rate_budget(self) -> RateBudget:
        return RateBudget(requests_per_second=1, burst=1)


class ChallengeProvider(FakeProvider):
    def assess(
        self,
        requested_url: str,
        fetch: RawFetch,
        extraction: ExtractedArticle,
    ) -> ArticleAssessment:
        return ArticleAssessment(
            access_state=AccessState.BLOCKED,
            provider_article_id=ARTICLE_ID,
            canonical_url=ARTICLE_URL,
            identity_match=True,
            negative_markers=("interactive_challenge",),
            structural_signals=(),
            word_count=extraction.word_count,
            reason="interactive_challenge",
        )


class FailedSearchProvider(FakeProvider):
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
        http.get(f"https://fixture.test/search?q={query}", session=session)
        raise ProviderTransportError("provider search returned HTTP 403")


def _service(
    tmp_path: Path,
    *,
    rejected: bool = False,
    timing: TimingRecorder | None = None,
) -> NewsclipService:
    registry = ProviderRegistry((FakeProvider(),))
    extractor = FakeExtractor()
    archive = ArchiveStore(
        tmp_path / "archive.sqlite3", registry=registry, extractor=extractor
    )
    incidents = IncidentStore(
        tmp_path / "incidents",
        build_identity=BuildIdentity(
            revision="a" * 40,
            dirty=False,
            source_fingerprint="a" * 64,
            source=BuildIdentitySource.ENVIRONMENT,
        ),
        utc_now=lambda: NOW,
    )
    return NewsclipService(
        registry,
        FakeHttp(rejected=rejected),
        extractor,
        archive=archive,
        timing=timing,
        incidents=incidents,
    )


def test_product_search_get_and_save_emit_decision_step_timings(
    tmp_path: Path,
) -> None:
    timing = TimingRecorder(tmp_path / "timings", invocation_id="service-test")
    service = _service(tmp_path, timing=timing)

    service.search_many("capital", provider_keys=("fixture",))
    service.get(ARTICLE_URL)
    service.save(ARTICLE_URL)

    runs = {run.started.operation: run for run in iter_timing_runs(timing.root)}
    assert set(runs) == {
        TimingOperation.SEARCH,
        TimingOperation.GET,
        TimingOperation.SAVE,
    }
    expected = {
        TimingOperation.SEARCH: [
            TimingStep.SESSION_LOAD,
            TimingStep.PROVIDER_SEARCH,
        ],
        TimingOperation.GET: [
            TimingStep.SESSION_LOAD,
            TimingStep.FETCH,
            TimingStep.EXTRACT,
            TimingStep.ASSESS,
            TimingStep.BUILD_ARTICLE,
        ],
        TimingOperation.SAVE: [
            TimingStep.SESSION_LOAD,
            TimingStep.FETCH,
            TimingStep.EXTRACT,
            TimingStep.ASSESS,
            TimingStep.BUILD_ARTICLE,
            TimingStep.ARCHIVE,
        ],
    }
    for operation, run in runs.items():
        assert run.invocation_id == "service-test"
        assert run.finished is not None
        assert run.finished.outcome is TimingOutcome.SUCCESS
        assert [
            event.step
            for record in run.records
            if isinstance((event := record.event), StepFinishedEvent)
        ] == expected[operation]


def test_failed_search_records_last_completed_response_once(tmp_path: Path) -> None:
    provider = FailedSearchProvider()
    registry = ProviderRegistry((provider,))
    incidents = IncidentStore(
        tmp_path / "incidents",
        build_identity=BuildIdentity(
            revision="a" * 40,
            dirty=False,
            source_fingerprint="a" * 64,
            source=BuildIdentitySource.ENVIRONMENT,
        ),
    )
    service = NewsclipService(
        registry,
        FakeHttp(),
        FakeExtractor(),
        incidents=incidents,
    )

    with pytest.raises(ProviderTransportError, match="all selected providers"):
        service.search_many("capital", provider_keys=("fixture",))

    capsules = tuple(incidents.iter_capsules())
    assert len(capsules) == 1
    assert capsules[0].operation is TimingOperation.SEARCH
    capture = incidents.capture_path(capsules[0])
    assert capture is not None
    assert capture.read_bytes() == b"RAW_HTML_SENTINEL"


def test_service_and_cli_share_search_get_save_archive_and_reextract(
    tmp_path: Path, monkeypatch
) -> None:
    service = _service(tmp_path)
    direct_search = service.search_many("capital", provider_keys=("fixture",))
    direct_get = service.get(ARTICLE_URL)
    direct_save = service.save(ARTICLE_URL)
    direct_archive = service.archive_search("fixture article")
    direct_reextract = service.reextract(direct_save.id)
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    runner = CliRunner()

    search_result = runner.invoke(app, ["search", "fixture", "capital", "--json"])
    get_result = runner.invoke(app, ["get", ARTICLE_URL, "--json"])
    save_result = runner.invoke(app, ["save", ARTICLE_URL, "--json"])
    archive_result = runner.invoke(app, ["archive-search", "fixture article", "--json"])
    reextract_result = runner.invoke(app, ["reextract", direct_save.id, "--json"])

    for result in (
        search_result,
        get_result,
        save_result,
        archive_result,
        reextract_result,
    ):
        assert result.exit_code == 0, result.output
        assert "RAW_HTML_SENTINEL" not in result.output
    assert json.loads(search_result.stdout) == direct_search.public_dict()
    assert json.loads(get_result.stdout) == direct_get.public_dict()
    assert json.loads(save_result.stdout) == direct_save.public_dict()
    assert json.loads(archive_result.stdout) == [
        item.public_dict() for item in direct_archive
    ]
    assert json.loads(reextract_result.stdout) == direct_reextract.public_dict()


def test_cli_save_short_output_option_writes_and_reports_markdown(
    tmp_path: Path,
    monkeypatch,
) -> None:
    service = _service(tmp_path)
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    destination = tmp_path / "export" / "fixture.md"

    result = CliRunner().invoke(
        app,
        ["save", ARTICLE_URL, "-o", str(destination)],
    )

    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines() == [
        "Saved: Fixture article",
        "Archive ID: fixture:fixture-article",
        f"Markdown: {destination}",
    ]
    assert destination.read_text(encoding="utf-8") == (
        "Generated fixture article body.\n"
    )


def test_archive_commands_report_outcomes_in_human_terms(
    tmp_path: Path,
    monkeypatch,
) -> None:
    service = _service(tmp_path)
    saved = service.save(ARTICLE_URL)
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    backup = tmp_path / "backups" / "archive.sqlite3"
    runner = CliRunner()

    found = runner.invoke(app, ["archive-search", "fixture article"])
    empty = runner.invoke(app, ["archive-search", "no-match-sentinel"])
    reextracted = runner.invoke(app, ["reextract", saved.id])
    integrity = runner.invoke(app, ["archive-integrity"])
    rebuilt = runner.invoke(app, ["archive-rebuild-fts"])
    backed_up = runner.invoke(app, ["archive-backup", str(backup)])

    class RestoreService:
        def archive_restore(self, source: Path):  # noqa: ANN201
            assert source == backup
            return service.archive_integrity()

    monkeypatch.setattr("newsclip.cli.build_service", lambda: RestoreService())
    restored = runner.invoke(app, ["archive-restore", str(backup)])
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    drift = runner.invoke(app, ["drift"])

    for name, result in (
        ("search", found),
        ("empty search", empty),
        ("reextract", reextracted),
        ("integrity", integrity),
        ("rebuild", rebuilt),
        ("backup", backed_up),
        ("restore", restored),
        ("drift", drift),
    ):
        assert result.exit_code == 0, f"{name}: {result.output}"
    found_text = " ".join(found.stdout.split())
    assert "Archive results for “fixture article”" in found_text
    assert "FIXTURE" in found_text
    assert "Fixture article" in found_text
    assert saved.id in found_text
    assert "1 archived article" in found_text
    assert "Generated fixture article body" not in found.stdout
    assert empty.stdout.strip() == ('No archived articles matched "no-match-sentinel".')
    assert reextracted.stdout.splitlines() == [
        "Re-extracted: Fixture article",
        f"Archive ID: {saved.id}",
    ]
    assert integrity.stdout.splitlines() == [
        "Archive integrity: passed",
        "Foreign-key violations: 0",
        f"Schema version: {SCHEMA_VERSION}",
    ]
    assert rebuilt.stdout.splitlines()[0] == "Archive search index rebuilt"
    assert backed_up.stdout.strip() == f"Archive backup created: {backup}"
    assert restored.stdout.splitlines()[0] == f"Archive restored from {backup}"
    assert drift.stdout.splitlines() == [
        "Drift check: clean",
        "Checked: 1 archived revision",
    ]


def test_cli_save_json_export_remains_path_free(
    tmp_path: Path,
    monkeypatch,
) -> None:
    service = _service(tmp_path)
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    destination = tmp_path / "PRIVATE_PATH_SENTINEL" / "fixture.md"

    result = CliRunner().invoke(
        app,
        ["save", ARTICLE_URL, "--out", str(destination), "--json"],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["id"] == "fixture:fixture-article"
    assert "PRIVATE_PATH_SENTINEL" not in result.stdout
    assert destination.is_file()


def test_cli_search_forwards_aware_publication_bounds(monkeypatch) -> None:
    captured: list[SearchFilters] = []

    class SearchService:
        def requires_browser_for_search(self, provider_keys) -> bool:
            assert provider_keys == ("fixture",)
            return False

        def requires_browser_runtime(self, provider_keys) -> bool:
            assert provider_keys == ("fixture",)
            return False

        def search_many(
            self,
            query: str,
            filters: SearchFilters,
            *,
            provider_keys,
            acquire_session,
        ) -> SearchResponse:
            assert (provider_keys, query) == (("fixture",), "capital")
            assert callable(acquire_session)
            captured.append(filters)
            return SearchResponse(
                query=query,
                results=(),
                sources=(
                    SourceSearchReport(
                        provider="fixture",
                        state=SourceSearchState.OK,
                        result_count=0,
                    ),
                ),
            )

    monkeypatch.setattr("newsclip.cli.build_service", lambda: SearchService())

    result = CliRunner().invoke(
        app,
        [
            "search",
            "fixture",
            "capital",
            "--published-after",
            "2026-07-15T00:00:00+00:00",
            "--published-before",
            "2026-07-17T00:00:00+00:00",
            "--json",
        ],
    )

    assert result.exit_code == 0
    assert captured == [
        SearchFilters(
            published_after=datetime(2026, 7, 15, tzinfo=UTC),
            published_before=datetime(2026, 7, 17, tzinfo=UTC),
        )
    ]

    naive = CliRunner().invoke(
        app,
        [
            "search",
            "fixture",
            "capital",
            "--published-after",
            "2026-07-15T00:00:00",
            "--json",
        ],
    )
    assert naive.exit_code == 2
    assert json.loads(naive.stderr)["category"] == "usage"


def test_archive_maintenance_results_are_typed_and_path_free(
    tmp_path: Path, monkeypatch
) -> None:
    service = _service(tmp_path)
    monkeypatch.setattr("newsclip.cli.build_service", lambda: service)
    backup = tmp_path / "PRIVATE_PROFILE_SENTINEL" / "backup.sqlite3"
    runner = CliRunner()

    integrity = runner.invoke(app, ["archive-integrity", "--json"])
    backed_up = runner.invoke(app, ["archive-backup", str(backup), "--json"])

    assert integrity.exit_code == 0
    assert json.loads(integrity.stdout) == {
        "foreign_key_violations": 0,
        "integrity": "ok",
        "ok": True,
        "user_version": SCHEMA_VERSION,
    }
    assert backed_up.exit_code == 0
    assert json.loads(backed_up.stdout) == {"ok": True}
    assert "PRIVATE_PROFILE_SENTINEL" not in backed_up.stdout
    assert backup.is_file()


def test_public_serialization_rejects_untyped_mappings_even_with_innocent_keys() -> (
    None
):
    with pytest.raises(PersistenceError, match="explicit public serializer"):
        public_value({"detail": "COOKIE_VALUE_SENTINEL"})


class MissingSessions:
    def get_valid_session(
        self, provider: str, account_key: str = "default"
    ) -> SessionArtifact:
        raise SessionRequiredError("explicit login required")


class CheckpointSessions:
    def __init__(self) -> None:
        self.artifact = SessionArtifact(
            generation_id=uuid4(),
            provider="fixture",
            created_at=NOW,
            verified_at=NOW,
            cookies=(
                PortableCookie(
                    name="Session",
                    value="CHECKPOINT_COOKIE_SENTINEL",
                    domain="fixture.test",
                ),
            ),
        )

    def get_valid_session(
        self, provider: str, account_key: str = "default"
    ) -> SessionArtifact:
        return self.artifact


def test_session_checkpoint_verifies_without_minter_and_is_redacted(
    monkeypatch,
) -> None:
    sessions = CheckpointSessions()
    service = NewsclipService(
        ProviderRegistry((FakeProvider(),)),
        FakeHttp(),
        FakeExtractor(),
        sessions=sessions,
        wall_clock=lambda: NOW + timedelta(hours=24),
    )

    checkpoint = service.session_checkpoint("fixture")

    assert checkpoint.session_age_seconds == 24 * 60 * 60
    assert len(checkpoint.generation_fingerprint) == 12
    serialized = json.dumps(checkpoint.public_dict())
    assert "CHECKPOINT_COOKIE_SENTINEL" not in serialized
    assert "cookies" not in serialized

    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: service)
    result = CliRunner().invoke(app, ["session-checkpoint", "fixture", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == checkpoint.public_dict()

    with pytest.raises(SessionRequiredError, match="required checkpoint age"):
        service.session_checkpoint("fixture", minimum_age_hours=24.1)
    with pytest.raises(SessionRequiredError, match="generation does not match"):
        service.session_checkpoint(
            "fixture", expected_generation_fingerprint="000000000000"
        )

    early = CliRunner().invoke(
        app,
        [
            "session-checkpoint",
            "fixture",
            "--minimum-age-hours",
            "25",
            "--json",
        ],
    )
    assert early.exit_code == 3
    assert json.loads(early.stderr)["category"] == "session_required"


def test_browser_checkpoint_prepares_virtual_display(monkeypatch) -> None:
    class BrowserCheckpointService:
        def requires_browser_for_provider(self, provider: str) -> bool:
            assert provider == "fixture"
            return True

        def session_checkpoint(self, provider: str, **kwargs):  # noqa: ANN003
            assert provider == "fixture"
            return SessionCheckpoint(
                provider="fixture",
                generation_fingerprint="0" * 12,
                created_at=NOW,
                verified_at=NOW,
                checked_at=NOW,
                session_age_seconds=0,
            )

    prepared: list[tuple[list[str], bool]] = []
    monkeypatch.setattr(
        "newsclip.cli.build_auth_service", lambda: BrowserCheckpointService()
    )
    monkeypatch.setattr(
        "newsclip.cli._prepare_virtual_display",
        lambda argv, *, child_owns_invocation: prepared.append(
            (list(argv), child_owns_invocation)
        ),
    )

    result = CliRunner().invoke(app, ["session-checkpoint", "fixture", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["provider"] == "fixture"
    assert len(prepared) == 1
    assert prepared[0][1] is True


def test_get_and_save_without_session_never_start_acquisition(tmp_path: Path) -> None:
    provider = FakeProvider()
    provider.capabilities = ProviderCapabilities(requires_session_for_retrieve=True)
    registry = ProviderRegistry((provider,))
    http = FakeHttp()
    archive = ArchiveStore(tmp_path / "archive.sqlite3")
    service = NewsclipService(
        registry,
        http,
        FakeExtractor(),
        sessions=MissingSessions(),
        archive=archive,
    )

    with pytest.raises(SessionRequiredError):
        service.get(ARTICLE_URL)
    with pytest.raises(SessionRequiredError):
        service.save(ARTICLE_URL)

    assert http.calls == []
    assert archive.inspect_schema()["counts"]["fetches"] == 0


def test_rejected_save_records_diagnostic_but_no_fts_or_export(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path, rejected=True)
    destination = tmp_path / "rejected.md"

    with pytest.raises(ContentNotFullError, match="paywall_teaser"):
        service.save(ARTICLE_URL, out=destination)

    assert not destination.exists()
    assert service.archive_search("fixture") == []
    archive = service._archive
    assert isinstance(archive, ArchiveStore)
    assert archive.inspect_schema()["counts"] == {
        "articles": 0,
        "fetches": 1,
        "extractions": 0,
        "extraction_assessments": 0,
        "article_fts": 0,
    }


def test_rejected_get_and_save_write_deduplicated_private_incidents(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path, rejected=True)

    with pytest.raises(ContentNotFullError):
        service.get(ARTICLE_URL)
    with pytest.raises(ContentNotFullError):
        service.get(ARTICLE_URL)
    with pytest.raises(ContentNotFullError):
        service.save(ARTICLE_URL)

    capsules = tuple(service._incidents.iter_capsules())
    assert [capsule.operation for capsule in capsules] == [
        TimingOperation.GET,
        TimingOperation.SAVE,
    ]
    for capsule in capsules:
        capture = service._incidents.capture_path(capsule)
        assert capture is not None
        assert capture.read_bytes() == b"REJECTED_FIXTURE"


def test_readiness_rejection_retains_terminal_private_incident(
    tmp_path: Path,
) -> None:
    fetch = RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        raw_html=b"REJECTED_FIXTURE",
    )
    snapshot = BrowserSemanticSnapshot(
        document_url=ARTICLE_URL,
        content=fetch.raw_html,
        observation=BrowserReadinessObservation(
            ready=False,
            assessment_promotable=True,
            content_fingerprint="a" * 64,
            word_count=773,
            coverage_bucket=ReadinessCoverageBucket.FROM_75_TO_89,
        ),
        stabilized=False,
        terminal_state=ReadinessTerminalState.PROMOTABLE_INCOMPLETE_TIMEOUT,
        content_change_count=0,
        last_content_change_ms=2_989,
    )

    class RejectedReadinessHttp(FakeHttp):
        def get(
            self,
            url: str,
            *,
            session: SessionArtifact | None = None,
            timeout: float = 40,
        ) -> RawFetch:
            raise BrowserSnapshotRejected(fetch=fetch, snapshot=snapshot)

    registry = ProviderRegistry((FakeProvider(),))
    extractor = FakeExtractor()
    incidents = IncidentStore(
        tmp_path / "incidents",
        build_identity=BuildIdentity(
            revision="a" * 40,
            dirty=False,
            source_fingerprint="a" * 64,
            source=BuildIdentitySource.ENVIRONMENT,
        ),
        utc_now=lambda: NOW,
    )
    service = NewsclipService(
        registry,
        RejectedReadinessHttp(),
        extractor,
        archive=ArchiveStore(
            tmp_path / "archive.sqlite3",
            registry=registry,
            extractor=extractor,
        ),
        incidents=incidents,
    )

    with pytest.raises(
        ContentNotFullError,
        match="browser_semantic_readiness_timeout",
    ):
        service.get(ARTICLE_URL)

    (capsule,) = tuple(incidents.iter_capsules())
    assert capsule.operation is TimingOperation.GET
    assert capsule.readiness is not None
    assert capsule.readiness.state is (
        ReadinessTerminalState.PROMOTABLE_INCOMPLETE_TIMEOUT
    )
    assert capsule.readiness.word_count == 773
    assert capsule.readiness.coverage_bucket is (ReadinessCoverageBucket.FROM_75_TO_89)
    assert capsule.readiness.content_change_count == 0
    assert capsule.readiness.last_content_change_ms == 2_989
    capture = incidents.capture_path(capsule)
    assert capture is not None
    assert capture.read_bytes() == b"REJECTED_FIXTURE"


def test_save_records_closed_content_failure_evidence(tmp_path: Path) -> None:
    timing = TimingRecorder(tmp_path / "timings", invocation_id="content-failure")
    service = _service(tmp_path, rejected=True, timing=timing)

    with pytest.raises(ContentNotFullError, match="paywall_teaser"):
        service.save(ARTICLE_URL)

    run = next(iter_timing_runs(timing.root))
    assert run.finished is not None
    assert run.finished.failure_stage is MintFailureStage.PAID_PROBE
    assert run.finished.failure_category is MintFailureCategory.ARTICLE_NOT_FULL


def test_save_records_direct_challenge_failure_evidence(tmp_path: Path) -> None:
    timing = TimingRecorder(tmp_path / "timings", invocation_id="challenge-failure")
    provider = ChallengeProvider()
    registry = ProviderRegistry((provider,))
    extractor = FakeExtractor()
    service = NewsclipService(
        registry,
        FakeHttp(),
        extractor,
        archive=ArchiveStore(
            tmp_path / "archive.sqlite3", registry=registry, extractor=extractor
        ),
        timing=timing,
    )

    with pytest.raises(ContentNotFullError, match="interactive_challenge"):
        service.save(ARTICLE_URL)

    run = next(iter_timing_runs(timing.root))
    assert run.finished is not None
    assert run.finished.failure_stage is MintFailureStage.CHALLENGE
    assert run.finished.failure_category is MintFailureCategory.CHALLENGE_BLOCKED


def test_non_owned_url_is_rejected_before_http_or_archive(tmp_path: Path) -> None:
    registry = ProviderRegistry((FakeProvider(),))
    http = FakeHttp()
    archive = ArchiveStore(tmp_path / "archive.sqlite3")
    service = NewsclipService(registry, http, FakeExtractor(), archive=archive)

    with pytest.raises(UsageError):
        service.get("https://evil.test/content/fixture")
    with pytest.raises(UsageError):
        service.save("https://evil.test/content/fixture")

    assert http.calls == []
    assert archive.inspect_schema()["counts"]["fetches"] == 0


@pytest.mark.parametrize(
    ("error", "expected_exit"),
    [
        (UsageError("usage_fixture"), 2),
        (SessionRequiredError("session_fixture"), 3),
        (ContentNotFullError("content_fixture"), 4),
        (ProviderTransportError("transport_fixture"), 5),
        (PersistenceError("persistence_fixture"), 6),
    ],
)
def test_cli_maps_stable_exit_categories(
    monkeypatch, error: Exception, expected_exit: int
) -> None:
    class FailingService:
        def requires_browser_for_url(self, url: str) -> bool:
            return False

        def get(self, url: str, **kwargs):
            assert callable(kwargs["acquire_session"])
            raise error

    monkeypatch.setattr("newsclip.cli.build_service", lambda: FailingService())

    result = CliRunner().invoke(app, ["get", ARTICLE_URL, "--json"])

    assert result.exit_code == expected_exit
    assert str(error) not in result.stderr
    assert json.loads(result.stderr)["ok"] is False


def test_cli_search_surfaces_provider_failure_instead_of_empty_success(
    monkeypatch,
) -> None:
    class FailingService:
        def requires_browser_for_search(self, provider_keys):  # noqa: ANN001
            assert provider_keys == ("ft",)
            return False

        def requires_browser_runtime(self, provider_keys):  # noqa: ANN001
            assert provider_keys == ("ft",)
            return False

        def search_many(
            self,
            query,  # noqa: ANN001
            filters,  # noqa: ANN001
            *,
            provider_keys,  # noqa: ANN001
            acquire_session,  # noqa: ANN001
        ):
            assert query == "capital"
            assert provider_keys == ("ft",)
            assert callable(acquire_session)
            raise ProviderTransportError("search fixture unavailable")

    monkeypatch.setattr("newsclip.cli.build_service", lambda: FailingService())

    result = CliRunner().invoke(app, ["search", "ft", "capital", "--json"])

    assert result.exit_code == 5
    assert json.loads(result.stderr) == {
        "category": "transport",
        "exit_code": 5,
        "message": "provider transport failed",
        "ok": False,
        "retryable": True,
        "action": "retry_later",
    }


def test_cli_search_legacy_argument_error_uses_public_envelope() -> None:
    result = CliRunner().invoke(
        app,
        ["search", "ft", "query", "--source", "wsj"],
    )

    assert result.exit_code == 2
    assert result.stderr.splitlines() == [
        "error: invalid request",
        "hint: run 'newsclip --help' for valid arguments",
    ]
    assert "Traceback" not in result.stderr
    assert "cli.py" not in result.stderr


@pytest.mark.parametrize(
    ("error", "category", "retryable", "action"),
    [
        (UsageError("usage_fixture"), "usage", False, "none"),
        (
            OperatorActionRequiredError(
                "PRIVATE_OPERATOR_SENTINEL",
                provider="ft",
                reason_code="credential_credential_rejected",
            ),
            "operator_action",
            False,
            "human_account_check",
        ),
        (
            SessionRequiredError("session_fixture"),
            "session_required",
            False,
            "none",
        ),
        (
            ContentNotFullError("unknown_layout"),
            "content_not_full",
            False,
            "none",
        ),
        (
            ProviderDefenseError(
                "PRIVATE_DEFENSE_SENTINEL",
                provider="reuters",
                reason_code="challenge_challenge_blocked",
            ),
            "provider_defense",
            True,
            "retry_later",
        ),
        (
            ProviderTransportError(
                "timeout_fixture", category=TransportFailure.TIMEOUT
            ),
            "timeout",
            True,
            "retry_later",
        ),
        (
            ProviderTransportError("dns_fixture", category=TransportFailure.DNS),
            "dns",
            True,
            "retry_later",
        ),
        (PersistenceError("archive_fixture"), "persistence", False, "none"),
    ],
)
def test_cli_json_failures_are_structured_and_redaction_safe(
    monkeypatch, error: Exception, category: str, retryable: bool, action: str
) -> None:
    class FailingService:
        def requires_browser_for_url(self, url: str) -> bool:
            return False

        def get(self, url: str, **kwargs):
            assert callable(kwargs["acquire_session"])
            raise error

    monkeypatch.setattr("newsclip.cli.build_service", lambda: FailingService())

    result = CliRunner().invoke(app, ["get", ARTICLE_URL, "--json"])
    payload = json.loads(result.stderr)

    assert payload == {
        "category": category,
        "exit_code": result.exit_code,
        "message": {
            "usage": "invalid request",
            "operator_action": "operator action required",
            "session_required": "session required",
            "content_not_full": "content did not verify as full",
            "provider_defense": "provider defense active",
            "timeout": "provider transport failed",
            "dns": "provider transport failed",
            "persistence": "persistence operation failed",
        }[category],
        "ok": False,
        "retryable": retryable,
        "action": action,
    }
    assert "RAW_HTML_SENTINEL" not in result.stderr
    assert "COOKIE_VALUE_SENTINEL" not in result.stderr
    assert "PRIVATE_DEFENSE_SENTINEL" not in result.stderr


@pytest.mark.parametrize(
    ("error", "expected_hint"),
    [
        (UsageError("PRIVATE_USAGE_SENTINEL"), "newsclip --help"),
        (
            OperatorActionRequiredError("PRIVATE_OPERATOR_SENTINEL"),
            "auth status <provider>",
        ),
        (SessionRequiredError("PRIVATE_SESSION_SENTINEL"), "auth login PROVIDER"),
        (ContentNotFullError("PRIVATE_CONTENT_SENTINEL"), "no archive revision"),
        (
            ContentNotFullError("interactive_challenge"),
            "interactive challenge",
        ),
        (
            ContentNotFullError("browser_semantic_readiness_timeout"),
            "did not finish rendering",
        ),
        (
            ContentNotFullError("paywall_teaser"),
            "served a partial body",
        ),
        (
            ContentNotFullError("insufficient_article_structure"),
            "could not verify as whole",
        ),
        (
            ProviderTransportError(
                "PRIVATE_TIMEOUT_SENTINEL",
                category=TransportFailure.TIMEOUT,
            ),
            "provider timed out",
        ),
        (
            ProviderTransportError(
                "PRIVATE_DNS_SENTINEL",
                category=TransportFailure.DNS,
            ),
            "check DNS",
        ),
        (ProviderTransportError("PRIVATE_TRANSPORT_SENTINEL"), "newsclip doctor"),
        (PersistenceError("PRIVATE_PERSISTENCE_SENTINEL"), "data permissions"),
    ],
)
def test_cli_human_failures_include_a_safe_next_step(
    monkeypatch,
    error: Exception,
    expected_hint: str,
) -> None:
    class FailingService:
        def requires_browser_for_url(self, url: str) -> bool:
            return False

        def get(self, url: str, **kwargs):
            raise error

    monkeypatch.setattr("newsclip.cli.build_service", lambda: FailingService())

    result = CliRunner().invoke(app, ["get", ARTICLE_URL])

    assert result.exit_code in {2, 3, 4, 5, 6}
    assert expected_hint in result.stderr
    # Closed reasons refine the hint; they must not appear as the public error
    # line and arbitrary exception text still stays redacted.
    if str(error) == "interactive_challenge":
        assert "content did not verify as full" in result.stderr
        assert "session" not in result.stderr.casefold()
        assert "do not retry blindly" in result.stderr
    elif str(error) == "browser_semantic_readiness_timeout":
        assert "content did not verify as full" in result.stderr
        assert "existing session was preserved" in result.stderr
        assert "no login was attempted" in result.stderr
        assert str(error) not in result.stderr
    else:
        assert str(error) not in result.stderr


def test_cli_credential_rejection_names_provider_and_safe_recovery(
    monkeypatch,
) -> None:
    error = OperatorActionRequiredError(
        "PRIVATE_OPERATOR_SENTINEL",
        provider="ft",
        reason_code="credential_credential_rejected",
    )

    class FailingService:
        def requires_browser_for_url(self, url: str) -> bool:
            return False

        def get(self, url: str, **kwargs):
            raise error

    monkeypatch.setattr("newsclip.cli.build_service", lambda: FailingService())

    result = CliRunner().invoke(app, ["get", ARTICLE_URL])

    assert result.exit_code == 3
    assert result.stderr.splitlines() == [
        "error: FT sign-in credentials were rejected",
        (
            "hint: verify the FT credentials manually and correct the stored "
            "credentials; then run 'uv run newsclip auth reset ft' followed by "
            "one 'uv run newsclip auth login ft'"
        ),
    ]
    assert str(error) not in result.stderr


def test_cli_challenge_operator_action_avoids_login_retry_hint(
    monkeypatch,
) -> None:
    error = OperatorActionRequiredError(
        "PRIVATE_OPERATOR_SENTINEL",
        provider="ft",
        reason_code="challenge_challenge_blocked",
    )

    class FailingService:
        def requires_browser_for_url(self, url: str) -> bool:
            return False

        def get(self, url: str, **kwargs):
            raise error

    monkeypatch.setattr("newsclip.cli.build_service", lambda: FailingService())

    result = CliRunner().invoke(app, ["get", ARTICLE_URL])

    assert result.exit_code == 3
    assert result.stderr.splitlines() == [
        "error: FT returned an interactive challenge",
        (
            "hint: preserve the first FT failure and review its retained evidence; "
            "do not reset or retry blindly"
        ),
    ]
    assert "auth login" not in result.stderr
    assert str(error) not in result.stderr


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (5893, "1h 38m"),
        (7200, "2h"),
        (1200, "20m"),
        (45, "45s"),
        # A sub-second remainder is still a wait, never "0s".
        (0.2, "1s"),
    ],
)
def test_retry_delay_renders_as_a_short_duration(
    seconds: float,
    expected: str,
) -> None:
    assert _format_retry_delay(seconds) == expected


def test_cli_defense_refusal_tells_the_operator_how_long_to_wait(
    monkeypatch,
) -> None:
    error = ProviderDefenseError(
        "PRIVATE_DEFENSE_SENTINEL",
        provider="reuters",
        retry_after_seconds=5893,
    )

    class FailingService:
        def requires_browser_for_url(self, url: str) -> bool:
            return False

        def get(self, url: str, **kwargs):
            raise error

    monkeypatch.setattr("newsclip.cli.build_service", lambda: FailingService())

    result = CliRunner().invoke(app, ["get", ARTICLE_URL])

    assert result.exit_code == 5
    assert result.stderr.splitlines() == [
        "error: REUTERS edge defense refused the request",
        (
            "hint: the provider's edge defense refused the request; wait about "
            "1h 38m before retrying — immediate retries extend the block"
        ),
    ]
    assert str(error) not in result.stderr


def test_cli_defense_refusal_without_a_known_wait_keeps_the_generic_hint(
    monkeypatch,
) -> None:
    """An unbounded refusal must not invent a duration it was never given."""

    error = ProviderDefenseError("PRIVATE_DEFENSE_SENTINEL", provider="reuters")

    class FailingService:
        def requires_browser_for_url(self, url: str) -> bool:
            return False

        def get(self, url: str, **kwargs):
            raise error

    monkeypatch.setattr("newsclip.cli.build_service", lambda: FailingService())

    result = CliRunner().invoke(app, ["get", ARTICLE_URL])

    assert result.exit_code == 5
    assert result.stderr.splitlines() == [
        "error: REUTERS edge defense refused the request",
        (
            "hint: the provider's edge defense refused the request; wait and "
            "retry later — immediate retries extend the block"
        ),
    ]
    assert "wait about" not in result.stderr


def test_cli_error_envelope_never_serializes_neutral_exception_text(
    monkeypatch,
) -> None:
    sensitive = (
        "credential@example.com COOKIE_SENTINEL CAPTCHA_TOKEN "
        "op://vault/item /private/profile paid article body"
    )

    class FailingService:
        def requires_browser_for_url(self, url: str) -> bool:
            return False

        def get(self, url: str, **kwargs):
            assert callable(kwargs["acquire_session"])
            raise PersistenceError(sensitive)

    monkeypatch.setattr("newsclip.cli.build_service", lambda: FailingService())
    result = CliRunner().invoke(app, ["get", ARTICLE_URL, "--json"])

    assert result.exit_code == 6
    assert sensitive not in result.stderr
    assert json.loads(result.stderr)["message"] == "persistence operation failed"


def test_mcp_command_maps_deferred_optional_import_failure(monkeypatch) -> None:
    def missing_mcp() -> None:
        raise ModuleNotFoundError("No module named 'mcp'", name="mcp")

    # Exercise the deferred boundary without importing either optional dependency.
    mcp_server = ModuleType("newsclip.mcp_server")
    mcp_server.run_stdio = missing_mcp
    monkeypatch.setitem(sys.modules, "newsclip.mcp_server", mcp_server)

    result = CliRunner().invoke(app, ["mcp"])

    assert result.exit_code == 2
    assert result.stderr.splitlines() == [
        "error: invalid request",
        "hint: install optional dependencies with 'uv sync --extra mcp'",
    ]


def test_mcp_install_hint_does_not_mask_other_failure_categories(monkeypatch) -> None:
    def failed_state() -> None:
        raise PersistenceError("PRIVATE_MCP_STATE_SENTINEL")

    mcp_server = ModuleType("newsclip.mcp_server")
    mcp_server.run_stdio = failed_state
    monkeypatch.setitem(sys.modules, "newsclip.mcp_server", mcp_server)

    result = CliRunner().invoke(app, ["mcp"])

    assert result.exit_code == 6
    assert "data permissions" in result.stderr
    assert "uv sync --extra mcp" not in result.stderr
    assert "PRIVATE_MCP_STATE_SENTINEL" not in result.stderr


def test_public_error_envelope_rejects_extra_or_inconsistent_facts() -> None:
    valid = {
        "category": "persistence",
        "exit_code": 6,
        "message": "persistence operation failed",
    }

    with pytest.raises(ValidationError, match="extra_forbidden"):
        PublicErrorEnvelope.model_validate({**valid, "diagnostic": "SECRET"})
    with pytest.raises(ValidationError, match="do not match category"):
        PublicErrorEnvelope.model_validate({**valid, "exit_code": 5})
    with pytest.raises(ValidationError):
        PublicErrorEnvelope.model_validate({**valid, "category": "other"})


def test_cli_help_explains_provider_browser_and_restore_contracts() -> None:
    runner = CliRunner()
    root = runner.invoke(app, ["--help"])
    login_help = runner.invoke(app, ["auth", "login", "--help"])
    restore = runner.invoke(app, ["archive-restore", "--help"])

    assert root.exit_code == 0
    assert login_help.exit_code == 0
    assert restore.exit_code == 0
    # Rich styles help text with ANSI escapes inside option tokens when color
    # is forced (as on CI), so assert against the unstyled text.
    plain_root = re.sub(r"\x1b\[[0-9;]*m", "", root.stdout)
    plain_login = re.sub(r"\x1b\[[0-9;]*m", "", login_help.stdout)
    plain_restore = re.sub(r"\x1b\[[0-9;]*m", "", restore.stdout)
    normalized_login = " ".join(plain_login.split())
    normalized_login_text = " ".join(re.sub(r"[│╭╮╰╯─]+", " ", plain_login).split())
    normalized_restore = " ".join(plain_restore.split())
    # The epilog wraps across terminal lines once the catalog is long enough, so
    # compare against the whitespace-normalized text as the prose assertion does.
    normalized_root_text = " ".join(re.sub(r"[│╭╮╰╯─]+", " ", plain_root).split())
    assert f"Built-in providers: {BUILTIN_PROVIDER_KEYS_CSV}" in normalized_root_text
    assert BUILTIN_PROVIDER_KEYS_PROSE in normalized_login_text
    assert "--solver" not in plain_login
    assert "--import-cookies" in plain_login
    assert "--import-stdin" in plain_login
    assert "--headless" in plain_login
    assert "Ensure a verified session" in normalized_login
    assert "explicitly uses the" in normalized_login
    assert "current desktop" in normalized_login
    assert "schema-1 or current-schema SQLite backup" in normalized_restore


def test_headless_login_does_not_eagerly_prepare_browser(monkeypatch) -> None:
    health = SessionHealth(
        provider="ft",
        account_key="default",
        status=SessionStatus.VERIFIED,
    )

    class WarmService:
        def login(self, provider: str, **kwargs):
            assert provider == "ft"
            assert kwargs["before_browser"] is not None
            return health

    def unexpected_preparation(*args, **kwargs):
        raise AssertionError("warm login must not prepare a browser surface")

    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: WarmService())
    monkeypatch.setattr(
        "newsclip.cli.maybe_reexec_for_virtual_display",
        unexpected_preparation,
    )

    result = CliRunner().invoke(app, ["login", "ft", "--headless", "--json"])

    assert result.exit_code == 0


def test_headless_cookie_import_exposes_lazy_surface_preparation(
    tmp_path: Path, monkeypatch
) -> None:
    cookie_file = tmp_path / "cookies.json"
    cookie_file.write_text(
        json.dumps(
            [
                {
                    "name": "Session",
                    "value": "fixture",
                    "domain": ".fixture.test",
                }
            ]
        ),
        encoding="utf-8",
    )
    prepared = 0
    health = SessionHealth(
        provider="fixture",
        account_key="default",
        status=SessionStatus.VERIFIED,
    )

    class ImportService:
        def login(self, provider: str, **kwargs):
            assert provider == "fixture"
            assert kwargs["headless"] is True
            assert kwargs["cookie_payload"][0]["name"] == "Session"
            assert kwargs["before_browser"] is not None
            kwargs["before_browser"]()
            return health

    def prepare(argv, *, required: bool):  # noqa: ANN001
        nonlocal prepared
        assert required is True
        prepared += 1
        return None

    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: ImportService())
    monkeypatch.setattr("newsclip.cli.maybe_reexec_for_virtual_display", prepare)

    result = CliRunner().invoke(
        app,
        [
            "login",
            "fixture",
            "--headless",
            "--import-cookies",
            str(cookie_file),
            "--json",
        ],
    )

    assert result.exit_code == 0
    assert prepared == 1


def test_cookie_import_from_stdin_is_bounded_and_not_echoed(monkeypatch) -> None:
    sentinel = "PRIVATE_COOKIE_VALUE_SENTINEL"
    health = SessionHealth(
        provider="fixture",
        account_key="default",
        status=SessionStatus.VERIFIED,
    )

    class ImportService:
        def requires_browser_for_provider(self, provider: str) -> bool:
            assert provider == "fixture"
            return False

        def login(self, provider: str, **kwargs):
            assert provider == "fixture"
            assert kwargs["cookie_payload"][0]["value"] == sentinel
            return health

    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: ImportService())
    payload = json.dumps(
        [{"name": "Session", "value": sentinel, "domain": ".fixture.test"}]
    )

    result = CliRunner().invoke(
        app,
        ["auth", "login", "fixture", "--import-stdin", "--json"],
        input=payload,
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "verified"
    assert sentinel not in result.stdout
    assert sentinel not in result.stderr


def test_cookie_import_rejects_file_and_stdin_together(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cookie_file = tmp_path / "cookies.json"
    cookie_file.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        "newsclip.cli.build_auth_service",
        lambda: pytest.fail("ambiguous import must stop before service construction"),
    )

    result = CliRunner().invoke(
        app,
        [
            "auth",
            "login",
            "ft",
            "--import-cookies",
            str(cookie_file),
            "--import-stdin",
            "--json",
        ],
        input="[]",
    )

    assert result.exit_code == 2
    assert json.loads(result.stderr)["category"] == "usage"


@pytest.mark.parametrize(
    "payload",
    (
        "not-json",
        " " * (1024 * 1024 + 1),
        "[" * 10_000 + "]" * 10_000,
    ),
    ids=("invalid-json", "over-limit", "excessive-nesting"),
)
def test_cookie_import_stdin_fails_closed(
    payload: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ImportService:
        def requires_browser_for_provider(self, provider: str) -> bool:
            del provider
            return False

    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: ImportService())

    result = CliRunner().invoke(
        app,
        ["auth", "login", "ft", "--import-stdin", "--json"],
        input=payload,
    )

    assert result.exit_code == 2
    assert json.loads(result.stderr)["category"] == "usage"
    assert payload[:20] not in result.stdout


def test_browser_stdin_import_prepares_display_before_consuming_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consumed = False
    preparations = 0
    health = SessionHealth(
        provider="fixture",
        account_key="default",
        status=SessionStatus.VERIFIED,
    )

    class ImportService:
        def requires_browser_for_provider(self, provider: str) -> bool:
            assert provider == "fixture"
            return True

        def login(self, provider: str, **kwargs):
            assert provider == "fixture"
            assert kwargs["cookie_payload"] == []
            kwargs["before_browser"]()
            return health

    def prepare(argv, *, child_owns_invocation: bool):  # noqa: ANN001
        nonlocal preparations
        del argv
        assert child_owns_invocation is True
        if preparations == 0:
            assert consumed is False
        preparations += 1

    def read_stdin() -> list[object]:
        nonlocal consumed
        consumed = True
        return []

    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: ImportService())
    monkeypatch.setattr("newsclip.cli._prepare_virtual_display", prepare)
    monkeypatch.setattr("newsclip.cli._read_cookie_payload_stdin", read_stdin)

    result = CliRunner().invoke(
        app,
        ["auth", "login", "fixture", "--import-stdin", "--json"],
        input="[]",
    )

    assert result.exit_code == 0
    assert consumed is True
    assert preparations == 2


def test_browser_cookie_import_prepares_surface_before_verification() -> None:
    prepared = 0

    class BrowserImportProvider(FakeProvider):
        key = "browser-import"
        capabilities = ProviderCapabilities(
            session_kind="cookie", retrieval_transport="browser"
        )
        login_recipe = object()

    class ImportSessions:
        def __init__(self) -> None:
            self.payload = None

        def mark_account_alert(self, provider, account_key="default", **kwargs):
            raise AssertionError("not used")

        def import_cookies(self, provider: str, payload: object) -> None:
            assert provider == "browser-import"
            self.payload = payload

        def status(self, provider: str) -> SessionHealth:
            return SessionHealth(
                provider=provider,
                account_key="default",
                status=SessionStatus.VERIFIED,
            )

        def get_valid_session(self, provider: str, account_key: str = "default"):
            raise AssertionError("not used")

        def mark_required(
            self,
            provider: str,
            account_key: str = "default",
            *,
            generation_id=None,
        ) -> None:
            raise AssertionError("not used")

        def explicit_login(self, provider: str, **kwargs):
            raise AssertionError("not used")

        def reset_browser_profile(
            self, provider: str, account_key: str = "default"
        ) -> None:
            raise AssertionError("not used")

        def reset(self, provider: str, account_key: str = "default") -> None:
            raise AssertionError("not used")

        def clear(self, provider: str, account_key: str = "default") -> None:
            raise AssertionError("not used")

        def acknowledge(self, provider: str, account_key: str = "default") -> None:
            raise AssertionError("not used")

    sessions = ImportSessions()
    service = NewsclipService(
        ProviderRegistry((BrowserImportProvider(),)),
        FakeHttp(),
        FakeExtractor(),
        sessions=sessions,
    )

    def prepare() -> None:
        nonlocal prepared
        prepared += 1

    result = service.login(
        "browser-import",
        headless=True,
        cookie_payload=[{"name": "Session"}],
        before_browser=prepare,
    )

    assert isinstance(result, SessionHealth)
    assert prepared == 1
    assert sessions.payload == [{"name": "Session"}]


def test_headless_surface_failure_is_a_closed_transport_error(monkeypatch) -> None:
    class BrowserService:
        def login(self, provider: str, **kwargs):
            kwargs["before_browser"]()
            raise AssertionError("preparation failure must stop login")

    def unavailable(argv, *, required: bool):  # noqa: ANN001
        raise BrowserRuntimeError(InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE)

    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: BrowserService())
    monkeypatch.setattr(
        "newsclip.cli.maybe_reexec_for_virtual_display",
        unavailable,
    )

    result = CliRunner().invoke(app, ["login", "ft", "--headless", "--json"])

    assert result.exit_code == 5
    assert "Traceback" not in result.stderr
    assert json.loads(result.stderr) == {
        "category": "transport",
        "exit_code": 5,
        "message": "provider transport failed",
        "ok": False,
        "retryable": True,
        "action": "retry_later",
    }


def test_get_auto_auth_uses_quiet_scoped_child_and_resumes_exact_url(
    tmp_path: Path,
    monkeypatch,
) -> None:
    article = _service(tmp_path).get(ARTICLE_URL)
    prepared_argv: list[list[str]] = []
    login_calls: list[tuple[str, dict[str, object]]] = []

    class AutoService:
        def requires_browser_for_url(self, url: str) -> bool:
            assert url == ARTICLE_URL
            return False

        def get(self, url: str, **kwargs):
            assert url == ARTICLE_URL
            kwargs["acquire_session"]("ft")
            return article

        def login(self, provider: str, **kwargs):
            login_calls.append((provider, kwargs))
            kwargs["before_browser"]()
            return SessionHealth(
                provider=provider,
                status=SessionStatus.VERIFIED,
            )

    def prepare(argv, *, required: bool):  # noqa: ANN001
        assert required is True
        prepared_argv.append(list(argv))
        return 0

    monkeypatch.setattr("newsclip.cli.build_service", lambda: AutoService())
    monkeypatch.setattr("newsclip.cli.maybe_reexec_for_virtual_display", prepare)

    result = CliRunner().invoke(app, ["get", ARTICLE_URL, "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == article.public_dict()
    assert [provider for provider, _ in login_calls] == ["ft"]
    assert login_calls[0][1]["headless"] is True
    assert prepared_argv[0][1:] == [
        "auth",
        "login",
        "ft",
        "--headless",
        "--challenge-mode",
        "auto",
        "--quiet",
        "--json",
    ]


@pytest.mark.parametrize("command", ["get", "save"])
def test_browser_target_preflights_entire_command_before_service_work(
    command: str,
    monkeypatch,
) -> None:
    prepared: list[list[str]] = []

    class BrowserService:
        def requires_browser_for_url(self, url: str) -> bool:
            return True

        def get(self, url: str, **kwargs):
            raise AssertionError("delegated child owns browser retrieval")

        def save(self, url: str, **kwargs):
            raise AssertionError("delegated child owns browser retrieval")

    def prepare(argv, *, required: bool):  # noqa: ANN001
        assert required is True
        prepared.append(list(argv))
        return 0

    monkeypatch.setattr("newsclip.cli.build_service", lambda: BrowserService())
    monkeypatch.setattr("newsclip.cli.maybe_reexec_for_virtual_display", prepare)

    result = CliRunner().invoke(app, [command, ARTICLE_URL, "--json"])

    assert result.exit_code == 0
    assert result.stdout == ""
    assert len(prepared) == 1


def test_quiet_login_suppresses_only_success_output(monkeypatch) -> None:
    health = SessionHealth(
        provider="ft",
        status=SessionStatus.VERIFIED,
    )

    class WarmService:
        def login(self, provider: str, **kwargs):
            return health

    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: WarmService())

    result = CliRunner().invoke(app, ["login", "ft", "--quiet"])

    assert result.exit_code == 0
    assert result.stdout == ""


def test_public_envelope_names_only_recognized_reasons() -> None:
    named = public_error(ContentNotFullError("paywall_teaser"))
    unnamed = public_error(ContentNotFullError("some_internal_detail"))

    assert named is not None
    assert named.public_dict() == {
        "category": "content_not_full",
        "exit_code": 4,
        "message": "content did not verify as full",
        "ok": False,
        "retryable": False,
        "action": "none",
        "reason": "paywall_teaser",
    }
    assert unnamed is not None
    # An unrecognized reason leaves the established shape untouched.
    assert unnamed.public_dict() == {
        "category": "content_not_full",
        "exit_code": 4,
        "message": "content did not verify as full",
        "ok": False,
        "retryable": False,
        "action": "none",
    }


def test_public_envelope_separates_a_teaser_from_a_challenge() -> None:
    teaser = public_error(ContentNotFullError("paywall_teaser"))
    challenge = public_error(ContentNotFullError("interactive_challenge"))

    assert teaser is not None
    assert challenge is not None
    assert teaser.category is challenge.category
    assert teaser.reason is PublicErrorReason.PAYWALL_TEASER
    assert challenge.reason is PublicErrorReason.INTERACTIVE_CHALLENGE


def test_public_envelope_carries_the_retained_incident_reference() -> None:
    incident_id = f"incident-{'a' * 24}"

    envelope = public_error(
        ContentNotFullError("paywall_teaser", incident_id=incident_id)
    )

    assert envelope is not None
    assert envelope.public_dict()["incident_id"] == incident_id


def test_public_envelope_rejects_a_malformed_incident_reference() -> None:
    with pytest.raises(ValidationError):
        PublicErrorEnvelope(
            category=PublicErrorCategory.CONTENT_NOT_FULL,
            exit_code=4,
            message=PublicErrorMessage.CONTENT_NOT_FULL,
            incident_id="../../etc/passwd",
        )


def test_public_envelope_ignores_a_foreign_incident_attribute() -> None:
    """Error mapping runs inside exception handling and must not itself raise."""

    class Foreign(ContentNotFullError):
        incident_id = "not-an-incident"

    envelope = public_error(Foreign("paywall_teaser"))

    assert envelope is not None
    assert "incident_id" not in envelope.public_dict()


def test_human_failure_surfaces_the_incident_reference_the_hint_points_at(
    monkeypatch,
) -> None:
    """The content-not-full hints tell the operator to inspect the evidence.

    That instruction is only actionable if the human surface names the
    incident, which previously only JSON callers received.
    """

    incident_id = f"incident-{'b' * 24}"

    class FailingService:
        def requires_browser_for_url(self, url: str) -> bool:
            return False

        def get(self, url: str, **kwargs):
            raise ContentNotFullError("paywall_teaser", incident_id=incident_id)

    monkeypatch.setattr("newsclip.cli.build_service", lambda: FailingService())

    result = CliRunner().invoke(app, ["get", ARTICLE_URL])

    assert result.exit_code == 4
    assert "content did not verify as full" in result.stderr
    assert "served a partial body" in result.stderr
    assert f"incident: {incident_id}" in result.stderr


def test_human_failure_without_retained_evidence_omits_the_incident_line(
    monkeypatch,
) -> None:
    class FailingService:
        def requires_browser_for_url(self, url: str) -> bool:
            return False

        def get(self, url: str, **kwargs):
            raise ContentNotFullError("paywall_teaser")

    monkeypatch.setattr("newsclip.cli.build_service", lambda: FailingService())

    result = CliRunner().invoke(app, ["get", ARTICLE_URL])

    assert result.exit_code == 4
    assert "incident:" not in result.stderr


@pytest.mark.parametrize("operation", ["get", "save"])
@pytest.mark.parametrize(
    "probe",
    [
        AccessState.TEASER,
        AccessState.FULL,
        AccessState.AUTH_REQUIRED,
        AccessState.BLOCKED,
        AccessState.UNKNOWN,
    ],
)
def test_serving_failure_handoff_follows_probe_evidence(tmp_path, operation, probe):
    from newsclip.models import SessionVerification
    from newsclip.recovery import RecoveryStore

    class Recipe:
        def verify(self, http, session):
            return SessionVerification(
                verified=probe is AccessState.FULL,
                access_state=probe,
                reason="fixture_probe",
                verified_at=NOW,
            )

    class Sessions(CheckpointSessions):
        def mark_required(self, provider, *, generation_id):
            assert generation_id == self.artifact.generation_id

    provider = FakeProvider()
    provider.capabilities = ProviderCapabilities(requires_session_for_retrieve=True)
    provider.login_recipe = Recipe()
    store = RecoveryStore(tmp_path / "recovery", utc_now=lambda: NOW)
    service = _service(tmp_path, rejected=True)
    service._registry = ProviderRegistry((provider,))
    service._sessions = Sessions()
    service._recovery_store = store
    with pytest.raises((ContentNotFullError, SessionRequiredError)) as caught:
        getattr(service, operation)(ARTICLE_URL)
    record = store.load("fixture")
    envelope = public_error(caught.value)
    if probe in {AccessState.FULL, AccessState.BLOCKED, AccessState.UNKNOWN}:
        assert record is None
        assert envelope.action.value == "none"
    else:
        assert record is not None
        assert record.incident_id == caught.value.incident_id
        assert record.generation_id == service._sessions.artifact.generation_id
        assert envelope.recovery_id == record.health.request_id
        assert envelope.action.value == "renewal_pending"
    assert service._http.calls == [ARTICLE_URL]


@pytest.mark.parametrize("operation", ["get", "save"])
def test_full_serving_resolves_exact_failed_recovery(tmp_path, operation):
    from newsclip.recovery import RecoveryStore

    timing = TimingRecorder(tmp_path / "timing.jsonl", invocation_id="mcp-proof")
    service = _service(tmp_path, timing=timing)
    store = RecoveryStore(tmp_path / "recovery", utc_now=lambda: NOW)
    service._recovery_store = store
    record = store.request(
        "fixture",
        generation_id=None,
        url=ARTICLE_URL,
        incident_id=None,
        diagnostic_id="mcp-failed",
    )
    claimed = store.claim("fixture", "cli-recovery")
    store.finish(claimed, reason="paywall_teaser", session_verified=True)
    getattr(service, operation)(ARTICLE_URL)
    resolved = store.load("fixture")
    assert resolved.health.status.value == "succeeded"
    assert resolved.health.article_verified
    assert resolved.health.request_id == record.health.request_id
    runs = tuple(iter_timing_runs(tmp_path / "timing.jsonl"))
    assert runs[0].finished.recovery.status.value == "succeeded"
    assert service._http.calls == [ARTICLE_URL]


def test_resolution_write_failure_preserves_full_article_and_diagnostic(
    tmp_path, monkeypatch
):
    from newsclip.recovery import RecoveryStore

    path = tmp_path / "timing.jsonl"
    service = _service(tmp_path, timing=TimingRecorder(path, invocation_id="mcp-proof"))
    store = RecoveryStore(tmp_path / "recovery")
    service._recovery_store = store

    def fail(*args, **kwargs):
        raise PersistenceError("fixture write failed")

    monkeypatch.setattr(store, "article_verified", fail)
    assert service.get(ARTICLE_URL).body_markdown == "Generated fixture article body."
    runs = tuple(iter_timing_runs(path))
    assert runs[0].finished.recovery.omission == "resolution_failed"


def test_missing_session_queues_without_provider_io_and_failed_handoff_is_honest(
    tmp_path,
):
    from newsclip.recovery import RecoveryStore

    provider = FakeProvider()
    provider.capabilities = ProviderCapabilities(requires_session_for_retrieve=True)
    store = RecoveryStore(tmp_path / "recovery", utc_now=lambda: NOW)
    service = NewsclipService(
        ProviderRegistry((provider,)),
        FakeHttp(),
        FakeExtractor(),
        sessions=MissingSessions(),
        recovery_store=store,
    )
    with pytest.raises(SessionRequiredError) as caught:
        service.get(ARTICLE_URL)
    assert store.load("fixture").generation_id is None
    assert public_error(caught.value).action.value == "renewal_pending"
    assert service._http.calls == []
    (store.root / "fixture.json").write_text("corrupt")
    with pytest.raises(SessionRequiredError) as caught:
        service.get(ARTICLE_URL)
    envelope = public_error(caught.value)
    assert envelope.action.value == "none"
    assert envelope.recovery_omission == "handoff_failed"


def test_recovery_article_check_cannot_enqueue_itself_or_archive(tmp_path):
    from newsclip.recovery import RecoveryStore

    provider = FakeProvider()
    provider.capabilities = ProviderCapabilities(requires_session_for_retrieve=True)
    store = RecoveryStore(tmp_path / "recovery")
    service = NewsclipService(
        ProviderRegistry((provider,)),
        FakeHttp(),
        FakeExtractor(),
        sessions=MissingSessions(),
        recovery_store=store,
    )
    with pytest.raises(SessionRequiredError):
        service.verify_recovery_article("fixture", ARTICLE_URL)
    assert store.load("fixture") is None
    with pytest.raises(UsageError):
        service.verify_recovery_article("ft", ARTICLE_URL)
    assert service._http.calls == []


def test_explicit_cli_acquisition_does_not_race_background_recovery(tmp_path):
    from newsclip.recovery import RecoveryStore

    provider = FakeProvider()
    provider.capabilities = ProviderCapabilities(requires_session_for_retrieve=True)
    store = RecoveryStore(tmp_path / "recovery")
    service = NewsclipService(
        ProviderRegistry((provider,)),
        FakeHttp(),
        FakeExtractor(),
        sessions=MissingSessions(),
        recovery_store=store,
    )

    def acquire(provider_key):
        assert provider_key == "fixture"
        service._sessions = CheckpointSessions()

    assert service.get(ARTICLE_URL, acquire_session=acquire).provider == "fixture"
    assert store.load("fixture") is None


def test_handoff_failure_is_correlated_in_timing(tmp_path):
    from newsclip.recovery import RecoveryStore

    provider = FakeProvider()
    provider.capabilities = ProviderCapabilities(requires_session_for_retrieve=True)
    store = RecoveryStore(tmp_path / "recovery")
    service = NewsclipService(
        ProviderRegistry((provider,)),
        FakeHttp(),
        FakeExtractor(),
        sessions=MissingSessions(),
        recovery_store=store,
        timing=TimingRecorder(tmp_path / "timings"),
    )
    with pytest.raises(SessionRequiredError) as caught:
        service.get(ARTICLE_URL)
    runs = tuple(iter_timing_runs(tmp_path / "timings"))
    assert runs[0].finished.recovery.request_id == caught.value.recovery_id
