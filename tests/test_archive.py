from __future__ import annotations

import gzip
import hashlib
import sqlite3
import stat
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from newsclip.archive import _SCHEMA_V1, SCHEMA_VERSION, ArchiveStore
from newsclip.errors import PersistenceError
from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import (
    AccessState,
    ArchiveIntegrityStatus,
    Article,
    ArticleAssessment,
    ExtractedArticle,
    RawFetch,
    SessionArtifact,
)
from newsclip.provider_config import load_provider_spec
from newsclip.providers import FTProvider, ProviderRegistry
from newsclip.service import build_article

NOW = datetime(2026, 7, 17, tzinfo=UTC)
ARTICLE_ID = "11111111-1111-4111-8111-111111111111"
ARTICLE_URL = f"https://www.ft.com/content/{ARTICLE_ID}"
FIXTURES = Path(__file__).parent / "fixtures" / "ft"
INVALID_DEFLATE_GZIP = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xffinvalid-deflate"


def _raw(
    fixture: str = "full.html",
    *,
    final_url: str = ARTICLE_URL,
    status: int = 200,
    retry_after: float | None = None,
    retrieved_at: datetime = NOW,
) -> RawFetch:
    return RawFetch(
        requested_url=ARTICLE_URL,
        final_url=final_url,
        http_status=status,
        content_type="text/html; charset=utf-8",
        retry_after=retry_after,
        retrieved_at=retrieved_at,
        session_cookie_present=True,
        raw_html=(FIXTURES / fixture).read_bytes(),
    )


def _accepted(fetch: RawFetch | None = None, extractor=None):
    fetch = fetch or _raw()
    extractor = extractor or TrafilaturaExtractor()
    provider = FTProvider()
    extraction = extractor.extract(fetch)
    assessment = provider.assess(ARTICLE_URL, fetch, extraction)
    assert assessment.access_state is AccessState.FULL
    article = build_article(
        provider,
        fetch,
        extraction,
        assessment,
        extractor_name=extractor.name,
        extractor_version=extractor.version,
    )
    return article, fetch, assessment, extraction


def _store(path: Path, **kwargs) -> ArchiveStore:
    return ArchiveStore(
        path,
        registry=ProviderRegistry((FTProvider(),)),
        extractor=TrafilaturaExtractor(),
        **kwargs,
    )


def test_archive_mode_enforcement_wraps_chmod_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")

    def fail_chmod(path: Path, mode: int) -> None:
        del path, mode
        raise OSError("/private/archive-sensitive-path")

    monkeypatch.setattr("newsclip.archive.os.chmod", fail_chmod)

    with pytest.raises(
        PersistenceError,
        match="archive mode enforcement failed",
    ) as captured:
        store._enforce_modes()

    assert "/private/archive-sensitive-path" not in str(captured.value)


def _copy_as_v1_archive(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(destination) as legacy:
        legacy.executescript(_SCHEMA_V1)
        legacy.execute("ATTACH DATABASE ? AS source", (str(source),))
        legacy.execute("INSERT INTO articles SELECT * FROM source.articles ORDER BY id")
        legacy.execute(
            "INSERT INTO fetches("
            "id, provider, provider_article_id, article_id, requested_url, "
            "final_url, http_status, content_type, retrieved_at, "
            "session_cookie_present, raw_sha256, raw_html_gzip, assessment_json, "
            "first_seen_at, last_seen_at, seen_count) "
            "SELECT id, provider, provider_article_id, article_id, requested_url, "
            "final_url, http_status, content_type, retrieved_at, "
            "session_cookie_present, raw_sha256, raw_html_gzip, assessment_json, "
            "first_seen_at, last_seen_at, seen_count FROM source.fetches ORDER BY id"
        )
        legacy.execute(
            "INSERT INTO extractions SELECT * FROM source.extractions ORDER BY id"
        )
        legacy.execute(
            "INSERT INTO article_fts SELECT * FROM source.article_fts ORDER BY rowid"
        )
    return destination


def test_full_save_is_transactional_searchable_and_private(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()

    saved = store.save("ft", article, fetch, assessment, extraction)

    assert saved == article
    assert store.get(article.id) == article
    assert [item.id for item in store.search("capital")] == [article.id]
    inspection = store.inspect_schema()
    assert inspection == {
        "user_version": SCHEMA_VERSION,
        "journal_mode": "wal",
        "foreign_keys": 1,
        "counts": {
            "articles": 1,
            "fetches": 1,
            "extractions": 1,
            "extraction_assessments": 1,
            "article_fts": 1,
        },
        "directory_mode": 0o700,
        "database_mode": 0o600,
    }
    for private_path in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        if private_path.exists():
            assert stat.S_IMODE(private_path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    ("fixture", "final_url", "status", "state"),
    [
        ("teaser.html", ARTICLE_URL, 200, AccessState.TEASER),
        (
            "auth.html",
            "https://accounts.ft.com/login",
            200,
            AccessState.AUTH_REQUIRED,
        ),
        ("interstitial.html", ARTICLE_URL, 200, AccessState.BLOCKED),
        ("long_nonarticle.html", ARTICLE_URL, 200, AccessState.UNKNOWN),
        ("wrong_canonical.html", ARTICLE_URL, 200, AccessState.UNKNOWN),
        ("http_error.html", ARTICLE_URL, 503, AccessState.UNKNOWN),
    ],
)
def test_nonfull_fetch_is_diagnostic_only(
    tmp_path: Path,
    fixture: str,
    final_url: str,
    status: int,
    state: AccessState,
) -> None:
    store = _store(tmp_path / fixture / "archive.sqlite3")
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    before = store.get(article.id)

    rejected_fetch = _raw(fixture, final_url=final_url, status=status)
    rejected_extraction = TrafilaturaExtractor().extract(rejected_fetch)
    rejected_assessment = FTProvider().assess(
        ARTICLE_URL, rejected_fetch, rejected_extraction
    )
    assert rejected_assessment.access_state is state

    result = store.save(
        "ft", None, rejected_fetch, rejected_assessment, rejected_extraction
    )

    assert result is None
    assert store.get(article.id) == before
    assert [item.id for item in store.search("capital")] == [article.id]
    counts = store.inspect_schema()["counts"]
    assert counts == {
        "articles": 1,
        "fetches": 2,
        "extractions": 1,
        "extraction_assessments": 1,
        "article_fts": 1,
    }


def test_failure_before_commit_leaves_no_partial_rows(tmp_path: Path) -> None:
    def fail(point: str) -> None:
        if point == "before_commit":
            raise OSError("injected transaction fault")

    store = _store(tmp_path / "data" / "archive.sqlite3", fault_hook=fail)
    article, fetch, assessment, extraction = _accepted()

    with pytest.raises(PersistenceError, match="archive save failed"):
        store.save("ft", article, fetch, assessment, extraction)

    assert store.inspect_schema()["counts"] == {
        "articles": 0,
        "fetches": 0,
        "extractions": 0,
        "extraction_assessments": 0,
        "article_fts": 0,
    }


def test_export_failure_preserves_committed_archive_and_prior_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    destination = tmp_path / "export" / "article.md"
    destination.parent.mkdir()
    destination.write_text("prior complete export\n", encoding="utf-8")

    def fail(point: str) -> None:
        if point == "before_export_replace":
            raise OSError("injected export fault")

    failing_store = _store(path, fault_hook=fail)
    with pytest.raises(PersistenceError, match="Markdown export failed"):
        failing_store.export_markdown(article, destination)

    assert destination.read_text(encoding="utf-8") == "prior complete export\n"
    assert failing_store.get(article.id) == article


def test_repeated_save_is_one_fetch_and_one_extraction(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()

    first = store.save("ft", article, fetch, assessment, extraction)
    second = store.save("ft", article, fetch, assessment, extraction)

    assert first == second == store.get(article.id)
    counts = store.inspect_schema()["counts"]
    assert counts["fetches"] == 1
    assert counts["extractions"] == 1
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT seen_count FROM fetches").fetchone()[0] == 2


def test_repeated_save_accepts_equivalent_gzip_encoding(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    first = store.save("ft", article, fetch, assessment, extraction)
    alternate_gzip = gzip.compress(fetch.raw_html, mtime=1)
    assert alternate_gzip != gzip.compress(fetch.raw_html, mtime=0)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE fetches SET raw_html_gzip = ?",
            (alternate_gzip,),
        )

    repeated = store.save("ft", article, fetch, assessment, extraction)

    assert repeated == first
    assert store.current_raw_snapshots()[0][2].raw_html == fetch.raw_html
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT raw_html_gzip, seen_count FROM fetches"
        ).fetchone()
    assert row == (alternate_gzip, 2)


def test_repeated_evidence_returns_the_canonical_archived_revision(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    first = store.save("ft", article, fetch, assessment, extraction)
    later_fetch = fetch.model_copy(update={"retrieved_at": NOW + timedelta(days=1)})
    later_article, _, later_assessment, later_extraction = _accepted(later_fetch)

    repeated = store.save(
        "ft",
        later_article,
        later_fetch,
        later_assessment,
        later_extraction,
    )

    assert repeated == first == store.get(article.id)
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT retrieved_at, last_seen_at, seen_count FROM fetches"
        ).fetchone()
    assert row == (
        NOW.isoformat(),
        (NOW + timedelta(days=1)).isoformat(),
        2,
    )


def test_concurrent_save_returns_each_transactions_canonical_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    first_before_commit = threading.Event()
    allow_first_commit = threading.Event()
    second_finished = threading.Event()

    def fault(point: str) -> None:
        if (
            point == "before_commit"
            and threading.current_thread().name == "archive-first"
        ):
            first_before_commit.set()
            assert allow_first_commit.wait(timeout=5)

    store = _store(path, fault_hook=fault)
    first = _accepted()
    second_fetch = _raw(
        retry_after=120,
        retrieved_at=NOW + timedelta(minutes=1),
    )
    second = _accepted(second_fetch)
    original_get = store.get

    def delayed_get(article_id: str):
        if threading.current_thread().name == "archive-first":
            assert second_finished.wait(timeout=5)
        return original_get(article_id)

    monkeypatch.setattr(store, "get", delayed_get)
    results: dict[str, object] = {}
    errors: list[BaseException] = []

    def save(name: str, values) -> None:  # noqa: ANN001
        try:
            results[name] = store.save("ft", *values)
        except BaseException as error:
            errors.append(error)
        finally:
            if name == "second":
                second_finished.set()

    first_thread = threading.Thread(
        target=save,
        args=("first", first),
        name="archive-first",
    )
    second_thread = threading.Thread(
        target=save,
        args=("second", second),
        name="archive-second",
    )
    first_thread.start()
    assert first_before_commit.wait(timeout=5)
    second_thread.start()
    allow_first_commit.set()
    first_thread.join(timeout=5)
    second_thread.join(timeout=5)

    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert errors == []
    assert results == {
        "first": first[0],
        "second": second[0],
    }
    assert store.get(first[0].id) == second[0]


def test_same_body_with_different_transport_evidence_is_not_conflated(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    retry_fetch = _raw(retry_after=120)
    retry_article, _, retry_assessment, retry_extraction = _accepted(retry_fetch)

    saved = store.save(
        "ft",
        retry_article,
        retry_fetch,
        retry_assessment,
        retry_extraction,
    )

    assert saved == retry_article
    assert store.current_raw_snapshots()[0][2].retry_after == 120
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT retry_after, count(*) FROM fetches GROUP BY retry_after "
            "ORDER BY retry_after"
        ).fetchall()
    assert rows == [(None, 1), (120.0, 1)]


def test_diagnostic_reassessment_cannot_replace_current_revision_assessment(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    diagnostic = assessment.model_copy(
        update={
            "access_state": AccessState.TEASER,
            "identity_match": False,
            "reason": "policy_reassessment_fixture",
        }
    )

    store.save("ft", None, fetch, diagnostic, extraction)

    snapshot = store.current_raw_snapshots()[0]
    assert snapshot[3] == assessment
    with sqlite3.connect(path) as connection:
        fetch_assessment, revision_assessment = connection.execute(
            "SELECT f.assessment_json, ea.assessment_json FROM fetches f "
            "JOIN extractions e ON e.fetch_id = f.id "
            "JOIN extraction_assessments ea ON ea.extraction_id = e.id"
        ).fetchone()
    assert "policy_reassessment_fixture" in fetch_assessment
    assert "full_article_verified" in revision_assessment


def test_save_rejects_article_that_disagrees_with_extraction(tmp_path: Path) -> None:
    store = _store(tmp_path / "data" / "archive.sqlite3")
    article, fetch, assessment, extraction = _accepted()
    mismatched = article.model_copy(
        update={"body_markdown": "INDEX_ONLY_SENTINEL", "word_count": 1}
    )

    with pytest.raises(PersistenceError, match="assessed raw evidence"):
        store.save("ft", mismatched, fetch, assessment, extraction)

    assert store.inspect_schema()["counts"] == {
        "articles": 0,
        "fetches": 0,
        "extractions": 0,
        "extraction_assessments": 0,
        "article_fts": 0,
    }


def test_save_rejects_changed_content_under_an_existing_extraction_identity(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "data" / "archive.sqlite3")
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    changed_extraction = ExtractedArticle(
        body_markdown=f"{extraction.body_markdown}\n\nVERSION_COLLISION_SENTINEL",
        metadata=extraction.metadata,
        word_count=extraction.word_count + 1,
    )
    changed_article = article.model_copy(
        update={
            "body_markdown": changed_extraction.body_markdown,
            "word_count": changed_extraction.word_count,
        }
    )

    with pytest.raises(PersistenceError, match="extraction identity"):
        store.save("ft", changed_article, fetch, assessment, changed_extraction)

    assert store.get(article.id) == article
    assert store.search("VERSION_COLLISION_SENTINEL") == []
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT seen_count FROM fetches").fetchone()[0] == 1


def test_save_maps_nonserializable_extraction_metadata_to_persistence(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "data" / "archive.sqlite3")
    article, fetch, assessment, extraction = _accepted()
    invalid = extraction.model_copy(
        update={"metadata": {**extraction.metadata, "bad": object()}}
    )

    with pytest.raises(PersistenceError, match="archive save failed"):
        store.save("ft", article, fetch, assessment, invalid)

    assert store.inspect_schema()["counts"]["fetches"] == 0


class OfflineOnlyFTProvider(FTProvider):
    def fetch(
        self,
        http,
        session: SessionArtifact | None,
        url: str,
    ) -> RawFetch:
        raise AssertionError("re-extraction attempted network retrieval")


class VersionedExtractor:
    name = "trafilatura"
    version = "offline-fixture-v2"

    def extract(
        self,
        fetch: RawFetch,
        *,
        scope_xpath: tuple[str, ...] | None = None,
    ):
        return TrafilaturaExtractor().extract(fetch, scope_xpath=scope_xpath)


class LegacyUtf8OnlyExtractor:
    name = "trafilatura"
    version = "legacy-utf8-only"

    def extract(
        self,
        fetch: RawFetch,
        *,
        scope_xpath: tuple[str, ...] | None = None,
    ) -> ExtractedArticle:
        legacy_fetch = fetch.model_copy(
            update={"content_type": "text/html; charset=utf-8"}
        )
        return TrafilaturaExtractor().extract(
            legacy_fetch,
            scope_xpath=scope_xpath,
        )


class ChangedOutputExtractor:
    name = "trafilatura"

    def __init__(self, extractor_version: str) -> None:
        self.version = extractor_version

    def extract(
        self,
        fetch: RawFetch,
        *,
        scope_xpath: tuple[str, ...] | None = None,
    ) -> ExtractedArticle:
        extraction = TrafilaturaExtractor().extract(fetch, scope_xpath=scope_xpath)
        body_markdown = f"{extraction.body_markdown}\n\nVERSIONED_OUTPUT_SENTINEL"
        return extraction.model_copy(
            update={
                "body_markdown": body_markdown,
                "word_count": len(body_markdown.split()),
            }
        )


class ChangedAssessmentProvider(OfflineOnlyFTProvider):
    def __init__(self, policy_version: str) -> None:
        super().__init__()
        self.assessment_policy_version = policy_version
        self.extraction_scope: tuple[str, ...] | None = None

    def assess(
        self,
        requested_url: str,
        fetch: RawFetch,
        extraction: ExtractedArticle,
    ) -> ArticleAssessment:
        assessment = super().assess(requested_url, fetch, extraction)
        return assessment.model_copy(
            update={
                "structural_signals": assessment.structural_signals
                + ("changed_engine_semantics",)
            }
        )


def test_extractor_identity_owns_newsclip_and_dependency_revisions() -> None:
    assert TrafilaturaExtractor().version.startswith("newsclip-r4+trafilatura-")


def test_reextract_requires_version_bump_for_changed_output(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    initial_store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    initial_store.save("ft", article, fetch, assessment, extraction)

    same_identity_store = ArchiveStore(
        path,
        registry=ProviderRegistry((OfflineOnlyFTProvider(),)),
        extractor=ChangedOutputExtractor(TrafilaturaExtractor().version),
    )
    with pytest.raises(PersistenceError, match="extraction identity"):
        same_identity_store.reextract(article.id)
    assert same_identity_store.get(article.id) == article

    bumped_version = f"{TrafilaturaExtractor().version}.fixture-v2"
    bumped_identity_store = ArchiveStore(
        path,
        registry=ProviderRegistry((OfflineOnlyFTProvider(),)),
        extractor=ChangedOutputExtractor(bumped_version),
    )
    reextracted = bumped_identity_store.reextract(article.id)

    assert reextracted.extraction.extractor_version == bumped_version
    assert reextracted.body_markdown.endswith("VERSIONED_OUTPUT_SENTINEL")
    assert bumped_identity_store.get(article.id) == reextracted
    assert bumped_identity_store.inspect_schema()["counts"]["extractions"] == 2


def test_reextract_requires_policy_bump_for_changed_assessment(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    initial_store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    initial_store.save("ft", article, fetch, assessment, extraction)

    same_identity_store = ArchiveStore(
        path,
        registry=ProviderRegistry(
            (ChangedAssessmentProvider(article.extraction.policy_version),)
        ),
        extractor=TrafilaturaExtractor(),
    )
    with pytest.raises(PersistenceError, match="different assessment"):
        same_identity_store.reextract(article.id)
    assert same_identity_store.get(article.id) == article

    bumped_policy_version = load_provider_spec("ft").assessment_policy_version(
        "configured-r3"
    )
    bumped_identity_store = ArchiveStore(
        path,
        registry=ProviderRegistry((ChangedAssessmentProvider(bumped_policy_version),)),
        extractor=TrafilaturaExtractor(),
    )
    reextracted = bumped_identity_store.reextract(article.id)

    assert reextracted.extraction.policy_version == bumped_policy_version
    assert bumped_identity_store.get(article.id) == reextracted
    assert bumped_identity_store.inspect_schema()["counts"]["extractions"] == 2


def test_reextract_uses_archived_raw_without_provider_fetch(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    initial_store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    initial_store.save("ft", article, fetch, assessment, extraction)
    offline_store = ArchiveStore(
        path,
        registry=ProviderRegistry((OfflineOnlyFTProvider(),)),
        extractor=VersionedExtractor(),
    )

    reextracted = offline_store.reextract(article.id)

    assert reextracted.extraction.extractor_version == "offline-fixture-v2"
    assert reextracted.extraction.raw_sha256 == article.extraction.raw_sha256
    assert offline_store.inspect_schema()["counts"]["extractions"] == 2


def test_reextract_decodes_archived_meta_declared_charset(tmp_path: Path) -> None:
    source = (
        (FIXTURES / "full.html")
        .read_text()
        .replace(
            "<head>",
            '<head><meta charset="windows-1252">',
        )
    )
    source = source.replace(
        "Generated fixture prose",
        "Café’s résumé explains euro-area markets – generated fixture prose",
    )
    fetch = _raw().model_copy(
        update={
            "content_type": "text/html",
            "raw_html": source.encode("windows-1252"),
        }
    )
    initial_store = ArchiveStore(
        tmp_path / "data" / "archive.sqlite3",
        registry=ProviderRegistry((FTProvider(),)),
        extractor=LegacyUtf8OnlyExtractor(),
    )
    article, _, assessment, extraction = _accepted(
        fetch,
        extractor=LegacyUtf8OnlyExtractor(),
    )
    initial_store.save("ft", article, fetch, assessment, extraction)
    assert "\ufffd" in article.body_markdown
    offline_store = ArchiveStore(
        initial_store.path,
        registry=ProviderRegistry((OfflineOnlyFTProvider(),)),
        extractor=TrafilaturaExtractor(),
    )

    reextracted = offline_store.reextract(article.id)

    assert "Café’s résumé" in reextracted.body_markdown
    assert "\ufffd" not in reextracted.body_markdown
    assert offline_store.inspect_schema()["counts"]["extractions"] == 2


def test_reextract_does_not_replace_a_concurrently_promoted_revision(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    initial_store = _store(path)
    initial = _accepted()
    initial_store.save("ft", *initial)
    concurrent_fetch = _raw(
        retry_after=120,
        retrieved_at=NOW + timedelta(minutes=1),
    )
    concurrent = _accepted(concurrent_fetch)

    class RacingExtractor(VersionedExtractor):
        def extract(
            self,
            fetch: RawFetch,
            *,
            scope_xpath: tuple[str, ...] | None = None,
        ) -> ExtractedArticle:
            initial_store.save("ft", *concurrent)
            return super().extract(fetch, scope_xpath=scope_xpath)

    reextracting_store = ArchiveStore(
        path,
        registry=ProviderRegistry((OfflineOnlyFTProvider(),)),
        extractor=RacingExtractor(),
    )

    with pytest.raises(PersistenceError, match="changed during re-extraction"):
        reextracting_store.reextract(initial[0].id)

    assert reextracting_store.get(initial[0].id) == concurrent[0]
    assert reextracting_store.inspect_schema()["counts"]["extractions"] == 2


def test_fts_rebuild_reproduces_search_results(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    before = [item.public_dict() for item in store.search("capital plans")]

    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM article_fts")
    assert store.search("capital plans") == []

    store.rebuild_fts()

    assert [item.public_dict() for item in store.search("capital plans")] == before


def test_integrity_check_detects_logically_corrupt_full_text_index(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    store.save("ft", *_accepted())
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM article_fts")

    result = store.integrity_check()

    assert result.ok is False
    assert result.integrity is ArchiveIntegrityStatus.FAILED
    assert result.foreign_key_violations == 0


def test_newer_schema_is_rejected_without_database_content_change(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "future.sqlite3"
    path.parent.mkdir()
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE future_marker(value TEXT)")
        connection.execute("INSERT INTO future_marker VALUES ('preserve')")
        connection.execute("PRAGMA user_version=99")
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(PersistenceError, match="newer than supported"):
        ArchiveStore(path)

    after = hashlib.sha256(path.read_bytes()).hexdigest()
    assert after == before
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT value FROM future_marker").fetchone() == (
            "preserve",
        )


def test_v1_archive_migrates_without_losing_canonical_data(tmp_path: Path) -> None:
    current_path = tmp_path / "current" / "archive.sqlite3"
    current = _store(current_path)
    article, fetch, assessment, extraction = _accepted()
    current.save("ft", article, fetch, assessment, extraction)
    legacy_path = _copy_as_v1_archive(
        current_path, tmp_path / "legacy" / "archive.sqlite3"
    )

    migrated = _store(legacy_path)

    assert migrated.get(article.id) == article
    assert migrated.search("capital") == [article]
    assert migrated.integrity_check().public_dict() == {
        "ok": True,
        "integrity": "ok",
        "foreign_key_violations": 0,
        "user_version": SCHEMA_VERSION,
    }
    with sqlite3.connect(legacy_path) as connection:
        row = connection.execute(
            "SELECT retry_after, length(evidence_sha256) FROM fetches"
        ).fetchone()
    assert row == (None, 64)
    assert migrated.current_raw_snapshots()[0][3] == assessment


def test_fts_and_provider_filters_treat_input_as_data(tmp_path: Path) -> None:
    store = _store(tmp_path / "data" / "archive.sqlite3")
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)

    assert store.search('capital" OR headline:*') == []
    assert store.search("capital", provider="ft' OR 1=1 --") == []
    assert store.get(article.id) == article


def test_logically_corrupt_article_is_a_typed_persistence_failure(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE articles SET authors_json = ? WHERE id = ?",
            ("not-json", article.id),
        )

    with pytest.raises(PersistenceError, match="article is corrupt"):
        store.get(article.id)


def test_raw_evidence_reads_reject_hash_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE fetches SET raw_html_gzip = ?",
            (gzip.compress(b"different valid gzip content", mtime=0),),
        )

    with pytest.raises(PersistenceError, match="raw fetch"):
        store.current_raw_snapshots()
    with pytest.raises(PersistenceError, match="raw fetch"):
        store.reextract(article.id)


def test_raw_evidence_reads_reject_invalid_deflate_as_persistence_failure(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE fetches SET raw_html_gzip = ?",
            (INVALID_DEFLATE_GZIP,),
        )

    with pytest.raises(PersistenceError, match="raw fetch"):
        store.current_raw_snapshots()
    with pytest.raises(PersistenceError, match="raw fetch"):
        store.reextract(article.id)


def test_raw_evidence_reads_reject_transport_identity_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE fetches SET final_url = ?", ("https://example.com",))

    with pytest.raises(PersistenceError, match="fetch evidence"):
        store.current_raw_snapshots()


def test_successful_export_is_atomic_and_private(tmp_path: Path) -> None:
    store = _store(tmp_path / "data" / "archive.sqlite3")
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)

    destination = store.export_markdown(article, tmp_path / "export" / "article.md")

    assert destination.read_text(encoding="utf-8") == f"{article.body_markdown}\n"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert not [
        path
        for path in destination.parent.iterdir()
        if path.name.startswith(f".{destination.name}.")
    ]


@pytest.mark.parametrize("operation", ["backup", "export"])
@pytest.mark.parametrize("suffix", ["", "-wal", "-shm"])
def test_outbound_writes_reject_archive_owned_destinations(
    tmp_path: Path,
    operation: str,
    suffix: str,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    owned_paths = (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
    before = {
        candidate: candidate.read_bytes() if candidate.exists() else None
        for candidate in owned_paths
    }
    destination = Path(f"{path}{suffix}")

    with pytest.raises(PersistenceError, match="differ from archive storage"):
        if operation == "backup":
            store.backup(destination)
        else:
            store.export_markdown(article, destination)

    after = {
        candidate: candidate.read_bytes() if candidate.exists() else None
        for candidate in owned_paths
    }
    assert after == before
    assert store.get(article.id) == article
    assert store.integrity_check().ok is True


@pytest.mark.parametrize("operation", ["backup", "export"])
def test_outbound_writes_reject_symlink_alias_of_archive(
    tmp_path: Path,
    operation: str,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    alias = tmp_path / "archive-alias"
    alias.symlink_to(path)
    before = path.read_bytes()

    with pytest.raises(PersistenceError, match="differ from archive storage"):
        if operation == "backup":
            store.backup(alias)
        else:
            store.export_markdown(article, alias)

    assert path.read_bytes() == before
    assert alias.is_symlink()
    assert store.get(article.id) == article
    assert store.integrity_check().ok is True


@pytest.mark.parametrize("operation", ["backup", "export"])
@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_outbound_writes_reject_sidecars_of_symlinked_archive_path(
    tmp_path: Path,
    operation: str,
    suffix: str,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    initial_store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    initial_store.save("ft", article, fetch, assessment, extraction)
    alias = tmp_path / "archive-alias.sqlite3"
    alias.symlink_to(path)
    store = _store(alias)

    with pytest.raises(PersistenceError, match="differ from archive storage"):
        if operation == "backup":
            store.backup(Path(f"{alias}{suffix}"))
        else:
            store.export_markdown(article, Path(f"{alias}{suffix}"))

    assert store.get(article.id) == article
    assert store.integrity_check().ok is True


@pytest.mark.parametrize("operation", ["backup", "export"])
def test_outbound_writes_map_symlink_loop_to_persistence_error(
    tmp_path: Path,
    operation: str,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    loop = tmp_path / "loop"
    loop.symlink_to(loop, target_is_directory=True)

    with pytest.raises(PersistenceError, match="destination is invalid"):
        if operation == "backup":
            store.backup(loop / "archive.sqlite3")
        else:
            store.export_markdown(article, loop / "article.md")

    assert store.get(article.id) == article
    assert store.integrity_check().ok is True


def test_backup_and_export_map_unusable_destination_to_persistence(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "data" / "archive.sqlite3")
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    blocked_parent = tmp_path / "not-a-directory"
    blocked_parent.write_text("fixture", encoding="utf-8")

    with pytest.raises(PersistenceError, match="archive backup failed"):
        store.backup(blocked_parent / "archive.sqlite3")
    with pytest.raises(PersistenceError, match="Markdown export failed"):
        store.export_markdown(article, blocked_parent / "article.md")


def test_backup_mutate_restore_recovers_revisions_and_fts(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    offline_store = ArchiveStore(
        path,
        registry=ProviderRegistry((OfflineOnlyFTProvider(),)),
        extractor=VersionedExtractor(),
    )
    current = offline_store.reextract(article.id)
    before_counts = offline_store.inspect_schema()["counts"]
    before_results = [item.public_dict() for item in offline_store.search("capital")]
    backup_path = offline_store.backup(tmp_path / "backup" / "archive.sqlite3")

    assert stat.S_IMODE(backup_path.stat().st_mode) == 0o600
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE articles SET current_extraction_id = NULL")
        connection.execute("DELETE FROM article_fts")
        connection.execute("DELETE FROM extractions")
        connection.execute("DELETE FROM fetches")
        connection.execute("DELETE FROM articles")
    assert offline_store.search("capital") == []

    offline_store.restore(backup_path)

    assert offline_store.integrity_check().public_dict() == {
        "ok": True,
        "integrity": "ok",
        "foreign_key_violations": 0,
        "user_version": SCHEMA_VERSION,
    }
    assert offline_store.inspect_schema()["counts"] == before_counts
    assert [
        item.public_dict() for item in offline_store.search("capital")
    ] == before_results
    assert offline_store.get(article.id) == current


def test_restore_migrates_a_v1_backup_before_replacing_the_archive(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    legacy = _copy_as_v1_archive(path, tmp_path / "backup" / "archive-v1.sqlite3")
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM article_fts")
        connection.execute("DELETE FROM extractions")
        connection.execute("DELETE FROM fetches")
        connection.execute("DELETE FROM articles")

    store.restore(legacy)

    assert store.get(article.id) == article
    assert store.search("capital") == [article]
    assert store.integrity_check().user_version == SCHEMA_VERSION
    assert store.inspect_schema()["journal_mode"] == "wal"


def test_invalid_restore_source_does_not_replace_archive(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    invalid = tmp_path / "invalid.sqlite3"
    with sqlite3.connect(invalid) as connection:
        connection.execute("CREATE TABLE unrelated(value TEXT)")

    with pytest.raises(PersistenceError, match="valid archive backup"):
        store.restore(invalid)

    assert store.get(article.id) == article
    assert store.integrity_check().ok is True


def test_restore_rejects_same_named_incompatible_schema_without_replacing_archive(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    invalid = tmp_path / "same-names.sqlite3"
    with sqlite3.connect(invalid) as connection:
        for table in ("articles", "fetches", "extractions", "article_fts"):
            connection.execute(f"CREATE TABLE {table}(unrelated TEXT)")
        connection.execute("PRAGMA user_version=1")

    with pytest.raises(PersistenceError, match="schema"):
        store.restore(invalid)

    assert store.get(article.id) == article
    assert store.integrity_check().ok is True


def test_restore_rejects_foreign_key_violations_before_replacing_archive(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    invalid = store.backup(tmp_path / "foreign-key-invalid.sqlite3")
    with sqlite3.connect(invalid) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            "INSERT INTO fetches("
            "provider, provider_article_id, article_id, requested_url, final_url, "
            "http_status, content_type, retry_after, retrieved_at, "
            "session_cookie_present, raw_sha256, evidence_sha256, raw_html_gzip, "
            "assessment_json, first_seen_at, last_seen_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "ft",
                "missing",
                "ft:missing",
                "https://www.ft.com/content/00000000-0000-4000-8000-000000000000",
                "https://www.ft.com/content/00000000-0000-4000-8000-000000000000",
                200,
                "text/html",
                None,
                NOW.isoformat(),
                1,
                "0" * 64,
                "1" * 64,
                b"not-used",
                "{}",
                NOW.isoformat(),
                NOW.isoformat(),
            ),
        )

    with pytest.raises(PersistenceError, match="valid archive backup"):
        store.restore(invalid)

    assert store.get(article.id) == article
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM fetches").fetchone()[0] == 1


def test_restore_rejects_logically_corrupt_rows_without_replacing_archive(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    invalid = store.backup(tmp_path / "logically-invalid.sqlite3")
    with sqlite3.connect(invalid) as connection:
        connection.execute(
            "UPDATE articles SET authors_json = ? WHERE id = ?",
            ("not-json", article.id),
        )

    with pytest.raises(PersistenceError, match="valid archive backup"):
        store.restore(invalid)

    assert store.get(article.id) == article


def test_restore_rejects_invalid_deflate_without_replacing_archive(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    invalid = store.backup(tmp_path / "invalid-deflate.sqlite3")
    with sqlite3.connect(invalid) as connection:
        connection.execute(
            "UPDATE fetches SET raw_html_gzip = ?",
            (INVALID_DEFLATE_GZIP,),
        )

    with pytest.raises(PersistenceError, match="valid archive backup"):
        store.restore(invalid)

    assert store.get(article.id) == article
    assert store.integrity_check().ok is True


def test_restore_rejects_missing_revision_assessment_without_replacing_archive(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    invalid = store.backup(tmp_path / "missing-assessment.sqlite3")
    with sqlite3.connect(invalid) as connection:
        connection.execute("DELETE FROM extraction_assessments")

    with pytest.raises(PersistenceError, match="valid archive backup"):
        store.restore(invalid)

    assert store.get(article.id) == article


def test_restore_rejects_cross_linked_revisions_without_replacing_archive(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    second_provider_id = "22222222-2222-4222-8222-222222222222"
    second_url = f"https://www.ft.com/content/{second_provider_id}"
    second_fetch = RawFetch.model_validate(
        {
            **fetch.model_dump(mode="python"),
            "requested_url": second_url,
            "final_url": second_url,
        }
    )
    second_assessment = type(assessment).model_validate(
        {
            **assessment.model_dump(mode="python"),
            "provider_article_id": second_provider_id,
            "canonical_url": second_url,
        }
    )
    second_article = build_article(
        FTProvider(),
        second_fetch,
        extraction,
        second_assessment,
        extractor_name="fixture",
        extractor_version="1",
    )
    store.save(
        "ft",
        second_article,
        second_fetch,
        second_assessment,
        extraction,
    )
    invalid = store.backup(tmp_path / "cross-linked.sqlite3")
    with sqlite3.connect(invalid) as connection:
        connection.execute(
            "UPDATE extractions SET article_id = ? WHERE article_id = ?",
            (article.id, second_article.id),
        )

    with pytest.raises(PersistenceError, match="valid archive backup"):
        store.restore(invalid)

    assert store.get(article.id) == article
    assert store.get(second_article.id) == second_article


def test_restore_accepts_backup_paths_with_uri_characters(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    backup = store.backup(tmp_path / "backup?version=1#safe.sqlite3")
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM article_fts")
        connection.execute("DELETE FROM extractions")
        connection.execute("DELETE FROM fetches")
        connection.execute("DELETE FROM articles")

    store.restore(backup)

    assert store.get(article.id) == article


def test_serving_transport_round_trips_and_enters_fetch_identity(
    tmp_path: Path,
) -> None:
    """R8 provenance: the archive records which transport served the bytes."""

    store = _store(tmp_path / "archive.sqlite3")
    curl_fetch = _raw().model_copy(update={"serving_transport": "safari2601"})
    article, _fetch, assessment, extraction = _accepted(curl_fetch)

    store.save("ft", article, curl_fetch, assessment, extraction)

    snapshots = store.current_raw_snapshots()
    assert [snapshot[2].serving_transport for snapshot in snapshots] == ["safari2601"]

    # The same bytes served by another transport are different evidence, so
    # they land as their own row rather than bumping the first one's count.
    browser_fetch = curl_fetch.model_copy(update={"serving_transport": "browser"})
    store.save("ft", article, browser_fetch, assessment, extraction)

    assert store.inspect_schema()["counts"]["fetches"] == 2
    assert store.integrity_check().ok is True


def test_rows_stored_before_provenance_keep_validating(tmp_path: Path) -> None:
    """A pre-v3 row's evidence hash must not be retroactively reinterpreted."""

    store = _store(tmp_path / "archive.sqlite3")
    article, fetch, assessment, extraction = _accepted()
    assert fetch.serving_transport is None

    store.save("ft", article, fetch, assessment, extraction)

    # Reading, re-extracting, and integrity all accept the unknown transport.
    assert store.current_raw_snapshots()[0][2].serving_transport is None
    assert store.integrity_check().ok is True
    assert store.reextract(article.id) == article


def test_v2_archive_gains_the_transport_column_without_touching_rows(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    del store

    path = tmp_path / "archive.sqlite3"
    with sqlite3.connect(path) as connection:
        before = connection.execute(
            "SELECT evidence_sha256 FROM fetches ORDER BY id"
        ).fetchall()
        connection.execute("ALTER TABLE fetches DROP COLUMN serving_transport")
        connection.execute("PRAGMA user_version=2")

    migrated = _store(path)

    assert migrated.inspect_schema()["user_version"] == SCHEMA_VERSION
    with sqlite3.connect(path) as connection:
        after = connection.execute(
            "SELECT evidence_sha256, serving_transport FROM fetches ORDER BY id"
        ).fetchall()
    assert [(row[0],) for row in after] == before
    assert all(row[1] is None for row in after)
    assert migrated.integrity_check().ok is True
    assert migrated.get(article.id) == article


def test_restore_migrates_a_v2_backup_before_replacing_the_archive(
    tmp_path: Path,
) -> None:
    """A backup taken before the transport column still restores (R8)."""

    path = tmp_path / "data" / "archive.sqlite3"
    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)

    legacy = tmp_path / "backup" / "archive-v2.sqlite3"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    store.backup(legacy)
    with sqlite3.connect(legacy) as connection:
        connection.execute("ALTER TABLE fetches DROP COLUMN serving_transport")
        connection.execute("PRAGMA user_version=2")
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM article_fts")
        connection.execute("DELETE FROM extraction_assessments")
        connection.execute("DELETE FROM extractions")
        connection.execute("DELETE FROM fetches")
        connection.execute("DELETE FROM articles")

    store.restore(legacy)

    assert store.get(article.id) == article
    assert store.integrity_check().user_version == SCHEMA_VERSION
    assert store.current_raw_snapshots()[0][2].serving_transport is None


def _saved_with_second_revision(path: Path) -> Article:
    """An archive whose current extraction id is not the first row id."""

    store = _store(path)
    article, fetch, assessment, extraction = _accepted()
    store.save("ft", article, fetch, assessment, extraction)
    reextracting = ArchiveStore(
        path,
        registry=ProviderRegistry((OfflineOnlyFTProvider(),)),
        extractor=ChangedOutputExtractor(
            f"{TrafilaturaExtractor().version}.fixture-v2"
        ),
    )
    return reextracting.reextract(article.id)


def _fts_rows(path: Path) -> list[tuple[int, str]]:
    with sqlite3.connect(path) as connection:
        return connection.execute(
            "SELECT rowid, article_id FROM article_fts ORDER BY rowid"
        ).fetchall()


def test_fts_rows_are_keyed_and_replaced_by_current_extraction_id(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    article = _saved_with_second_revision(path)

    with sqlite3.connect(path) as connection:
        current = connection.execute(
            "SELECT current_extraction_id FROM articles WHERE id = ?", (article.id,)
        ).fetchone()[0]
    # The first revision's row was deleted by rowid, not left behind.
    assert current == 2
    assert _fts_rows(path) == [(2, article.id)]
    assert _store(path).search("VERSIONED_OUTPUT_SENTINEL") == [article]
    assert _store(path).integrity_check().ok is True


def test_fts_delete_is_a_rowid_lookup_not_an_index_scan(tmp_path: Path) -> None:
    from newsclip.archive import _FTS_DELETE_SQL

    path = tmp_path / "data" / "archive.sqlite3"
    _store(path)
    with sqlite3.connect(path) as connection:
        plan = connection.execute(
            f"EXPLAIN QUERY PLAN {_FTS_DELETE_SQL}", (1,)
        ).fetchall()
        legacy = connection.execute(
            "EXPLAIN QUERY PLAN DELETE FROM article_fts WHERE article_id = ?", ("x",)
        ).fetchall()
    # FTS5 reports a rowid-equality plan as "INDEX 0:=" and a full scan of
    # every row (the v3 UNINDEXED article_id delete) as a bare "INDEX 0:".
    assert [row[3] for row in plan] == ["SCAN article_fts VIRTUAL TABLE INDEX 0:="]
    assert [row[3] for row in legacy] == ["SCAN article_fts VIRTUAL TABLE INDEX 0:"]


def _downgrade_to_v3(path: Path) -> None:
    """Reproduce a v3 archive: identical tables, FTS rows keyed arbitrarily."""

    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT article_id, headline, body_markdown FROM article_fts"
        ).fetchall()
        connection.execute("DELETE FROM article_fts")
        connection.executemany(
            "INSERT INTO article_fts(rowid, article_id, headline, body_markdown) "
            "VALUES (?, ?, ?, ?)",
            [(100 + index, *row) for index, row in enumerate(rows)],
        )
        connection.execute("PRAGMA user_version=3")


def test_v3_archive_migrates_to_rowid_keyed_fts_with_data(tmp_path: Path) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    article = _saved_with_second_revision(path)
    before_counts = _store(path).inspect_schema()["counts"]
    _downgrade_to_v3(path)
    assert _fts_rows(path) == [(100, article.id)]

    migrated = _store(path)

    assert migrated.inspect_schema()["user_version"] == SCHEMA_VERSION == 4
    assert migrated.inspect_schema()["counts"] == before_counts
    assert _fts_rows(path) == [(2, article.id)]
    assert migrated.search("VERSIONED_OUTPUT_SENTINEL") == [article]
    assert migrated.get(article.id) == article
    assert migrated.integrity_check().ok is True
    # A later save replaces the migrated row instead of adding a second one.
    migrated.save("ft", *_accepted())
    assert len(_fts_rows(path)) == 1


def test_integrity_check_rejects_fts_rows_keyed_by_anything_else(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    _saved_with_second_revision(path)
    store = _store(path)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE article_fts SET rowid = 7")

    assert store.integrity_check().ok is False


def test_restore_migrates_a_v3_backup_before_replacing_the_archive(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "archive.sqlite3"
    article = _saved_with_second_revision(path)
    store = _store(path)
    legacy = tmp_path / "backup" / "archive-v3.sqlite3"
    store.backup(legacy)
    _downgrade_to_v3(legacy)
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM article_fts")

    store.restore(legacy)

    assert store.integrity_check().user_version == SCHEMA_VERSION
    assert _fts_rows(path) == [(2, article.id)]
    assert store.search("VERSIONED_OUTPUT_SENTINEL") == [article]
