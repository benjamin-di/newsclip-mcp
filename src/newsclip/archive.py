"""Crash-consistent SQLite archive and rebuildable full-text index."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import zlib
from collections.abc import Callable
from contextlib import suppress
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .articles import build_article
from .contracts import ExtractionEngine
from .errors import ContentNotFullError, PersistenceError
from .models import (
    ArchiveIntegrity,
    ArchiveIntegrityStatus,
    Article,
    ArticleAssessment,
    ExtractedArticle,
    RawFetch,
)
from .providers.base import (
    ProviderNativeExtraction,
    ProviderNativeExtractionState,
)
from .providers.registry import ProviderRegistry

SCHEMA_VERSION = 4
#: Every schema version a backup may carry into a restore. Older versions
#: are migrated forward on the staged copy before it replaces the archive.
_RESTORABLE_SCHEMA_VERSIONS = frozenset({1, 2, 3, SCHEMA_VERSION})
# v4 keys each full-text row by its FTS rowid, which equals the article's
# current extraction id (an INTEGER PRIMARY KEY, so VACUUM cannot renumber
# it). `article_id` is UNINDEXED in FTS5, so deleting by it scanned the whole
# index on every save; a rowid delete is a direct lookup. The table
# definition is unchanged: v3 and v4 differ only in how rows are keyed.
_FTS_DELETE_SQL = "DELETE FROM article_fts WHERE rowid = ?"
_FTS_REBUILD_SQL = (
    "INSERT INTO article_fts(rowid, article_id, headline, body_markdown) "
    "SELECT e.id, a.id, a.headline, e.body_markdown FROM articles a "
    "JOIN extractions e ON e.id = a.current_extraction_id"
)
_TABLES = (
    "articles",
    "fetches",
    "extractions",
    "extraction_assessments",
    "article_fts",
)
_FETCHES_V1_TABLE = """
CREATE TABLE fetches (
    id INTEGER PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_article_id TEXT,
    article_id TEXT,
    requested_url TEXT NOT NULL,
    final_url TEXT NOT NULL,
    http_status INTEGER NOT NULL,
    content_type TEXT,
    retrieved_at TEXT NOT NULL,
    session_cookie_present INTEGER NOT NULL,
    raw_sha256 TEXT NOT NULL,
    raw_html_gzip BLOB NOT NULL,
    assessment_json TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(provider, requested_url, raw_sha256),
    FOREIGN KEY(article_id) REFERENCES articles(id)
);
"""
_FETCHES_V2_TABLE = """
CREATE TABLE fetches (
    id INTEGER PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_article_id TEXT,
    article_id TEXT,
    requested_url TEXT NOT NULL,
    final_url TEXT NOT NULL,
    http_status INTEGER NOT NULL,
    content_type TEXT,
    retry_after REAL,
    retrieved_at TEXT NOT NULL,
    session_cookie_present INTEGER NOT NULL,
    raw_sha256 TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    raw_html_gzip BLOB NOT NULL,
    assessment_json TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(provider, evidence_sha256),
    FOREIGN KEY(article_id) REFERENCES articles(id)
);
"""
# v3 adds the serving transport: which profile, or the browser, produced
# these bytes. A runtime pin and a per-fetch browser escalation both break
# the old inference from the definition's git history, so the fact is stored
# (ARCHITECTURE, "Transport pins"). NULL on every pre-v3 row, which is what
# keeps their evidence hashes valid under the prior shape.
_FETCHES_V3_TABLE = """
CREATE TABLE fetches (
    id INTEGER PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_article_id TEXT,
    article_id TEXT,
    requested_url TEXT NOT NULL,
    final_url TEXT NOT NULL,
    http_status INTEGER NOT NULL,
    content_type TEXT,
    retry_after REAL,
    retrieved_at TEXT NOT NULL,
    session_cookie_present INTEGER NOT NULL,
    raw_sha256 TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    raw_html_gzip BLOB NOT NULL,
    assessment_json TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    -- Declared last so a v2 archive's ALTER TABLE ADD COLUMN produces the
    -- identical column order, and one signature describes both paths.
    serving_transport TEXT,
    UNIQUE(provider, evidence_sha256),
    FOREIGN KEY(article_id) REFERENCES articles(id)
);
"""
_EXTRACTION_ASSESSMENTS_TABLE = """
CREATE TABLE extraction_assessments (
    extraction_id INTEGER PRIMARY KEY,
    assessment_json TEXT NOT NULL,
    FOREIGN KEY(extraction_id) REFERENCES extractions(id) ON DELETE CASCADE
);
"""
_SCHEMA_TEMPLATE = """
BEGIN IMMEDIATE;

CREATE TABLE articles (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_article_id TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    headline TEXT NOT NULL,
    authors_json TEXT NOT NULL,
    published TEXT,
    section TEXT,
    current_extraction_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(provider, provider_article_id),
    FOREIGN KEY(current_extraction_id) REFERENCES extractions(id)
);

{fetches_table}

CREATE INDEX fetches_article_id ON fetches(article_id);

CREATE TABLE extractions (
    id INTEGER PRIMARY KEY,
    article_id TEXT NOT NULL,
    fetch_id INTEGER NOT NULL,
    extractor_name TEXT NOT NULL,
    extractor_version TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    assessment_schema_version INTEGER NOT NULL,
    body_markdown TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    word_count INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(fetch_id, extractor_name, extractor_version, policy_version),
    FOREIGN KEY(article_id) REFERENCES articles(id),
    FOREIGN KEY(fetch_id) REFERENCES fetches(id)
);

CREATE INDEX extractions_article_id ON extractions(article_id);

{extraction_assessments_table}

CREATE VIRTUAL TABLE article_fts USING fts5(
    article_id UNINDEXED,
    headline,
    body_markdown,
    tokenize = 'unicode61'
);

PRAGMA user_version = {schema_version};
COMMIT;
"""
_SCHEMA_V1 = _SCHEMA_TEMPLATE.format(
    fetches_table=_FETCHES_V1_TABLE,
    extraction_assessments_table="",
    schema_version=1,
)
_SCHEMA_V2 = _SCHEMA_TEMPLATE.format(
    fetches_table=_FETCHES_V2_TABLE,
    extraction_assessments_table=_EXTRACTION_ASSESSMENTS_TABLE,
    schema_version=2,
)
_SCHEMA_V3 = _SCHEMA_TEMPLATE.format(
    fetches_table=_FETCHES_V3_TABLE,
    extraction_assessments_table=_EXTRACTION_ASSESSMENTS_TABLE,
    schema_version=3,
)
_SCHEMA = _SCHEMA_TEMPLATE.format(
    fetches_table=_FETCHES_V3_TABLE,
    extraction_assessments_table=_EXTRACTION_ASSESSMENTS_TABLE,
    schema_version=SCHEMA_VERSION,
)


class ArchiveStore:
    """One private SQLite database containing raw evidence and accepted revisions."""

    def __init__(
        self,
        path: Path,
        *,
        registry: ProviderRegistry | None = None,
        extractor: ExtractionEngine | None = None,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.path = Path(path)
        self._registry = registry
        self._extractor = extractor
        self._fault_hook = fault_hook
        self._initialize()

    def save(
        self,
        provider_key: str,
        article: Article | None,
        fetch: RawFetch,
        assessment: ArticleAssessment,
        extraction: ExtractedArticle,
        *,
        expected_current_extraction_id: int | None = None,
    ) -> Article | None:
        """Commit evidence and promote an article if its expected base is current."""

        promotable = assessment.promotable
        if promotable != (article is not None):
            raise PersistenceError(
                "accepted assessment and supplied article must agree"
            )
        if article is not None:
            self._validate_article(
                provider_key,
                article,
                fetch,
                assessment,
                extraction,
            )

        try:
            raw_sha256 = hashlib.sha256(fetch.raw_html).hexdigest()
            evidence_sha256 = _fetch_evidence_sha256(
                provider_key,
                requested_url=str(fetch.requested_url),
                final_url=str(fetch.final_url),
                http_status=fetch.http_status,
                content_type=fetch.content_type,
                retry_after=fetch.retry_after,
                session_cookie_present=fetch.session_cookie_present,
                raw_sha256=raw_sha256,
                serving_transport=fetch.serving_transport,
            )
            compressed = gzip.compress(fetch.raw_html, mtime=0)
            assessment_json = assessment.model_dump_json()
            metadata_json = json.dumps(
                extraction.metadata, ensure_ascii=False, sort_keys=True
            )
        except (OSError, TypeError, ValueError) as error:
            raise PersistenceError("archive save failed") from error
        retrieved_at = fetch.retrieved_at.isoformat()

        connection = self._connect()
        try:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                if expected_current_extraction_id is not None:
                    current = connection.execute(
                        "SELECT current_extraction_id FROM articles WHERE id = ?",
                        (article.id if article is not None else None,),
                    ).fetchone()
                    if (
                        current is None
                        or current["current_extraction_id"]
                        != expected_current_extraction_id
                    ):
                        raise PersistenceError(
                            "archive current revision changed during re-extraction"
                        )
                if article is not None:
                    self._upsert_article(connection, article)
                linked_article_id = self._existing_article_id(
                    connection, provider_key, assessment.provider_article_id
                )
                fetch_id = self._upsert_fetch(
                    connection,
                    provider_key=provider_key,
                    article_id=linked_article_id,
                    provider_article_id=assessment.provider_article_id,
                    fetch=fetch,
                    raw_sha256=raw_sha256,
                    evidence_sha256=evidence_sha256,
                    compressed=compressed,
                    assessment_json=assessment_json,
                    retrieved_at=retrieved_at,
                )
                self._fault("after_fetch_before_commit")
                if article is None:
                    return None

                extraction_id = self._upsert_extraction(
                    connection,
                    article,
                    fetch_id,
                    extraction,
                    metadata_json,
                    assessment_json,
                )
                previous = connection.execute(
                    "SELECT current_extraction_id FROM articles WHERE id = ?",
                    (article.id,),
                ).fetchone()
                connection.execute(
                    "UPDATE articles SET current_extraction_id = ?, updated_at = ? "
                    "WHERE id = ?",
                    (extraction_id, retrieved_at, article.id),
                )
                if previous is not None and previous[0] is not None:
                    connection.execute(_FTS_DELETE_SQL, (previous[0],))
                connection.execute(
                    "INSERT INTO article_fts(rowid, article_id, headline, "
                    "body_markdown) VALUES (?, ?, ?, ?)",
                    (
                        extraction_id,
                        article.id,
                        article.headline,
                        article.body_markdown,
                    ),
                )
                self._fault("before_commit")
                saved_article = _current_article(connection, article.id)
            # An exact observation seen again updates its occurrence counters but
            # does not create a new extraction revision. Return the canonical
            # stored revision rather than a caller object with a later observation
            # timestamp that was deliberately deduplicated. The row was captured
            # inside this write transaction, so another writer cannot change the
            # operation's response after commit.
            return saved_article
        except (sqlite3.Error, OSError, TypeError, ValueError) as error:
            raise PersistenceError("archive save failed") from error
        finally:
            connection.close()
            self._enforce_modes()

    def get(self, article_id: str) -> Article:
        connection = self._connect()
        try:
            return _current_article(connection, article_id)
        except sqlite3.Error as error:
            raise PersistenceError("archive read failed") from error
        finally:
            connection.close()

    def current_raw_snapshots(
        self, *, provider: str | None = None
    ) -> list[tuple[str, str, RawFetch, ArticleAssessment]]:
        """Return ``(article_id, provider, raw_fetch, stored_assessment)`` for
        every current accepted extraction. Read-only: it decompresses archived
        raw bytes for drift re-assessment but never writes or moves a pointer."""

        sql = (
            "SELECT a.id AS article_id, a.provider AS provider, "
            "f.requested_url, f.final_url, f.http_status, f.content_type, "
            "f.retry_after, f.retrieved_at, f.session_cookie_present, "
            "f.serving_transport, f.raw_sha256, f.evidence_sha256, "
            "f.raw_html_gzip, ea.assessment_json "
            "FROM articles a "
            "JOIN extractions e ON e.id = a.current_extraction_id "
            "JOIN extraction_assessments ea ON ea.extraction_id = e.id "
            "JOIN fetches f ON f.id = e.fetch_id"
        )
        parameters: list[str] = []
        if provider is not None:
            sql += " WHERE a.provider = ?"
            parameters.append(provider)
        sql += " ORDER BY a.id"
        connection = self._connect()
        try:
            rows = connection.execute(sql, parameters).fetchall()
        except sqlite3.Error as error:
            raise PersistenceError("archive snapshot read failed") from error
        finally:
            connection.close()

        snapshots: list[tuple[str, str, RawFetch, ArticleAssessment]] = []
        for row in rows:
            try:
                raw_html = gzip.decompress(row["raw_html_gzip"])
                if hashlib.sha256(raw_html).hexdigest() != row["raw_sha256"]:
                    raise PersistenceError("archived raw fetch hash is inconsistent")
                fetch = RawFetch(
                    requested_url=row["requested_url"],
                    final_url=row["final_url"],
                    http_status=row["http_status"],
                    content_type=row["content_type"],
                    retry_after=row["retry_after"],
                    retrieved_at=row["retrieved_at"],
                    session_cookie_present=bool(row["session_cookie_present"]),
                    serving_transport=row["serving_transport"],
                    raw_html=raw_html,
                )
                assessment = ArticleAssessment.model_validate_json(
                    row["assessment_json"]
                )
                _validate_fetch_evidence(row, fetch)
            except (
                EOFError,
                OSError,
                TypeError,
                ValueError,
                ValidationError,
                zlib.error,
            ) as error:
                raise PersistenceError("archived raw fetch is corrupt") from error
            snapshots.append((row["article_id"], row["provider"], fetch, assessment))
        return snapshots

    def search(
        self,
        query: str,
        *,
        provider: str | None = None,
        limit: int | None = None,
    ) -> list[Article]:
        if limit is not None and limit < 1:
            raise ValueError("archive search limit must be positive")
        fts_query = _fts_query(query)
        if not fts_query:
            return []
        sql = (
            _CURRENT_ARTICLE_SQL
            + " JOIN article_fts ON article_fts.article_id = a.id "
            + "WHERE article_fts MATCH ?"
        )
        parameters: list[object] = [fts_query]
        if provider is not None:
            sql += " AND a.provider = ?"
            parameters.append(provider)
        sql += " ORDER BY bm25(article_fts), a.id"
        if limit is not None:
            sql += " LIMIT ?"
            parameters.append(limit)
        connection = self._connect()
        try:
            rows = connection.execute(sql, parameters).fetchall()
        except sqlite3.Error as error:
            raise PersistenceError("archive search failed") from error
        finally:
            connection.close()
        return [_article_from_row(row) for row in rows]

    def reextract(self, article_id: str) -> Article:
        """Re-run the configured extractor solely against archived raw bytes."""

        if self._registry is None or self._extractor is None:
            raise PersistenceError("re-extraction dependencies are not configured")
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT e.id AS extraction_id, a.provider, f.requested_url, "
                "f.final_url, f.http_status, "
                "f.content_type, f.retry_after, f.retrieved_at, "
                "f.session_cookie_present, f.serving_transport, "
                "f.raw_sha256, f.evidence_sha256, "
                "f.raw_html_gzip "
                "FROM articles a "
                "JOIN extractions e ON e.id = a.current_extraction_id "
                "JOIN fetches f ON f.id = e.fetch_id "
                "WHERE a.id = ?",
                (article_id,),
            ).fetchone()
        except sqlite3.Error as error:
            raise PersistenceError("archived raw fetch read failed") from error
        finally:
            connection.close()
        if row is None:
            raise PersistenceError("archived article not found")

        try:
            raw_html = gzip.decompress(row["raw_html_gzip"])
            if hashlib.sha256(raw_html).hexdigest() != row["raw_sha256"]:
                raise PersistenceError("archived raw fetch hash is inconsistent")
            fetch = RawFetch(
                requested_url=row["requested_url"],
                final_url=row["final_url"],
                http_status=row["http_status"],
                content_type=row["content_type"],
                retry_after=row["retry_after"],
                retrieved_at=row["retrieved_at"],
                session_cookie_present=bool(row["session_cookie_present"]),
                serving_transport=row["serving_transport"],
                raw_html=raw_html,
            )
            _validate_fetch_evidence(row, fetch)
        except (
            EOFError,
            OSError,
            TypeError,
            ValueError,
            ValidationError,
            zlib.error,
        ) as error:
            raise PersistenceError("archived raw fetch is corrupt") from error
        provider = self._registry.get(row["provider"])
        extraction = self._extractor.extract(
            fetch, scope_xpath=provider.extraction_scope
        )
        assessment = provider.assess(str(fetch.requested_url), fetch, extraction)
        extractor_name = self._extractor.name
        extractor_version = self._extractor.version
        if isinstance(provider, ProviderNativeExtraction):
            native = provider.native_extraction(str(fetch.requested_url), fetch)
            if native.state is ProviderNativeExtractionState.INVALID:
                raise ContentNotFullError("insufficient_article_structure")
            if native.state is ProviderNativeExtractionState.VALID:
                if (
                    native.extraction is None
                    or native.assessment is None
                    or native.extractor_name is None
                    or native.extractor_version is None
                ):
                    raise PersistenceError(
                        "valid native re-extraction omitted candidate fields"
                    )
                extraction = native.extraction
                assessment = native.assessment
                extractor_name = native.extractor_name
                extractor_version = native.extractor_version
        if not assessment.promotable:
            raise ContentNotFullError(assessment.reason)
        article = build_article(
            provider,
            fetch,
            extraction,
            assessment,
            extractor_name=extractor_name,
            extractor_version=extractor_version,
        )
        saved = self.save(
            provider.key,
            article,
            fetch,
            assessment,
            extraction,
            expected_current_extraction_id=row["extraction_id"],
        )
        if saved is None:  # pragma: no cover - guarded by the promotable check
            raise PersistenceError("accepted re-extraction was not saved")
        return saved

    def rebuild_fts(self) -> None:
        connection = self._connect()
        try:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("DROP TABLE article_fts")
                connection.execute(
                    "CREATE VIRTUAL TABLE article_fts USING fts5("
                    "article_id UNINDEXED, headline, body_markdown, "
                    "tokenize = 'unicode61')"
                )
                connection.execute(_FTS_REBUILD_SQL)
        except sqlite3.Error as error:
            raise PersistenceError("FTS rebuild failed") from error
        finally:
            connection.close()
            self._enforce_modes()

    def integrity_check(self) -> ArchiveIntegrity:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            rows = connection.execute("PRAGMA integrity_check").fetchall()
            messages = tuple(str(row[0]) for row in rows)
            foreign_key_violations = connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
            logical_ok = False
            if messages == ("ok",) and not foreign_key_violations:
                try:
                    self._validate_schema(connection)
                    self._validate_backup_contents(connection)
                except (
                    EOFError,
                    OSError,
                    PersistenceError,
                    sqlite3.Error,
                    TypeError,
                    ValueError,
                    zlib.error,
                ):
                    pass
                else:
                    logical_ok = True
            ok = messages == ("ok",) and not foreign_key_violations and logical_ok
            return ArchiveIntegrity(
                ok=ok,
                integrity=(
                    ArchiveIntegrityStatus.OK if ok else ArchiveIntegrityStatus.FAILED
                ),
                foreign_key_violations=len(foreign_key_violations),
                user_version=user_version,
            )
        except sqlite3.Error as error:
            raise PersistenceError("archive integrity check failed") from error
        finally:
            connection.close()

    def backup(self, destination: Path) -> Path:
        destination = Path(destination)
        self._reject_archive_owned_destination(destination, operation="backup")
        temporary: Path | None = None
        source: sqlite3.Connection | None = None
        target: sqlite3.Connection | None = None
        try:
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{destination.name}.",
                suffix=".tmp",
                dir=destination.parent,
            )
            temporary = Path(temporary_name)
            os.close(descriptor)
            source = self._connect()
            target = sqlite3.connect(temporary)
            source.backup(target)
            target.commit()
            target.close()
            target = None
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
            _fsync_directory(destination.parent)
        except PersistenceError:
            _discard_temporary(temporary)
            raise
        except (sqlite3.Error, OSError) as error:
            _discard_temporary(temporary)
            raise PersistenceError("archive backup failed") from error
        finally:
            if target is not None:
                target.close()
            if source is not None:
                source.close()
        return destination

    def restore(self, source: Path) -> None:
        source_path = Path(source)
        if source_path.resolve() == self.path.resolve():
            raise PersistenceError("restore source must differ from archive")
        source_connection: sqlite3.Connection | None = None
        staged: sqlite3.Connection | None = None
        destination: sqlite3.Connection | None = None
        staged_path: Path | None = None
        try:
            source_connection = sqlite3.connect(
                f"{source_path.resolve().as_uri()}?mode=ro", uri=True
            )
            source_connection.row_factory = sqlite3.Row
            # Keep validation and the backup copy on one immutable read
            # snapshot, even if another process still has the source open.
            source_connection.execute("BEGIN")
            source_version = source_connection.execute(
                "PRAGMA user_version"
            ).fetchone()[0]
            source_integrity = source_connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
            if source_version not in _RESTORABLE_SCHEMA_VERSIONS or (
                source_integrity != "ok"
            ):
                raise PersistenceError("restore source is not a valid archive backup")
            self._validate_schema(source_connection, version=source_version)
            if source_connection.execute("PRAGMA foreign_key_check").fetchone():
                raise PersistenceError("restore source is not a valid archive backup")

            descriptor, staged_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.restore.",
                suffix=".tmp",
                dir=self.path.parent,
            )
            os.close(descriptor)
            staged_path = Path(staged_name)
            staged = sqlite3.connect(staged_path)
            staged.row_factory = sqlite3.Row
            source_connection.backup(staged)
            staged.commit()
            if source_version == 1:
                self._migrate_v1_to_v2(staged)
            if source_version < 3:
                self._migrate_v2_to_v3(staged)
            if source_version < SCHEMA_VERSION:
                self._migrate_v3_to_v4(staged)
            staged.execute("PRAGMA foreign_keys=ON")
            self._validate_schema(staged)
            if staged.execute("PRAGMA foreign_key_check").fetchone():
                raise PersistenceError("restore source is not a valid archive backup")
            try:
                self._validate_backup_contents(staged)
            except (
                EOFError,
                OSError,
                PersistenceError,
                TypeError,
                ValueError,
                zlib.error,
            ) as error:
                raise PersistenceError(
                    "restore source is not a valid archive backup"
                ) from error
            destination = self._connect()
            staged.backup(destination)
            destination.commit()
            destination.execute("PRAGMA journal_mode=WAL")
        except PersistenceError:
            raise
        except (sqlite3.Error, OSError) as error:
            raise PersistenceError("archive restore failed") from error
        finally:
            if destination is not None:
                destination.close()
            if staged is not None:
                staged.close()
            if source_connection is not None:
                source_connection.close()
            _discard_sqlite_temporary(staged_path)
            self._enforce_modes()
        if not self.integrity_check().ok:
            raise PersistenceError("restored archive failed integrity check")

    def export_markdown(self, article: Article, path: Path) -> Path:
        """Atomically export only the currently committed article revision."""

        destination = Path(path)
        self._reject_archive_owned_destination(destination, operation="Markdown export")
        current = self.get(article.id)
        if current.extraction != article.extraction:
            raise PersistenceError("only the current archived revision can be exported")
        file_descriptor: int | None = None
        temporary_path: Path | None = None
        try:
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{destination.name}.", dir=destination.parent
            )
            temporary_path = Path(temporary_name)
            handle = os.fdopen(file_descriptor, "w", encoding="utf-8")
            file_descriptor = None
            with handle:
                handle.write(current.body_markdown)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_path, 0o600)
            self._fault("before_export_replace")
            os.replace(temporary_path, destination)
            os.chmod(destination, 0o600)
            directory_descriptor = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError as error:
            _discard_temporary(temporary_path)
            raise PersistenceError("Markdown export failed") from error
        finally:
            if file_descriptor is not None:
                os.close(file_descriptor)
        return destination

    def _reject_archive_owned_destination(
        self,
        destination: Path,
        *,
        operation: str,
    ) -> None:
        try:
            with suppress(FileNotFoundError, NotADirectoryError):
                destination.resolve(strict=True)
                # New exports/backups may not exist. Other failures, including
                # symlink loops, must not be hidden by non-strict resolution.
            archive_paths = {
                Path(os.path.abspath(self.path)),
                self.path.resolve(),
            }
            archive_owned_paths = {
                owned
                for archive in archive_paths
                for owned in (archive, Path(f"{archive}-wal"), Path(f"{archive}-shm"))
            }
            destination_paths = {
                Path(os.path.abspath(destination)),
                destination.resolve(),
            }
        except (OSError, RuntimeError) as error:
            raise PersistenceError(f"{operation} destination is invalid") from error
        if not destination_paths.isdisjoint(archive_owned_paths):
            raise PersistenceError(
                f"{operation} destination must differ from archive storage"
            )

    def inspect_schema(self) -> dict[str, Any]:
        connection = self._connect()
        try:
            counts = {
                table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in _TABLES
            }
            return {
                "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
                "journal_mode": connection.execute("PRAGMA journal_mode").fetchone()[0],
                "foreign_keys": connection.execute("PRAGMA foreign_keys").fetchone()[0],
                "counts": counts,
                "directory_mode": stat.S_IMODE(self.path.parent.stat().st_mode),
                "database_mode": stat.S_IMODE(self.path.stat().st_mode),
            }
        except (sqlite3.Error, OSError) as error:
            raise PersistenceError("archive inspection failed") from error
        finally:
            connection.close()

    def _initialize(self) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.path.parent, 0o700)
            if not self.path.exists():
                descriptor = os.open(
                    self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600
                )
                os.close(descriptor)
            os.chmod(self.path, 0o600)
            connection = sqlite3.connect(self.path)
            try:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version > SCHEMA_VERSION:
                    raise PersistenceError(
                        f"archive schema {version} is newer than supported version "
                        f"{SCHEMA_VERSION}"
                    )
                if version == 0:
                    existing = connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type IN ('table', 'view') "
                        "AND name NOT LIKE 'sqlite_%'"
                    ).fetchall()
                    if existing:
                        raise PersistenceError("unversioned archive is not supported")
                    connection.execute("PRAGMA journal_mode=WAL")
                    try:
                        connection.executescript(_SCHEMA)
                    except sqlite3.Error:
                        connection.rollback()
                        raise
                elif version < SCHEMA_VERSION:
                    # Migrations chain: a v1 archive walks v1→v2→v3→v4 in one
                    # open, and each step validates the shape it expects
                    # before touching a row.
                    self._validate_schema(connection, version=version)
                    if version == 1:
                        self._migrate_v1_to_v2(connection)
                        self._validate_schema(connection, version=2)
                    if version <= 2:
                        self._migrate_v2_to_v3(connection)
                        self._validate_schema(connection, version=3)
                    self._migrate_v3_to_v4(connection)
                    self._validate_schema(connection)
                    if connection.execute("PRAGMA foreign_key_check").fetchone():
                        raise PersistenceError("archive migration broke relationships")
                    connection.execute("PRAGMA journal_mode=WAL")
                else:
                    self._validate_schema(connection)
                    connection.execute("PRAGMA journal_mode=WAL")
                connection.commit()
            finally:
                connection.close()
            self._enforce_modes()
        except PersistenceError:
            raise
        except (sqlite3.Error, OSError) as error:
            raise PersistenceError("archive initialization failed") from error

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.path, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            return connection
        except sqlite3.Error as error:
            raise PersistenceError("archive connection failed") from error

    def _validate_schema(
        self,
        connection: sqlite3.Connection,
        *,
        version: int = SCHEMA_VERSION,
    ) -> None:
        if _schema_signature(connection) != _expected_schema_signature(version):
            raise PersistenceError("archive schema is incompatible")

    def _migrate_v1_to_v2(self, connection: sqlite3.Connection) -> None:
        """Replace the lossy v1 fetch key while preserving every stored row."""

        previous_row_factory = connection.row_factory
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=OFF")
        try:
            connection.execute("BEGIN IMMEDIATE")
            v2_table = _FETCHES_V2_TABLE.replace(
                "CREATE TABLE fetches (", "CREATE TABLE fetches_v2 (", 1
            )
            connection.execute(v2_table)
            rows = connection.execute("SELECT * FROM fetches ORDER BY id").fetchall()
            for row in rows:
                evidence_sha256 = _fetch_evidence_sha256(
                    row["provider"],
                    requested_url=row["requested_url"],
                    final_url=row["final_url"],
                    http_status=row["http_status"],
                    content_type=row["content_type"],
                    retry_after=None,
                    session_cookie_present=bool(row["session_cookie_present"]),
                    raw_sha256=row["raw_sha256"],
                )
                connection.execute(
                    "INSERT INTO fetches_v2("
                    "id, provider, provider_article_id, article_id, requested_url, "
                    "final_url, http_status, content_type, retry_after, retrieved_at, "
                    "session_cookie_present, raw_sha256, evidence_sha256, "
                    "raw_html_gzip, assessment_json, first_seen_at, last_seen_at, "
                    "seen_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "?, ?, ?, ?)",
                    (
                        row["id"],
                        row["provider"],
                        row["provider_article_id"],
                        row["article_id"],
                        row["requested_url"],
                        row["final_url"],
                        row["http_status"],
                        row["content_type"],
                        None,
                        row["retrieved_at"],
                        row["session_cookie_present"],
                        row["raw_sha256"],
                        evidence_sha256,
                        row["raw_html_gzip"],
                        row["assessment_json"],
                        row["first_seen_at"],
                        row["last_seen_at"],
                        row["seen_count"],
                    ),
                )
            connection.execute("DROP TABLE fetches")
            connection.execute("ALTER TABLE fetches_v2 RENAME TO fetches")
            connection.execute("CREATE INDEX fetches_article_id ON fetches(article_id)")
            connection.execute(_EXTRACTION_ASSESSMENTS_TABLE)
            connection.execute(
                "INSERT INTO extraction_assessments(extraction_id, assessment_json) "
                "SELECT e.id, f.assessment_json FROM extractions e "
                "JOIN fetches f ON f.id = e.fetch_id"
            )
            connection.execute("PRAGMA user_version=2")
            connection.commit()
        except (sqlite3.Error, OSError, TypeError, ValueError) as error:
            connection.rollback()
            raise PersistenceError("archive schema migration failed") from error
        finally:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.row_factory = previous_row_factory

    def _migrate_v2_to_v3(self, connection: sqlite3.Connection) -> None:
        """Add the serving-transport column without rewriting a single row.

        Every existing row keeps ``serving_transport`` NULL, which is exactly
        what makes its stored evidence hash still validate: the hash payload
        omits the field when it is unknown, so pre-v3 evidence is unchanged
        rather than retroactively reinterpreted (ARCHITECTURE, "Transport pins").
        """

        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("ALTER TABLE fetches ADD COLUMN serving_transport TEXT")
            connection.execute("PRAGMA user_version=3")
            connection.commit()
        except (sqlite3.Error, OSError) as error:
            connection.rollback()
            raise PersistenceError("archive schema migration failed") from error

    def _migrate_v3_to_v4(self, connection: sqlite3.Connection) -> None:
        """Re-key the full-text index by current extraction id.

        The index is derived data, so it is rebuilt from the accepted
        revisions in the same transaction as the version bump; evidence,
        extraction and article rows are untouched.
        """

        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM article_fts")
            connection.execute(_FTS_REBUILD_SQL)
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            connection.commit()
        except (sqlite3.Error, OSError) as error:
            connection.rollback()
            raise PersistenceError("archive schema migration failed") from error

    def _validate_backup_contents(self, connection: sqlite3.Connection) -> None:
        """Validate logical rows that SQLite integrity checks do not understand."""

        inconsistent_relation = connection.execute(
            "SELECT 1 FROM extractions e "
            "JOIN fetches f ON f.id = e.fetch_id "
            "JOIN articles a ON a.id = e.article_id "
            "WHERE f.article_id IS NOT e.article_id "
            "OR f.provider != a.provider "
            "OR f.provider_article_id IS NOT a.provider_article_id "
            "LIMIT 1"
        ).fetchone()
        if inconsistent_relation is not None:
            raise PersistenceError("archive revision relationships are inconsistent")
        missing_revision_assessment = connection.execute(
            "SELECT 1 FROM extractions e "
            "LEFT JOIN extraction_assessments ea ON ea.extraction_id = e.id "
            "WHERE ea.extraction_id IS NULL LIMIT 1"
        ).fetchone()
        if missing_revision_assessment is not None:
            raise PersistenceError("archive revision assessment is missing")

        article_rows = connection.execute(
            _CURRENT_ARTICLE_SQL + " ORDER BY a.id"
        ).fetchall()
        wrong_current_revision = connection.execute(
            "SELECT 1 FROM articles a "
            "JOIN extractions e ON e.id = a.current_extraction_id "
            "WHERE e.article_id != a.id LIMIT 1"
        ).fetchone()
        if wrong_current_revision is not None:
            raise PersistenceError("archive current revision is inconsistent")
        article_count = connection.execute("SELECT count(*) FROM articles").fetchone()[
            0
        ]
        if article_count != len(article_rows):
            raise PersistenceError("archive contains an article without a revision")
        articles = tuple(_article_from_row(row) for row in article_rows)
        current_extractions = dict(
            connection.execute("SELECT id, current_extraction_id FROM articles")
        )
        expected_fts = tuple(
            (
                current_extractions[article.id],
                article.id,
                article.headline,
                article.body_markdown,
            )
            for article in articles
        )
        # v4 keys every row by the current extraction id; a row keyed by
        # anything else would survive the next save's rowid delete.
        actual_fts = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT rowid, article_id, headline, body_markdown "
                "FROM article_fts ORDER BY article_id"
            )
        )
        if actual_fts != expected_fts:
            raise PersistenceError("archive full-text index is inconsistent")

        for row in connection.execute(
            "SELECT requested_url, final_url, http_status, content_type, "
            "retry_after, retrieved_at, session_cookie_present, "
            "serving_transport, raw_sha256, "
            "evidence_sha256, raw_html_gzip, assessment_json, provider "
            "FROM fetches"
        ):
            raw_html = gzip.decompress(row["raw_html_gzip"])
            if hashlib.sha256(raw_html).hexdigest() != row["raw_sha256"]:
                raise PersistenceError("archive raw fetch hash is inconsistent")
            fetch = RawFetch(
                requested_url=row["requested_url"],
                final_url=row["final_url"],
                http_status=row["http_status"],
                content_type=row["content_type"],
                retry_after=row["retry_after"],
                retrieved_at=row["retrieved_at"],
                session_cookie_present=bool(row["session_cookie_present"]),
                serving_transport=row["serving_transport"],
                raw_html=raw_html,
            )
            _validate_fetch_evidence(row, fetch)
            ArticleAssessment.model_validate_json(row["assessment_json"])

        for row in connection.execute(
            "SELECT body_markdown, metadata_json, word_count FROM extractions"
        ):
            ExtractedArticle(
                body_markdown=row["body_markdown"],
                metadata=json.loads(row["metadata_json"]),
                word_count=row["word_count"],
            )
        for row in connection.execute(
            "SELECT assessment_json FROM extraction_assessments"
        ):
            ArticleAssessment.model_validate_json(row["assessment_json"])

    def _validate_article(
        self,
        provider_key: str,
        article: Article,
        fetch: RawFetch,
        assessment: ArticleAssessment,
        extraction: ExtractedArticle,
    ) -> None:
        raw_sha256 = hashlib.sha256(fetch.raw_html).hexdigest()
        if (
            article.provider != provider_key
            or article.provider_article_id != assessment.provider_article_id
            or article.extraction.raw_sha256 != raw_sha256
            or str(article.canonical_url) != str(assessment.canonical_url)
            or str(article.url) != str(fetch.final_url)
            or article.retrieved_at != fetch.retrieved_at
            or article.body_markdown != extraction.body_markdown
            or article.word_count != extraction.word_count
        ):
            raise PersistenceError("article does not match assessed raw evidence")
        if self._registry is not None:
            provider = self._registry.get(provider_key)
            expected = build_article(
                provider,
                fetch,
                extraction,
                assessment,
                extractor_name=article.extraction.extractor_name,
                extractor_version=article.extraction.extractor_version,
            )
            if article != expected:
                raise PersistenceError("article does not match assessed raw evidence")

    def _upsert_article(self, connection: sqlite3.Connection, article: Article) -> None:
        timestamp = article.retrieved_at.isoformat()
        connection.execute(
            "INSERT INTO articles("
            "id, provider, provider_article_id, canonical_url, headline, "
            "authors_json, published, section, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(provider, provider_article_id) DO UPDATE SET "
            "canonical_url=excluded.canonical_url, headline=excluded.headline, "
            "authors_json=excluded.authors_json, published=excluded.published, "
            "section=excluded.section, updated_at=excluded.updated_at",
            (
                article.id,
                article.provider,
                article.provider_article_id,
                str(article.canonical_url),
                article.headline,
                json.dumps(article.authors, ensure_ascii=False),
                article.published.isoformat() if article.published else None,
                article.section,
                timestamp,
                timestamp,
            ),
        )

    def _existing_article_id(
        self,
        connection: sqlite3.Connection,
        provider_key: str,
        provider_article_id: str | None,
    ) -> str | None:
        if provider_article_id is None:
            return None
        row = connection.execute(
            "SELECT id FROM articles WHERE provider = ? AND provider_article_id = ?",
            (provider_key, provider_article_id),
        ).fetchone()
        return row[0] if row else None

    def _upsert_fetch(
        self,
        connection: sqlite3.Connection,
        *,
        provider_key: str,
        article_id: str | None,
        provider_article_id: str | None,
        fetch: RawFetch,
        raw_sha256: str,
        evidence_sha256: str,
        compressed: bytes,
        assessment_json: str,
        retrieved_at: str,
    ) -> int:
        connection.execute(
            "INSERT INTO fetches("
            "provider, provider_article_id, article_id, requested_url, final_url, "
            "http_status, content_type, retry_after, retrieved_at, "
            "session_cookie_present, serving_transport, raw_sha256, "
            "evidence_sha256, raw_html_gzip, "
            "assessment_json, first_seen_at, last_seen_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(provider, evidence_sha256) DO UPDATE SET "
            "last_seen_at=excluded.last_seen_at, seen_count=fetches.seen_count + 1, "
            "assessment_json=excluded.assessment_json, "
            "provider_article_id=COALESCE(fetches.provider_article_id, "
            "excluded.provider_article_id), "
            "article_id=COALESCE(fetches.article_id, excluded.article_id)",
            (
                provider_key,
                provider_article_id,
                article_id,
                str(fetch.requested_url),
                str(fetch.final_url),
                fetch.http_status,
                fetch.content_type,
                fetch.retry_after,
                retrieved_at,
                int(fetch.session_cookie_present),
                fetch.serving_transport,
                raw_sha256,
                evidence_sha256,
                compressed,
                assessment_json,
                retrieved_at,
                retrieved_at,
            ),
        )
        row = connection.execute(
            "SELECT * FROM fetches WHERE provider = ? AND evidence_sha256 = ?",
            (provider_key, evidence_sha256),
        ).fetchone()
        if row is None:  # pragma: no cover - insert/select invariant
            raise PersistenceError("saved fetch could not be found")
        expected_identity = (
            provider_article_id,
            article_id,
            str(fetch.requested_url),
            str(fetch.final_url),
            fetch.http_status,
            fetch.content_type,
            fetch.retry_after,
            int(fetch.session_cookie_present),
            raw_sha256,
        )
        stored_identity = (
            row["provider_article_id"],
            row["article_id"],
            row["requested_url"],
            row["final_url"],
            row["http_status"],
            row["content_type"],
            row["retry_after"],
            row["session_cookie_present"],
            row["raw_sha256"],
        )
        # Null relationship fields may be filled by a later policy promotion;
        # once present they are part of the immutable evidence relationship.
        relationship_matches = all(
            stored is None or expected is None or stored == expected
            for stored, expected in zip(
                stored_identity[:2], expected_identity[:2], strict=True
            )
        )
        if not relationship_matches or stored_identity[2:] != expected_identity[2:]:
            raise PersistenceError("fetch evidence identity was reused inconsistently")
        return int(row["id"])

    def _upsert_extraction(
        self,
        connection: sqlite3.Connection,
        article: Article,
        fetch_id: int,
        extraction: ExtractedArticle,
        metadata_json: str,
        assessment_json: str,
    ) -> int:
        meta = article.extraction
        connection.execute(
            "INSERT INTO extractions("
            "article_id, fetch_id, extractor_name, extractor_version, "
            "policy_version, assessment_schema_version, body_markdown, "
            "metadata_json, word_count, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(fetch_id, extractor_name, extractor_version, "
            "policy_version) DO NOTHING",
            (
                article.id,
                fetch_id,
                meta.extractor_name,
                meta.extractor_version,
                meta.policy_version,
                meta.assessment_schema_version,
                extraction.body_markdown,
                metadata_json,
                extraction.word_count,
                article.retrieved_at.isoformat(),
            ),
        )
        row = connection.execute(
            "SELECT id, article_id, assessment_schema_version, body_markdown, "
            "metadata_json, word_count FROM extractions "
            "WHERE fetch_id = ? AND extractor_name = ? "
            "AND extractor_version = ? AND policy_version = ?",
            (
                fetch_id,
                meta.extractor_name,
                meta.extractor_version,
                meta.policy_version,
            ),
        ).fetchone()
        if row is None:  # pragma: no cover - insert/select invariant
            raise PersistenceError("saved extraction could not be found")
        if (
            row["article_id"] != article.id
            or row["assessment_schema_version"] != meta.assessment_schema_version
            or row["body_markdown"] != extraction.body_markdown
            or row["metadata_json"] != metadata_json
            or row["word_count"] != extraction.word_count
        ):
            raise PersistenceError(
                "extraction identity was reused for different content"
            )
        extraction_id = int(row["id"])
        connection.execute(
            "INSERT INTO extraction_assessments(extraction_id, assessment_json) "
            "VALUES (?, ?) ON CONFLICT(extraction_id) DO NOTHING",
            (extraction_id, assessment_json),
        )
        assessment_row = connection.execute(
            "SELECT assessment_json FROM extraction_assessments "
            "WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if (
            assessment_row is None
            or assessment_row["assessment_json"] != assessment_json
        ):
            raise PersistenceError(
                "extraction identity was reused for a different assessment"
            )
        return extraction_id

    def _fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    def _enforce_modes(self) -> None:
        try:
            if self.path.parent.exists():
                os.chmod(self.path.parent, 0o700)
            for path in (
                self.path,
                Path(f"{self.path}-wal"),
                Path(f"{self.path}-shm"),
            ):
                if path.exists():
                    os.chmod(path, 0o600)
        except OSError as error:
            raise PersistenceError("archive mode enforcement failed") from error


_CURRENT_ARTICLE_SQL = """
SELECT
    a.id,
    a.provider,
    a.provider_article_id,
    a.canonical_url,
    a.headline,
    a.authors_json,
    a.published,
    a.section,
    e.word_count,
    e.body_markdown,
    e.extractor_name,
    e.extractor_version,
    e.policy_version,
    e.assessment_schema_version,
    f.final_url,
    f.retrieved_at,
    f.raw_sha256
FROM articles a
JOIN extractions e ON e.id = a.current_extraction_id
JOIN fetches f ON f.id = e.fetch_id
"""


def _current_article(connection: sqlite3.Connection, article_id: str) -> Article:
    row = connection.execute(
        _CURRENT_ARTICLE_SQL + " WHERE a.id = ?", (article_id,)
    ).fetchone()
    if row is None:
        raise PersistenceError("archived article not found")
    return _article_from_row(row)


def _article_from_row(row: sqlite3.Row) -> Article:
    try:
        return Article.model_validate(
            {
                "id": row["id"],
                "provider_article_id": row["provider_article_id"],
                "url": row["final_url"],
                "canonical_url": row["canonical_url"],
                "provider": row["provider"],
                "headline": row["headline"],
                "authors": json.loads(row["authors_json"]),
                "published": row["published"],
                "section": row["section"],
                "word_count": row["word_count"],
                "body_markdown": row["body_markdown"],
                "retrieved_at": row["retrieved_at"],
                "extraction": {
                    "extractor_name": row["extractor_name"],
                    "extractor_version": row["extractor_version"],
                    "raw_sha256": row["raw_sha256"],
                    "assessment_schema_version": row["assessment_schema_version"],
                    "policy_version": row["policy_version"],
                },
            }
        )
    except (json.JSONDecodeError, TypeError, ValueError, ValidationError) as error:
        raise PersistenceError("archived article is corrupt") from error


def _fts_query(query: str) -> str:
    terms = re.findall(r"[^\W_]+", query, flags=re.UNICODE)
    return " AND ".join(f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms)


def _schema_signature(connection: sqlite3.Connection) -> tuple[object, ...]:
    """Describe the executable schema without duplicating its DDL as metadata."""

    tables: list[object] = []
    for table in _TABLES:
        columns = tuple(
            (
                str(row[1]),
                str(row[2]).upper(),
                int(row[3]),
                None if row[4] is None else str(row[4]),
                int(row[5]),
            )
            for row in connection.execute(f"PRAGMA table_info({table})")
        )
        foreign_keys = tuple(
            sorted(
                (
                    str(row[3]),
                    str(row[2]),
                    str(row[4]),
                    str(row[5]).upper(),
                    str(row[6]).upper(),
                )
                for row in connection.execute(f"PRAGMA foreign_key_list({table})")
            )
        )
        indexes = []
        for index in connection.execute(f"PRAGMA index_list({table})"):
            index_name = str(index[1])
            indexes.append(
                (
                    int(index[2]),
                    str(index[3]),
                    int(index[4]),
                    tuple(
                        str(row[0])
                        for row in connection.execute(
                            "SELECT name FROM pragma_index_info(?) ORDER BY seqno",
                            (index_name,),
                        )
                    ),
                )
            )
        tables.append((table, columns, foreign_keys, tuple(sorted(indexes))))
    fts_row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'article_fts'"
    ).fetchone()
    fts_sql = " ".join(str(fts_row[0]).lower().split()) if fts_row else ""
    return (*tables, fts_sql)


@lru_cache(maxsize=8)
def _expected_schema_signature(version: int = SCHEMA_VERSION) -> tuple[object, ...]:
    scripts = {1: _SCHEMA_V1, 2: _SCHEMA_V2, 3: _SCHEMA_V3, SCHEMA_VERSION: _SCHEMA}
    script = scripts.get(version)
    if script is None:
        raise ValueError("unsupported archive schema signature")
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(script)
        return _schema_signature(connection)
    finally:
        connection.close()


def _fetch_evidence_sha256(
    provider: str,
    *,
    requested_url: str,
    final_url: str,
    http_status: int,
    content_type: str | None,
    retry_after: float | None,
    session_cookie_present: bool,
    raw_sha256: str,
    serving_transport: str | None = None,
) -> str:
    """Hash every immutable transport fact used to interpret stored raw bytes.

    The serving transport enters the payload only when it is known. A row
    stored before it was recorded hashes exactly as it did then, so every
    pre-v3 row still validates; a row that knows which profile served it
    carries that fact into its identity, because the same bytes fetched over
    a different transport are different evidence.
    """

    payload = {
        "provider": provider,
        "requested_url": requested_url,
        "final_url": final_url,
        "http_status": http_status,
        "content_type": content_type,
        "retry_after": retry_after,
        "session_cookie_present": session_cookie_present,
        "raw_sha256": raw_sha256,
    }
    if serving_transport is not None:
        payload["serving_transport"] = serving_transport
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_fetch_evidence(row: sqlite3.Row, fetch: RawFetch) -> None:
    expected = _fetch_evidence_sha256(
        row["provider"],
        requested_url=str(fetch.requested_url),
        final_url=str(fetch.final_url),
        http_status=fetch.http_status,
        content_type=fetch.content_type,
        retry_after=fetch.retry_after,
        session_cookie_present=fetch.session_cookie_present,
        raw_sha256=row["raw_sha256"],
        serving_transport=fetch.serving_transport,
    )
    if row["evidence_sha256"] != expected:
        raise PersistenceError("archived fetch evidence hash is inconsistent")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _discard_temporary(path: Path | None) -> None:
    if path is None:
        return
    with suppress(OSError):
        path.unlink(missing_ok=True)


def _discard_sqlite_temporary(path: Path | None) -> None:
    if path is None:
        return
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        _discard_temporary(candidate)
