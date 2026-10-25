"""Private, bounded incident evidence for operator-reviewed reproduction."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, get_args
from uuid import uuid4

from pydantic import AwareDatetime, Field, HttpUrl

from .browser_readiness import (
    BrowserSemanticSnapshot,
    ReadinessCoverageBucket,
    ReadinessTerminalState,
)
from .models import INCIDENT_ID_PATTERN as _INCIDENT_ID_PATTERN
from .models import ArticleAssessment, FrozenModel, RawFetch
from .private_state import exclusive_lock
from .provenance import BuildIdentity
from .provider_keys import PROVIDER_KEY_PATTERN
from .timing import (
    ContentAssessmentEvidence,
    SessionProbeEvidence,
    TimingOperation,
    content_assessment_evidence,
    current_timing_invocation_id,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_CAPTURE_BYTES = 4 * 1024 * 1024
_MAX_INCIDENT_METADATA_BYTES = 64 * 1024
_MAX_INCIDENT_CONTEXT_BYTES = 16 * 1024
_MAX_INCIDENTS_PER_PROVIDER = 50
_MAX_CAPTURE_STORAGE_BYTES_PER_PROVIDER = 64 * 1024 * 1024


class IncidentPersistenceError(RuntimeError):
    """Private incident evidence could not be committed safely."""


class IncidentSchemaUnsupportedError(IncidentPersistenceError):
    """Incident metadata is well formed but written by an unknown schema."""


@contextmanager
def incident_retention_lock(root: Path, provider: str) -> Iterator[None]:
    from .provider_keys import is_provider_key

    if not is_provider_key(provider):
        raise IncidentPersistenceError("incident provider is invalid")
    with exclusive_lock(root / f".{provider}.retention.lock", timeout_seconds=2):
        yield


@contextmanager
def protect_incident_reference(
    root: Path | None, provider: str, incident_id: str | None
) -> Iterator[None]:
    """Publish a reference only while pruning is excluded and capture exists."""
    if root is None or incident_id is None:
        yield
        return
    if not _valid_incident_id(incident_id):
        raise IncidentPersistenceError("incident identifier is invalid")
    with incident_retention_lock(root, provider):
        capsule = IncidentCapsule.model_validate_json(
            _read_bounded(
                root / incident_id / "incident.json",
                maximum=_MAX_INCIDENT_METADATA_BYTES,
                message="referenced incident unavailable",
            )
        )
        if capsule.incident_id != incident_id or capsule.provider != provider:
            raise IncidentPersistenceError("incident reference is inconsistent")
        yield


class IncidentKind(StrEnum):
    RETRIEVAL_ASSESSMENT = "retrieval_assessment"
    SEARCH_RESPONSE = "search_response"


class SearchFailureKind(StrEnum):
    CONTRACT = "contract"
    RESPONSE_REJECTED = "response_rejected"


class IncidentContext(FrozenModel):
    """Private request facts required to reconstruct an inert RawFetch."""

    schema_version: Literal[1] = 1
    incident_id: str = Field(pattern=_INCIDENT_ID_PATTERN)
    requested_url: HttpUrl
    final_url: HttpUrl
    content_type: str | None = Field(default=None, max_length=256)


class IncidentReadinessEvidence(FrozenModel):
    """Bounded terminal readiness facts; article text stays in private capture."""

    state: ReadinessTerminalState
    word_count: int = Field(ge=0, le=1_000_000)
    coverage_bucket: ReadinessCoverageBucket
    content_change_count: int = Field(ge=0, le=65_535)
    last_content_change_ms: int = Field(ge=0, le=120_000)


class IncidentCapsule(FrozenModel):
    """Closed metadata; raw HTML remains a separate private artifact."""

    schema_version: Literal[1, 2] = 2
    incident_id: str = Field(pattern=_INCIDENT_ID_PATTERN)
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    operation: TimingOperation
    kind: IncidentKind
    occurred_at: AwareDatetime
    build_identity: BuildIdentity
    requested_url_sha256: str = Field(pattern=_SHA256_PATTERN)
    final_url_sha256: str = Field(pattern=_SHA256_PATTERN)
    raw_sha256: str = Field(pattern=_SHA256_PATTERN)
    capture_bytes: int = Field(ge=0)
    capture_available: bool
    context_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    http_status: int = Field(ge=100, le=599)
    session_cookie_present: bool
    assessment: ContentAssessmentEvidence | None = None
    search_failure: SearchFailureKind | None = None
    readiness: IncidentReadinessEvidence | None = None
    diagnostic_id: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$"
    )
    screenshot_status: Literal[
        "captured",
        "capture_failed",
        "too_large",
        "not_requested",
        "not_browser",
        "legacy_unknown",
    ] = "legacy_unknown"
    screenshot_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    trace_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    diagnostic_fingerprint: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    def model_post_init(self, __context: object) -> None:
        retrieval = self.kind is IncidentKind.RETRIEVAL_ASSESSMENT
        if retrieval != (self.assessment is not None):
            raise ValueError("incident kind and assessment are inconsistent")
        if retrieval and self.operation not in {
            TimingOperation.GET,
            TimingOperation.SAVE,
        }:
            raise ValueError("incident kind and operation are inconsistent")
        if not retrieval and self.operation is not TimingOperation.SEARCH:
            raise ValueError("incident kind and operation are inconsistent")
        if retrieval and self.search_failure is not None:
            raise ValueError("retrieval incident cannot have a search failure")
        if not retrieval and self.readiness is not None:
            raise ValueError("search incident cannot have readiness evidence")

    def validate_identity(self) -> None:
        """Reject metadata whose deterministic identifier was altered."""

        _validate_capsule_identity(self)


# Derived from the capsule itself so the retention rule cannot drift from the
# schema it protects: any version outside this set belongs to another build.
_SUPPORTED_SCHEMA_VERSIONS = frozenset(
    get_args(IncidentCapsule.model_fields["schema_version"].annotation)
)


class IncidentEvidenceHealth(FrozenModel):
    incident_id: str | None = Field(default=None, pattern=_INCIDENT_ID_PATTERN)
    status: Literal["complete", "partial", "missing", "not_recorded"] = "not_recorded"
    screenshot_status: str | None = Field(default=None, pattern=r"^[a-z_]{1,32}$")
    trace_available: bool = False
    diagnostic_id: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$"
    )


class IncidentStore:
    """Atomically retain the first private capture for one failure signature."""

    def __init__(
        self,
        root: Path,
        *,
        build_identity: BuildIdentity,
        utc_now=None,
        evidence_root: Path | None = None,
        protected_incidents: Callable[[str], frozenset[str]] | None = None,
    ) -> None:
        self.root = Path(root)
        self.build_identity = build_identity
        self._utc_now = utc_now or (lambda: datetime.now(UTC))
        self._last_scan_corrupt_entries = 0
        self.evidence_root = evidence_root
        self._protected_incidents = protected_incidents or (lambda _: frozenset())

    def retain_evidence(self, capsule: IncidentCapsule) -> None:
        """Copy a verified capsule into a live invocation before temp cleanup."""

        if self.evidence_root is None:
            return
        capsule = self.load(capsule.incident_id)
        self.load_context(capsule)
        capture = self.capture_path(capsule)
        context = _read_bounded(
            self.root / capsule.incident_id / "context.json",
            maximum=_MAX_INCIDENT_CONTEXT_BYTES,
            message="incident context unavailable",
        )
        payload = (
            _read_bounded(
                capture,
                maximum=_MAX_CAPTURE_BYTES,
                message="incident capture unavailable",
            )
            if capture is not None
            else None
        )
        if hashlib.sha256(context).hexdigest() != capsule.context_sha256 or (
            payload is not None
            and hashlib.sha256(payload).hexdigest() != capsule.raw_sha256
        ):
            raise IncidentPersistenceError("incident evidence changed during retention")
        destination = IncidentStore(
            self.evidence_root, build_identity=self.build_identity
        )
        destination._commit(
            capsule,
            payload,
            context,
            screenshot=self.diagnostic_bytes(capsule, "screenshot"),
            trace=self.diagnostic_bytes(capsule, "trace"),
        )

    @property
    def last_scan_corrupt_entries(self) -> int:
        """Return corrupt entries skipped by the most recent index scan."""

        return self._last_scan_corrupt_entries

    def record_retrieval(
        self,
        *,
        provider: str,
        operation: TimingOperation,
        fetch: RawFetch,
        assessment: ContentAssessmentEvidence,
        readiness: IncidentReadinessEvidence | None = None,
    ) -> IncidentCapsule:
        if operation not in {TimingOperation.GET, TimingOperation.SAVE}:
            raise ValueError("retrieval incidents require get or save")
        raw_sha256 = hashlib.sha256(fetch.raw_html).hexdigest()
        requested_url_sha256 = _text_sha256(str(fetch.requested_url))
        final_url_sha256 = _text_sha256(str(fetch.final_url))
        diagnostic_fingerprint = _diagnostic_fingerprint(fetch)
        incident_id = _incident_id(
            diagnostic_fingerprint=diagnostic_fingerprint,
            provider=provider,
            operation=operation,
            build_identity=self.build_identity,
            requested_url_sha256=requested_url_sha256,
            raw_sha256=raw_sha256,
            assessment=assessment,
        )
        context = _context_bytes(
            incident_id=incident_id,
            fetch=fetch,
        )
        capture_available = len(fetch.raw_html) <= _MAX_CAPTURE_BYTES
        capsule = IncidentCapsule(
            incident_id=incident_id,
            provider=provider,
            operation=operation,
            kind=IncidentKind.RETRIEVAL_ASSESSMENT,
            occurred_at=self._utc_now(),
            build_identity=self.build_identity,
            requested_url_sha256=requested_url_sha256,
            final_url_sha256=final_url_sha256,
            raw_sha256=raw_sha256,
            capture_bytes=len(fetch.raw_html),
            capture_available=capture_available,
            context_sha256=hashlib.sha256(context).hexdigest(),
            http_status=fetch.http_status,
            session_cookie_present=fetch.session_cookie_present,
            diagnostic_id=current_timing_invocation_id(),
            diagnostic_fingerprint=diagnostic_fingerprint,
            screenshot_status=(
                fetch.diagnostics.screenshot_status
                if fetch.diagnostics
                else "not_browser"
            ),
            screenshot_sha256=(
                hashlib.sha256(fetch.diagnostics.screenshot).hexdigest()
                if fetch.diagnostics and fetch.diagnostics.screenshot
                else None
            ),
            trace_sha256=(
                hashlib.sha256(fetch.diagnostics.trace).hexdigest()
                if fetch.diagnostics and fetch.diagnostics.trace
                else None
            ),
            assessment=assessment,
            readiness=readiness,
        )
        return self._commit(
            capsule,
            fetch.raw_html if capture_available else None,
            context,
            screenshot=fetch.diagnostics.screenshot if fetch.diagnostics else None,
            trace=fetch.diagnostics.trace if fetch.diagnostics else None,
        )

    def record_assessed_retrieval(
        self,
        *,
        provider: str,
        operation: TimingOperation,
        fetch: RawFetch,
        assessment: ArticleAssessment,
        readiness: BrowserSemanticSnapshot | None = None,
        session_probe: SessionProbeEvidence | None = None,
    ) -> IncidentCapsule:
        """Retain the closed assessment and any already-observed session probe.

        Probe metadata does not change incident identity: identical captures
        in the same build keep the first capsule, including its probe result.
        """

        return self.record_retrieval(
            provider=provider,
            operation=operation,
            fetch=fetch,
            assessment=ContentAssessmentEvidence.model_validate(
                {
                    **content_assessment_evidence(assessment).model_dump(),
                    "session_probe": session_probe,
                }
            ),
            readiness=(
                incident_readiness_evidence(readiness)
                if readiness is not None
                else None
            ),
        )

    def record_search(
        self,
        *,
        provider: str,
        fetch: RawFetch,
        failure: SearchFailureKind,
    ) -> IncidentCapsule:
        raw_sha256 = hashlib.sha256(fetch.raw_html).hexdigest()
        requested_url_sha256 = _text_sha256(str(fetch.requested_url))
        final_url_sha256 = _text_sha256(str(fetch.final_url))
        diagnostic_fingerprint = _diagnostic_fingerprint(fetch)
        incident_id = _incident_id(
            diagnostic_fingerprint=diagnostic_fingerprint,
            provider=provider,
            operation=TimingOperation.SEARCH,
            build_identity=self.build_identity,
            requested_url_sha256=requested_url_sha256,
            raw_sha256=raw_sha256,
            assessment=None,
            http_status=fetch.http_status,
            search_failure=failure,
        )
        context = _context_bytes(
            incident_id=incident_id,
            fetch=fetch,
        )
        capture_available = len(fetch.raw_html) <= _MAX_CAPTURE_BYTES
        capsule = IncidentCapsule(
            incident_id=incident_id,
            provider=provider,
            operation=TimingOperation.SEARCH,
            kind=IncidentKind.SEARCH_RESPONSE,
            occurred_at=self._utc_now(),
            build_identity=self.build_identity,
            requested_url_sha256=requested_url_sha256,
            final_url_sha256=final_url_sha256,
            raw_sha256=raw_sha256,
            capture_bytes=len(fetch.raw_html),
            capture_available=capture_available,
            context_sha256=hashlib.sha256(context).hexdigest(),
            http_status=fetch.http_status,
            session_cookie_present=fetch.session_cookie_present,
            diagnostic_id=current_timing_invocation_id(),
            diagnostic_fingerprint=diagnostic_fingerprint,
            screenshot_status=(
                fetch.diagnostics.screenshot_status
                if fetch.diagnostics
                else "not_browser"
            ),
            screenshot_sha256=(
                hashlib.sha256(fetch.diagnostics.screenshot).hexdigest()
                if fetch.diagnostics and fetch.diagnostics.screenshot
                else None
            ),
            trace_sha256=(
                hashlib.sha256(fetch.diagnostics.trace).hexdigest()
                if fetch.diagnostics and fetch.diagnostics.trace
                else None
            ),
            search_failure=failure,
        )
        return self._commit(
            capsule,
            fetch.raw_html if capture_available else None,
            context,
            screenshot=fetch.diagnostics.screenshot if fetch.diagnostics else None,
            trace=fetch.diagnostics.trace if fetch.diagnostics else None,
        )

    def load(self, incident_id: str) -> IncidentCapsule:
        self._require_existing_root()
        directory = self._incident_directory(incident_id)
        self._require_incident_directory(directory)
        try:
            path = directory / "incident.json"
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise IncidentPersistenceError("incident metadata is unavailable")
            payload = _read_bounded(
                path,
                maximum=_MAX_INCIDENT_METADATA_BYTES,
                message="incident metadata is invalid",
            )
            try:
                capsule = IncidentCapsule.model_validate_json(payload)
            except ValueError as error:
                _reject_unsupported_schema(payload)
                raise IncidentPersistenceError(
                    "incident metadata is invalid"
                ) from error
            capsule.validate_identity()
            if capsule.incident_id != incident_id:
                raise IncidentPersistenceError("incident identifier is inconsistent")
            return capsule
        except (OSError, ValueError) as error:
            raise IncidentPersistenceError("incident metadata is invalid") from error

    def capture_path(self, capsule: IncidentCapsule) -> Path | None:
        if not capsule.capture_available:
            return None
        self._require_existing_root()
        directory = self._incident_directory(capsule.incident_id)
        self._require_incident_directory(directory)
        path = directory / "capture.html"
        try:
            metadata = path.lstat()
        except OSError as error:
            raise IncidentPersistenceError("incident capture is unavailable") from error
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise IncidentPersistenceError("incident capture is invalid")
        if (
            metadata.st_size != capsule.capture_bytes
            or metadata.st_size > _MAX_CAPTURE_BYTES
        ):
            raise IncidentPersistenceError("incident capture size mismatch")
        try:
            payload = _read_bounded(
                path,
                maximum=_MAX_CAPTURE_BYTES,
                message="incident capture is unavailable",
            )
        except OSError as error:
            raise IncidentPersistenceError("incident capture is unavailable") from error
        if (
            len(payload) != capsule.capture_bytes
            or hashlib.sha256(payload).hexdigest() != capsule.raw_sha256
        ):
            raise IncidentPersistenceError("incident capture digest mismatch")
        return path

    def load_context(self, capsule: IncidentCapsule) -> IncidentContext:
        if capsule.context_sha256 is None:
            raise IncidentPersistenceError("incident request context is unavailable")
        self._require_existing_root()
        directory = self._incident_directory(capsule.incident_id)
        self._require_incident_directory(directory)
        path = directory / "context.json"
        try:
            metadata = path.lstat()
        except OSError as error:
            raise IncidentPersistenceError(
                "incident request context is unavailable"
            ) from error
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise IncidentPersistenceError("incident request context is invalid")
        try:
            payload = _read_bounded(
                path,
                maximum=_MAX_INCIDENT_CONTEXT_BYTES,
                message="incident request context is invalid",
            )
            if hashlib.sha256(payload).hexdigest() != capsule.context_sha256:
                raise IncidentPersistenceError(
                    "incident request context digest mismatch"
                )
            context = IncidentContext.model_validate_json(payload)
        except (OSError, ValueError) as error:
            raise IncidentPersistenceError(
                "incident request context is invalid"
            ) from error
        if context.incident_id != capsule.incident_id:
            raise IncidentPersistenceError(
                "incident request context identifier is inconsistent"
            )
        return context

    def iter_capsules(self) -> Iterator[IncidentCapsule]:
        self._last_scan_corrupt_entries = 0
        if not self.root.exists():
            return
        self._require_existing_root()
        try:
            directories = tuple(sorted(self.root.iterdir(), key=lambda path: path.name))
        except OSError as error:
            raise IncidentPersistenceError("incident index is unavailable") from error
        for directory in directories:
            if not _valid_incident_id(directory.name):
                continue
            try:
                yield self.load(directory.name)
            except IncidentPersistenceError:
                self._last_scan_corrupt_entries += 1

    def _commit(
        self,
        capsule: IncidentCapsule,
        capture: bytes | None,
        context: bytes,
        *,
        screenshot: bytes | None = None,
        trace: bytes | None = None,
    ) -> IncidentCapsule:
        final = self._incident_directory(capsule.incident_id)
        temporary = self.root / f".tmp-{uuid4().hex}"
        try:
            root_existed = self.root.exists()
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.root.is_symlink() or not self.root.is_dir():
                raise IncidentPersistenceError("incident index is invalid")
            os.chmod(self.root, 0o700)
            if not root_existed:
                _fsync_directory(self.root.parent)
            if final.exists():
                existing = self.load(capsule.incident_id)
                _validate_same_incident(existing, capsule)
                self._prune_provider(
                    capsule.provider,
                    preserve=capsule.incident_id,
                )
                return existing
            temporary.mkdir(mode=0o700)
            _write_private(
                temporary / "incident.json",
                (
                    json.dumps(
                        capsule.model_dump(mode="json"),
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8"),
            )
            if capture is not None:
                _write_private(temporary / "capture.html", capture)
            _write_private(temporary / "context.json", context)
            if screenshot is not None:
                if len(screenshot) > _MAX_CAPTURE_BYTES:
                    raise IncidentPersistenceError("incident screenshot exceeds limit")
                _write_private(temporary / "terminal.png", screenshot)
            if trace is not None:
                if len(trace) > 1024 * 1024:
                    raise IncidentPersistenceError("incident trace exceeds limit")
                _write_private(temporary / "browser.jsonl", trace)
            _fsync_directory(temporary)
            try:
                os.rename(temporary, final)
            except OSError:
                if not final.exists():
                    raise
                existing = self.load(capsule.incident_id)
                _validate_same_incident(existing, capsule)
                self._prune_provider(
                    capsule.provider,
                    preserve=capsule.incident_id,
                )
                return existing
            _fsync_directory(self.root)
            self._prune_provider(capsule.provider, preserve=capsule.incident_id)
            return capsule
        except IncidentPersistenceError:
            raise
        except OSError as error:
            raise IncidentPersistenceError("incident persistence failed") from error
        finally:
            if temporary.exists() and not temporary.is_symlink():
                shutil.rmtree(temporary, ignore_errors=True)

    def evidence_health(self, incident_id: str) -> IncidentEvidenceHealth:
        try:
            capsule = self.load(incident_id)
            self.load_context(capsule)
            capture = self.capture_path(capsule)
            screenshot = self.diagnostic_bytes(capsule, "screenshot")
            trace = self.diagnostic_bytes(capsule, "trace")
            complete = capture is not None and (
                capsule.screenshot_status == "not_browser"
                or (
                    capsule.screenshot_status == "captured"
                    and screenshot is not None
                    and trace is not None
                )
            )
            return IncidentEvidenceHealth(
                incident_id=incident_id,
                status="complete" if complete else "partial",
                screenshot_status=capsule.screenshot_status,
                trace_available=trace is not None,
                diagnostic_id=capsule.diagnostic_id,
            )
        except (IncidentPersistenceError, OSError, ValueError):
            return IncidentEvidenceHealth(incident_id=incident_id, status="missing")

    def diagnostic_bytes(
        self, capsule: IncidentCapsule, kind: Literal["screenshot", "trace"]
    ) -> bytes | None:
        digest = (
            capsule.screenshot_sha256 if kind == "screenshot" else capsule.trace_sha256
        )
        if digest is None:
            return None
        name = "terminal.png" if kind == "screenshot" else "browser.jsonl"
        payload = _read_bounded(
            self._incident_directory(capsule.incident_id) / name,
            maximum=_MAX_CAPTURE_BYTES if kind == "screenshot" else 1024 * 1024,
            message="incident diagnostic unavailable",
        )
        if hashlib.sha256(payload).hexdigest() != digest:
            raise IncidentPersistenceError("incident diagnostic digest mismatch")
        return payload

    def _incident_directory(self, incident_id: str) -> Path:
        if not _valid_incident_id(incident_id):
            raise IncidentPersistenceError("incident identifier is invalid")
        return self.root / incident_id

    def _prune_provider(self, provider: str, *, preserve: str) -> None:
        """Serialize pruning with publication of unresolved evidence references."""
        try:
            with incident_retention_lock(self.root, provider):
                self._prune_provider_locked(provider, preserve=preserve)
        except (OSError, IncidentPersistenceError):
            return

    def _prune_provider_locked(self, provider: str, *, preserve: str) -> None:
        """Best-effort bounded retention after the current incident is committed."""

        # State records are atomic; an unreadable protection reference must
        # never authorize deletion of the evidence needed to repair it.
        try:
            protected = self._protected_incidents(provider)
        except Exception:
            return
        entries: list[tuple[int, int, Path]] = []
        removed = False
        try:
            directories = tuple(self.root.iterdir())
        except OSError:
            return
        for directory in directories:
            if (
                not _valid_incident_id(directory.name)
                or directory.is_symlink()
                or not directory.is_dir()
            ):
                continue
            try:
                capsule = self.load(directory.name)
                if capsule.provider != provider:
                    continue
                entries.append(
                    (
                        directory.stat().st_mtime_ns,
                        (capsule.capture_bytes if capsule.capture_available else 0)
                        + sum(
                            (directory / name).stat().st_size
                            for name in ("terminal.png", "browser.jsonl")
                            if (directory / name).is_file()
                        ),
                        directory,
                    )
                )
            except IncidentSchemaUnsupportedError:
                continue
            except IncidentPersistenceError as error:
                if isinstance(error.__cause__, OSError):
                    continue
                if directory.name in protected:
                    continue
                try:
                    shutil.rmtree(directory)
                    removed = True
                except OSError:
                    pass
                continue
            except OSError:
                continue
        entries.sort(key=lambda item: (item[0], item[2].name), reverse=True)
        retained_count = 0
        retained_bytes = 0
        for _, capture_bytes, directory in entries:
            keep = (
                directory.name == preserve
                or directory.name in protected
                or (
                    retained_count < _MAX_INCIDENTS_PER_PROVIDER
                    and retained_bytes + capture_bytes
                    <= _MAX_CAPTURE_STORAGE_BYTES_PER_PROVIDER
                )
            )
            if keep:
                retained_count += 1
                retained_bytes += capture_bytes
                continue
            try:
                shutil.rmtree(directory)
                removed = True
            except OSError:
                continue
        if removed:
            try:
                _fsync_directory(self.root)
            except OSError:
                return

    def _require_existing_root(self) -> None:
        if self.root.is_symlink() or not self.root.is_dir():
            raise IncidentPersistenceError("incident index is invalid")

    @staticmethod
    def _require_incident_directory(directory: Path) -> None:
        if directory.is_symlink() or not directory.is_dir():
            raise IncidentPersistenceError("incident directory is invalid")


def _diagnostic_fingerprint(fetch: RawFetch) -> str | None:
    diagnostics = fetch.diagnostics
    if diagnostics is None:
        return None
    # Keep the exact browser response and attempt together. An earlier primary
    # HTTP capsule (or a different browser attempt) must not absorb this view.
    digest = hashlib.sha256()
    for part in (
        diagnostics.screenshot_status.encode(),
        fetch.raw_html,
        diagnostics.screenshot or b"",
        diagnostics.trace or b"",
    ):
        digest.update(hashlib.sha256(part).digest())
    return digest.hexdigest()


def _incident_id(
    *,
    provider: str,
    operation: TimingOperation,
    build_identity: BuildIdentity,
    requested_url_sha256: str,
    raw_sha256: str,
    assessment: ContentAssessmentEvidence | None,
    http_status: int | None = None,
    search_failure: SearchFailureKind | None = None,
    diagnostic_fingerprint: str | None = None,
) -> str:
    signature = _incident_signature(
        provider=provider,
        operation=operation,
        build_identity=build_identity,
        requested_url_sha256=requested_url_sha256,
        raw_sha256=raw_sha256,
        assessment=assessment,
        http_status=http_status,
        search_failure=search_failure,
        diagnostic_fingerprint=diagnostic_fingerprint,
    )
    return f"incident-{hashlib.sha256(signature.encode()).hexdigest()[:24]}"


def _incident_signature(
    *,
    provider: str,
    operation: TimingOperation,
    build_identity: BuildIdentity,
    requested_url_sha256: str,
    raw_sha256: str,
    assessment: ContentAssessmentEvidence | None,
    http_status: int | None,
    search_failure: SearchFailureKind | None,
    diagnostic_fingerprint: str | None = None,
) -> str:
    closed_outcome = (
        (
            assessment.access_state.value,
            assessment.reason.value,
            "identity" if assessment.identity_match else "identity_mismatch",
        )
        if assessment is not None
        else (
            "search_response",
            str(http_status),
            (search_failure.value if search_failure is not None else "not_applicable"),
        )
    )
    return "\0".join(
        (
            provider,
            operation.value,
            _build_signature(build_identity, raw_sha256=raw_sha256),
            requested_url_sha256,
            *closed_outcome,
            *((diagnostic_fingerprint,) if diagnostic_fingerprint is not None else ()),
        )
    )


def _valid_incident_id(value: str) -> bool:
    return (
        len(value) == len("incident-") + 24
        and value.startswith("incident-")
        and all(character in "0123456789abcdef" for character in value[9:])
    )


def incident_readiness_evidence(
    snapshot: BrowserSemanticSnapshot,
) -> IncidentReadinessEvidence:
    """Reduce a private terminal snapshot to bounded incident metadata."""

    observation = snapshot.observation
    return IncidentReadinessEvidence(
        state=snapshot.terminal_state,
        word_count=observation.word_count if observation is not None else 0,
        coverage_bucket=(
            observation.coverage_bucket
            if observation is not None
            else ReadinessCoverageBucket.UNAVAILABLE
        ),
        content_change_count=snapshot.content_change_count,
        last_content_change_ms=snapshot.last_content_change_ms,
    )


def _validate_same_incident(
    existing: IncidentCapsule,
    candidate: IncidentCapsule,
) -> None:
    existing_signature = _incident_signature(
        provider=existing.provider,
        operation=existing.operation,
        build_identity=existing.build_identity,
        requested_url_sha256=existing.requested_url_sha256,
        raw_sha256=existing.raw_sha256,
        assessment=existing.assessment,
        http_status=existing.http_status,
        search_failure=existing.search_failure,
        diagnostic_fingerprint=existing.diagnostic_fingerprint,
    )
    candidate_signature = _incident_signature(
        provider=candidate.provider,
        operation=candidate.operation,
        build_identity=candidate.build_identity,
        requested_url_sha256=candidate.requested_url_sha256,
        raw_sha256=candidate.raw_sha256,
        assessment=candidate.assessment,
        http_status=candidate.http_status,
        search_failure=candidate.search_failure,
        diagnostic_fingerprint=candidate.diagnostic_fingerprint,
    )
    if existing.incident_id != candidate.incident_id or existing_signature != (
        candidate_signature
    ):
        raise IncidentPersistenceError("incident identifier collision")


def _validate_capsule_identity(capsule: IncidentCapsule) -> None:
    expected = _incident_id(
        provider=capsule.provider,
        operation=capsule.operation,
        build_identity=capsule.build_identity,
        requested_url_sha256=capsule.requested_url_sha256,
        raw_sha256=capsule.raw_sha256,
        assessment=capsule.assessment,
        http_status=capsule.http_status,
        search_failure=capsule.search_failure,
        diagnostic_fingerprint=capsule.diagnostic_fingerprint,
    )
    if capsule.incident_id != expected:
        raise IncidentPersistenceError("incident identifier is inconsistent")


def _build_signature(build_identity: BuildIdentity, *, raw_sha256: str) -> str:
    if build_identity.source_fingerprint is not None:
        return build_identity.source_fingerprint
    if build_identity.revision is not None:
        return build_identity.revision
    return f"{build_identity.source.value}:{raw_sha256}"


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _context_bytes(*, incident_id: str, fetch: RawFetch) -> bytes:
    context = IncidentContext(
        incident_id=incident_id,
        requested_url=fetch.requested_url,
        final_url=fetch.final_url,
        content_type=fetch.content_type,
    )
    return (
        json.dumps(
            context.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _write_private(path: Path, payload: bytes) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("incident artifact is not regular")
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("incident artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _reject_unsupported_schema(payload: bytes) -> None:
    """Separate schema skew from corruption before evidence can be discarded.

    A capsule this build cannot validate is normally tampered or truncated and
    may be pruned. One that declares a schema version this build does not know
    was written by another build and must survive instead. This depends on
    ``IncidentCapsule.schema_version`` being bumped whenever the capsule shape
    changes; adding a field without bumping it makes prior builds treat the new
    metadata as corrupt.
    """

    try:
        document = json.loads(payload)
    except ValueError:
        return
    if not isinstance(document, dict):
        return
    version = document.get("schema_version")
    if isinstance(version, int) and version not in _SUPPORTED_SCHEMA_VERSIONS:
        raise IncidentSchemaUnsupportedError("incident metadata schema is unsupported")


def _read_bounded(path: Path, *, maximum: int, message: str) -> bytes:
    try:
        if path.stat().st_size > maximum:
            raise IncidentPersistenceError(message)
        with path.open("rb") as stream:
            payload = stream.read(maximum + 1)
    except OSError as error:
        raise IncidentPersistenceError(message) from error
    if len(payload) > maximum:
        raise IncidentPersistenceError(message)
    return payload
