"""A rejected HTTP response must be diagnosable from its live invocation."""

import hashlib
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from newsclip.archive import ArchiveStore
from newsclip.challenge_transport import ChallengeAwareHttpClient
from newsclip.errors import ContentNotFullError, ProviderDefenseError
from newsclip.extraction import TrafilaturaExtractor
from newsclip.incidents import IncidentStore
from newsclip.live_reporting import (
    EvidenceGap,
    LiveExitClass,
    LiveReportOutcome,
    LiveReportStore,
    _operation_evidence,
)
from newsclip.models import RawFetch, SearchFilters
from newsclip.provenance import build_source_identity, legacy_build_identity
from newsclip.providers.ap import ApProvider
from newsclip.providers.registry import ProviderRegistry
from newsclip.service import NewsclipService
from newsclip.timing import (
    TimingOperation,
    TimingRecorder,
    TimingRunMode,
    TimingTransport,
    iter_timing_runs,
)


@pytest.mark.parametrize(
    "method", ["_search_provider", "_search_provider_page", "_record_defense_error"]
)
@pytest.mark.parametrize("terminal", ["available", "missing", "write_failed"])
def test_search_fallback_preserves_response_evidence(
    tmp_path, monkeypatch, method, terminal
):
    identity = legacy_build_identity(revision=None, dirty=None)
    trace_root = tmp_path / "invocation"
    store = IncidentStore(
        tmp_path / "incidents",
        build_identity=identity,
        evidence_root=trace_root / "wsj" / "incidents",
    )
    primary = RawFetch(
        requested_url="https://www.wsj.com/search?query=fixture",
        final_url="https://www.wsj.com/search?query=fixture",
        retrieved_at=datetime.now(UTC),
        http_status=401,
        content_type="text/html",
        raw_html=b"<html>Initial device check</html>",
        session_cookie_present=False,
    )
    terminal_fetch = primary.model_copy(
        update={"raw_html": b"<html>Terminal restriction</html>"}
    )
    error = ProviderDefenseError(
        "fixture restriction",
        provider="wsj",
        fetch=None if terminal == "missing" else terminal_fetch,
    )

    def blocked(*args, **kwargs):
        raise error

    def search(http, session, query, filters, **kwargs):
        return http.get(str(primary.requested_url), session=session)

    provider = SimpleNamespace(key="wsj", search=search, search_page=search)
    service = NewsclipService.__new__(NewsclipService)
    service._incidents = store
    service._defense = None
    client = ChallengeAwareHttpClient(
        "wsj",
        SimpleNamespace(get=lambda *args, **kwargs: primary),
        is_challenge=lambda fetch: True,
        browser_fallback=SimpleNamespace(get=blocked),
        on_challenge_observed=lambda fetch: service._record_http_challenge(
            provider, fetch
        ),
    )
    monkeypatch.setattr(service, "_search_session_for", lambda provider: None)
    monkeypatch.setattr(service, "_provider_search_http", lambda provider: client)
    if terminal == "write_failed":
        retain = store.retain_evidence

        def fail_terminal(capsule):
            if capsule.raw_sha256 != hashlib.sha256(primary.raw_html).hexdigest():
                raise OSError("fixture terminal retention failure")
            return retain(capsule)

        monkeypatch.setattr(store, "retain_evidence", fail_terminal)
    timing_root = tmp_path / "timings"
    recorder = TimingRecorder(timing_root, build_identity=identity)
    with (
        pytest.raises(ProviderDefenseError) as caught,
        recorder.operation(
            TimingOperation.SEARCH, provider="wsj", transport=TimingTransport.HTTP
        ),
    ):
        kwargs = (
            {"next_url": None, "metadata_fetch_budget": None}
            if method == "_search_provider_page"
            else {}
        )
        if method == "_record_defense_error":
            try:
                client.get(str(primary.requested_url))
            except ProviderDefenseError as failure:
                service._record_defense_error(provider, failure, TimingOperation.SEARCH)
                raise
        else:
            getattr(service, method)(provider, "fixture", SearchFilters(), **kwargs)
    assert caught.value is error
    runs = tuple(iter_timing_runs(timing_root))
    incident = _operation_evidence(runs, trace_root)[0].incident
    assert incident is not None
    assert incident.incident_id is not None
    if terminal != "available":
        # A missing terminal response must not mark the retained primary corrupt.
        assert incident.omission is None
        assert incident.capture_failure is not None
    assert incident.response_role == (
        "terminal" if terminal == "available" else "primary"
    )
    assert incident.omission is None
    if terminal == "available":
        assert incident.capture_failure is None
    else:
        assert (
            incident.capture_failure.model_dump()
            == {
                "missing": {"stage": "response", "reason": "unavailable"},
                "write_failed": {"stage": "persistence", "reason": "failed"},
            }[terminal]
        )
    assert _operation_evidence(runs, trace_root)[0].browser_fallback_attempted is True
    retained = IncidentStore(trace_root / "wsj" / "incidents", build_identity=identity)
    capsule = retained.load(incident.incident_id)
    expected = terminal_fetch if terminal == "available" else primary
    assert retained.capture_path(capsule).read_bytes() == expected.raw_html
    report = LiveReportStore(
        report_path=trace_root / "live-report.json",
        baseline_root=tmp_path / "baselines",
        invocation_id="live-search-fallback-fixture",
        mode=TimingRunMode.WARM,
        providers=("wsj",),
        source=build_source_identity(Path.cwd()),
        started_at=datetime.now(UTC),
    ).finalize(
        outcome=LiveReportOutcome.FAILURE,
        exit_class=LiveExitClass.PYTEST_FAILURE,
        runs=runs,
        surface="none",
        trace_root=trace_root,
    )
    gaps = report.provider_diagnoses[0].missing_evidence
    assert (EvidenceGap.MISSING_RESPONSE_CAPTURE in gaps) is (terminal != "available")
    explanation = subprocess.check_output(
        [
            sys.executable,
            "scripts/explain_live_report.py",
            str(trace_root / "live-report.json"),
            "--format",
            "text",
        ],
        text=True,
    )
    assert f"Response role: {incident.response_role}" in explanation
    assert "not_configured" not in explanation
    assert "Transport path: HTTP -> browser" in explanation
    assert "Response capture omitted" not in explanation
    assert ("does not establish the terminal browser response" in explanation) is (
        terminal != "available"
    )
    # Evidence with an explicit terminal gap must still undergo integrity checks.
    retained.capture_path(capsule).write_bytes(b"tampered fixture")
    assert (
        _operation_evidence(runs, trace_root)[0].incident.omission == "invalid_capture"
    )


def test_recovered_search_challenge_consumes_no_incident_budget(tmp_path, monkeypatch):
    identity = legacy_build_identity(revision=None, dirty=None)
    store = IncidentStore(tmp_path / "incidents", build_identity=identity)
    primary = RawFetch(
        requested_url="https://www.wsj.com/search?query=fixture",
        final_url="https://www.wsj.com/search?query=fixture",
        retrieved_at=datetime.now(UTC),
        http_status=401,
        content_type="text/html",
        raw_html=b"<html>Initial device check</html>",
        session_cookie_present=False,
    )
    served = primary.model_copy(
        update={"http_status": 200, "raw_html": b"<html>results</html>"}
    )

    def search(http, session, query, filters, **kwargs):
        http.get(str(primary.requested_url), session=session)
        return []

    provider = SimpleNamespace(key="wsj", search=search)
    service = NewsclipService.__new__(NewsclipService)
    service._incidents = store
    service._defense = None
    client = ChallengeAwareHttpClient(
        "wsj",
        SimpleNamespace(get=lambda *args, **kwargs: primary),
        is_challenge=lambda fetch: fetch.http_status == 401,
        browser_fallback=SimpleNamespace(get=lambda *args, **kwargs: served),
        on_challenge_observed=lambda fetch: service._record_http_challenge(
            provider, fetch
        ),
    )
    monkeypatch.setattr(service, "_search_session_for", lambda provider: None)
    monkeypatch.setattr(service, "_provider_search_http", lambda provider: client)
    timing_root = tmp_path / "timings"
    recorder = TimingRecorder(timing_root, build_identity=identity)
    with recorder.operation(
        TimingOperation.SEARCH, provider="wsj", transport=TimingTransport.HTTP
    ):
        assert service._search_provider(provider, "fixture", SearchFilters()) == (
            [],
            None,
        )

    # The challenge stays visible as a timing fact without evicting real
    # failure evidence from the bounded per-provider incident store.
    assert not any((tmp_path / "incidents").glob("incident-*"))
    (run,) = tuple(iter_timing_runs(timing_root))
    assert run.finished is not None
    assert run.finished.browser_fallback_attempted is True
    assert run.finished.incident is None


@pytest.mark.parametrize("failure", [None, "write", "copy", "tamper"])
def test_http_failure_links_retained_response_without_replacing_error(
    tmp_path, monkeypatch, failure
):
    identity = legacy_build_identity(revision=None, dirty=None)
    trace_root = tmp_path / "invocation"
    store = IncidentStore(
        tmp_path / "temporary-state" / "incidents",
        build_identity=identity,
        evidence_root=trace_root / "ap" / "incidents",
    )

    def unavailable(*args, **kwargs):
        raise OSError("fixture write unavailable")

    if failure == "write":
        monkeypatch.setattr(store, "record_assessed_retrieval", unavailable)
    if failure == "copy":
        monkeypatch.setattr(store, "retain_evidence", unavailable)
    provider = ApProvider()
    url = str(provider.spec.check.canonical_url)
    fetch = RawFetch(
        requested_url=url,
        final_url=url,
        retrieved_at=datetime.now(UTC),
        http_status=403,
        content_type="text/html",
        raw_html=b"<title>Forbidden</title><p>Private fixture response.</p>",
    )
    registry = ProviderRegistry([provider])
    timing_root = tmp_path / "timings"
    service = NewsclipService(
        registry,
        SimpleNamespace(get=lambda *args, **kwargs: fetch),
        TrafilaturaExtractor(),
        archive=ArchiveStore(tmp_path / "archive.sqlite3", registry=registry),
        incidents=store,
        timing=TimingRecorder(
            timing_root, build_identity=identity, run_mode=TimingRunMode.WARM
        ),
    )
    with pytest.raises(ContentNotFullError, match="http_forbidden"):
        service.save(url)
    runs = tuple(iter_timing_runs(timing_root))
    operation = _operation_evidence(runs, trace_root)[0]
    assert operation.incident is not None

    def assert_explanation(expected_omission):
        report = LiveReportStore(
            report_path=trace_root / "live-report.json",
            baseline_root=tmp_path / "baselines",
            invocation_id="live-incident-fixture",
            mode=TimingRunMode.WARM,
            providers=("ap",),
            source=build_source_identity(Path.cwd()),
            started_at=datetime.now(UTC),
        ).finalize(
            outcome=LiveReportOutcome.FAILURE,
            exit_class=LiveExitClass.PYTEST_FAILURE,
            runs=runs,
            surface="none",
            trace_root=trace_root,
        )
        assert report.operations[0].incident.omission == expected_omission
        gaps = report.provider_diagnoses[0].missing_evidence
        assert (EvidenceGap.MISSING_RESPONSE_CAPTURE in gaps) is bool(expected_omission)
        explanation = subprocess.check_output(
            [
                sys.executable,
                "scripts/explain_live_report.py",
                str(trace_root / "live-report.json"),
                "--format",
                "text",
            ],
            text=True,
        )
        assert "Private fixture response" not in explanation
        assert url not in explanation
        assert ("Response capture omitted" in explanation) is bool(expected_omission)
        if expected_omission is None:
            assert "Response evidence: ap/incidents/incident-" in explanation

    assert_explanation(operation.incident.omission)
    if failure in {"write", "copy"}:
        assert operation.incident.omission == "write_failed"
        return
    assert operation.incident.omission is None
    retained = IncidentStore(trace_root / "ap" / "incidents", build_identity=identity)
    capsule = retained.load(operation.incident.incident_id)
    path = retained.capture_path(capsule)
    assert path.read_bytes() == fetch.raw_html
    assert retained.load_context(capsule).requested_url == fetch.requested_url
    assert path.stat().st_mode & 0o777 == 0o600
    # The copied capsule remains usable after the source store disappears.
    store.root.rename(tmp_path / "former-state")
    assert _operation_evidence(runs, trace_root)[0].incident.omission is None
    if failure == "tamper":
        path.write_bytes(b"different fixture")
        assert (
            _operation_evidence(runs, trace_root)[0].incident.omission
            == "invalid_capture"
        )
        assert_explanation("invalid_capture")
