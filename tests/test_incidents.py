from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from newsclip.incidents import (
    IncidentKind,
    IncidentPersistenceError,
    IncidentSchemaUnsupportedError,
    IncidentStore,
    SearchFailureKind,
)
from newsclip.models import AccessState, ArticleAssessment, RawFetch
from newsclip.provenance import (
    BuildIdentity,
    BuildIdentitySource,
    BuildIdentityUnavailableReason,
)
from newsclip.timing import TimingOperation, content_assessment_evidence

NOW = datetime(2026, 7, 24, tzinfo=UTC)
URL = "https://www.ft.com/content/fixture"
SOURCE_FINGERPRINT = "a" * 64


def _identity() -> BuildIdentity:
    return BuildIdentity(
        revision="a" * 40,
        dirty=False,
        source_fingerprint=SOURCE_FINGERPRINT,
        source=BuildIdentitySource.ENVIRONMENT,
    )


def _fetch(
    payload: bytes = b"<html><body>private fixture</body></html>",
    *,
    url: str = URL,
) -> RawFetch:
    return RawFetch(
        requested_url=url,
        final_url=url,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=payload,
    )


def _assessment() -> ArticleAssessment:
    return ArticleAssessment(
        access_state=AccessState.TEASER,
        identity_match=True,
        word_count=42,
        session_cookie_present=True,
        reason="paywall_teaser",
    )


def test_incident_store_commits_private_bounded_evidence(tmp_path: Path) -> None:
    store = IncidentStore(
        tmp_path / "incidents",
        build_identity=_identity(),
        utc_now=lambda: NOW,
    )

    capsule = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=_assessment(),
    )

    directory = store.root / capsule.incident_id
    metadata = directory / "incident.json"
    context_path = directory / "context.json"
    capture = store.capture_path(capsule)
    assert capture is not None
    assert capture.read_bytes() == _fetch().raw_html
    assert capsule.raw_sha256 == hashlib.sha256(_fetch().raw_html).hexdigest()
    assert capsule.requested_url_sha256 == hashlib.sha256(URL.encode()).hexdigest()
    assert capsule.capture_available is True
    assert (
        capsule.context_sha256 == hashlib.sha256(context_path.read_bytes()).hexdigest()
    )
    assert capsule.assessment.reason == "paywall_teaser"
    assert store.load(capsule.incident_id) == capsule
    assert tuple(store.iter_capsules()) == (capsule,)
    assert oct(directory.stat().st_mode & 0o777) == "0o700"
    assert oct(metadata.stat().st_mode & 0o777) == "0o600"
    assert oct(context_path.stat().st_mode & 0o777) == "0o600"
    assert oct(capture.stat().st_mode & 0o777) == "0o600"
    assert URL not in metadata.read_text(encoding="utf-8")


def test_browser_terminal_evidence_does_not_reuse_primary_http_capsule(tmp_path):
    from newsclip.models import RetrievalDiagnostics

    store = IncidentStore(tmp_path / "incidents", build_identity=_identity())
    primary = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=_assessment(),
    )
    terminal = _fetch().model_copy(
        update={
            "diagnostics": RetrievalDiagnostics(
                screenshot_status="captured",
                screenshot=b"terminal viewport",
                trace=b"bounded terminal trace",
            )
        }
    )
    browser = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=terminal,
        assessment=_assessment(),
    )
    assert browser.incident_id != primary.incident_id
    assert store.load(primary.incident_id) == primary
    assert store.load(browser.incident_id) == browser
    assert store.diagnostic_bytes(browser, "screenshot") == b"terminal viewport"
    assert (
        store.record_assessed_retrieval(
            provider="ft",
            operation=TimingOperation.GET,
            fetch=terminal,
            assessment=_assessment(),
        )
        == browser
    )


def test_incident_commit_fsyncs_artifacts_and_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import newsclip.incidents as incidents

    synced: list[Path] = []
    real_fsync = incidents._fsync_directory

    def observe(path: Path) -> None:
        synced.append(path)
        real_fsync(path)

    monkeypatch.setattr(incidents, "_fsync_directory", observe)
    store = IncidentStore(tmp_path / "incidents", build_identity=_identity())

    store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=_assessment(),
    )

    assert store.root in synced
    assert any(
        path.parent == store.root and path.name.startswith(".tmp-") for path in synced
    )


def test_incident_store_deduplicates_same_failure_signature(tmp_path: Path) -> None:
    store = IncidentStore(
        tmp_path / "incidents",
        build_identity=_identity(),
        utc_now=lambda: NOW,
    )

    first = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.SAVE,
        fetch=_fetch(b"first private response"),
        assessment=_assessment(),
    )
    second = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.SAVE,
        fetch=_fetch(b"later private response"),
        assessment=_assessment(),
    )

    assert second == first
    first_capture = store.capture_path(first)
    assert first_capture is not None
    assert first_capture.read_bytes() == b"first private response"


def test_incident_store_deduplicates_bounded_assessment_variation(
    tmp_path: Path,
) -> None:
    store = IncidentStore(
        tmp_path / "incidents",
        build_identity=_identity(),
        utc_now=lambda: NOW,
    )
    first = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(b"first private response"),
        assessment=_assessment(),
    )
    later_assessment = _assessment().model_copy(update={"word_count": 99})

    second = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(b"later private response"),
        assessment=later_assessment,
    )

    assert second == first


def test_incident_store_does_not_conflate_unknown_build_responses(
    tmp_path: Path,
) -> None:
    identity = BuildIdentity(
        source=BuildIdentitySource.UNAVAILABLE,
        unavailable_reason=BuildIdentityUnavailableReason.SOURCE_TREE_UNAVAILABLE,
    )
    store = IncidentStore(tmp_path / "incidents", build_identity=identity)

    first = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(b"first private response"),
        assessment=_assessment(),
    )
    second = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(b"later private response"),
        assessment=_assessment(),
    )

    assert first.incident_id != second.incident_id
    assert len(tuple(store.iter_capsules())) == 2


def test_incident_store_marks_oversized_capture_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import newsclip.incidents as incidents

    monkeypatch.setattr(incidents, "_MAX_CAPTURE_BYTES", 4)
    store = IncidentStore(tmp_path / "incidents", build_identity=_identity())

    capsule = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(b"12345"),
        assessment=_assessment(),
    )

    assert capsule.capture_available is False
    assert store.capture_path(capsule) is None


def test_incident_store_prunes_each_provider_to_bounded_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import newsclip.incidents as incidents

    store = IncidentStore(tmp_path / "incidents", build_identity=_identity())
    foreign = store.record_assessed_retrieval(
        provider="cnbc",
        operation=TimingOperation.GET,
        fetch=_fetch(url="https://www.cnbc.com/2026/07/24/fixture.html"),
        assessment=_assessment(),
    )

    latest = None
    latest_fetch = None
    for index in range(3):
        latest_fetch = _fetch(url=f"{URL}?case={index}")
        latest = store.record_assessed_retrieval(
            provider="ft",
            operation=TimingOperation.GET,
            fetch=latest_fetch,
            assessment=_assessment(),
        )

    assert latest is not None
    assert latest_fetch is not None
    assert sum(capsule.provider == "ft" for capsule in store.iter_capsules()) == 3
    monkeypatch.setattr(incidents, "_MAX_INCIDENTS_PER_PROVIDER", 2)
    assert (
        store.record_assessed_retrieval(
            provider="ft",
            operation=TimingOperation.GET,
            fetch=latest_fetch,
            assessment=_assessment(),
        )
        == latest
    )
    retained = tuple(store.iter_capsules())
    assert sum(capsule.provider == "ft" for capsule in retained) == 2
    assert store.load(latest.incident_id) == latest
    assert store.load(foreign.incident_id) == foreign


def test_incident_store_prunes_provider_capture_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import newsclip.incidents as incidents

    monkeypatch.setattr(incidents, "_MAX_CAPTURE_STORAGE_BYTES_PER_PROVIDER", 6)
    store = IncidentStore(tmp_path / "incidents", build_identity=_identity())

    latest = None
    for index in range(2):
        latest = store.record_assessed_retrieval(
            provider="ft",
            operation=TimingOperation.GET,
            fetch=_fetch(b"12345", url=f"{URL}?case={index}"),
            assessment=_assessment(),
        )

    assert latest is not None
    retained = tuple(store.iter_capsules())
    assert retained == (latest,)
    assert store.capture_path(latest) is not None


def test_incident_store_retains_search_response_without_assessment(
    tmp_path: Path,
) -> None:
    store = IncidentStore(tmp_path / "incidents", build_identity=_identity())

    capsule = store.record_search(
        provider="ft",
        fetch=_fetch(),
        failure=SearchFailureKind.CONTRACT,
    )

    assert capsule.operation is TimingOperation.SEARCH
    assert capsule.kind is IncidentKind.SEARCH_RESPONSE
    assert capsule.assessment is None
    assert capsule.search_failure is SearchFailureKind.CONTRACT
    assert capsule.http_status == 200
    capture = store.capture_path(capsule)
    assert capture is not None
    assert capture.read_bytes() == _fetch().raw_html
    context = store.load_context(capsule)
    assert str(context.requested_url) == URL
    assert str(context.final_url) == URL
    assert context.content_type == "text/html"


def test_incident_store_reads_legacy_search_capsule_without_replay_context(
    tmp_path: Path,
) -> None:
    requested_hash = hashlib.sha256(URL.encode()).hexdigest()
    raw_hash = hashlib.sha256(_fetch().raw_html).hexdigest()
    signature = "\0".join(
        (
            "ft",
            "search",
            SOURCE_FINGERPRINT,
            requested_hash,
            "search_response",
            "200",
            "not_applicable",
        )
    )
    incident_id = f"incident-{hashlib.sha256(signature.encode()).hexdigest()[:24]}"
    root = tmp_path / "incidents"
    directory = root / incident_id
    directory.mkdir(parents=True)
    payload = {
        "schema_version": 1,
        "incident_id": incident_id,
        "provider": "ft",
        "operation": "search",
        "kind": "search_response",
        "occurred_at": NOW.isoformat(),
        "build_identity": _identity().model_dump(mode="json"),
        "requested_url_sha256": requested_hash,
        "final_url_sha256": requested_hash,
        "raw_sha256": raw_hash,
        "capture_bytes": len(_fetch().raw_html),
        "capture_available": True,
        "http_status": 200,
        "session_cookie_present": True,
        "assessment": None,
    }
    (directory / "incident.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    store = IncidentStore(root, build_identity=_identity())

    capsule = store.load(incident_id)

    assert capsule.search_failure is None
    assert capsule.context_sha256 is None
    with pytest.raises(IncidentPersistenceError, match="context is unavailable"):
        store.load_context(capsule)


def test_incident_store_rejects_tampered_capture(tmp_path: Path) -> None:
    store = IncidentStore(tmp_path / "incidents", build_identity=_identity())
    capsule = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=_assessment(),
    )
    capture = store.capture_path(capsule)
    assert capture is not None
    capture.write_bytes(b"x" * len(_fetch().raw_html))

    with pytest.raises(IncidentPersistenceError, match="digest mismatch"):
        store.capture_path(capsule)


def test_incident_store_ignores_non_directory_index_entries(tmp_path: Path) -> None:
    root = tmp_path / "incidents"
    root.mkdir()
    (root / "unrelated").write_text("ignored", encoding="utf-8")
    store = IncidentStore(root, build_identity=_identity())

    assert tuple(store.iter_capsules()) == ()


def test_incident_store_skips_and_counts_corrupt_valid_entries(tmp_path: Path) -> None:
    root = tmp_path / "incidents"
    store = IncidentStore(root, build_identity=_identity())
    valid = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=_assessment(),
    )
    corrupt = root / ("incident-" + "a" * 24)
    corrupt.mkdir(parents=True)
    (corrupt / "incident.json").write_text("not json", encoding="utf-8")

    assert tuple(store.iter_capsules()) == (valid,)
    assert store.last_scan_corrupt_entries == 1


def test_incident_store_pruning_removes_corrupt_valid_entries(tmp_path: Path) -> None:
    root = tmp_path / "incidents"
    store = IncidentStore(root, build_identity=_identity())
    corrupt = root / ("incident-" + "a" * 24)
    corrupt.mkdir(parents=True)
    (corrupt / "incident.json").write_text("not json", encoding="utf-8")

    store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=_assessment(),
    )

    assert not corrupt.exists()


def test_incident_store_pruning_preserves_unknown_schema_evidence(
    tmp_path: Path,
) -> None:
    """Evidence from another build's schema is not this build's to discard."""

    root = tmp_path / "incidents"
    newer = root / ("incident-" + "b" * 24)
    newer.mkdir(parents=True)
    (newer / "incident.json").write_text(
        json.dumps({"schema_version": 99, "incident_id": newer.name, "provider": "ft"}),
        encoding="utf-8",
    )
    corrupt = root / ("incident-" + "c" * 24)
    corrupt.mkdir(parents=True)
    (corrupt / "incident.json").write_text("not json", encoding="utf-8")

    store = IncidentStore(root, build_identity=_identity())
    with pytest.raises(IncidentSchemaUnsupportedError):
        store.load(newer.name)

    store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=_assessment(),
    )

    assert newer.exists()
    assert not corrupt.exists()


def test_incident_store_pruning_preserves_infrastructure_read_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "incidents"
    store = IncidentStore(root, build_identity=_identity())
    unavailable = root / ("incident-" + "a" * 24)
    unavailable.mkdir(parents=True)
    (unavailable / "incident.json").write_text("unreadable", encoding="utf-8")
    durable_load = store.load

    def fail_unavailable(incident_id: str):
        if incident_id == unavailable.name:
            try:
                raise OSError("injected read failure")
            except OSError as error:
                raise IncidentPersistenceError(
                    "incident metadata is unavailable"
                ) from error
        return durable_load(incident_id)

    monkeypatch.setattr(store, "load", fail_unavailable)

    store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=_assessment(),
    )

    assert unavailable.is_dir()


def test_incident_store_rejects_metadata_with_inconsistent_identifier(
    tmp_path: Path,
) -> None:
    store = IncidentStore(tmp_path / "incidents", build_identity=_identity())
    capsule = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=_assessment(),
    )
    metadata = store.root / capsule.incident_id / "incident.json"
    payload = metadata.read_text(encoding="utf-8").replace(
        '"provider":"ft"',
        '"provider":"wsj"',
    )
    metadata.write_text(payload, encoding="utf-8")

    with pytest.raises(IncidentPersistenceError, match="identifier is inconsistent"):
        store.load(capsule.incident_id)


def test_incident_store_rejects_symlinked_incident_directory(tmp_path: Path) -> None:
    root = tmp_path / "incidents"
    external = tmp_path / "external"
    external.mkdir()
    root.mkdir()
    incident_id = "incident-" + "a" * 24
    (root / incident_id).symlink_to(external, target_is_directory=True)
    store = IncidentStore(root, build_identity=_identity())

    with pytest.raises(IncidentPersistenceError, match="directory is invalid"):
        store.load(incident_id)


def test_incident_metadata_never_serializes_private_url_or_body(tmp_path: Path) -> None:
    store = IncidentStore(tmp_path / "incidents", build_identity=_identity())
    capsule = store.record_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=content_assessment_evidence(_assessment()),
    )

    metadata = (store.root / capsule.incident_id / "incident.json").read_bytes()
    assert URL.encode() not in metadata
    assert b"private fixture" not in metadata
    assert os.stat(store.root).st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "mismatch", [None, "assessment", "provider", "operation", "new_target"]
)
def test_service_incident_retains_only_matching_emitted_session_probe(
    tmp_path, mismatch
):
    from types import SimpleNamespace

    from newsclip.models import SessionVerification
    from newsclip.providers import ProviderRegistry
    from newsclip.service import NewsclipService
    from newsclip.timing import (
        SessionProbeOutcome,
        TimingRecorder,
        TimingTransport,
        clear_timing_content_assessment,
        read_timing_file,
        set_timing_content_assessment,
        set_timing_session_probe,
    )

    store = IncidentStore(tmp_path / "incidents", build_identity=_identity())
    recorder = TimingRecorder(tmp_path / "timings")
    # This path is local evidence persistence; these sentinels fail if it
    # unexpectedly tries to extract content or contact a provider.
    service = NewsclipService(ProviderRegistry(()), object(), object(), incidents=store)
    assessment = _assessment()
    with recorder.operation(
        TimingOperation.GET, provider="ft", transport=TimingTransport.BROWSER
    ) as operation:
        set_timing_content_assessment(assessment)
        set_timing_session_probe(
            SessionProbeOutcome.INCONCLUSIVE,
            SessionVerification(
                verified=False,
                access_state=AccessState.TEASER,
                reason="paywall_teaser",
                verified_at=NOW,
            ),
        )
        if mismatch == "assessment":
            assessment = assessment.model_copy(update={"word_count": 99})
        if mismatch == "new_target":
            clear_timing_content_assessment()
            set_timing_content_assessment(assessment)
        incident_id = service._record_retrieval_incident(
            SimpleNamespace(key="wsj" if mismatch == "provider" else "ft"),
            TimingOperation.SAVE if mismatch == "operation" else TimingOperation.GET,
            _fetch(),
            assessment,
        )
    assert incident_id is not None
    capsule = store.load(incident_id)
    if mismatch is None:
        emitted = read_timing_file(operation.path).finished.content_assessment
        assert capsule.assessment == emitted
        assert (
            capsule.assessment.session_probe.outcome is SessionProbeOutcome.INCONCLUSIVE
        )
    else:
        assert capsule.assessment.session_probe is None
    metadata = (store.root / incident_id / "incident.json").read_bytes()
    assert URL.encode() not in metadata
    assert b"private fixture" not in metadata


def test_unresolved_hold_and_defense_evidence_survive_retention(tmp_path, monkeypatch):
    from test_provider_guard import _check, _guard

    import newsclip.incidents as module
    from newsclip.composition import _protected_incidents
    from newsclip.defense import DefenseState
    from newsclip.models import SessionDisposition
    from newsclip.provider_check import ProviderCheckFailure

    monkeypatch.setattr(module, "_MAX_INCIDENTS_PER_PROVIDER", 2)
    store = IncidentStore(
        tmp_path / "incidents",
        build_identity=_identity(),
        protected_incidents=lambda provider: _protected_incidents(
            tmp_path, provider, _identity()
        ),
    )
    first = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=_assessment(),
    )
    guard, _ = _guard(tmp_path)
    held = guard.run(
        "ft",
        lambda: _check(
            failure=ProviderCheckFailure.CONTENT_NOT_FULL,
            disposition=SessionDisposition.VERIFIED,
            incident_id=first.incident_id,
        ),
    )
    second = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(url=URL + "?defense"),
        assessment=_assessment(),
    )
    defense = DefenseState(tmp_path / "provider-defense", incident_root=store.root)
    defense.arm("ft", origin="retrieval")
    defense.attach_incident("ft", second.incident_id)
    for i in range(8):
        store.record_assessed_retrieval(
            provider="ft",
            operation=TimingOperation.GET,
            fetch=_fetch(url=URL + f"?sample={i}"),
            assessment=_assessment(),
        )
    assert store.load(first.incident_id) == first
    assert store.load(second.incident_id) == second
    assert guard.peek("ft").incident_id == first.incident_id
    assert len(tuple(store.iter_capsules())) <= 4
    guard.acknowledge("ft", hold_id=held.hold_id)
    defense.clear("ft")
    store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(url=URL + "?resolved"),
        assessment=_assessment(),
    )
    assert len(tuple(store.iter_capsules())) == 2
    assert all(
        c.incident_id not in {first.incident_id, second.incident_id}
        for c in store.iter_capsules()
    )


@pytest.mark.parametrize("status", ["pending", "running", "failed"])
def test_unresolved_recovery_evidence_survives_retention_until_resolved(
    tmp_path, monkeypatch, status
):
    import newsclip.incidents as module
    from newsclip.composition import _protected_incidents
    from newsclip.models import RecoveryStatus
    from newsclip.recovery import RecoveryStore

    monkeypatch.setattr(module, "_MAX_INCIDENTS_PER_PROVIDER", 2)
    store = IncidentStore(
        tmp_path / "incidents",
        build_identity=_identity(),
        protected_incidents=lambda provider: _protected_incidents(
            tmp_path, provider, _identity()
        ),
    )
    first = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=_assessment(),
    )
    recovery = RecoveryStore(tmp_path / "recovery", utc_now=lambda: NOW)
    requested = recovery.request(
        "ft",
        generation_id=None,
        url=URL,
        incident_id=first.incident_id,
        diagnostic_id=None,
    )
    if status in {"running", "failed"}:
        with recovery.operation("ft"):
            claimed = recovery.claim("ft", diagnostic_id=None)
            assert claimed is not None
            if status == "failed":
                recovery.finish(claimed, reason="article_not_full")
    assert recovery.load("ft").health.status is RecoveryStatus(status)
    for i in range(8):
        store.record_assessed_retrieval(
            provider="ft",
            operation=TimingOperation.GET,
            fetch=_fetch(url=URL + f"?sample={i}"),
            assessment=_assessment(),
        )
    assert store.load(first.incident_id) == first
    assert len(tuple(store.iter_capsules())) <= 3

    recovery.finish(requested, reason=None, article_verified=True)
    store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(url=URL + "?resolved"),
        assessment=_assessment(),
    )
    assert len(tuple(store.iter_capsules())) == 2
    assert first.incident_id not in {c.incident_id for c in store.iter_capsules()}


def test_unreadable_recovery_state_cannot_authorize_evidence_pruning(
    tmp_path, monkeypatch
):
    import newsclip.incidents as module
    from newsclip.composition import _protected_incidents

    monkeypatch.setattr(module, "_MAX_INCIDENTS_PER_PROVIDER", 1)
    (tmp_path / "recovery").mkdir()
    (tmp_path / "recovery" / "ft.json").write_text("invalid json")
    store = IncidentStore(
        tmp_path / "incidents",
        build_identity=_identity(),
        protected_incidents=lambda provider: _protected_incidents(
            tmp_path, provider, _identity()
        ),
    )
    for i in range(4):
        store.record_assessed_retrieval(
            provider="ft",
            operation=TimingOperation.GET,
            fetch=_fetch(url=URL + f"?sample={i}"),
            assessment=_assessment(),
        )
    assert len(tuple(store.iter_capsules())) == 4


def test_private_terminal_bundle_survives_invocation_copy_and_detects_tampering(
    tmp_path,
):
    from newsclip.models import RetrievalDiagnostics

    diagnostics = RetrievalDiagnostics(
        screenshot_status="captured",
        screenshot=b"private viewport",
        trace=b'{"event":"inert"}\n',
    )
    fetch = _fetch().model_copy(update={"diagnostics": diagnostics})
    assert "diagnostics" not in fetch.model_dump()
    store = IncidentStore(
        tmp_path / "incidents",
        build_identity=_identity(),
        evidence_root=tmp_path / "invocation",
    )
    capsule = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=fetch,
        assessment=_assessment(),
    )
    store.retain_evidence(capsule)
    copied = IncidentStore(tmp_path / "invocation", build_identity=_identity())
    assert copied.diagnostic_bytes(capsule, "screenshot") == b"private viewport"
    assert copied.diagnostic_bytes(capsule, "trace") == diagnostics.trace
    assert copied.evidence_health(capsule.incident_id).status == "complete"
    (copied.root / capsule.incident_id / "terminal.png").write_bytes(b"changed")
    assert copied.evidence_health(capsule.incident_id).status == "missing"


def test_capture_failure_stays_explicit_without_losing_original_response(tmp_path):
    from newsclip.models import RetrievalDiagnostics

    store = IncidentStore(tmp_path / "incidents", build_identity=_identity())
    capsule = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch().model_copy(
            update={
                "diagnostics": RetrievalDiagnostics(screenshot_status="capture_failed")
            }
        ),
        assessment=_assessment(),
    )
    health = store.evidence_health(capsule.incident_id)
    assert health.status == "partial" and health.screenshot_status == "capture_failed"
    assert store.capture_path(capsule).read_bytes() == _fetch().raw_html
