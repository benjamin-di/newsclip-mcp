from __future__ import annotations

import json
import os
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from newsclip.acquisition import (
    AcquisitionMode,
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
)
from newsclip.errors import ProviderTransportError, TransportFailure
from newsclip.models import AccessState, ArticleAssessment, SessionVerification
from newsclip.provenance import BuildIdentity, BuildIdentitySource
from newsclip.timing import (
    ContentAssessmentEvidence,
    OperationFinishedEvent,
    SessionProbeEvidence,
    SessionProbeOutcome,
    StepFinishedEvent,
    StepStartedEvent,
    TimingOperation,
    TimingOutcome,
    TimingRecorder,
    TimingRun,
    TimingRunMode,
    TimingStep,
    TimingSurface,
    TimingTransport,
    clear_timing_content_assessment,
    current_timing_invocation_id,
    iter_timing_runs,
    read_timing_file,
    set_timing_acquisition_mode,
    set_timing_browser_major,
    set_timing_content_assessment,
    set_timing_failure,
    set_timing_session_probe,
    timing_invocation,
    timing_step,
)


class FakeTime:
    def __init__(self) -> None:
        self.nanoseconds = 1_000
        self.now = datetime(2026, 7, 20, tzinfo=UTC)

    def monotonic_ns(self) -> int:
        return self.nanoseconds

    def utc_now(self) -> datetime:
        value = self.now
        self.now += timedelta(microseconds=1)
        return value

    def advance(self, nanoseconds: int) -> None:
        self.nanoseconds += nanoseconds


def _recorder(root: Path, clock: FakeTime, **kwargs) -> TimingRecorder:
    return TimingRecorder(
        root,
        monotonic_ns=clock.monotonic_ns,
        utc_now=clock.utc_now,
        **kwargs,
    )


def test_records_exact_nested_durations_and_private_permissions(tmp_path: Path) -> None:
    clock = FakeTime()
    recorder = _recorder(
        tmp_path / "timings",
        clock,
        invocation_id="live-check-1",
        run_mode=TimingRunMode.COLD,
        build_revision="1234567",
        build_dirty=True,
        surface=TimingSurface.HOST_XVFB,
    )
    assert not recorder.root.exists()

    with recorder.operation(
        TimingOperation.GET,
        provider="ft",
        transport=TimingTransport.HTTP,
    ) as operation:
        with timing_step(TimingStep.FETCH, provider="ft"):
            clock.advance(2_000_000)
            with timing_step(TimingStep.CONTENT_READ, provider="ft"):
                clock.advance(3_000_000)
            clock.advance(5_000_000)
        set_timing_acquisition_mode(AcquisitionMode.ARTIFACT_REUSE)
        set_timing_browser_major(137)
        clock.advance(7_000_000)

    assert operation.path is not None
    run = read_timing_file(operation.path)
    assert run.operation_id == operation.operation_id
    assert run.invocation_id == "live-check-1"
    assert run.started.run_mode is TimingRunMode.COLD
    assert run.started.build_revision == "1234567"
    assert run.started.build_dirty is True
    assert run.started.surface is TimingSurface.HOST_XVFB
    assert run.active_steps == ()
    assert run.finished == OperationFinishedEvent(
        operation=TimingOperation.GET,
        outcome=TimingOutcome.SUCCESS,
        duration_ns=17_000_000,
        acquisition_mode=AcquisitionMode.ARTIFACT_REUSE,
        browser_major=137,
        browser_fallback_attempted=False,
    )
    step_starts = [
        record.event
        for record in run.records
        if isinstance(record.event, StepStartedEvent)
    ]
    assert step_starts[1].parent_step_id == step_starts[0].step_id
    step_finishes = [
        record.event
        for record in run.records
        if isinstance(record.event, StepFinishedEvent)
    ]
    assert [event.duration_ns for event in step_finishes] == [
        3_000_000,
        10_000_000,
    ]
    assert stat.S_IMODE(operation.path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(operation.path.stat().st_mode) == 0o600


def test_operation_start_retains_compact_build_identity(tmp_path: Path) -> None:
    clock = FakeTime()
    recorder = _recorder(
        tmp_path / "timings",
        clock,
        build_identity=BuildIdentity(
            revision="1234567",
            dirty=False,
            source_fingerprint="a" * 64,
            source=BuildIdentitySource.ENVIRONMENT,
        ),
    )

    with recorder.operation(
        TimingOperation.GET,
        provider="ft",
        transport=TimingTransport.HTTP,
    ) as operation:
        pass

    assert operation.path is not None
    started = read_timing_file(operation.path).started
    assert started.build_revision == "1234567"
    assert started.build_dirty is False
    assert started.build_source_fingerprint == "a" * 64
    assert started.build_identity_source is BuildIdentitySource.ENVIRONMENT
    assert started.build_identity_unavailable_reason is None


def test_exception_is_preserved_and_typed_as_timeout(tmp_path: Path) -> None:
    clock = FakeTime()
    recorder = _recorder(tmp_path / "timings", clock)

    with (
        pytest.raises(TimeoutError, match="provider deadline"),
        recorder.operation(
            TimingOperation.SEARCH,
            provider="all",
            transport=TimingTransport.MIXED,
        ) as operation,
        timing_step(TimingStep.PROVIDER_SEARCH, provider="wsj"),
    ):
        clock.advance(41)
        raise TimeoutError("provider deadline")

    assert operation.path is not None
    run = read_timing_file(operation.path)
    assert run.finished is not None
    assert run.finished.outcome is TimingOutcome.TIMEOUT
    finished_steps = [
        record.event
        for record in run.records
        if isinstance(record.event, StepFinishedEvent)
    ]
    assert finished_steps[0].outcome is TimingOutcome.TIMEOUT


def test_timing_uses_the_shared_provider_key_contract(tmp_path: Path) -> None:
    recorder = TimingRecorder(tmp_path / "timings")

    with (
        recorder.operation(
            TimingOperation.GET,
            provider="news_wire",
            transport=TimingTransport.HTTP,
        ),
        timing_step(TimingStep.FETCH, provider="news_wire"),
    ):
        pass

    with pytest.raises(ValueError, match="invalid timing provider key"):
        recorder.operation(
            TimingOperation.GET,
            provider="news.wire",
            transport=TimingTransport.HTTP,
        )


def test_typed_provider_timeout_is_not_flattened_to_generic_error(
    tmp_path: Path,
) -> None:
    recorder = TimingRecorder(tmp_path / "timings")

    with (
        pytest.raises(ProviderTransportError),
        recorder.operation(
            TimingOperation.GET,
            provider="ft",
            transport=TimingTransport.HTTP,
        ) as operation,
    ):
        raise ProviderTransportError(
            "deadline",
            category=TransportFailure.TIMEOUT,
        )

    assert operation.path is not None
    run = read_timing_file(operation.path)
    assert run.finished is not None
    assert run.finished.outcome is TimingOutcome.TIMEOUT


def test_failed_operation_persists_only_closed_acquisition_evidence(
    tmp_path: Path,
) -> None:
    recorder = TimingRecorder(tmp_path / "timings")
    failure = MintFailureEvidence(
        stage=MintFailureStage.CREDENTIAL,
        category=MintFailureCategory.SECRET_DELIVERY_FAILED,
    )

    with (
        pytest.raises(RuntimeError, match="private diagnostic"),
        recorder.operation(
            TimingOperation.LOGIN,
            provider="bloomberg",
            transport=TimingTransport.BROWSER,
        ) as operation,
    ):
        set_timing_failure(failure)
        raise RuntimeError("private diagnostic")

    assert operation.path is not None
    run = read_timing_file(operation.path)
    assert run.finished is not None
    assert run.finished.failure_stage is MintFailureStage.CREDENTIAL
    assert run.finished.failure_category is MintFailureCategory.SECRET_DELIVERY_FAILED
    assert "private diagnostic" not in operation.path.read_text(encoding="utf-8")


def test_terminal_content_evidence_is_bounded_and_retry_coherent(
    tmp_path: Path,
) -> None:
    recorder = TimingRecorder(tmp_path / "timings")
    teaser = ArticleAssessment(
        access_state=AccessState.TEASER,
        identity_match=True,
        word_count=91,
        session_cookie_present=True,
        reason="paywall_teaser",
    )
    verification = SessionVerification(
        verified=True,
        access_state=AccessState.FULL,
        reason="full_article_verified",
        verified_at=datetime(2026, 7, 20, tzinfo=UTC),
    )
    full = teaser.model_copy(
        update={
            "access_state": AccessState.FULL,
            "word_count": 640,
            "reason": "full_article_verified",
        }
    )

    with recorder.operation(
        TimingOperation.SAVE,
        provider="bloomberg",
        transport=TimingTransport.BROWSER,
    ) as operation:
        set_timing_content_assessment(teaser)
        set_timing_session_probe(SessionProbeOutcome.VERIFIED, verification)
        clear_timing_content_assessment()
        set_timing_content_assessment(full)

    assert operation.path is not None
    finished = read_timing_file(operation.path).finished
    assert finished is not None
    assert finished.content_assessment == ContentAssessmentEvidence(
        access_state=AccessState.FULL,
        reason="full_article_verified",
        identity_match=True,
        word_count=640,
        session_cookie_present=True,
    )
    serialized = operation.path.read_text(encoding="utf-8")
    assert "COOKIE" not in serialized
    assert "https://" not in serialized


def test_session_probe_evidence_requires_consistent_facts() -> None:
    with pytest.raises(ValidationError, match="failure reason"):
        SessionProbeEvidence(
            outcome=SessionProbeOutcome.NOT_APPLICABLE,
            failure_reason="authority_changed",
        )
    with pytest.raises(ValidationError, match="observation fields"):
        SessionProbeEvidence(
            outcome=SessionProbeOutcome.TRANSPORT_ERROR,
            access_state=AccessState.BLOCKED,
        )
    with pytest.raises(ValidationError, match="observation is incomplete"):
        SessionProbeEvidence(
            outcome=SessionProbeOutcome.VERIFIED,
        )


def test_content_evidence_replaces_unapproved_reason_identifiers() -> None:
    content = ContentAssessmentEvidence(
        access_state=AccessState.TEASER,
        reason="private_provider_detail",
        identity_match=True,
        word_count=91,
        session_cookie_present=True,
        session_probe=SessionProbeEvidence(
            outcome=SessionProbeOutcome.INCONCLUSIVE,
            access_state=AccessState.UNKNOWN,
            reason="private_verification_detail",
        ),
    )

    assert content.reason == "unavailable"
    assert content.session_probe is not None
    assert content.session_probe.reason == "unavailable"


def test_timing_normalizes_unclosed_reasons_without_masking_product_result(
    tmp_path: Path,
) -> None:
    recorder = TimingRecorder(tmp_path / "timings")
    assessment = ArticleAssessment(
        access_state=AccessState.FULL,
        identity_match=False,
        word_count=640,
        session_cookie_present=True,
        reason="private_provider_detail",
    )
    verification = SessionVerification(
        verified=False,
        access_state=AccessState.UNKNOWN,
        reason="private_verification_detail",
        verified_at=datetime(2026, 7, 20, tzinfo=UTC),
    )

    with recorder.operation(
        TimingOperation.GET,
        provider="ft",
        transport=TimingTransport.HTTP,
    ) as operation:
        set_timing_content_assessment(assessment)
        set_timing_session_probe(SessionProbeOutcome.INCONCLUSIVE, verification)

    assert operation.path is not None
    finished = read_timing_file(operation.path).finished
    assert finished is not None
    assert finished.content_assessment is not None
    assert finished.content_assessment.reason == "unavailable"
    assert finished.content_assessment.session_probe is not None
    assert finished.content_assessment.session_probe.reason == "unavailable"
    serialized = operation.path.read_text(encoding="utf-8")
    assert "private_provider_detail" not in serialized
    assert "private_verification_detail" not in serialized


def test_closed_mint_timeout_survives_outer_error_wrapping(tmp_path: Path) -> None:
    recorder = TimingRecorder(tmp_path / "timings")

    with (
        pytest.raises(RuntimeError),
        recorder.operation(
            TimingOperation.LOGIN,
            provider="ft",
            transport=TimingTransport.BROWSER,
        ) as operation,
    ):
        set_timing_failure(
            MintFailureEvidence(
                stage=MintFailureStage.SESSION,
                category=MintFailureCategory.TIMEOUT,
            )
        )
        raise RuntimeError("outer redacted wrapper")

    assert operation.path is not None
    run = read_timing_file(operation.path)
    assert run.finished is not None
    assert run.finished.outcome is TimingOutcome.TIMEOUT


def test_incomplete_run_exposes_last_active_step(tmp_path: Path) -> None:
    path = tmp_path / "timings" / "get" / "ft" / "run.jsonl"
    path.parent.mkdir(parents=True)
    records = [
        {
            "schema_version": 1,
            "operation_id": "op-123",
            "invocation_id": None,
            "sequence": 1,
            "occurred_at": "2026-07-20T00:00:00Z",
            "elapsed_ns": 0,
            "event": {
                "event": "operation_started",
                "operation": "get",
                "provider": "ft",
                "run_mode": "product",
                "transport": "http",
                "app_version": "0.3.2",
                "build_revision": None,
                "build_dirty": None,
                "surface": "none",
            },
        },
        {
            "schema_version": 1,
            "operation_id": "op-123",
            "invocation_id": None,
            "sequence": 2,
            "occurred_at": "2026-07-20T00:00:01Z",
            "elapsed_ns": 1_000_000_000,
            "event": {
                "event": "step_started",
                "step_id": 1,
                "parent_step_id": None,
                "step": "browser_open",
                "attempt": 1,
                "provider": "ft",
            },
        },
    ]
    path.write_text("".join(json.dumps(record) + "\n" for record in records))

    run = read_timing_file(path)

    assert run.finished is None
    assert [step.step for step in run.active_steps] == [TimingStep.BROWSER_OPEN]


def test_context_isolation_across_parallel_operations(tmp_path: Path) -> None:
    def work(provider: str) -> TimingRun:
        recorder = TimingRecorder(tmp_path / "timings")
        with (
            recorder.operation(
                TimingOperation.GET,
                provider=provider,
                transport=TimingTransport.HTTP,
            ) as operation,
            timing_step(TimingStep.FETCH, provider=provider),
        ):
            pass
        assert operation.path is not None
        return read_timing_file(operation.path)

    with ThreadPoolExecutor(max_workers=2) as executor:
        runs = tuple(executor.map(work, ("ft", "wsj")))

    assert len({run.operation_id for run in runs}) == 2
    for run in runs:
        providers = {
            event.provider
            for record in run.records
            if isinstance((event := record.event), StepStartedEvent)
        }
        assert providers == {run.started.provider}


def test_copied_context_supports_parallel_steps_in_one_operation(
    tmp_path: Path,
) -> None:
    recorder = TimingRecorder(tmp_path / "timings")
    with recorder.operation(
        TimingOperation.SEARCH,
        provider="all",
        transport=TimingTransport.MIXED,
    ) as operation:
        contexts = [copy_context(), copy_context()]

        def work(provider: str) -> None:
            with timing_step(TimingStep.PROVIDER_SEARCH, provider=provider):
                pass

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(context.run, work, provider)
                for context, provider in zip(contexts, ("ft", "wsj"), strict=True)
            ]
            for future in futures:
                future.result()

    assert operation.path is not None
    run = read_timing_file(operation.path)
    starts = [
        event
        for record in run.records
        if isinstance((event := record.event), StepStartedEvent)
    ]
    assert {event.provider for event in starts} == {"ft", "wsj"}
    assert len({event.step_id for event in starts}) == 2
    assert run.active_steps == ()


def test_write_failure_never_masks_product_result(tmp_path: Path) -> None:
    blocked_root = tmp_path / "not-a-directory"
    blocked_root.write_text("occupied")
    recorder = TimingRecorder(blocked_root)

    with (
        recorder.operation(
            TimingOperation.GET,
            provider="ft",
            transport=TimingTransport.HTTP,
        ) as operation,
        timing_step(TimingStep.FETCH),
    ):
        value = 42

    assert value == 42
    assert operation.write_failed


def test_record_construction_failure_never_masks_product_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import newsclip.timing as timing

    recorder = TimingRecorder(tmp_path / "timings")

    with recorder.operation(
        TimingOperation.GET,
        provider="ft",
        transport=TimingTransport.HTTP,
    ) as operation:
        monkeypatch.setattr(
            timing,
            "TimingRecord",
            lambda **_kwargs: (_ for _ in ()).throw(ValueError("injected")),
        )
        value = 42

    assert value == 42
    assert operation.write_failed


def test_finished_event_construction_failure_never_masks_product_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import newsclip.timing as timing

    recorder = TimingRecorder(tmp_path / "timings")

    with recorder.operation(
        TimingOperation.GET,
        provider="ft",
        transport=TimingTransport.HTTP,
    ) as operation:
        monkeypatch.setattr(
            timing,
            "OperationFinishedEvent",
            lambda **_kwargs: (_ for _ in ()).throw(ValueError("injected")),
        )
        value = 42

    assert value == 42
    assert operation.write_failed


def test_retention_is_bounded_per_operation_and_provider(tmp_path: Path) -> None:
    clock = FakeTime()
    recorder = _recorder(tmp_path / "timings", clock, retention=2)

    for _ in range(3):
        with recorder.operation(
            TimingOperation.GET,
            provider="ft",
            transport=TimingTransport.HTTP,
        ):
            pass

    runs = list(iter_timing_runs(recorder.root))
    assert len(runs) == 2
    assert all(run.started.provider == "ft" for run in runs)


def test_retention_reclaims_unfinished_traces_of_dead_writers_after_a_day(
    tmp_path: Path,
) -> None:
    clock = FakeTime()
    recorder = _recorder(tmp_path / "timings", clock, retention=1)
    directory = recorder.root / "get" / "ft"
    directory.mkdir(parents=True)
    # Sorted before any new trace, so both are beyond the retention cap.
    abandoned = directory / "00000000T000000000000Z-op-abandoned.jsonl"
    interrupted = directory / "00000000T000000000000Z-op-interrupted.jsonl"
    for path in (abandoned, interrupted):
        path.write_text('{"unfinished": true}\n')
    stale = time.time() - 2 * 24 * 3600
    os.utime(abandoned, (stale, stale))

    with recorder.operation(
        TimingOperation.GET,
        provider="ft",
        transport=TimingTransport.HTTP,
    ):
        pass

    # A killed process never finishes its trace; without a live lock holder
    # it is reclaimed after a day, while a recent one still tells its story.
    assert not abandoned.exists()
    assert interrupted.exists()


def test_retention_never_prunes_an_active_operation(tmp_path: Path) -> None:
    clock = FakeTime()
    recorder = _recorder(tmp_path / "timings", clock, retention=1)
    competing = _recorder(tmp_path / "timings", clock, retention=1)
    older = recorder.operation(
        TimingOperation.GET,
        provider="ft",
        transport=TimingTransport.HTTP,
    )

    with older:
        with competing.operation(
            TimingOperation.GET,
            provider="ft",
            transport=TimingTransport.HTTP,
        ) as newer:
            pass
        assert older.path is not None
        assert newer.path is not None
        assert older.path.exists()
        assert read_timing_file(newer.path).finished is not None

    assert read_timing_file(older.path).finished is not None
    with recorder.operation(
        TimingOperation.GET,
        provider="ft",
        transport=TimingTransport.HTTP,
    ):
        pass

    runs = list(iter_timing_runs(recorder.root))
    assert len(runs) == 1
    assert runs[0].finished is not None


def test_invocation_filter_skips_unrelated_future_schema(tmp_path: Path) -> None:
    root = tmp_path / "timings"
    clock = FakeTime()
    selected = _recorder(root, clock, invocation_id="selected-run")
    unrelated = _recorder(root, clock, invocation_id="unrelated-run")

    with selected.operation(
        TimingOperation.GET,
        provider="ft",
        transport=TimingTransport.HTTP,
    ):
        pass
    with (
        unrelated.operation(
            TimingOperation.LOGIN,
            provider="bloomberg",
            transport=TimingTransport.BROWSER,
        ) as future,
        timing_step(TimingStep.IDENTITY_FLOW),
    ):
        pass

    assert future.path is not None
    future.path.write_text(
        future.path.read_text(encoding="utf-8").replace(
            '"step":"identity_flow"',
            '"step":"future_timing_step"',
        ),
        encoding="utf-8",
    )

    runs = tuple(iter_timing_runs(root, invocation_id="selected-run"))

    assert len(runs) == 1
    assert runs[0].invocation_id == "selected-run"
    with pytest.raises(ValidationError):
        tuple(iter_timing_runs(root))


def test_timing_discovery_ignores_non_timing_jsonl_trees(tmp_path: Path) -> None:
    clock = FakeTime()
    recorder = _recorder(tmp_path / "timings", clock)
    with recorder.operation(
        TimingOperation.GET,
        provider="ft",
        transport=TimingTransport.HTTP,
    ):
        pass
    runtime_trace = recorder.root / "browser-traces" / "invocation" / "runtime.jsonl"
    runtime_trace.parent.mkdir(parents=True)
    runtime_trace.write_text('{"event":"browser_started"}\n', encoding="utf-8")

    runs = list(iter_timing_runs(recorder.root))

    assert len(runs) == 1
    assert runs[0].started.operation is TimingOperation.GET


def test_reader_rejects_unknown_evidence(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    valid = {
        "schema_version": 1,
        "operation_id": "op-123",
        "invocation_id": None,
        "sequence": 1,
        "occurred_at": "2026-07-20T00:00:00Z",
        "elapsed_ns": 0,
        "event": {
            "event": "operation_started",
            "operation": "get",
            "provider": "ft",
            "run_mode": "product",
            "transport": "http",
            "app_version": "0.3.2",
            "build_revision": None,
            "build_dirty": None,
            "surface": "none",
            "url": "https://example.invalid/private",
        },
    }
    path.write_text(json.dumps(valid) + "\n")
    with pytest.raises(ValidationError):
        read_timing_file(path)

    with pytest.raises(ValidationError):
        TimingRun(path=path, records=())


def test_reader_rejects_inconsistent_duration(tmp_path: Path) -> None:
    clock = FakeTime()
    recorder = _recorder(tmp_path / "timings", clock)
    with (
        recorder.operation(
            TimingOperation.GET,
            provider="ft",
            transport=TimingTransport.HTTP,
        ) as operation,
        timing_step(TimingStep.FETCH),
    ):
        clock.advance(100)

    assert operation.path is not None
    lines = operation.path.read_text().splitlines()
    record = json.loads(lines[2])
    record["event"]["duration_ns"] = 99
    lines[2] = json.dumps(record)
    operation.path.write_text("\n".join(lines) + "\n")

    with pytest.raises(ValidationError, match="does not match its start"):
        read_timing_file(operation.path)


def test_invalid_environment_invocation_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEWSCLIP_INVOCATION_ID", "private value with spaces")
    recorder = TimingRecorder(tmp_path / "timings")
    with recorder.operation(
        TimingOperation.LOGIN,
        provider="ft",
        transport=TimingTransport.BROWSER,
    ) as operation:
        pass

    assert operation.path is not None
    assert read_timing_file(operation.path).invocation_id is None


def test_contextual_invocation_overrides_process_fallback(tmp_path: Path) -> None:
    recorder = TimingRecorder(tmp_path / "timings", invocation_id="process-default")

    with (
        timing_invocation("mcp-request-1"),
        recorder.operation(
            TimingOperation.GET,
            provider="ft",
            transport=TimingTransport.HTTP,
        ) as operation,
    ):
        pass

    assert operation.path is not None
    assert read_timing_file(operation.path).invocation_id == "mcp-request-1"


def test_current_invocation_uses_context_then_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEWSCLIP_INVOCATION_ID", "process-default")

    assert current_timing_invocation_id() == "process-default"
    with timing_invocation("mcp-request-1"):
        assert current_timing_invocation_id() == "mcp-request-1"


def test_current_invocation_rejects_invalid_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEWSCLIP_INVOCATION_ID", "private value with spaces")

    assert current_timing_invocation_id() is None
