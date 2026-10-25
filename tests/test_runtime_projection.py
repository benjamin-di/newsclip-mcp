"""Projection contracts independent of files, browser execution, and services."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest

import newsclip.runtime_projection as projection
from newsclip.browser_runtime.events import (
    AttemptFinishedEvent,
    AttemptStartedEvent,
    AuthObservationEvent,
    ChallengeResolutionEvent,
    DiagnosticHealthEvent,
    RuntimeEvent,
    RuntimeRecord,
    RuntimeRun,
    SemanticActionFinishedEvent,
    SemanticActionStartedEvent,
)
from newsclip.runtime_projection import RuntimeTraceEvidence, project_runtime_evidence


def _run(*events: RuntimeEvent) -> RuntimeRun:
    return RuntimeRun(
        path=Path("never-opened.jsonl"),
        records=tuple(
            RuntimeRecord(
                run_id="projection-test",
                sequence=index,
                occurred_at=datetime(2026, 9, 8, tzinfo=UTC),
                event=event,
            )
            for index, event in enumerate(events, start=1)
        ),
    )


@pytest.mark.parametrize(
    ("fixture", "outcome", "actions", "observations", "resolutions"),
    [
        ("restricted", "error", 5, 6, 7),
        ("callback_clear", "success", 5, 7, 7),
        ("article_clear", "success", 6, 6, 6),
        ("search_restricted", "error", 0, 0, 1),
    ],
)
def test_retained_records_project_without_file_access(
    monkeypatch, fixture, outcome, actions, observations, resolutions
):
    # Invented event sequences preserve projection regressions without shipping
    # operational ledgers. No timestamps, measurements or ids come from a run.
    attempt_id = "attempt-" + "0" * 32
    events = [
        AttemptStartedEvent(
            attempt_id=attempt_id,
            provider="wsj",
            purpose="search" if fixture == "search_restricted" else "login",
        )
    ]
    for index in range(actions):
        events.extend(
            [
                SemanticActionStartedEvent(
                    attempt_id=attempt_id,
                    action_id=index + 1,
                    action="navigate",
                    sequence=index + 1,
                    pre_observation_code="unknown",
                ),
                SemanticActionFinishedEvent(
                    attempt_id=attempt_id,
                    action_id=index + 1,
                    dispatched=True,
                    result="unknown",
                ),
            ]
        )
    for _ in range(observations):
        events.append(
            AuthObservationEvent(
                attempt_id=attempt_id,
                provider="wsj",
                phase="verification",
                observation_id="authenticated",
                state_code="authenticated",
                evidence_families=("selector",),
                route_class="known_idp",
            )
        )
    for _ in range(resolutions):
        events.append(
            ChallengeResolutionEvent(
                attempt_id=attempt_id,
                provider="wsj",
                capability="interactive_mechanic",
                mode="auto",
                status="non_interactive",
                detection={"state": "asset_only", "vendor": "datadome"},
            )
        )
    events.append(
        AttemptFinishedEvent(
            attempt_id=attempt_id,
            provider="wsj",
            outcome=outcome,
            last_phase="verification",
        )
    )
    run = _run(*events)

    def forbidden(*args, **kwargs):
        pytest.fail("projection performed file I/O")

    with monkeypatch.context() as patch:
        patch.setattr("builtins.open", forbidden)
        patch.setattr(Path, "open", forbidden)
        patch.setattr(Path, "rglob", forbidden)
        result = project_runtime_evidence([RuntimeTraceEvidence("wsj", run)])

    assert len(result.attempts) == 1
    attempt = result.attempts[0]
    assert attempt.outcome == outcome
    assert attempt.action_count == actions
    assert attempt.challenge_action_count == 0
    assert attempt.terminal_observation_code == (
        "authenticated" if observations else None
    )
    expected_counts = {
        "attempt_started": 1,
        "attempt_finished": 1,
        "challenge_resolution": resolutions,
    }
    if observations:
        expected_counts["auth_observation"] = observations
    if actions:
        expected_counts["semantic_action_started"] = actions
        expected_counts["semantic_action_finished"] = actions
    assert result.runtime.event_counts == expected_counts
    assert result.runtime_by_provider[0].provider == "wsj"
    assert result.runtime_by_provider[0].event_counts == expected_counts
    assert len(result.challenge_resolutions) == resolutions


def test_in_memory_projection_keeps_interruption_and_loss_attribution():
    attempt_id = "attempt-" + "a" * 32
    result = project_runtime_evidence(
        [
            RuntimeTraceEvidence(
                "ft",
                _run(
                    AttemptStartedEvent(
                        attempt_id=attempt_id, provider="ft", purpose="login"
                    ),
                    SemanticActionStartedEvent(
                        attempt_id=attempt_id,
                        action_id=1,
                        action="navigate",
                        sequence=1,
                        pre_observation_code="unknown",
                    ),
                    DiagnosticHealthEvent(screenshot_write_failures=2),
                ),
            ),
            RuntimeTraceEvidence("wsj", None),
            RuntimeTraceEvidence(None, None),
            RuntimeTraceEvidence(
                None, _run(DiagnosticHealthEvent(event_write_failures=1))
            ),
        ]
    )
    attempt = result.attempts[0]
    assert attempt.outcome == "incomplete"
    assert attempt.action_count == 0
    assert attempt.last_action_dispatched == "not_observed"
    assert attempt.last_action_result == "not_observed"
    assert result.runtime.event_counts == {
        "attempt_started": 1,
        "semantic_action_started": 1,
        "diagnostic_health": 2,
        "invalid_trace": 2,
    }
    assert result.runtime.unattributed_invalid_traces == 1
    assert result.runtime.unattributed_event_write_failures == 1
    assert result.runtime.screenshot_write_failures == 2
    assert result.runtime.unattributed_screenshot_write_failures == 0
    ft, wsj = result.runtime_by_provider
    assert ft.provider == "ft"
    assert ft.screenshot_write_failures == 2
    assert "invalid_trace" not in ft.event_counts
    assert wsj.provider == "wsj"
    assert wsj.event_counts == {"invalid_trace": 1}
    # Each call owns its state; a prior failure cannot taint a new snapshot.
    empty = project_runtime_evidence([])
    assert empty.attempts == empty.runtime_by_provider == ()
    assert empty.runtime.event_counts == {}


def test_projection_depends_only_on_models_and_in_memory_utilities():
    tree = ast.parse(Path(projection.__file__).read_text())
    allowed = {
        "__future__",
        "re",
        "collections",
        "collections.abc",
        "dataclasses",
        "typing",
        "pydantic",
        "browser_runtime.events",
        "models",
        "provider_keys",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name in allowed for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module in allowed
            if node.module == "browser_runtime.events":
                # This module also houses persistence; import only its contracts.
                assert not {"RuntimeTrace", "read_runtime_file"}.intersection(
                    alias.name for alias in node.names
                )
                assert all(
                    isinstance(getattr(projection, alias.asname or alias.name), type)
                    or alias.name == "RuntimeEvent"
                    for alias in node.names
                )


def test_existing_report_imports_remain_the_same_contracts():
    import newsclip.live_reporting as reporting

    for name in ("LiveAttemptEvidence", "RuntimeEvidence", "RuntimeProviderEvidence"):
        assert getattr(reporting, name) is getattr(projection, name)
