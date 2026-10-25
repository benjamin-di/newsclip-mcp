#!/usr/bin/env python3
"""Print the bounded deterministic diagnosis from a local diagnostic report."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Sequence
from pathlib import Path

from newsclip.acquisition import MintFailureCategory, MintFailureStage
from newsclip.live_diagnostics import LiveDiagnosis
from newsclip.live_reporting import LiveReport
from newsclip.models import AccessState
from newsclip.timing import TimingOperation, TimingStep

_TRANSPORT_PROBE_COMMAND = (
    "uv run --group transport-lab python bench/transport_probe.py "
    "--url <article-url> --case <case>"
    if (Path(__file__).resolve().parents[1] / "bench/transport_probe.py").is_file()
    else "newsclip doctor"
)
_RETRIEVAL_STEPS = frozenset(
    {
        TimingStep.FETCH,
        TimingStep.EXTRACT,
        TimingStep.ASSESS,
        TimingStep.ARTICLE_NAVIGATION,
        TimingStep.VERIFICATION_NAVIGATION,
        TimingStep.CONTENT_READ,
    }
)
_RETRIEVAL_FAILURES = frozenset(
    {
        MintFailureCategory.ARTICLE_NOT_FULL,
        MintFailureCategory.CHALLENGE_BLOCKED,
        MintFailureCategory.TIMEOUT,
        MintFailureCategory.TRANSPORT_FAILURE,
    }
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Explain one closed newsclip live-report.json"
    )
    parser.add_argument("report", type=Path, help="path to live-report.json")
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="text gives a concise failure story; JSON remains the default",
    )
    return parser


def _text_summary(report: LiveReport) -> str:
    lines = [
        f"{report.invocation_id}: {report.mode.value} {report.outcome.value}",
        "Passed providers: " + (", ".join(report.successful_providers) or "none"),
    ]
    safe_references = [
        ref
        for ref in report.artifacts.references
        if all(
            re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,255}", part) for part in ref.split("/")
        )
    ]
    for provider in report.providers:
        diagnosis = next(
            (d for d in report.provider_diagnoses if d.provider == provider), None
        )
        if provider in report.successful_providers and (
            diagnosis is None or diagnosis.evidence_complete
        ):
            continue
        lines.append(f"\n{provider}:")
        lines.extend(f"  {line}" for line in _failure_story(report, provider))
        if diagnosis is not None:
            lines.append(
                f"  Diagnosis: {diagnosis.diagnosis.diagnosis.value} "
                f"({diagnosis.diagnosis.evidence_strength.value}); "
                f"next: {diagnosis.diagnosis.next_action.value}"
            )
            lines.append(
                "  Required diagnostic contract: "
                + (
                    "satisfied (does not establish the provider's detection trigger)"
                    if diagnosis.evidence_complete
                    else ", ".join(gap.value for gap in diagnosis.missing_evidence)
                )
            )
        for operation in report.operations:
            if operation.provider != provider:
                continue
            mode = (
                operation.acquisition_mode.value
                if operation.acquisition_mode
                else "unknown"
            )
            step = operation.last_step.value if operation.last_step else "unknown"
            lines.append(
                f"  {operation.operation.value}: {operation.outcome}; "
                f"acquisition: {mode}; last step: {step}"
            )
            if operation.browser_first is True:
                lines.append(
                    "    Transport path: browser first (standing rot signal); "
                    "HTTP leg skipped."
                )
            elif operation.browser_fallback_attempted is True:
                lines.append("    Transport path: HTTP -> browser; fallback attempted.")
            else:
                fallback = (
                    "not attempted"
                    if operation.browser_fallback_attempted is False
                    else "unknown (legacy or incomplete evidence)"
                )
                lines.append(f"    Browser fallback: {fallback}.")
            if operation.failure_stage is not None:
                category = operation.failure_category
                lines.append(
                    f"    Failure: {operation.failure_stage.value}; "
                    f"category: {category.value if category is not None else 'unknown'}"
                )
            assessment = operation.content_assessment
            if operation.incident is not None:
                incident = operation.incident
                if incident.incident_id is not None:
                    lines.append(
                        f"    Response evidence: {provider}/incidents/"
                        f"{incident.incident_id}/incident.json"
                    )
                    if incident.response_role != "unknown":
                        lines.append(f"    Response role: {incident.response_role}")
                if incident.omission is not None:
                    lines.append(f"    Response capture omitted: {incident.omission}")
                if incident.capture_failure is not None:
                    failure = incident.capture_failure
                    lines.append(
                        f"    Capture failure: {failure.stage}/{failure.reason}."
                    )
                if (
                    incident.omission is not None
                    or incident.capture_failure is not None
                ) and incident.response_role == "primary":
                    lines.append(
                        "    Retained primary HTTP evidence does not establish "
                        "the terminal browser response."
                    )
            if assessment is not None:
                lines.append(
                    f"    Content: {assessment.access_state.value}; "
                    f"identity match: {assessment.identity_match}"
                )
                if assessment.session_probe is not None:
                    reason = assessment.session_probe.failure_reason
                    lines.append(
                        f"    Paid proof: {assessment.session_probe.outcome.value}"
                        + (f"; reason: {reason}" if reason is not None else "")
                    )
        for attempt in report.attempts:
            if attempt.provider != provider:
                continue
            lines.append(
                f"  {attempt.attempt_id}: {attempt.purpose.value} "
                f"{attempt.outcome.value if attempt.outcome else 'incomplete'}; "
                f"last phase: {attempt.last_phase.value}; "
                f"recorded action dispatches: {attempt.action_count}"
            )
            if attempt.last_action is not None:
                dispatch = (
                    "dispatched or possibly dispatched"
                    if attempt.last_action_dispatched
                    else (
                        "not dispatched"
                        if attempt.last_action_dispatched is False
                        else "unknown"
                    )
                )
                lines.append(
                    f"    Last action: {attempt.last_action.value}; {dispatch}"
                )
            terminal = next(
                (
                    r
                    for r in reversed(report.challenge_resolutions)
                    if r.attempt_id == attempt.attempt_id
                ),
                None,
            )
            if terminal is not None:
                accepted = (
                    str(terminal.acceptance.accepted).lower()
                    if terminal.acceptance is not None
                    else "unobserved"
                )
                lines.append(
                    f"    Challenge: {terminal.detection.vendor.value} "
                    f"{terminal.status.value}; capability: {terminal.capability}; "
                    f"reason: {terminal.reason.value if terminal.reason else 'none'}; "
                    f"acceptance: {accepted}"
                )
            hcaptcha = next(
                (
                    item
                    for item in reversed(report.hcaptcha_attempts)
                    if item.attempt_id == attempt.attempt_id
                ),
                None,
            )
            if hcaptcha is not None:
                lines.append(
                    f"    hCaptcha: {hcaptcha.terminal_reason.value}; "
                    f"acceptance: {hcaptcha.acceptance_source.value}; "
                    f"vendor outcome: {hcaptcha.last_vendor_outcome.value}"
                )
        acquisitions = {
            a.operation_id: a for a in report.acquisitions if a.provider == provider
        }
        if not acquisitions:
            lines.append("  Session publication: unknown / not reached")
        for acquisition in acquisitions.values():
            published = any(
                item.operation_id == acquisition.operation_id
                and item.stage == "published"
                for item in report.acquisitions
            )
            lines.append(
                f"  {acquisition.operation_id}: {acquisition.stage}; "
                f"publication: {'observed' if published else 'unknown / not reached'}; "
                f"evidence complete: {acquisition.evidence_complete}"
                + (
                    f"; reason: {acquisition.retention_reason}"
                    if acquisition.retention_reason
                    else ""
                )
            )
        for artifact in report.diagnostic_artifacts:
            if artifact.provider != provider:
                continue
            if artifact.omission is not None:
                description = "omitted: " + artifact.omission.value
            else:
                references = [
                    ref for ref in safe_references if Path(ref).name == artifact.path
                ]
                acquisition = acquisitions.get(artifact.operation_id)
                description = ", ".join(references) or (
                    "discarded after successful publication"
                    if acquisition is not None
                    and acquisition.stage == "artifacts_discarded"
                    else "reference unavailable"
                )
            lines.append(f"    {artifact.label}: {description}")
        if not any(a.provider == provider for a in report.diagnostic_artifacts):
            lines.extend(
                f"    Retained artifact: {ref}"
                for ref in safe_references
                if ref.startswith(provider + "/") and ref.endswith((".png", ".txt"))
            )
    return "\n".join(lines)


def _failure_story(report: LiveReport, provider: str) -> list[str]:
    """Explain closed observations without turning missing evidence into a cause."""

    failed = [
        attempt
        for attempt in report.attempts
        if attempt.provider == provider and attempt.outcome != "success"
    ]
    if not failed:
        return []
    lines = [
        "State scope: "
        + (
            "isolated cold state; a later cold run uses a different session."
            if report.mode.value == "cold"
            else "operational state reused."
        )
    ]
    for attempt in failed:
        lines.append(
            f"{attempt.purpose.value} failure; profile at browser open: "
            f"{attempt.profile_state} (not authentication proof)."
        )
        lines.append(
            f"Profile scope: {attempt.profile_scope}; paid-session proof is separate."
        )
        if attempt.capture_failure is not None:
            failure = attempt.capture_failure
            lines.append(f"Capture failure: {failure.stage}/{failure.reason}.")
        if "authenticated" in attempt.observation_codes:
            lines.append(
                "Authenticated page observation recorded; paid proof is separate."
            )
        if attempt.last_action_pre_observation_code == "authenticated" and (
            attempt.last_action is not None and attempt.last_action.value == "navigate"
        ):
            lines.append(
                "Article/context navigation was attempted after that observation."
            )
        nav = attempt.last_navigation
        lines.append(
            f"Last navigation response: HTTP {nav.status or 'unknown'}; "
            f"destination relative to request: {nav.destination}; "
            f"elapsed: {nav.elapsed_ms:.0f} ms."
            if nav is not None
            else "Navigation response evidence: unavailable."
        )
        count = attempt.challenge_action_count
        lines.append(
            f"Challenge actions dispatched or possibly dispatched: {count}."
            if count is not None
            else "Challenge action count: unavailable in this report."
        )
        resolutions = [
            item
            for item in report.challenge_resolutions
            if item.attempt_id == attempt.attempt_id
        ]
        if resolutions:
            terminal = resolutions[-1]
            actionable = terminal.actionable_observed
            surface = (
                "observed"
                if actionable is True
                else "not observed (does not establish a hard block)"
                if actionable is False
                else "unknown"
            )
            elapsed = (
                f"{terminal.elapsed_ms:.0f} ms"
                if terminal.elapsed_ms is not None
                else "unavailable"
            )
            lines.append(
                f"{terminal.detection.vendor.value}: {terminal.status.value}; "
                f"actionable control: {surface}; elapsed: {elapsed}."
            )
            if terminal.status.value == "blocked":
                lines.append(
                    "Provider restriction trigger: not established by client evidence."
                )
    lines.append(
        "Source/result comparisons are correlations, "
        "not proof of a code regression or repair."
    )
    return lines


def _transport_probe_guidance(report: LiveReport) -> list[dict[str, object]]:
    """Derive a safe next step without changing or acting on the live report."""

    successful = frozenset(report.successful_providers)
    guidance: list[dict[str, object]] = []
    for provider in report.provider_diagnoses:
        if provider.provider in successful:
            continue
        status, reason = _transport_probe_status(
            report,
            provider.provider,
            diagnosis=provider.diagnosis.diagnosis,
            evidence_complete=provider.evidence_complete,
            repairable=provider.diagnosis.repairable,
        )
        guidance.append(
            {
                "provider": provider.provider,
                "status": status,
                "reason": reason,
                "command": (
                    _TRANSPORT_PROBE_COMMAND
                    if status
                    in {
                        "after_cooldown_or_review",
                        "after_evidence_review",
                    }
                    else None
                ),
            }
        )
    return guidance


def _transport_probe_status(
    report: LiveReport,
    provider: str,
    *,
    diagnosis: LiveDiagnosis,
    evidence_complete: bool,
    repairable: bool,
) -> tuple[str, str]:
    if not _has_failed_retrieval_transport(report, provider):
        return "not_applicable", "no_failed_retrieval_transport"
    if diagnosis is LiveDiagnosis.PROVIDER_DEFENSE:
        return "after_cooldown_or_review", "provider_defense_retrieval"
    if diagnosis is LiveDiagnosis.ACCOUNT_ACTION:
        return "operator_action_first", "account_action"
    if diagnosis is LiveDiagnosis.LOCAL_INFRASTRUCTURE:
        return "repair_environment_first", "local_infrastructure"
    if diagnosis is LiveDiagnosis.PROVIDER_AVAILABILITY:
        return "later_gate_first", "provider_availability"
    if repairable:
        return "use_reproducer", "reproduced_defect"
    if not evidence_complete:
        return "complete_evidence_first", "incomplete_diagnostic_evidence"
    return "after_evidence_review", "unexplained_retrieval_result"


def _has_failed_retrieval_transport(report: LiveReport, provider: str) -> bool:
    for operation in report.operations:
        if (
            operation.provider != provider
            or operation.operation not in {TimingOperation.GET, TimingOperation.SAVE}
            or operation.outcome == "success"
        ):
            continue
        assessment = operation.content_assessment
        if (
            assessment is not None
            and assessment.access_state is AccessState.FULL
            and assessment.identity_match
        ):
            continue
        if (
            operation.assessment_reached
            or operation.last_step in _RETRIEVAL_STEPS
            or operation.failure_stage is MintFailureStage.TRANSPORT
            or operation.failure_category in _RETRIEVAL_FAILURES
        ):
            return True
    return False


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = LiveReport.model_validate_json(args.report.read_bytes())
    except (OSError, ValueError):
        print("error: live report is unavailable or invalid")
        return 2
    if args.format == "text":
        print(_text_summary(report))
        return 0
    payload = {
        "diagnostic_contract_version": report.diagnostic_contract_version,
        "invocation_id": report.invocation_id,
        "outcome": report.outcome,
        "providers": report.providers,
        "successful_providers": report.successful_providers,
        "failure_explanations": {
            provider: _failure_story(report, provider)
            for provider in report.providers
            if provider not in report.successful_providers
        },
        "diagnosis": report.diagnosis.model_dump(mode="json"),
        "provider_diagnoses": [
            item.model_dump(mode="json") for item in report.provider_diagnoses
        ],
        "transport_probe_guidance": _transport_probe_guidance(report),
        "operations": [
            operation.model_dump(mode="json") for operation in report.operations
        ],
        "attempts": [
            {
                "attempt_id": attempt.attempt_id,
                "provider": attempt.provider,
                "purpose": attempt.purpose,
                "outcome": attempt.outcome,
                "last_phase": attempt.last_phase,
                "observation_codes": attempt.observation_codes,
                "terminal_observation_code": attempt.terminal_observation_code,
                "action_count": attempt.action_count,
                "profile_state": attempt.profile_state,
                "profile_scope": attempt.profile_scope,
                "capture_failure": (
                    attempt.capture_failure.model_dump(mode="json")
                    if attempt.capture_failure is not None
                    else None
                ),
                "challenge_action_count": attempt.challenge_action_count,
                "last_navigation": (
                    attempt.last_navigation.model_dump(mode="json")
                    if attempt.last_navigation
                    else None
                ),
                "last_action": attempt.last_action,
                "last_action_pre_observation_code": (
                    attempt.last_action_pre_observation_code
                ),
                "last_action_dispatched": attempt.last_action_dispatched,
                "last_action_result": attempt.last_action_result,
            }
            for attempt in report.attempts
        ],
        "diagnostic_health": {
            "event_write_failures": report.runtime.event_write_failures,
            "screenshot_capture_failures": (report.runtime.screenshot_capture_failures),
            "screenshot_write_failures": report.runtime.screenshot_write_failures,
            "unattributed_event_write_failures": (
                report.runtime.unattributed_event_write_failures
            ),
            "unattributed_screenshot_capture_failures": (
                report.runtime.unattributed_screenshot_capture_failures
            ),
            "unattributed_screenshot_write_failures": (
                report.runtime.unattributed_screenshot_write_failures
            ),
            "providers": [
                {
                    "provider": item.provider,
                    "event_write_failures": item.event_write_failures,
                    "screenshot_capture_failures": (item.screenshot_capture_failures),
                    "screenshot_write_failures": item.screenshot_write_failures,
                }
                for item in report.runtime_by_provider
                if any(
                    (
                        item.event_write_failures,
                        item.screenshot_capture_failures,
                        item.screenshot_write_failures,
                    )
                )
            ],
        },
        "hcaptcha_attempts": [
            terminal.model_dump(mode="json", exclude={"event"})
            for terminal in report.hcaptcha_attempts
        ],
        "hcaptcha_rounds": [
            round_event.model_dump(mode="json", exclude={"event"})
            for round_event in report.hcaptcha_rounds
        ],
        "hcaptcha_checkpoints": [
            checkpoint.model_dump(mode="json", exclude={"event"})
            for checkpoint in report.hcaptcha_checkpoints
        ],
        "acquisitions": [
            acquisition.model_dump(mode="json", exclude={"event"})
            for acquisition in report.acquisitions
        ],
        "diagnostic_artifacts": [
            artifact.model_dump(mode="json", exclude={"event"})
            for artifact in report.diagnostic_artifacts
        ],
        "challenge_resolutions": [
            resolution.model_dump(mode="json", exclude={"event"})
            for resolution in report.challenge_resolutions
        ],
        "artifacts": report.artifacts.model_dump(mode="json"),
        "http_attempts": [
            attempt.model_dump(mode="json", exclude={"event"})
            for attempt in report.http_attempts
        ],
        "identity_handoffs": [
            handoff.model_dump(mode="json", exclude={"event"})
            for handoff in report.identity_handoffs
        ],
        "perimeterx_holds": [
            hold.model_dump(mode="json", exclude={"event"})
            for hold in report.perimeterx_holds
        ],
        "comparisons": [
            {
                "provider": comparison.provider,
                "operation": comparison.operation,
                "same_source": comparison.same_source,
                "changed_paths": comparison.changed_paths,
                "stable_observation_changed": (comparison.stable_observation_changed),
                "http_changed": comparison.http_changed,
                "prior_http": (
                    comparison.prior_http.model_dump(mode="json")
                    if comparison.prior_http is not None
                    else None
                ),
                "current_http": (
                    comparison.current_http.model_dump(mode="json")
                    if comparison.current_http is not None
                    else None
                ),
                "content_assessment_changed": (comparison.content_assessment_changed),
                "prior_content_assessment": (
                    comparison.prior_content_assessment.model_dump(mode="json")
                    if comparison.prior_content_assessment is not None
                    else None
                ),
                "current_content_assessment": (
                    comparison.current_content_assessment.model_dump(mode="json")
                    if comparison.current_content_assessment is not None
                    else None
                ),
            }
            for comparison in report.comparisons
        ],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main
    raise SystemExit(main())
