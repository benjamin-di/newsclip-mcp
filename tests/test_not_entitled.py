"""A teaser behind a verified session is ``not_entitled``, not a session fault.

Also covers bounded in-process reuse of a verified probe, which lets a repeated
teaser skip the browser relaunch the probe would otherwise cost.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from test_session_verification import (
    ARTICLE_URL,
    PROBE_URL,
    FakeExtractor,
    FakeStore,
    FixtureProvider,
    ScriptedHttp,
    _service,
)

from newsclip.archive import ArchiveStore
from newsclip.cli import _human_error_hint
from newsclip.errors import (
    NOT_ENTITLED_REASON,
    ContentNotFullError,
    SessionRequiredError,
)
from newsclip.providers import ProviderRegistry
from newsclip.recovery import RecoveryStore
from newsclip.results import (
    PublicErrorAction,
    PublicErrorCategory,
    PublicErrorReason,
    public_error,
)
from newsclip.service import NewsclipService
from newsclip.session_keeper import _failure_reason
from newsclip.session_proofs import SessionProofMemory
from newsclip.timing import SessionProbeOutcome, TimingRecorder, iter_timing_runs

TEASER = b"paywall body"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _get_failure(service, url: str = ARTICLE_URL) -> ContentNotFullError:
    with pytest.raises(ContentNotFullError) as caught:
        service.get(url)
    return caught.value


def test_teaser_behind_verified_session_is_not_entitled() -> None:
    http = ScriptedHttp({ARTICLE_URL: TEASER, PROBE_URL: b"FULL body"})
    store = FakeStore()

    failure = _get_failure(_service(http, store))

    assert str(failure) == NOT_ENTITLED_REASON
    assert failure.recovery_eligible is False
    assert store.downgrades == 0
    envelope = public_error(failure)
    assert envelope is not None
    assert envelope.category is PublicErrorCategory.CONTENT_NOT_FULL
    assert envelope.reason is PublicErrorReason.NOT_ENTITLED
    assert envelope.action is PublicErrorAction.NONE
    assert envelope.retryable is False
    hint = _human_error_hint(PublicErrorCategory.CONTENT_NOT_FULL, error=failure)
    assert "outside the subscription" in hint
    assert "do not renew" in hint


def test_teaser_with_teaser_probe_stays_paywall_teaser_and_may_recover() -> None:
    http = ScriptedHttp({ARTICLE_URL: TEASER, PROBE_URL: TEASER})

    failure = _get_failure(_service(http, FakeStore()))

    assert str(failure) == "paywall_teaser"
    assert failure.recovery_eligible is True


def test_teaser_with_inconclusive_probe_stays_paywall_teaser() -> None:
    http = ScriptedHttp({ARTICLE_URL: TEASER, PROBE_URL: b"opaque page"})

    failure = _get_failure(_service(http, FakeStore()))

    assert str(failure) == "paywall_teaser"
    assert failure.recovery_eligible is False


def test_non_teaser_failure_behind_verified_session_keeps_its_reason() -> None:
    http = ScriptedHttp({ARTICLE_URL: b"opaque page", PROBE_URL: b"FULL body"})

    failure = _get_failure(_service(http, FakeStore()))

    assert str(failure) == "opaque_fixture"


def test_not_entitled_save_is_classified_like_get(tmp_path: Path) -> None:
    registry = ProviderRegistry((FixtureProvider(),))
    extractor = FakeExtractor()
    http = ScriptedHttp({ARTICLE_URL: TEASER, PROBE_URL: b"FULL body"})
    service = NewsclipService(
        registry,
        http,
        extractor,
        sessions=FakeStore(),
        archive=ArchiveStore(
            tmp_path / "archive.sqlite3", registry=registry, extractor=extractor
        ),
        network_sleep=lambda _seconds: None,
    )

    with pytest.raises(ContentNotFullError, match=NOT_ENTITLED_REASON):
        service.save(ARTICLE_URL)


def test_not_entitled_requests_no_recovery(tmp_path: Path) -> None:
    def attempt(probe_body: bytes, root: Path) -> tuple[str, RecoveryStore]:
        recovery = RecoveryStore(root)
        service = NewsclipService(
            ProviderRegistry((FixtureProvider(),)),
            ScriptedHttp({ARTICLE_URL: TEASER, PROBE_URL: probe_body}),
            FakeExtractor(),
            sessions=FakeStore(),
            recovery_store=recovery,
            network_sleep=lambda _seconds: None,
        )
        return str(_get_failure(service)), recovery

    reason, recovery = attempt(b"FULL body", tmp_path / "entitled")
    assert reason == NOT_ENTITLED_REASON
    assert recovery.load("fixture") is None
    # Contrast: the same teaser behind an unproven session does hand off.
    reason, recovery = attempt(TEASER, tmp_path / "unproven")
    assert reason == "paywall_teaser"
    assert recovery.load("fixture") is not None


def test_keeper_settles_not_entitled_instead_of_retrying_content() -> None:
    assert _failure_reason(ContentNotFullError(NOT_ENTITLED_REASON)) == (
        NOT_ENTITLED_REASON
    )
    assert _failure_reason(ContentNotFullError("paywall_teaser")) == (
        "content_not_full"
    )


def test_repeated_teaser_reuses_recent_verified_probe(tmp_path: Path) -> None:
    http = ScriptedHttp({ARTICLE_URL: TEASER, PROBE_URL: b"FULL body"})
    recorder = TimingRecorder(tmp_path / "timings")
    service = _service(http, FakeStore(), timing=recorder)

    first = _get_failure(service)
    second = _get_failure(service)

    assert str(first) == str(second) == NOT_ENTITLED_REASON
    assert http.calls == [ARTICLE_URL, PROBE_URL, ARTICLE_URL]
    outcomes = []
    for run in iter_timing_runs(recorder.root):
        assert run.finished is not None
        content = run.finished.content_assessment
        assert content is not None and content.session_probe is not None
        outcomes.append(content.session_probe.outcome)
    assert sorted(outcomes) == sorted(
        [SessionProbeOutcome.VERIFIED, SessionProbeOutcome.REUSED_VERIFIED]
    )


def test_reuse_expires_and_probes_again() -> None:
    http = ScriptedHttp({ARTICLE_URL: TEASER, PROBE_URL: b"FULL body"})
    service = _service(http, FakeStore())
    clock = Clock()
    service._session_proofs = SessionProofMemory(clock=clock)

    _get_failure(service)
    clock.now += 601
    _get_failure(service)

    assert http.calls.count(PROBE_URL) == 2


def test_new_session_generation_does_not_inherit_a_proof() -> None:
    http = ScriptedHttp({ARTICLE_URL: TEASER, PROBE_URL: b"FULL body"})
    store = FakeStore()
    service = _service(http, store)

    _get_failure(service)
    assert store.artifact is not None
    store.artifact = store.artifact.model_copy(update={"generation_id": uuid4()})
    _get_failure(service)

    assert http.calls.count(PROBE_URL) == 2


def test_non_teaser_failure_still_probes_despite_recent_proof() -> None:
    bodies = {ARTICLE_URL: TEASER, PROBE_URL: b"FULL body"}
    http = ScriptedHttp(bodies)
    store = FakeStore()
    service = _service(http, store)

    _get_failure(service)
    bodies[ARTICLE_URL] = b"teaser body"  # an authentication wall
    bodies[PROBE_URL] = b"auth wall"

    with pytest.raises(SessionRequiredError):
        service.get(ARTICLE_URL)

    assert http.calls.count(PROBE_URL) == 2
    assert store.downgrades == 1


def test_reused_proof_without_session_is_never_applied() -> None:
    memory = SessionProofMemory()
    memory.record("fixture", None)

    assert memory.recent("fixture", None) is False


def test_proof_memory_is_bounded_and_keyed_by_provider_and_generation() -> None:
    store = FakeStore()
    artifact = store.artifact
    assert artifact is not None
    clock = Clock()
    memory = SessionProofMemory(capacity=2, clock=clock)
    other = artifact.model_copy(update={"generation_id": uuid4()})
    third = artifact.model_copy(update={"generation_id": uuid4()})

    memory.record("fixture", artifact)
    assert memory.recent("fixture", artifact)
    assert not memory.recent("fixture", other)
    assert not memory.recent("wsj", artifact)
    memory.record("fixture", other)
    memory.record("fixture", third)
    assert not memory.recent("fixture", artifact)
    assert memory.recent("fixture", other) and memory.recent("fixture", third)
    memory.forget("fixture")
    assert not memory.recent("fixture", other)
    memory.record("fixture", artifact)
    clock.now -= 1  # a clock that runs backwards never extends a proof
    assert not memory.recent("fixture", artifact)


def test_dead_probe_forgets_the_provider_proof() -> None:
    bodies = {ARTICLE_URL: TEASER, PROBE_URL: b"FULL body"}
    http = ScriptedHttp(bodies)
    store = FakeStore()
    service = _service(http, store)
    _get_failure(service)
    artifact = store.artifact
    assert service._session_proofs.recent("fixture", artifact)

    bodies[ARTICLE_URL] = b"teaser body"
    bodies[PROBE_URL] = b"auth wall"
    with pytest.raises(SessionRequiredError):
        service.get(ARTICLE_URL)

    assert not service._session_proofs.recent("fixture", artifact)
