"""One-shot provider challenge transport escalation."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from newsclip.challenge_transport import ChallengeAwareHttpClient
from newsclip.errors import ProviderDefenseError
from newsclip.models import RawFetch, SessionArtifact

NOW = datetime(2026, 7, 24, tzinfo=UTC)
URL = "https://example.test/article"


def _fetch(body: bytes) -> RawFetch:
    return RawFetch(
        requested_url=URL,
        final_url=URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        raw_html=body,
    )


class RecordingClient:
    def __init__(self, result: RawFetch) -> None:
        self.result = result
        self.calls: list[tuple[str, SessionArtifact | None, float]] = []

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.calls.append((url, session, timeout))
        return self.result


def test_ordinary_response_never_opens_browser_fallback() -> None:
    primary = RecordingClient(_fetch(b"article"))
    fallback = RecordingClient(_fetch(b"browser article"))
    client = ChallengeAwareHttpClient(
        "fixture",
        primary,
        is_challenge=lambda fetch: b"challenge" in fetch.raw_html,
        browser_fallback=fallback,
    )

    result = client.get(URL, timeout=17)

    assert result.raw_html == b"article"
    assert primary.calls == [(URL, None, 17)]
    assert fallback.calls == []


def test_challenge_uses_exactly_one_browser_get_without_reclassification() -> None:
    primary = RecordingClient(_fetch(b"challenge"))
    fallback = RecordingClient(_fetch(b"challenge still present"))
    classifications: list[bytes] = []

    def classify(fetch: RawFetch) -> bool:
        classifications.append(fetch.raw_html)
        return b"challenge" in fetch.raw_html

    client = ChallengeAwareHttpClient(
        "fixture",
        primary,
        is_challenge=classify,
        browser_fallback=fallback,
    )

    result = client.get(URL, timeout=23)

    assert result.raw_html == b"challenge still present"
    assert primary.calls == [(URL, None, 23)]
    assert fallback.calls == [(URL, None, 23)]
    assert classifications == [b"challenge"]


def test_challenge_without_promoted_fallback_requires_operator_action() -> None:
    primary = RecordingClient(_fetch(b"challenge"))
    client = ChallengeAwareHttpClient(
        "fixture",
        primary,
        is_challenge=lambda _fetch: True,
        browser_fallback=None,
    )

    with pytest.raises(
        ProviderDefenseError,
        match="fixture returned an unsupported interactive challenge",
    ) as captured:
        client.get(URL)

    assert len(primary.calls) == 1
    assert captured.value.provider == "fixture"
    assert captured.value.reason_code == "challenge_challenge_blocked"
    assert captured.value.fetch is primary.result


def test_escalation_served_hands_over_the_refused_primary_fetch() -> None:
    primary = RecordingClient(_fetch(b"challenge"))
    fallback = RecordingClient(_fetch(b"browser article"))
    served: list[bytes] = []
    client = ChallengeAwareHttpClient(
        "fixture",
        primary,
        is_challenge=lambda fetch: b"challenge" in fetch.raw_html,
        browser_fallback=fallback,
        on_escalation_served=lambda fetch: served.append(fetch.raw_html),
    )

    result = client.get(URL)

    assert result.raw_html == b"browser article"
    # The refused primary fetch is the rot evidence, not the browser answer.
    assert served == [b"challenge"]


def test_escalation_served_stays_silent_when_browser_is_challenged_too() -> None:
    primary = RecordingClient(_fetch(b"challenge"))
    fallback = RecordingClient(_fetch(b"challenge still present"))
    served: list[bytes] = []
    client = ChallengeAwareHttpClient(
        "fixture",
        primary,
        is_challenge=lambda fetch: b"challenge" in fetch.raw_html,
        browser_fallback=fallback,
        on_escalation_served=lambda fetch: served.append(fetch.raw_html),
    )

    result = client.get(URL)

    assert result.raw_html == b"challenge still present"
    assert served == []


def test_escalation_served_stays_silent_without_a_challenge() -> None:
    primary = RecordingClient(_fetch(b"article"))
    fallback = RecordingClient(_fetch(b"browser article"))
    served: list[bytes] = []
    client = ChallengeAwareHttpClient(
        "fixture",
        primary,
        is_challenge=lambda fetch: b"challenge" in fetch.raw_html,
        browser_fallback=fallback,
        on_escalation_served=lambda fetch: served.append(fetch.raw_html),
    )

    client.get(URL)

    assert served == []


def test_fallback_diagnostic_fault_preserves_single_dispatch(monkeypatch) -> None:
    primary = RecordingClient(_fetch(b"challenge"))
    fallback = RecordingClient(_fetch(b"browser article"))

    def unavailable():
        raise OSError("fixture diagnostic failure")

    monkeypatch.setattr(
        "newsclip.challenge_transport.record_timing_browser_fallback", unavailable
    )
    client = ChallengeAwareHttpClient(
        "fixture",
        primary,
        is_challenge=lambda fetch: b"challenge" in fetch.raw_html,
        browser_fallback=fallback,
    )
    assert client.get(URL, timeout=23) is fallback.result
    assert primary.calls == [(URL, None, 23)]
    assert fallback.calls == [(URL, None, 23)]


class FailingClient:
    def __init__(self) -> None:
        self.calls = 0

    def get(self, url: str, **kwargs) -> RawFetch:
        self.calls += 1
        raise ProviderDefenseError("fixture browser refusal", provider="fixture")


@pytest.mark.parametrize(
    ("fallback", "retained"),
    [
        (None, True),
        (RecordingClient(_fetch(b"browser article")), False),
        (RecordingClient(_fetch(b"challenge still present")), True),
        (FailingClient(), True),
    ],
    ids=["no-fallback", "recovered", "challenged-again", "fallback-raised"],
)
def test_challenge_evidence_is_retained_only_when_unrecovered(
    fallback, retained
) -> None:
    primary = RecordingClient(_fetch(b"challenge"))
    observed: list[bytes] = []
    client = ChallengeAwareHttpClient(
        "fixture",
        primary,
        is_challenge=lambda fetch: b"challenge" in fetch.raw_html,
        browser_fallback=fallback,
        on_challenge_observed=lambda fetch: observed.append(fetch.raw_html),
    )

    if fallback is None or isinstance(fallback, FailingClient):
        with pytest.raises(ProviderDefenseError):
            client.get(URL)
    else:
        client.get(URL)

    # Routine recovered challenges must not consume the bounded incident store.
    assert observed == ([b"challenge"] if retained else [])


def test_unclassifiable_browser_answer_keeps_primary_evidence() -> None:
    primary = RecordingClient(_fetch(b"challenge"))
    fallback = RecordingClient(_fetch(b"browser answer"))
    observed: list[bytes] = []

    def classify(fetch: RawFetch) -> bool:
        if fetch.raw_html == b"browser answer":
            raise ValueError("fixture classifier failure")
        return True

    client = ChallengeAwareHttpClient(
        "fixture",
        primary,
        is_challenge=classify,
        browser_fallback=fallback,
        on_challenge_observed=lambda fetch: observed.append(fetch.raw_html),
    )

    assert client.get(URL).raw_html == b"browser answer"
    assert observed == [b"challenge"]


def test_browser_first_skips_the_refused_primary() -> None:
    primary = RecordingClient(_fetch(b"challenge"))
    fallback = RecordingClient(_fetch(b"browser article"))
    served: list[bytes] = []
    client = ChallengeAwareHttpClient(
        "fixture",
        primary,
        is_challenge=lambda fetch: b"challenge" in fetch.raw_html,
        browser_fallback=fallback,
        on_escalation_served=lambda fetch: served.append(fetch.raw_html),
        browser_first=lambda: True,
    )

    result = client.get(URL, timeout=19)

    assert result.raw_html == b"browser article"
    assert primary.calls == []
    assert fallback.calls == [(URL, None, 19)]
    assert served == []


def test_browser_first_is_recorded_apart_from_a_fallback(tmp_path) -> None:
    """The live gate must tell a skipped HTTP leg from a lost HTTP trace."""

    from newsclip.timing import (
        TimingOperation,
        TimingRecorder,
        TimingRunMode,
        TimingTransport,
        iter_timing_runs,
    )

    recorder = TimingRecorder(
        tmp_path / "timings", invocation_id="fixture", run_mode=TimingRunMode.WARM
    )
    for browser_first in (True, False):
        client = ChallengeAwareHttpClient(
            "fixture",
            RecordingClient(_fetch(b"challenge")),
            is_challenge=lambda fetch: b"challenge" in fetch.raw_html,
            browser_fallback=RecordingClient(_fetch(b"browser article")),
            browser_first=lambda value=browser_first: value,
        )
        with recorder.operation(
            TimingOperation.SAVE, provider="fixture", transport=TimingTransport.HTTP
        ):
            client.get(URL)

    observed = {
        (run.finished.browser_first, run.finished.browser_fallback_attempted)
        for run in iter_timing_runs(recorder.root)
        if run.finished is not None
    }
    assert observed == {(True, True), (None, True)}


@pytest.mark.parametrize("signal", [lambda: False, lambda: 1 / 0])
def test_browser_first_keeps_declared_order_when_off_or_unreadable(signal) -> None:
    primary = RecordingClient(_fetch(b"article"))
    fallback = RecordingClient(_fetch(b"browser article"))
    client = ChallengeAwareHttpClient(
        "fixture",
        primary,
        is_challenge=lambda fetch: b"challenge" in fetch.raw_html,
        browser_fallback=fallback,
        browser_first=signal,
    )

    assert client.get(URL).raw_html == b"article"
    assert fallback.calls == []


def test_browser_first_without_a_fallback_still_uses_the_primary() -> None:
    primary = RecordingClient(_fetch(b"article"))
    client = ChallengeAwareHttpClient(
        "fixture",
        primary,
        is_challenge=lambda fetch: b"challenge" in fetch.raw_html,
        browser_fallback=None,
        browser_first=lambda: True,
    )

    assert client.get(URL).raw_html == b"article"
    assert len(primary.calls) == 1
