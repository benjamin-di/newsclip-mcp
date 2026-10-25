"""The per-provider defense state machine (ARCHITECTURE, provider containment).

Backing off is the heal: an observed challenge arms a doubling cooldown,
retrieval fails fast while armed, exactly one canary proceeds on expiry, and
only a full-access success clears containment.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Thread

import pytest

from newsclip.defense import (
    BASE_COOLDOWN_SECONDS,
    MAX_COOLDOWN_SECONDS,
    PROBE_LEASE_SECONDS,
    DefenseArm,
    DefenseRecord,
    DefenseState,
)
from newsclip.errors import PersistenceError

START = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = START

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def state(tmp_path: Path, clock: Clock) -> DefenseState:
    return DefenseState(tmp_path / "provider-defense", utc_now=clock)


def test_unarmed_provider_proceeds(state: DefenseState) -> None:
    decision = state.gate("reuters")
    assert decision.allowed is True
    assert decision.canary is False


def test_arm_blocks_with_retry_hint(state: DefenseState, clock: Clock) -> None:
    state.arm("reuters", origin="retrieval")
    decision = state.gate("reuters")
    assert decision.allowed is False
    assert decision.retry_after_seconds == pytest.approx(BASE_COOLDOWN_SECONDS, abs=1)


def _failed_canary(state: DefenseState, clock: Clock) -> DefenseRecord:
    record = state.status("reuters")
    assert record is not None
    clock.now = record.active_until + timedelta(seconds=1)
    assert state.gate("reuters").canary is True
    return state.arm("reuters", origin="retrieval")


def test_cooldown_doubles_per_failed_canary(state: DefenseState, clock: Clock) -> None:
    first = state.arm("reuters", origin="retrieval")
    assert (first.active_until - clock.now).total_seconds() == pytest.approx(
        BASE_COOLDOWN_SECONDS
    )
    second = _failed_canary(state, clock)
    assert (second.active_until - clock.now).total_seconds() == pytest.approx(
        2 * BASE_COOLDOWN_SECONDS
    )
    for _ in range(8):
        record = _failed_canary(state, clock)
    assert (record.active_until - clock.now).total_seconds() == pytest.approx(
        MAX_COOLDOWN_SECONDS
    )


def test_in_flight_challenges_join_the_episode_without_escalating(
    state: DefenseState, clock: Clock
) -> None:
    """Concurrent requests refused in one episode are one observation.

    They were dispatched before the first arm, so the gate never let them
    through a running cooldown; doubling per concurrent refusal took a single
    episode from 20 to 80 minutes before any backoff had been tried.
    """

    first = state.arm_observed("reuters", origin="retrieval")
    clock.advance(30)
    second = state.arm_observed("reuters", origin="http_search")

    assert first.first_of_episode is True
    assert second.first_of_episode is False
    assert second.record == first.record
    stored = state.status("reuters")
    assert stored == first.record
    assert stored.next_cooldown_seconds == 2 * BASE_COOLDOWN_SECONDS
    assert len(stored.arms) == 1


def test_concurrent_challenges_arm_one_base_cooldown(
    state: DefenseState, clock: Clock
) -> None:
    workers = 8
    barrier = Barrier(workers)
    arms: list[DefenseArm] = []

    def observe() -> None:
        barrier.wait(timeout=5)
        arms.append(state.arm_observed("reuters", origin="retrieval"))

    threads = [Thread(target=observe) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert len(arms) == workers
    assert sum(arm.first_of_episode for arm in arms) == 1
    record = state.status("reuters")
    assert record is not None
    assert (record.active_until - clock.now).total_seconds() == pytest.approx(
        BASE_COOLDOWN_SECONDS
    )
    assert record.next_cooldown_seconds == 2 * BASE_COOLDOWN_SECONDS
    assert len(record.arms) == 1


def test_expired_record_rearms_doubled_without_a_canary(
    state: DefenseState, clock: Clock
) -> None:
    state.arm("reuters", origin="retrieval")
    clock.advance(BASE_COOLDOWN_SECONDS + 1)
    # An ungated surface (search) refused after expiry: backing off did not
    # relent the provider, so this is a real re-arm.
    record = state.arm("reuters", origin="http_search")
    assert (record.active_until - clock.now).total_seconds() == pytest.approx(
        2 * BASE_COOLDOWN_SECONDS
    )


def test_canary_outliving_its_lease_still_escalates(
    state: DefenseState, clock: Clock
) -> None:
    state.arm("reuters", origin="retrieval")
    clock.advance(BASE_COOLDOWN_SECONDS + 1)
    assert state.gate("reuters").canary is True
    clock.advance(PROBE_LEASE_SECONDS + 1)
    record = state.arm("reuters", origin="retrieval")
    assert (record.active_until - clock.now).total_seconds() == pytest.approx(
        2 * BASE_COOLDOWN_SECONDS
    )


def test_expiry_grants_exactly_one_canary(state: DefenseState, clock: Clock) -> None:
    state.arm("reuters", origin="retrieval")
    clock.advance(BASE_COOLDOWN_SECONDS + 1)
    first = state.gate("reuters")
    assert first.allowed is True and first.canary is True
    # Competitor sees the backoff reserved before the probe was dispatched.
    second = state.gate("reuters")
    assert second.allowed is False
    assert second.retry_after_seconds is not None
    assert second.retry_after_seconds == 2 * BASE_COOLDOWN_SECONDS


def test_crashed_canary_keeps_reserved_backoff(
    state: DefenseState, clock: Clock
) -> None:
    state.arm("reuters", origin="retrieval")
    clock.advance(BASE_COOLDOWN_SECONDS + 1)
    assert state.gate("reuters").canary is True
    clock.advance(PROBE_LEASE_SECONDS + 1)
    retry = state.gate("reuters")
    assert retry.allowed is False
    clock.advance(2 * BASE_COOLDOWN_SECONDS)
    assert state.gate("reuters").canary is True


def test_failed_canary_rearms_doubled(state: DefenseState, clock: Clock) -> None:
    state.arm("reuters", origin="retrieval")
    clock.advance(BASE_COOLDOWN_SECONDS + 1)
    assert state.gate("reuters").canary is True
    record = state.arm("reuters", origin="guard")
    assert (record.active_until - clock.now).total_seconds() == pytest.approx(
        2 * BASE_COOLDOWN_SECONDS
    )
    assert record.probe_lease_until is None


def test_full_success_clears(state: DefenseState, clock: Clock) -> None:
    state.arm("reuters", origin="retrieval")
    assert state.clear("reuters") is True
    assert state.status("reuters") is None
    assert state.gate("reuters").allowed is True
    # Clearing again is a cheap no-op (no lock taken on the missing file).
    assert state.clear("reuters") is False


def test_repeated_arms_stay_capped_and_keep_rolling_history(
    state: DefenseState, clock: Clock
) -> None:
    record = state.arm("reuters", origin="retrieval")
    for _ in range(13):
        record = _failed_canary(state, clock)

    # Arms older than a rolling day are pruned as each arm writes.
    assert 1 < len(record.arms) < 14
    assert len(record.arms) == record.arms_within_day(clock.now)
    assert (record.active_until - clock.now).total_seconds() == pytest.approx(
        MAX_COOLDOWN_SECONDS
    )
    assert record.next_cooldown_seconds == MAX_COOLDOWN_SECONDS

    clock.now = record.active_until + timedelta(days=1)
    rolled = state.arm("reuters", origin="retrieval")
    assert len(rolled.arms) == 1
    assert rolled.next_cooldown_seconds == MAX_COOLDOWN_SECONDS


def test_stale_unknown_field_is_ignored_without_losing_cooldown(
    state: DefenseState,
) -> None:
    armed = state.arm("reuters", origin="retrieval")
    path = state.root / "reuters.defense.json"
    payload = json.loads(path.read_text())
    payload["exhausted"] = True
    path.write_text(json.dumps(payload))

    loaded = state.status("reuters")

    assert loaded is not None
    assert loaded.active_until == armed.active_until
    assert loaded.next_cooldown_seconds == armed.next_cooldown_seconds
    assert loaded.arms == armed.arms
    assert "exhausted" not in loaded.public_dict()
    decision = state.gate("reuters")
    assert decision.allowed is False
    assert decision.retry_after_seconds == pytest.approx(BASE_COOLDOWN_SECONDS)


def test_records_are_per_provider(state: DefenseState) -> None:
    state.arm("reuters", origin="retrieval")
    assert state.gate("bloomberg").allowed is True


def test_invalid_provider_key_rejected(state: DefenseState) -> None:
    with pytest.raises(PersistenceError):
        state.gate("../escape")


def test_malformed_record_is_a_persistence_error(
    state: DefenseState, tmp_path: Path
) -> None:
    state.root.mkdir(parents=True, exist_ok=True)
    (state.root / "reuters.defense.json").write_text("not json")
    with pytest.raises(PersistenceError):
        state.gate("reuters")


def test_arm_count_is_taken_against_the_readers_clock(
    state: DefenseState, clock: Clock
) -> None:
    """A record written hours ago still carries arms that have since aged out.

    ``arm`` prunes to a rolling day as it writes, so the stored tuple is only
    correct as of the last write. An operator reading it later must see the
    count for *their* now, or a provider that refused four times yesterday and
    once today reads as five and looks worse than it is.
    """

    state.arm("reuters", origin="retrieval")
    clock.advance(3600)
    record = state.arm("reuters", origin="retrieval")

    assert record.arms_within_day(clock.now) == 2
    # A day and a moment later, both arms have aged past the horizon.
    assert record.arms_within_day(clock.now + timedelta(days=1, seconds=1)) == 0
    # Exactly on the horizon the older arm is already out; the newer is not.
    assert record.arms_within_day(clock.now + timedelta(hours=23, minutes=30)) == 1


def test_slow_probe_stays_exclusive_beyond_lease_and_backoff(state, clock, tmp_path):
    state.arm("reuters", origin="retrieval")
    clock.advance(BASE_COOLDOWN_SECONDS + 1)
    other = DefenseState(tmp_path / "provider-defense", utc_now=clock)
    with state.probe("reuters") as first:
        assert first.allowed and first.canary
        clock.advance(4 * BASE_COOLDOWN_SECONDS)
        with other.probe("reuters") as competing:
            assert not competing.allowed
    with other.probe("reuters") as later:
        assert later.allowed and later.canary


def test_failed_probe_does_not_erase_original_exception_or_backoff(state, clock):
    state.arm("reuters", origin="retrieval")
    clock.advance(BASE_COOLDOWN_SECONDS + 1)
    with (
        pytest.raises(TimeoutError, match="inert timeout"),
        state.probe("reuters") as decision,
    ):
        assert decision.allowed
        raise TimeoutError("inert timeout")
    assert not state.gate("reuters").allowed


def test_probe_owner_allows_nested_proof_but_not_copied_thread_context(state, clock):
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context

    state.arm("reuters", origin="retrieval")
    clock.advance(BASE_COOLDOWN_SECONDS + 1)

    def competitor():
        with state.probe("reuters") as decision:
            return decision.allowed

    with state.probe("reuters") as outer:
        assert outer.allowed
        with state.probe("reuters") as proof:
            assert proof.allowed
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert (
                pool.submit(copy_context().run, competitor).result(timeout=3) is False
            )
    assert not state.gate("reuters").allowed
