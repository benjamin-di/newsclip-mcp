"""Runtime transport-pin state: the rot signal and its safety boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from newsclip.transport_pins import (
    TransportPinError,
    TransportPinState,
    TransportPinStore,
)

NOW = datetime(2026, 8, 2, tzinfo=UTC)


def _store(tmp_path: Path) -> TransportPinStore:
    return TransportPinStore(tmp_path / "transport-pins", utc_now=lambda: NOW)


def test_rot_signal_round_trips(tmp_path: Path) -> None:
    store = _store(tmp_path)

    recorded = store.record_rot("reuters", profile="safari2601")

    assert recorded.rot_observed_at == NOW
    assert recorded.rot_profile == "safari2601"
    loaded = store.load("reuters")
    assert loaded == recorded
    assert oct((store.root / "reuters.json").stat().st_mode & 0o777) == "0o600"


def test_absent_state_reads_as_none(tmp_path: Path) -> None:
    assert _store(tmp_path).load("reuters") is None


def test_corrupt_state_raises_on_load_but_never_suppresses_rot(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    store.root.mkdir(mode=0o700, parents=True)
    (store.root / "reuters.json").write_bytes(b"not-json")

    with pytest.raises(TransportPinError):
        store.load("reuters")

    recorded = store.record_rot("reuters", profile="safari2601")
    assert recorded.rot_profile == "safari2601"
    assert store.load("reuters") == recorded


def test_rot_of_the_active_pin_stops_it_governing(tmp_path: Path) -> None:
    store = _store(tmp_path)
    seeded = TransportPinState(
        provider="reuters",
        active_profile="chrome146",
        pinned_at=NOW,
    )
    with store._locked("reuters"):
        store._write_locked("reuters", seeded)

    rotted = store.record_rot("reuters", profile="chrome146")

    assert rotted.active_profile is None
    assert rotted.pinned_at is None
    assert rotted.rot_profile == "chrome146"


def test_rot_of_another_profile_leaves_the_active_pin(tmp_path: Path) -> None:
    store = _store(tmp_path)
    seeded = TransportPinState(
        provider="reuters",
        active_profile="safari2601",
        pinned_at=NOW,
    )
    with store._locked("reuters"):
        store._write_locked("reuters", seeded)

    rotted = store.record_rot("reuters", profile="chrome146")

    assert rotted.active_profile == "safari2601"
    assert rotted.pinned_at == NOW


def test_provider_key_is_validated(tmp_path: Path) -> None:
    with pytest.raises(TransportPinError):
        _store(tmp_path).load("../escape")


def test_promotion_enforces_the_allowlist_and_observed_passes(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)

    promoted = store.promote("reuters", profile="chrome146", passes=3)
    assert promoted.active_profile == "chrome146"
    assert promoted.passes_observed == 3
    assert promoted.pinned_at == NOW

    with pytest.raises(TransportPinError):
        store.promote("reuters", profile="firefox147", passes=3)
    with pytest.raises(TransportPinError):
        store.promote("reuters", profile="chrome146", passes=0)
    # The refused promotions changed nothing.
    assert store.load("reuters") == promoted


def test_resolver_sees_a_promotion_without_being_rebuilt(tmp_path: Path) -> None:
    """The R8 gate: a pin promoted elsewhere governs the next fetch here."""

    from newsclip.transport_pins import TransportPinResolver

    store = _store(tmp_path)
    resolver = TransportPinResolver(
        store,
        providers_by_host={"www.reuters.com": "reuters"},
    )

    assert resolver.for_host("www.reuters.com") is None

    # A different process (the keeper) promotes over the shared mount.
    TransportPinStore(store.root, utc_now=lambda: NOW).promote(
        "reuters", profile="chrome146", passes=3
    )

    assert resolver.for_host("www.reuters.com") == "chrome146"
    assert resolver.for_host("WWW.REUTERS.COM") == "chrome146"
    assert resolver.for_host("www.ft.com") is None


def test_resolver_falls_back_for_absent_corrupt_and_unlisted_profiles(
    tmp_path: Path,
) -> None:
    from newsclip.transport_pins import TransportPinResolver

    store = _store(tmp_path)
    resolver = TransportPinResolver(
        store,
        providers_by_host={"www.reuters.com": "reuters"},
    )

    # Absent.
    assert resolver.for_host("www.reuters.com") is None

    # A profile outside the typed allowlist never governs a real fetch, even
    # when something wrote it into the state file directly.
    with store._locked("reuters"):
        store._write_locked(
            "reuters",
            TransportPinState(
                provider="reuters",
                active_profile="firefox147",
                pinned_at=NOW,
                passes_observed=3,
            ),
        )
    assert resolver.for_host("www.reuters.com") is None

    # Corrupt.
    (store.root / "reuters.json").write_bytes(b"not-json")
    assert resolver.for_host("www.reuters.com") is None

    # And recovery: a valid promotion after the corruption governs again.
    store.promote("reuters", profile="safari2601", passes=3)
    assert resolver.for_host("www.reuters.com") == "safari2601"


def test_resolver_rereads_only_when_the_file_moves(tmp_path: Path) -> None:
    from newsclip.transport_pins import TransportPinResolver

    store = _store(tmp_path)
    store.promote("reuters", profile="chrome146", passes=3)
    resolver = TransportPinResolver(
        store,
        providers_by_host={"www.reuters.com": "reuters"},
    )
    reads = 0
    original = TransportPinStore.load

    def counted(self, provider):  # noqa: ANN001, ANN202
        nonlocal reads
        reads += 1
        return original(self, provider)

    TransportPinStore.load = counted  # type: ignore[method-assign]
    try:
        for _ in range(5):
            assert resolver.for_host("www.reuters.com") == "chrome146"
        assert reads == 1
        store.promote("reuters", profile="safari2601", passes=3)
        assert resolver.for_host("www.reuters.com") == "safari2601"
        assert reads == 2
    finally:
        TransportPinStore.load = original  # type: ignore[method-assign]


def test_browser_first_holds_only_for_a_fresh_unhealed_rot(tmp_path: Path) -> None:
    from newsclip.transport_pins import BROWSER_FIRST_WINDOW, TransportPinResolver

    clock = [NOW]
    store = TransportPinStore(tmp_path / "transport-pins", utc_now=lambda: clock[0])
    resolver = TransportPinResolver(
        store,
        providers_by_host={"www.reuters.com": "reuters"},
    )

    # No state: the declared order stands.
    assert resolver.browser_first("reuters") is False

    store.record_rot("reuters", profile="safari2601")
    assert resolver.browser_first("reuters") is True

    # The window lapses: one read may re-test the declared pin.
    clock[0] = NOW + BROWSER_FIRST_WINDOW
    assert resolver.browser_first("reuters") is False

    # A fresh refusal renews it.
    store.record_rot("reuters", profile="safari2601")
    assert resolver.browser_first("reuters") is True

    # A promoted runtime pin is a measured-good HTTP leg; it leads again.
    store.promote("reuters", profile="chrome146", passes=3)
    assert resolver.browser_first("reuters") is False


def test_browser_first_is_off_for_corrupt_state_and_other_providers(
    tmp_path: Path,
) -> None:
    from newsclip.transport_pins import TransportPinResolver

    store = _store(tmp_path)
    resolver = TransportPinResolver(
        store,
        providers_by_host={"www.reuters.com": "reuters"},
    )
    store.record_rot("reuters", profile="safari2601")
    assert resolver.browser_first("ft") is False

    (store.root / "reuters.json").write_bytes(b"not-json")
    assert resolver.browser_first("reuters") is False
    assert resolver.browser_first("../escape") is False


def _drip(
    tmp_path: Path,
    probe,  # noqa: ANN001
    *,
    declared: str = "safari2601",
    clock: dict[str, datetime] | None = None,
):
    """A drip over an advancing clock, so the hourly cadence is real."""

    from newsclip.transport_pins import TransportDrip

    ticking = clock if clock is not None else {"now": NOW}
    store = TransportPinStore(
        tmp_path / "transport-pins",
        utc_now=lambda: ticking["now"],
    )
    return (
        TransportDrip(
            store,
            declared_profiles={"reuters": declared},
            probe=probe,
        ),
        store,
        ticking,
    )


def _tick(clock: dict[str, datetime], hours: float = 1.0) -> None:
    clock["now"] = clock["now"] + timedelta(hours=hours)


def test_drip_stays_idle_until_a_rot_signal_stands(tmp_path: Path) -> None:
    from newsclip.transport_pins import DripOutcome

    drip, store, _clock = _drip(
        tmp_path,
        lambda provider, profile: pytest.fail("no rot signal means no probe"),
    )

    # No state at all.
    assert drip.drip("reuters") is DripOutcome.IDLE
    # A provider that declares no escalation is never dripped.
    assert drip.drip("ft") is DripOutcome.IDLE
    # A healthy runtime pin: nothing to heal.
    store.promote("reuters", profile="chrome146", passes=3)
    assert drip.drip("reuters") is DripOutcome.IDLE


def test_drip_measures_one_candidate_per_cycle_and_promotes_on_three(
    tmp_path: Path,
) -> None:
    from newsclip.transport_pins import DripOutcome

    probed: list[tuple[str, str]] = []

    def probe(provider: str, profile: str) -> bool:
        probed.append((provider, profile))
        return True

    drip, store, clock = _drip(tmp_path, probe)
    store.record_rot("reuters", profile="safari2601")

    first = drip.drip("reuters")
    _tick(clock)
    second = drip.drip("reuters")
    _tick(clock)
    third = drip.drip("reuters")

    # One request per cycle, and the same candidate keeps its turn.
    assert [profile for _provider, profile in probed] == [
        probed[0][1],
        probed[0][1],
        probed[0][1],
    ]
    assert first is DripOutcome.CANDIDATE_PASS
    assert second is DripOutcome.CANDIDATE_PASS
    assert third is DripOutcome.PROMOTED

    state = store.load("reuters")
    assert state is not None
    assert state.active_profile == probed[0][1]
    assert state.passes_observed == 3
    # A promoted pin ends the drip.
    assert drip.drip("reuters") is DripOutcome.IDLE


def test_drip_never_repeats_a_failed_candidate_and_parks_when_spent(
    tmp_path: Path,
) -> None:
    from newsclip.models import HTTP_IMPERSONATION_PROFILES
    from newsclip.transport_pins import DripOutcome

    probed: list[str] = []

    def probe(provider: str, profile: str) -> bool:
        probed.append(profile)
        return False

    drip, store, clock = _drip(tmp_path, probe)
    store.record_rot("reuters", profile="safari2601")

    outcomes = []
    for _ in range(8):
        outcomes.append(drip.drip("reuters"))
        _tick(clock)

    # Every candidate except the declared pin and the rotted profile, once.
    expected = sorted(HTTP_IMPERSONATION_PROFILES - {"safari2601"})
    assert probed == expected
    assert outcomes[: len(expected)] == [DripOutcome.CANDIDATE_FAILED] * len(expected)
    assert outcomes[len(expected)] is DripOutcome.POOL_EXHAUSTED

    state = store.load("reuters")
    assert state is not None
    assert state.pool_exhausted_at is not None
    # Parked: no further probing, and the operator decision is on the record.
    assert outcomes[len(expected) + 1 :] == [DripOutcome.IDLE] * (
        len(outcomes) - len(expected) - 1
    )


def test_drip_ignores_unreadable_state_rather_than_probing(tmp_path: Path) -> None:
    from newsclip.transport_pins import DripOutcome

    drip, store, _clock = _drip(
        tmp_path,
        lambda provider, profile: pytest.fail("unreadable state must not probe"),
    )
    store.record_rot("reuters", profile="safari2601")
    (store.root / "reuters.json").write_bytes(b"not-json")

    assert drip.drip("reuters") is DripOutcome.IDLE


def test_drip_holds_the_hourly_cadence_regardless_of_caller(tmp_path: Path) -> None:
    """R8's "one request per hour" is the mechanism's property, not the timer's.

    `auth keep` and the ops `heal` path both reach the drip, so a caller
    that runs it in a loop must not turn a slow drip into burst probing.
    """

    from newsclip.transport_pins import DripOutcome

    probed: list[str] = []
    drip, store, clock = _drip(
        tmp_path,
        lambda provider, profile: probed.append(profile) or False,
    )
    store.record_rot("reuters", profile="safari2601")

    first = drip.drip("reuters")
    immediate = [drip.drip("reuters") for _ in range(5)]
    _tick(clock, hours=0.9)
    still_early = drip.drip("reuters")
    _tick(clock, hours=0.2)
    after_the_hour = drip.drip("reuters")

    assert first is DripOutcome.CANDIDATE_FAILED
    assert immediate == [DripOutcome.IDLE] * 5
    assert still_early is DripOutcome.IDLE
    assert after_the_hour is DripOutcome.CANDIDATE_FAILED
    assert len(probed) == 2


def test_repeat_rot_of_the_same_profile_never_restarts_the_sweep(
    tmp_path: Path,
) -> None:
    """The keeper re-escalates every cycle, so rot repeats. Progress must hold.

    Wiping the sweep on each repeat would make promotion and pool exhaustion
    both unreachable — an hourly probe forever with no operator signal.
    """

    from newsclip.transport_pins import DripOutcome

    drip, store, clock = _drip(tmp_path, lambda provider, profile: True)
    store.record_rot("reuters", profile="safari2601")

    outcomes = []
    for _ in range(3):
        outcomes.append(drip.drip("reuters"))
        # The watch's own retrieval re-escalates and re-records the same rot.
        store.record_rot("reuters", profile="safari2601")
        _tick(clock)

    assert outcomes[-1] is DripOutcome.PROMOTED
    state = store.load("reuters")
    assert state is not None
    assert state.active_profile is not None
    assert state.passes_observed == 3


def test_rot_of_a_different_profile_opens_a_fresh_sweep(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record_rot("reuters", profile="safari2601")
    store.record_candidate_failure("reuters", profile="chrome146")

    carried = store.load("reuters")
    assert carried is not None
    assert carried.exhausted_profiles == ("chrome146",)

    # A promotion, then a later rot naming the newly promoted profile: the
    # pool's exclusions were computed against the old signal, so they reset.
    store.promote("reuters", profile="chrome131_android", passes=3)
    reopened = store.record_rot("reuters", profile="chrome131_android")

    assert reopened.active_profile is None
    assert reopened.exhausted_profiles == ()
    assert reopened.pool_exhausted_at is None
    assert reopened.rot_profile == "chrome131_android"
