"""Application lease naming and timing over shared process-safe locks."""

from __future__ import annotations

import hashlib
from contextlib import contextmanager, nullcontext
from pathlib import Path

from signin_window.leases import (
    HeldProfileLease as _HeldProfileLease,
)
from signin_window.leases import (
    LeaseBusyError as LeaseBusyError,
)
from signin_window.leases import (
    LeaseKind as LeaseKind,
)
from signin_window.leases import (
    LockOrderError as LockOrderError,
)
from signin_window.leases import (
    ordered_file_lease as _ordered_file_lease,
)

from ..account_keys import require_account_key
from ..provider_keys import is_provider_key
from ..timing import TimingStep, timing_step


@contextmanager
def ordered_file_lease(path, *, kind, timeout_seconds=30):
    step = {
        LeaseKind.PROVIDER_ATTEMPT: TimingStep.ATTEMPT_LEASE_WAIT,
        LeaseKind.DURABLE_PROFILE: TimingStep.PROFILE_LEASE_WAIT,
    }.get(kind)
    # Acquisition timing closes before the caller's protected work starts.
    lease = _ordered_file_lease(path, kind=kind, timeout_seconds=timeout_seconds)
    with timing_step(step) if step is not None else nullcontext():
        lease.__enter__()
    try:
        yield
    finally:
        lease.__exit__(None, None, None)


class HeldProfileLease(_HeldProfileLease):
    def __init__(self, path, *, timeout_seconds=30):
        with timing_step(TimingStep.PROFILE_LEASE_WAIT):
            super().__init__(path, timeout_seconds=timeout_seconds)


class LeaseManager:
    """Create account-global attempt and path-specific profile leases."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def attempt(
        self,
        provider: str,
        account_key: str,
        *,
        timeout_seconds: float = 30,
    ):
        if not is_provider_key(provider):
            raise ValueError("invalid provider key")
        account_key = require_account_key(account_key)
        account_id = hashlib.sha256(account_key.encode("utf-8")).hexdigest()[:16]
        return ordered_file_lease(
            self.root / f"{provider}-attempt-{account_id}.lock",
            kind=LeaseKind.PROVIDER_ATTEMPT,
            timeout_seconds=timeout_seconds,
        )

    def profile(self, profile: Path, *, timeout_seconds: float = 30):
        profile_id = hashlib.sha256(
            str(Path(profile).expanduser().resolve()).encode("utf-8")
        ).hexdigest()[:16]
        return ordered_file_lease(
            self.root / f"profile-{profile_id}.lock",
            kind=LeaseKind.DURABLE_PROFILE,
            timeout_seconds=timeout_seconds,
        )

    def hold_profile(
        self, profile: Path, *, timeout_seconds: float = 10
    ) -> HeldProfileLease:
        """Acquire a long-lived profile flock for a keep-alive browser."""

        profile_id = hashlib.sha256(
            str(Path(profile).expanduser().resolve()).encode("utf-8")
        ).hexdigest()[:16]
        return HeldProfileLease(
            self.root / f"profile-{profile_id}.lock",
            timeout_seconds=timeout_seconds,
        )
