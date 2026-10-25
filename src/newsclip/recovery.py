"""One durable recovery request per provider, never a credential authority.

Readers request maintenance; the keeper owns attempts and their verdicts. The
first failure is retained, repeated requests cannot refund a budget, and an
interrupted dispatch is never silently replayed. All URLs stay private.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, HttpUrl, ValidationError

from .errors import RETRYABLE_READ_FAILURES, PersistenceError
from .models import FrozenModel, RecoveryAttempt, RecoveryHealth, RecoveryStatus
from .private_state import (
    PrivateStateBusyError,
    PrivateStateError,
    atomic_private_write,
    exclusive_lock,
)
from .provider_keys import PROVIDER_KEY_PATTERN, is_provider_key

_BACKOFF = timedelta(minutes=20)
_WINDOW = timedelta(hours=24)
_MAX_ATTEMPTS = 3
_MAX_BYTES = 16 * 1024


class RecoveryBusyError(RuntimeError):
    """Another maintenance process already owns this provider."""


class RecoveryRecord(FrozenModel):
    schema_version: int = Field(default=2, ge=1, le=2)
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    generation_id: UUID | None
    session_required: bool = False
    url: HttpUrl = Field(max_length=4096)
    incident_id: str | None = Field(default=None, pattern=r"^incident-[a-f0-9]{24}$")
    source_diagnostic_id: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$"
    )
    attempt_diagnostic_id: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$"
    )
    window_started_at: AwareDatetime
    health: RecoveryHealth
    not_before: AwareDatetime
    #: Existing-authority reconciliation has been reserved. This can be set
    #: while PENDING for a delayed retry of an initial transient serving read.
    reconciliation_started: bool = False
    #: A guarded FULL check may authorize one exact-URL reconciliation only
    #: when it is newer than the failure it is meant to disprove. These two
    #: timestamps make that proof durable and single-use across processes.
    last_failed_at: AwareDatetime | None = None
    last_reconciliation_check_at: AwareDatetime | None = None


class RecoveryStore:
    def __init__(
        self, root: Path, *, utc_now: Callable[[], datetime] | None = None
    ) -> None:
        self.root = root
        self._now = utc_now or (lambda: datetime.now(UTC))

    def _directory(self) -> None:
        if self.root.is_symlink():
            raise PersistenceError("recovery directory is not private")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path(self, provider: str) -> Path:
        if not is_provider_key(provider):
            raise ValueError("invalid recovery provider")
        return self.root / f"{provider}.json"

    @contextmanager
    def operation(self, provider: str) -> Iterator[None]:
        """Serialize all keeper/ops upkeep for this provider across processes."""
        self._path(provider)
        self._directory()
        try:
            with ExitStack() as lock:
                try:
                    lock.enter_context(
                        exclusive_lock(
                            self.root / f"{provider}.operation.lock", timeout_seconds=0
                        )
                    )
                except PrivateStateBusyError as error:
                    raise RecoveryBusyError from error
                # A nested state failure after acquisition is a persistence
                # failure, not evidence that this operation's lock was busy.
                yield
        except PrivateStateError as error:
            raise PersistenceError("recovery operation unavailable") from error

    @contextmanager
    def _locked(self, provider: str) -> Iterator[None]:
        self._path(provider)
        self._directory()
        try:
            with exclusive_lock(self.root / f"{provider}.lock", timeout_seconds=5):
                yield
        except (OSError, ValidationError) as error:
            raise PersistenceError("recovery state unavailable") from error

    def load(self, provider: str) -> RecoveryRecord | None:
        """Read without creating state or locking a browser operation."""
        path = self._path(provider)
        try:
            if self.root.is_symlink() or path.is_symlink():
                raise PersistenceError("recovery state is not private")
            if not path.exists():
                return None
            with path.open("rb") as stream:
                payload = stream.read(_MAX_BYTES + 1)
            if len(payload) > _MAX_BYTES:
                raise PersistenceError("recovery state exceeds size limit")
            record = RecoveryRecord.model_validate_json(payload)
            if record.provider != provider:
                raise PersistenceError("recovery provider mismatch")
            return record.model_copy(
                update={
                    "health": record.health.model_copy(
                        update={
                            "incident_id": record.incident_id,
                            "budget_reset_at": record.window_started_at + _WINDOW,
                        }
                    )
                }
            )
        except (OSError, ValidationError) as error:
            raise PersistenceError("recovery state unreadable") from error

    def _write(self, record: RecoveryRecord) -> RecoveryRecord:
        record = record.model_copy(
            update={
                "schema_version": 2,
                "health": record.health.model_copy(
                    update={
                        "incident_id": record.incident_id,
                        "budget_reset_at": record.window_started_at + _WINDOW,
                    }
                ),
            }
        )
        payload = record.model_dump_json().encode()
        if len(payload) > _MAX_BYTES:
            raise PersistenceError("recovery state exceeds size limit")
        atomic_private_write(self._path(record.provider), payload)
        return record

    def refresh(self, provider: str) -> RecoveryRecord | None:
        """Migrate an old budget latch into a real wait; never perform I/O.

        The watcher and keeper both call this. Merely reading health does not
        rewrite state. Window rollover and reservation remain under one lock.
        Failed article attempts are deliberately not scheduled here.
        """
        record = self.load(provider)
        if (
            record is None
            or record.health.status is not RecoveryStatus.FAILED
            or record.health.reason != "recovery_budget_spent"
        ):
            return record
        with self._locked(provider):
            record = self.load(provider)
            if record is None:
                return None
            if (
                record.health.status is RecoveryStatus.FAILED
                and record.health.reason == "recovery_budget_spent"
            ):
                due = max(record.window_started_at + _WINDOW, record.not_before)
                record = record.model_copy(
                    update={
                        "health": record.health.model_copy(
                            update={
                                "status": RecoveryStatus.PENDING,
                                "next_attempt_at": due,
                            }
                        )
                    }
                )
                return self._write(record)
            return record

    def _roll_window(self, record: RecoveryRecord) -> RecoveryRecord:
        if self._now() >= record.window_started_at + _WINDOW:
            return record.model_copy(
                update={
                    "window_started_at": self._now(),
                    "health": record.health.model_copy(update={"attempts": 0}),
                }
            )
        return record

    def reconciliation_blocker(
        self,
        record: RecoveryRecord,
        *,
        verified_check_at: datetime | None,
        require_proof: bool = True,
    ) -> str | None:
        """One decision shared by execution and operator instructions."""
        if (
            record.health.attempts >= _MAX_ATTEMPTS
            and self._now() < record.window_started_at + _WINDOW
        ):
            return "recovery_budget_spent"
        if self._now() < record.not_before:
            return "recovery_backoff"
        if not require_proof:
            return None
        if not self.valid_reconciliation_proof(record, verified_check_at):
            return "provider_check_required"
        return None

    def valid_reconciliation_proof(
        self, record: RecoveryRecord, checked_at: datetime | None
    ) -> bool:
        floor = record.last_failed_at or record.health.requested_at
        return (
            checked_at is not None
            and floor < checked_at <= self._now()
            and (
                record.last_reconciliation_check_at is None
                or checked_at > record.last_reconciliation_check_at
            )
        )

    def automatic_retry_available(self, record: RecoveryRecord) -> bool:
        """Only one follow-up to a known first dispatch, across all windows.

        Manual reconciliation and interrupted dispatch reconciliation consume
        this allowance too. Unknown legacy episode history grants no action.
        """
        return (
            record.health.status is RecoveryStatus.FAILED
            and record.health.episode_attempts == 1
            and not record.reconciliation_started
            and record.last_reconciliation_check_at is None
        )

    def automatic_retry_due(self, record: RecoveryRecord) -> datetime | None:
        """Local watcher schedule; current guards are checked by the keeper."""
        if (
            not self.automatic_retry_available(record)
            or record.health.reason not in RETRYABLE_READ_FAILURES
        ):
            return None
        return self.retry_not_before(record)

    def retry_not_before(self, record: RecoveryRecord) -> datetime:
        """The durable backoff/deferral and provider-window lower bound."""
        due = max(record.not_before, record.health.next_attempt_at or record.not_before)
        if record.health.attempts >= _MAX_ATTEMPTS:
            due = max(due, record.window_started_at + _WINDOW)
        return due

    def _reserve(
        self, record: RecoveryRecord, diagnostic_id: str | None
    ) -> RecoveryRecord:
        now = self._now()
        record = self._roll_window(record)
        episode_attempts = record.health.episode_attempts
        return record.model_copy(
            update={
                "not_before": now + _BACKOFF,
                "attempt_diagnostic_id": diagnostic_id,
                "health": record.health.model_copy(
                    update={
                        "status": RecoveryStatus.RUNNING,
                        "attempts": record.health.attempts + 1,
                        "episode_attempts": episode_attempts + 1
                        if episode_attempts is not None
                        else None,
                        "diagnostic_id": diagnostic_id,
                        "reason": None,
                        "next_attempt_at": None,
                        "recent_attempts": (
                            *record.health.recent_attempts,
                            RecoveryAttempt(
                                request_id=record.health.request_id,
                                diagnostic_id=diagnostic_id,
                                started_at=now,
                            ),
                        )[-6:],
                    }
                ),
            }
        )

    def request(
        self,
        provider: str,
        *,
        generation_id: UUID | None,
        session_required: bool = False,
        url: str,
        incident_id: str | None,
        diagnostic_id: str | None,
        read_failure_reason: str | None = None,
    ) -> RecoveryRecord:
        if (
            read_failure_reason is not None
            and read_failure_reason not in RETRYABLE_READ_FAILURES
        ):
            raise ValueError("unsupported automatic read failure")
        with self._locked(provider):
            prior = self.load(provider)
            now = self._now()
            # New traffic cannot replace the first incident or refund an action.
            if prior is not None and (
                prior.health.status in {RecoveryStatus.PENDING, RecoveryStatus.RUNNING}
                or (
                    prior.health.status is RecoveryStatus.FAILED
                    and (
                        prior.url == HttpUrl(url)
                        or (
                            prior.generation_id == generation_id
                            and now - prior.window_started_at < _WINDOW
                        )
                    )
                )
            ):
                return prior
            in_window = prior is not None and now - prior.window_started_at < _WINDOW
            attempts = prior.health.attempts if prior is not None and in_window else 0
            due = max(now, prior.not_before) if prior is not None else now
            if read_failure_reason is not None:
                due = max(due, now + _BACKOFF)
            return self._write(
                RecoveryRecord(
                    provider=provider,
                    generation_id=generation_id,
                    session_required=session_required,
                    reconciliation_started=read_failure_reason is not None,
                    url=HttpUrl(url),
                    incident_id=incident_id,
                    source_diagnostic_id=diagnostic_id,
                    window_started_at=prior.window_started_at
                    if prior is not None and in_window
                    else now,
                    not_before=due,
                    health=RecoveryHealth(
                        request_id=f"recovery-{uuid4().hex}",
                        status=RecoveryStatus.PENDING,
                        requested_at=now,
                        next_attempt_at=due,
                        attempts=attempts,
                        episode_attempts=0,
                        recent_attempts=prior.health.recent_attempts if prior else (),
                        reason=read_failure_reason,
                    ),
                )
            )

    def claim(self, provider: str, diagnostic_id: str | None) -> RecoveryRecord | None:
        """Caller holds operation(). Persist an attempt before provider I/O."""
        with self._locked(provider):
            record = self.load(provider)
            if record is None:
                return None
            health = record.health
            now = self._now()
            if health.status is RecoveryStatus.RUNNING:
                if record.reconciliation_started:
                    self._write(
                        record.model_copy(
                            update={
                                "last_failed_at": now,
                                "health": health.model_copy(
                                    update={
                                        "status": RecoveryStatus.FAILED,
                                        "reason": "interrupted_reconciliation",
                                        "next_attempt_at": None,
                                    }
                                ),
                            }
                        )
                    )
                    return None
                # Once the operation lock is available the old worker is gone.
                # Reconcile once using read-only proof; never replay its login.
                return self._write(
                    record.model_copy(
                        update={
                            "reconciliation_started": True,
                            "health": health.model_copy(
                                update={
                                    "diagnostic_id": diagnostic_id,
                                    "reason": "interrupted_recovery",
                                }
                            ),
                        }
                    )
                )
            if (
                health.status is RecoveryStatus.SUCCEEDED
                or health.next_attempt_at is None
            ):
                return None
            if health.next_attempt_at > now:
                return None
            record = self._roll_window(record)
            health = record.health
            if health.attempts >= _MAX_ATTEMPTS:
                self._write(
                    record.model_copy(
                        update={
                            "health": health.model_copy(
                                update={
                                    "status": RecoveryStatus.PENDING,
                                    "reason": "recovery_budget_spent",
                                    "next_attempt_at": max(
                                        record.window_started_at + _WINDOW,
                                        record.not_before,
                                    ),
                                }
                            )
                        }
                    )
                )
                return None
            return self._write(self._reserve(record, diagnostic_id))

    def claim_verified_reconciliation(
        self,
        provider: str,
        diagnostic_id: str | None,
        *,
        verified_check_at: datetime,
        automatic: bool = False,
    ) -> RecoveryRecord | None:
        """Claim one read-only retry authorized by newer guarded FULL proof.

        The caller owns ``operation()`` and has already established that the
        observation is a successful provider check. Persist its timestamp
        before article I/O so a crash or repeated heal cannot reuse the same
        proof. This never changes credential authority.
        """

        with self._locked(provider):
            record = self.load(provider)
            if record is None or record.health.status is not RecoveryStatus.FAILED:
                return None
            if automatic and not self.automatic_retry_available(record):
                return None
            if (
                self.reconciliation_blocker(record, verified_check_at=verified_check_at)
                is not None
            ):
                return None
            return self._write(
                self._reserve(record, diagnostic_id).model_copy(
                    update={
                        "last_reconciliation_check_at": verified_check_at,
                        "reconciliation_started": True,
                    }
                )
            )

    def claim_read_retry(
        self, provider: str, diagnostic_id: str | None
    ) -> RecoveryRecord | None:
        """Reserve the one typed transient read retry without inventing proof."""
        with self._locked(provider):
            record = self.load(provider)
            if record is None:
                return None
            due = self.automatic_retry_due(record)
            if due is None or due > self._now():
                return None
            return self._write(
                self._reserve(record, diagnostic_id).model_copy(
                    update={"reconciliation_started": True}
                )
            )

    def defer_read_retry(self, provider: str, *, until: datetime) -> None:
        """Avoid spinning the local worker while a current guard blocks it."""
        with self._locked(provider):
            record = self.load(provider)
            if record is None or self.automatic_retry_due(record) is None:
                return
            self._write(
                record.model_copy(
                    update={
                        "health": record.health.model_copy(
                            update={"next_attempt_at": until}
                        )
                    }
                )
            )

    def defer(self, provider: str, *, until: datetime, reason: str) -> None:
        """A pre-dispatch guard delays work without spending an attempt."""
        with self._locked(provider):
            record = self.load(provider)
            if record is None or record.health.status is not RecoveryStatus.PENDING:
                return
            self._write(
                record.model_copy(
                    update={
                        "health": record.health.model_copy(
                            update={
                                "next_attempt_at": until,
                                "reason": reason,
                            }
                        )
                    }
                )
            )

    def release_hold_deferral(self, provider: str) -> RecoveryRecord | None:
        """The hold that deferred this pending request is gone: allow it now.

        A hold defers the local watcher until the hold could plausibly have
        cleared. The scheduled keeper re-reads the hold every cycle and, once
        it is gone, releases that deferral so recovery need not wait out a
        long estimate. Backoff (``not_before``) and budgets still apply.
        """
        with self._locked(provider):
            record = self.load(provider)
            if (
                record is None
                or record.health.status is not RecoveryStatus.PENDING
                or record.health.reason != "provider_held"
            ):
                return record
            return self._write(
                record.model_copy(
                    update={
                        "health": record.health.model_copy(
                            update={
                                "next_attempt_at": max(self._now(), record.not_before)
                            }
                        )
                    }
                )
            )

    def worker_failed(self, provider: str, request_id: str) -> None:
        """Settle only an exited, unclaimed dispatch; never replace live work."""
        try:
            with self.operation(provider), self._locked(provider):
                record = self.load(provider)
                if (
                    record is None
                    or record.health.request_id != request_id
                    or (
                        record.health.status is not RecoveryStatus.PENDING
                        and self.automatic_retry_due(record) is None
                    )
                ):
                    return
                self._write(
                    record.model_copy(
                        update={
                            "health": record.health.model_copy(
                                update={
                                    "status": RecoveryStatus.FAILED,
                                    "reason": "recovery_worker_failed",
                                    "next_attempt_at": None,
                                }
                            ),
                            "last_failed_at": self._now(),
                        }
                    )
                )
        except RecoveryBusyError:
            # A different keeper owns the provider now. Its verdict wins.
            return

    def article_verified(
        self,
        provider: str,
        url: str,
        *,
        verified_at: datetime,
        diagnostic_id: str | None = None,
    ) -> RecoveryRecord | None:
        """Exact successful serving can settle a queued or failed request.

        An active worker owns its verdict. An unrelated article or a positive
        session check cannot clear the original content failure.
        """
        if self.load(provider) is None:
            return None
        with self._locked(provider):
            record = self.load(provider)
            if (
                record is None
                or record.url != HttpUrl(url)
                or verified_at < record.health.requested_at
                or record.health.status
                not in {RecoveryStatus.PENDING, RecoveryStatus.FAILED}
            ):
                return None
            return self._write(
                record.model_copy(
                    update={
                        "health": record.health.model_copy(
                            update={
                                "status": RecoveryStatus.SUCCEEDED,
                                "article_verified": True,
                                "diagnostic_id": diagnostic_id
                                or record.health.diagnostic_id,
                                "reason": None,
                                "next_attempt_at": None,
                            }
                        )
                    }
                )
            )

    def session_verified(self, record: RecoveryRecord) -> None:
        with self._locked(record.provider):
            current = self.load(record.provider)
            if current is None or current.health.request_id != record.health.request_id:
                raise PersistenceError("recovery request changed during verification")
            self._write(
                current.model_copy(
                    update={
                        "health": current.health.model_copy(
                            update={
                                "session_verified": True,
                            }
                        )
                    }
                )
            )

    def require_session(self, record: RecoveryRecord) -> RecoveryRecord:
        """Persist explicit session-loss evidence before entering renewal."""
        with self._locked(record.provider):
            current = self.load(record.provider)
            if current is None or current.health.request_id != record.health.request_id:
                raise PersistenceError(
                    "recovery request changed during session diagnosis"
                )
            return self._write(current.model_copy(update={"session_required": True}))

    def finish(
        self,
        record: RecoveryRecord,
        *,
        reason: str | None,
        session_verified: bool = False,
        article_verified: bool = False,
    ) -> RecoveryRecord:
        with self._locked(record.provider):
            current = self.load(record.provider)
            if current is None or current.health.request_id != record.health.request_id:
                raise PersistenceError("recovery request changed during attempt")
            history = current.health.recent_attempts
            if history and history[-1].request_id == current.health.request_id:
                history = (
                    *history[:-1],
                    history[-1].model_copy(
                        update={
                            "completed_at": self._now(),
                            "reason": reason,
                            "article_verified": article_verified,
                        }
                    ),
                )
            return self._write(
                current.model_copy(
                    update={
                        "last_failed_at": None if article_verified else self._now(),
                        "health": current.health.model_copy(
                            update={
                                "status": RecoveryStatus.SUCCEEDED
                                if article_verified
                                else RecoveryStatus.FAILED,
                                "session_verified": session_verified,
                                "article_verified": article_verified,
                                "reason": reason,
                                "next_attempt_at": None,
                                "recent_attempts": history,
                            }
                        ),
                    }
                )
            )
