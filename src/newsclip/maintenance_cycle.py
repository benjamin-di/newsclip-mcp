"""Public, bounded account maintenance orchestration.

Application verdicts and provider-check cadence belong to Newsclip. Callers own
when to run this cycle and where to send its closed results. No notification
service, account reference or installation-specific transport is built in.
"""

from __future__ import annotations

import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from signin_window.state import atomic_private_write, read_private_file

from .errors import PersistenceError
from .process_signals import TIMED_OUT_EXIT_STATUSES, under_timeout
from .provider_guard import GuardAction
from .provider_keys import is_provider_key

ENUMS = {
    "action": (
        "idle busy fresh renewed held cooldown "
        "operator_action_required renewal_failed checked check_failed "
    ),
    "overall_state": ("healthy waiting needs_attention "),
    "automatic_recovery_action": (
        "retry_article wait_for_provider_check blocked review none "
    ),
    "status": (
        "verified required cooldown operator_action pending running succeeded failed "
    ),
    "next_action": (
        "provider_check_then_heal allow_credential_mint "
        "repair_keeper_readiness acknowledge_hold review_account "
        "review_provider heal wait_for_recovery review_recovery "
        "update_http_fingerprint "
    ),
    "reason": (
        "recovery_budget_spent recovery_backoff cooldown "
        "credential_budget_spent recovery_worker_failed "
        "interrupted_reconciliation interrupted_recovery "
        "recovery_verification_failed session_required "
        "article_verification_failed session_verification_failed "
        "read_timeout read_dns read_provider_error content_not_full "
        "paid_probe_inconclusive account_action provider_defense "
        "provider_held session_cooldown recovery_state_unreadable "
        "recovery_unavailable persistence unclassified "
        "unclassified_error idle busy fresh renewed held "
        "operator_action_required renewal_failed checked check_failed "
    ),
    "reason_code": (
        "paid_probe_inconclusive verification_unresolved "
        "session_verification_unresolved session_promotion_required "
        "credential_mint_not_permitted credential_host_not_ready "
        "credential_budget_spent transport_failure session_required "
        "read_timeout read_dns read_provider_error content_not_full "
        "account_action provider_defense recovery_state_unreadable "
        "recovery_unavailable persistence unclassified "
        "unclassified_error "
    ),
    "recovery_blocker": (
        "ready review_recovery recovery_budget_spent recovery_backoff "
        "provider_check_required provider_held provider_defense "
        "account_action recovery_worker_failed "
        "interrupted_reconciliation "
    ),
}


def project_verdict(data, recovery=False):
    safe = {}
    for key, value in data.items():
        if value is None and (key in ENUMS or key == "automatic_recovery_due_at"):
            safe[key] = None
        elif key in ENUMS and isinstance(value, str) and value in ENUMS[key].split():
            safe[key] = value
        elif key in {"reason", "reason_code", "recovery_blocker"}:
            safe[key] = "unclassified"
        elif (
            (
                key
                in {
                    "stale",
                    "credential_attempt",
                    "article_verified",
                    "session_verified",
                    "automatic_recovery_stalled",
                    "renewal_unresolved",
                }
                and type(value) is bool
            )
            or (
                key in {"attempts", "episode_attempts", "http_challenges_24h"}
                and type(value) is int
                and 0 <= value <= 10000
            )
            or (
                key in {"diagnostic_id", "request_id", "incident_id"}
                and isinstance(value, str)
                and re.fullmatch(r"(?:cli|recovery|incident)-[a-f0-9]{24,32}", value)
            )
            or (
                key
                in {
                    "requested_at",
                    "next_attempt_at",
                    "budget_reset_at",
                    "recovery_retry_at",
                    "automatic_recovery_due_at",
                }
                and isinstance(value, str)
                and re.fullmatch(r"\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|\+00:00)", value)
                and len(value) <= 40
            )
        ):
            safe[key] = value
        elif key == "recovery" and not recovery and isinstance(value, dict):
            safe[key] = project_verdict(value, recovery=True)
    return safe


@dataclass(frozen=True)
class MaintenanceCycleResult:
    mode: str
    ran: bool
    needs_attention: bool
    results: tuple[dict, ...]
    schema_version: int = 1

    @property
    def exit_code(self) -> int:
        return int(self.needs_attention)

    def public_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "ran": self.ran,
            "needs_attention": self.needs_attention,
            "results": list(self.results),
        }


@contextmanager
def cycle_lease(root: Path) -> Iterator[int]:
    """A child keeps this lease if its invoking parent is interrupted."""
    import fcntl

    root.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        root / "maintenance-cycle.lock",
        os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PersistenceError("maintenance lease is unavailable")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd
    finally:
        # Do not explicitly unlock: a surviving child shares this description.
        os.close(fd)


def reserve_check_window(root: Path, *, now: float, interval: int) -> bool:
    """Preserve the existing ASCII schedule and reserve before provider I/O."""
    path = root / "provider-monitor-next-run-at"
    try:
        raw = read_private_file(path, max_bytes=64).decode("ascii").strip()
        if not raw.isdigit():
            raise ValueError("invalid schedule")
        next_run = int(raw)
    except FileNotFoundError:
        next_run = 0
    except (OSError, ValueError) as error:
        raise PersistenceError("provider check schedule is unavailable") from error
    if now < next_run:
        return False
    atomic_private_write(path, f"{int(now) + interval}\n".encode())
    return True


def run_command(
    arguments: list[str], *, timeout: int, lock_fd: int
) -> tuple[int, dict]:
    """Bound children, discard stderr, and never return arbitrary process output."""
    with tempfile.TemporaryFile() as output:
        child = subprocess.Popen(
            under_timeout([sys.executable, "-m", "newsclip", *arguments], timeout),
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.DEVNULL,
            pass_fds=(lock_fd,),
            start_new_session=True,
        )
        try:
            code = child.wait()
        finally:
            if child.poll() is None:
                # The caller may be interrupted while GNU timeout still owns
                # a provider/browser group. Give that entire owned group TERM.
                with suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    with suppress(ProcessLookupError):
                        os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
        if code in TIMED_OUT_EXIT_STATUSES:
            return code, {}
        output.seek(0)
        raw = output.read(32769)
    if len(raw) > 32768:
        raise ValueError("oversize maintenance result")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("invalid maintenance result")
    return code, data


def run_maintenance_cycle(
    providers: Sequence[str],
    *,
    root: Path,
    mode: Literal["keep", "check"] = "keep",
    timeout: int = 900,
    max_age_hours: float = 12,
    allow_credential_mint: bool = False,
    check_interval: int = 86400,
    on_start: Callable[[], None] | None = None,
    runner: Callable = run_command,
    now: Callable[[], float] = time.time,
) -> MaintenanceCycleResult:
    """Run all configured providers, preserving independent guards and budgets.

    A provider failure never prevents a later provider from being checked. The
    check mode distinguishes bounded automatic waiting from operator-required
    states; callers choose their own alert policy over this structured result.
    """
    if (
        not providers
        or len(providers) > 10
        or len(set(providers)) != len(providers)
        or any(not is_provider_key(p) for p in providers)
        or mode not in {"keep", "check"}
        or not 1 <= timeout <= 86400
        or not 60 <= check_interval <= 365 * 86400
        or not 0 < max_age_hours <= 8760
    ):
        raise ValueError("invalid bounded maintenance configuration")
    results = []
    with cycle_lease(root) as lock_fd:
        if mode == "check" and not reserve_check_window(
            root, now=now(), interval=check_interval
        ):
            return MaintenanceCycleResult(mode, False, False, ())
        if on_start is not None:
            on_start()
        for provider in providers:
            arguments = (
                [
                    "auth",
                    "keep",
                    provider,
                    "--json",
                    "--max-age-hours",
                    str(max_age_hours),
                ]
                if mode == "keep"
                else ["provider-guard", "--provider", provider, "--scheduled", "--json"]
            )
            if mode == "keep" and allow_credential_mint:
                arguments.append("--allow-credential-mint")
            code = 1
            try:
                code, data = runner(arguments, timeout=timeout, lock_fd=lock_fd)
                if data.get("provider") != provider:
                    raise ValueError("provider mismatch")
                safe = project_verdict(data)
                if mode == "keep":
                    if (
                        safe.get("action") not in ENUMS["action"].split()
                        or safe.get("overall_state")
                        not in ENUMS["overall_state"].split()
                    ):
                        raise ValueError("missing keeper verdict")
                    attention = (
                        bool(code)
                        or safe["overall_state"] == "needs_attention"
                        or safe.get("automatic_recovery_stalled") is True
                    )
                else:
                    action = GuardAction(data.get("action"))
                    safe["action"] = action.value
                    attention = action in {
                        GuardAction.OPERATOR_ACTION,
                        GuardAction.LOCAL_REPAIR_REQUIRED,
                        GuardAction.SESSION_PROMOTION_REQUIRED,
                    }
                    # A valid application verdict is required even for expected waiting.
                    attention = attention or code not in {0, 1}
                safe.update(
                    provider=provider, needs_attention=attention, exit_code=code
                )
            except (OSError, ValueError, UnicodeError, RecursionError):
                safe = {
                    "provider": provider,
                    "needs_attention": True,
                    "overall_state": "needs_attention",
                    "reason_code": "cli_timeout"
                    if code in TIMED_OUT_EXIT_STATUSES
                    else "cli_output_invalid",
                    "exit_code": code or 1,
                }
            results.append(safe)
    return MaintenanceCycleResult(
        mode, True, any(r["needs_attention"] for r in results), tuple(results)
    )
