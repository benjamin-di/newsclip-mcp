"""Cheap local polling beside the existing keeper's hourly maintenance cycle.

Each dispatched child runs the sanctioned auth keep operation with its existing
credential budget. Healthy providers never start a child or contact a website.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime

from .errors import PersistenceError
from .models import RecoveryStatus
from .process_signals import under_timeout
from .provider_keys import is_provider_key
from .recovery import RecoveryStore


def _run(provider: str, allow_credentials: bool, timeout: int) -> dict[str, object]:
    args = [
        sys.executable,
        "-m",
        "newsclip",
        "auth",
        "keep",
        provider,
        "--recovery-only",
        "--json",
    ]
    if allow_credentials:
        args.append("--allow-credential-mint")
    completed = subprocess.run(
        under_timeout(args, timeout), capture_output=True, check=False
    )
    # Only the CLI's closed structured verdict is eligible for scheduler logs.
    try:
        payload = json.loads(completed.stdout)
        if not isinstance(payload, dict):
            raise ValueError("invalid outcome")
        from .session_keeper import KeeperResult

        result = KeeperResult.model_validate(
            {
                key: value
                for key, value in payload.items()
                if key not in {"next_action", "overall_state", "repair_hint"}
            }
        )
        return result.public_dict()
    except ValueError:
        return {
            "provider": provider,
            "action": "recovery_worker_failed",
            "exit_code": completed.returncode,
        }


class RecoveryWatch:
    def __init__(
        self,
        store: RecoveryStore,
        providers: tuple[str, ...],
        *,
        allow_credentials: bool,
        timeout: int = 900,
        runner: Callable[[str, bool, int], dict[str, object]] = _run,
        utc_now: Callable[[], datetime] | None = None,
    ) -> None:
        if not providers or any(
            not is_provider_key(provider) for provider in providers
        ):
            raise ValueError("invalid recovery providers")
        if timeout <= 0:
            raise ValueError("invalid recovery timeout")
        self.store = store
        self.providers = tuple(dict.fromkeys(providers))
        self.allow_credentials = allow_credentials
        self.timeout = timeout
        self.runner = runner
        self.now = utc_now or (lambda: datetime.now(UTC))
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="recovery")
        self.active: dict[str, Future[dict[str, object]]] = {}
        self._requests: dict[str, str] = {}
        self._cursor = 0

    def tick(self) -> list[dict[str, object]]:
        outcomes: list[dict[str, object]] = []
        for provider, future in list(self.active.items()):
            if future.done():
                try:
                    outcome = future.result()
                except Exception:
                    outcome = {"provider": provider, "action": "recovery_worker_failed"}
                outcomes.append(outcome)
                request_id = self._requests.pop(provider)
                if outcome.get("action") == "recovery_worker_failed":
                    try:
                        self.store.worker_failed(provider, request_id)
                    except PersistenceError:
                        outcomes.append(
                            {
                                "provider": provider,
                                "action": "recovery_state_unreadable",
                            }
                        )
                del self.active[provider]
        ordered = self.providers[self._cursor :] + self.providers[: self._cursor]
        for provider in ordered:
            if len(self.active) >= 2:
                break
            if provider in self.active:
                continue
            try:
                record = self.store.refresh(provider)
            except PersistenceError:
                outcomes.append(
                    {"provider": provider, "action": "recovery_state_unreadable"}
                )
                continue
            if record is None or record.health.status is RecoveryStatus.SUCCEEDED:
                continue
            due = (
                self.store.automatic_retry_due(record)
                if record.health.status is RecoveryStatus.FAILED
                else record.health.next_attempt_at
            )
            if record.health.status is RecoveryStatus.FAILED and due is None:
                continue
            if (
                record.health.status in {RecoveryStatus.PENDING, RecoveryStatus.FAILED}
                and due is not None
                and due > self.now()
            ):
                continue
            self.active[provider] = self.pool.submit(
                self.runner, provider, self.allow_credentials, self.timeout
            )
            self._requests[provider] = record.health.request_id
            self._cursor = (self.providers.index(provider) + 1) % len(self.providers)
        return outcomes

    def close(self) -> None:
        self.pool.shutdown(wait=True, cancel_futures=True)


def main() -> None:
    from .process_signals import exit_on_sigterm
    from .tenancy import user_scope

    # Stop waits for in-flight keeper children (they get the same TERM).
    exit_on_sigterm()
    with user_scope(os.environ.get("NEWSCLIP_USER") or None):
        _watch_account()


def _watch_account() -> None:
    from .composition import _application_root

    providers = tuple(os.environ["NEWSCLIP_KEEPER_PROVIDERS"].split())
    watcher = RecoveryWatch(
        RecoveryStore(
            _application_root("NEWSCLIP_STATE_HOME", ".local/state") / "recovery"
        ),
        providers,
        allow_credentials=os.environ.get("NEWSCLIP_KEEPER_ALLOW_CREDENTIAL_MINT")
        == "1",
        timeout=int(os.environ.get("NEWSCLIP_KEEPER_TIMEOUT_SECONDS", "900")),
    )
    try:
        while True:
            for outcome in watcher.tick():
                print(json.dumps(outcome), flush=True)
            time.sleep(30)
    finally:
        watcher.close()


if __name__ == "__main__":
    main()
