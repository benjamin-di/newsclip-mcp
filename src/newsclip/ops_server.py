"""The authenticated ops MCP surface: every repair verb, one tool call away.

Served only when ``NEWSCLIP_MCP_OPS=1`` — by the credentialed maintenance
container, never the public serving process (ARCHITECTURE, "MCP boundary").
Startup fails closed: the flag without a *dedicated* ops bearer and an op
service-account token refuses to serve, so a compose copy-paste cannot expose
repair tools behind the public bearer.

Every mutating verb shells out to the operator CLI rather than re-driving the
library in-process: ``auth keep`` (heal), ``auth login --import-stdin``
(session_promote), ``provider-guard`` (provider_check), and
``provider-guard-acknowledge`` (acknowledge_hold). The CLI already owns the
hard parts — virtual-display re-exec for browser mints, credential-budget
enforcement, atomic import-and-verify — and reusing it keeps this server a
thin authenticated adapter with the same behavior operators get over SSH.

``heal`` is asynchronous by design: a mint can run minutes, far beyond
gateway and client timeouts, so the tool returns immediately and the outcome
lands in ``health()`` (and durably in the keeper outcome store). One heal per
provider may be in flight; this is request-initiated bounded work, not a
scheduler.

Failures are native MCP tool errors (``isError: true``) that still carry the
structured ``{"ok": false, "category", ...}`` payload: a request the server
refuses and an operator command that fails with its closed error envelope.
A completed command's verdict (for example a guard check that finds a hold)
is a successful result, not an error.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
from typing import Annotated, Any

from pydantic import Field

from .errors import ProviderTransportError, TransportFailure
from .process_signals import TIMED_OUT_EXIT_STATUSES, under_timeout
from .provider_keys import PROVIDER_KEY_PATTERN
from .results import PublicErrorEnvelope, public_error

OPS_ENV = "NEWSCLIP_MCP_OPS"
OPS_BEARER_TOKEN_ENV = "NEWSCLIP_OPS_BEARER_TOKEN"
_OP_TOKEN_ENV = "OP_SERVICE_ACCOUNT_TOKEN"

#: The complete ops surface. The public serving instance never registers
#: these; the ops instance registers nothing else.
OPS_TOOLS = (
    "health",
    "heal",
    "provider_check",
    "session_promote",
    "acknowledge_hold",
)

OPS_SERVER_INSTRUCTIONS = (
    "Repair surface for newsclip providers. Use health for the one-call "
    "fleet overview (session freshness, defense cooldowns, holds, running "
    "heals, and the identity targets' holds, cooldowns and snapshot age; an "
    "identity hold is cleared only by the keeper's identity acknowledge, never "
    "by acknowledge_hold). heal starts one bounded repair for a provider and returns "
    "immediately; after a successful newer provider_check it can consume that "
    "proof for one credential-free exact recovery check. Poll health for its "
    "outcome. provider_check runs one guarded canary. session_promote imports "
    "a cookie export (raw JSON or an "
    "op:// reference) through the atomic import-and-verify path. "
    "acknowledge_hold compare-and-clears one explicitly identified hold and "
    "then runs one guarded follow-up canary so health has fresh evidence; a "
    "follow-up failure never un-acknowledges, and a durable failure honestly "
    "re-holds. Nothing here retries into a hold or bypasses cooldowns."
)

_MAX_COOKIE_BYTES = 1024 * 1024
_HEAL_TIMEOUT_SECONDS = 900.0
_CHECK_TIMEOUT_SECONDS = 600.0
_PROMOTE_TIMEOUT_SECONDS = 300.0
# The acknowledgement now carries a guarded follow-up canary (R10), so its
# budget is the check budget plus the clear itself.
_ACK_TIMEOUT_SECONDS = 630.0

ProviderKeyArg = Annotated[
    str,
    Field(
        min_length=1,
        max_length=32,
        pattern=PROVIDER_KEY_PATTERN,
        description="Configured provider key, e.g. wsj or ft.",
    ),
]


@dataclass(frozen=True)
class CommandOutcome:
    """The bounded result of one operator-CLI invocation."""

    exit_code: int
    stdout: str
    stderr: str = ""

    def payload(self) -> dict[str, Any]:
        """Parse the CLI's closed JSON line; never echo raw output on failure."""

        parsed = _last_json_object(self.stdout)
        if parsed is None:
            stderr = _last_json_object(self.stderr)
            try:
                envelope = PublicErrorEnvelope.model_validate(stderr)
            except (TypeError, ValueError):
                envelope = None
            if envelope is not None and envelope.exit_code == self.exit_code:
                return envelope.public_dict()
            parsed = {}
        parsed.setdefault("exit_code", self.exit_code)
        return parsed


def _last_json_object(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if not stripped:
        return None
    try:
        parsed = json.loads(stripped.splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _usage_failure(detail: str) -> dict[str, Any]:
    return {
        "ok": False,
        "category": "usage",
        "exit_code": 2,
        "message": "invalid request",
        "detail": detail,
    }


def _command_response(payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap a CLI payload; a closed error envelope is the tool's failure."""

    if payload.get("ok") is False:
        return payload
    return {"ok": True, "result": payload}


def _is_failure(structured: Any) -> bool:
    return isinstance(structured, dict) and structured.get("ok") is False


CommandRunner = Callable[[list[str], bytes | None, float], CommandOutcome]


def _run_cli(args: list[str], stdin: bytes | None, timeout: float) -> CommandOutcome:
    # A heal is the keeper's `auth keep`: bound it as recovery_watch does, so a
    # timeout also ends the browser it started.
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        under_timeout([sys.executable, "-m", "newsclip", *args], timeout),
        input=stdin,
        capture_output=True,
        check=False,
    )
    if completed.returncode in TIMED_OUT_EXIT_STATUSES:
        envelope = public_error(
            ProviderTransportError(
                "operator CLI timed out",
                category=TransportFailure.TIMEOUT,
            )
        )
        if envelope is None:  # pragma: no cover - closed classifier invariant
            raise AssertionError("timeout did not produce a public error envelope")
        return CommandOutcome(
            exit_code=envelope.exit_code,
            stdout=json.dumps(envelope.public_dict()),
        )
    return CommandOutcome(
        exit_code=completed.returncode,
        stdout=completed.stdout.decode("utf-8", "replace"),
        stderr=completed.stderr.decode("utf-8", "replace"),
    )


class OpsAdapter:
    """State and CLI plumbing behind the five ops tools."""

    def __init__(self, *, runner: CommandRunner | None = None) -> None:
        self._runner = runner or _run_cli
        self._executor = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="newsclip-ops-heal"
        )
        self._heals: dict[str, Future[CommandOutcome]] = {}
        self._last_heal: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    # -- heal ------------------------------------------------------------

    def start_heal(
        self,
        provider: str,
        *,
        allow_credential_mint: bool,
        ignore_escalation: bool = False,
    ) -> dict[str, Any]:
        with self._lock:
            running = self._heals.get(provider)
            if running is not None and not running.done():
                return {"provider": provider, "status": "in_progress"}
            args = [
                "auth",
                "keep",
                provider,
                "--json",
                "--reconcile-failed-recovery",
            ]
            if allow_credential_mint:
                args.append("--allow-credential-mint")
            if ignore_escalation:
                args.append("--ignore-escalation")
            future = self._executor.submit(
                self._runner, args, None, _HEAL_TIMEOUT_SECONDS
            )
            self._heals[provider] = future
        # Registered OUTSIDE the lock, deliberately. add_done_callback runs the
        # callback inline in this thread when the future has already finished —
        # and a heal can finish that fast (a held provider returns immediately).
        # _record_heal takes the same non-reentrant lock, so registering here
        # while holding it deadlocks the ops server permanently.
        future.add_done_callback(partial(self._record_heal, provider))
        return {"provider": provider, "status": "started"}

    def _record_heal(self, provider: str, done: Future[CommandOutcome]) -> None:
        try:
            payload = done.result().payload()
        except Exception as error:  # noqa: BLE001 - recorded, never raised here
            payload = {"error": type(error).__name__}
        with self._lock:
            self._last_heal[provider] = payload

    def heal_state(self, provider: str) -> dict[str, Any] | None:
        with self._lock:
            running = self._heals.get(provider)
            if running is not None and not running.done():
                return {"status": "in_progress"}
            last = self._last_heal.get(provider)
            if last is not None:
                return {"status": "completed", "result": last}
        return None

    # -- synchronous CLI verbs ------------------------------------------

    def provider_check(self, provider: str) -> dict[str, Any]:
        return self._runner(
            ["provider-guard", "--provider", provider, "--json"],
            None,
            _CHECK_TIMEOUT_SECONDS,
        ).payload()

    def promote(self, provider: str, payload: bytes) -> dict[str, Any]:
        return self._runner(
            ["auth", "login", provider, "--import-stdin", "--json"],
            payload,
            _PROMOTE_TIMEOUT_SECONDS,
        ).payload()

    def acknowledge(self, provider: str, hold_id: str) -> dict[str, Any]:
        return self._runner(
            [
                "provider-guard-acknowledge",
                "--provider",
                provider,
                "--hold-id",
                hold_id,
                "--json",
            ],
            None,
            _ACK_TIMEOUT_SECONDS,
        ).payload()

    # -- health ----------------------------------------------------------

    def health(self):
        from .tenancy import user_scope

        with user_scope(os.environ.get("NEWSCLIP_USER") or None):
            return self._health()

    def _health(self) -> dict[str, Any]:
        """The shared fleet snapshot plus this process's in-flight heals.

        The snapshot itself is `health.collect_fleet_health`, the same call
        the CLI `health` command makes — one implementation, so an operator
        over SSH and an agent over MCP never get divergent answers.
        """

        from .health import collect_fleet_health

        fleet = collect_fleet_health()
        providers: list[dict[str, Any]] = []
        for entry in fleet.providers:
            payload = entry.public_dict()
            # Heal state is process-local (this server owns the futures), so
            # it is layered on here rather than in the shared snapshot.
            payload["heal"] = self.heal_state(entry.provider)
            providers.append(payload)
        return {"providers": providers}


def _require_ops_environment(*, public_token: str | None) -> str:
    """Fail-closed gate for serving the ops surface at all."""

    ops_token = os.environ.get(OPS_BEARER_TOKEN_ENV, "").strip()
    if not ops_token:
        raise ValueError(f"{OPS_ENV}=1 requires a dedicated {OPS_BEARER_TOKEN_ENV}")
    if public_token and ops_token == public_token.strip():
        raise ValueError(f"{OPS_BEARER_TOKEN_ENV} must differ from the public bearer")
    return ops_token


def build_ops_app(public_token: str | None = None):
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    from .mcp_server import BearerAuthMiddleware, _http_app

    token = _require_ops_environment(public_token=public_token)
    server = build_ops_server()

    @server.custom_route("/health", methods=["GET"], include_in_schema=False)
    async def health(_request: Request):
        return JSONResponse({"status": "ok", "service": "newsclip-ops"})

    return BearerAuthMiddleware(_http_app(server), token)


def _error_result_middleware() -> Any:
    """Mark ``{"ok": false}`` results as native tool errors (``isError``).

    The structured payload is kept, so a client that reads the envelope sees
    the same fields, and one that honours ``isError`` (a FastMCP ``Client``
    raises by default) cannot mistake a failure for success.
    """

    from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
    from fastmcp.tools.base import ToolResult

    class ErrorResultMiddleware(Middleware):
        async def on_call_tool(
            self, context: MiddlewareContext, call_next: CallNext
        ) -> Any:
            result = await call_next(context)
            if (
                isinstance(result, ToolResult)
                and not result.is_error
                and _is_failure(result.structured_content)
            ):
                result.is_error = True
            return result

    return ErrorResultMiddleware()


def build_ops_server(adapter: OpsAdapter | None = None):
    """Register exactly the five ops tools on a FastMCP server."""

    import anyio
    from mcp.types import ToolAnnotations

    from .mcp_server import new_fastmcp

    ops = adapter or OpsAdapter()
    server = new_fastmcp("newsclip-ops", instructions=OPS_SERVER_INSTRUCTIONS)
    server.add_middleware(_error_result_middleware())

    @server.tool(
        title="Provider fleet health",
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
    )
    async def health() -> dict[str, Any]:
        """Session freshness, defense cooldowns, holds, readiness, and heals.

        The health snapshot contains only configured provider state.
        Reads stored state only; contacts no provider.
        """

        return {
            "ok": True,
            "result": await anyio.to_thread.run_sync(ops.health),
        }

    @server.tool(
        title="Start one bounded repair",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    async def heal(
        provider: ProviderKeyArg,
        allow_credential_mint: bool = True,
        ignore_escalation: bool = False,
    ) -> dict[str, Any]:
        """Start `auth keep` semantics for one provider and return immediately.

        Stored-state first, hold- and cooldown-honoring, at most one credential
        mint per budget window. After a newer successful `provider_check`, it
        may also recheck the exact URL from a failed recovery once without
        credentials. Poll `health` for the outcome.

        Set `ignore_escalation` after repairing what caused a run of
        inconclusive probes. Only a renewal clears that escalation and the
        escalation stops the keeper renewing, so a repair is otherwise
        unprovable. It relaxes nothing else: holds, cooldowns, readiness and
        the credential budget all still apply.
        """

        return {
            "ok": True,
            "result": ops.start_heal(
                provider,
                allow_credential_mint=allow_credential_mint,
                ignore_escalation=ignore_escalation,
            ),
        }

    @server.tool(
        title="Run one guarded canary",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    async def provider_check(provider: ProviderKeyArg) -> dict[str, Any]:
        """One bounded guard check; never logs in, never retries into a hold."""

        return _command_response(
            await anyio.to_thread.run_sync(ops.provider_check, provider)
        )

    @server.tool(
        title="Promote a session from a cookie export",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    async def session_promote(
        provider: ProviderKeyArg,
        cookies_json: Annotated[
            str | list[Any] | dict[str, Any] | None,
            Field(
                default=None,
                description=(
                    "Cookie-Editor/Playwright JSON export, as a JSON string or "
                    "the parsed array/object. Persists in the calling agent's "
                    "conversation log — prefer op_reference for sensitive "
                    "sessions."
                ),
            ),
        ] = None,
        op_reference: Annotated[
            str | None,
            Field(
                default=None,
                pattern=r"^op://[^\s]+$",
                description=(
                    "1Password secret reference resolved inside this process, "
                    "so the export never enters a conversation."
                ),
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Atomic import-and-verify; a failed candidate never replaces the
        prior verified generation."""

        if (cookies_json is None) == (op_reference is None):
            return _usage_failure("provide exactly one of cookies_json or op_reference")
        if op_reference is not None:
            from .secret_reference import OpSecretReader, SecretResolutionError

            try:
                cookies_json = OpSecretReader().read(op_reference)
            except SecretResolutionError:
                return {
                    "ok": False,
                    "category": "operator_action",
                    "exit_code": 3,
                    "message": "operator action required",
                    "detail": "the op reference could not be resolved",
                }
        assert cookies_json is not None
        # MCP transports (and FastMCP's own pre-parse of JSON-looking string
        # arguments) may deliver the export already decoded, so accept both
        # shapes and hand the CLI the JSON text it reads on stdin.
        if not isinstance(cookies_json, str):
            cookies_json = json.dumps(cookies_json)
        payload = cookies_json.encode("utf-8")
        if len(payload) > _MAX_COOKIE_BYTES:
            return _usage_failure("cookie payload exceeds 1 MiB")
        return _command_response(
            await anyio.to_thread.run_sync(ops.promote, provider, payload)
        )

    @server.tool(
        title="Acknowledge one identified hold",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    async def acknowledge_hold(
        provider: ProviderKeyArg,
        hold_id: Annotated[
            str,
            Field(
                min_length=6,
                max_length=128,
                pattern=r"^guard-[0-9a-f]+$",
                description="The exact hold id reported by the guard.",
            ),
        ],
    ) -> dict[str, Any]:
        """Compare-and-clear, then one guarded follow-up canary (R10).

        A stale id cannot clear a newer hold. After a successful clear the
        result carries the follow-up check so health holds fresh serving
        evidence; a follow-up failure is reported beside the acknowledgement
        and never un-acknowledges it.
        """

        return _command_response(
            await anyio.to_thread.run_sync(ops.acknowledge, provider, hold_id)
        )

    return server


__all__ = [
    "OPS_BEARER_TOKEN_ENV",
    "OPS_ENV",
    "OPS_SERVER_INSTRUCTIONS",
    "OPS_TOOLS",
    "CommandOutcome",
    "CommandRunner",
    "OpsAdapter",
    "build_ops_server",
    "_require_ops_environment",
]
