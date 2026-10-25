"""Typer adapter for the synchronous Newsclip core."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sys
from collections.abc import Callable
from contextlib import suppress
from contextvars import ContextVar
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Annotated
from uuid import uuid4

if __name__ == "__main__":
    sys.modules.setdefault("newsclip.cli", sys.modules[__name__])

import typer
from click import echo_via_pager
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .acquisition import (
    AcquisitionMode,
    ChallengeMode,
    LoginResult,
    MintFailureCategory,
    MintFailureStage,
)
from .browser_runtime import (
    BrowserRuntimeError,
    display_is_usable,
    docker_cli_usable,
    maybe_reexec_for_virtual_display,
)
from .client import NewsclipClient
from .composition import (
    build_auth_service as _local_auth_service,
)
from .composition import (
    build_provider_guard,
    build_registry,
    build_session_keeper,
)
from .composition import (
    build_service as _local_service,
)
from .drift import DriftReport
from .errors import (
    ContentNotFullError,
    NewsclipError,
    OperatorActionRequiredError,
    PersistenceError,
    ProviderDefenseError,
    ProviderTransportError,
    TransportFailure,
    UnsearchableQueryError,
    UsageError,
)
from .health import FleetHealth, collect_fleet_health
from .models import (
    ArchiveBackupResult,
    ArchiveIntegrity,
    Article,
    DoctorReport,
    ProviderReadiness,
    SearchFilters,
    SearchResponse,
    SearchSort,
    SessionCheckpoint,
    SessionHealth,
    SessionStatus,
    SourceSearchReason,
    SourceSearchState,
)
from .provider_check import ProviderCheckResult
from .provider_guard import (
    AcknowledgementReport,
    GuardAction,
    GuardResult,
    ProviderGuardPersistenceError,
)
from .provider_readiness import browser_engine_available
from .providers.builtins import (
    BUILTIN_PROVIDER_KEYS_CSV,
    BUILTIN_PROVIDER_KEYS_PROSE,
    BUILTIN_PROVIDER_REGISTRATIONS,
)
from .results import (
    PublicErrorCategory,
    PublicErrorEnvelope,
    public_error,
    public_value,
)
from .service import FederatedSearchPager, NewsclipService, _ordered_search_batch
from .session_keeper import KeeperPolicy, KeeperResult
from .tenancy import add_proxy_user, add_user, user_scope

Service = NewsclipService | NewsclipClient
_CLIENT: ContextVar[NewsclipClient | None] = ContextVar(
    "newsclip_cli_client", default=None
)


def _remote_client() -> NewsclipClient | None:
    return _CLIENT.get()


def build_service() -> Service:
    return _remote_client() or _local_service()


def build_auth_service() -> Service:
    return _remote_client() or _local_auth_service()


_MAX_COOKIE_IMPORT_BYTES = 1024 * 1024

app = typer.Typer(
    name="newsclip",
    help="Retrieve and privately archive news from supported providers.",
    epilog=(
        'Examples: newsclip search "bank capital"; newsclip save URL; '
        "newsclip auth status ft. "
        f"Built-in providers: {BUILTIN_PROVIDER_KEYS_CSV}."
    ),
    invoke_without_command=True,
    no_args_is_help=False,
)
auth_app = typer.Typer(
    help="Inspect or repair provider authentication.",
    no_args_is_help=True,
)
app.add_typer(auth_app, name="auth")
users_app = typer.Typer(
    help="Manage standalone server users and access tokens.", no_args_is_help=True
)
app.add_typer(users_app, name="users")
ProviderArgument = Annotated[
    str,
    typer.Argument(help=f"Provider key; built-ins are {BUILTIN_PROVIDER_KEYS_PROSE}."),
]


def _version_callback(value: bool) -> None:
    if value:
        from . import __version__

        typer.echo(__version__)
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
    server: str | None = typer.Option(
        None,
        "--server",
        envvar="NEWSCLIP_URL",
        help="User server URL, including /users/USER.",
    ),
    token_file: Annotated[
        Path | None,
        typer.Option(
            "--token-file",
            envvar="NEWSCLIP_TOKEN_FILE",
            help="Private file holding your server token.",
        ),
    ] = None,
    user: str | None = typer.Option(
        None,
        "--user",
        envvar="NEWSCLIP_USER",
        help="Select local user storage. Remote identity comes from the server token.",
    ),
) -> None:
    """Retrieve and privately archive news from supported providers."""

    if server:
        if user:
            raise typer.BadParameter(
                "--user selects local storage; "
                "the server URL and token select a remote user"
            )
        try:
            token = (
                token_file.expanduser().read_text().strip()
                if token_file
                else os.environ.get("NEWSCLIP_TOKEN", "")
            )
            ctx.obj = NewsclipClient(server, token)
        except (OSError, UsageError) as error:
            raise typer.BadParameter(
                "configure a valid server URL and readable token file"
            ) from error
        ctx.call_on_close(ctx.obj.close)
        client_context = _CLIENT.set(ctx.obj)
        ctx.call_on_close(lambda: _CLIENT.reset(client_context))
    try:
        ctx.with_resource(user_scope(user))
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    _prepare_timing_invocation()
    if ctx.invoked_subcommand is None:
        _execute(
            lambda: _search_workflow(
                query=None,
                sources=(),
                filters=SearchFilters(),
                select=None,
                save_selected=True,
                json_output=False,
            ),
            json_output=False,
            emit_result=False,
        )


def _prepare_timing_invocation() -> None:
    owner = os.environ.get("NEWSCLIP_INVOCATION_OWNER_PID")
    current_pid = str(os.getpid())
    if "NEWSCLIP_INVOCATION_ID" not in os.environ or owner == current_pid:
        os.environ["NEWSCLIP_INVOCATION_ID"] = f"cli-{uuid4().hex}"
        os.environ["NEWSCLIP_INVOCATION_OWNER_PID"] = current_pid


@app.command("login", hidden=True)
@auth_app.command("login")
def login(
    provider: ProviderArgument,
    headless: bool = typer.Option(
        True,
        help=(
            "When a browser is needed, use headed Chromium on a managed virtual "
            "display. --no-headless explicitly uses the current desktop display."
        ),
    ),
    challenge_mode: Annotated[
        ChallengeMode,
        typer.Option(
            "--challenge-mode",
            help=(
                "'auto' runs bounded provider challenge handling; 'detect-only' "
                "stops for operator action."
            ),
        ),
    ] = ChallengeMode.AUTO,
    import_cookies: Annotated[
        Path | None,
        typer.Option(
            "--import-cookies",
            exists=True,
            dir_okay=False,
            readable=True,
            help="Import a Cookie-Editor or Playwright cookie JSON file.",
        ),
    ] = None,
    import_cookies_stdin: bool = typer.Option(
        False,
        "--import-stdin",
        help="Import cookie JSON from a non-interactive standard-input pipe.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    quiet: bool = typer.Option(False, "--quiet", hidden=True),
) -> None:
    """Ensure a verified session, reusing warm state before credentials."""

    if _remote_client() is not None:
        if import_cookies is not None or import_cookies_stdin:
            raise typer.BadParameter(
                "remote sign-in uses auth connect; import cookies locally on the server"
            )
        auth_connect(provider, json_output=json_output)
        return

    def action() -> LoginResult | SessionHealth:
        if import_cookies is not None and import_cookies_stdin:
            raise UsageError("choose either --import-cookies or --import-stdin")
        service = build_auth_service()
        if (
            import_cookies_stdin
            and headless
            and service.requires_browser_for_provider(provider)
        ):
            # Prepare/re-exec before consuming the pipe. The child inherits the
            # unread descriptor; consuming first would leave browser imports at EOF.
            _prepare_virtual_display(sys.argv, child_owns_invocation=True)
        if import_cookies is not None:
            payload = _read_cookie_payload(import_cookies)
        elif import_cookies_stdin:
            payload = _read_cookie_payload_stdin()
        else:
            payload = None

        def prepare_browser() -> None:
            _prepare_virtual_display(sys.argv, child_owns_invocation=True)

        return service.login(
            provider,
            headless=headless,
            cookie_payload=payload,
            challenge_mode=challenge_mode,
            before_browser=(prepare_browser if headless else None),
        )

    _execute(
        action,
        json_output=json_output,
        emit_result=not quiet,
        human_renderer=lambda value: _render_login_result(
            value,
            imported=import_cookies is not None or import_cookies_stdin,
        ),
    )


@auth_app.command("connect")
def auth_connect(
    provider: ProviderArgument,
    json_output: bool = typer.Option(
        False, "--json", help="Emit the sign-in link as JSON."
    ),
) -> None:
    """Create an expiring link to sign in yourself on the publisher's page."""

    def action():
        client = _remote_client()
        if client is None:
            raise UsageError(
                "configure --server and --token-file, then run auth connect"
            )
        return client.connect(provider)

    _execute(
        action,
        json_output=json_output,
        human_renderer=lambda value: typer.echo(
            f"Open this link to sign in:\n{value.url}\n"
            f"Expires: {value.expires_at.isoformat()}"
        ),
    )


@users_app.command("add")
def users_add(
    name: Annotated[str, typer.Argument(help="A lowercase user id.")],
    config: Annotated[
        Path, typer.Option("--config", help="Server user registry path.")
    ],
    token_file: Annotated[
        Path,
        typer.Option(
            "--token-file", help="Write the generated token to a new private file."
        ),
    ],
    rotate: bool = typer.Option(
        False, "--rotate", help="Replace this user's existing token."
    ),
) -> None:
    """Create a user or rotate their token without printing secrets."""

    try:
        add_user(config.expanduser(), name, token_file.expanduser(), rotate=rotate)
    except (OSError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    typer.echo(
        f"User {name} configured. Token written to {token_file}. "
        "Restart the server after adding users."
    )


@users_app.command("add-proxy")
def users_add_proxy(
    name: Annotated[str, typer.Argument(help="A lowercase trusted-proxy user id.")],
    config: Annotated[
        Path, typer.Option("--config", help="Server user registry path.")
    ],
) -> None:
    """Register a proxy identity without creating a native bearer credential."""

    try:
        add_proxy_user(config.expanduser(), name)
    except (OSError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    typer.echo(f"Proxy user {name} configured. Restart the server after adding users.")


@app.command("serve")
def serve(
    users_file: Annotated[
        Path,
        typer.Option(
            "--users-file",
            envvar="NEWSCLIP_USERS_FILE",
            help="User registry containing token hashes.",
        ),
    ],
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port", min=1, max=65535),
) -> None:
    """Run the standalone multi-user HTTP, MCP and sign-in relay server."""

    from .standalone import run_server

    os.environ["NEWSCLIP_USERS_FILE"] = str(users_file.expanduser())
    run_server(host=host, port=port)


@app.command("signin-service")
def signin_service(
    users_file: Annotated[
        Path, typer.Option("--users-file", envvar="NEWSCLIP_USERS_FILE")
    ],
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8080, "--port", min=1, max=65535),
) -> None:
    """Run the private browser service used by human sign-in links."""

    from .signin import run_signin_service

    os.environ["NEWSCLIP_USERS_FILE"] = str(users_file.expanduser())
    run_signin_service(host=host, port=port)


@auth_app.command("keep")
def auth_keep(
    provider: ProviderArgument,
    allow_credential_mint: bool = typer.Option(
        False,
        "--allow-credential-mint",
        help=(
            "Permit one unattended credential submission when warm renewal "
            "cannot recover the session and this host can complete the login."
        ),
    ),
    max_age_hours: float = typer.Option(
        12.0,
        "--max-age-hours",
        min=0.0001,
        help="Renew a verified session once it is at least this old.",
    ),
    ignore_escalation: bool = typer.Option(
        False,
        "--ignore-escalation",
        help=(
            "Attempt renewal even where a run of inconclusive probes has "
            "escalated to operator action. Use after fixing the cause: only a "
            "renewal clears the escalation, so without this the fix cannot be "
            "proven. Scheduled cycles must not set it."
        ),
    ),
    recovery_only: bool = typer.Option(
        False,
        "--recovery-only",
        help="Consume pending recovery only; never probe healthy providers.",
    ),
    reconcile_failed_recovery: bool = typer.Option(
        False,
        "--reconcile-failed-recovery",
        hidden=True,
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit closed JSON."),
) -> None:
    """Run one scheduled upkeep step for one provider."""

    completed: list[KeeperResult] = []

    def action() -> KeeperResult:
        service = build_auth_service()
        try:
            if isinstance(service, NewsclipClient):
                raise UsageError("run session upkeep locally on the server")
            keeper = build_session_keeper(
                service,
                policy=KeeperPolicy(max_age_hours=max_age_hours),
            )
            if service.requires_browser_for_provider(provider):
                _prepare_virtual_display(sys.argv, child_owns_invocation=True)
            result = keeper.keep(
                provider,
                allow_credential_mint=allow_credential_mint,
                ignore_escalation=ignore_escalation,
                recovery_only=recovery_only,
                reconcile_failed_recovery=reconcile_failed_recovery,
            )
        finally:
            service.close()
        completed.append(result)
        return result

    _execute(
        action,
        json_output=json_output,
        human_renderer=_render_keeper_result,
    )
    # A deliberate wait is not a failure; only an outcome needing a person is.
    if completed and completed[0].needs_attention:
        raise typer.Exit(code=1)


_ACKNOWLEDGE_LEASE_SECONDS = 10.0


@app.command()
def health(
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Report article serving and session renewal evidence for every provider.

    The same snapshot the ops MCP `health` tool returns. Reads stored state
    only: no provider is contacted and no session is touched.
    """

    _execute(
        collect_fleet_health,
        json_output=json_output,
        human_renderer=_render_fleet_health,
    )


@app.command("session-status", hidden=True)
@auth_app.command("status")
def session_status(
    provider: ProviderArgument,
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Show redacted provider session health."""

    _execute(
        lambda: build_auth_service().session_status(provider),
        json_output=json_output,
        human_renderer=_render_session_health,
    )


@app.command("provider-check")
def provider_check(
    provider: Annotated[
        str,
        typer.Option(
            "--provider",
            help=f"Provider key; built-ins are {BUILTIN_PROVIDER_KEYS_PROSE}.",
        ),
    ],
    json_output: bool = typer.Option(False, "--json", help="Emit closed JSON."),
) -> None:
    """Run one credential-free, archive-free provider health sequence."""

    completed: list[ProviderCheckResult] = []

    def action() -> ProviderCheckResult:
        service = build_auth_service()
        try:
            if service.requires_browser_for_provider(provider):
                _prepare_virtual_display(sys.argv, child_owns_invocation=True)
            result = service.provider_check(provider)
            completed.append(result)
            return result
        finally:
            service.close()

    _execute(
        action,
        json_output=json_output,
        human_renderer=_render_provider_check,
    )
    if completed and not completed[0].ok:
        raise typer.Exit(code=1)


@app.command("provider-guard")
def provider_guard(
    provider: Annotated[
        str,
        typer.Option(
            "--provider",
            help=f"Provider key; built-ins are {BUILTIN_PROVIDER_KEYS_PROSE}.",
        ),
    ],
    scheduled: bool = typer.Option(
        False,
        "--scheduled",
        help=(
            "Identify this invocation as the scheduled monitor, which an "
            "incident-review hold permits one bounded canary per 24h (R9). "
            "On-demand checks omit this and keep the held short-circuit."
        ),
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit closed JSON."),
) -> None:
    """Run one contained provider check or return its existing hold."""

    completed: list[GuardResult] = []

    def action() -> GuardResult:
        try:
            guard = build_provider_guard()
        except Exception as error:
            if public_error(error) is not None:
                raise
            raise PersistenceError("provider guard initialization failed") from error

        # An existing hold is reported without constructing the provider
        # service. Otherwise the virtual display is prepared before the guard
        # lock is taken: preparation re-executes this same command, and the
        # child cannot acquire a lock its own parent is still holding.
        opened: Service | None = None
        try:
            try:
                current = guard.peek_before_check(provider)
                # A scheduled invocation may contact the provider under an
                # incident-review hold (the R9 canary), so it prepares for
                # that case too — but only when the canary is actually due,
                # so an hourly scheduler does not pay for a browser the
                # guard will suppress. Every other hold still never pays
                # for a browser it cannot use.
                may_contact = current is None or (
                    scheduled
                    and current.action is GuardAction.INCIDENT_REVIEW_REQUIRED
                    and guard.incident_canary_due(provider)
                )
            except ProviderGuardPersistenceError:
                # Contended or unreadable: guard.run owns that verdict and
                # needs no browser, so prepare nothing and let it classify.
                may_contact = False
            if may_contact:
                opened = build_auth_service()
                if opened.requires_browser_for_provider(provider):
                    _prepare_virtual_display(sys.argv, child_owns_invocation=True)

            def check_provider() -> ProviderCheckResult:
                nonlocal opened
                if opened is None:
                    opened = build_auth_service()
                try:
                    return opened.provider_check(provider)
                except Exception as error:
                    if public_error(error) is not None:
                        raise
                    raise ProviderTransportError(
                        "provider guard check failed"
                    ) from error

            try:
                if scheduled:
                    result = guard.run_incident_review_canary(provider, check_provider)
                else:
                    result = guard.run(provider, check_provider)
            except Exception as error:
                if public_error(error) is not None:
                    raise
                raise PersistenceError("provider guard execution failed") from error
        finally:
            if opened is not None:
                opened.close()
        completed.append(result)
        return result

    _execute(
        action,
        json_output=json_output,
        human_renderer=_render_guard_result,
    )
    if completed and completed[0].action is not GuardAction.HEALTHY:
        raise typer.Exit(code=1)


@app.command("provider-guard-acknowledge")
def provider_guard_acknowledge(
    provider: Annotated[
        str,
        typer.Option(
            "--provider",
            help=f"Provider key; built-ins are {BUILTIN_PROVIDER_KEYS_PROSE}.",
        ),
    ],
    hold_id: str = typer.Option(
        ...,
        "--hold-id",
        help="Exact opaque hold identifier reported by provider-guard.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit closed JSON."),
) -> None:
    """Acknowledge a held provider, then re-measure it once (R10)."""

    completed: list[AcknowledgementReport] = []

    def action() -> AcknowledgementReport:
        try:
            guard = build_provider_guard()
        except Exception as error:
            if public_error(error) is not None:
                raise
            raise PersistenceError("provider guard initialization failed") from error

        opened: Service | None = None
        try:
            # Prepare the display before the compare-and-clear when the
            # follow-up will need a browser: preparation re-executes this
            # whole command, and a re-exec after the clear would re-run the
            # acknowledgement against a hold that no longer exists. The peek
            # only decides preparation; the acknowledgement itself remains
            # the locked compare-and-clear. A contended or unreadable peek
            # still prepares — a wasted preparation is harmless, while a
            # skipped one silently costs the follow-up its browser.
            try:
                current = guard.peek(provider)
                matched = current is not None and current.hold_id == hold_id
            except ProviderGuardPersistenceError:
                matched = True
            if matched:
                opened = build_auth_service()
                if opened.requires_browser_for_provider(provider):
                    # A host that cannot supply a display must not turn an
                    # acknowledgement into a failed command: the clear
                    # proceeds and the follow-up fails closed into
                    # follow_up_error. typer.Exit (the re-exec parent) is
                    # deliberately not suppressed.
                    with suppress(ProviderTransportError):
                        _prepare_virtual_display(sys.argv, child_owns_invocation=True)

            def check_provider() -> ProviderCheckResult:
                nonlocal opened
                if opened is None:
                    opened = build_auth_service()
                try:
                    return opened.provider_check(provider)
                except Exception as error:
                    if public_error(error) is not None:
                        raise
                    raise ProviderTransportError(
                        "provider guard check failed"
                    ) from error

            result = guard.acknowledge_and_check(
                provider,
                hold_id=hold_id,
                check_provider=check_provider,
            )
        finally:
            if opened is not None:
                opened.close()
        completed.append(result)
        return result

    _execute(
        action,
        json_output=json_output,
        human_renderer=_render_acknowledgement_report,
    )
    if completed and not completed[0].acknowledgement.acknowledged:
        raise typer.Exit(code=1)


@app.command("session-checkpoint", hidden=True)
@auth_app.command("checkpoint")
def session_checkpoint(
    provider: ProviderArgument,
    minimum_age_hours: float = typer.Option(
        0,
        "--minimum-age-hours",
        min=0,
        help="Fail unless this session generation is at least this old.",
    ),
    expected_generation: str | None = typer.Option(
        None,
        "--expected-generation",
        help="Fail unless the redacted generation fingerprint matches.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Verify a stored session and emit redacted durability evidence."""

    def action() -> SessionCheckpoint:
        service = build_auth_service()
        if service.requires_browser_for_provider(provider):
            _prepare_virtual_display(sys.argv, child_owns_invocation=True)
        return service.session_checkpoint(
            provider,
            minimum_age_hours=minimum_age_hours,
            expected_generation_fingerprint=expected_generation,
        )

    _execute(
        action,
        json_output=json_output,
        human_renderer=_render_session_checkpoint,
    )


@app.command("session-reset", hidden=True)
@auth_app.command("reset")
def session_reset(
    provider: ProviderArgument,
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Clear a terminal/cooldown state before another explicit login."""

    _execute(
        lambda: build_auth_service().session_reset(provider),
        json_output=json_output,
        human_renderer=lambda value: _render_session_action(
            value, "session state reset"
        ),
    )


@app.command("session-clear", hidden=True)
@auth_app.command("clear")
def session_clear(
    provider: ProviderArgument,
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Explicitly discard a provider session and its failure state."""

    _execute(
        lambda: build_auth_service().session_clear(provider),
        json_output=json_output,
        human_renderer=lambda value: _render_session_action(value, "session cleared"),
    )


@app.command("session-acknowledge", hidden=True)
@auth_app.command("acknowledge")
def session_acknowledge(
    provider: ProviderArgument,
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Acknowledge a terminal/cooldown result without reading credentials."""

    _execute(
        lambda: build_auth_service().session_acknowledge(provider),
        json_output=json_output,
        human_renderer=lambda value: _render_session_action(
            value, "session result acknowledged"
        ),
    )


@app.command("browser-profile-reset", hidden=True)
@auth_app.command("reset-profile")
def browser_profile_reset(
    provider: ProviderArgument,
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Explicitly discard only a provider's retained browser profile."""

    _execute(
        lambda: build_auth_service().browser_profile_reset(provider),
        json_output=json_output,
        human_renderer=lambda value: _render_session_action(
            value, "browser profile reset"
        ),
    )


@app.command(context_settings={"allow_extra_args": True})
def search(
    ctx: typer.Context,
    query: Annotated[str, typer.Argument(help="Words to search for.")],
    sources: Annotated[
        list[str] | None,
        typer.Option(
            "--source",
            "-s",
            help="Search only this provider; repeat to select several.",
        ),
    ] = None,
    limit: int = typer.Option(
        20,
        min=1,
        max=100,
        help="Maximum results to load per page.",
    ),
    published_after: Annotated[
        str | None,
        typer.Option(
            help="Include results at/after this ISO-8601 timestamp with timezone."
        ),
    ] = None,
    published_before: Annotated[
        str | None,
        typer.Option(
            help="Include results at/before this ISO-8601 timestamp with timezone."
        ),
    ] = None,
    sort_order: Annotated[
        SearchSort,
        typer.Option(
            "--sort",
            help=(
                "Result order: 'balanced' preserves the fair provider-rank merge; "
                "'newest' reorders only each loaded page by publication time."
            ),
        ),
    ] = SearchSort.BALANCED,
    select: Annotated[
        int | None,
        typer.Option(
            min=1,
            help="Open this 1-based result directly without prompting.",
        ),
    ] = None,
    no_save: bool = typer.Option(
        False,
        "--no-save",
        help="Read the selected article without adding it to the archive.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Search all enabled providers, then optionally choose an article."""

    interactive = _interactive_terminal() and not json_output and select is None

    def action() -> SearchResponse | Article | None:
        selected_sources = tuple(sources or ())
        resolved_query = query
        if ctx.args:
            if len(ctx.args) != 1 or selected_sources:
                raise UsageError("invalid search arguments")
            selected_sources = (query,)
            resolved_query = ctx.args[0]
            if not json_output:
                typer.echo(
                    "warning: provider-first search syntax is deprecated; use --source",
                    err=True,
                )
        return _search_workflow(
            query=resolved_query,
            sources=selected_sources,
            filters=SearchFilters(
                limit=limit,
                published_after=_aware_timestamp(published_after),
                published_before=_aware_timestamp(published_before),
                sort=sort_order,
            ),
            select=select,
            save_selected=not no_save,
            json_output=json_output,
        )

    _execute(
        action,
        json_output=json_output,
        show_article_body=select is not None,
        emit_result=json_output or select is not None or not interactive,
    )


@app.command()
def doctor(
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Check enabled providers and browser-display prerequisites."""

    def action() -> DoctorReport:
        client = _remote_client()
        if client is not None:
            return client.doctor()
        registry = build_registry()
        providers = tuple(provider.key for provider in registry)
        browser_providers = tuple(
            provider.key
            for provider in registry
            if provider.login_recipe is not None
            or provider.capabilities.retrieval_transport == "browser"
            or provider.capabilities.search_transport == "browser"
            or bool(
                BUILTIN_PROVIDER_REGISTRATIONS[provider.key].approved_challenge_vendors
            )
        )
        virtual_display_active = (
            os.environ.get("NEWSCLIP_VIRTUAL_DISPLAY") == "1" and display_is_usable()
        )
        host_xvfb_available = shutil.which("Xvfb") is not None
        docker_fallback_available = bool(shutil.which("bwrap") and docker_cli_usable())
        readiness: list[ProviderReadiness] = []
        for provider in registry:
            probe = BUILTIN_PROVIDER_REGISTRATIONS[
                provider.key
            ].check_credential_readiness
            if probe is not None:
                readiness.append(probe())
        return DoctorReport(
            providers=providers,
            browser_providers=browser_providers,
            provider_readiness=tuple(readiness),
            browser_engine_available=browser_engine_available(),
            virtual_display_active=virtual_display_active,
            host_xvfb_available=host_xvfb_available,
            docker_fallback_available=docker_fallback_available,
        )

    _execute(
        action,
        json_output=json_output,
        human_renderer=_render_doctor_report,
    )


@app.command("get")
def get_article(
    url: Annotated[
        str,
        typer.Argument(help="Article URL from a supported provider."),
    ],
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Retrieve one verified full article without archiving it."""

    def action() -> Article:
        service = build_service()
        if service.requires_browser_for_url(url):
            _prepare_virtual_display(sys.argv, child_owns_invocation=True)
        return service.get(
            url,
            acquire_session=_session_acquirer(
                service,
                json_output=json_output,
            ),
        )

    _execute(
        action,
        json_output=json_output,
        show_article_body=True,
    )


@app.command()
def save(
    url: Annotated[
        str,
        typer.Argument(help="Article URL from a supported provider."),
    ],
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="Also write the committed article as Markdown at this path.",
        ),
    ] = None,
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Retrieve, archive, and optionally export one verified full article."""

    def action() -> Article:
        service = build_service()
        if service.requires_browser_for_url(url):
            _prepare_virtual_display(sys.argv, child_owns_invocation=True)
        article = service.save(
            url,
            out=out,
            acquire_session=_session_acquirer(
                service,
                json_output=json_output,
            ),
        )
        return article

    _execute(
        action,
        json_output=json_output,
        human_renderer=lambda article: _render_article_action(
            article,
            action="Saved",
            markdown_path=out,
        ),
    )


@app.command("archive-search")
def archive_search(
    query: Annotated[str, typer.Argument(help="Words to find in the archive.")],
    provider: str | None = typer.Option(
        None,
        help="Limit results to one provider key.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Search current accepted archive revisions offline."""

    _execute(
        lambda: build_service().archive_search(query, provider=provider),
        json_output=json_output,
        human_renderer=lambda articles: _render_archive_search(articles, query=query),
    )


@app.command("archive-get")
def archive_get(
    article_id: Annotated[
        str, typer.Argument(help="Article id returned by save or archive-search.")
    ],
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Read a previously saved article without contacting its publisher."""

    _execute(
        lambda: build_service().archive_get(article_id),
        json_output=json_output,
        show_article_body=True,
    )


@app.command()
def reextract(
    article_id: Annotated[
        str,
        typer.Argument(help="Archive ID shown by save or archive-search."),
    ],
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Re-extract an article from archived raw bytes only."""

    _execute(
        lambda: build_service().reextract(article_id),
        json_output=json_output,
        human_renderer=lambda article: _render_article_action(
            article,
            action="Re-extracted",
        ),
    )


@app.command("archive-integrity")
def archive_integrity(
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Run SQLite integrity and foreign-key checks."""

    _execute(
        lambda: build_service().archive_integrity(),
        json_output=json_output,
        human_renderer=_render_archive_integrity,
    )


@app.command("archive-rebuild-fts")
def archive_rebuild_fts(
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Rebuild FTS solely from current accepted extractions."""

    _execute(
        lambda: build_service().archive_rebuild_fts(),
        json_output=json_output,
        human_renderer=lambda result: _render_archive_integrity(
            result,
            heading="Archive search index rebuilt",
        ),
    )


@app.command("archive-backup")
def archive_backup(
    destination: Annotated[
        Path,
        typer.Argument(help="Destination for the new SQLite backup."),
    ],
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Create a consistent SQLite backup."""

    _execute(
        lambda: build_service().archive_backup(destination),
        json_output=json_output,
        human_renderer=lambda result: _render_archive_backup(
            result,
            destination=destination,
        ),
    )


@app.command("archive-restore")
def archive_restore(
    source: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            readable=True,
            help="Validated schema-1 or current-schema SQLite backup.",
        ),
    ],
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Restore the working archive from a validated compatible backup."""

    _execute(
        lambda: build_service().archive_restore(source),
        json_output=json_output,
        human_renderer=lambda result: _render_archive_integrity(
            result,
            heading=f"Archive restored from {source}",
        ),
    )


@app.command()
def drift(
    provider: Annotated[
        str | None,
        typer.Option(help="Limit the sweep to one registered provider."),
    ] = None,
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Re-assess archived raw fetches and report provider/extraction drift."""

    _execute(
        lambda: build_service().archive_drift(provider),
        json_output=json_output,
        human_renderer=_render_drift_report,
    )


@app.command("mcp")
def mcp() -> None:
    """Serve the local stdio MCP surface (requires the 'mcp' extra)."""

    def run() -> None:
        try:
            from .mcp_server import run_stdio

            run_stdio()
        except ImportError as error:
            missing_root = (error.name or "").split(".", 1)[0]
            if missing_root not in {"anyio", "mcp"}:
                raise
            raise UsageError(
                "the MCP surface requires the optional 'mcp' extra: uv sync --extra mcp"
            ) from error

    _execute(
        run,
        json_output=False,
        human_usage_hint="install optional dependencies with 'uv sync --extra mcp'",
    )


@app.command("mcp-http")
def mcp_http() -> None:
    """Serve authenticated streamable HTTP MCP (requires the 'mcp' extra)."""

    def run() -> None:
        try:
            if os.environ.get("NEWSCLIP_USERS_FILE"):
                from .standalone import run_server

                run_server(
                    host=os.environ.get("NEWSCLIP_MCP_HOST", "127.0.0.1"),
                    port=int(os.environ.get("NEWSCLIP_MCP_PORT", "8000")),
                )
                return
            from .mcp_server import run_http

            run_http()
        except ImportError as error:
            missing_root = (error.name or "").split(".", 1)[0]
            if missing_root not in {"anyio", "mcp", "starlette", "uvicorn"}:
                raise
            raise UsageError(
                "the MCP surface requires the optional 'mcp' extra: uv sync --extra mcp"
            ) from error

    _execute(
        run,
        json_output=False,
        human_usage_hint="install optional dependencies with 'uv sync --extra mcp'",
    )


def _search_workflow(
    *,
    query: str | None,
    sources: tuple[str, ...],
    filters: SearchFilters,
    select: int | None,
    save_selected: bool,
    json_output: bool,
) -> SearchResponse | Article | None:
    interactive = _interactive_terminal() and not json_output and select is None
    if query is None and not interactive:
        raise UsageError("a search query is required when input is not interactive")

    service = build_service()
    provider_keys = sources or None
    # Discovery may be pure HTTP while selected results still need browser
    # retrieve (WSJ/Economist/Bloomberg). Prepare display once before search so
    # interactive selection does not fail with transport after results paint.
    if service.requires_browser_runtime(provider_keys):
        _prepare_virtual_display(sys.argv, child_owns_invocation=True)
    acquire_session = _session_acquirer(service, json_output=json_output)
    current_query = query
    clipped: set[str] = set()
    view_sort = filters.sort
    pager_filters = filters.model_copy(update={"sort": SearchSort.BALANCED})

    while True:
        if current_query is None:
            current_query = _prompt_search_query()
        if interactive:
            pager, response = _start_search_pager_with_progress(
                service,
                current_query,
                pager_filters,
                provider_keys=provider_keys,
                acquire_session=acquire_session,
            )
        else:
            response = _search_with_progress(
                service,
                current_query,
                filters,
                provider_keys=provider_keys,
                acquire_session=acquire_session,
                show_progress=not json_output,
            )
        if select is not None:
            return _open_search_result(
                service,
                response,
                select,
                save_selected=save_selected,
                acquire_session=acquire_session,
            )
        if not interactive:
            return response
        pages = [response]
        page_index = 0
        loaded_results = list(response.results)
        while True:
            canonical_page = pages[page_index]
            page = canonical_page.model_copy(
                update={
                    "results": _ordered_search_batch(
                        canonical_page.results,
                        view_sort,
                    )
                }
            )
            start_index = 1 + sum(len(item.results) for item in pages[:page_index])
            cached_next = page_index + 1 < len(pages)
            can_load_more = cached_next or (
                page_index + 1 == len(pages) and pages[-1].has_more
            )
            _render_search_response(
                page,
                clipped=clipped,
                start_index=start_index,
                total_loaded=len(loaded_results),
                sort_order=view_sort,
            )
            choice = _prompt_result_choice(
                len(loaded_results),
                selection_start=start_index,
                selection_end=start_index + len(page.results) - 1,
                has_more=can_load_more,
                has_previous=page_index > 0,
                sort_order=view_sort if page.results else None,
            )
            if choice == "quit":
                return None
            if choice == "new":
                current_query = None
                break
            if choice == "previous":
                page_index -= 1
                continue
            if choice == "sort":
                view_sort = (
                    SearchSort.NEWEST
                    if view_sort is SearchSort.BALANCED
                    else SearchSort.BALANCED
                )
                continue
            if choice == "more":
                if cached_next:
                    page_index += 1
                    continue
                next_page = _next_search_page_with_progress(pager, filters.limit)
                if next_page.results:
                    pages.append(next_page)
                    loaded_results.extend(next_page.results)
                    page_index += 1
                else:
                    pages[-1] = pages[-1].model_copy(
                        update={
                            "sources": next_page.sources,
                            "has_more": next_page.has_more,
                        }
                    )
                    message = (
                        "No new articles loaded; try again to continue or retry "
                        "sources."
                        if next_page.has_more
                        else "All available results are loaded."
                    )
                    Console(stderr=True).print(message)
                continue
            page_selection = int(choice) - start_index + 1
            selected_url = str(page.results[page_selection - 1].url)
            try:
                article = _open_search_result(
                    service,
                    page,
                    page_selection,
                    save_selected=save_selected,
                    acquire_session=acquire_session,
                )
            except NewsclipError as error:
                envelope = public_error(error)
                if envelope is None:  # pragma: no cover - future error subclasses
                    raise
                _emit_public_error(envelope, json_output=False, error=error)
                continue
            clipped.add(selected_url)
            _page_article(
                article,
                archive_path=service.archive_path if save_selected else None,
            )


def _start_search_pager_with_progress(
    service: Service,
    query: str,
    filters: SearchFilters,
    *,
    provider_keys: tuple[str, ...] | None,
    acquire_session: Callable[[str], None],
) -> tuple[FederatedSearchPager, SearchResponse]:
    with Console(stderr=True).status("Searching enabled sources…"):
        pager = service.search_pager(
            query,
            filters,
            provider_keys=provider_keys,
            acquire_session=acquire_session,
        )
        return pager, pager.next_batch(filters.limit)


def _next_search_page_with_progress(
    pager: FederatedSearchPager,
    size: int,
) -> SearchResponse:
    with Console(stderr=True).status("Loading more results…"):
        return pager.next_batch(size)


def _search_with_progress(
    service: Service,
    query: str,
    filters: SearchFilters,
    *,
    provider_keys: tuple[str, ...] | None,
    acquire_session: Callable[[str], None],
    show_progress: bool,
) -> SearchResponse:
    if not show_progress:
        return service.search_many(
            query,
            filters,
            provider_keys=provider_keys,
            acquire_session=acquire_session,
        )
    with Console(stderr=True).status("Searching enabled sources…"):
        return service.search_many(
            query,
            filters,
            provider_keys=provider_keys,
            acquire_session=acquire_session,
        )


def _open_search_result(
    service: Service,
    response: SearchResponse,
    selection: int,
    *,
    save_selected: bool,
    acquire_session: Callable[[str], None],
) -> Article:
    if selection < 1 or selection > len(response.results):
        raise UsageError(
            f"selection must be between 1 and {len(response.results)}"
            if response.results
            else "cannot select from an empty result set"
        )
    url = str(response.results[selection - 1].url)
    if service.requires_browser_for_url(url):
        _prepare_virtual_display(sys.argv, child_owns_invocation=True)
    if save_selected:
        return service.save(url, acquire_session=acquire_session)
    return service.get(url, acquire_session=acquire_session)


def _render_search_response(
    response: SearchResponse,
    *,
    clipped: set[str] | None = None,
    start_index: int = 1,
    total_loaded: int | None = None,
    sort_order: SearchSort | None = None,
) -> None:
    clipped = clipped or set()
    end_index = start_index + len(response.results) - 1
    result_range = f" {start_index}–{end_index}" if response.results else ""
    table = Table(
        title=f"Results{result_range} for “{response.query}”",
        box=None,
    )
    table.add_column("#", justify="right", style="bold cyan", no_wrap=True)
    table.add_column("Source", style="magenta", no_wrap=True)
    table.add_column("Published", no_wrap=True)
    table.add_column("Headline")
    for index, result in enumerate(response.results, start=start_index):
        headline = result.headline
        if str(result.url) in clipped:
            headline = f"✓ {headline}"
        table.add_row(
            str(index),
            result.provider.upper(),
            result.published.date().isoformat() if result.published else "—",
            headline,
        )
    if not response.results:
        table.add_row("—", "—", "—", "No matching articles")
    console = Console()
    console.print(table)
    states = []
    for source in response.sources:
        marker = {
            SourceSearchState.OK: "✓",
            SourceSearchState.UNAVAILABLE: "unavailable",
            SourceSearchState.NEEDS_ATTENTION: "needs attention",
        }[source.state]
        notes: list[str] = []
        if source.state is SourceSearchState.OK:
            # A bare "✓" reads as exhaustive coverage. When a source can only
            # search a moving window, say how far back this answer reached, so a
            # small honest count is not mistaken for the source having nothing.
            if source.coverage_start is not None:
                reached = source.coverage_start.astimezone(UTC)
                notes.append(f"searchable from {reached:%Y-%m-%d %H:%M}Z")
            if source.missing_published_count:
                count = source.missing_published_count
                noun = "date" if count == 1 else "dates"
                notes.append(f"{count} {noun} unavailable")
            if source.undated_excluded_count:
                count = source.undated_excluded_count
                noun = "result" if count == 1 else "results"
                notes.append(f"{count} undated {noun} withheld by date filter")
        if source.reason is not None:
            reason = {
                SourceSearchReason.SESSION_REQUIRED: "session required",
                SourceSearchReason.OPERATOR_ACTION: "authentication repair required",
                SourceSearchReason.TIMEOUT: "timed out",
                SourceSearchReason.DNS: "DNS unavailable",
                SourceSearchReason.CONTRACT: "provider response changed",
                SourceSearchReason.PERSISTENCE: "local state error",
                SourceSearchReason.TRANSPORT: "connection failed",
                SourceSearchReason.RATE_LIMITED: "provider rate-limited us",
                SourceSearchReason.PROVIDER_ERROR: "provider refused the request",
                SourceSearchReason.UNSEARCHABLE_QUERY: (
                    "no searchable terms in the query"
                ),
            }[source.reason]
            notes.append(reason)
        # Search answering is not retrieval answering. A source whose articles
        # are behind an armed cooldown still lists selectable rows, and saying
        # so here is the difference between choosing one and discovering the
        # refusal only after committing to it.
        if source.retrieval_contained_until is not None:
            until = source.retrieval_contained_until.astimezone(UTC)
            notes.append(f"articles unavailable until {until:%H:%M}Z")
        suffix = f" ({'; '.join(notes)})" if notes else ""
        states.append(f"{source.provider.upper()} {marker}{suffix}")
    console.print("Sources: " + " · ".join(states), style="dim")
    loaded = len(response.results) if total_loaded is None else total_loaded
    availability = (
        "More available" if response.has_more else "All available results loaded"
    )
    summary = f"{loaded} loaded · {availability}"
    if sort_order is SearchSort.BALANCED:
        summary = f"Order: Balanced sources · {summary}"
    elif sort_order is SearchSort.NEWEST:
        summary = f"Order: Newest first (this page; undated last) · {summary}"
    console.print(summary, style="dim")


def _prompt_search_query() -> str:
    while True:
        query = Console().input("Search: ").strip()
        if query:
            return query


def _prompt_result_choice(
    result_count: int,
    *,
    selection_start: int = 1,
    selection_end: int | None = None,
    has_more: bool = False,
    has_previous: bool = False,
    sort_order: SearchSort | None = None,
) -> str:
    selection_end = result_count if selection_end is None else selection_end
    has_selection = result_count > 0 and selection_end >= selection_start
    console = Console()
    prompt = _result_choice_prompt(
        result_count,
        selection_start=selection_start,
        selection_end=selection_end,
        has_more=has_more,
        has_previous=has_previous,
        sort_order=sort_order,
    )
    while True:
        raw = console.input(prompt).strip().lower()
        if raw in {"q", "quit"}:
            return "quit"
        if raw in {"n", "new"}:
            return "new"
        if has_more and raw in {"m", "more", "]"}:
            return "more"
        if has_previous and raw in {"b", "back", "["}:
            return "previous"
        if sort_order is not None and raw in {"s", "sort"}:
            return "sort"
        try:
            choice = int(raw)
        except ValueError:
            actions = ["n", "q"]
            if sort_order is not None:
                actions.insert(0, "s")
            if has_more:
                actions.insert(0, "m")
            if has_previous:
                actions.insert(0, "b")
            choices = _choice_list(actions)
            if has_selection:
                selection = (
                    str(selection_start)
                    if selection_start == selection_end
                    else f"{selection_start}–{selection_end}"
                )
                message = f"Enter {selection}, {choices}."
            else:
                message = f"Enter {choices}."
            Console(stderr=True).print(message)
            continue
        if has_selection and selection_start <= choice <= selection_end:
            return str(choice)
        if has_selection and selection_start == selection_end:
            message = f"Choose article {selection_start}."
        elif has_selection:
            message = f"Choose an article from {selection_start} to {selection_end}."
        else:
            actions = ["n", "q"]
            if sort_order is not None:
                actions.insert(0, "s")
            if has_more:
                actions.insert(0, "m")
            if has_previous:
                actions.insert(0, "b")
            choices = _choice_list(actions)
            message = f"There are no articles to open; choose {choices}."
        Console(stderr=True).print(message)


def _choice_list(actions: list[str]) -> str:
    if len(actions) == 1:
        return actions[0]
    if len(actions) == 2:
        return f"{actions[0]} or {actions[1]}"
    return ", ".join(actions[:-1]) + f", or {actions[-1]}"


def _result_choice_prompt(
    result_count: int,
    *,
    selection_start: int = 1,
    selection_end: int | None = None,
    has_more: bool = False,
    has_previous: bool = False,
    sort_order: SearchSort | None = None,
) -> Text:
    selection_end = result_count if selection_end is None else selection_end
    has_selection = result_count > 0 and selection_end >= selection_start
    prompt = Text()
    if has_selection:
        selection = (
            str(selection_start)
            if selection_start == selection_end
            else f"{selection_start}–{selection_end}"
        )
        prompt.append("Select article ")
        prompt.append(f"[{selection}]", style="bold cyan")
    else:
        prompt.append("No articles")
    if has_previous:
        prompt.append(" · ")
        prompt.append("[b]", style="bold cyan")
        prompt.append(" Previous results")
    if has_more:
        prompt.append(" · ")
        prompt.append("[m]", style="bold cyan")
        prompt.append(" More results")
    if sort_order is not None:
        prompt.append(" · ")
        prompt.append("[s]", style="bold cyan")
        prompt.append(
            " Newest first"
            if sort_order is SearchSort.BALANCED
            else " Balanced sources"
        )
    prompt.append(" · ")
    prompt.append("[n]", style="bold cyan")
    prompt.append(" New search · ")
    prompt.append("[q]", style="bold cyan")
    prompt.append(" Quit: ")
    return prompt


def _page_article(article: Article, *, archive_path: Path | str | None) -> None:
    content = _render_article_reader(article, archive_path=archive_path)
    # Click negotiates pager capabilities and never invokes $PAGER through a
    # shell. The reader itself is ANSI-free, so even editor-style pagers can
    # never expose terminal control sequences as literal ``ESC[...]`` text.
    echo_via_pager(content, color=False)


def _render_article_reader(article: Article, *, archive_path: Path | str | None) -> str:
    status = (
        f"Saved to archive: {archive_path}" if archive_path is not None else "Not saved"
    )
    authors = ", ".join(article.authors)
    metadata = "  ·  ".join(
        item
        for item in (
            article.provider.upper(),
            article.section,
            article.published.date().isoformat() if article.published else None,
            f"{article.word_count:,} words",
            status,
        )
        if item
    )
    width = max(20, min(shutil.get_terminal_size((100, 24)).columns, 100))
    output = StringIO()
    console = Console(
        file=output,
        color_system=None,
        highlight=False,
        width=width,
    )
    controls = _pager_exit_hint()
    console.print(f"NEWSCLIP READER  ·  {controls}")
    console.rule()
    console.print()
    console.print(article.headline)
    console.print(metadata)
    if authors:
        console.print(f"By {authors}")
    console.print()
    console.rule()
    console.print()
    from rich.markdown import Markdown

    console.print(Markdown(article.body_markdown, hyperlinks=False))
    console.print()
    console.rule("End of article")
    console.print(controls)
    return "\n".join(line.rstrip() for line in output.getvalue().splitlines()) + "\n"


def _pager_exit_hint() -> str:
    try:
        command = shlex.split(os.environ.get("PAGER", ""))
    except ValueError:
        command = []
    executable = Path(command[0]).name.casefold() if command else "less"
    if executable in {"vim", "nvim", "view", "vi"}:
        return "Exit: :q  ·  Back to results"
    if executable == "cat":
        return "Returns automatically to results"
    return "Exit: q  ·  Back to results"


def _interactive_terminal() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _human_label(value: str) -> str:
    return value.replace("_", " ")


def _human_timestamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


def _human_duration(seconds: float) -> str:
    if seconds >= 3600:
        return f"{seconds / 3600:.1f} hours"
    if seconds >= 60:
        return f"{seconds / 60:.1f} minutes"
    return f"{seconds:.0f} seconds"


def _render_session_details(health: SessionHealth) -> None:
    status = {
        SessionStatus.VERIFIED: "verified",
        SessionStatus.REQUIRED: "login required",
        SessionStatus.COOLDOWN: "cooldown",
        SessionStatus.OPERATOR_ACTION: "operator action required",
    }[health.status]
    typer.echo(f"Status: {status}")
    if health.last_verified_at is not None:
        typer.echo(f"Last verified: {_human_timestamp(health.last_verified_at)}")
    if health.retry_not_before is not None:
        typer.echo(f"Retry after: {_human_timestamp(health.retry_not_before)}")
    if health.last_failure is not None:
        typer.echo(f"Last result: {_human_label(health.last_failure.value)}")
    if health.failure_reason_code is not None:
        typer.echo(f"Reason: {_human_label(health.failure_reason_code)}")


def _render_session_health(health: SessionHealth) -> None:
    typer.echo(f"{health.provider.upper()} session")
    _render_session_details(health)


def _render_session_action(health: SessionHealth, action: str) -> None:
    typer.echo(f"{health.provider.upper()} {action}")
    _render_session_details(health)


def _render_provider_check(result: ProviderCheckResult) -> None:
    typer.echo(f"{result.provider.upper()} provider check")
    if result.ok:
        typer.echo(
            f"Result: healthy ({result.word_count} words; "
            f"{result.search_result_count} search results)"
        )
        if result.canary_in_search is False:
            typer.echo("Advisory: canary article missing from search results")
        return
    failure = result.failure
    if failure is None:  # pragma: no cover - model invariant
        raise PersistenceError("provider-check failure is incomplete")
    typer.echo(f"Result: failed / {failure.value}")
    if result.access_state is not None and result.reason is not None:
        typer.echo(f"Assessment: {result.access_state.value} / {result.reason.value}")
    if result.incident_id is not None:
        typer.echo(f"Incident: {result.incident_id}")


def _render_fleet_health(fleet: FleetHealth) -> None:
    for entry in fleet.providers:
        line = f"{entry.provider.upper():<10} serving={entry.serving.status.value}"
        if entry.serving.checked_at is not None:
            line += f" checked={_human_timestamp(entry.serving.checked_at)}"
        if entry.serving.failure is not None:
            line += f" check_failure={entry.serving.failure.value}"
        if entry.serving.canary_in_search is False:
            line += " canary_in_search=false"

        session = entry.session or {}
        if session:
            line += f" session={session.get('status') or 'unknown'}"
            stored_health = session.get("health")
            renewal = {
                "fresh": "fresh",
                "stale": "due",
                "degraded": "failing",
            }.get(stored_health if isinstance(stored_health, str) else "", "unknown")
            line += f" renewal={renewal}"
        elif entry.session_backed:
            line += " session=unknown renewal=unknown"
        else:
            line += " session=n/a"

        failures = session.get("consecutive_renewal_failures") or 0
        if failures:
            line += f" renewal_failures={failures}"
        error = session.get("last_renewal_error")
        if error:
            line += f" ({error})"
        if entry.defense is not None:
            active_until = entry.defense.get("active_until")
            defense_state = "active" if entry.defense_active else "recovery_pending"
            line += f" defense={defense_state}"
            line += f" defense_until={active_until}"
            line += f" arms_24h={entry.defense_arms_24h}"
        if entry.hold is not None:
            line += f" hold={entry.hold.get('action')}"
        if entry.transport_pin is not None:
            pin = entry.transport_pin
            active = pin.get("active_profile")
            if active:
                line += f" pin={active}"
            if pin.get("rot_observed_at"):
                # A standing rot signal is the drip working, not a fault —
                # but an operator reading a human line should still see it.
                line += f" pin_rot={pin.get('rot_profile') or 'unknown'}"
                candidate = pin.get("candidate_profile")
                if candidate:
                    line += f" pin_candidate={candidate}"
                    line += f"({pin.get('candidate_passes') or 0}/3)"
        if entry.transport_pin_pool_exhausted:
            # The one condition here that is a decision rather than a state.
            line += " pin_pool=exhausted"
        if entry.http_challenges is not None:
            refused = entry.http_challenges
            line += (
                f" http_challenged_24h={refused.get('last_24h')}"
                f" ({refused.get('profile') or 'unknown'})"
            )
        if entry.readiness_missing:
            line += f" missing={','.join(entry.readiness_missing)}"
        if entry.state_errors:
            line += " state_errors=" + ",".join(
                error.value for error in entry.state_errors
            )
        typer.echo(line)


def _render_keeper_result(result: KeeperResult) -> None:
    typer.echo(f"{result.provider.upper()} session keeper")
    typer.echo(f"Action: {result.action.value}")
    if result.status is not None:
        typer.echo(f"Status: {result.status.value}")
    if result.credential_attempt:
        typer.echo("Credential attempt: yes")
    if result.reason_code is not None:
        typer.echo(f"Reason: {result.reason_code}")
    if result.diagnostic_id is not None:
        typer.echo(f"Diagnostic: {result.diagnostic_id}")


def _render_guard_result(result: GuardResult) -> None:
    typer.echo(f"{result.provider.upper()} provider guard")
    typer.echo(f"Action: {result.action.value}")
    if result.diagnostic_id is not None:
        typer.echo(f"Diagnostic: {result.diagnostic_id}")
    if result.hold_id is not None:
        typer.echo(f"Hold: {result.hold_id}")
    if result.incident_id is not None:
        typer.echo(f"Incident: {result.incident_id}")
    elif result.check is not None and result.check.incident_id is not None:
        typer.echo(f"Incident: {result.check.incident_id}")


def _render_acknowledgement_report(result: AcknowledgementReport) -> None:
    acknowledgement = result.acknowledgement
    state = "acknowledged" if acknowledgement.acknowledged else "no active hold"
    typer.echo(f"{acknowledgement.provider.upper()} provider hold: {state}")
    if acknowledgement.current_hold_id is not None:
        typer.echo(f"Current hold: {acknowledgement.current_hold_id}")
    if result.follow_up is not None:
        typer.echo(f"Follow-up check: {result.follow_up.action.value}")
        if result.follow_up.hold_id is not None:
            typer.echo(f"New hold: {result.follow_up.hold_id}")
        if result.follow_up.incident_id is not None:
            typer.echo(f"Incident: {result.follow_up.incident_id}")
    if result.follow_up_error is not None:
        typer.echo(f"Follow-up check failed: {result.follow_up_error}")


def _render_login_result(
    result: LoginResult | SessionHealth,
    *,
    imported: bool,
) -> None:
    if isinstance(result, SessionHealth):
        action = "session imported" if imported else "session verified"
        _render_session_action(result, action)
        return
    route = {
        AcquisitionMode.ARTIFACT_REUSE: "existing verified session reused",
        AcquisitionMode.PROFILE_REHYDRATE: "retained browser profile restored",
        AcquisitionMode.CREDENTIAL_MINT: "fresh credentials submitted",
    }[result.acquisition.mode]
    typer.echo(f"{result.health.provider.upper()} login complete")
    _render_session_details(result.health)
    typer.echo(f"Session route: {route}")
    if result.refresh_failure is not None:
        typer.echo(
            "Refresh warning: "
            f"{_human_label(result.refresh_failure.stage.value)} / "
            f"{_human_label(result.refresh_failure.category.value)}"
        )


def _render_session_checkpoint(checkpoint: SessionCheckpoint) -> None:
    typer.echo(f"{checkpoint.provider.upper()} session checkpoint passed")
    typer.echo(f"Generation: {checkpoint.generation_fingerprint}")
    typer.echo(f"Age: {_human_duration(checkpoint.session_age_seconds)}")
    typer.echo(f"Created: {_human_timestamp(checkpoint.created_at)}")
    typer.echo(f"Verified: {_human_timestamp(checkpoint.verified_at)}")
    typer.echo(f"Checked: {_human_timestamp(checkpoint.checked_at)}")


def _render_doctor_report(report: DoctorReport) -> None:
    providers = ", ".join(item.upper() for item in report.providers) or "none"
    browser_providers = (
        ", ".join(item.upper() for item in report.browser_providers) or "none"
    )
    if not report.browser_providers:
        browser_route = "not required"
    elif not report.browser_engine_available:
        browser_route = "Chromium unavailable"
    elif report.virtual_display_active:
        browser_route = "active managed display"
    elif report.host_xvfb_available:
        browser_route = "host Xvfb available on demand"
    elif report.docker_fallback_available:
        browser_route = "Docker + bwrap fallback available on demand"
    else:
        browser_route = "unavailable"
    typer.echo("Newsclip doctor")
    typer.echo(f"Providers: {providers}")
    typer.echo(f"Browser providers: {browser_providers}")
    typer.echo(f"Browser runtime: {browser_route}")
    login_readiness = report.provider_readiness
    if login_readiness:
        states = ", ".join(
            (
                f"{readiness.provider.upper()}=ready"
                if readiness.ready
                else (
                    f"{readiness.provider.upper()}=missing:"
                    f"{'+'.join(item.value for item in readiness.missing)}"
                )
            )
            for readiness in login_readiness
        )
        typer.echo(f"Credential tooling: {states}")
    if report.browser_providers and not report.browser_engine_available:
        typer.echo("Next: run `uv run patchright install chromium`.")
    elif report.browser_providers and not report.browser_ready:
        typer.echo("Next: install Xvfb, or provide Docker and bwrap.")


def _render_article_action(
    article: Article,
    *,
    action: str,
    markdown_path: Path | None = None,
) -> None:
    typer.echo(f"{action}: {article.headline}")
    typer.echo(f"Archive ID: {article.id}")
    if markdown_path is not None:
        typer.echo(f"Markdown: {markdown_path}")


def _render_archive_search(articles: list[Article], *, query: str) -> None:
    if not articles:
        typer.echo(f'No archived articles matched "{query}".')
        return
    table = Table(title=f"Archive results for “{query}”", box=None)
    table.add_column("#", justify="right", style="bold cyan", no_wrap=True)
    table.add_column("Source", style="magenta", no_wrap=True)
    table.add_column("Published", no_wrap=True)
    table.add_column("Headline")
    table.add_column("Archive ID", no_wrap=True)
    for index, article in enumerate(articles, start=1):
        table.add_row(
            str(index),
            article.provider.upper(),
            article.published.date().isoformat() if article.published else "—",
            article.headline,
            article.id,
        )
    Console().print(table)
    noun = "article" if len(articles) == 1 else "articles"
    typer.echo(f"{len(articles)} archived {noun}")


def _render_archive_integrity(
    result: ArchiveIntegrity,
    *,
    heading: str | None = None,
) -> None:
    if heading is not None:
        typer.echo(heading)
    typer.echo(f"Archive integrity: {'passed' if result.ok else 'failed'}")
    typer.echo(f"Foreign-key violations: {result.foreign_key_violations}")
    typer.echo(f"Schema version: {result.user_version}")


def _render_archive_backup(
    result: ArchiveBackupResult,
    *,
    destination: Path,
) -> None:
    if result.ok:
        typer.echo(f"Archive backup created: {destination}")


def _render_drift_report(report: DriftReport) -> None:
    finding_count = len(report.findings)
    finding_noun = "finding" if finding_count == 1 else "findings"
    status = "clean" if report.is_clean else f"{finding_count} {finding_noun}"
    typer.echo(f"Drift check: {status}")
    revision_noun = "revision" if report.checked == 1 else "revisions"
    typer.echo(f"Checked: {report.checked} archived {revision_noun}")
    if report.findings:
        table = Table(box=None)
        table.add_column("Scope", no_wrap=True)
        table.add_column("Change", no_wrap=True)
        table.add_column("Expected")
        table.add_column("Actual")
        for finding in report.findings:
            table.add_row(
                finding.scope,
                _human_label(finding.kind),
                _human_label(finding.expected),
                _human_label(finding.actual),
            )
        Console().print(table)
    if report.skipped_providers:
        skipped = ", ".join(item.upper() for item in report.skipped_providers)
        typer.echo(f"Skipped unregistered providers: {skipped}")


def _execute[ResultT](
    action: Callable[[], ResultT],
    *,
    json_output: bool,
    show_article_body: bool = False,
    emit_result: bool = True,
    human_renderer: Callable[[ResultT], None] | None = None,
    human_usage_hint: str | None = None,
) -> None:
    try:
        value = action()
        if emit_result:
            if json_output or human_renderer is None:
                _emit(
                    value,
                    json_output=json_output,
                    show_article_body=show_article_body,
                )
            else:
                human_renderer(value)
    except Exception as error:
        envelope = public_error(error)
        if envelope is None:
            raise
        _fail(
            envelope,
            json_output=json_output,
            human_usage_hint=human_usage_hint,
            error=error,
        )


def _session_acquirer(
    service: Service,
    *,
    json_output: bool,
) -> Callable[[str], None]:
    def acquire(provider: str) -> None:
        def prepare_browser() -> None:
            scoped_argv = [
                sys.argv[0],
                "auth",
                "login",
                provider,
                "--headless",
                "--challenge-mode",
                ChallengeMode.AUTO.value,
                "--quiet",
            ]
            if json_output:
                scoped_argv.append("--json")
            _prepare_virtual_display(
                scoped_argv,
                child_owns_invocation=False,
            )

        service.login(
            provider,
            headless=True,
            challenge_mode=ChallengeMode.AUTO,
            before_browser=prepare_browser,
        )

    return acquire


def _prepare_virtual_display(
    argv: list[str],
    *,
    child_owns_invocation: bool,
) -> None:
    try:
        child_exit = maybe_reexec_for_virtual_display(argv, required=True)
    except BrowserRuntimeError as error:
        raise ProviderTransportError(
            "browser runtime unavailable",
            category=TransportFailure.TRANSPORT,
        ) from error
    if child_exit is None:
        return
    if child_owns_invocation or child_exit != 0:
        raise typer.Exit(code=child_exit)


def _emit(value: object, *, json_output: bool, show_article_body: bool = False) -> None:
    if json_output:
        typer.echo(json.dumps(public_value(value), ensure_ascii=False, sort_keys=True))
        return
    if isinstance(value, Article):
        typer.echo(value.headline)
        if show_article_body:
            typer.echo()
            typer.echo(value.body_markdown)
        else:
            typer.echo(value.id)
    elif isinstance(value, SearchResponse):
        _render_search_response(value)
    elif value is not None:
        raise PersistenceError("result has no human renderer")


def _read_cookie_payload(path: Path) -> object:
    try:
        with path.open("rb") as stream:
            payload = stream.read(_MAX_COOKIE_IMPORT_BYTES + 1)
    except OSError as error:
        raise UsageError("cookie import file is not valid JSON") from error
    return _parse_cookie_payload(payload, source="file")


def _read_cookie_payload_stdin() -> object:
    if sys.stdin.isatty():
        raise UsageError("cookie import standard input must be piped")
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    try:
        payload = stream.read(_MAX_COOKIE_IMPORT_BYTES + 1)
    except OSError as error:
        raise UsageError("cookie import standard input could not be read") from error
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return _parse_cookie_payload(payload, source="standard input")


def _parse_cookie_payload(payload: bytes, *, source: str) -> object:
    if len(payload) > _MAX_COOKIE_IMPORT_BYTES:
        raise UsageError("cookie import input exceeds the 1 MiB limit")
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        label = "file" if source == "file" else "standard input"
        raise UsageError(f"cookie import {label} is not valid JSON") from error


def _aware_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise UsageError("publication bounds must be ISO-8601 timestamps") from error
    if parsed.tzinfo is None:
        raise UsageError("publication bounds must include a timezone")
    return parsed


# Closed assessment reasons that may refine the human next-step without
# echoing arbitrary exception text into the public CLI surface.
_CONTENT_NOT_FULL_HINTS = {
    "browser_semantic_readiness_timeout": (
        "the article did not finish rendering; the existing session was "
        "preserved and no login was attempted"
    ),
    "interactive_challenge": (
        "provider returned an interactive challenge; preserve the first "
        "failure and do not retry blindly"
    ),
    # Both of these reach the CLI with a live, valid session, so the shared
    # fallback's advice to check the session — and its reference to an archive
    # path a browser provider never walks — sends the operator the wrong way.
    "paywall_teaser": (
        "the provider served a partial body; inspect the retained incident "
        "before renewing the session"
    ),
    "not_entitled": (
        "the session verified paid access but this article stayed partial; it "
        "is outside the subscription, so do not renew the session or retry"
    ),
    "insufficient_article_structure": (
        "the provider served a body the assessment could not verify as whole; "
        "inspect the retained incident before renewing the session"
    ),
}
_CREDENTIAL_REJECTED_REASON = (
    f"{MintFailureStage.CREDENTIAL.value}_"
    f"{MintFailureCategory.CREDENTIAL_REJECTED.value}"
)
_CHALLENGE_BLOCKED_REASON = (
    f"{MintFailureStage.CHALLENGE.value}_{MintFailureCategory.CHALLENGE_BLOCKED.value}"
)


def _human_error_message(
    envelope: PublicErrorEnvelope,
    *,
    error: BaseException | None = None,
) -> str:
    if envelope.category is PublicErrorCategory.PROVIDER_DEFENSE and isinstance(
        error, ProviderDefenseError
    ):
        if error.provider is not None:
            return f"{error.provider.upper()} edge defense refused the request"
        return envelope.message.value
    if envelope.category is not PublicErrorCategory.OPERATOR_ACTION or not isinstance(
        error, OperatorActionRequiredError
    ):
        return envelope.message.value
    provider = error.provider
    if provider is None:
        return envelope.message.value
    label = provider.upper()
    if error.reason_code == _CREDENTIAL_REJECTED_REASON:
        return f"{label} sign-in credentials were rejected"
    if error.reason_code == _CHALLENGE_BLOCKED_REASON:
        return f"{label} returned an interactive challenge"
    return f"{label} requires operator action"


def _format_retry_delay(seconds: float) -> str:
    """Render a cooldown remainder as a short human duration.

    Deliberately a duration and not a wall-clock expiry: this renderer is pure,
    and reading the clock here would make the one hint an operator most needs
    depend on ambient time in tests and on the caller's timezone in the field.
    """

    total = max(1, round(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, whole_seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    if minutes:
        return f"{minutes}m"
    return f"{whole_seconds}s"


def _human_error_hint(
    category: PublicErrorCategory,
    *,
    error: BaseException | None = None,
    retry_after_seconds: float | None = None,
) -> str:
    if category is PublicErrorCategory.USAGE:
        if isinstance(error, UnsearchableQueryError):
            return (
                "the selected sources rank on informative words only; add a "
                "distinctive term to the query"
            )
        return "run 'newsclip --help' for valid arguments"
    if category is PublicErrorCategory.CONTENT_NOT_FULL and isinstance(
        error, ContentNotFullError
    ):
        closed_hint = _CONTENT_NOT_FULL_HINTS.get(str(error))
        if closed_hint is not None:
            return closed_hint
    if category is PublicErrorCategory.OPERATOR_ACTION and isinstance(
        error, OperatorActionRequiredError
    ):
        provider = error.provider
        if provider is not None:
            label = provider.upper()
            if error.reason_code == _CREDENTIAL_REJECTED_REASON:
                return (
                    f"verify the {label} credentials manually and correct the stored "
                    "credentials; then run "
                    f"'uv run newsclip auth reset {provider}' followed by one "
                    f"'uv run newsclip auth login {provider}'"
                )
            if error.reason_code == _CHALLENGE_BLOCKED_REASON:
                return (
                    f"preserve the first {label} failure and review its retained "
                    "evidence; do not reset or retry blindly"
                )
            return (
                f"inspect 'uv run newsclip auth status {provider}'; "
                "do not reset or retry login blindly"
            )
    # The containment that refused this request already knows how long it will
    # last, and the envelope carries the number. Withholding it left the one
    # question the operator actually has — "how long?" — answerable only by
    # retrying, which is the behaviour the cooldown exists to stop.
    if (
        category is PublicErrorCategory.PROVIDER_DEFENSE
        and retry_after_seconds is not None
    ):
        return (
            "the provider's edge defense refused the request; wait about "
            f"{_format_retry_delay(retry_after_seconds)} before retrying — "
            "immediate retries extend the block"
        )
    return {
        PublicErrorCategory.OPERATOR_ACTION: (
            "inspect 'uv run newsclip auth status <provider>'; "
            "do not reset or retry login blindly"
        ),
        PublicErrorCategory.PROVIDER_DEFENSE: (
            "the provider's edge defense refused the request; wait and retry "
            "later — immediate retries extend the block"
        ),
        PublicErrorCategory.SESSION_REQUIRED: (
            "establish a session with 'newsclip auth login PROVIDER'"
        ),
        PublicErrorCategory.CONTENT_NOT_FULL: (
            "verify the article URL and session; no archive revision was accepted"
        ),
        PublicErrorCategory.TIMEOUT: "the provider timed out; retry later",
        PublicErrorCategory.DNS: "check DNS and network connectivity, then retry",
        PublicErrorCategory.TRANSPORT: (
            "run 'newsclip doctor' and retry when the provider route is healthy"
        ),
        PublicErrorCategory.PERSISTENCE: (
            "check local state and data permissions before retrying"
        ),
    }[category]


def _emit_public_error(
    envelope: PublicErrorEnvelope,
    *,
    json_output: bool,
    human_usage_hint: str | None = None,
    error: BaseException | None = None,
) -> None:
    if json_output:
        typer.echo(
            json.dumps(envelope.public_dict(), sort_keys=True),
            err=True,
        )
    else:
        typer.echo(
            f"error: {_human_error_message(envelope, error=error)}",
            err=True,
        )
        hint = (
            human_usage_hint
            if envelope.category is PublicErrorCategory.USAGE
            and human_usage_hint is not None
            else _human_error_hint(
                envelope.category,
                error=error,
                retry_after_seconds=envelope.retry_after_seconds,
            )
        )
        typer.echo(f"hint: {hint}", err=True)
        # A hint that says to inspect the retained evidence is only actionable
        # if the operator can find it. JSON callers already receive this id.
        if envelope.incident_id is not None:
            typer.echo(f"incident: {envelope.incident_id}", err=True)


def _fail(
    envelope: PublicErrorEnvelope,
    *,
    json_output: bool,
    human_usage_hint: str | None = None,
    error: BaseException | None = None,
) -> None:
    _emit_public_error(
        envelope,
        json_output=json_output,
        human_usage_hint=human_usage_hint,
        error=error,
    )
    raise typer.Exit(code=envelope.exit_code)


def run() -> None:
    """Console entry point: unwind on SIGTERM so browsers close, then run."""

    from .process_signals import exit_on_sigterm

    exit_on_sigterm()
    app()


if __name__ == "__main__":
    run()
