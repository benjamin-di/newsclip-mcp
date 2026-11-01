"""Remote-only commands with no publisher acquisition or browser imports."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer

from .client import NewsclipClient
from .errors import NewsclipError, UsageError
from .models import SearchFilters, SearchSort
from .results import public_error, public_value

app = typer.Typer(
    help="Newsclip remote client. Local operation requires the local extra.",
    no_args_is_help=True,
)
auth = typer.Typer(help="Inspect subscription status or open owner Connections.")
app.add_typer(auth, name="auth")


def _version(value: bool) -> None:
    if value:
        from . import __version__

        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def configure(
    ctx: typer.Context,
    server: str | None = typer.Option(None, envvar="NEWSCLIP_URL"),
    token_file: Annotated[
        Path | None, typer.Option(envvar="NEWSCLIP_TOKEN_FILE")
    ] = None,
    user: str | None = typer.Option(None, envvar="NEWSCLIP_USER"),
    version: bool = typer.Option(False, callback=_version, is_eager=True),
) -> None:
    del version
    ctx.obj = (server, token_file, user)


def _client(ctx: typer.Context) -> NewsclipClient:
    server, token_file, user = ctx.find_root().obj
    if not server:
        raise UsageError(
            "set --server / NEWSCLIP_URL; install newsclip[local] for local operations"
        )
    if user:
        raise UsageError("remote identity comes from the server URL and token")
    try:
        token = (
            token_file.expanduser().read_text().strip()
            if token_file
            else os.environ.get("NEWSCLIP_TOKEN", "")
        )
    except OSError as error:
        raise UsageError("configure a readable token file") from error
    return NewsclipClient(server, token)


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


def _execute(ctx: typer.Context, operation, json_output: bool) -> None:
    try:
        with _client(ctx) as client:
            value = operation(client)
        rendered = public_value(value)
    except (NewsclipError, ValueError) as error:
        envelope = getattr(error, "remote_error", None) or public_error(error)
        if envelope is None:
            raise
        typer.echo(
            json.dumps(envelope.public_dict()) if json_output else envelope.message,
            err=True,
        )
        if isinstance(error, UsageError) and not json_output:
            typer.echo(
                "hint: configure --server / NEWSCLIP_URL and a token; "
                "local mode requires newsclip[local]",
                err=True,
            )
        raise typer.Exit(envelope.exit_code) from None
    if json_output:
        typer.echo(json.dumps(rendered))
    elif isinstance(rendered, dict) and "body_markdown" in rendered:
        typer.echo(rendered["body_markdown"])
    else:
        typer.echo(json.dumps(rendered, indent=2))


@app.command()
def search(
    ctx: typer.Context,
    query: Annotated[str, typer.Argument()],
    source: Annotated[list[str] | None, typer.Option("--source", "-s")] = None,
    limit: int = typer.Option(20, min=1, max=100),
    published_after: str | None = None,
    published_before: str | None = None,
    sort_order: Annotated[SearchSort, typer.Option("--sort")] = SearchSort.BALANCED,
    select: Annotated[int | None, typer.Option(min=1)] = None,
    no_save: bool = False,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Search a bounded batch; no automatic retrieval or storage."""

    def operation(client):
        response = client.search_many(
            query,
            SearchFilters(
                limit=limit,
                published_after=_aware_timestamp(published_after),
                published_before=_aware_timestamp(published_before),
                sort=sort_order,
            ),
            provider_keys=source,
        )
        if select is None:
            return response
        if select > len(response.results):
            raise UsageError("selection is outside the result set")
        url = str(response.results[select - 1].url)
        return client.get(url) if no_save else client.save(url)

    _execute(ctx, operation, json_output)


@app.command("get")
def get_article(
    ctx: typer.Context, url: str, json_output: bool = typer.Option(False, "--json")
) -> None:
    """Read one verified full article."""
    _execute(ctx, lambda client: client.get(url), json_output)


@app.command()
def save(
    ctx: typer.Context,
    url: str,
    out: Annotated[Path | None, typer.Option("--out", "-o")] = None,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Archive an article on the server and optionally export Markdown locally."""
    _execute(ctx, lambda client: client.save(url, out=out), json_output)


@app.command("archive-search")
def archive_search(
    ctx: typer.Context,
    query: str,
    provider: str | None = None,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    _execute(
        ctx, lambda client: client.archive_search(query, provider=provider), json_output
    )


@app.command("archive-get")
def archive_get(
    ctx: typer.Context,
    article_id: str,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    _execute(ctx, lambda client: client.archive_get(article_id), json_output)


@app.command()
def reextract(
    ctx: typer.Context,
    article_id: str,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Re-extract a previously saved article from its stored raw bytes."""
    _execute(ctx, lambda client: client.reextract(article_id), json_output)


@app.command("archive-integrity")
def archive_integrity(
    ctx: typer.Context, json_output: bool = typer.Option(False, "--json")
) -> None:
    _execute(ctx, lambda client: client.archive_integrity(), json_output)


@app.command("archive-rebuild-fts")
def archive_rebuild_fts(
    ctx: typer.Context, json_output: bool = typer.Option(False, "--json")
) -> None:
    _execute(ctx, lambda client: client.archive_rebuild_fts(), json_output)


@app.command()
def doctor(
    ctx: typer.Context, json_output: bool = typer.Option(False, "--json")
) -> None:
    _execute(ctx, lambda client: client.doctor(), json_output)


@auth.command("status")
def status(
    ctx: typer.Context, provider: str, json_output: bool = typer.Option(False, "--json")
) -> None:
    _execute(ctx, lambda client: client.session_status(provider), json_output)


@auth.command("login")
@auth.command("connect")
def connect(
    ctx: typer.Context, provider: str, json_output: bool = typer.Option(False, "--json")
) -> None:
    _execute(ctx, lambda client: client.connect(provider), json_output)
    if not json_output:
        typer.echo("Only the authenticated owner can start sign-in on Connections.")


def run() -> None:
    app()
