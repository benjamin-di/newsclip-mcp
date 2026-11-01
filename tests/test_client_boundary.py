"""Remote installs need only HTTP, public models and the CLI presentation."""

import importlib.metadata
import subprocess
import sys

import httpx
import pytest
from packaging.requirements import Requirement

from newsclip.client import NewsclipClient
from newsclip.errors import ContentNotFullError, ProviderTransportError
from newsclip.results import public_error


def test_remote_imports_do_not_load_local_runtime():
    script = """
import importlib.abc, sys
class BlockLocal(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, *args):
        local = {'signin_window', 'patchright', 'curl_cffi', 'trafilatura',
                 'lxml', 'account_connections'}
        if fullname.split('.')[0] in local:
            raise AssertionError('remote client imported ' + fullname)
sys.meta_path.insert(0, BlockLocal())
from newsclip.client import NewsclipClient
from newsclip.remote_cli import app
from typer.testing import CliRunner
result = CliRunner().invoke(app, ['--help'])
assert result.exit_code == 0, result.output
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("category", "message", "exit_code", "action", "retryable", "error_type"),
    [
        (
            "content_not_full",
            "content did not verify as full",
            4,
            "renewal_pending",
            False,
            ContentNotFullError,
        ),
        (
            "provider_defense",
            "provider defense active",
            5,
            "retry_later",
            True,
            ProviderTransportError,
        ),
    ],
)
def test_remote_error_retains_closed_contract(
    category, message, exit_code, action, retryable, error_type
):
    envelope = {
        "ok": False,
        "category": category,
        "message": message,
        "exit_code": exit_code,
        "action": action,
        "retryable": retryable,
    }
    if retryable:
        envelope["retry_after_seconds"] = 90
    with (
        NewsclipClient(
            "https://reader.example.test/users/alice",
            "fixture",
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=envelope)),
        ) as client,
        pytest.raises(error_type) as caught,
    ):
        client.get("https://publisher.example.test/article")
    assert caught.value.remote_error.public_dict() == envelope
    assert public_error(caught.value).public_dict() == envelope


def test_untrusted_error_fields_are_not_repeated():
    with (
        NewsclipClient(
            "https://reader.example.test/users/alice",
            "fixture",
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    200,
                    json={
                        "ok": False,
                        "category": "transport",
                        "message": "PRIVATE_SENTINEL",
                    },
                )
            ),
        ) as client,
        pytest.raises(ProviderTransportError) as caught,
    ):
        client.get("https://publisher.example.test/article")
    assert "PRIVATE_SENTINEL" not in str(caught.value)
    assert caught.value.retryable is False


@pytest.mark.parametrize(
    "command",
    [
        ["search", "--help"],
        ["auth", "status", "--help"],
        ["reextract", "--help"],
        ["archive-integrity", "--help"],
        ["archive-rebuild-fts", "--help"],
        ["auth", "login", "--help"],
    ],
)
def test_unconfigured_remote_subcommands_offer_help(monkeypatch, command):
    from typer.testing import CliRunner

    from newsclip.remote_cli import app

    for name in ("NEWSCLIP_URL", "NEWSCLIP_TOKEN", "NEWSCLIP_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)
    result = CliRunner().invoke(app, command)
    assert result.exit_code == 0, result.output


def test_remote_date_options_and_selected_read_preserve_contract(monkeypatch):
    from typer.testing import CliRunner

    from newsclip import remote_cli
    from newsclip.models import SearchResponse, SearchResult

    observed = []

    class FakeClient:
        def __init__(self, *_):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def search_many(self, query, filters, **kwargs):
            observed.append((filters, kwargs))
            return SearchResponse(
                query=query,
                sources=(),
                results=(
                    SearchResult(
                        provider="ap",
                        url="https://publisher.example.test/item",
                        headline="Fixture",
                    ),
                ),
            )

        def get(self, url):
            observed.append(url)
            from types import SimpleNamespace

            return SimpleNamespace(
                public_dict=lambda: {"body_markdown": "Fixture body"}
            )

    monkeypatch.setattr(remote_cli, "NewsclipClient", FakeClient)
    common = ["--server", "https://reader.example.test/users/alice"]
    runner = CliRunner()
    result = runner.invoke(
        remote_cli.app,
        [
            *common,
            "search",
            "fixture",
            "-s",
            "ap",
            "--published-after",
            "2026-10-01T00:00:00Z",
            "--published-before",
            "2026-11-01T08:00:00+08:00",
            "--sort",
            "newest",
            "--select",
            "1",
            "--no-save",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    filters, kwargs = observed[0]
    assert filters.published_after.tzinfo is not None
    assert filters.published_before.tzinfo is not None
    assert filters.sort.value == "newest" and kwargs["provider_keys"] == ["ap"]
    assert observed[1] == "https://publisher.example.test/item"
    assert "Fixture body" in result.stdout
    failure = runner.invoke(
        remote_cli.app,
        [*common, "search", "fixture", "--published-after", "2026-10-01", "--json"],
    )
    assert failure.exit_code != 0
    assert failure.stdout == ""
    assert '"ok": false' in failure.stderr


def test_missing_remote_configuration_explains_local_extra(monkeypatch):
    from typer.testing import CliRunner

    from newsclip.remote_cli import app

    monkeypatch.delenv("NEWSCLIP_URL", raising=False)
    result = CliRunner().invoke(app, ["search", "fixture"])
    assert result.exit_code == 2
    assert "NEWSCLIP_URL" in result.stderr
    assert "newsclip[local]" in result.stderr


@pytest.mark.parametrize(
    ("extra", "package", "vulnerable", "patched"),
    [
        (extra, package, vulnerable, patched)
        for extra in ("local", "mcp")
        for package, vulnerable, patched in (
            ("authlib", "1.8.0", "1.9.1"),
            ("joserfc", "1.7.5", "1.7.6"),
            ("dnspython", "2.8.0", "2.9.0"),
        )
    ]
    + [
        ("mcp", "fastmcp", "4.0.10", "4.1.2"),
        ("mcp", "fastmcp-slim", "4.0.10", "4.1.2"),
    ],
)
def test_published_extra_requirements_enforce_security_minima(
    extra, package, vulnerable, patched
):
    requirements = [
        Requirement(value) for value in importlib.metadata.requires("newsclip") or ()
    ]
    selected = [
        requirement
        for requirement in requirements
        if requirement.name == package
        and (
            requirement.marker is None or requirement.marker.evaluate({"extra": extra})
        )
    ]
    assert selected, f"{extra} must declare its {package} security requirement"
    assert any(vulnerable not in requirement.specifier for requirement in selected)
    assert all(patched in requirement.specifier for requirement in selected)


def test_published_base_requirements_remain_lightweight():
    requirements = [
        Requirement(value) for value in importlib.metadata.requires("newsclip") or ()
    ]
    base = {
        requirement.name
        for requirement in requirements
        if requirement.marker is None or requirement.marker.evaluate({"extra": ""})
    }
    assert base == {"click", "httpx", "pydantic", "rich", "typer"}
