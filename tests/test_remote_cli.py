"""CLI and Python client exercise the authenticated HTTP application."""

from __future__ import annotations

import json

import httpx
import pytest
from typer.testing import CliRunner

pytest.importorskip("signin_window")
pytest.importorskip("fastmcp")

from starlette.testclient import TestClient  # noqa: E402
from test_standalone import make_app  # noqa: E402

from newsclip import cli  # noqa: E402
from newsclip.client import NewsclipClient  # noqa: E402


def test_remote_cli_uses_shared_search_save_archive_and_connect(
    accounts, tmp_path, monkeypatch
):
    app, tokens, _ = make_app(accounts, tmp_path)
    token_file = tmp_path / "alice.token"
    with TestClient(app, base_url="http://127.0.0.1") as http:

        def transport(request):
            result = http.request(
                request.method,
                str(request.url),
                headers=request.headers,
                content=request.content,
            )
            return httpx.Response(
                result.status_code, headers=result.headers, content=result.content
            )

        original_init = NewsclipClient.__init__

        def initialize(self, url, token, **kwargs):
            original_init(self, url, token, transport=httpx.MockTransport(transport))

        monkeypatch.setattr(NewsclipClient, "__init__", initialize)
        runner = CliRunner()
        common = [
            "--server",
            "http://127.0.0.1/users/alice",
            "--token-file",
            str(token_file),
        ]
        search = runner.invoke(
            cli.app,
            [
                *common,
                "search",
                "fixture",
                "--source",
                "fixture",
                "--limit",
                "2",
                "--json",
            ],
        )
        assert search.exit_code == 0, search.output
        assert len(json.loads(search.stdout)["results"]) == 2
        destination = tmp_path / "client/article.md"
        saved = runner.invoke(
            cli.app,
            [
                *common,
                "save",
                "https://fixture.test/content/full-article",
                "--out",
                str(destination),
                "--json",
            ],
        )
        assert saved.exit_code == 0, saved.output
        article = json.loads(saved.stdout)
        assert destination.read_text().strip() == article["body_markdown"]
        archived = runner.invoke(
            cli.app, [*common, "archive-get", article["id"], "--json"]
        )
        assert archived.exit_code == 0, archived.output
        assert json.loads(archived.stdout)["id"] == article["id"]
        connect = runner.invoke(
            cli.app, [*common, "auth", "connect", "fixture", "--json"]
        )
        assert connect.exit_code == 0, connect.output
        assert "/connections/#fixture" in json.loads(connect.stdout)["url"]
        assert json.loads(connect.stdout)["expires_at"] is None
        assert tokens["alice"] not in connect.stdout
        human_connect = runner.invoke(cli.app, [*common, "auth", "connect", "fixture"])
        assert human_connect.exit_code == 0, human_connect.output
        assert "Only the authenticated owner" in human_connect.stdout
        doctor = runner.invoke(cli.app, [*common, "doctor", "--json"])
        assert doctor.exit_code == 0, doctor.output
        assert json.loads(doctor.stdout)["providers"] == ["fixture"]
        denied = runner.invoke(
            cli.app,
            [
                "--server",
                "http://127.0.0.1/users/bob",
                "--token-file",
                str(token_file),
                "archive-get",
                article["id"],
                "--json",
            ],
        )
        assert denied.exit_code != 0
        assert article["body_markdown"] not in denied.output


def test_new_token_revokes_previous_token_without_restarting(accounts, tmp_path):
    from newsclip.tenancy import add_user

    app, tokens, _ = make_app(accounts, tmp_path)
    registry, _ = accounts
    with TestClient(app, base_url="http://127.0.0.1") as client:
        url = "/users/alice/api/providers"
        assert (
            client.post(
                url, json={}, headers={"Authorization": f"Bearer {tokens['alice']}"}
            ).status_code
            == 200
        )
        new_file = tmp_path / "new.token"
        add_user(registry, "alice", new_file, rotate=True)
        assert (
            client.post(
                url, json={}, headers={"Authorization": f"Bearer {tokens['alice']}"}
            ).status_code
            == 401
        )
        assert (
            client.post(
                url,
                json={},
                headers={"Authorization": f"Bearer {new_file.read_text().strip()}"},
            ).status_code
            == 200
        )


def test_provider_defense_reason_crosses_authenticated_http_and_cli(
    accounts, tmp_path, monkeypatch
):
    from test_federated_search import SearchProvider, _service

    from newsclip.errors import ProviderDefenseError

    monkeypatch.setattr(
        "test_standalone._service",
        lambda *args: _service(
            SearchProvider("refused", error=ProviderDefenseError("private detail")),
            SearchProvider("healthy"),
        ),
    )
    app, tokens, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as http:

        def transport(request):
            response = http.request(
                request.method,
                str(request.url),
                headers=request.headers,
                content=request.content,
            )
            return httpx.Response(
                response.status_code, headers=response.headers, content=response.content
            )

        original = NewsclipClient.__init__

        def initialize(self, url, token, **kwargs):
            original(self, url, token, transport=httpx.MockTransport(transport))

        monkeypatch.setattr(NewsclipClient, "__init__", initialize)
        runner = CliRunner()
        args = [
            "--server",
            "http://127.0.0.1/users/alice",
            "--token-file",
            str(tmp_path / "alice.token"),
            "search",
            "capital",
        ]
        response = runner.invoke(cli.app, [*args, "--json"])
        assert response.exit_code == 0, response.output
        assert json.loads(response.output)["sources"][0]["reason"] == "provider_defense"
        text = runner.invoke(cli.app, args)
        assert text.exit_code == 0, text.output
        assert "publisher challenge or cooldown" in text.output
        assert "private detail" not in text.output
        denied = http.post(
            "/users/bob/api/search",
            json={"query": "capital"},
            headers={"Authorization": f"Bearer {tokens['alice']}"},
        )
        assert denied.status_code == 401
