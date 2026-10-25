"""vision_environment: minimal child env, egress isolated to the solver."""

from __future__ import annotations

from newsclip.vision_cli import vision_environment


def test_ambient_proxy_is_never_inherited(monkeypatch) -> None:
    """Provider mint traffic must come from the host IP the session will be
    used from; an ambient HTTPS_PROXY would silently route it via the AI
    egress. Only the dedicated vision vars may reach the solver child."""

    monkeypatch.setenv("HTTPS_PROXY", "http://ambient.example.com:1080")
    monkeypatch.setenv("HTTP_PROXY", "http://ambient.example.com:1080")
    monkeypatch.delenv("NEWSCLIP_VISION_HTTPS_PROXY", raising=False)
    environment = vision_environment("codex")
    assert "HTTPS_PROXY" not in environment
    assert "HTTP_PROXY" not in environment


def test_vision_proxy_reaches_only_the_solver_child(monkeypatch) -> None:
    monkeypatch.setenv("NEWSCLIP_VISION_HTTPS_PROXY", "http://proxy.example.com:1080")
    monkeypatch.setenv("NEWSCLIP_VISION_NO_PROXY", "localhost,127.0.0.1")
    environment = vision_environment("codex")
    assert environment["HTTPS_PROXY"] == "http://proxy.example.com:1080"
    assert environment["HTTP_PROXY"] == "http://proxy.example.com:1080"
    assert environment["NO_PROXY"] == "localhost,127.0.0.1"


def test_codex_home_passthrough(monkeypatch) -> None:
    monkeypatch.setenv("CODEX_HOME", "/var/lib/newsclip/codex-home")
    monkeypatch.delenv("NEWSCLIP_VISION_HTTPS_PROXY", raising=False)
    environment = vision_environment("codex")
    assert environment["CODEX_HOME"] == "/var/lib/newsclip/codex-home"
    assert set(environment) <= {
        "HOME",
        "PATH",
        "LANG",
        "LC_ALL",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "CODEX_HOME",
    }


def test_claude_service_grant_is_isolated_from_codex_and_provider_secrets(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "synthetic-claude-grant")
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "synthetic-provider-authority")
    monkeypatch.setenv("EXAMPLE_MAIL_BEARER", "synthetic-mail-authority")
    claude = vision_environment("claude")
    assert claude["CLAUDE_CODE_OAUTH_TOKEN"] == "synthetic-claude-grant"
    assert claude["DISABLE_AUTOUPDATER"] == "1"
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in vision_environment("codex")
    assert "OP_SERVICE_ACCOUNT_TOKEN" not in claude
    assert "EXAMPLE_MAIL_BEARER" not in claude
