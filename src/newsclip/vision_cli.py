"""Least-privilege command and environment policy for local vision CLIs."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

VisionProvider = Literal["codex", "claude"]


def daily_codex_model() -> tuple[str, str]:
    """The daily tier's Codex leg (model, effort): its model, else its fallback.

    Daily may run a Claude model; Codex-only callers then use the fallback
    which is on the other provider.
    """
    tier = {
        key: os.environ.get(f"AGENT_TIER_DAILY_{key}", "").strip()
        for key in ("MODEL", "EFFORT", "FALLBACK", "FALLBACK_EFFORT")
    }
    for model, effort in (
        (tier["MODEL"], tier["EFFORT"]),
        (tier["FALLBACK"], tier["FALLBACK_EFFORT"]),
    ):
        if model.startswith(("gpt-", "codex-")):
            return model, effort or "high"
    return "gpt-6.1-sol", "high"


def daily_claude_model() -> str:
    """Resolve Claude's daily-tier leg from the shared model manifest env."""

    for name in ("AGENT_TIER_DAILY_MODEL", "AGENT_TIER_DAILY_FALLBACK"):
        model = os.environ.get(name, "").strip()
        if model.startswith("claude-"):
            return model
    return "claude-sonnet-5-5"


def vision_environment(provider: VisionProvider) -> dict[str, str]:
    """Return only the process state required for local OAuth and TLS.

    Egress note: the solver's AI-API traffic may need a dedicated proxy on
    hosts where model API traffic needs a separate route, so
    ``NEWSCLIP_VISION_HTTPS_PROXY`` (with optional ``NEWSCLIP_VISION_NO_PROXY``)
    is injected into the child as HTTPS_PROXY/HTTP_PROXY. The parent's own
    HTTPS_PROXY is deliberately **not** inherited: provider login and browser
    traffic must originate from the host IP the minted session will later be
    used from, and one ambient proxy variable would silently route both.
    """

    environment = {
        "HOME": os.environ.get("HOME", str(Path.home())),
        "PATH": os.environ.get("PATH", os.defpath),
    }
    for name in ("LANG", "LC_ALL", "SSL_CERT_DIR", "SSL_CERT_FILE"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    config_name = "CODEX_HOME" if provider == "codex" else "CLAUDE_CONFIG_DIR"
    config_value = os.environ.get(config_name)
    if config_value:
        environment[config_name] = config_value
    if provider == "claude":
        # The configured service grant belongs only to the Claude child;
        # provider credentials and the 1Password service token never reach it.
        token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
        if token:
            environment["CLAUDE_CODE_OAUTH_TOKEN"] = token
        environment["DISABLE_AUTOUPDATER"] = "1"
    vision_proxy = os.environ.get("NEWSCLIP_VISION_HTTPS_PROXY", "").strip()
    if vision_proxy:
        environment["HTTPS_PROXY"] = vision_proxy
        environment["HTTP_PROXY"] = vision_proxy
        no_proxy = os.environ.get("NEWSCLIP_VISION_NO_PROXY", "").strip()
        if no_proxy:
            environment["NO_PROXY"] = no_proxy
    return environment


def codex_vision_command(
    executable: str,
    *,
    working_directory: Path,
    images: Sequence[Path],
    output_file: Path | None = None,
) -> list[str]:
    """Build Codex native-image input without shell, browser, or connector tools."""

    if not images:
        raise ValueError("Codex vision requires at least one image")
    root = working_directory.resolve()
    if output_file is not None and output_file.resolve().parent != root:
        raise ValueError("Codex vision output must stay in the working directory")
    command = [
        executable,
        "-a",
        "never",
        "exec",
        "--model",
        daily_codex_model()[0],
        "--json",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--disable",
        "shell_tool",
        "--disable",
        "unified_exec",
        "--disable",
        "apps",
        "--disable",
        "browser_use",
        "--disable",
        "computer_use",
        "--disable",
        "multi_agent",
        "--config",
        'web_search="disabled"',
        # Plans must arrive while the captured browser task is still current.
        # Do not inherit the CLI's general-purpose reasoning default.
        # Deliberately low, not the daily tier's effort: solving is latency-bound.
        "--config",
        'model_reasoning_effort="low"',
        "--cd",
        str(root),
    ]
    if output_file is not None:
        command.extend(("--output-last-message", str(output_file.resolve())))
    for image in images:
        command.extend(("--image", str(image.resolve())))
    command.append("-")
    return command


def claude_vision_command(
    executable: str,
    *,
    working_directory: Path,
    images: Sequence[Path],
) -> list[str]:
    """Build a Claude turn whose only readable files are challenge images."""

    if not images:
        raise ValueError("Claude vision requires at least one image")
    root = working_directory.resolve()
    if any(image.resolve().parent != root for image in images):
        raise ValueError(
            "Claude vision images must be in the private working directory"
        )
    allowed_files = {image.resolve() for image in images}
    if root.is_dir() and any(
        path.resolve() not in allowed_files for path in root.iterdir()
    ):
        raise ValueError("Claude vision working directory contains unrelated files")
    return [
        executable,
        "--print",
        "--output-format",
        "json",
        "--model",
        daily_claude_model(),
        "--effort",
        "low",
        "--tools",
        "Read",
        "--allowedTools",
        "Read",
        "--permission-mode",
        "dontAsk",
        "--safe-mode",
        "--setting-sources",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--no-session-persistence",
        "--no-chrome",
        "--disable-slash-commands",
        "--add-dir",
        str(root),
    ]
