"""Synthetic artifact, logging and installed-package attribution contracts."""

import asyncio
import importlib.util
import io
import json
import logging
import os
import runpy
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from newsclip import build_identity as identity
from newsclip import log

ROOT = Path(__file__).resolve().parents[1]
VERSION = identity.BUILD.version
REVISION = "a" * 40
EMBED = runpy.run_path(str(ROOT / "scripts/embed-build-identity.py"))["embed"]
VERIFY = runpy.run_path(str(ROOT / "scripts/check-build-distributions.py"))["verify"]


def _source(root):
    for name in (
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "LICENSE",
        "NOTICE",
        ".gitignore",
    ):
        shutil.copy(ROOT / name, root)
    shutil.copytree(ROOT / "src", root / "src")
    return root


def test_build_inputs_and_runtime_override_rejection(tmp_path, monkeypatch):
    _source(tmp_path)
    for product, source in [
        ("", REVISION),
        ("99.0.0", REVISION),
        (VERSION, "unknown"),
        (VERSION, "a" * 12),
    ]:
        with pytest.raises(ValueError):
            EMBED(tmp_path, product, source)
    with pytest.raises(ValueError, match="fingerprint"):
        EMBED(tmp_path, VERSION, REVISION, expected_fingerprint="0" * 64)
    EMBED(tmp_path, "v" + VERSION, REVISION, dirty=True)
    path = tmp_path / "src/newsclip/build_identity.json"
    monkeypatch.setenv("NEWSCLIP_BUILD_REVISION", "f" * 40)
    monkeypatch.setenv("NEWSCLIP_BUILD_SOURCE_FINGERPRINT", "f" * 64)
    build = identity.load_build(path)
    assert build.source_revision == REVISION and build.dirty is True
    assert len(build.source_fingerprint) == 64
    for payload in [
        "[]",
        "{broken",
        '{"version":"1","version":"2"}',
        json.dumps({"service": "wrong"}),
    ]:
        path.write_text(payload)
        with pytest.raises(ValueError):
            identity.load_build(path)


def test_unknown_requires_editable(tmp_path, monkeypatch):
    path = tmp_path / "missing"
    monkeypatch.setattr(
        identity, "distribution", lambda _: SimpleNamespace(read_text=lambda _: "{}")
    )
    with pytest.raises(ValueError, match="Missing"):
        identity.load_build(path)
    monkeypatch.setattr(
        identity,
        "distribution",
        lambda _: SimpleNamespace(read_text=lambda _: '{"dir_info":{"editable":true}}'),
    )
    assert identity.load_build(path).source_revision == "unknown"


@pytest.mark.parametrize("rich", [False, True])
def test_isolated_formatter_filter_quiet_and_structured_fields_survive(rich):
    class Closed(logging.Formatter):
        def format(self, record):
            return json.dumps(
                {
                    "msg": "sanitized",
                    "count": 7,
                    "flag": False,
                    "level": {"captured": True},
                    "service": [1],
                }
            )

    stream = io.StringIO()
    if rich:
        from rich.console import Console
        from rich.logging import RichHandler

        console = Console(file=stream, quiet=True, width=240)
        handler = RichHandler(
            console=console, show_time=False, show_level=False, show_path=False
        )
    else:
        handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(Closed())
    handler.addFilter(lambda record: record.msg != "suppressed")
    logger = logging.getLogger("fastmcp.identity.synthetic")
    previous = logger.handlers, logger.level, logger.propagate
    logger.handlers, logger.level, logger.propagate = [handler], logging.DEBUG, False
    try:
        log.stamp_handlers()
        log.stamp_handlers()
        if rich:
            logger.critical("quiet")
            assert stream.getvalue() == ""
            console.quiet = False
        logger.error("private original", extra={"private_extra": "omitted"})
        visible = stream.getvalue()
        logger.error("suppressed")
        logger.handlers[0].setLevel(logging.CRITICAL)
        logger.warning("below threshold")
        if rich:
            console.quiet = True
            logger.critical("quiet again")
        assert stream.getvalue() == visible
        payload = json.loads(visible)
        assert (
            payload["msg"] == "sanitized"
            and payload["count"] == 7
            and payload["flag"] is False
        )
        assert payload["level"] == "ERROR" and payload["level_"] == {"captured": True}
        assert payload["service_"] == [1] and payload["service"] == "newsclip"
        assert (
            payload["source_revision"] == identity.BUILD.source_revision
            and payload["instance"]
        )
        assert "private" not in visible and "omitted" not in visible
        assert logger.handlers[0].stream is stream
    finally:
        logger.handlers, logger.level, logger.propagate = previous


def test_native_mcp_product_version():
    pytest.importorskip("fastmcp")
    from fastmcp import Client

    from newsclip.mcp_server import new_fastmcp

    async def initialize():
        for mode in ("legacy", "auto"):
            async with Client(
                new_fastmcp("Newsclip synthetic", instructions=""), mode=mode
            ) as client:
                assert client.server_info.version == VERSION

    asyncio.run(initialize())


@pytest.mark.parametrize("protocol", ["2025-03-26", "2025-11-25"])
def test_actual_stdio_retains_protocol_stdout_and_contextual_sdk_debug(
    tmp_path, protocol
):
    pytest.importorskip("fastmcp")
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol,
            "capabilities": {},
            "clientInfo": {"name": "synthetic", "version": "1"},
        },
    }
    environment = {
        **os.environ,
        "NEWSCLIP_STATE_HOME": str(tmp_path / "state"),
        "NEWSCLIP_DATA_HOME": str(tmp_path / "data"),
        "NEWSCLIP_CONFIG_HOME": str(tmp_path / "config"),
        "FASTMCP_LOG_LEVEL": "DEBUG",
    }
    result = subprocess.run(
        [sys.executable, "-m", "newsclip", "mcp"],
        input=json.dumps(request) + "\n",
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    response = json.loads(result.stdout)
    assert response["result"]["serverInfo"]["version"] == VERSION
    records = [json.loads(line) for line in result.stderr.splitlines()]
    assert records
    assert all(
        row["service"] == "newsclip"
        and row["version"] == VERSION
        and row["source_revision"] == identity.BUILD.source_revision
        and row["instance"]
        for row in records
    )


@pytest.mark.parametrize(
    "module", ["newsclip.cli", "newsclip.remote_cli", "newsclip.entrypoint"]
)
def test_unexpected_startup_failure_is_attributed_without_raw_inputs(module):
    program = """
import importlib, sys
module = importlib.import_module(sys.argv[1])
def fail():
    raise RuntimeError("synthetic-private-value /private/synthetic-path")
if sys.argv[1] == "newsclip.entrypoint":
    module._invoke = fail
else:
    module.app = fail
module.run()
"""
    result = subprocess.run(
        [sys.executable, "-c", program, module],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1 and result.stdout == ""
    record = json.loads(result.stderr)
    assert record["level"] == "ERROR" and record["service"] == "newsclip"
    assert "RuntimeError" in record["message"] and record["instance"]
    assert "synthetic-private" not in result.stderr and "/private" not in result.stderr


def test_retained_traces_attribute_new_records_without_relabeling_legacy(tmp_path):
    from newsclip.browser_runtime.events import (
        DisplayClass,
        RuntimeRecord,
        RuntimeTrace,
        SurfaceMode,
        SurfaceSelectedEvent,
    )
    from newsclip.timing import (
        TimingOperation,
        TimingRecord,
        TimingRecorder,
        TimingTransport,
    )

    trace_path = tmp_path / "runtime.jsonl"
    trace = RuntimeTrace(trace_path, run_id="synthetic")
    trace.write(
        SurfaceSelectedEvent(
            mode=SurfaceMode.MANAGED_VIRTUAL, display_class=DisplayClass.VIRTUAL_LOCAL
        )
    )
    recorder = TimingRecorder(tmp_path / "timings")
    with recorder.operation(
        TimingOperation.GET, provider="ft", transport=TimingTransport.HTTP
    ) as operation:
        pass
    assert operation.path is not None
    for path, model in [(trace_path, RuntimeRecord), (operation.path, TimingRecord)]:
        for line in path.read_text().splitlines():
            payload = json.loads(line)
            record = model.model_validate(payload)
            assert record.service == "newsclip" and record.version == VERSION
            assert (
                record.source_revision == identity.BUILD.source_revision
                and record.instance
            )
            legacy = model.model_validate(
                {
                    key: value
                    for key, value in payload.items()
                    if key not in identity.log_fields()
                }
            )
            assert (
                legacy.service
                is legacy.version
                is legacy.source_revision
                is legacy.instance
                is None
            )


def test_watcher_logs_closed_outcome_with_context_without_forwarding_child_output(
    monkeypatch, tmp_path, capsys
):
    import newsclip.recovery_watch as watcher

    class SyntheticWatch:
        def __init__(self, *args, **kwargs):
            pass

        def tick(self):
            return [
                {"provider": "ft", "action": "recovery_worker_failed", "exit_code": 7}
            ]

        def close(self):
            pass

    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path))
    monkeypatch.setenv("NEWSCLIP_KEEPER_PROVIDERS", "ft")
    monkeypatch.setattr(watcher, "RecoveryWatch", SyntheticWatch)
    monkeypatch.setattr(
        watcher.time, "sleep", lambda _: (_ for _ in ()).throw(SystemExit(0))
    )
    with pytest.raises(SystemExit):
        watcher._watch_account()
    output = capsys.readouterr()
    payload = json.loads(output.out)
    assert output.err == ""
    assert payload["action"] == "recovery_worker_failed" and payload["exit_code"] == 7
    assert {key: payload[key] for key in identity.log_fields()} == identity.log_fields()


def test_wheel_sdist_and_installed_artifact_acceptance(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    _source(source)
    EMBED(source, VERSION, REVISION)
    output = tmp_path / "dist"
    result = subprocess.run(
        [
            "uv",
            "build",
            "--offline",
            "--no-sources",
            "--out-dir",
            str(output),
            str(source),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    wheel, sdist = next(output.glob("*.whl")), next(output.glob("*.tar.gz"))
    VERIFY(output, VERSION, REVISION)
    with pytest.raises(ValueError, match="fingerprint"):
        VERIFY(output, VERSION, REVISION, "0" * 64)
    with pytest.raises(ValueError, match="identity"):
        VERIFY(output, VERSION, "b" * 40)
    tampered = tmp_path / "tampered"
    tampered.mkdir()
    shutil.copy(sdist, tampered)
    with (
        zipfile.ZipFile(wheel) as original,
        zipfile.ZipFile(tampered / wheel.name, "w") as changed,
    ):
        for entry in original.infolist():
            data = original.read(entry)
            if entry.filename == "newsclip/cli.py":
                data += b"\n# Synthetic source mismatch.\n"
            changed.writestr(entry, data)
    with pytest.raises(ValueError, match="different application source"):
        VERIFY(tampered, VERSION, REVISION)
    with zipfile.ZipFile(wheel) as archive:
        assert (
            json.loads(archive.read("newsclip/build_identity.json"))["source_revision"]
            == REVISION
        )
    with tarfile.open(sdist) as archive:
        entry = next(
            item
            for item in archive.getmembers()
            if item.name.endswith("/src/newsclip/build_identity.json")
        )
        assert json.load(archive.extractfile(entry))["source_revision"] == REVISION
    installed = tmp_path / "installed"
    install = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--offline",
            "--no-deps",
            "--target",
            str(installed),
            str(wheel),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert install.returncode == 0, install.stderr
    script = ROOT / "scripts/check-build-identity.py"
    program = (
        "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));"
        "sys.argv=sys.argv[1:];runpy.run_path(sys.argv[0],run_name='__main__')"
    )
    environment = {**os.environ, "NEWSCLIP_BUILD_REVISION": "f" * 40}
    optional_mcp = ["--mcp"] if importlib.util.find_spec("fastmcp") else []
    for revision, expected in [(REVISION, 0), ("b" * 40, 1)]:
        accepted = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                program,
                str(installed),
                str(script),
                revision,
                VERSION,
                *optional_mcp,
            ],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert accepted.returncode == expected, accepted.stderr
    installed_stamp = installed / "newsclip/build_identity.json"
    conflict = json.loads(installed_stamp.read_text())
    conflict["version"] = "99.0.0"
    installed_stamp.write_text(json.dumps(conflict))
    conflicting = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(installed),
            str(script),
            REVISION,
            VERSION,
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert conflicting.returncode != 0 and "conflicts" in conflicting.stderr
    installed_stamp.unlink()
    missing = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(installed),
            str(script),
            REVISION,
            VERSION,
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert (
        missing.returncode != 0
        and "Missing application build identity" in missing.stderr
    )


def test_unknown_is_not_available_to_uninstalled_source(tmp_path, monkeypatch):
    def missing(_):
        raise identity.PackageNotFoundError("newsclip")

    monkeypatch.setattr(identity, "distribution", missing)
    with pytest.raises(ValueError, match="Missing"):
        identity.load_build(tmp_path / "missing")


def test_startup_failures_and_child_diagnostics_are_attributed():
    program = """
import logging
from newsclip.log import configure
configure()
logging.getLogger('newsclip.synthetic').warning('child diagnostic')
from newsclip import entrypoint
def broken(_):
    raise RuntimeError('PRIVATE_STARTUP_SENTINEL')
entrypoint.find_spec = broken
entrypoint.run()
"""
    instances = []
    for _ in range(2):
        child = subprocess.run(
            [sys.executable, "-I", "-c", program],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert child.returncode == 1 and child.stdout == ""
        records = [json.loads(line) for line in child.stderr.splitlines()]
        assert [record["level"] for record in records] == ["WARNING", "ERROR"]
        assert all(record["service"] == "newsclip" for record in records)
        assert all(record["version"] == VERSION for record in records)
        assert all(
            record["source_revision"] == identity.BUILD.source_revision
            for record in records
        )
        assert records[0]["instance"] == records[1]["instance"]
        assert "PRIVATE_STARTUP_SENTINEL" not in child.stderr
        instances.append(records[0]["instance"])
    assert instances[0] != instances[1]


def test_uvicorn_and_late_sdk_handlers_keep_streams_and_debug():
    pytest.importorskip("uvicorn")
    program = """
import asyncio, logging
from newsclip.log import configure, runtime_logs, uvicorn_log_config
configure()
from uvicorn import Config
Config('synthetic:app', log_config=uvicorn_log_config(), log_level='debug')
logging.getLogger('uvicorn.error').error('startup diagnostic')
logger = logging.getLogger('mcp.synthetic')
logger.propagate = False
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())
async def run():
    async with runtime_logs(None):
        logger.debug('retained debug')
asyncio.run(run())
"""
    child = subprocess.run(
        [sys.executable, "-I", "-c", program],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert child.returncode == 0 and child.stdout == "", child.stderr
    records = [json.loads(line) for line in child.stderr.splitlines()]
    assert [record["level"] for record in records] == ["ERROR", "DEBUG"]
    assert records[0]["instance"] == records[1]["instance"]
    assert all(record["service"] == "newsclip" for record in records)


def test_stdio_native_identity_keeps_stdout_protocol_only():
    pytest.importorskip("fastmcp")
    program = """
from newsclip.log import configure
configure()
from newsclip.mcp_server import new_fastmcp
server = new_fastmcp('synthetic', instructions='')
server.run(transport='stdio', show_banner=False)
"""
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", program],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "synthetic", "version": "1"},
        },
    }
    try:
        child.stdin.write(json.dumps(request) + "\n")
        child.stdin.flush()
        import select

        assert select.select([child.stdout], [], [], 15)[0], "No initialize response"
        response = json.loads(child.stdout.readline())
        assert response["result"]["serverInfo"]["version"] == VERSION
        child.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )
        child.stdin.flush()
        stdout, stderr = child.communicate(timeout=15)
        assert child.returncode == 0, stderr
        assert stdout == ""
        for line in stderr.splitlines():
            record = json.loads(line)
            assert record["service"] == "newsclip" and record["instance"]
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate()
