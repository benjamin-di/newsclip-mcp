"""Attribute retained diagnostics after existing formatters and redaction."""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Callable
from contextlib import asynccontextmanager
from copy import deepcopy
from functools import partial
from typing import Any

from .build_identity import log_fields


class IdentityFormatter(logging.Formatter):
    def __init__(self, original: logging.Formatter | None, *, tty: bool = False):
        super().__init__()
        self.original = original or logging.Formatter()
        self.tty = tty

    def format(self, record: logging.LogRecord) -> str:
        rendered = self.original.format(record)
        try:
            payload = json.loads(rendered)
        except (ValueError, TypeError):
            payload = None
        fields = {"level": record.levelname, "logger": record.name, **log_fields()}
        if isinstance(payload, dict):
            for name in fields:
                if name in payload:
                    displaced = name + "_"
                    while displaced in payload:
                        displaced += "_"
                    payload[displaced] = payload[name]
            return json.dumps({**payload, **fields}, ensure_ascii=False)
        if self.tty:
            header = " ".join(f"{key}={value}" for key, value in fields.items())
            return "\n".join(
                f"{header} {line}" for line in rendered.splitlines() or [""]
            )
        return json.dumps({"message": rendered, **fields}, ensure_ascii=False)


def _native_console_dispatch(console: Any, render: Any, hook: Any) -> Any:
    """Scope render provenance to this thread without replacing print dispatch."""
    from contextlib import contextmanager
    from threading import local

    @contextmanager
    def dispatch() -> Any:
        key = "_build_identity_render_dispatch"
        with console._lock:
            state = vars(console).get(key)
            if state is None:
                missing = object()
                state = {
                    "local": local(),
                    "users": 0,
                    "render": console.render,
                    "saved_render": vars(console).get("render", missing),
                    "missing": missing,
                    "hooks": console._render_hooks,
                }

                def current() -> Any:
                    stack = getattr(state["local"], "stack", ())
                    return stack[-1] if stack else None

                def dispatch_render(*args: Any, **kwargs: Any) -> Any:
                    context = current()
                    if context is None:
                        yield from state["render"](*args, **kwargs)
                        return
                    stack = state["local"].stack
                    stack.append(None)
                    try:
                        yield from context[0](*args, **kwargs)
                    finally:
                        stack.pop()

                class DispatchHook:
                    def __init__(self, original: Any) -> None:
                        self.original = original

                    def process_renderables(self, renderables: list[Any]) -> list[Any]:
                        context = current()
                        target = self.original
                        if context is not None:
                            target = context[1](target)
                        return target.process_renderables(renderables)

                class DispatchHooks:
                    def __getattr__(self, name: str) -> Any:
                        return getattr(state["hooks"], name)

                    def __getitem__(self, index: Any) -> Any:
                        items = state["hooks"][index]
                        if current() is None:
                            return items
                        if isinstance(index, slice):
                            return [DispatchHook(item) for item in items]
                        return DispatchHook(items)

                    def __len__(self) -> int:
                        return len(state["hooks"])

                    def __iter__(self) -> Any:
                        return iter(self[:])

                state["dispatch_render"] = dispatch_render
                state["dispatch_hooks"] = DispatchHooks()
                console.render = dispatch_render
                console._render_hooks = state["dispatch_hooks"]
                vars(console)[key] = state
            state["users"] += 1
            stack = getattr(state["local"], "stack", None)
            if stack is None:
                stack = state["local"].stack = []
            stack.append((render, hook))
        try:
            yield
        finally:
            with console._lock:
                stack.pop()
                state["users"] -= 1
                if not state["users"]:
                    if console.render is state["dispatch_render"]:
                        if state["saved_render"] is state["missing"]:
                            del console.render
                        else:
                            console.render = state["saved_render"]
                    if console._render_hooks is state["dispatch_hooks"]:
                        console._render_hooks = state["hooks"]
                    del vars(console)[key]

    return dispatch()


class _RichSink(logging.Handler):
    """Attach identity only after Rich applies its rendering and traceback policy."""

    def __init__(self, original: Any, identity_formatter: logging.Formatter) -> None:
        super().__init__(original.level)
        self.original = original
        self.filters = list(original.filters)
        self.setFormatter(original.formatter)
        self.identity_formatter = identity_formatter

    @property
    def stream(self) -> Any:
        return self.original.console.file

    def setFormatter(self, formatter: logging.Formatter | None) -> None:
        super().setFormatter(formatter)
        self.original.setFormatter(formatter)

    def emit(self, record: logging.LogRecord) -> None:
        owner = self
        original: Any = self.original
        original.acquire()
        console = original.console

        class RecordConsole:
            def __getattr__(self, name: str) -> Any:
                return getattr(console, name)

            def __setattr__(self, name: str, value: Any) -> None:
                setattr(console, name, value)

            def __delattr__(self, name: str) -> None:
                delattr(console, name)

            def print(self, *objects: Any, **kwargs: Any) -> None:
                from rich.control import Control, ControlType
                from rich.live import Live
                from rich.live_render import LiveRender
                from rich.segment import Segment

                host_renderables: set[int] = set()
                markers: dict[int, tuple[Any, bool]] = {}

                class Hook:
                    def __init__(self, original_hook: Any) -> None:
                        self.original_hook = original_hook

                    def process_renderables(self, renderables: list[Any]) -> list[Any]:
                        incoming = {id(item) for item in renderables}
                        result = self.original_hook.process_renderables(renderables)
                        if isinstance(self.original_hook, Live):
                            host_renderables.update(
                                id(item)
                                for item in result
                                if id(item) not in incoming
                                and isinstance(item, (Control, LiveRender))
                            )
                        return result

                def marker(owned: bool) -> Any:
                    # Fresh tuple identity carries provenance through native cropping.
                    controls = [(ControlType.BELL,)]
                    token = tuple(controls)
                    markers[id(token)] = (token, owned)
                    return Segment("", None, token)

                def render(renderable: Any, options: Any = None) -> Any:
                    yield marker(id(renderable) not in host_renderables)
                    yield from console.render(renderable, options)
                    yield marker(True)

                with console:
                    # Rich owns a thread-local buffer; isolate this print from host
                    # output and restore it even if a hook or renderer raises.
                    prefix = console._buffer[:]
                    console._buffer.clear()
                    try:
                        with _native_console_dispatch(console, render, Hook):
                            console.print(*objects, **kwargs)
                        raw = console._buffer[:]
                    finally:
                        console._buffer[:] = prefix
                    groups: list[tuple[bool, list[Any]]] = []
                    owned = True
                    for segment in raw:
                        provenance = markers.get(id(segment.control))
                        if provenance is not None:
                            owned = provenance[1]
                        elif groups and groups[-1][0] == owned:
                            groups[-1][1].append(segment)
                        else:
                            groups.append((owned, [segment]))
                    for owned, segments in groups:
                        if not owned:
                            console._buffer.extend(segments)
                            continue
                        rendered = console._render_buffer(segments)
                        if not rendered:
                            continue
                        retained = logging.makeLogRecord(
                            {
                                "name": record.name,
                                "levelno": record.levelno,
                                "levelname": record.levelname,
                                "created": record.created,
                                "msecs": record.msecs,
                                "msg": rendered.rstrip("\n"),
                                "args": (),
                            }
                        )
                        attributed = owner.identity_formatter.format(retained)
                        try:
                            structured = json.loads(attributed)
                        except (ValueError, TypeError):
                            structured = None
                        if getattr(
                            owner.identity_formatter, "tty", False
                        ) and not isinstance(structured, dict):
                            # These formatters declare a constant prefix
                            # for every native line.
                            native_line = (rendered.rstrip("\n").splitlines() or [""])[
                                0
                            ]
                            attributed_line = attributed.splitlines()[0]
                            header = (
                                attributed_line[
                                    : len(attributed_line) - len(native_line)
                                ]
                                if native_line
                                else attributed_line
                            )
                            retained_segments = segments[:]
                            for index in range(len(retained_segments) - 1, -1, -1):
                                segment = retained_segments[index]
                                if segment.control:
                                    continue
                                trimmed = segment.text.rstrip("\n")
                                retained_segments[index] = Segment(
                                    trimmed, segment.style
                                )
                                if trimmed or trimmed == segment.text:
                                    break
                            line_start = True
                            for segment in retained_segments:
                                if segment.control:
                                    console._buffer.append(segment)
                                    continue
                                for part in segment.text.splitlines(keepends=True):
                                    if line_start:
                                        console._buffer.append(Segment(header))
                                    console._buffer.append(Segment(part, segment.style))
                                    line_start = part.endswith("\n")
                            console._buffer.append(Segment.line())
                        else:
                            from rich.ansi import AnsiDecoder

                            text = AnsiDecoder().decode_line(attributed + "\n")
                            text.end = ""
                            console._buffer.extend(
                                console.render(
                                    text,
                                    console.options.update(
                                        no_wrap=True, overflow="ignore"
                                    ),
                                )
                            )

        try:
            original.console = RecordConsole()
            original.emit(record)
        finally:
            original.console = console
            original.release()


def stamp_handlers() -> None:
    loggers = [
        logging.getLogger(),
        *(
            logger
            for name, logger in logging.Logger.manager.loggerDict.copy().items()
            if isinstance(logger, logging.Logger)
            and name.split(".")[0] in {"newsclip", "fastmcp", "mcp", "uvicorn"}
        ),
    ]
    rich = sys.modules.get("rich.logging")
    replacements: dict[logging.Handler, logging.Handler] = {}
    for logger in loggers:
        for index, existing in enumerate(logger.handlers):
            handler = replacements.get(existing, existing)
            if rich is not None and isinstance(handler, rich.RichHandler):
                tty = bool(getattr(handler.console.file, "isatty", lambda: False)())
                handler = _RichSink(
                    handler, IdentityFormatter(logging.Formatter(), tty=tty)
                )
                replacements[existing] = handler
            logger.handlers[index] = handler
            if isinstance(handler, _RichSink):
                continue
            if not isinstance(handler.formatter, IdentityFormatter):
                tty = bool(
                    getattr(getattr(handler, "stream", None), "isatty", lambda: False)()
                )
                handler.setFormatter(IdentityFormatter(handler.formatter, tty=tty))


def configure() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    stamp_handlers()


def run_command(invoke: Callable[[], object]) -> None:
    """Keep unexpected startup failures useful without echoing private inputs."""
    configure()
    try:
        invoke()
    except Exception as error:
        stamp_handlers()
        logging.getLogger("newsclip").error("Command failed (%s)", type(error).__name__)
        raise SystemExit(1) from None


@asynccontextmanager
async def runtime_logs(server):
    stamp_handlers()
    yield


def _formatter(formatter_type, **options):
    return IdentityFormatter(formatter_type(**options))


def uvicorn_log_config():
    from uvicorn.config import LOGGING_CONFIG
    from uvicorn.logging import AccessFormatter, DefaultFormatter

    config = deepcopy(LOGGING_CONFIG)
    for name, formatter_type in (
        ("default", DefaultFormatter),
        ("access", AccessFormatter),
    ):
        config["formatters"][name]["()"] = partial(_formatter, formatter_type)
    return config
