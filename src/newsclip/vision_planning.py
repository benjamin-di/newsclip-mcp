"""Typed visual planning through least-privilege local agent CLIs."""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from pydantic import TypeAdapter, ValidationError

from .provider_readiness import vision_auth_available
from .vision_cli import (
    VisionProvider,
    claude_vision_command,
    codex_vision_command,
    vision_environment,
)
from .visual_plans import (
    DragPath as DragPath,
)
from .visual_plans import (
    GridGeometry as GridGeometry,
)
from .visual_plans import (
    NormalizedPoint as NormalizedPoint,
)
from .visual_plans import (
    VisionPlanner as VisionPlanner,
)
from .visual_plans import (
    VisionPlanningError as VisionPlanningError,
)
from .visual_plans import (
    VisualPlan as VisualPlan,
)
from .visual_plans import (
    VisualPlanKind as VisualPlanKind,
)

_PLAN_ADAPTER = TypeAdapter(VisualPlan)
_MAX_INSTRUCTION_CHARACTERS = 8_000


_OTHER_PROVIDER: dict[VisionProvider, VisionProvider] = {
    "codex": "claude",
    "claude": "codex",
}


class LocalCliVisionPlanner:
    """Invoke a selected local OAuth agent and validate its visual plan.

    With ``failover`` (the default) a turn the selected CLI cannot complete,
    such as a usage cap or an expired login, goes to the other CLI when it is
    installed and locally logged in; its login is checked only then. A caller
    that chose its backend deliberately passes ``failover=False``.
    """

    def __init__(self, provider: str | None = None, *, failover: bool = True) -> None:
        selected = (provider or os.environ.get("AGENT_PROVIDER") or "codex").lower()
        if selected not in {"codex", "claude"}:
            raise ValueError("vision provider must be codex or claude")
        self._provider = cast(VisionProvider, selected)
        self._failover = failover

    @property
    def provider(self) -> VisionProvider:
        return self._provider

    def plan(
        self,
        image: Path,
        *,
        companion_images: Sequence[Path] = (),
        instruction: str,
        timeout_seconds: float,
    ) -> VisualPlan:
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("vision timeout must be positive and finite")
        body = instruction.strip()
        if not body or len(body) > _MAX_INSTRUCTION_CHARACTERS:
            raise ValueError("vision instruction must be nonblank and bounded")
        executable = shutil.which(self._provider)
        if not image.is_file() or executable is None:
            raise VisionPlanningError("vision planner is unavailable")
        image = image.resolve()
        companions = tuple(value.resolve() for value in companion_images)
        if any(not value.is_file() for value in companions):
            raise VisionPlanningError("vision companion image is unavailable")
        working_directory = image.parent
        if any(value.parent != working_directory for value in companions):
            raise VisionPlanningError("vision images must share one private directory")
        images = (image, *companions)
        deadline = time.monotonic() + timeout_seconds
        failure: BaseException | None = None
        provider: VisionProvider | None = self._provider
        while provider is not None:
            plan, failure = self._attempt(
                provider, executable, body, images, deadline, failure
            )
            if plan is not None:
                return plan
            provider, executable = self._fallback(provider, deadline)
        raise VisionPlanningError("vision planner failed") from failure

    def _fallback(
        self, failed: VisionProvider, deadline: float
    ) -> tuple[VisionProvider | None, str]:
        """The other CLI, once, when installed and locally logged in."""

        other = _OTHER_PROVIDER[failed]
        if not self._failover or failed != self._provider:
            return None, ""
        if deadline - time.monotonic() < 1.0:
            return None, ""
        executable = shutil.which(other)
        if executable is None or not vision_auth_available(other):
            return None, ""
        return other, executable

    def _attempt(
        self,
        provider: VisionProvider,
        executable: str,
        instruction: str,
        images: tuple[Path, ...],
        deadline: float,
        failure: BaseException | None,
    ) -> tuple[VisualPlan | None, BaseException | None]:
        working_directory = images[0].parent
        body = instruction
        if provider == "codex":
            command = codex_vision_command(
                executable,
                working_directory=working_directory,
                images=images,
            )
        else:
            paths = ", ".join(str(value) for value in images)
            body += f"\nUse the Read tool on these images in order: {paths}."
            command = claude_vision_command(
                executable,
                working_directory=working_directory,
                images=images,
            )
        for _ in range(2):
            remaining = deadline - time.monotonic()
            if remaining < 1.0:
                break
            try:
                completed = subprocess.run(
                    command,
                    input=body,
                    text=True,
                    capture_output=True,
                    timeout=remaining,
                    check=False,
                    cwd=working_directory,
                    env=vision_environment(provider),
                    shell=False,
                )
                if completed.returncode != 0:
                    failure = VisionPlanningError("vision planner process failed")
                    continue
                value = _extract_plan_object(completed.stdout)
                return _PLAN_ADAPTER.validate_python(value), failure
            except (
                OSError,
                subprocess.TimeoutExpired,
                VisionPlanningError,
                ValidationError,
            ) as error:
                failure = error
        return None, failure


def _extract_plan_object(text: str) -> object:
    value = text.strip()
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        decoded = None
    if isinstance(decoded, Mapping):
        # Claude's JSON mode and Codex JSONL may wrap the model message.
        for key in ("result", "text"):
            nested = decoded.get(key)
            if isinstance(nested, str):
                return _extract_plan_object(nested)
        if "kind" in decoded:
            return decoded
    for line in reversed(value.splitlines()):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, Mapping):
            item = row.get("item")
            if isinstance(item, Mapping) and item.get("type") == "agent_message":
                message = item.get("text")
                if isinstance(message, str):
                    return _extract_plan_object(message)
            if "kind" in row:
                return row
    start, end = value.find("{"), value.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(value[start : end + 1])
        except json.JSONDecodeError:
            pass
    raise VisionPlanningError("vision planner returned no plan")
