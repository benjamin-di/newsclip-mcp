"""Typed visual planning through least-privilege local agent CLIs."""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field, TypeAdapter, model_validator

from .models import FrozenModel

VisionProvider = Literal["codex", "claude"]


class VisualPlanKind(StrEnum):
    GRID = "grid"
    POINT = "point"
    DRAG = "drag"
    PASS = "pass"


class NormalizedPoint(FrozenModel):
    x: float = Field(ge=0, le=1)
    y: float = Field(ge=0, le=1)


class DragPath(FrozenModel):
    start: NormalizedPoint
    end: NormalizedPoint


class GridGeometry(FrozenModel):
    """Normalized grid bounds within the exact image sent to the planner."""

    top_left: NormalizedPoint
    bottom_right: NormalizedPoint
    rows: int = Field(ge=2, le=4)
    columns: int = Field(ge=2, le=4)

    @model_validator(mode="after")
    def validate_bounds(self) -> GridGeometry:
        if (
            self.bottom_right.x <= self.top_left.x
            or self.bottom_right.y <= self.top_left.y
        ):
            raise ValueError("grid bounds must have positive area")
        return self


class VisualPlan(FrozenModel):
    """Closed, normalized browser-action plan produced by a vision backend."""

    kind: VisualPlanKind
    indices: tuple[int, ...] = ()
    grid: GridGeometry | None = None
    points: tuple[NormalizedPoint, ...] = ()
    paths: tuple[DragPath, ...] = ()

    @model_validator(mode="after")
    def validate_payload(self) -> VisualPlan:
        populated = sum(
            bool(value) for value in (self.indices, self.points, self.paths)
        )
        if self.kind is VisualPlanKind.GRID:
            if not self.indices or populated != 1:
                raise ValueError("grid plan requires only tile indices")
            maximum_index = (
                self.grid.rows * self.grid.columns if self.grid is not None else 16
            )
            if len(self.indices) > 16 or any(
                index < 1 or index > maximum_index for index in self.indices
            ):
                raise ValueError("grid indices are out of bounds")
            if len(set(self.indices)) != len(self.indices):
                raise ValueError("grid indices must be unique")
        elif self.grid is not None:
            raise ValueError("only grid plans can carry grid geometry")
        elif self.kind is VisualPlanKind.POINT:
            if not self.points or len(self.points) > 8 or populated != 1:
                raise ValueError("point plan requires only bounded points")
        elif self.kind is VisualPlanKind.DRAG:
            if not self.paths or len(self.paths) > 4 or populated != 1:
                raise ValueError("drag plan requires only bounded paths")
        elif populated:
            raise ValueError("pass plan cannot carry actions")
        return self


class VisionPlanner(Protocol):
    def plan(
        self,
        image: Path,
        *,
        companion_images: Sequence[Path] = (),
        instruction: str,
        timeout_seconds: float,
    ) -> VisualPlan: ...


class VisionPlanningError(RuntimeError):
    """A bounded local vision turn was unavailable or returned no valid plan."""


_PLAN_ADAPTER = TypeAdapter(VisualPlan)
_MAX_INSTRUCTION_CHARACTERS = 8_000


_OTHER_PROVIDER: dict[VisionProvider, VisionProvider] = {
    "codex": "claude",
    "claude": "codex",
}
