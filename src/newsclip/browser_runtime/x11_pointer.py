"""Native X11 pointer delivery for headed virtual browser challenges."""

from __future__ import annotations

import ctypes
import math
import os
from dataclasses import dataclass
from typing import Any


class NativePointerUnavailable(RuntimeError):
    """The selected virtual surface cannot deliver native pointer events."""


@dataclass(frozen=True, slots=True)
class _ScreenTransform:
    left: float
    top: float
    scale: float

    def map(self, x: float, y: float) -> tuple[int, int]:
        return (
            round((self.left + x) * self.scale),
            round((self.top + y) * self.scale),
        )


class X11Pointer:
    """Send pointer events through XTest instead of the browser debug protocol."""

    def __init__(self, page: Any) -> None:
        try:
            self._x11 = ctypes.CDLL("libX11.so.6")
            self._xtst = ctypes.CDLL("libXtst.so.6")
        except OSError as error:
            raise NativePointerUnavailable("x11 libraries unavailable") from error
        _configure_libraries(self._x11, self._xtst)

        display_name = os.environ.get("DISPLAY", "").strip()
        if not display_name:
            raise NativePointerUnavailable("x11 display unavailable")
        self._display = self._x11.XOpenDisplay(os.fsencode(display_name))
        if not self._display:
            raise NativePointerUnavailable("x11 display unavailable")

        try:
            event_base = ctypes.c_int()
            error_base = ctypes.c_int()
            major = ctypes.c_int()
            minor = ctypes.c_int()
            if not self._xtst.XTestQueryExtension(
                self._display,
                ctypes.byref(event_base),
                ctypes.byref(error_base),
                ctypes.byref(major),
                ctypes.byref(minor),
            ):
                raise NativePointerUnavailable("x11 xtest unavailable")
            self._screen = int(self._x11.XDefaultScreen(self._display))
            display_width = int(self._x11.XDisplayWidth(self._display, self._screen))
            self._transform = _screen_transform(page, display_width=display_width)
            self._last_position = self._query_position()
        except BaseException:
            self.close()
            raise

    def move(self, x: float, y: float, *, steps: int = 1) -> None:
        target = self._transform.map(x, y)
        count = max(1, int(steps))
        origin = self._last_position
        for index in range(1, count + 1):
            if origin is None:
                next_x, next_y = target
            else:
                progress = index / count
                next_x = round(origin[0] + (target[0] - origin[0]) * progress)
                next_y = round(origin[1] + (target[1] - origin[1]) * progress)
            if not self._xtst.XTestFakeMotionEvent(
                self._display,
                self._screen,
                next_x,
                next_y,
                0,
            ):
                raise NativePointerUnavailable("x11 pointer motion failed")
            self._x11.XFlush(self._display)
        self._last_position = target

    def down(self) -> None:
        self._button(pressed=True)

    def up(self) -> None:
        self._button(pressed=False)

    def close(self) -> None:
        display = getattr(self, "_display", None)
        if display:
            self._display = None
            self._x11.XCloseDisplay(display)

    def _button(self, *, pressed: bool) -> None:
        if not self._xtst.XTestFakeButtonEvent(
            self._display,
            1,
            pressed,
            0,
        ):
            raise NativePointerUnavailable("x11 pointer button failed")
        self._x11.XFlush(self._display)

    def _query_position(self) -> tuple[int, int] | None:
        root = self._x11.XRootWindow(self._display, self._screen)
        root_return = ctypes.c_ulong()
        child_return = ctypes.c_ulong()
        root_x = ctypes.c_int()
        root_y = ctypes.c_int()
        window_x = ctypes.c_int()
        window_y = ctypes.c_int()
        mask = ctypes.c_uint()
        if not self._x11.XQueryPointer(
            self._display,
            root,
            ctypes.byref(root_return),
            ctypes.byref(child_return),
            ctypes.byref(root_x),
            ctypes.byref(root_y),
            ctypes.byref(window_x),
            ctypes.byref(window_y),
            ctypes.byref(mask),
        ):
            return None
        return root_x.value, root_y.value


def _screen_transform(page: Any, *, display_width: int) -> _ScreenTransform:
    metrics = page.evaluate(
        """() => ({
            screenX: window.screenX,
            screenY: window.screenY,
            outerWidth: window.outerWidth,
            outerHeight: window.outerHeight,
            innerWidth: window.innerWidth,
            innerHeight: window.innerHeight,
            screenWidth: window.screen.width
        })"""
    )
    if not isinstance(metrics, dict) or display_width <= 0:
        raise NativePointerUnavailable("browser screen geometry unavailable")
    try:
        screen_x = _finite(metrics["screenX"])
        screen_y = _finite(metrics["screenY"])
        outer_width = _finite(metrics["outerWidth"])
        outer_height = _finite(metrics["outerHeight"])
        inner_width = _finite(metrics["innerWidth"])
        inner_height = _finite(metrics["innerHeight"])
        screen_width = _finite(metrics["screenWidth"])
    except (KeyError, TypeError, ValueError) as error:
        raise NativePointerUnavailable("browser screen geometry unavailable") from error
    if min(outer_width, outer_height, inner_width, inner_height, screen_width) <= 0:
        raise NativePointerUnavailable("browser screen geometry unavailable")

    side_inset = max(0.0, (outer_width - inner_width) / 2)
    top_inset = max(0.0, outer_height - inner_height - side_inset)
    return _ScreenTransform(
        left=screen_x + side_inset,
        top=screen_y + top_inset,
        scale=display_width / screen_width,
    )


def _finite(value: object) -> float:
    result = float(value)  # type: ignore[arg-type]
    if not math.isfinite(result):
        raise ValueError("non-finite screen geometry")
    return result


def _configure_libraries(x11: Any, xtst: Any) -> None:
    display_pointer = ctypes.c_void_p
    x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x11.XOpenDisplay.restype = display_pointer
    x11.XCloseDisplay.argtypes = [display_pointer]
    x11.XCloseDisplay.restype = ctypes.c_int
    x11.XDefaultScreen.argtypes = [display_pointer]
    x11.XDefaultScreen.restype = ctypes.c_int
    x11.XDisplayWidth.argtypes = [display_pointer, ctypes.c_int]
    x11.XDisplayWidth.restype = ctypes.c_int
    x11.XRootWindow.argtypes = [display_pointer, ctypes.c_int]
    x11.XRootWindow.restype = ctypes.c_ulong
    x11.XQueryPointer.argtypes = [
        display_pointer,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_uint),
    ]
    x11.XQueryPointer.restype = ctypes.c_int
    x11.XFlush.argtypes = [display_pointer]
    x11.XFlush.restype = ctypes.c_int
    xtst.XTestQueryExtension.argtypes = [
        display_pointer,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
    ]
    xtst.XTestQueryExtension.restype = ctypes.c_int
    xtst.XTestFakeMotionEvent.argtypes = [
        display_pointer,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    xtst.XTestFakeMotionEvent.restype = ctypes.c_int
    xtst.XTestFakeButtonEvent.argtypes = [
        display_pointer,
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    xtst.XTestFakeButtonEvent.restype = ctypes.c_int
