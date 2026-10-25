"""Application compatibility over shared challenge mechanics."""

from signin_window.automation.detection import (
    _CONTEXT_REPLACEMENT_ATTEMPTS as _CONTEXT_REPLACEMENT_ATTEMPTS,
)
from signin_window.automation.detection import (
    _NATIVE_INTERACTIVE_SELECTORS as _NATIVE_INTERACTIVE_SELECTORS,
)
from signin_window.automation.detection import (
    _NATIVE_MATCH_LIMIT as _NATIVE_MATCH_LIMIT,
)
from signin_window.automation.detection import (
    _NATIVE_PREFILTER_SELECTOR as _NATIVE_PREFILTER_SELECTOR,
)
from signin_window.automation.detection import _VIEWPORT_SCRIPT as _VIEWPORT_SCRIPT
from signin_window.automation.detection import DETECTION_SCRIPT as DETECTION_SCRIPT
from signin_window.automation.detection import (
    ChallengeDetectionError as ChallengeDetectionError,
)
from signin_window.automation.detection import _context_replaced as _context_replaced
from signin_window.automation.detection import (
    _detect_challenge_once as _detect_challenge_once,
)
from signin_window.automation.detection import (
    _native_interactive_challenge as _native_interactive_challenge,
)
from signin_window.automation.detection import (
    _native_locator_is_visible as _native_locator_is_visible,
)
from signin_window.automation.detection import (
    _native_surface_absent as _native_surface_absent,
)
from signin_window.automation.detection import detect_challenge as detect_challenge
from signin_window.automation.detection import (
    detect_challenge_for_reads as detect_challenge_for_reads,
)
