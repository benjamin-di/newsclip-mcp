"""Authentication observation over the shared implementation."""

from signin_window.automation.auth_ui import _OBSERVE_AUTH_UI as _OBSERVE_AUTH_UI
from signin_window.automation.auth_ui import _STATE_PRECEDENCE as _STATE_PRECEDENCE
from signin_window.automation.auth_ui import (
    AuthObservationSnapshot as AuthObservationSnapshot,
)
from signin_window.automation.auth_ui import (
    AuthSelectorEvaluationError as AuthSelectorEvaluationError,
)
from signin_window.automation.auth_ui import (
    _configured_families as _configured_families,
)
from signin_window.automation.auth_ui import _primary_state as _primary_state
from signin_window.automation.auth_ui import (
    build_auth_observation_script as build_auth_observation_script,
)
from signin_window.automation.auth_ui import observe_auth_ui as observe_auth_ui
from signin_window.automation.auth_ui import (
    parse_auth_observation as parse_auth_observation,
)
from signin_window.automation.auth_ui import (
    record_auth_observation as record_auth_observation,
)
from signin_window.automation.auth_ui import route_class as route_class
