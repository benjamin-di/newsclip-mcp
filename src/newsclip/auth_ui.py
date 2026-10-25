"""Fixed browser observation engine for configured authentication page evidence."""

from __future__ import annotations

import json
from collections.abc import Mapping
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from .browser_runtime.events import (
    AuthEvidenceFamily,
    AuthPhase,
    RouteClass,
)
from .models import FrozenModel
from .provider_config import AuthObservationSpec

_OBSERVE_AUTH_UI = r"""
() => {
  const specs = __NEWSCLIP_AUTH_OBSERVATIONS__;
  let selectorError = false;
  const shown = (element) => {
    const box = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    return box.width > 0 && box.height > 0
      && style.display !== 'none' && style.visibility !== 'hidden';
  };
  const visible = (selector) => {
    try {
      return Array.from(document.querySelectorAll(selector)).some(shown);
    } catch (_) {
      selectorError = true;
      return false;
    }
  };
  // Shown is not usable. A two-step login renders the other step's field as a
  // visible read-only decoy, so geometry and CSS alone cannot say which step
  // is live; `fill` needs an element it can actually type into.
  const editable = (selector) => {
    try {
      return Array.from(document.querySelectorAll(selector)).some(
        (element) => shown(element) && !element.disabled && !element.readOnly
      );
    } catch (_) {
      selectorError = true;
      return false;
    }
  };
  const text = (document.body?.innerText || '').toLowerCase();
  const host = location.hostname.toLowerCase().replace(/\.$/, '');
  const path = location.pathname.toLowerCase();
  const result = {};
  const families = {};
  for (const [name, spec] of Object.entries(specs)) {
    const selectorEvidence = spec.any_selectors.some(visible)
      || spec.editable_selectors.some(editable);
    const textEvidence = spec.any_text.some(
      (marker) => text.includes(marker.toLowerCase())
    );
    const pathEvidence = spec.any_path_contains.some(
      (marker) => path.includes(marker.toLowerCase())
    );
    const evidenceConfigured = spec.any_selectors.length > 0
      || spec.editable_selectors.length > 0
      || spec.any_text.length > 0 || spec.any_path_contains.length > 0;
    const evidence = !evidenceConfigured
      || selectorEvidence || textEvidence || pathEvidence;
    const requiredSelectors = spec.required_selectors.length === 0
      || spec.required_selectors.some(visible);
    const requiredText = spec.required_text.length === 0
      || spec.required_text.some((marker) => text.includes(marker.toLowerCase()));
    const requiredHosts = spec.required_hosts.length === 0
      || spec.required_hosts.includes(host);
    const requiredSuffixes = spec.required_host_suffixes.length === 0
      || spec.required_host_suffixes.some(
        (suffix) => host === suffix || host.endsWith('.' + suffix)
      );
    const excludedHosts = !spec.excluded_hosts.includes(host);
    const excludedPaths = !spec.excluded_path_prefixes.some(
      (prefix) => path.startsWith(prefix.toLowerCase())
    );
    const absentSelectors = spec.absent_selectors.every(
      (selector) => !visible(selector)
    );
    result[name] = evidence && requiredSelectors && requiredText
      && requiredHosts && requiredSuffixes && excludedHosts
      && excludedPaths && absentSelectors;
    const matched = [];
    if (selectorEvidence || (result[name] && (
      spec.required_selectors.length > 0 || spec.absent_selectors.length > 0
    ))) matched.push('selector');
    if (textEvidence || (result[name] && spec.required_text.length > 0)) {
      matched.push('text');
    }
    if (pathEvidence) matched.push('path');
    if (result[name] && (
      spec.required_hosts.length > 0 || spec.required_host_suffixes.length > 0
      || spec.excluded_hosts.length > 0
    )) matched.push('host_class');
    families[name] = matched;
  }
  return {states: result, families, selector_error: selectorError};
}
"""

_STATE_PRECEDENCE = (
    "account_alert",
    "second_factor",
    "unsupported_second_factor",
    "credential_rejected",
    "captcha_rejected",
    "authenticated",
    "password_visible",
    "totp_visible",
    "username_visible",
    "email_visible",
    "account_chooser",
    "consent_visible",
)
_KNOWN_CHALLENGE_SUFFIXES = (
    "hcaptcha.com",
    "captcha-delivery.com",
    "perimeterx.net",
    "px-cloud.net",
    "challenges.cloudflare.com",
)


class AuthSelectorEvaluationError(ValueError):
    """A configured selector could not be evaluated on the current document."""


class AuthObservationSnapshot(FrozenModel):
    states: dict[str, bool]
    state_code: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    observation_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    evidence_families: tuple[AuthEvidenceFamily, ...]
    route_class: RouteClass
    selector_error: bool = False

    @field_validator("states")
    @classmethod
    def validate_state_ids(cls, value: dict[str, bool]) -> dict[str, bool]:
        if any(
            not key or len(key) > 64 or not key.replace("_", "a").isalnum()
            for key in value
        ):
            raise ValueError("invalid authentication observation ID")
        return value


def build_auth_observation_script(
    observations: Mapping[str, AuthObservationSpec],
) -> str:
    """Build one inert-data specialization of the fixed observation program."""

    payload = {
        name: observation.model_dump(mode="json")
        for name, observation in sorted(observations.items())
    }
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    return _OBSERVE_AUTH_UI.replace("__NEWSCLIP_AUTH_OBSERVATIONS__", encoded)


def parse_auth_observation(
    raw: object,
    observations: Mapping[str, AuthObservationSpec],
    *,
    current_url: str,
    publisher_hosts: tuple[str, ...],
    auth_hosts: tuple[str, ...],
    identity_hosts: tuple[str, ...],
) -> AuthObservationSnapshot:
    if not isinstance(raw, Mapping):
        raise ValueError("authentication observation is not an object")
    states: object
    families: object
    selector_error: object
    if set(raw).issubset(observations) and all(
        isinstance(value, bool) for value in raw.values()
    ):
        states = {name: bool(raw.get(name, False)) for name in observations}
        families = {
            name: _configured_families(spec) if states[name] else []
            for name, spec in observations.items()
        }
        selector_error = False
    else:
        states = raw.get("states")
        families = raw.get("families")
        selector_error = raw.get("selector_error")
    if (
        not isinstance(states, Mapping)
        or not isinstance(families, Mapping)
        or not isinstance(selector_error, bool)
        or set(states) != set(observations)
        or set(families) != set(observations)
        or not all(isinstance(value, bool) for value in states.values())
    ):
        raise ValueError("authentication observation schema is invalid")
    normalized_families: dict[str, tuple[AuthEvidenceFamily, ...]] = {}
    for name, values in families.items():
        if not isinstance(name, str) or not isinstance(values, list):
            raise ValueError("authentication evidence schema is invalid")
        normalized_families[name] = tuple(
            dict.fromkeys(AuthEvidenceFamily(value) for value in values)
        )
    normalized_states = {str(key): bool(value) for key, value in states.items()}
    state_code = _primary_state(normalized_states, selector_error=selector_error)
    observation_id = state_code if normalized_states.get(state_code) else None
    return AuthObservationSnapshot(
        states=normalized_states,
        state_code=state_code,
        observation_id=observation_id,
        evidence_families=(
            normalized_families.get(state_code, ()) or (AuthEvidenceFamily.NONE,)
        ),
        route_class=route_class(
            current_url,
            publisher_hosts=publisher_hosts,
            auth_hosts=auth_hosts,
            identity_hosts=identity_hosts,
        ),
        selector_error=selector_error,
    )


def record_auth_observation(
    browser,
    snapshot: AuthObservationSnapshot,
    *,
    phase: AuthPhase | str,
) -> dict[str, bool]:
    record = getattr(browser, "record_auth_observation", None)
    if callable(record):
        record(
            phase=phase,
            state_code=snapshot.state_code,
            observation_id=snapshot.observation_id,
            evidence_families=snapshot.evidence_families,
            route_class=snapshot.route_class,
            selector_error=snapshot.selector_error,
        )
    return snapshot.states


def observe_auth_ui(
    browser,
    script: str,
    observations: Mapping[str, AuthObservationSpec],
    *,
    phase: AuthPhase | str,
    publisher_hosts: tuple[str, ...],
    auth_hosts: tuple[str, ...],
    identity_hosts: tuple[str, ...],
) -> dict[str, bool]:
    current_url = getattr(browser, "current_url", None)
    if not isinstance(current_url, str) or not current_url:
        current_url = getattr(getattr(browser, "page", None), "url", "")
    if not isinstance(current_url, str) or not current_url:
        current_url = f"https://{auth_hosts[0]}/" if auth_hosts else "about:blank"
    snapshot = parse_auth_observation(
        browser.evaluate(script),
        observations,
        current_url=current_url,
        publisher_hosts=publisher_hosts,
        auth_hosts=auth_hosts,
        identity_hosts=identity_hosts,
    )
    states = record_auth_observation(browser, snapshot, phase=phase)
    if snapshot.selector_error:
        # Preserve the previous fail-closed contract while retaining the new
        # bounded fact that explains why no selector result is trustworthy.
        raise AuthSelectorEvaluationError("authentication selector evaluation failed")
    return states


def route_class(
    current_url: str,
    *,
    publisher_hosts: tuple[str, ...],
    auth_hosts: tuple[str, ...],
    identity_hosts: tuple[str, ...],
) -> RouteClass:
    host = (urlsplit(current_url).hostname or "").lower().rstrip(".")
    if any(
        host == suffix or host.endswith(f".{suffix}")
        for suffix in _KNOWN_CHALLENGE_SUFFIXES
    ):
        return RouteClass.KNOWN_CHALLENGE_VENDOR
    if host in identity_hosts:
        return RouteClass.KNOWN_IDP
    if host in auth_hosts:
        return RouteClass.PUBLISHER_AUTH
    if host in publisher_hosts:
        return RouteClass.PUBLISHER_CONTENT
    return RouteClass.OTHER


def _primary_state(states: Mapping[str, bool], *, selector_error: bool) -> str:
    for state in _STATE_PRECEDENCE:
        if states.get(state):
            return state
    matched = sorted(key for key, value in states.items() if value)
    if matched:
        return matched[0]
    return "selector_error" if selector_error else "unknown"


def _configured_families(spec: AuthObservationSpec) -> list[str]:
    families: list[str] = []
    if (
        spec.any_selectors
        or spec.editable_selectors
        or spec.required_selectors
        or spec.absent_selectors
    ):
        families.append("selector")
    if spec.any_text or spec.required_text:
        families.append("text")
    if spec.any_path_contains:
        families.append("path")
    if spec.required_hosts or spec.required_host_suffixes or spec.excluded_hosts:
        families.append("host_class")
    return families


__all__ = [
    "AuthObservationSnapshot",
    "AuthSelectorEvaluationError",
    "build_auth_observation_script",
    "observe_auth_ui",
    "parse_auth_observation",
    "record_auth_observation",
    "route_class",
]
