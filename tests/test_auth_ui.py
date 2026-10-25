from __future__ import annotations

import json

import pytest

from newsclip.auth_ui import (
    build_auth_observation_script,
    observe_auth_ui,
    parse_auth_observation,
    route_class,
)
from newsclip.browser_runtime import AuthEvidenceFamily, RouteClass
from newsclip.provider_config import load_provider_spec


def test_observation_script_is_deterministic_fixed_code_with_inert_config() -> None:
    auth = load_provider_spec("wsj").auth

    first = build_auth_observation_script(auth.observations)
    second = build_auth_observation_script(dict(reversed(auth.observations.items())))

    assert first == second
    assert json.dumps("input[name='emailOrUsername']") in first
    assert json.dumps("sso.accounts.dowjones.com") not in first
    assert "Object.entries(specs)" in first
    assert "host === suffix || host.endsWith('.' + suffix)" in first
    assert "text.includes(marker.toLowerCase())" in first


def test_each_provider_observation_set_specializes_the_same_engine() -> None:
    scripts = {
        key: build_auth_observation_script(load_provider_spec(key).auth.observations)
        for key in ("ft", "wsj", "bloomberg")
    }

    assert "captcha was unsuccessful" in scripts["ft"]
    assert "frame=challenge" not in scripts["ft"]
    assert "captcha-delivery" not in scripts["wsj"]
    assert "accountchooser" in scripts["bloomberg"]
    assert all(
        "__NEWSCLIP_AUTH_OBSERVATIONS__" not in script for script in scripts.values()
    )


def test_closed_observation_preserves_state_family_and_route_without_page_data() -> (
    None
):
    spec = load_provider_spec("wsj")
    auth = spec.require_auth()
    states = {name: False for name in auth.observations}
    states["password_visible"] = True
    families = {name: [] for name in auth.observations}
    families["password_visible"] = ["selector", "host_class"]

    snapshot = parse_auth_observation(
        {
            "states": states,
            "families": families,
            "selector_error": False,
        },
        auth.observations,
        current_url="https://sso.accounts.dowjones.com/private?credential=sentinel",
        publisher_hosts=spec.identity.allowed_hosts,
        auth_hosts=("accounts.wsj.com", "sso.accounts.dowjones.com"),
        identity_hosts=auth.identity_hosts,
    )

    assert snapshot.state_code == "password_visible"
    assert snapshot.observation_id == "password_visible"
    assert snapshot.evidence_families == (
        AuthEvidenceFamily.SELECTOR,
        AuthEvidenceFamily.HOST_CLASS,
    )
    assert snapshot.route_class is RouteClass.KNOWN_IDP
    assert "sentinel" not in snapshot.model_dump_json()


def test_observation_rejects_unknown_state_or_evidence() -> None:
    spec = load_provider_spec("ft")
    auth = spec.require_auth()

    with pytest.raises(ValueError, match="schema"):
        parse_auth_observation(
            {"unknown_state": True},
            auth.observations,
            current_url="https://accounts.ft.com/login",
            publisher_hosts=spec.identity.allowed_hosts,
            auth_hosts=("accounts.ft.com",),
            identity_hosts=auth.identity_hosts,
        )


def test_selector_error_is_recorded_then_fails_closed() -> None:
    spec = load_provider_spec("ft")
    auth = spec.require_auth()
    states = {name: False for name in auth.observations}
    families = {name: [] for name in auth.observations}
    recorded: list[dict[str, object]] = []

    class Browser:
        current_url = "https://accounts.ft.com/login"

        def evaluate(self, _script: str) -> dict[str, object]:
            return {
                "states": states,
                "families": families,
                "selector_error": True,
            }

        def record_auth_observation(self, **facts: object) -> None:
            recorded.append(facts)

    with pytest.raises(ValueError, match="selector evaluation"):
        observe_auth_ui(
            Browser(),
            "fixed-script",
            auth.observations,
            phase="entry",
            publisher_hosts=spec.identity.allowed_hosts,
            auth_hosts=("accounts.ft.com",),
            identity_hosts=auth.identity_hosts,
        )

    assert recorded == [
        {
            "phase": "entry",
            "state_code": "selector_error",
            "observation_id": None,
            "evidence_families": (AuthEvidenceFamily.NONE,),
            "route_class": RouteClass.PUBLISHER_AUTH,
            "selector_error": True,
        }
    ]


@pytest.mark.parametrize(
    ("url", "identity_hosts", "expected"),
    [
        (
            "https://accounts.google.com/signin",
            ("accounts.google.com",),
            RouteClass.KNOWN_IDP,
        ),
        ("https://accounts.google.com/signin", (), RouteClass.OTHER),
        (
            "https://newassets.hcaptcha.com/captcha",
            (),
            RouteClass.KNOWN_CHALLENGE_VENDOR,
        ),
        ("https://accounts.ft.com/login", (), RouteClass.PUBLISHER_AUTH),
        ("https://www.ft.com/content/id", (), RouteClass.PUBLISHER_CONTENT),
        ("https://example.com/", (), RouteClass.OTHER),
    ],
)
def test_route_class_is_closed(
    url: str,
    identity_hosts: tuple[str, ...],
    expected: RouteClass,
) -> None:
    assert (
        route_class(
            url,
            publisher_hosts=("www.ft.com",),
            auth_hosts=("accounts.ft.com",),
            identity_hosts=identity_hosts,
        )
        is expected
    )
