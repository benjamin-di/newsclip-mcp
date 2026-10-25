from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from patchright.sync_api import Error as PatchrightError
from patchright.sync_api import Page, sync_playwright

from newsclip.auth_ui import build_auth_observation_script, observe_auth_ui
from newsclip.browser_runtime import AuthPhase, RouteClass
from newsclip.challenge_resolver import ChallengeResolver
from newsclip.provider_config import (
    AuthObservationSpec,
    AuthSpec,
    ProviderSpec,
    load_builtin_provider_specs,
    load_provider_spec,
)
from newsclip.providers.economist import EconomistLoginRecipe
from newsclip.providers.economist_auth import EconomistAcquisitionAdapter
from newsclip.providers.ft_auth import build_ft_native_token_probe_script

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass(frozen=True)
class AuthSelectorCase:
    provider: str
    owner: str
    selector: str

    @property
    def test_id(self) -> str:
        return f"{self.provider}-{self.owner}"


@dataclass(frozen=True)
class AuthSurfaceCase:
    provider: str
    fixture: str
    url: str
    expected_states: frozenset[str]
    expected_primary_state: str
    expected_controls: tuple[str, ...]
    expected_route_class: RouteClass

    @property
    def test_id(self) -> str:
        return f"{self.provider}-{Path(self.fixture).stem}"


class ObservationBrowser:
    def __init__(self, page: Page) -> None:
        self.page = page
        self.records: list[dict[str, object]] = []

    @property
    def current_url(self) -> str:
        return self.page.url

    def evaluate(self, script: str) -> object:
        return self.page.evaluate(script)

    def record_auth_observation(self, **facts: object) -> None:
        self.records.append(facts)


def _selector_cases() -> tuple[AuthSelectorCase, ...]:
    cases: list[AuthSelectorCase] = []
    for spec in load_builtin_provider_specs():
        auth = spec.auth
        if auth is None:
            continue
        for control_id, selectors in auth.controls.items():
            cases.extend(
                AuthSelectorCase(
                    spec.key,
                    f"control-{control_id}-{index}",
                    selector,
                )
                for index, selector in enumerate(selectors)
            )
        for observation_id, observation in auth.observations.items():
            for field_name in (
                "any_selectors",
                "editable_selectors",
                "required_selectors",
                "absent_selectors",
            ):
                cases.extend(
                    AuthSelectorCase(
                        spec.key,
                        f"observation-{observation_id}-{field_name}-{index}",
                        selector,
                    )
                    for index, selector in enumerate(getattr(observation, field_name))
                )
        if auth.token_probe is not None:
            cases.extend(
                AuthSelectorCase(spec.key, f"token-probe-{field_name}", selector)
                for field_name, selector in (
                    (
                        "password-form",
                        auth.token_probe.password_form_selector,
                    ),
                    (
                        "response-field",
                        auth.token_probe.response_field_selector,
                    ),
                    ("widget", auth.token_probe.widget_selector),
                )
            )
    return tuple(cases)


SELECTOR_CASES = _selector_cases()
SURFACE_CASES = (
    AuthSurfaceCase(
        provider="ft",
        fixture="ft/auth/username.html",
        url="https://accounts.ft.com/login/email?fixture=auth-surface",
        expected_states=frozenset({"username_visible"}),
        expected_primary_state="username_visible",
        expected_controls=("username", "username_submit"),
        expected_route_class=RouteClass.PUBLISHER_AUTH,
    ),
    AuthSurfaceCase(
        provider="ft",
        fixture="ft/auth/password.html",
        url="https://accounts.ft.com/login/password?fixture=auth-surface",
        expected_states=frozenset({"password_visible"}),
        expected_primary_state="password_visible",
        expected_controls=("password", "password_submit"),
        expected_route_class=RouteClass.PUBLISHER_AUTH,
    ),
    AuthSurfaceCase(
        provider="ft",
        fixture="ft/auth/passkey.html",
        url="https://accounts.ft.com/login/passkey?fixture=auth-surface",
        expected_states=frozenset(),
        expected_primary_state="unknown",
        expected_controls=("passkey_skip",),
        expected_route_class=RouteClass.PUBLISHER_AUTH,
    ),
    AuthSurfaceCase(
        provider="wsj",
        fixture="wsj/auth.html",
        url=("https://sso.accounts.dowjones.com/login-page?fixture=auth-surface"),
        expected_states=frozenset({"username_visible", "password_visible"}),
        expected_primary_state="password_visible",
        expected_controls=("username", "password"),
        expected_route_class=RouteClass.KNOWN_IDP,
    ),
    AuthSurfaceCase(
        provider="bloomberg",
        fixture="bloomberg/auth.html",
        url="https://www.bloomberg.com/account/signin?fixture=auth-surface",
        expected_states=frozenset(),
        expected_primary_state="unknown",
        expected_controls=("google_continue",),
        expected_route_class=RouteClass.PUBLISHER_AUTH,
    ),
    AuthSurfaceCase(
        provider="bloomberg",
        fixture="bloomberg/google-email.html",
        url=("https://accounts.google.com/v3/signin/identifier?fixture=auth-surface"),
        expected_states=frozenset({"email_visible"}),
        expected_primary_state="email_visible",
        expected_controls=("email", "email_submit"),
        expected_route_class=RouteClass.KNOWN_IDP,
    ),
    # A second GIS popup opened for the callback replay lands here whenever a
    # Google session already exists, so the chooser surface and its selectable
    # account tiles must both stay observable.
    AuthSurfaceCase(
        provider="bloomberg",
        fixture="bloomberg/google-account-chooser.html",
        url=(
            "https://accounts.google.com/v3/signin/accountchooser?fixture=auth-surface"
        ),
        expected_states=frozenset({"account_chooser"}),
        expected_primary_state="account_chooser",
        expected_controls=("account_choices", "use_another"),
        expected_route_class=RouteClass.KNOWN_IDP,
    ),
    # NYT renders both credential fields on both steps, the inactive one
    # visible and read-only. Each step must resolve to exactly the state whose
    # control can actually be typed into, or the flow fills a decoy and blocks
    # until it times out.
    AuthSurfaceCase(
        provider="nyt",
        fixture="nyt/auth/email_step.html",
        url="https://myaccount.nytimes.com/auth/enter-email?fixture=auth-surface",
        expected_states=frozenset({"username_visible"}),
        expected_primary_state="username_visible",
        expected_controls=("username", "username_submit"),
        expected_route_class=RouteClass.PUBLISHER_AUTH,
    ),
    AuthSurfaceCase(
        provider="nyt",
        fixture="nyt/auth/password_step.html",
        url="https://myaccount.nytimes.com/auth/login?fixture=auth-surface",
        expected_states=frozenset({"password_visible"}),
        expected_primary_state="password_visible",
        expected_controls=("password", "password_submit"),
        expected_route_class=RouteClass.PUBLISHER_AUTH,
    ),
)


@pytest.fixture(scope="module")
def auth_page() -> Iterator[Page]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            yield browser.new_page()
        finally:
            browser.close()


def _assert_selector_compiles(page: Page, case: AuthSelectorCase) -> None:
    try:
        page.locator(case.selector).count()
    except PatchrightError as error:
        raise AssertionError(
            f"{case.provider} {case.owner} has an invalid selector: {case.selector!r}"
        ) from error


@pytest.mark.parametrize(
    "case",
    SELECTOR_CASES,
    ids=(case.test_id for case in SELECTOR_CASES),
)
def test_every_configured_auth_selector_compiles(
    auth_page: Page,
    case: AuthSelectorCase,
) -> None:
    _assert_selector_compiles(auth_page, case)


def test_selector_failure_names_provider_and_config_owner(auth_page: Page) -> None:
    invalid = AuthSelectorCase("fixture", "control-username-0", "input[")

    with pytest.raises(
        AssertionError,
        match=r"fixture control-username-0 has an invalid selector",
    ):
        _assert_selector_compiles(auth_page, invalid)


def _route_fixture(page: Page, case: AuthSurfaceCase) -> None:
    body = (FIXTURES / case.fixture).read_text(encoding="utf-8")
    page.route(
        case.url,
        lambda route: route.fulfill(
            status=200,
            content_type="text/html",
            body=body,
        ),
    )
    page.goto(case.url, wait_until="domcontentloaded")


def _auth_hosts(spec: ProviderSpec, auth: AuthSpec) -> tuple[str, ...]:
    session = spec.require_session()
    hosts = {
        urlsplit(str(auth.login_url)).hostname or "",
        *(urlsplit(origin).hostname or "" for origin in session.allowed_origins),
    }
    return tuple(sorted(hosts))


def _control_is_visible(page: Page, auth: AuthSpec, control_id: str) -> bool:
    return any(
        locator.count() > 0 and locator.first.is_visible()
        for selector in auth.control(control_id)
        for locator in (page.locator(selector),)
    )


@pytest.mark.parametrize(
    "case",
    SURFACE_CASES,
    ids=(case.test_id for case in SURFACE_CASES),
)
def test_representative_auth_surfaces_match_configured_contract(
    auth_page: Page,
    case: AuthSurfaceCase,
) -> None:
    spec = load_provider_spec(case.provider)
    auth = spec.require_auth()
    _route_fixture(auth_page, case)

    for control_id in case.expected_controls:
        assert _control_is_visible(auth_page, auth, control_id), control_id

    browser = ObservationBrowser(auth_page)
    states = observe_auth_ui(
        browser,
        build_auth_observation_script(auth.observations),
        auth.observations,
        phase=AuthPhase.ENTRY,
        publisher_hosts=spec.identity.allowed_hosts,
        auth_hosts=_auth_hosts(spec, auth),
        identity_hosts=auth.identity_hosts,
    )

    assert frozenset(name for name, matched in states.items() if matched) == (
        case.expected_states
    )
    assert browser.records[-1]["state_code"] == case.expected_primary_state
    assert browser.records[-1]["route_class"] is case.expected_route_class
    assert browser.records[-1]["selector_error"] is False


def test_economist_open_shadow_login_uses_native_observation_contract(
    auth_page: Page,
) -> None:
    spec = load_provider_spec("economist")
    auth = spec.require_auth()
    case = AuthSurfaceCase(
        provider="economist",
        fixture="economist/auth.html",
        url=("https://myaccount.economist.com/api/auth/login?fixture=auth-surface"),
        expected_states=frozenset({"username_visible", "password_visible"}),
        expected_primary_state="password_visible",
        expected_controls=("username", "password", "submit"),
        expected_route_class=RouteClass.PUBLISHER_AUTH,
    )
    _route_fixture(auth_page, case)

    for control_id in case.expected_controls:
        assert _control_is_visible(auth_page, auth, control_id), control_id

    browser = ObservationBrowser(auth_page)
    verification_url = str(spec.require_session().default_verification_url)
    adapter = EconomistAcquisitionAdapter(
        recipe=EconomistLoginRecipe(verification_url=verification_url),
        challenge_resolver=ChallengeResolver({}),
        spec=spec,
    )

    observation = adapter._observe_for_phase(browser, AuthPhase.ENTRY)

    assert observation.username_visible is True
    assert observation.password_visible is True
    assert browser.records[-1]["state_code"] == case.expected_primary_state
    assert browser.records[-1]["route_class"] is case.expected_route_class
    assert browser.records[-1]["selector_error"] is False


def test_ft_password_surface_binds_native_token_probe(auth_page: Page) -> None:
    spec = load_provider_spec("ft")
    auth = spec.require_auth()
    probe = auth.token_probe
    assert probe is not None
    case = next(
        case for case in SURFACE_CASES if case.fixture == "ft/auth/password.html"
    )
    _route_fixture(auth_page, case)
    script = build_ft_native_token_probe_script(spec)

    assert auth_page.evaluate(script) == {"accepted": False, "source": "none"}

    auth_page.locator(probe.response_field_selector).first.evaluate(
        "field => { field.value = 'fixture-token-' + 'x'.repeat(32); }"
    )

    assert auth_page.evaluate(script) == {
        "accepted": True,
        "source": "existing_form_field",
    }


_EDITABLE_PROBE_URL = "https://accounts.example.test/editable?fixture=auth-surface"
_EDITABLE_PROBE_HTML = """<!doctype html>
<html><body>
  <input id="live" type="password">
  <input id="readonly" type="password" readonly>
  <input id="disabled" type="password" disabled>
  <input id="hidden" type="password" style="display:none">
</body></html>"""


@pytest.mark.parametrize(
    ("selector", "shown", "editable"),
    [
        ("#live", True, True),
        # The decoy shape: a two-step login renders the other step's field
        # visible and read-only, so geometry and CSS say "this step is live".
        ("#readonly", True, False),
        ("#disabled", True, False),
        ("#hidden", False, False),
    ],
)
def test_editable_selectors_require_a_control_fill_could_use(
    auth_page: Page,
    selector: str,
    shown: bool,
    editable: bool,
) -> None:
    """`fill` needs an element it can type into; being shown is not enough.

    The two predicates must agree on live and hidden controls and differ on
    exactly the ones a fill would block against — otherwise selecting a step
    by observation promises something the fill cannot honour.
    """

    auth_page.route(
        _EDITABLE_PROBE_URL,
        lambda route: route.fulfill(
            status=200,
            content_type="text/html",
            body=_EDITABLE_PROBE_HTML,
        ),
    )
    auth_page.goto(_EDITABLE_PROBE_URL, wait_until="domcontentloaded")

    script = build_auth_observation_script(
        {
            "shown_probe": AuthObservationSpec(any_selectors=(selector,)),
            "editable_probe": AuthObservationSpec(editable_selectors=(selector,)),
        }
    )
    observed = auth_page.evaluate(script)

    assert observed["selector_error"] is False
    assert observed["states"]["shown_probe"] is shown
    assert observed["states"]["editable_probe"] is editable
