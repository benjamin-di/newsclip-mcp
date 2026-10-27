"""Human sign-in runners: observe, verify, then publish a retained profile."""

from __future__ import annotations

import os
import shutil
import time
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import HttpUrl

from .account_keys import require_account_key
from .connection_controls import ConnectionControls
from .models import RawFetch, SessionArtifact
from .session_cookies import SessionCookiesMissing, normalize_browser_cookie_export
from .sessions import SessionStore
from .tenancy import application_root, load_users, require_user, user_scope

# Resources needed by publisher sign-in pages. Only publisher/identity hosts
# may be top-level documents; these hosts cannot turn a window into a browser.
RESOURCE_HOSTS = (
    "gstatic.com",
    "googleapis.com",
    "googleusercontent.com",
    "google.com",
    "hcaptcha.com",
    "hcaptcha.net",
    "challenges.cloudflare.com",
    "captcha-delivery.com",
    "datadome.co",
    "px-cdn.net",
    "px-cloud.net",
    "pxchk.net",
    "perimeterx.net",
    "onetrust.com",
    "cookielaw.org",
    "cookiepro.com",
    "trustarc.com",
    "googletagmanager.com",
    "googletagservices.com",
    "doubleclick.net",
)
PUBLISHER_RESOURCES = {
    "ft": ("ft.com", "ft-static.com", "ftchinese.com"),
    "wsj": ("wsj.com", "dowjones.com", "wsj.net", "dowjones.io", "auth0.com"),
    "bloomberg": ("bloomberg.com", "bwbx.io", "bloombergquint.com"),
    "economist": ("economist.com", "economistgroup.com", "auth0.com"),
    "nyt": ("nytimes.com", "nyt.com"),
}


def human_signin(
    window: Any,
    *,
    registry=None,
    spec_loader=None,
    service_factory=None,
    configure_context=None,
) -> None:
    """Open the real site; all form entry and challenges belong to the person."""

    from patchright.sync_api import sync_playwright
    from signin_window.automation.profiles import OwnedBrowserProcess
    from signin_window.automation.runtime import close_owned_browser
    from signin_window.browser import LAUNCH_ARGS, browser_environment, harden_sync
    from signin_window.hosts import allowed, host_resolver_rules, proxy_hosts, top_level

    from .composition import build_auth_service, build_registry
    from .provider_config import load_provider_spec

    user = require_user(window.params["user"])
    provider_key = window.params["provider"]
    account_key = require_account_key(window.params.get("account_key", "default"))
    revision = window.params.get("connection_revision")
    if not isinstance(revision, str):
        raise ValueError("sign-in requires an application-issued connection revision")
    provider = (registry or build_registry()).get(provider_key)
    spec = (spec_loader or load_provider_spec)(provider_key)
    recipe = provider.login_recipe
    if recipe is None or spec.auth is None:
        raise ValueError("provider does not support sign-in")
    auth = spec.auth
    session = spec.require_session()
    page_hosts = tuple(
        dict.fromkeys(
            [urlsplit(origin).hostname or "" for origin in recipe.allowed_origins]
            + list(spec.identity.allowed_hosts)
            + list(auth.identity_hosts)
        )
    )
    resource_hosts = tuple(
        dict.fromkeys(
            page_hosts + RESOURCE_HOSTS + PUBLISHER_RESOURCES.get(provider_key, ())
        )
    )
    with user_scope(user):
        root = application_root("NEWSCLIP_STATE_HOME", ".local/state")
    controls = ConnectionControls(root)
    if not controls.current(provider_key, account_key, revision):
        raise ValueError("sign-in target has been replaced or disconnected")
    profile_id = uuid4()
    profile = (
        root / "browser-profiles" / provider_key / f"{account_key}--{profile_id.hex}"
    )
    profile.mkdir(mode=0o700, parents=True)
    published = False
    service = None
    service_closed = False
    try:
        service = (service_factory or build_auth_service)(user=user)
        store = service._sessions
        if not isinstance(store, SessionStore):
            raise RuntimeError("sign-in service requires a session manager")
        if store.root.resolve() != root.resolve():
            raise RuntimeError("sign-in and reader must use the same user state root")
        expected_generation = store.current_generation(provider_key, account_key)
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                profile,
                headless=False,
                env={**browser_environment(window.env())},
                no_viewport=True,
                locale=auth.launch.locale,
                timezone_id=auth.launch.timezone_id,
                service_workers="block",
                args=[
                    *LAUNCH_ARGS,
                    "--window-position=0,0",
                    "--disable-dev-shm-usage",
                    "--host-resolver-rules="
                    + host_resolver_rules(resource_hosts, proxy_hosts()),
                ],
            )
            owned_process = None
            try:
                owned_process = OwnedBrowserProcess.capture(profile)
                harden_sync(context)

                def route(request_route):
                    request = request_route.request
                    hosts = page_hosts if top_level(request) else resource_hosts
                    if allowed(request.url, hosts):
                        request_route.continue_()
                    else:
                        request_route.abort()

                context.route("**/*", route)
                if configure_context is not None:
                    configure_context(context, window)
                page = context.pages[0] if context.pages else context.new_page()
                responses: list[Any] = []

                def observe(response):
                    with suppress(Exception):
                        if (
                            response.request.is_navigation_request()
                            and response.frame == page.main_frame
                        ):
                            responses[:] = [response]

                page.on("response", observe)
                page.goto(
                    str(auth.login_url), wait_until="domcontentloaded", timeout=45000
                )
                window.waiting(urlsplit(page.url).hostname or "")
                verifying = False
                candidate = None
                proof = None
                while (
                    not window.cancelled.is_set() and time.monotonic() < window.deadline
                ):
                    now = datetime.now(UTC)
                    window.at(urlsplit(page.url).hostname or "")
                    try:
                        cookies = normalize_browser_cookie_export(
                            context.cookies(),
                            allowed_domains=recipe.allowed_cookie_domains,
                            now=now,
                        )
                    except SessionCookiesMissing:
                        page.wait_for_timeout(500)
                        continue
                    if not verifying:
                        current = urlsplit(page.url)
                        login = urlsplit(str(auth.login_url))
                        if (
                            current.hostname not in spec.identity.allowed_hosts
                            or (
                                current.hostname == login.hostname
                                and current.path.rstrip("/") == login.path.rstrip("/")
                            )
                            or any(
                                current.path.startswith(prefix)
                                for prefix in auth.auth_path_prefixes
                            )
                            or (
                                session.session_cookie_name_prefixes
                                and not any(
                                    cookie.name.lower().startswith(
                                        session.session_cookie_name_prefixes
                                    )
                                    for cookie in cookies
                                )
                            )
                        ):
                            page.wait_for_timeout(500)
                            continue
                        verifying = True
                        page.goto(
                            recipe.verification_url,
                            wait_until="domcontentloaded",
                            timeout=45000,
                        )
                    if responses:
                        response = responses[-1]
                        proof = RawFetch(
                            requested_url=HttpUrl(recipe.verification_url),
                            final_url=HttpUrl(page.url),
                            http_status=response.status,
                            content_type=response.headers.get("content-type"),
                            retrieved_at=now,
                            session_cookie_present=True,
                            serving_transport="browser",
                            raw_html=page.content().encode(),
                        )
                        verification = recipe.verify_fetch(proof)
                        if verification.verified:
                            window.saving()
                            candidate = SessionArtifact(
                                schema_version=2,
                                browser_profile_id=profile_id,
                                generation_id=uuid4(),
                                provider=provider_key,
                                account_key=account_key,
                                created_at=now,
                                verified_at=verification.verified_at,
                                cookies=cookies,
                                user_agent=page.evaluate("navigator.userAgent"),
                            )
                            break
                    page.wait_for_timeout(500)
            finally:
                close_owned_browser(
                    context,
                    playwright,
                    owned_process,
                    primary_failure=candidate is None,
                )
        if candidate is not None and proof is not None:
            service_closed = True
            service.close()
            store.promote_browser_session(
                candidate,
                proof,
                expected_generation=expected_generation,
                connection_revision=revision,
            )
            published = True
            window.finish("connected")
    finally:
        try:
            if service is not None and not service_closed:
                service.close()
        finally:
            if not published:
                shutil.rmtree(profile, ignore_errors=True)


def build_signin_app(*, runner: Callable | None = None, users_path: Path | None = None):
    from signin_window.browser import policy_installed
    from signin_window.service import Windows, build_app

    from .composition import build_registry
    from .standalone import read_login_token

    if runner is None and not policy_installed():
        raise ValueError(
            "install the signin-window browser policy before starting the login service"
        )
    identifiers = {
        user.id
        for user in load_users(users_path or Path(os.environ["NEWSCLIP_USERS_FILE"]))
    }
    registry = build_registry()

    def start_params(body):
        if set(body) - {
            "layout",
            "user",
            "provider",
            "account_key",
            "connection_revision",
        }:
            raise ValueError("invalid sign-in parameters")
        user, provider = body.get("user"), body.get("provider")
        if (
            not isinstance(user, str)
            or user not in identifiers
            or not isinstance(provider, str)
        ):
            raise ValueError("invalid sign-in target")
        from .errors import UsageError

        try:
            selected = registry.get(provider)
        except UsageError as error:
            raise ValueError("invalid sign-in target") from error
        if selected.login_recipe is None:
            raise ValueError("invalid sign-in target")
        account_key = require_account_key(body.get("account_key", "default"))
        revision = body.get("connection_revision")
        if not isinstance(revision, str) or not 32 <= len(revision) <= 128:
            raise ValueError("invalid sign-in revision")
        with user_scope(user):
            controls = ConnectionControls(
                application_root("NEWSCLIP_STATE_HOME", ".local/state")
            )
        if not controls.current(provider, account_key, revision):
            raise ValueError("invalid sign-in revision")
        controls.started(provider, account_key, revision)
        return {
            "user": user,
            "provider": provider,
            "account_key": account_key,
            "connection_revision": revision,
            "key": f"{user}:{provider}:{account_key}",
        }

    windows = Windows(runner or human_signin, slots=4, minutes=10)
    app = build_app(
        windows,
        token=read_login_token(),
        novnc_dir=os.environ.get("NOVNC_DIR", "/opt/novnc"),
        start_params=start_params,
        title="Connect a news subscription",
    )
    app.state.windows = windows
    return app


def run_signin_service(*, host: str = "127.0.0.1", port: int = 8080) -> None:
    import uvicorn

    uvicorn.run(
        build_signin_app(),
        host=host,
        port=port,
        access_log=False,
        proxy_headers=False,
        server_header=False,
    )
