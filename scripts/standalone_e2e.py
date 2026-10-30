"""Offline browser acceptance: MCP link, real noVNC input, proof, archive, restart.

Run in the login image with --network none. Publisher responses are synthetic
and intercepted inside Chromium; no publisher or account is contacted.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import sys
import tempfile
import urllib.request
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import signin_window.browser as window_browser
import signin_window.hosts as window_hosts
import uvicorn
from patchright.async_api import async_playwright
from pocket_id_acceptance import Identity
from pydantic import HttpUrl
from signin_window.browser import policy_installed
from signin_window.oidc import OIDCConfig

import newsclip.composition as composition
from newsclip.browser_runtime import BrowserLaunchConfig, PatchrightRuntime
from newsclip.browser_runtime.surface import ensure_virtual_display
from newsclip.client import NewsclipClient
from newsclip.connection_controls import ConnectionControls
from newsclip.connections import ConnectionsConfig
from newsclip.errors import SessionRequiredError
from newsclip.models import RawFetch
from newsclip.provider_config import ProviderSpec, load_provider_spec
from newsclip.providers.ft import FTProvider
from newsclip.providers.registry import ProviderRegistry
from newsclip.providers.wsj import WSJProvider
from newsclip.signin import build_signin_app, human_signin
from newsclip.standalone import build_standalone_app
from newsclip.tenancy import add_user

ARTICLE_URL = "https://www.example.com/content/11111111-1111-4111-8111-111111111111"
ARTICLE_URLS = {
    "ft": ARTICLE_URL,
    "wsj": "https://www.example.com/world/synthetic-research-1234abcd",
}
LOGIN_TOKEN = "synthetic-internal-browser-token-for-offline-testing"
INPUT = "reader@example.com"
OFFLINE_ARGS = (
    "--no-proxy-server",
    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1",
)
PARAGRAPH = (
    "This generated paragraph describes a fictional research project and its "
    "imaginary timetable. The participants compare invented measurements, "
    "review synthetic observations and discuss ordinary planning assumptions. "
    "No publisher text or actual account information appears in this example. "
    "Several additional invented details ensure the extraction has enough "
    "coherent prose for a full article assessment."
)
FULL = (
    "<!doctype html><html><head><title>Synthetic research report</title>"
    f'<link rel="canonical" href="{ARTICLE_URL}">'
    '<script type="application/ld+json">'
    + json.dumps(
        {
            "@type": "NewsArticle",
            "headline": "Synthetic research report",
            "url": ARTICLE_URL,
            "datePublished": "2000-01-01T00:00:00Z",
        }
    )
    + "</script></head><body><article><h1>Synthetic research report</h1>"
    + "".join(f"<p>{PARAGRAPH}</p>" for _ in range(8))
    + "</article></body></html>"
)
FORM = (
    "<!doctype html><title>Synthetic sign-in</title>"
    '<form action="https://www.example.com/connected">'
    '<input autofocus name="signal" '
    "oninput=\"fetch('https://www.example.com/typed?signal='"
    '+encodeURIComponent(this.value))" '
    'style="position:fixed;inset:0;width:100%;'
    'height:100%;font-size:24px"><button type="submit">Continue</button></form>'
)


def free_port() -> int:
    with socket.socket() as channel:
        channel.bind(("127.0.0.1", 0))
        return channel.getsockname()[1]


def synthetic_spec(key: str) -> ProviderSpec:
    payload = load_provider_spec(key).model_dump(mode="json")
    payload["identity"].update(
        allowed_hosts=["www.example.com"], canonical_host="www.example.com"
    )
    payload["check"].update(
        query="Synthetic research report", canonical_url=ARTICLE_URLS[key]
    )
    payload["search"]["endpoint"] = "https://www.example.com/search"
    payload["session"].update(
        allowed_origins=["https://accounts.example.com", "https://www.example.com"],
        allowed_cookie_domains=["example.com"],
        default_verification_url=ARTICLE_URLS[key],
        secret_ref="",
    )
    payload["auth"].update(
        login_url="https://accounts.example.com/signin",
        identity_hosts=["accounts.example.com"],
        auth_path_prefixes=[],
        post_callback_urls=[],
    )
    payload["browser_retrieval"].update(warmup_urls=[], recovery_warmup_urls=[])
    return ProviderSpec.model_validate(payload)


class SyntheticHttp:
    def __init__(self, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def close(self):
        pass

    def get(self, url, *, session=None, timeout=40):
        if str(url) not in ARTICLE_URLS.values():
            raise AssertionError("unexpected synthetic article URL")
        return RawFetch(
            requested_url=HttpUrl(url),
            final_url=HttpUrl(url),
            http_status=200,
            content_type="text/html",
            retrieved_at=datetime.now(UTC),
            session_cookie_present=session is not None,
            raw_html=FULL.replace(ARTICLE_URL, str(url)).encode(),
        )


async def serve(app, port):
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            access_log=False,
            lifespan="on",
        )
    )
    task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            return server, task
        if task.done():
            await task
        await asyncio.sleep(0.05)
    raise AssertionError("test server did not start")


def mcp_link(
    origin, token, user="alice", provider="ft", *, host=None, request_origin=None
):
    def call(method, params, identifier):
        request = urllib.request.Request(
            origin + f"/users/{user}/mcp",
            data=json.dumps(
                {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}
            ).encode(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2025-03-26",
            },
        )
        if host:
            request.add_header("Host", host)
        if request_origin:
            request.add_header("Origin", request_origin)
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())

    call(
        "initialize",
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "synthetic-test", "version": "1"},
        },
        1,
    )
    result = call(
        "tools/call", {"name": "connect", "arguments": {"provider": provider}}, 2
    )["result"]
    assert not result.get("isError"), result
    return json.loads(result["content"][0]["text"])["result"]


async def main() -> None:
    if "--unmanaged" in sys.argv:
        print(
            "Local unmanaged acceptance; image policy qualification remains required",
            flush=True,
        )
    else:
        assert policy_installed(), "browser policy was not installed in the image"
    servers = []
    with tempfile.TemporaryDirectory(prefix="newsclip-e2e-") as directory:
        root = Path(directory)
        users = root / "users.json"
        for user in ("alice", "bob"):
            add_user(users, user, root / f"{user}.token")
        alice_token = (root / "alice.token").read_text().strip()
        bob_token = (root / "bob.token").read_text().strip()
        os.environ["NEWSCLIP_USERS_FILE"] = str(users)
        os.environ["NEWSCLIP_LOGIN_TOKEN"] = LOGIN_TOKEN
        os.environ["NEWSCLIP_STATE_HOME"] = str(root / "state")
        os.environ["NEWSCLIP_DATA_HOME"] = str(root / "data")
        os.environ["NEWSCLIP_CONFIG_HOME"] = str(root / "config")
        specs = {key: synthetic_spec(key) for key in ("ft", "wsj")}
        registry = ProviderRegistry(
            (
                FTProvider(spec=specs["ft"], verification_url=ARTICLE_URLS["ft"]),
                WSJProvider(spec=specs["wsj"], verification_url=ARTICLE_URLS["wsj"]),
            )
        )
        composition.build_registry = lambda: registry
        composition.load_builtin_provider_specs = lambda: tuple(specs.values())
        composition.CurlCffiHttpClient = SyntheticHttp
        reader_markers = []

        class InterceptedRuntime(PatchrightRuntime):
            @contextlib.contextmanager
            def open(self, profile, **kwargs):
                config = kwargs.get("launch_config") or BrowserLaunchConfig()
                kwargs["launch_config"] = replace(
                    config, args=(*config.args, *OFFLINE_ARGS)
                )
                with super().open(profile, **kwargs) as browser:

                    def article_route(route):
                        if route.request.url in ARTICLE_URLS.values():
                            route.fulfill(
                                status=200,
                                content_type="text/html",
                                body=FULL.replace(ARTICLE_URL, route.request.url),
                            )
                        else:
                            route.abort()

                    browser.context.route("https://*.example.com/**", article_route)

                    def record_marker():
                        if browser.page.url in ARTICLE_URLS.values():
                            reader_markers.append(
                                browser.page.evaluate(
                                    "localStorage.getItem('synthetic-user')"
                                )
                            )

                    browser.page.on("domcontentloaded", record_marker)
                    yield browser

        composition.PatchrightRuntime = InterceptedRuntime
        # These restrictions belong only to the synthetic acceptance process.
        # Any request missed by interception must fail without external DNS.
        window_browser.LAUNCH_ARGS = (*window_browser.LAUNCH_ARGS, "--no-proxy-server")
        window_hosts.host_resolver_rules = lambda *args: OFFLINE_ARGS[1].split("=", 1)[
            1
        ]

        submitted = []
        typed = {}

        def configure_context(context, window):
            def route(request_route):
                parsed = urlsplit(request_route.request.url)
                if parsed.path == "/signin":
                    request_route.fulfill(
                        status=200, content_type="text/html", body=FORM
                    )
                elif parsed.path == "/typed":
                    typed[window.params["user"], window.params["provider"]] = parse_qs(
                        parsed.query
                    ).get("signal", [""])[0]
                    request_route.fulfill(status=204, body="")
                elif parsed.path == "/connected":
                    assert parse_qs(parsed.query).get("signal") == [INPUT]
                    submitted.append((window.params["user"], window.params["provider"]))
                    request_route.fulfill(
                        status=200,
                        content_type="text/html",
                        body='<script>localStorage.setItem("synthetic-user", '
                        + json.dumps(window.params["user"])
                        + ")</script><h1>Signed in</h1>",
                        headers={
                            "set-cookie": (
                                "FTSession"
                                if window.params["provider"] == "ft"
                                else "djcs"
                            )
                            + "=synthetic-"
                            + window.params["user"]
                            + "; "
                            "Domain=.example.com; Path=/; Secure; HttpOnly"
                        },
                    )
                elif request_route.request.url in ARTICLE_URLS.values():
                    request_route.fulfill(
                        status=200,
                        content_type="text/html",
                        body=FULL.replace(ARTICLE_URL, request_route.request.url),
                    )
                else:
                    request_route.abort()

            context.route("https://*.example.com/**", route)

        login_port, port = free_port(), free_port()
        origin = f"http://127.0.0.1:{port}"
        browser_origin = f"http://localhost:{port}"
        identity = Identity()
        try:
            await identity.start(browser_origin)
        except BaseException:
            await identity.close()
            raise
        connections_config = ConnectionsConfig(
            OIDCConfig(
                identity.issuer,
                "newsclip-ui",
                browser_origin,
                root / "state" / "connections-browser",
                cookie_name="__Host-newsclip-connections",
                required_group="newsclip-users",
                claim_names=("account_alias",),
                allow_loopback_http=True,
            ),
            "account_alias",
            {},
        )
        sign_in = partial(
            human_signin,
            registry=registry,
            spec_loader=lambda key: specs[key],
            service_factory=composition.build_auth_service,
            configure_context=configure_context,
        )

        def runner(window):
            try:
                sign_in(window)
            except Exception:
                import traceback

                traceback.print_exc()
                raise

        login = build_signin_app(runner=runner, users_path=users)
        servers.append(await serve(login, login_port))

        def app():
            return build_standalone_app(
                users_path=users,
                public_url=origin,
                login_url=f"http://127.0.0.1:{login_port}",
                login_token=LOGIN_TOKEN,
                service_factory=lambda user: composition.build_mcp_service(user=user),
                connections_config=connections_config,
                mcp_public_url_aliases=("https://api.example.test:8443/newsclip",),
            )

        servers.append(await serve(app(), port))
        try:
            async with async_playwright() as playwright:
                viewer = await playwright.chromium.launch(
                    headless=True, args=OFFLINE_ARGS
                )
                context = await viewer.new_context(
                    viewport={"width": 1280, "height": 900}
                )
                other = await viewer.new_context(viewport={"width": 390, "height": 844})
                contexts = {"alice": context, "bob": other}
                owner_pages = {}
                for number, user in enumerate(("alice", "bob")):
                    owner_pages[user] = await contexts[user].new_page()
                    await identity.enroll(
                        contexts[user],
                        owner_pages[user],
                        number,
                        browser_origin + "/connections/",
                    )
                    await contexts[user].grant_permissions(
                        ["clipboard-write"], origin=browser_origin
                    )
                    assert await owner_pages[user].evaluate(
                        "document.documentElement.scrollWidth <= innerWidth"
                    )
                print(
                    "OK: two Pocket ID passkey users; isolated browser sessions",
                    flush=True,
                )
                bearer = {"authorization": "Bearer " + alice_token}
                assert (
                    await context.request.post(
                        browser_origin + "/users/alice/api/providers",
                        data={},
                        headers=bearer,
                    )
                ).status == 403
                assert (
                    await context.request.post(
                        origin + "/users/alice/api/providers",
                        data={},
                        headers={**bearer, "origin": browser_origin},
                    )
                ).status == 403
                print("OK: browser origin cannot admit native API access", flush=True)
                for host in (None, "api.example.test:8443"):
                    legacy = await asyncio.to_thread(
                        mcp_link,
                        origin,
                        alice_token,
                        host=host,
                        request_origin="https://api.example.test:8443",
                    )
                    assert legacy["expires_at"] is None
                print("OK: explicit legacy API authority/origin retained", flush=True)
                for user, token, provider_key in (
                    ("alice", alice_token, "ft"),
                    ("alice", alice_token, "wsj"),
                    ("bob", bob_token, "ft"),
                ):
                    controls = ConnectionControls(root / "state/users" / user)
                    before_request = controls.status(provider_key)
                    link = await asyncio.to_thread(
                        mcp_link, origin, token, user, provider_key
                    )
                    assert link["expires_at"] is None
                    assert link["url"].startswith(browser_origin + "/connections/")
                    assert controls.status(provider_key) == before_request
                    page = await contexts[user].new_page()
                    await page.goto(link["url"])
                    card = page.locator("article").filter(
                        has=page.get_by_role(
                            "heading",
                            name={
                                "ft": "Financial Times",
                                "wsj": "The Wall Street Journal",
                            }[provider_key],
                            exact=True,
                        )
                    )
                    await card.locator("form[action$='/start'] button").click()
                    await page.wait_for_url("**/users/" + user + "/connect/*")
                    wrong = contexts["bob" if user == "alice" else "alice"]
                    assert (await wrong.request.get(page.url)).status == 404
                    assert (await wrong.request.get(page.url + "/state")).status == 404
                    # Owner-bound: the window opens on its own.
                    try:
                        element = await page.wait_for_selector("iframe", timeout=30000)
                    except Exception:
                        print("Viewer state:", await page.inner_text("body"))
                        print(
                            "Window outcomes:",
                            [
                                (window.state, window.error)
                                for window in login.state.windows._windows.values()
                            ],
                        )
                        raise
                    frame = await element.content_frame()
                    await frame.wait_for_function(
                        "document.documentElement.classList.contains('noVNC_connected')",
                        timeout=60000,
                    )
                    await page.bring_to_front()
                    await frame.locator("#noVNC_transition").wait_for(state="hidden")
                    await frame.locator("#noVNC_container canvas").click(
                        position={"x": 20, "y": 20}
                    )
                    await page.evaluate(
                        "value => navigator.clipboard.writeText(value)", INPUT
                    )
                    await page.keyboard.press("Control+V")
                    for _ in range(50):
                        if typed.get((user, provider_key)) == INPUT:
                            break
                        await asyncio.sleep(0.1)
                    assert typed.get((user, provider_key)) == INPUT, (
                        "clipboard did not reach the synthetic field"
                    )
                    await page.keyboard.press("Enter")

                    def status(user=user, token=token, provider_key=provider_key):
                        with NewsclipClient(origin + f"/users/{user}", token) as client:
                            return client.session_status(provider_key)

                    for _ in range(200):
                        report = await asyncio.to_thread(status)
                        if report.status.value == "verified":
                            break
                        await asyncio.sleep(0.1)
                    if report.status.value != "verified":
                        print("Synthetic submissions:", submitted, flush=True)
                        print(
                            "Synthetic window outcomes:",
                            [
                                (window.state, window.error)
                                for window in login.state.windows._windows.values()
                            ],
                            flush=True,
                        )
                        raise AssertionError("human sign-in did not publish")
                    await page.close(run_before_unload=True)
                assert submitted == [("alice", "ft"), ("alice", "wsj"), ("bob", "ft")]

                # Explicit cancellation preserves accepted authority.
                def generation():
                    service = composition.build_auth_service(user="alice")
                    try:
                        return service._sessions.get_valid_session("ft").generation_id
                    finally:
                        service.close()

                previous_generation = await asyncio.to_thread(generation)
                with NewsclipClient(origin + "/users/alice", alice_token) as client:
                    previous = await asyncio.to_thread(client.session_status, "ft")
                    cancel_link = await asyncio.to_thread(client.connect, "ft")
                page = await context.new_page()
                await page.goto(str(cancel_link.url))
                card = page.locator("article").filter(
                    has=page.get_by_role("heading", name="Financial Times", exact=True)
                )
                await card.locator("form[action$='/start'] button").click()
                await page.wait_for_url("**/users/alice/connect/*")
                # Owner-bound: the window opens on its own.
                await page.wait_for_selector("iframe", timeout=30000)
                await page.get_by_role(
                    "button", name="Cancel sign-in", exact=True
                ).click()
                await page.close()
                for _ in range(100):
                    if all(
                        window.state not in ("starting", "waiting", "saving")
                        for window in login.state.windows._windows.values()
                    ):
                        break
                    await asyncio.sleep(0.1)
                with NewsclipClient(origin + "/users/alice", alice_token) as client:
                    preserved = await asyncio.to_thread(client.session_status, "ft")
                assert previous.last_verified_at == preserved.last_verified_at
                assert previous_generation == await asyncio.to_thread(generation)
                profiles = root / "state/users/alice/browser-profiles/ft"
                for _ in range(300):
                    if len(list(profiles.iterdir())) == 1:
                        break
                    await asyncio.sleep(0.1)
                assert len(list(profiles.iterdir())) == 1

                def save_and_check():
                    with NewsclipClient(origin + "/users/alice", alice_token) as client:
                        return {
                            key: client.save(url) for key, url in ARTICLE_URLS.items()
                        }

                saved = await asyncio.to_thread(save_and_check)
                assert all(
                    "generated paragraph" in article.body_markdown
                    for article in saved.values()
                )
                server, task = servers.pop()
                server.should_exit = True
                await task
                servers.append(await serve(app(), port))

                def after_restart():
                    with NewsclipClient(origin + "/users/alice", alice_token) as client:
                        for key, article in saved.items():
                            report = client.session_status(key)
                            assert report.status.value == "verified", report.model_dump(
                                mode="json"
                            )
                            assert (
                                client.archive_get(article.id).body_markdown
                                == article.body_markdown
                            )
                            assert client.get(ARTICLE_URLS[key]).id == article.id
                    with NewsclipClient(origin + "/users/bob", bob_token) as client:
                        assert client.archive_search("generated") == []

                await asyncio.to_thread(after_restart)
                assert reader_markers and all(
                    value == "alice" for value in reader_markers
                )
                page = owner_pages["alice"]
                await page.goto(browser_origin + "/connections/login?reauth=1")
                await identity.finish_login(page, browser_origin + "/connections/")
                card = page.locator("article").filter(
                    has=page.get_by_role("heading", name="Financial Times", exact=True)
                )
                await card.locator("details.manage summary").click()
                await card.get_by_role(
                    "button", name="Disconnect this subscription"
                ).click()
                await card.get_by_text("Disconnected", exact=False).wait_for()

                def after_disconnect():
                    service = composition.build_auth_service(user="alice")
                    try:
                        try:
                            service._sessions.get_valid_session("ft")
                        except SessionRequiredError:
                            pass
                        else:
                            raise AssertionError(
                                "a restarted application ignored disconnect"
                            )
                        assert service._sessions.get_valid_session("wsj")
                    finally:
                        service.close()
                    with NewsclipClient(origin + "/users/alice", alice_token) as client:
                        assert (
                            client.archive_get(saved["ft"].id).body_markdown
                            == saved["ft"].body_markdown
                        )
                    with NewsclipClient(origin + "/users/bob", bob_token) as client:
                        assert client.session_status("ft").status.value == "verified"

                await asyncio.to_thread(after_disconnect)
                await viewer.close()
                print(
                    "OK: owner disconnect survived restart; other subscriptions, "
                    "user and archive preserved",
                    flush=True,
                )
                print(
                    "OK: HTTP and retained-browser paths; MCP link, noVNC paste, "
                    "human sign-in, paid proof, archive "
                    "and restart reuse; users isolated"
                )
        finally:
            for server, task in reversed(servers):
                server.should_exit = True
                with contextlib.suppress(Exception):
                    await task
            await identity.close()


if __name__ == "__main__":
    ensure_virtual_display()
    asyncio.run(main())
