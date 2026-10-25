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
import tempfile
import urllib.request
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import uvicorn
from patchright.async_api import async_playwright
from pydantic import HttpUrl
from signin_window.browser import policy_installed

import newsclip.composition as composition
from newsclip.browser_runtime import PatchrightRuntime
from newsclip.browser_runtime.surface import ensure_virtual_display
from newsclip.client import NewsclipClient
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
    '<input autofocus name="signal" style="position:fixed;inset:0;width:100%;'
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


def mcp_link(origin, token, user="alice", provider="ft"):
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

        submitted = []

        def configure_context(context, window):
            def route(request_route):
                parsed = urlsplit(request_route.request.url)
                if parsed.path == "/signin":
                    request_route.fulfill(
                        status=200, content_type="text/html", body=FORM
                    )
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
            )

        servers.append(await serve(app(), port))
        try:
            async with async_playwright() as playwright:
                viewer = await playwright.chromium.launch(headless=True)
                context = await viewer.new_context(
                    viewport={"width": 1280, "height": 900}
                )
                await context.grant_permissions(["clipboard-write"], origin=origin)
                for user, token, provider_key in (
                    ("alice", alice_token, "ft"),
                    ("alice", alice_token, "wsj"),
                    ("bob", bob_token, "ft"),
                ):
                    link = await asyncio.to_thread(
                        mcp_link, origin, token, user, provider_key
                    )
                    page = await context.new_page()
                    await page.goto(link["url"])
                    await page.click("#go")
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
                    await frame.locator("#noVNC_container canvas").click()
                    await page.evaluate(
                        "value => navigator.clipboard.writeText(value)", INPUT
                    )
                    await page.keyboard.press("Control+V")
                    await asyncio.sleep(1.5)
                    await page.keyboard.press("Enter")

                    def status(user=user, token=token, provider_key=provider_key):
                        with NewsclipClient(origin + f"/users/{user}", token) as client:
                            return client.session_status(provider_key)

                    for _ in range(200):
                        report = await asyncio.to_thread(status)
                        if report.status.value == "verified":
                            break
                        await asyncio.sleep(0.1)
                    assert report.status.value == "verified", (
                        "human sign-in did not publish"
                    )
                    await page.close(run_before_unload=True)
                assert submitted == [("alice", "ft"), ("alice", "wsj"), ("bob", "ft")]

                # Closing a new window preserves authority and discards its candidate.
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
                await page.click("#go")
                await page.wait_for_selector("iframe", timeout=30000)
                await page.close(run_before_unload=True)
                for _ in range(100):
                    if all(
                        window.state not in ("starting", "waiting", "saving")
                        for window in login.state.windows._windows.values()
                    ):
                        break
                    await asyncio.sleep(0.1)
                await viewer.close()
                with NewsclipClient(origin + "/users/alice", alice_token) as client:
                    preserved = await asyncio.to_thread(client.session_status, "ft")
                assert previous.last_verified_at == preserved.last_verified_at
                assert previous_generation == await asyncio.to_thread(generation)
                assert (
                    len(
                        list((root / "state/users/alice/browser-profiles/ft").iterdir())
                    )
                    == 1
                )

            def save_and_check():
                with NewsclipClient(origin + "/users/alice", alice_token) as client:
                    return {key: client.save(url) for key, url in ARTICLE_URLS.items()}

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
                        assert client.session_status(key).status.value == "verified"
                        assert (
                            client.archive_get(article.id).body_markdown
                            == article.body_markdown
                        )
                        assert client.get(ARTICLE_URLS[key]).id == article.id
                with NewsclipClient(origin + "/users/bob", bob_token) as client:
                    assert client.archive_search("generated") == []

            await asyncio.to_thread(after_restart)
            assert reader_markers and all(value == "alice" for value in reader_markers)
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


if __name__ == "__main__":
    ensure_virtual_display()
    asyncio.run(main())
