"""Disposable Pocket ID and synthetic passkeys for browser acceptance."""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import secrets
import socket
import subprocess
import tempfile
from pathlib import Path

import httpx2

# Official Pocket ID 2.19.1 Linux amd64 release checksum.
SHA256 = "fbe58b3af6e225600136c7da033810d2d86436fbd13a135fa52205f467544436"


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(type=kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Identity:
    def __init__(self):
        binary = Path(os.environ["POCKET_ID_BIN"])
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == SHA256
        self.temp = tempfile.TemporaryDirectory(prefix="newsclip-identity-acceptance-")
        self.root = Path(self.temp.name)
        listen = free_port()
        self.actors_port = free_port(socket.SOCK_DGRAM)
        while self.actors_port == listen:
            self.actors_port = free_port(socket.SOCK_DGRAM)
        self.issuer = f"http://localhost:{listen}"
        api_key = secrets.token_urlsafe(32)
        env = {
            name: os.environ[name]
            for name in ("PATH", "LANG", "TZ")
            if name in os.environ
        }
        env.update(
            APP_URL=self.issuer,
            HOST="127.0.0.1",
            PORT=str(listen),
            ACTORS_HOST="127.0.0.1",
            ACTORS_PORT=str(self.actors_port),
            DB_CONNECTION_STRING=str(self.root / "identity.db"),
            ENCRYPTION_KEY=secrets.token_urlsafe(32),
            STATIC_API_KEY=api_key,
            ANALYTICS_DISABLED="true",
            VERSION_CHECK_DISABLED="true",
            ALLOW_INSECURE_CALLBACK_URLS="true",
            DISABLE_RATE_LIMITING="true",
        )
        self.log = (self.root / "provider.log").open("wb")
        self.process = subprocess.Popen(
            [str(binary)], cwd=self.root, env=env, stdout=self.log, stderr=self.log
        )
        self.admin = httpx2.Client(
            base_url=self.issuer, headers={"X-API-Key": api_key}, timeout=10
        )
        self.users = []

    def post(self, url, body):
        try:
            response = self.admin.post(url, json=body)
        except httpx2.HTTPError:
            # Preserve only this disposable provider's diagnostics, never data
            # from a real installation. The enclosing acceptance still fails.
            with tempfile.NamedTemporaryFile(
                prefix="newsclip-pocket-startup-", suffix=".log", delete=False
            ) as diagnostic:
                diagnostic.write((self.root / "provider.log").read_bytes())
            print(
                "Disposable identity provider failed:",
                self.process.poll(),
                "diagnostic:",
                diagnostic.name,
                flush=True,
            )
            raise
        assert response.status_code in (200, 201), (url, response.status_code)
        return response.json()

    async def start(self, base):
        try:
            await self._start(base)
        except BaseException:
            with tempfile.NamedTemporaryFile(
                prefix="pocket-startup-", suffix=".log", delete=False
            ) as diagnostic:
                diagnostic.write((self.root / "provider.log").read_bytes())
            print(
                "Disposable identity startup failed:",
                self.process.poll(),
                "diagnostic:",
                diagnostic.name,
                flush=True,
            )
            raise

    async def _start(self, base):
        for _ in range(200):
            try:
                if self.admin.get("/api/application-configuration").status_code == 200:
                    break
            except httpx2.HTTPError:
                pass
            await asyncio.sleep(0.1)
        else:
            raise AssertionError("Disposable identity provider did not start")
        group = self.post(
            "/api/user-groups",
            {"name": "newsclip-users", "friendlyName": "Newsclip users"},
        )
        for number in (1, 2):
            user = self.post(
                "/api/users",
                {
                    "username": f"example{number}",
                    "firstName": "Example",
                    "lastName": str(number),
                    "email": f"example{number}@example.com",
                    "isAdmin": False,
                },
            )
            result = self.admin.put(
                f"/api/users/{user['id']}/user-groups",
                json={"userGroupIds": [group["id"]]},
            )
            assert result.status_code in (200, 204)
            result = self.admin.put(
                f"/api/custom-claims/user/{user['id']}",
                json=[
                    {"key": "account_alias", "value": "alice" if number == 1 else "bob"}
                ],
            )
            assert result.status_code == 200
            self.users.append(user)
        self.post(
            "/api/oidc/clients",
            {
                "id": "newsclip-ui",
                "name": "Newsclip connections",
                "callbackURLs": [base + "/connections/callback"],
                "isPublic": True,
                "pkceEnabled": True,
                "launchURL": base + "/connections/",
            },
        )

    async def finish_login(self, page, home):
        for _ in range(20):
            if page.url == home:
                return
            await page.wait_for_timeout(350)
            button = page.get_by_role(
                "button", name=re.compile(r"^(Authenticate|Sign in|Allow|Authorize)$")
            )
            if await button.count() and await button.first.is_visible():
                await button.first.click()
        await page.wait_for_url(home, timeout=15000)

    async def enroll(self, context, page, number, home):
        user = self.users[number]
        cdp = await context.new_cdp_session(page)
        await cdp.send("WebAuthn.enable")
        authenticator = await cdp.send(
            "WebAuthn.addVirtualAuthenticator",
            {
                "options": {
                    "protocol": "ctap2",
                    "transport": "internal",
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "isUserVerified": True,
                    "automaticPresenceSimulation": True,
                }
            },
        )
        token = self.post(f"/api/users/{user['id']}/one-time-access-token", {})["token"]
        response = await context.request.post(
            self.issuer + "/api/one-time-access-token/" + token
        )
        assert response.ok
        await page.goto(self.issuer + "/settings/account")
        await page.get_by_role(
            "button", name=re.compile("add passkey", re.I)
        ).first.click()
        for _ in range(40):
            credentials = await cdp.send(
                "WebAuthn.getCredentials",
                {"authenticatorId": authenticator["authenticatorId"]},
            )
            if (
                credentials["credentials"]
                and self.admin.get(
                    f"/api/users/{user['id']}/webauthn-credentials"
                ).json()
            ):
                break
            await page.wait_for_timeout(100)
        else:
            raise AssertionError("Synthetic passkey enrollment did not finish")
        await context.clear_cookies()
        await page.goto(home)
        await page.get_by_role(
            "link", name="Continue with your identity provider"
        ).click()
        await self.finish_login(page, home)
        used = await cdp.send(
            "WebAuthn.getCredentials",
            {"authenticatorId": authenticator["authenticatorId"]},
        )
        assert (
            used["credentials"][0]["signCount"]
            > credentials["credentials"][0]["signCount"]
        )
        return cdp, authenticator

    async def close(self):
        self.admin.close()
        self.process.terminate()
        await asyncio.to_thread(self.process.wait, 10)
        self.log.close()
        self.temp.cleanup()
