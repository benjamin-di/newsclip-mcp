"""Exercise the shipped server image offline with its production composition."""

from __future__ import annotations

import asyncio
import os
import socket
import tempfile
from importlib.util import find_spec
from pathlib import Path

import httpx
import uvicorn
from signin_window.oidc import OIDCConfig

from newsclip.client import NewsclipClient
from newsclip.connections import ConnectionsConfig
from newsclip.standalone import build_standalone_app
from newsclip.tenancy import add_user


async def main() -> None:
    assert find_spec("newsclip.local_extensions") is None
    assert not os.environ.get("OP_SERVICE_ACCOUNT_TOKEN")
    with tempfile.TemporaryDirectory(prefix="newsclip-smoke-") as directory:
        root = Path(directory)
        registry = root / "users.json"
        for user in ("alice", "bob"):
            add_user(registry, user, root / f"{user}.token")
        alice = (root / "alice.token").read_text().strip()
        os.environ["NEWSCLIP_CONFIG_HOME"] = str(root / "config")
        os.environ["NEWSCLIP_STATE_HOME"] = str(root / "state")
        os.environ["NEWSCLIP_DATA_HOME"] = str(root / "data")
        with socket.socket() as channel:
            channel.bind(("127.0.0.1", 0))
            port = channel.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        app = build_standalone_app(
            users_path=registry,
            public_url=origin,
            login_token="synthetic-smoke-internal-token-without-any-account",
            connections_config=ConnectionsConfig(
                OIDCConfig(
                    "https://identity.example.com",
                    "newsclip-ui",
                    origin,
                    root / "state" / "connections-browser",
                    cookie_name="__Host-newsclip-connections",
                    required_group="newsclip-users",
                    allow_loopback_http=True,
                ),
                "account_alias",
                {},
            ),
        )
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
        try:
            for _ in range(100):
                if server.started:
                    break
                if task.done():
                    await task
                await asyncio.sleep(0.05)
            assert server.started

            def check():
                with NewsclipClient(origin + "/users/alice", alice) as client:
                    assert client.archive_search("synthetic") == []
                    assert client.session_status("ft").status.value == "required"
                    assert client.doctor().browser_ready
                    link = client.connect("ft")
                    assert str(link.url) == origin + "/connections/#ft"
                    assert link.expires_at is None
                with httpx.Client(base_url=origin) as client:
                    assert client.get("/health").status_code == 200
                    assert (
                        client.post("/users/alice/api/providers", json={}).status_code
                        == 401
                    )
                    assert (
                        client.post(
                            "/users/bob/api/providers",
                            json={},
                            headers={"Authorization": f"Bearer {alice}"},
                        ).status_code
                        == 401
                    )

            await asyncio.to_thread(check)
            print(
                "OK: production composition, browser prerequisites, "
                "user authentication and isolated archives"
            )
        finally:
            server.should_exit = True
            await task


if __name__ == "__main__":
    asyncio.run(main())
