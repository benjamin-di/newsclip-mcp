"""Exercise the shipped server image offline with its production composition."""

from __future__ import annotations

import asyncio
import os
import socket
import tempfile
from pathlib import Path

import httpx
import uvicorn

from newsclip.client import NewsclipClient
from newsclip.extensions import local_extensions
from newsclip.providers.builtins import BUILTIN_PROVIDER_REGISTRATIONS
from newsclip.standalone import build_standalone_app
from newsclip.tenancy import add_user


async def main() -> None:
    assert local_extensions() is None
    assert not os.environ.get("OP_SERVICE_ACCOUNT_TOKEN")
    assert all(
        registration.build_auth_adapter is None
        for registration in BUILTIN_PROVIDER_REGISTRATIONS.values()
    )
    with tempfile.TemporaryDirectory(prefix="newsclip-smoke-") as directory:
        root = Path(directory)
        registry = root / "users.json"
        for user in ("alice", "bob"):
            add_user(registry, user, root / f"{user}.token")
        alice = (root / "alice.token").read_text().strip()
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
                    assert str(client.connect("ft").url).startswith(
                        origin + "/users/alice/connect/"
                    )
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
