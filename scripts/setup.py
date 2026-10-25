"""Create an idempotent local Compose configuration without displaying tokens."""

from __future__ import annotations

import argparse
import os
import secrets
from pathlib import Path

from newsclip import __version__
from newsclip.private_state import atomic_private_write
from newsclip.standalone import validate_public_url
from newsclip.tenancy import add_user, load_users


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user", action="append", required=True)
    parser.add_argument("--public-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    origin = validate_public_url(args.public_url)
    root = Path(__file__).resolve().parents[1]
    local = root / "local"
    for name in ("config", "tokens", "state", "data"):
        (local / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    registry = local / "config/users.json"
    existing = (
        {user.id: user for user in load_users(registry)} if registry.exists() else {}
    )
    for user in args.user:
        token_file = local / "tokens" / f"{user}.token"
        if user in existing:
            if not token_file.is_file() or not existing[user].accepts(
                token_file.read_text().strip()
            ):
                parser.error(
                    "existing user has no matching token file; use users add --rotate"
                )
        else:
            add_user(registry, user, token_file)
    login_token = local / "config/login.token"
    if not login_token.exists():
        atomic_private_write(login_token, (secrets.token_urlsafe(32) + "\n").encode())
    env = root / ".env"
    if not env.exists():
        atomic_private_write(
            env,
            (
                f"NEWSCLIP_UID={os.getuid()}\nNEWSCLIP_GID={os.getgid()}\n"
                f"NEWSCLIP_VERSION={__version__}\nNEWSCLIP_PUBLIC_URL={origin}\n"
            ).encode(),
        )
    print("OK: private configuration created. Start with docker compose up -d.")
    for user in args.user:
        print(f"User URL: {origin}/users/{user}; token file: local/tokens/{user}.token")


if __name__ == "__main__":
    main()
