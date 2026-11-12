#!/usr/bin/env python3
"""Offline acceptance of an installed artifact, with optional native MCP probe."""

import argparse
import asyncio
import json
from importlib.metadata import distribution, version

from newsclip.build_identity import BUILD


def check(revision: str, product_version: str, fingerprint: str | None, *, mcp: bool):
    assert BUILD.service == "newsclip"
    assert BUILD.version == version("newsclip") == product_version
    assert BUILD.source_revision == revision
    assert BUILD.dirty is False
    direct = json.loads(distribution("newsclip").read_text("direct_url.json") or "{}")
    assert not direct.get("dir_info", {}).get("editable", False)
    if fingerprint is not None:
        assert BUILD.source_fingerprint == fingerprint
    if mcp:
        from fastmcp import Client

        from newsclip.mcp_server import new_fastmcp

        async def initialize():
            for mode in ("legacy", "auto"):
                async with Client(
                    new_fastmcp("Newsclip acceptance", instructions=""), mode=mode
                ) as client:
                    assert client.server_info.version == product_version

        asyncio.run(initialize())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    parser.add_argument("version")
    parser.add_argument("--fingerprint")
    parser.add_argument("--mcp", action="store_true")
    args = parser.parse_args()
    check(args.revision, args.version, args.fingerprint, mcp=args.mcp)
