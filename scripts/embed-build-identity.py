#!/usr/bin/env python3
"""Stamp a selected artifact before installation; fingerprints remain bounded."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path


def embed(
    root: Path,
    product_version: str,
    revision: str,
    *,
    dirty: bool = False,
    expected_fingerprint: str | None = None,
) -> None:
    declared = tomllib.loads((root / "pyproject.toml").read_text())["project"][
        "version"
    ]
    normalized = product_version.strip().removeprefix("v")
    if not normalized or normalized != declared:
        raise ValueError("VERSION must match the product version in pyproject.toml")
    if not re.fullmatch(r"(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", revision):
        raise ValueError("VCS_REF must be a full hexadecimal source revision")
    # Publisher tooling owns source inspection. Runtime only reads this artifact.
    sys.path.insert(0, str(root / "src"))
    from newsclip.provenance import build_source_identity

    source = build_source_identity(root)
    if (
        expected_fingerprint is not None
        and source.source_fingerprint != expected_fingerprint
    ):
        raise ValueError("Source fingerprint differs from the selected build inputs")
    (root / "src/newsclip/build_identity.json").write_text(
        json.dumps(
            {
                "service": "newsclip",
                "version": normalized,
                "source_revision": revision.lower(),
                "source_fingerprint": source.source_fingerprint,
                "dirty": dirty,
            }
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("revision")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--dirty", choices=("0", "1"), default="0")
    parser.add_argument("--expected-fingerprint")
    args = parser.parse_args()
    embed(
        args.root,
        args.version,
        args.revision,
        dirty=args.dirty == "1",
        expected_fingerprint=args.expected_fingerprint,
    )
