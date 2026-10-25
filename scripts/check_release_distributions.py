"""Verify that a release download contains exactly its two digest-bound packages."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


def verify(metadata: dict, directory: Path, version: str) -> None:
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        raise ValueError("invalid release version")
    expected = {f"newsclip-{version}-py3-none-any.whl", f"newsclip-{version}.tar.gz"}
    files = list(directory.iterdir())
    if {path.name for path in files} != expected or len(files) != 2:
        raise ValueError("release distribution set does not match")
    for path in files:
        assets = [
            asset
            for asset in metadata.get("assets", [])
            if asset.get("name") == path.name
        ]
        if len(assets) != 1 or path.is_symlink() or not path.is_file():
            raise ValueError("ambiguous release distribution")
        digest = assets[0].get("digest", "")
        actual = "sha256:" + hashlib.file_digest(path.open("rb"), "sha256").hexdigest()
        if re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None or actual != digest:
            raise ValueError("release distribution digest does not match")


def main() -> None:
    verify(json.loads(Path(sys.argv[1]).read_text()), Path(sys.argv[2]), sys.argv[3])
    print("Release distribution digests verified")


if __name__ == "__main__":
    main()
