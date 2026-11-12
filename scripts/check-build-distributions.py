#!/usr/bin/env python3
"""Check both distribution stamps against their actual, matching source bytes."""

from __future__ import annotations

import argparse
import json
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path
from tempfile import TemporaryDirectory

from newsclip.provenance import build_source_identity


def _behavior(path: str) -> bool:
    return path.startswith("newsclip/") and (
        path.endswith(".py")
        or (
            path.startswith("newsclip/provider_definitions/") and path.endswith(".toml")
        )
    )


def verify(
    directory: Path, version: str, revision: str, fingerprint: str | None = None
):
    wheel = directory / f"newsclip-{version}-py3-none-any.whl"
    sdist = directory / f"newsclip-{version}.tar.gz"
    files = {path for path in directory.iterdir() if path.name != ".gitignore"}
    if files != {wheel, sdist}:
        raise ValueError("Expected exactly the selected wheel and sdist")
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate wheel members")
        wheel_identity = json.loads(archive.read("newsclip/build_identity.json"))
        wheel_source = {name: archive.read(name) for name in names if _behavior(name)}
        metadata = archive.read(f"newsclip-{version}.dist-info/METADATA")
        if BytesParser().parsebytes(metadata)["Version"] != version:
            raise ValueError("Wheel metadata version conflicts")
    with TemporaryDirectory() as temporary, tarfile.open(sdist) as archive:
        root = Path(temporary)
        prefix = f"newsclip-{version}/"
        seen = set()
        sdist_source = {}
        for member in archive.getmembers():
            if not member.name.startswith(prefix) or not member.isfile():
                raise ValueError("Unexpected sdist member")
            name = member.name.removeprefix(prefix)
            if name in seen or ".." in Path(name).parts or Path(name).is_absolute():
                raise ValueError("Ambiguous sdist member")
            seen.add(name)
            if name not in {"pyproject.toml", "uv.lock", "PKG-INFO"} and not (
                name.startswith("src/")
                and (_behavior(name[4:]) or name == "src/newsclip/build_identity.json")
            ):
                continue
            handle = archive.extractfile(member)
            assert handle is not None
            data = handle.read()
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            if name.startswith("src/") and _behavior(name[4:]):
                sdist_source[name[4:]] = data
        sdist_identity = json.loads(
            (root / "src/newsclip/build_identity.json").read_text()
        )
        source = build_source_identity(root)
        expected = {
            "service": "newsclip",
            "version": version,
            "source_revision": revision,
            "source_fingerprint": source.source_fingerprint,
            "dirty": False,
        }
        if fingerprint is not None and fingerprint != source.source_fingerprint:
            raise ValueError(
                "Packaged source fingerprint conflicts with selected source"
            )
        if wheel_identity != expected or sdist_identity != expected:
            raise ValueError("Distribution build identity conflicts")
        if wheel_source != sdist_source:
            raise ValueError("Wheel and sdist contain different application source")
        declared = tomllib.loads((root / "pyproject.toml").read_text())["project"][
            "version"
        ]
        if (
            declared != version
            or BytesParser().parsebytes((root / "PKG-INFO").read_bytes())["Version"]
            != version
        ):
            raise ValueError("Source distribution version conflicts")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("version")
    parser.add_argument("revision")
    parser.add_argument("--fingerprint")
    args = parser.parse_args()
    verify(args.directory, args.version, args.revision, args.fingerprint)
