"""Digest binding fails closed on altered, missing or ambiguous release assets."""

import hashlib
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "release_distributions",
    Path(__file__).parents[1] / "scripts/check_release_distributions.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture
def distributions(tmp_path):
    names = ["newsclip-0.1.0-py3-none-any.whl", "newsclip-0.1.0.tar.gz"]
    metadata = {"assets": []}
    for name in names:
        path = tmp_path / name
        path.write_bytes(b"synthetic-distribution")
        metadata["assets"].append(
            {
                "name": name,
                "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return tmp_path, metadata


def test_exact_release_assets_are_accepted(distributions):
    root, metadata = distributions
    module.verify(metadata, root, "0.1.0")


@pytest.mark.parametrize(
    "damage", ["changed", "extra", "missing_digest", "duplicate_asset"]
)
def test_release_download_is_not_accepted_without_unique_matching_digests(
    distributions, damage
):
    root, metadata = distributions
    if damage == "changed":
        (root / metadata["assets"][0]["name"]).write_bytes(b"changed")
    elif damage == "extra":
        (root / "unexpected.whl").write_bytes(b"extra")
    elif damage == "missing_digest":
        metadata["assets"][0].pop("digest")
    else:
        metadata["assets"].append(metadata["assets"][0].copy())
    with pytest.raises(ValueError):
        module.verify(metadata, root, "0.1.0")
