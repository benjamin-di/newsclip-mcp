"""A failed or conflicting registry lookup must never overwrite a release."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "a" * 64


@pytest.mark.parametrize(
    "state,passed,created",
    [
        ("absent", True, True),
        ("same", True, False),
        ("conflict", False, False),
        ("unreachable", False, False),
    ],
)
def test_promotion_preserves_verified_digest(
    tmp_path: Path, state: str, passed: bool, created: bool
) -> None:
    docker = tmp_path / "docker"
    docker.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
marker = pathlib.Path(os.environ['MARKER'])
digest = os.environ['TEST_DIGEST']
if args[:3] == ['buildx', 'imagetools', 'create']:
    assert args[-1].endswith('@' + digest)
    marker.write_text('created')
    sys.exit(0)
reference = args[3]
state = os.environ['STATE']
if '@' in reference or marker.exists() or state == 'same':
    print(json.dumps({'digest': digest}))
elif state == 'conflict':
    print(json.dumps({'digest': 'sha256:' + 'b' * 64}))
else:
    message = 'manifest unknown' if state == 'absent' else 'connection timed out'
    print(message, file=sys.stderr)
    sys.exit(1)
""")
    docker.chmod(0o755)
    marker = tmp_path / "created"
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "scripts/promote_image.sh"),
            "registry/test",
            DIGEST,
            "1.2.3",
        ],
        env={
            **os.environ,
            "PATH": str(tmp_path) + ":" + os.environ["PATH"],
            "MARKER": str(marker),
            "STATE": state,
            "TEST_DIGEST": DIGEST,
        },
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) is passed, result.stderr
    assert marker.exists() is created
