"""Prove rollback to the previous release on disposable synthetic state.

The previous release's code and locked dependencies are exported from its tag
into an isolated virtualenv and run in a separate interpreter against state
written by this source, and the other way round. The receipt is
`.artifacts/rollback-check.json` (see fleet release_compatibility).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / ".artifacts"
RECEIPT = ARTIFACTS / "rollback-check.json"
EVIDENCE = ARTIFACTS / "rollback-check" / "evidence.json"

SID_ACTIVE = "A" * 43
SID_PENDING = "P" * 43
SID_REVOKED = "R" * 43
SID_ROLLBACK = "B" * 43
SID_NEXT = "N" * 43
FIXED_NOW = 1_800_000_000.0

SIDE = r"""
import importlib.metadata
import json
import sqlite3
import sys
from pathlib import Path

import newsclip
from newsclip.connection_controls import ConnectionControls
from signin_window.oidc import BrowserStore

op = sys.argv[1]
state_dir = Path(sys.argv[2])
expected_root = Path(sys.argv[3]).resolve()
if not Path(newsclip.__file__).resolve().is_relative_to(expected_root):
    raise SystemExit(f"unexpected module path: {newsclip.__file__}")
sw_version = importlib.metadata.version("signin-window")
now = float(sys.argv[4])

def store():
    return BrowserStore(state_dir / "connections-browser", clock=lambda: now)

def controls(require_existing=False):
    return ConnectionControls(
        state_dir / "user", clock=lambda: now, require_existing=require_existing
    )

def tables(s):
    with sqlite3.connect(s.path) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        return sorted(r[0] for r in rows)

out = {"signin_window": sw_version}
if op == "seed-sessions":
    s = store()
    s.save(
        sys.argv[5],
        {"issuer": "https://id.example", "sub": "owner-a", "expires": now + 3600},
    )
    s.save(
        sys.argv[6],
        {
            "_state_abc": {"nonce": "n1"},
            "next": "/connections/",
            "pending_expires": now + 600,
        },
    )
    out["tables"] = tables(s)
elif op == "seed-with-revocation":
    s = store()
    s.save_if_not_revoked(
        sys.argv[5],
        {
            "issuer": "https://id.example",
            "sub": "owner-a",
            "expires": now + 3600,
            "_family": "fam-active",
        },
    )
    s.save_if_not_revoked(
        sys.argv[6],
        {
            "_state_xyz": {"nonce": "n2"},
            "next": "/connections/",
            "pending_expires": now + 600,
        },
    )
    s.save_if_not_revoked(
        sys.argv[7],
        {
            "issuer": "https://id.example",
            "sub": "owner-b",
            "expires": now + 3600,
            "_family": "fam-revoked",
        },
    )
    s.revoke(sys.argv[7])
    out["tables"] = tables(s)
    with sqlite3.connect(s.path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM revocations").fetchone()[0]
        out["revocations"] = count
elif op == "read-sessions":
    s = store()
    out["tables"] = tables(s)
    out["loaded"] = {sid: s.load(sid) for sid in sys.argv[5:]}
elif op == "write-and-delete":
    s = store()
    s.save(
        sys.argv[5],
        {"issuer": "https://id.example", "sub": "owner-prev", "expires": now + 3600},
    )
    s.delete(sys.argv[6])
    out["loaded"] = s.load(sys.argv[5])
    out["deleted"] = s.load(sys.argv[6])
elif op == "rotate-and-revoke":
    s = store()
    ok = s.save_if_not_revoked(
        sys.argv[6],
        {
            "issuer": "https://id.example",
            "sub": "owner-prev",
            "expires": now + 3600,
            "_family": "fam-rot",
        },
        old_sid=sys.argv[5],
    )
    out["rotated"] = ok
    out["loaded_new"] = s.load(sys.argv[6])
    out["loaded_old"] = s.load(sys.argv[5])
    s.revoke(sys.argv[6])
    out["after_revoke"] = s.load(sys.argv[6])
elif op == "controls-init":
    cs = controls(require_existing=False)
    cs.initialize("ft")
    out["control"] = cs.status("ft")
elif op == "controls-read":
    out["control"] = controls(require_existing=True).status("ft")
elif op == "controls-update":
    cs = controls(require_existing=True)
    rev = cs.suspend("ft")
    cs.disconnected("ft", revision=rev)
    out["control"] = cs.status("ft")
elif op == "app-read":
    from newsclip.providers import FTProvider
    from newsclip.sessions import SessionStore

    recipe = FTProvider().login_recipe
    sess_store = SessionStore(state_dir / "user", recipes={"ft": recipe}, http=None)
    health = sess_store.status("ft")
    artifact = sess_store.get_valid_session("ft")
    out["provider"] = health.provider
    out["status"] = health.status.value
    out["generation"] = str(artifact.generation_id)
else:
    raise SystemExit(f"unknown op: {op}")

print(json.dumps(out, sort_keys=True))
"""


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def require(condition: bool, message: object = "rollback check failed") -> None:
    if not condition:
        raise AssertionError(str(message))


class Check:
    def __init__(self, previous_root: Path, previous_py: Path, state: Path):
        self.sides = {
            "previous": (previous_py, previous_root),
            "current": (Path(sys.executable), ROOT),
        }
        self.state = state
        self.log: list[dict] = []

    def run(self, side: str, op: str, *args: str) -> dict:
        python_bin, root = self.sides[side]
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        env.pop("PYTHONPATH", None)
        result = subprocess.run(
            [
                str(python_bin),
                "-B",
                "-c",
                SIDE,
                op,
                str(self.state),
                str(root),
                str(FIXED_NOW),
                *args,
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.log.append(
            {
                "side": side,
                "op": op,
                "args": list(args),
                "exit": result.returncode,
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-4000:],
            }
        )
        if result.returncode:
            raise AssertionError(f"{side} {op} failed: {result.stderr.strip()[-600:]}")
        return json.loads(result.stdout)


def preserved_files(state: Path) -> dict[str, str]:
    target = state / "user" / "sessions" / "ft" / "default.json"
    return {
        str(target.relative_to(state)): hashlib.sha256(target.read_bytes()).hexdigest()
    }


def fresh(base: Path) -> Path:
    state = Path(tempfile.mkdtemp(dir=base))
    state.chmod(0o700)
    sessions_dir = state / "user" / "sessions" / "ft"
    sessions_dir.mkdir(parents=True, mode=0o700)
    (state / "user").chmod(0o700)
    (state / "user" / "sessions").chmod(0o700)
    rec = sessions_dir / "default.json"
    ts = datetime.fromtimestamp(FIXED_NOW, UTC).isoformat()
    rec.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "verified",
                "artifact": {
                    "schema_version": 1,
                    "generation_id": "11111111-1111-4111-8111-111111111111",
                    "provider": "ft",
                    "account_key": "default",
                    "created_at": ts,
                    "verified_at": ts,
                    "user_agent": "Synthetic Browser",
                    "cookies": [
                        {
                            "name": "FTSession_s",
                            "value": "synthetic-cookie",
                            "domain": ".ft.com",
                            "path": "/",
                            "secure": True,
                            "http_only": True,
                        }
                    ],
                },
            }
        )
    )
    rec.chmod(0o600)
    return state


def scenarios(previous_root: Path, previous_py: Path, base: Path):
    results: dict[str, str] = {}
    checks: list[tuple[str, Check]] = []

    def scenario(name: str, body):
        check = Check(previous_root, previous_py, fresh(base))
        checks.append((name, check))
        try:
            body(check)
        except Exception as error:
            check.log.append({"failure": f"{type(error).__name__}: {error}"})
            results[name] = "failed"
        else:
            results[name] = "passed"

    def upgrade(c: Check):
        seeded = c.run("previous", "seed-sessions", SID_ACTIVE, SID_PENDING)
        require(seeded["signin_window"] == "0.8.4", seeded)
        require(seeded["tables"] == ["sessions"], seeded["tables"])
        upgraded = c.run("current", "read-sessions", SID_ACTIVE, SID_PENDING)
        require(upgraded["signin_window"] == "0.10.0", upgraded)
        require(
            set(upgraded["tables"]) == {"sessions", "revocations", "session_families"},
            upgraded["tables"],
        )
        require(upgraded["loaded"][SID_ACTIVE]["sub"] == "owner-a", upgraded["loaded"])
        require(
            upgraded["loaded"][SID_PENDING]["_state_abc"] == {"nonce": "n1"},
            upgraded["loaded"],
        )

    def previous_read(c: Check):
        seeded = c.run(
            "current", "seed-with-revocation", SID_ACTIVE, SID_PENDING, SID_REVOKED
        )
        require(
            set(seeded["tables"]) == {"sessions", "revocations", "session_families"},
            seeded["tables"],
        )
        require(seeded["revocations"] >= 1, seeded)
        seen = c.run("previous", "read-sessions", SID_ACTIVE, SID_PENDING, SID_REVOKED)
        require(seen["signin_window"] == "0.8.4", seen)
        require(seen["loaded"][SID_ACTIVE]["sub"] == "owner-a", seen["loaded"])
        require(
            seen["loaded"][SID_PENDING]["_state_xyz"] == {"nonce": "n2"}, seen["loaded"]
        )
        require(seen["loaded"][SID_REVOKED] == {}, seen["loaded"])

    def previous_write(c: Check):
        c.run("current", "seed-with-revocation", SID_ACTIVE, SID_PENDING, SID_REVOKED)
        written = c.run("previous", "write-and-delete", SID_ROLLBACK, SID_ACTIVE)
        require(written["loaded"]["sub"] == "owner-prev", written)
        require(written["deleted"] == {}, written)
        seen = c.run("current", "read-sessions", SID_ROLLBACK, SID_ACTIVE, SID_PENDING)
        require(seen["loaded"][SID_ROLLBACK]["sub"] == "owner-prev", seen["loaded"])
        require(seen["loaded"][SID_ACTIVE] == {}, seen["loaded"])
        require(
            seen["loaded"][SID_PENDING]["_state_xyz"] == {"nonce": "n2"}, seen["loaded"]
        )
        rotated = c.run("current", "rotate-and-revoke", SID_ROLLBACK, SID_NEXT)
        require(rotated["rotated"] is True, rotated)
        require(rotated["loaded_old"] == {}, rotated)
        require(rotated["loaded_new"]["sub"] == "owner-prev", rotated)
        require(rotated["after_revoke"] == {}, rotated)

    def controls(c: Check):
        created = c.run("current", "controls-init")["control"]
        seen = c.run("previous", "controls-read")["control"]
        require(seen == created, (seen, created))
        updated = c.run("previous", "controls-update")["control"]
        require(updated["phase"] == 1, updated)
        after = c.run("current", "controls-read")["control"]
        require(after == updated, (after, updated))

    def journal(c: Check):
        before = preserved_files(c.state)
        prev_app = c.run("previous", "app-read")
        require(
            prev_app["provider"] == "ft" and prev_app["status"] == "verified", prev_app
        )
        c.run("previous", "seed-sessions", SID_ACTIVE, SID_PENDING)
        c.run("current", "read-sessions", SID_ACTIVE, SID_PENDING)
        curr_app = c.run("current", "app-read")
        require(
            curr_app["provider"] == prev_app["provider"]
            and curr_app["status"] == prev_app["status"],
            (curr_app, prev_app),
        )
        c.run("current", "seed-with-revocation", SID_ACTIVE, SID_PENDING, SID_REVOKED)
        c.run("previous", "write-and-delete", SID_ROLLBACK, SID_ACTIVE)
        c.run("current", "read-sessions", SID_ROLLBACK, SID_PENDING)
        after_app = c.run("previous", "app-read")
        require(
            after_app["provider"] == prev_app["provider"]
            and after_app["status"] == prev_app["status"],
            (after_app, prev_app),
        )
        require(
            preserved_files(c.state) == before,
            "application stores changed across upgrade and rollback",
        )

    scenario("upgrade", upgrade)
    scenario("previous-read", previous_read)
    scenario("previous-write", previous_write)
    scenario("controls-preserved", controls)
    scenario("delivery-journal-preserved", journal)
    return results, {name: check.log for name, check in checks}


def main() -> int:
    started = datetime.now(UTC)
    source = git("rev-parse", "HEAD")
    compatibility = json.loads(
        (ROOT / "release" / "compatibility.json").read_text(encoding="utf-8")
    )
    rollback_versions = (compatibility.get("state") or {}).get(
        "rollback_versions"
    ) or []
    if not rollback_versions:
        raise RuntimeError(
            "release/compatibility.json must declare state.rollback_versions"
        )
    previous = str(rollback_versions[-1])
    tag = f"v{previous}"
    ARTIFACTS.mkdir(exist_ok=True)
    RECEIPT.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="rollback-check-") as temporary:
        base = Path(temporary)
        previous_root = base / "previous"
        previous_root.mkdir(mode=0o700)
        archive = subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "archive",
                tag,
                "pyproject.toml",
                "uv.lock",
                "README.md",
                "src",
            ],
            check=True,
            capture_output=True,
        )
        with tarfile.open(fileobj=BytesIO(archive.stdout)) as bundle:
            bundle.extractall(previous_root, filter="data")
        sync_env = {
            **os.environ,
            "UV_PROJECT_ENVIRONMENT": str(previous_root / ".venv"),
        }
        subprocess.run(
            ["uv", "sync", "--locked", "--no-dev", "--extra", "local", "--quiet"],
            cwd=previous_root,
            env=sync_env,
            check=True,
        )
        previous_py = previous_root / ".venv" / "bin" / "python"
        os.chmod(base, 0o700)
        results, log = scenarios(previous_root, previous_py, base)
    EVIDENCE.parent.mkdir(exist_ok=True)
    EVIDENCE.write_text(
        json.dumps(
            {"previous_tag": tag, "source_sha": source, "scenarios": log}, indent=1
        )
        + "\n"
    )
    passed = all(value == "passed" for value in results.values())
    receipt = {
        "schema": 1,
        "source_sha": source,
        "previous_version": previous,
        "status": "passed" if passed else "failed",
        "scenarios": results,
        "started_at": started.isoformat(),
        "finished_at": datetime.now(UTC).isoformat(),
        "artifacts": [
            {
                "path": str(EVIDENCE.relative_to(ROOT)),
                "sha256": hashlib.sha256(EVIDENCE.read_bytes()).hexdigest(),
            }
        ],
    }
    RECEIPT.write_text(json.dumps(receipt, indent=1, sort_keys=True) + "\n")
    print(json.dumps(results, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
