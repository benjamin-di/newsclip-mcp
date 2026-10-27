"""Missing publisher authority is distinct from first connection setup."""

import shutil

import pytest

from newsclip.connection_controls import ConnectionControls
from newsclip.errors import PersistenceError


def test_missing_saved_publisher_cannot_reactivate(tmp_path):
    controls = ConnectionControls(tmp_path)
    controls.initialize("ft")
    revision = controls.suspend("ft")
    controls.disconnected("ft", revision=revision)
    controls.path("ft").unlink()
    with pytest.raises(PersistenceError):
        ConnectionControls(tmp_path).require_active("ft")
    with pytest.raises(PersistenceError):
        ConnectionControls(tmp_path, require_existing=False).initialize("ft")
    shutil.rmtree(controls.root)
    with pytest.raises(PersistenceError):
        ConnectionControls(tmp_path).require_active("ft")


@pytest.mark.parametrize("setting", ["1", "invalid", ""])
def test_hosted_publisher_requires_explicit_idempotent_initialization(
    tmp_path, monkeypatch, setting
):
    monkeypatch.setenv("CONNECTIONS_REQUIRE_CONTROLS", setting)
    with pytest.raises(PersistenceError):
        ConnectionControls(tmp_path).require_active("ft")
    ConnectionControls(tmp_path, require_existing=False).initialize("ft")
    controls = ConnectionControls(tmp_path)
    controls.require_active("ft")
    revision = controls.suspend("ft")
    controls.disconnected("ft", revision=revision)
    before = controls.path("ft").read_bytes()
    ConnectionControls(tmp_path, require_existing=False).initialize("ft")
    assert controls.path("ft").read_bytes() == before
