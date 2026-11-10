"""Exercise the pytest temp-root boundary used by protocol fixture secrets."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(os.name != "posix", reason="Unix temporary-directory security boundary")
@pytest.mark.parametrize("symlink_root", [False, True])
def test_pytest_temp_root_preserves_private_fixtures_and_rejects_symlinks(
    tmp_path: Path, symlink_root: bool
) -> None:
    import getpass

    temproot = tmp_path / "temp"
    temproot.mkdir()
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    attacker.chmod(0o755)
    root = temproot / f"pytest-of-{getpass.getuser()}"
    if symlink_root:
        root.symlink_to(attacker, target_is_directory=True)
    suite = tmp_path / "test_fixture.py"
    suite.write_text(
        "def test_private_fixture(tmp_path):\n"
        "    (tmp_path / 'fixture.key').write_bytes(b'private-fixture')\n"
    )
    config = tmp_path / "pytest.ini"
    config.write_text("[pytest]\n")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-c", str(config), str(suite)],
        env={
            **os.environ,
            "PYTEST_DEBUG_TEMPROOT": str(temproot),
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    if symlink_root:
        # Rejection must precede chmod through the attacker-supplied symlink.
        assert attacker.stat().st_mode & 0o777 == 0o755
        assert result.returncode != 0, result.stdout + result.stderr
        assert "is a symbolic link" in result.stdout + result.stderr, result.stdout + result.stderr
        assert not list(attacker.rglob("fixture.key"))
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert root.stat().st_mode & 0o077 == 0
        assert len(list(root.rglob("fixture.key"))) == 1
