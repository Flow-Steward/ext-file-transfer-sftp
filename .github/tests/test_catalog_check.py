"""The catalog checker runs only as the pinned, digest-verified file."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
from pathlib import Path
from urllib.error import URLError

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "catalog_check.py"


def _load():
    spec = importlib.util.spec_from_file_location("catalog_check_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_checker_is_fetched_at_a_pinned_commit():
    module = _load()
    assert len(module.CATALOG_REVISION) == 40
    assert module.CATALOG.endswith(module.CATALOG_REVISION)
    assert "/main" not in module.CATALOG


def test_a_changed_checker_is_refused_and_fails_the_job(monkeypatch, tmp_path):
    module = _load()

    def poisoned(url, timeout):
        return io.BytesIO(b"import os; os.system('replace the archives')")

    monkeypatch.setattr(module.urllib.request, "urlopen", poisoned)
    assert module.main([str(tmp_path / "x-1.0.0.zip")]) == 1


@pytest.mark.parametrize(
    "missing", ["scripts/build_index.py", "categories.json", "verified_publishers.json"]
)
@pytest.mark.parametrize(
    "failure", [URLError("catalog unavailable"), TimeoutError("catalog timed out")]
)
def test_unavailable_checker_or_policy_fails_the_job(monkeypatch, capsys, missing, failure):
    module = _load()
    files = {
        "scripts/build_index.py": b"raise AssertionError('fetch all policies first')",
        "categories.json": b"[]",
        "verified_publishers.json": b"{}",
    }
    if hasattr(module, "CATALOG_DIGESTS"):
        monkeypatch.setattr(
            module,
            "CATALOG_DIGESTS",
            {path: hashlib.sha256(data).hexdigest() for path, data in files.items()},
        )

    def unavailable(url, timeout):
        path = next(path for path in files if url.endswith("/" + path))
        if path == missing:
            raise failure
        return io.BytesIO(files[path])

    monkeypatch.setattr(module.urllib.request, "urlopen", unavailable)
    assert module.main([]) == 1
    output = capsys.readouterr()
    assert "::error::" in output.out + output.err
