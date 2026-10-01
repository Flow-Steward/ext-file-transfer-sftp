#!/usr/bin/env python3
"""Check packaged archives with the extension catalog's own checker.

    python3 .github/scripts/catalog_check.py dist/*.zip

Fetches scripts/build_index.py from github.com/Flow-Steward/extensions and runs
its inspect_archive on every archive, so a release the catalog would refuse
fails here, before it is published.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
import urllib.request
from pathlib import Path

CATALOG = "https://raw.githubusercontent.com/Flow-Steward/extensions/main"
_NAME = re.compile(
    r"^(?P<id>[a-z0-9.-]+?)-(?P<version>\d+\.\d+\.\d+)(?:-(?P<target>linux-amd64|linux-arm64))?\.zip$"
)


def _repository() -> str:
    """https://github.com/<owner>/<repo> of this repository (GITHUB_REPOSITORY in Actions)."""
    import os
    import subprocess

    slug = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if not slug:
        remote = subprocess.run(
            ["git", "remote", "get-url", "origin"], capture_output=True, text=True, check=False
        ).stdout.strip()
        match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", remote)
        slug = match.group(1) if match else "owner/repo"
    return f"https://github.com/{slug}"


def _fetch(path: str) -> bytes:
    with urllib.request.urlopen(f"{CATALOG}/{path}", timeout=60) as response:  # noqa: S310 - fixed https host
        return response.read()


def main(paths: list[str]) -> int:
    try:
        source, categories = _fetch("scripts/build_index.py"), json.loads(_fetch("categories.json"))
        publishers = json.loads(_fetch("verified_publishers.json"))
    except OSError as exc:
        print(f"::warning::catalog checker unavailable ({exc}); archives were not checked against it")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "build_index.py"
        script.write_bytes(source)
        spec = importlib.util.spec_from_file_location("catalog_build_index", script)
        catalog = importlib.util.module_from_spec(spec)
        # Registered first: its dataclasses resolve their own module by name.
        sys.modules[spec.name] = catalog
        spec.loader.exec_module(catalog)
    failures = 0
    for path in paths:
        match = _NAME.match(Path(path).name)
        if not match:
            print(f"{path}: not named <extension_id>-<version>-<target>.zip", file=sys.stderr)
            failures += 1
            continue
        entry = catalog.parse_entry(match["id"], f"repository: {_repository()}\n")
        try:
            catalog.inspect_archive(
                Path(path).read_bytes(), entry=entry, version=match["version"],
                categories=set(categories), publishers=publishers, target=match["target"] or "",
            )
        except catalog.CatalogError as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"{Path(path).name}: the catalog would accept it")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
