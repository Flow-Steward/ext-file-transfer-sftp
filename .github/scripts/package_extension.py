#!/usr/bin/env python3
"""Package this repository as a Flow Steward extension archive.

    python3 .github/scripts/package_extension.py   ->  dist/<extension_id>-<version>.zip
                                                       or, with per-architecture wheels,
                                                       dist/<extension_id>-<version>-linux-amd64.zip
                                                       dist/<extension_id>-<version>-linux-arm64.zip

The archive is what ``flow-steward extensions bundle`` produces: every tracked
file under one top folder named after the id (``.`` and ``-`` become ``_``),
without the repository's own tooling (.github/) and without development caches.
When wheels/ holds wheels built for one architecture, it is what
``bundle --runtime-target`` produces instead: one archive per target, each with
only the wheels that install on it and a .fs-package.yaml naming the target.
"""

from __future__ import annotations

import re
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
# The product bundler leaves these out (core/application/tooling/extensions/bundle_extension.py).
EXCLUDED_DIRECTORIES = {
    ".fs-python", ".hypothesis", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__", "dev-wheels",
}
EXCLUDED_FILES = {".fs-extension-install.yaml", ".fs-package.yaml"}
REPOSITORY_TOOLING = {".github", "dist"}
TARGETS = {"linux-amd64": "x86_64", "linux-arm64": "aarch64"}
MAX_ZIP_BYTES = 50 * 1024 * 1024
MAX_UNPACKED_BYTES = 150 * 1024 * 1024


def manifest_field(name: str) -> str:
    text = (ROOT / "extension.yaml").read_text(encoding="utf-8")
    match = re.search(rf"^{name}:\s*['\"]?([^'\"\s#]+)", text, re.M)
    if not match:
        sys.exit(f"extension.yaml has no {name}")
    return match.group(1)


def shipped_files() -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True, text=True).stdout
    files = []
    for name in sorted(p for p in out.split("\0") if p):
        parts = PurePosixPath(name).parts
        if parts[0] in REPOSITORY_TOOLING or name in REPOSITORY_TOOLING:
            continue
        if any(part in EXCLUDED_DIRECTORIES for part in parts) or parts[-1] in EXCLUDED_FILES:
            continue
        if parts[0] == "bin":
            sys.exit("bin/ needs one archive per runtime target; see the catalog README")
        files.append(name)
    return files


def _wheel_platforms(name: str) -> list[str]:
    return name[: -len(".whl")].rsplit("-", 1)[-1].split(".") if name.endswith(".whl") else ["any"]


def wheel_supports_target(name: str, target: str) -> bool:
    """Flow Steward's rule: a pure wheel, or a Linux wheel for this architecture."""
    arch = TARGETS[target]
    return any(
        platform == "any"
        or (platform.startswith(("manylinux", "musllinux", "linux")) and platform.endswith(f"_{arch}"))
        for platform in _wheel_platforms(PurePosixPath(name).name)
    )


def _write(out: Path, folder: str, files: list[str], *, target: str = "") -> None:
    unpacked = 0
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in files:
            archive.write(ROOT / name, arcname=f"{folder}/{name}")
            unpacked += (ROOT / name).stat().st_size
        if target:
            archive.writestr(f"{folder}/.fs-package.yaml", f"runtime_target: {target}\n")
    size = out.stat().st_size
    if size > MAX_ZIP_BYTES or unpacked > MAX_UNPACKED_BYTES:
        sys.exit(f"{out.name}: {size} zipped / {unpacked} unpacked bytes exceed Flow Steward's install limits")
    print(f"{out.relative_to(ROOT)}  {size / 2**20:.1f} MB zipped, {unpacked / 2**20:.1f} MB unpacked")


def main() -> int:
    extension_id, version = manifest_field("extension_id"), manifest_field("version")
    folder = extension_id.replace(".", "_").replace("-", "_")
    (ROOT / "dist").mkdir(exist_ok=True)
    files = shipped_files()
    wheels = [name for name in files if PurePosixPath(name).parts[0] == "wheels" and name.endswith(".whl")]
    per_target = any("any" not in _wheel_platforms(PurePosixPath(name).name) for name in wheels)
    if not per_target:
        _write(ROOT / "dist" / f"{extension_id}-{version}.zip", folder, files)
        return 0
    for target in TARGETS:
        shipped = [name for name in files if name not in wheels or wheel_supports_target(name, target)]
        _write(ROOT / "dist" / f"{extension_id}-{version}-{target}.zip", folder, shipped, target=target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
