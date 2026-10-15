#!/usr/bin/env python3
"""Check a built File Transfer ZIP for one runtime target, and report its sizes.

This wraps the packaging contract Core already enforces; it resolves nothing.

Static mode (authoring container, needs PyYAML):
    verify_distribution.py --archive dist/x.zip --runtime-target linux-arm64
checks the installer size limits and that every locked requirement has a wheel
for the target whose SHA-256 the manifest lists.

Install mode (a clean container of the target architecture, no network):
    verify_distribution.py --archive x.zip --runtime-target linux-arm64 --install
installs the target's wheels offline into a fresh virtual environment without
system packages, measures its site-packages, imports the extension and runs
its health check.

Both print one JSON report and exit 1 on any hard failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess  # nosec B404
import sys
import tempfile
import venv
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

MiB = 1024 * 1024
ARCHIVE_MAX_BYTES = 50 * MiB
ARCHIVE_MAX_UNCOMPRESSED_BYTES = 150 * MiB
ARCHIVE_TARGET_BYTES = 40 * MiB
SITE_PACKAGES_MAX_BYTES = 500 * MiB
ARCHITECTURES = {"linux-amd64": "x86_64", "linux-arm64": "aarch64"}
PYTHON_TAG = "cp312"
RUNTIME_MODULES = ("file_operations", "connection_factory", "connections.s3", "connections.dropbox")


def wheel_supports(filename: str, runtime_target: str) -> bool:
    """Pure wheels, or CPython 3.12-compatible wheels built for the target's Linux architecture."""
    stem = PurePosixPath(filename).name.removesuffix(".whl")
    parts = stem.split("-")
    if len(parts) < 5:
        return False
    python_tags, abi_tags, platform_tags = (
        parts[-3].split("."),
        parts[-2].split("."),
        parts[-1].split("."),
    )
    architecture = ARCHITECTURES[runtime_target]
    platform_ok = any(
        tag == "any"
        or (
            tag.startswith(("manylinux", "musllinux", "linux")) and tag.endswith(f"_{architecture}")
        )
        for tag in platform_tags
    )
    python_ok = any(
        tag in {"py3", "py2"} or tag == PYTHON_TAG or (tag.startswith("cp3") and "abi3" in abi_tags)
        for tag in python_tags
    )
    return platform_ok and python_ok


def _wheel_name_version(filename: str) -> tuple[str, str]:
    name, version = PurePosixPath(filename).name.split("-")[:2]
    return name.lower().replace("_", "-").replace(".", "-"), version


def _normalize(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def archive_report(archive: Path) -> dict[str, Any]:
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        uncompressed = sum(member.file_size for member in members)
    compressed = archive.stat().st_size
    failures = []
    if compressed > ARCHIVE_MAX_BYTES:
        failures.append(f"archive is {compressed} bytes; the limit is {ARCHIVE_MAX_BYTES}")
    if uncompressed > ARCHIVE_MAX_UNCOMPRESSED_BYTES:
        failures.append(
            f"archive unpacks to {uncompressed} bytes; the limit is {ARCHIVE_MAX_UNCOMPRESSED_BYTES}"
        )
    return {
        "archive_bytes": compressed,
        "uncompressed_bytes": uncompressed,
        "member_count": len(members),
        "sha256": _sha256_file(archive),
        "recommendation": (
            f"archive is above the {ARCHIVE_TARGET_BYTES}-byte working target; trim dependencies"
            if compressed > ARCHIVE_TARGET_BYTES
            else None
        ),
        "failures": failures,
    }


def closure_report(archive: Path, runtime_target: str) -> dict[str, Any]:
    import yaml

    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        manifest_name = next(
            name for name in names if PurePosixPath(name).parts[1:] == ("extension.yaml",)
        )
        manifest = yaml.safe_load(bundle.read(manifest_name))
        wheels = {
            name: "sha256:" + hashlib.sha256(bundle.read(name)).hexdigest()
            for name in names
            if name.endswith(".whl") and "wheels" in PurePosixPath(name).parts
        }
    failures: list[str] = []
    selected: list[str] = []
    for requirement in manifest.get("python_requirements") or []:
        name, version = _normalize(str(requirement["name"])), str(requirement["version"])
        hashes = set(requirement.get("hashes") or [])
        candidates = [
            wheel
            for wheel in wheels
            if _wheel_name_version(wheel) == (name, version)
            and wheel_supports(wheel, runtime_target)
        ]
        if not candidates:
            failures.append(f"{name}=={version} has no wheel for {runtime_target}")
            continue
        listed = [wheel for wheel in candidates if wheels[wheel] in hashes]
        if not listed:
            failures.append(
                f"{name}=={version} wheel for {runtime_target} does not match a locked hash"
            )
            continue
        selected.append(PurePosixPath(listed[0]).name)
    return {"runtime_target": runtime_target, "wheels": sorted(selected), "failures": failures}


def install_report(archive: Path, runtime_target: str, sdk_wheel: Path | None) -> dict[str, Any]:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="ft-verify-") as temp:
        root = Path(temp)
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(root / "unpacked")
        (bundle_dir,) = [path for path in (root / "unpacked").iterdir() if path.is_dir()]
        wheels = sorted(
            path
            for path in (bundle_dir / "wheels").glob("*.whl")
            if wheel_supports(path.name, runtime_target)
        )
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True, system_site_packages=False, clear=True).create(environment)
        python = str(environment / "bin" / "python")
        install = subprocess.run(  # nosec B603
            [
                python,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-index",
                "--no-cache-dir",
                "--find-links",
                str(bundle_dir / "wheels"),
                *map(str, wheels),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if install.returncode != 0:
            failures.append("offline install failed: " + install.stderr.strip()[-2000:])
            return {"runtime_target": runtime_target, "failures": failures}
        site = Path(
            subprocess.run(  # nosec B603
                [python, "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        site_bytes = sum(path.stat().st_size for path in site.rglob("*") if path.is_file())
        if site_bytes > SITE_PACKAGES_MAX_BYTES:
            failures.append(
                f"site-packages is {site_bytes} bytes; the limit is {SITE_PACKAGES_MAX_BYTES}"
            )
        checks: dict[str, Any] = {}
        if sdk_wheel is not None:
            # Core provides the public SDK at run time; the same wheel stands in for it here.
            subprocess.run(  # nosec B603
                [python, "-m", "pip", "install", "--no-index", "--no-deps", "-q", str(sdk_wheel)],
                check=True,
            )
        health = subprocess.run(  # nosec B603
            [python, "health.py"], cwd=bundle_dir, capture_output=True, text=True, check=False
        )
        checks["health"] = health.stdout.strip()
        if health.returncode != 0:
            failures.append("health check failed: " + health.stdout.strip()[-500:])
        if sdk_wheel is None:
            checks["imports"] = "skipped: no --sdk-wheel"
            return {
                "runtime_target": runtime_target,
                "installed_wheels": [path.name for path in wheels],
                "site_packages_bytes": site_bytes,
                "checks": checks,
                "failures": failures,
            }
        imports = subprocess.run(  # nosec B603
            [
                python,
                "-c",
                "import importlib, sys; [importlib.import_module(m) for m in sys.argv[1:]]",
                *RUNTIME_MODULES,
            ],
            cwd=bundle_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if imports.returncode != 0:
            failures.append("runtime import failed: " + imports.stderr.strip()[-1000:])
        checks["imports"] = list(RUNTIME_MODULES) if imports.returncode == 0 else []
        return {
            "runtime_target": runtime_target,
            "installed_wheels": [path.name for path in wheels],
            "site_packages_bytes": site_bytes,
            "checks": checks,
            "failures": failures,
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(MiB), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--runtime-target", choices=sorted(ARCHITECTURES), required=True)
    parser.add_argument("--install", action="store_true", help="install offline and run health")
    parser.add_argument("--sdk-wheel", type=Path, help="the public SDK wheel Core provides")
    args = parser.parse_args(argv)
    report: dict[str, Any] = {"archive": archive_report(args.archive)}
    if args.install:
        report["install"] = install_report(args.archive, args.runtime_target, args.sdk_wheel)
    else:
        report["closure"] = closure_report(args.archive, args.runtime_target)
    print(json.dumps(report, indent=2, sort_keys=True))
    failures = [failure for section in report.values() for failure in section.get("failures", [])]
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
