"""The distribution check: a complete, untampered closure for each target, within size limits."""

from __future__ import annotations

import ast
import hashlib
import zipfile
from pathlib import Path

import pytest
import yaml

from scripts import verify_distribution as vd

BUNDLE_ROOT = Path(__file__).resolve().parents[1]
NATIVE = {
    "linux-amd64": "native_pkg-1.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
    "linux-arm64": "native_pkg-1.0-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.whl",
}
PURE = "pure_pkg-2.0-py3-none-any.whl"


def _build(
    tmp_path: Path, *, wheels: dict[str, bytes], hashes: dict[str, bytes] | None = None
) -> Path:
    """A minimal bundle ZIP; ``hashes`` are the wheel bodies the manifest was locked against."""
    locked = hashes if hashes is not None else wheels

    def _digest(body: bytes) -> str:
        return "sha256:" + hashlib.sha256(body).hexdigest()

    manifest = {
        "extension_id": "flowsteward.file-transfer",
        "python_requirements": [
            {
                "name": "native-pkg",
                "version": "1.0",
                "hashes": sorted(
                    _digest(body) for name, body in locked.items() if name.startswith("native")
                ),
            },
            {"name": "pure-pkg", "version": "2.0", "hashes": [_digest(locked[PURE])]},
        ],
    }
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("flowsteward_file_transfer/extension.yaml", yaml.safe_dump(manifest))
        for name, body in wheels.items():
            bundle.writestr(f"flowsteward_file_transfer/wheels/{name}", body)
    return archive


def _complete() -> dict[str, bytes]:
    return {NATIVE["linux-amd64"]: b"amd", NATIVE["linux-arm64"]: b"arm", PURE: b"pure"}


@pytest.mark.parametrize("target", ["linux-amd64", "linux-arm64"])
def test_complete_closure_passes_for_each_target(tmp_path, target):
    report = vd.closure_report(_build(tmp_path, wheels=_complete()), target)

    assert report["failures"] == []
    assert report["wheels"] == sorted([NATIVE[target], PURE])


def test_missing_arm64_wheel_fails_distribution(tmp_path):
    wheels = _complete()
    del wheels[NATIVE["linux-arm64"]]
    archive = _build(tmp_path, wheels=wheels, hashes=_complete())

    assert vd.closure_report(archive, "linux-amd64")["failures"] == []
    assert vd.closure_report(archive, "linux-arm64")["failures"] == [
        "native-pkg==1.0 has no wheel for linux-arm64"
    ]


def test_modified_wheel_hash_fails_distribution(tmp_path):
    wheels = _complete()
    wheels[PURE] = b"tampered"
    archive = _build(tmp_path, wheels=wheels, hashes=_complete())

    failures = vd.closure_report(archive, "linux-amd64")["failures"]

    assert failures == ["pure-pkg==2.0 wheel for linux-amd64 does not match a locked hash"]


def test_archive_size_limits(tmp_path, monkeypatch):
    archive = _build(tmp_path, wheels={**_complete(), PURE: b"x" * 4096})

    assert vd.archive_report(archive)["failures"] == []
    monkeypatch.setattr(vd, "ARCHIVE_MAX_BYTES", 64)
    monkeypatch.setattr(vd, "ARCHIVE_MAX_UNCOMPRESSED_BYTES", 128)
    monkeypatch.setattr(vd, "ARCHIVE_TARGET_BYTES", 32)
    report = vd.archive_report(archive)

    assert len(report["failures"]) == 2
    assert report["recommendation"] is not None


@pytest.mark.parametrize(
    ("filename", "target", "expected"),
    [
        ("a-1-py3-none-any.whl", "linux-arm64", True),
        ("a-1-cp39-abi3-manylinux2014_aarch64.manylinux_2_17_aarch64.whl", "linux-arm64", True),
        ("a-1-cp39-abi3-manylinux2014_aarch64.manylinux_2_17_aarch64.whl", "linux-amd64", False),
        ("a-1-cp311-cp311-manylinux2014_x86_64.whl", "linux-amd64", False),
        ("a-1-cp312-cp312-macosx_11_0_arm64.whl", "linux-arm64", False),
    ],
)
def test_wheel_target_matching(filename, target, expected):
    assert vd.wheel_supports(filename, target) is expected


def test_locked_manifest_covers_both_targets_with_the_bundled_wheels(tmp_path):
    archive = tmp_path / "repo.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.write(BUNDLE_ROOT / "extension.yaml", "flowsteward_file_transfer/extension.yaml")
        for wheel in sorted((BUNDLE_ROOT / "wheels").glob("*.whl")):
            bundle.write(wheel, f"flowsteward_file_transfer/wheels/{wheel.name}")

    for target in ("linux-amd64", "linux-arm64"):
        assert vd.closure_report(archive, target)["failures"] == [], target


def test_runtime_has_no_pip_resolution():
    runtime = [
        "main.py",
        "health.py",
        "file_operations.py",
        "file_connections.py",
        "file_errors.py",
        "connection_factory.py",
        "file_transfer_extension.py",
        *sorted(
            str(path.relative_to(BUNDLE_ROOT))
            for path in (BUNDLE_ROOT / "connections").glob("*.py")
        ),
    ]
    forbidden = {
        "pip",
        "subprocess",
        "ensurepip",
        "venv",
        "setuptools",
        "importlib.util.spec_from_file_location",
    }
    for rel in runtime:
        tree = ast.parse((BUNDLE_ROOT / rel).read_text())
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import | ast.ImportFrom)
            for alias in (
                node.names if isinstance(node, ast.Import) else [ast.alias(node.module or "")]
            )
        }
        assert not imported & forbidden, (rel, imported & forbidden)
