"""The bundle must disclose and bind every maintained wheel fork to its source."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import validate_bundle


def _fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(validate_bundle, "BUNDLE_ROOT", tmp_path)
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    wheel = wheels / "botocore-1.43.127+flowsteward.1-py3-none-any.whl"
    wheel.write_bytes(b"local-wheel")
    patch = tmp_path / "patch.json"
    patch.write_bytes(b"[]\n")
    wheel_hash = hashlib.sha256(wheel.read_bytes()).hexdigest()
    requirement = {
        "name": "botocore",
        "version": "1.43.127+flowsteward.1",
        "hashes": ["sha256:" + wheel_hash],
    }
    source = {
        "name": "botocore",
        "version": requirement["version"],
        "upstream_name": "botocore",
        "upstream_version": "1.43.127",
        "upstream_url": "https://files.pythonhosted.org/packages/botocore-1.43.127-py3-none-any.whl",
        "upstream_sha256": "a" * 64,
        "source_repository": "https://github.com/boto/botocore",
        "patches": "patch.json",
        "patch_sha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
        "wheel_filename": wheel.name,
        "wheel_sha256": wheel_hash,
    }
    return {"python_requirements": [requirement]}, source


def _validate(tmp_path, extension, rows):
    (tmp_path / "dependency-sources.json").write_text(
        json.dumps({"schema_version": 1, "dependencies": rows})
    )
    errors: list[str] = []
    validate_bundle._validate_python_wheels(extension, errors)
    return errors


def test_local_wheel_requires_source_provenance(tmp_path, monkeypatch):
    extension, _source = _fixture(tmp_path, monkeypatch)
    errors: list[str] = []
    validate_bundle._validate_python_wheels(extension, errors)
    assert any("provenance" in error for error in errors)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("upstream_name", "unrelated-package"),
        ("upstream_version", "1.0.0"),
        ("wheel_sha256", "b" * 64),
        ("patch_sha256", "b" * 64),
        ("wheel_filename", "missing.whl"),
        ("patches", "missing.json"),
        ("upstream_url", "https://example.invalid/botocore.whl"),
    ],
)
def test_local_wheel_rejects_unbound_provenance(tmp_path, monkeypatch, field, value):
    extension, source = _fixture(tmp_path, monkeypatch)
    source[field] = value
    assert _validate(tmp_path, extension, [source])


def test_local_wheel_accepts_bound_provenance(tmp_path, monkeypatch):
    extension, source = _fixture(tmp_path, monkeypatch)
    assert _validate(tmp_path, extension, [source]) == []


def test_actual_bundle_discloses_exact_local_wheel_and_patch_hashes():
    root = Path(__file__).resolve().parents[1]
    import yaml

    extension = yaml.safe_load((root / "extension.yaml").read_text())
    errors: list[str] = []
    validate_bundle._validate_python_wheels(extension, errors)
    assert errors == []
