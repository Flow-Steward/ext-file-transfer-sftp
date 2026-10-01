from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

import yaml

BUNDLE_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    errors: list[str] = []
    extension = _load_yaml("extension.yaml", errors)
    if not isinstance(extension, dict):
        _emit(errors)
        return 1

    _require(extension, "manifest_version", errors)
    _require_value(extension, "extension_id", "flowsteward.file-transfer", errors)
    _require(extension, "version", errors)
    _require_value(extension, "kind", "tool_provider", errors)

    for rel_path in _referenced_paths(extension):
        if not (BUNDLE_ROOT / rel_path).is_file():
            errors.append(f"referenced file is missing: {rel_path}")

    actions = _load_yaml("ui/actions/actions.yaml", errors)
    operations = _load_yaml("contracts/operation_manifest.yaml", errors)
    artifact_policies = _load_yaml("contracts/artifact_policies.yaml", errors)
    _validate_actions_and_operations(actions, operations, artifact_policies, errors)
    _validate_python_wheels(extension, errors)

    _emit(errors)
    return 1 if errors else 0


def _load_yaml(rel_path: str, errors: list[str]) -> Any:
    path = BUNDLE_ROOT / rel_path
    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    except Exception as exc:
        errors.append(f"{rel_path}: failed to parse YAML: {exc}")
        return None


def _referenced_paths(extension: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    schemas = _as_dict(extension.get("schemas"))
    for key in ("config", "secrets", "subscriptions"):
        value = str(schemas.get(key) or "").strip()
        if value:
            paths.append(value)
    runtime_v2 = _as_dict(_as_dict(extension.get("runtime")).get("extension_contract_v2"))
    for value in runtime_v2.values():
        text = str(value or "").strip()
        if text:
            paths.append(text)
    for key in ("ui_manifest", "action_manifest"):
        value = str(extension.get(key) or "").strip()
        if value:
            paths.append(value)
    for section in ("entrypoint", "health"):
        command = _as_dict(extension.get(section)).get("command")
        if isinstance(command, list) and len(command) >= 2:
            script = str(command[1] or "").strip()
            if script.endswith(".py"):
                paths.append(script)
    return paths


def _validate_actions_and_operations(
    actions: Any,
    operations: Any,
    artifact_policies: Any,
    errors: list[str],
) -> None:
    action_ids = {
        str(item.get("action_id") or "").strip()
        for item in _as_list(_as_dict(actions).get("actions"))
        if isinstance(item, dict)
    }
    operation_ids = {
        str(item.get("operation_id") or "").strip()
        for item in _as_list(_as_dict(operations).get("operations"))
        if isinstance(item, dict)
    }
    policy_ids = {
        str(item.get("operation_id") or "").strip()
        for item in _as_list(_as_dict(artifact_policies).get("policies"))
        if isinstance(item, dict)
    }
    if not action_ids:
        errors.append("ui/actions/actions.yaml must declare actions")
    if not operation_ids:
        errors.append("contracts/operation_manifest.yaml must declare operations")
    missing_actions = sorted(operation_ids - action_ids)
    if missing_actions:
        errors.append(f"operations missing UI actions: {', '.join(missing_actions)}")
    missing_operations = sorted(action_ids - operation_ids)
    if missing_operations:
        errors.append(f"UI actions missing operations: {', '.join(missing_operations)}")
    missing_policy_operations = sorted(policy_ids - operation_ids)
    if missing_policy_operations:
        errors.append(
            "artifact policies reference unknown operations: "
            + ", ".join(missing_policy_operations)
        )


def _validate_python_wheels(extension: dict[str, Any], errors: list[str]) -> None:
    wheel_hashes = {
        f"sha256:{_sha256(path)}": path.name for path in (BUNDLE_ROOT / "wheels").glob("*.whl")
    }
    for requirement in _as_list(extension.get("python_requirements")):
        if not isinstance(requirement, dict):
            errors.append("python_requirements entries must be objects")
            continue
        name = str(requirement.get("name") or "").strip()
        version = str(requirement.get("version") or "").strip()
        if not name or not version:
            errors.append("python_requirements entries require name and version")
        hashes = [str(item or "").strip() for item in _as_list(requirement.get("hashes"))]
        if not hashes:
            errors.append(f"python requirement {name or '<missing>'} has no hashes")
            continue
        missing = [item for item in hashes if item not in wheel_hashes]
        if missing:
            errors.append(
                f"python requirement {name or '<missing>'} has hashes with no bundled wheel: "
                + ", ".join(missing)
            )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require(mapping: dict[str, Any], key: str, errors: list[str]) -> None:
    if key not in mapping or mapping.get(key) in (None, ""):
        errors.append(f"extension.yaml missing required field: {key}")


def _require_value(
    mapping: dict[str, Any],
    key: str,
    expected: str,
    errors: list[str],
) -> None:
    value = str(mapping.get(key) or "").strip()
    if value != expected:
        errors.append(f"extension.yaml field {key} must be {expected!r}; got {value!r}")


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _emit(errors: list[str]) -> None:
    if not errors:
        print("bundle validation passed")
        return
    print("bundle validation failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
