#!/usr/bin/env python3

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import sys

REQUIRED_DEPENDENCIES = {
    "paramiko": "paramiko",
    "bcrypt": "bcrypt",
    "cryptography": "cryptography",
    "invoke": "invoke",
    "nacl": "PyNaCl",
}


def check_health() -> dict:
    missing: list[str] = []
    versions: dict[str, str] = {}
    for module_name, package_name in REQUIRED_DEPENDENCIES.items():
        if importlib.util.find_spec(module_name) is None:
            missing.append(package_name)
            continue
        try:
            versions[package_name] = importlib.metadata.version(package_name)
        except importlib.metadata.PackageNotFoundError:
            versions[package_name] = "unknown"
    if missing:
        return {
            "ok": False,
            "status": "unhealthy",
            "extension_id": "flowsteward.file-transfer",
            "error_code": "dependency_unavailable",
            "missing_dependencies": missing,
        }
    return {
        "ok": True,
        "status": "healthy",
        "extension_id": "flowsteward.file-transfer",
        "dependencies": versions,
    }


def main() -> int:
    payload = check_health()
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload.get("ok") is True else 2


if __name__ == "__main__":
    sys.exit(main())
