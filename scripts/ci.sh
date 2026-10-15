#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${BUNDLE_ROOT}"

PYTHON_BIN="${PYTHON_BIN:-python3}"
export PYTHONPATH="${BUNDLE_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

check_local_requirement_files() {
  local requirements_file="$1"
  local line requirement missing=0
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "${line}" ]] && continue

    case "${line}" in
      -r\ * | --requirement\ *)
        requirement="${line#* }"
        ;;
      ./* | ../*)
        requirement="${line}"
        ;;
      *)
        continue
        ;;
    esac
    requirement="${requirement%%[[:space:]]*}"
    if [[ ! -e "${requirement}" ]]; then
      echo "Missing local requirement referenced by ${requirements_file}: ${requirement}" >&2
      missing=1
    fi
  done < "${requirements_file}"

  if [[ "${missing}" -ne 0 ]]; then
    exit 1
  fi
}

check_local_requirement_files requirements-dev.txt

"${PYTHON_BIN}" -m pip install --upgrade pip
"${PYTHON_BIN}" -m pip install -r requirements-dev.txt

"${PYTHON_BIN}" scripts/validate_bundle.py
"${PYTHON_BIN}" -m compileall -q file_transfer_extension.py file_operations.py file_connections.py file_errors.py connection_factory.py connections health.py main.py tests scripts .github/scripts/verify_distribution.py
"${PYTHON_BIN}" -m ruff check .
"${PYTHON_BIN}" -m ruff format --check .
"${PYTHON_BIN}" -m mypy file_transfer_extension.py file_operations.py file_connections.py file_errors.py connection_factory.py connections health.py main.py tests scripts .github/scripts/verify_distribution.py
"${PYTHON_BIN}" -m bandit -q -r file_transfer_extension.py file_operations.py file_connections.py file_errors.py connection_factory.py connections health.py main.py
# Audit the whole locked closure (every transitive wheel), not just the direct requirements.
locked_requirements="$(mktemp)"
trap 'rm -f "${locked_requirements}"' EXIT
"${PYTHON_BIN}" - "${locked_requirements}" <<'PY'
import sys

import yaml

with open("extension.yaml", encoding="utf-8") as handle:
    rows = yaml.safe_load(handle).get("python_requirements") or []
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.writelines(f"{row['name']}=={row['version']}\n" for row in rows)
PY
"${PYTHON_BIN}" -m pip_audit --disable-pip --no-deps -r "${locked_requirements}"
"${PYTHON_BIN}" -m pytest -q tests
