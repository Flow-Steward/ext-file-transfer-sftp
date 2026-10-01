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
"${PYTHON_BIN}" -m compileall -q file_transfer_extension.py health.py main.py tests scripts
"${PYTHON_BIN}" -m ruff check .
"${PYTHON_BIN}" -m ruff format --check .
"${PYTHON_BIN}" -m mypy file_transfer_extension.py health.py main.py tests scripts
"${PYTHON_BIN}" -m bandit -q -r file_transfer_extension.py health.py main.py
"${PYTHON_BIN}" -m pip_audit -r requirements.in
"${PYTHON_BIN}" -m pytest -q tests
