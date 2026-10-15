"""The workflow-facing contract: three operations, four connection types, one artifact shape."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

BUNDLE_ROOT = Path(__file__).resolve().parents[1]
CONNECTION_TYPES = ["ftp", "sftp", "s3", "dropbox"]
WORKFLOW_OPERATIONS = {"list_files", "fetch_file", "upload_file"}


def _yaml(rel: str) -> Any:
    return yaml.safe_load((BUNDLE_ROOT / rel).read_text())


def _operations() -> dict[str, dict[str, Any]]:
    return {
        row["operation_id"]: row for row in _yaml("contracts/operation_manifest.yaml")["operations"]
    }


def test_exactly_three_workflow_visible_operations():
    operations = _operations()
    actions = {row["action_id"]: row for row in _yaml("ui/actions/actions.yaml")["actions"]}

    visible_ops = {key for key, row in operations.items() if row.get("workflow_visible", True)}
    visible_actions = {key for key, row in actions.items() if row.get("workflow_visible", True)}

    assert visible_ops == WORKFLOW_OPERATIONS
    assert visible_actions == WORKFLOW_OPERATIONS
    assert (
        set(operations)
        == set(actions)
        == WORKFLOW_OPERATIONS
        | {
            "discover_host_key",
            "test_connection",
        }
    )


def test_every_workflow_operation_serves_every_connection_type():
    types = [
        row["connection_type_id"]
        for row in _yaml("contracts/connection_types.yaml")["connection_types"]
    ]
    operations = _operations()

    assert types == CONNECTION_TYPES
    for operation_id in WORKFLOW_OPERATIONS:
        assert operations[operation_id]["connection_type_ids"] == CONNECTION_TYPES
    for row in _yaml("contracts/connection_types.yaml")["connection_types"]:
        assert row["capabilities"] == {
            "test_connection": True,
            "list_files": True,
            "fetch_file": True,
            "upload_file": True,
        }


def test_outputs_are_the_same_for_every_connection_type():
    operations = _operations()

    assert [row["name"] for row in operations["list_files"]["outputs"]] == ["files", "truncated"]
    assert [row["name"] for row in operations["fetch_file"]["outputs"]] == [
        "artifact_handle",
        "artifact_filename",
        "source_filename",
        "remote_path",
        "sha256",
        "size_bytes",
    ]
    assert [row["name"] for row in operations["upload_file"]["outputs"]] == [
        "uploaded",
        "remote_path",
        "sha256",
        "size_bytes",
        "overwrite_protection",
    ]


def test_artifact_policies_agree_between_manifest_and_contract():
    manifest = _yaml("extension.yaml")["artifact_policies"]
    contract = _yaml("contracts/artifact_policies.yaml")["policies"]

    def _shape(rows: list[dict[str, Any]]) -> set[tuple[str, str, str, int]]:
        return {
            (row["operation_id"], side, item["binding_key"], item["max_size_bytes"])
            for row in rows
            for side in ("inputs", "outputs")
            for item in row.get(side, [])
        }

    assert (
        _shape(manifest)
        == _shape(contract)
        == {
            ("fetch_file", "outputs", "fetched_file", 209715200),
            ("upload_file", "inputs", "source_artifact", 209715200),
        }
    )


def test_new_failure_codes_are_declared_for_workflow_operations():
    operations = _operations()

    for operation_id in WORKFLOW_OPERATIONS:
        codes = set(operations[operation_id]["error_codes"])
        assert {
            "authorization_required",
            "permission_denied",
            "rate_limited",
            "provider_unavailable",
            "timeout",
        } <= codes
    assert "timeout_unknown" in operations["upload_file"]["error_codes"]
    assert "already_exists" in operations["upload_file"]["error_codes"]


def test_release_declares_the_host_contract_core_invokes():
    # Core never invokes a release that does not name extension_host_v2.
    assert _yaml("extension.yaml")["runtime"]["contract_version"] == "extension_host_v2"


def test_egress_names_every_destination():
    egress = _yaml("extension.yaml")["egress"]

    assert egress == {
        "hosts": ["api.dropboxapi.com", "content.dropboxapi.com"],
        "connection_fields": ["ftp.host", "sftp.host", "s3.endpoint_url"],
    }
