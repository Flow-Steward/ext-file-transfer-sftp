"""File Transfer workflow composition coverage using the public SDK test kit."""

from __future__ import annotations

import json
from typing import Any

from flowsteward_extension_sdk import read_artifact_bytes, write_artifact_bytes
from flowsteward_extension_sdk.testing import ExtensionWorkflowHarness

FILE_TRANSFER_EXTENSION_ID = "flowsteward.file-transfer"


def _file_transfer_extension() -> dict[str, Any]:
    return {
        "extension_key": FILE_TRANSFER_EXTENSION_ID,
        "action_definitions": [
            {"action_id": "fetch_file"},
            {"action_id": "upload_file"},
        ],
        "compiled_manifest": {
            "artifact_policies": [
                {
                    "operation_id": "fetch_file",
                    "outputs": [
                        {
                            "kind": "artifact",
                            "binding_key": "fetched_file",
                            "filename": "download.bin",
                            "content_type": "application/octet-stream",
                            "max_size_bytes": 1024,
                        }
                    ],
                },
                {
                    "operation_id": "upload_file",
                    "inputs": [
                        {
                            "kind": "artifact",
                            "value_type": "artifact_handle",
                            "binding_key": "source_artifact",
                            "field": "artifact_handle",
                            "required": True,
                        }
                    ],
                },
            ],
        },
    }


def test_file_transfer_fetch_handle_flows_into_tabular_feed_without_body(tmp_path):
    harness = ExtensionWorkflowHarness(artifact_root=tmp_path / "artifact_store")
    state = harness.initial_state(
        job_id="job_file_transfer_fetch",
        workflow_id="wf.file-transfer.tabular",
        account_id="acc_alpha",
        project_id="project_alpha",
    )
    observed: dict[str, dict[str, Any]] = {}

    def _run_action(extension, action_id, input_payload, **kwargs):
        ext_id = extension["extension_key"]
        observed[f"{ext_id}.{action_id}"] = {
            "input_payload": dict(input_payload or {}),
            "artifact_inputs": list(kwargs.get("artifact_inputs") or []),
            "artifact_outputs": list(kwargs.get("artifact_outputs") or []),
        }
        if ext_id == FILE_TRANSFER_EXTENSION_ID and action_id == "fetch_file":
            outputs = list(kwargs.get("artifact_outputs") or [])
            assert outputs
            assert outputs[0]["binding_key"] == "fetched_file"
            assert "body" not in input_payload
            assert "content" not in input_payload
            write_artifact_bytes(
                {"artifacts": {"outputs": outputs}},
                b"sku,qty\nA1,2\n",
                binding_key="fetched_file",
            )
            return {
                "status": "succeeded",
                "response": {"ok": True, "result": {"remote_path": "/feeds/inventory.csv"}},
            }
        raise AssertionError(f"unexpected action {ext_id}.{action_id}")

    fetch_result = harness.execute_connector_step(
        step={
            "step_kind": "connector",
            "connector_id": f"{FILE_TRANSFER_EXTENSION_ID}.fetch_file",
            "input_mapping_jsonb": {
                "path": "literal:/feeds/inventory.csv",
                "max_bytes": "literal:1024",
            },
            "output_mapping_jsonb": {"artifact_handle": "state.raw_feed_artifact"},
        },
        state=state,
        extensions={FILE_TRANSFER_EXTENSION_ID: _file_transfer_extension()},
        run_action=_run_action,
    )
    state.update(fetch_result.get("state_patch") or {})
    tabular_result = harness.execute_tabular_feed_step(
        step={
            "step_kind": "tabular_feed",
            "override": {
                "tabular_feed": {
                    "operation": "read",
                    "input": {"artifact_handle": "{{state.raw_feed_artifact}}"},
                    "key_column": "sku",
                    "result_target": "state.normalized_feed",
                }
            },
        },
        state=state,
    )

    assert fetch_result["ok"] is True
    assert fetch_result["grant_outputs"]["fetched_file"] == state["raw_feed_artifact"]
    assert state["raw_feed_artifact"].startswith("artifact:")
    assert isinstance(state["raw_feed_artifact"], str)
    assert tabular_result["ok"] is True
    assert tabular_result["result"]["dataset_handle"].startswith("dst_")
    serializable_state = {key: value for key, value in state.items() if key != "_artifact_plane"}
    assert json.dumps(serializable_state).find("sku,qty") == -1


def test_tabular_export_handle_flows_into_file_transfer_upload_without_body(tmp_path):
    harness = ExtensionWorkflowHarness(artifact_root=tmp_path / "artifact_store")
    dataset_handle, _ = harness.plane.create_dataset(
        owner_scope={"account_id": "acc_alpha", "project_id": "project_alpha"},
        run_id="run_export",
        step_id="step_read",
        schema={"columns": [{"name": "sku", "type": "text"}]},
        rows=[{"sku": "A1"}],
    )
    state = harness.initial_state(
        job_id="job_file_transfer_upload",
        workflow_id="wf.tabular.file-transfer",
        account_id="acc_alpha",
        project_id="project_alpha",
        normalized_feed=f"dataset:{dataset_handle.dataset_id}",
    )
    observed_upload: dict[str, object] = {}

    def _run_action(extension, action_id, input_payload, **kwargs):
        ext_id = extension["extension_key"]
        if ext_id == FILE_TRANSFER_EXTENSION_ID and action_id == "upload_file":
            inputs = list(kwargs.get("artifact_inputs") or [])
            assert inputs
            assert inputs[0]["binding_key"] == "source_artifact"
            assert inputs[0]["artifact_id"] == state["exported_feed"]["artifact_handle"]
            observed_upload["artifact_handle"] = inputs[0]["artifact_handle"]
            observed_upload["body"] = read_artifact_bytes(
                {"artifacts": {"inputs": inputs}},
                binding_key="source_artifact",
            )
            assert "body" not in input_payload
            assert input_payload["remote_path"] == "/exports/export.csv"
            return {
                "status": "succeeded",
                "response": {
                    "ok": True,
                    "result": {"uploaded": True, "remote_path": input_payload["remote_path"]},
                },
            }
        raise AssertionError(f"unexpected action {ext_id}.{action_id}")

    write_result = harness.execute_tabular_feed_step(
        step={
            "step_kind": "tabular_feed",
            "override": {
                "tabular_feed": {
                    "operation": "write",
                    "input": {"dataset_handle": "{{state.normalized_feed}}"},
                    "format": "csv",
                    "result_target": "state.exported_feed",
                }
            },
        },
        state=state,
    )
    state.update(write_result.get("state_patch") or {})
    upload_result = harness.execute_connector_step(
        step={
            "step_kind": "connector",
            "connector_id": f"{FILE_TRANSFER_EXTENSION_ID}.upload_file",
            "input_mapping_jsonb": {
                "artifact_handle": "state.exported_feed.artifact_handle",
                "remote_path": "literal:/exports/export.csv",
                "overwrite": "literal:true",
            },
        },
        state=state,
        extensions={FILE_TRANSFER_EXTENSION_ID: _file_transfer_extension()},
        run_action=_run_action,
    )

    assert write_result["ok"] is True
    assert state["exported_feed"]["artifact_handle"].startswith("art_")
    assert upload_result["ok"] is True
    assert (
        observed_upload["artifact_handle"]
        == f"artifact:{state['exported_feed']['artifact_handle']}"
    )
    assert observed_upload["body"] == b"sku\nA1\n"
    serializable_state = {key: value for key, value in state.items() if key != "_artifact_plane"}
    assert json.dumps(serializable_state).find("sku\nA1\n") == -1
