"""Workflow composition through the real operation layer, for every connection type.

The SDK workflow harness provides real artifact grants; ``run_action`` hands
them to ``file_operations.handle_payload`` exactly as the host would, and each
connection type is backed by its fake (protocol client, TLS S3, Dropbox API).
Only handles cross the workflow state: file bodies never do.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from flowsteward_extension_sdk.testing import ExtensionWorkflowHarness

import file_operations as ops
import file_transfer_extension as ft
from connections import dropbox as dbx
from connections import s3
from tests._fake_s3 import ENDPOINT_HOST, SERVER_IP, FakeS3, write_certificates
from tests.test_dropbox_connection import FakeDropbox

EXTENSION_ID = "flowsteward.file-transfer"
FEED = b"sku,qty\nA1,2\nB2,5\n"


class MemoryClient:
    """An FTP/SFTP protocol client over a dict, for the protocol-client adapters."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files

    def __enter__(self) -> MemoryClient:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def list_dir(self, path):
        prefix = "" if path == "." else f"{path}/"
        entries = [
            ft.RemoteEntry(name=key[len(prefix) :], path=key, size_bytes=len(data))
            for key, data in sorted(self.files.items())
            if key.startswith(prefix) and "/" not in key[len(prefix) :]
        ]
        return entries, False

    def stat_file(self, path):
        if path not in self.files:
            raise ft.FileTransferError("not_found", "Remote file was not found")
        return ft.RemoteEntry(name=Path(path).name, path=path, size_bytes=len(self.files[path]))

    def stream_file(self, path):
        yield self.files[path]

    def upload_file(self, remote_path, chunks, *, overwrite):
        if not overwrite and remote_path in self.files:
            raise ft.FileTransferError("already_exists", "Remote path already exists")
        self.files[remote_path] = b"".join(chunks)
        return {
            "overwrite_protection": "best_effort",
            "remote_size_bytes": len(self.files[remote_path]),
        }


class Providers:
    """One fake backend per connection type, and the connection each step selects."""

    def __init__(self, s3_server: FakeS3, dropbox: FakeDropbox) -> None:
        self.s3 = s3_server
        self.dropbox = dropbox
        self.ftp_files: dict[str, bytes] = {}
        self.sftp_files: dict[str, bytes] = {}

    def connection(self, kind: str) -> dict[str, Any]:
        if kind == "s3":
            return {
                "connection_type_id": "s3",
                "config": {
                    "endpoint_url": f"https://{ENDPOINT_HOST}:{self.s3.port}",
                    "region": "us-east-1",
                    "bucket": "data",
                },
                "secrets": {"access_key_id": "AKIAEXPLICIT", "secret_access_key": "secret"},
            }
        if kind == "dropbox":
            return {
                "connection_type_id": "dropbox",
                "config": {"root_path": "."},
                "secrets": {"access_token": "tok-1"},
            }
        config: dict[str, Any] = {"host": f"{kind}.example.com", "root_path": ".", "use_tls": True}
        if kind == "sftp":
            config["host_key_fingerprint"] = "SHA256:" + "A" * 43
        return {
            "connection_type_id": kind,
            "config": config,
            "secrets": {"username": "user", "password": "secret"},
        }

    def put(self, kind: str, path: str, data: bytes) -> None:
        if kind == "s3":
            self.s3.objects[path] = data
        elif kind == "dropbox":
            self.dropbox.files[("tok-1", f"/{path}")] = data
        else:
            (self.ftp_files if kind == "ftp" else self.sftp_files)[path] = data

    def get(self, kind: str, path: str) -> bytes | None:
        if kind == "s3":
            return self.s3.objects.get(path)
        if kind == "dropbox":
            return self.dropbox.files.get(("tok-1", f"/{path}"))
        return (self.ftp_files if kind == "ftp" else self.sftp_files).get(path)


@pytest.fixture
def providers(tmp_path, monkeypatch) -> Iterator[Providers]:
    ca, cert, key = write_certificates(tmp_path, [ENDPOINT_HOST])
    monkeypatch.setenv("SSL_CERT_FILE", str(ca))
    monkeypatch.setattr(s3, "resolve_pinned_ips", lambda host, *, port, purpose: [SERVER_IP])
    server = FakeS3()
    server.start(cert, key)
    dropbox = FakeDropbox()
    dropbox.folders.add(("tok-1", "/out"))
    monkeypatch.setattr(dbx, "open_pinned_url", dropbox)
    backends = Providers(server, dropbox)
    monkeypatch.setattr(
        ft,
        "_client_for",
        lambda config: MemoryClient(
            backends.sftp_files if config.connection_type == "sftp" else backends.ftp_files
        ),
    )
    try:
        yield backends
    finally:
        server.stop()


def _extension() -> dict[str, Any]:
    return {
        "extension_key": EXTENSION_ID,
        "action_definitions": [{"action_id": "fetch_file"}, {"action_id": "upload_file"}],
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
                            "max_size_bytes": 1024 * 1024,
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
            ]
        },
    }


def _runner(
    providers: Providers, connections: dict[str, str], calls: list[dict[str, Any]]
) -> Callable[..., Any]:
    """The host side of an action: real grants in, the real operation layer, its envelope out."""

    def _run_action(extension, action_id, input_payload, **kwargs):
        payload = {
            "contract_version": "extension_host_v2",
            "runtime_context": {},
            "action": {
                "action_id": action_id,
                "target": {"connection": providers.connection(connections[action_id])},
                "input": dict(input_payload or {}),
            },
            "artifacts": {
                "inputs": list(kwargs.get("artifact_inputs") or []),
                "outputs": list(kwargs.get("artifact_outputs") or []),
            },
        }
        response = ops.handle_payload(payload)
        calls.append(
            {"action_id": action_id, "input": dict(input_payload or {}), "response": response}
        )
        return {"status": "succeeded" if response["ok"] else "failed", "response": response}

    return _run_action


def _fetch(harness, state, providers, kind, calls, path="feeds/inventory.csv"):
    return harness.execute_connector_step(
        step={
            "step_kind": "connector",
            "connector_id": f"{EXTENSION_ID}.fetch_file",
            "input_mapping_jsonb": {"path": f"literal:{path}"},
            "output_mapping_jsonb": {"artifact_handle": "state.raw_feed_artifact"},
        },
        state=state,
        extensions={EXTENSION_ID: _extension()},
        run_action=_runner(providers, {"fetch_file": kind}, calls),
    )


def _state(harness, name: str) -> dict[str, Any]:
    return harness.initial_state(
        job_id=f"job_{name}",
        workflow_id=f"wf.{name}",
        account_id="acc_alpha",
        project_id="project_alpha",
    )


def _no_body_in_state(state: dict[str, Any], body: bytes) -> None:
    serializable = {key: value for key, value in state.items() if key != "_artifact_plane"}
    assert body.decode() not in json.dumps(serializable)


@pytest.mark.parametrize("kind", ["ftp", "sftp", "s3", "dropbox"])
def test_fetch_flows_into_tabular_feed_for_every_connection_type(tmp_path, providers, kind):
    providers.put(kind, "feeds/inventory.csv", FEED)
    harness = ExtensionWorkflowHarness(artifact_root=tmp_path / "artifacts")
    state = _state(harness, f"{kind}_tabular")
    calls: list[dict[str, Any]] = []

    fetched = _fetch(harness, state, providers, kind, calls)
    state.update(fetched.get("state_patch") or {})
    table = harness.execute_tabular_feed_step(
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

    assert calls[0]["response"]["ok"] is True, calls[0]["response"]
    assert calls[0]["response"]["result"]["source_filename"] == "inventory.csv"
    assert fetched["ok"] is True
    assert table["ok"] is True
    assert table["result"]["dataset_handle"].startswith("dst_")
    _no_body_in_state(state, FEED)


@pytest.mark.parametrize(
    ("source", "target"), [("s3", "dropbox"), ("dropbox", "sftp"), ("sftp", "s3")]
)
def test_fetch_handle_uploads_across_connection_types(tmp_path, providers, source, target):
    providers.put(source, "feeds/inventory.csv", FEED)
    harness = ExtensionWorkflowHarness(artifact_root=tmp_path / "artifacts")
    state = _state(harness, f"{source}_to_{target}")
    calls: list[dict[str, Any]] = []

    fetched = _fetch(harness, state, providers, source, calls)
    state.update(fetched.get("state_patch") or {})
    uploaded = harness.execute_connector_step(
        step={
            "step_kind": "connector",
            "connector_id": f"{EXTENSION_ID}.upload_file",
            "input_mapping_jsonb": {
                "artifact_handle": "state.raw_feed_artifact",
                "remote_path": "literal:out/inventory.csv",
            },
        },
        state=state,
        extensions={EXTENSION_ID: _extension()},
        run_action=_runner(providers, {"upload_file": target}, calls),
    )

    assert [call["response"]["ok"] for call in calls] == [True, True], calls
    assert uploaded["ok"] is True
    assert providers.get(target, "out/inventory.csv") == FEED
    assert calls[1]["response"]["result"]["size_bytes"] == len(FEED)
    _no_body_in_state(state, FEED)


@pytest.mark.parametrize("kind", ["ftp", "sftp", "s3", "dropbox"])
def test_test_mode_upload_changes_nothing_for_every_connection_type(tmp_path, providers, kind):
    payload = {
        "contract_version": "extension_host_v2",
        "runtime_context": {"test_mode": True},
        "action": {
            "action_id": "upload_file",
            "target": {"connection": providers.connection(kind)},
            "input": {"artifact_handle": "art_in", "remote_path": "out/a.bin"},
        },
    }

    response = ops.handle_payload(payload)

    assert response["external_effect_status"] == "suppressed"
    assert providers.get(kind, "out/a.bin") is None
    assert providers.s3.seen == []
    assert providers.dropbox.calls == []
