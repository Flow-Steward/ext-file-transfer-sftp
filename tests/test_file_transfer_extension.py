from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

import file_transfer_extension as ft
import health as ft_health


def _fingerprint(blob: bytes = b"server-key") -> str:
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _attach_fake_ftp(client: ft.FTPClient, fake_ftp: Any) -> None:
    client._ftp = cast(Any, fake_ftp)


def _payload(
    operation: str,
    input_payload: dict,
    *,
    connection_type: str = "ftp",
    config: dict | None = None,
    secrets: dict | None = None,
    runtime_context: dict | None = None,
) -> dict:
    base_config = {
        "host": "files.example.com",
        "port": 21 if connection_type == "ftp" else 22,
        "root_path": ".",
        "use_tls": True,
    }
    if connection_type == "sftp":
        base_config["host_key_fingerprint"] = _fingerprint()
    base_config.update(config or {})
    base_secrets = {"username": "user", "password": "secret"}
    base_secrets.update(secrets or {})
    payload = {
        "contract_version": "extension_host_v1",
        "runtime_context": runtime_context or {},
        "action": {
            "action_id": operation,
            "target": {
                "connection": {
                    "connection_type_id": connection_type,
                    "config": base_config,
                    "secrets": base_secrets,
                }
            },
            "input": input_payload,
        },
    }
    artifact_handle = input_payload.get("artifact_handle")
    if artifact_handle:
        payload["artifacts"] = {
            "inputs": [
                {
                    "artifact_id": artifact_handle,
                    "artifact_handle": artifact_handle,
                    "binding_key": "source_artifact",
                    "size_bytes": input_payload.get("_artifact_size_bytes", 4),
                    "access": {"download_url": "file:///dev/null"},
                }
            ]
        }
    return payload


class FakeClient:
    def __init__(self, entries=None, body=b"payload") -> None:
        self.entries = entries or []
        self.body = body
        self.uploads: list[tuple[str, bytes, bool]] = []
        self.existing: set[str] = set()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def list_dir(self, path):
        return list(self.entries), False

    def stream_file(self, path):
        yield self.body

    def stat_file(self, path):
        if path in self.existing:
            return ft.RemoteEntry(name=Path(path).name, path=path, size_bytes=len(self.body))
        return ft.RemoteEntry(name=Path(path).name, path=path, size_bytes=len(self.body))

    def upload_file(self, remote_path, chunks, *, overwrite):
        payload = b"".join(chunks)
        if not overwrite and remote_path in self.existing:
            raise ft.FileTransferError(
                "already_exists",
                "Remote path already exists",
                external_effect_status="failed",
                definitely_no_external_effect=True,
            )
        self.uploads.append((remote_path, payload, overwrite))
        return {"overwrite_protection": "best_effort"}


def test_manifest_scope_contract_has_no_http_or_artifact_write():
    import yaml

    bundle_root = Path(__file__).resolve().parents[1]
    manifest = yaml.safe_load((bundle_root / "extension.yaml").read_text())
    actions = yaml.safe_load((bundle_root / "ui/actions/actions.yaml").read_text())["actions"]
    page = yaml.safe_load((bundle_root / "ui/pages/overview.yaml").read_text())
    assert manifest["extension_id"] == "flowsteward.file-transfer"
    assert manifest["kind"] == "tool_provider"
    assert set(manifest["features"]) == {"tool", "action"}
    assert set(manifest["supported_url_schemes"]) == {"ftp", "ftps", "sftp"}
    assert manifest["required_scopes"] == ["extension:invoke", "artifact:read"]
    assert {row["action_id"] for row in actions} >= {
        "discover_host_key",
        "test_connection",
        "list_files",
        "fetch_file",
        "upload_file",
    }
    assert "../components/file_transfer_connection_form.yaml" in {
        row["ref"] for row in page["components"]
    }
    text = (bundle_root / "contracts/connection_types.yaml").read_text()
    assert "http" not in text.lower()
    assert "artifact:write" not in str(manifest)
    assert any(row["name"] == "paramiko" for row in manifest["python_requirements"])
    assert (bundle_root / "wheels" / "paramiko-5.0.0-py3-none-any.whl").is_file()


def test_health_reports_missing_dependency(monkeypatch):
    def fake_find_spec(module_name):
        if module_name == "paramiko":
            return None
        return object()

    monkeypatch.setattr(ft_health.importlib.util, "find_spec", fake_find_spec)
    monkeypatch.setattr(
        ft_health.importlib.metadata,
        "version",
        lambda package_name: f"{package_name}-version",
    )

    payload = ft_health.check_health()

    assert payload["ok"] is False
    assert payload["status"] == "unhealthy"
    assert payload["error_code"] == "dependency_unavailable"
    assert payload["missing_dependencies"] == ["paramiko"]


def test_ui_action_error_codes_match_operation_manifest():
    import yaml

    bundle_root = Path(__file__).resolve().parents[1]
    actions = yaml.safe_load((bundle_root / "ui/actions/actions.yaml").read_text())["actions"]
    operations = yaml.safe_load((bundle_root / "contracts/operation_manifest.yaml").read_text())[
        "operations"
    ]

    action_codes = {row["action_id"]: set(row.get("error_codes") or []) for row in actions}
    operation_codes = {row["operation_id"]: set(row.get("error_codes") or []) for row in operations}

    for operation_id in {
        "discover_host_key",
        "test_connection",
        "list_files",
        "fetch_file",
        "upload_file",
    }:
        assert action_codes[operation_id] == operation_codes[operation_id]


def test_connection_forms_publish_expected_secret_fields():
    import yaml

    bundle_root = Path(__file__).resolve().parents[1]
    form = yaml.safe_load(
        (bundle_root / "ui/components/file_transfer_connection_form.yaml").read_text()
    )

    assert form["type"] == "connection_form"
    assert form["data"]["connection_type_field"] == "protocol"
    variants = form["data"]["connection_types"]
    ftp_form = variants["ftp"]
    sftp_form = variants["sftp"]
    assert ftp_form["connection_type"] == "ftp"
    assert set(ftp_form["secret_fields"]) == {"username", "password"}
    assert sftp_form["connection_type"] == "sftp"
    assert {"host_key_fingerprint", "connect_timeout_seconds"} <= set(sftp_form["config_fields"])
    assert {"username", "password", "private_key", "private_key_passphrase"} <= set(
        sftp_form["secret_fields"]
    )
    assert form["data"]["test_action"] == "test_connection"
    pre_save_action = form["data"]["pre_save_actions"][0]
    assert pre_save_action["action_id"] == "discover_host_key"
    assert pre_save_action["result_mapping"] == {
        "host_key_fingerprint": "result.host_key_fingerprint"
    }
    assert set(pre_save_action["target_connection"]["config_fields"]) == {
        "host",
        "port",
        "connect_timeout_seconds",
        "read_timeout_seconds",
    }
    assert "host_key_fingerprint" not in {row["path"] for row in form["fields"]}
    protocol_field = next(row for row in form["fields"] if row["path"] == "protocol")
    assert {row["value"] for row in protocol_field["options"]} == {"ftp", "sftp"}
    private_key_field = next(row for row in form["fields"] if row["path"] == "private_key")
    assert private_key_field["widget"] == "textarea"
    assert private_key_field["visible_if"] == [{"path": "protocol", "eq": "sftp"}]
    schema = yaml.safe_load((bundle_root / "contracts/connection_types.yaml").read_text())
    sftp_schema = next(
        row for row in schema["connection_types"] if row["connection_type_id"] == "sftp"
    )["secret_schema"]
    password_branch = sftp_schema["oneOf"][0]
    assert {"required": ["private_key_passphrase"]} in password_branch["not"]["anyOf"]


def test_plaintext_ftp_requires_explicit_acknowledgement_before_network(monkeypatch):
    resolve = MagicMock(side_effect=AssertionError("network resolution must not run"))
    monkeypatch.setattr(ft, "resolve_pinned_ips", resolve)

    response = ft.handle_payload(
        _payload(
            "list_files",
            {"path": "."},
            config={"use_tls": False, "allow_insecure_ftp": False},
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "insecure_ftp_not_acknowledged"
    resolve.assert_not_called()


def test_ftp_command_fields_reject_crlf_before_network(monkeypatch):
    resolve = MagicMock(side_effect=AssertionError("network resolution must not run"))
    monkeypatch.setattr(ft, "resolve_pinned_ips", resolve)

    response = ft.handle_payload(
        _payload(
            "list_files",
            {"path": "."},
            config={"root_path": ".\r\nDELE important.csv"},
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "invalid_connection"
    resolve.assert_not_called()


def test_connection_numeric_fields_are_strict_before_network(monkeypatch):
    resolve = MagicMock(side_effect=AssertionError("network resolution must not run"))
    monkeypatch.setattr(ft, "resolve_pinned_ips", resolve)

    bad_port = ft.handle_payload(
        _payload("list_files", {"path": "."}, config={"port": "not-a-port"})
    )
    bad_timeout = ft.handle_payload(
        _payload("list_files", {"path": "."}, config={"connect_timeout_seconds": "NaN"})
    )

    assert bad_port["ok"] is False
    assert bad_port["error_code"] == "invalid_connection"
    assert bad_timeout["ok"] is False
    assert bad_timeout["error_code"] == "invalid_connection"
    resolve.assert_not_called()


def test_connection_accepts_host_runtime_connection_type_shape(monkeypatch):
    client_for = MagicMock(return_value=FakeClient())
    monkeypatch.setattr(ft, "_client_for", client_for)
    payload = _payload("test_connection", {}, connection_type="sftp")
    connection = payload["action"]["target"]["connection"]
    connection["connection_type"] = connection.pop("connection_type_id")

    response = ft.handle_payload(payload)

    assert response["ok"] is True
    assert response["result"]["protocol"] == "sftp"
    assert client_for.call_args.args[0].connection_type == "sftp"


def test_payload_numeric_fields_are_strict_before_network(monkeypatch):
    client_for = MagicMock(side_effect=AssertionError("protocol should not run"))
    monkeypatch.setattr(ft, "_client_for", client_for)

    bad_limit = ft.handle_payload(_payload("list_files", {"path": ".", "limit": "abc"}))
    bad_max = ft.handle_payload(_payload("fetch_file", {"path": "in.csv", "max_bytes": "abc"}))

    assert bad_limit["ok"] is False
    assert bad_limit["error_code"] == "invalid_payload"
    assert bad_max["ok"] is False
    assert bad_max["error_code"] == "invalid_payload"
    client_for.assert_not_called()


def test_sftp_rejects_password_with_private_key_passphrase_before_network(monkeypatch):
    monkeypatch.setattr(
        ft.socket, "create_connection", MagicMock(side_effect=AssertionError("no socket"))
    )

    response = ft.handle_payload(
        _payload(
            "list_files",
            {"path": "."},
            connection_type="sftp",
            secrets={"password": "secret", "private_key": "", "private_key_passphrase": "ignored"},
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "invalid_connection"


def test_errors_redact_secret_echo_from_malicious_server(monkeypatch):
    class EchoClient(FakeClient):
        def list_dir(self, path):
            raise RuntimeError("530 password secret rejected")

    monkeypatch.setattr(ft, "_client_for", lambda _config: EchoClient())

    response = ft.handle_payload(_payload("list_files", {"path": "."}))

    assert response["ok"] is False
    assert "secret" not in response["error"]
    assert "[redacted]" in response["error"]


def test_errors_redact_short_secret_echo_from_malicious_server(monkeypatch):
    class EchoClient(FakeClient):
        def list_dir(self, path):
            raise RuntimeError("530 password xy rejected")

    monkeypatch.setattr(ft, "_client_for", lambda _config: EchoClient())

    response = ft.handle_payload(_payload("list_files", {"path": "."}, secrets={"password": "xy"}))

    assert response["ok"] is False
    assert "xy" not in response["error"]
    assert "[redacted]" in response["error"]


def test_private_target_block_happens_before_secret_use(monkeypatch):
    def _blocked(*args, **kwargs):
        raise ft.PinnedPeerError("blocked")

    monkeypatch.setattr(ft, "resolve_pinned_ips", _blocked)
    response = ft.handle_payload(_payload("list_files", {"path": "."}))

    assert response["ok"] is False
    assert response["error_code"] == "network_blocked"
    assert response["definitely_no_external_effect"] is True


def test_list_files_caps_raw_entries_and_filters_glob(monkeypatch):
    entries = [ft.RemoteEntry(name=f"{idx:03d}.csv", path=f"{idx:03d}.csv") for idx in range(3)]
    fake = FakeClient(entries=entries)
    monkeypatch.setattr(ft, "_client_for", lambda _config: fake)

    response = ft.handle_payload(
        _payload("list_files", {"path": ".", "name_glob": "*.csv", "limit": 2})
    )

    assert response["ok"] is True
    assert [row["name"] for row in response["result"]["files"]] == ["000.csv", "001.csv"]
    assert response["result"]["truncated"] is True


def test_list_files_requires_path_before_network(monkeypatch):
    client_for = MagicMock(side_effect=AssertionError("protocol should not run"))
    monkeypatch.setattr(ft, "_client_for", client_for)

    response = ft.handle_payload(_payload("list_files", {}))

    assert response["ok"] is False
    assert response["error_code"] == "invalid_payload"
    client_for.assert_not_called()


def test_fetch_glob_selects_latest_modified_and_writes_fixed_artifact(monkeypatch):
    entries = [
        ft.RemoteEntry(
            name="a.csv", path="in/a.csv", raw_modified=10, modified_at="2026-01-01T00:00:00Z"
        ),
        ft.RemoteEntry(
            name="b.csv", path="in/b.csv", raw_modified=10, modified_at="2026-01-01T00:00:00Z"
        ),
    ]
    fake = FakeClient(entries=entries, body=b"abc")
    monkeypatch.setattr(ft, "_client_for", lambda _config: fake)
    written: list[bytes] = []

    def _write(_payload, chunks, **_kwargs):
        written.append(b"".join(chunks))
        return {
            "artifact_handle": "art_out",
            "size_bytes": 3,
            "sha256": hashlib.sha256(b"abc").hexdigest(),
        }

    write = MagicMock(side_effect=_write)
    monkeypatch.setattr(ft, "write_artifact_stream", write)

    response = ft.handle_payload(
        _payload(
            "fetch_file",
            {"path": "in", "name_glob": "*.csv", "select": "latest_modified"},
        )
    )

    assert response["ok"] is True
    assert response["result"]["remote_path"] == "in/b.csv"
    assert response["result"]["artifact_filename"] == "download.bin"
    assert response["result"]["source_filename"] == "b.csv"
    assert written == [b"abc"]
    assert write.call_args.kwargs["binding_key"] == "fetched_file"


def test_fetch_rejects_directory_entry_501_before_selection(monkeypatch):
    class TooLargeClient(FakeClient):
        def list_dir(self, path):
            return [], True

    monkeypatch.setattr(ft, "_client_for", lambda _config: TooLargeClient())

    response = ft.handle_payload(_payload("fetch_file", {"path": "in", "name_glob": "*.csv"}))

    assert response["ok"] is False
    assert response["error_code"] == "directory_too_large"


def test_fetch_enforces_streaming_cap_without_successful_artifact(monkeypatch):
    fake = FakeClient(body=b"abcdef")
    monkeypatch.setattr(ft, "_client_for", lambda _config: fake)

    def _consume(_payload, chunks, **_kwargs):
        list(chunks)
        return {"artifact_handle": "art_out"}

    monkeypatch.setattr(ft, "write_artifact_stream", _consume)
    response = ft.handle_payload(_payload("fetch_file", {"path": "file.bin", "max_bytes": 3}))

    assert response["ok"] is False
    assert response["error_code"] == "max_bytes_exceeded"


def test_transfer_limit_uses_shared_operator_artifact_policy(monkeypatch):
    configured = 2 * 1024 * 1024 * 1024
    monkeypatch.setenv("FS_EXTENSION_ARTIFACT_MAX_BYTES", str(configured))

    assert ft._effective_max_bytes({}) == configured
    assert ft._effective_max_bytes({"max_bytes": 1024 * 1024}) == 1024 * 1024
    assert ft._effective_max_bytes({}, descriptor_limit=3 * 1024 * 1024) == 3 * 1024 * 1024


def test_fetch_exact_path_checks_metadata_before_streaming(monkeypatch):
    class MissingClient(FakeClient):
        def stat_file(self, path):
            raise ft.FileTransferError("not_found", "missing")

        def stream_file(self, path):
            raise AssertionError("body should not stream")
            yield b""

    write = MagicMock(side_effect=AssertionError("artifact write should not start"))
    monkeypatch.setattr(ft, "_client_for", lambda _config: MissingClient())
    monkeypatch.setattr(ft, "write_artifact_stream", write)

    response = ft.handle_payload(_payload("fetch_file", {"path": "missing.csv"}))

    assert response["ok"] is False
    assert response["error_code"] == "not_found"
    write.assert_not_called()


def test_fetch_uses_output_grant_access_size_limit_before_streaming(monkeypatch):
    class LargeClient(FakeClient):
        def stat_file(self, path):
            return ft.RemoteEntry(name="large.csv", path=path, size_bytes=8)

        def stream_file(self, path):
            raise AssertionError("body should not stream")
            yield b""

    payload = _payload("fetch_file", {"path": "large.csv", "max_bytes": 100})
    payload["artifacts"] = {
        "outputs": [
            {
                "artifact_id": "art_out",
                "artifact_handle": "artifact:art_out",
                "binding_key": "fetched_file",
                "access": {"max_size_bytes": 4, "upload_url": "https://example.test/upload"},
            }
        ]
    }
    monkeypatch.setattr(ft, "_client_for", lambda _config: LargeClient())
    monkeypatch.setattr(
        ft, "write_artifact_stream", MagicMock(side_effect=AssertionError("no write"))
    )

    response = ft.handle_payload(payload)

    assert response["ok"] is False
    assert response["error_code"] == "max_bytes_exceeded"


def test_fetch_rejects_unfinalized_or_empty_artifact_result(monkeypatch):
    fake = FakeClient(body=b"abc")
    monkeypatch.setattr(ft, "_client_for", lambda _config: fake)
    monkeypatch.setattr(ft, "write_artifact_stream", MagicMock(return_value={"finalized": False}))

    response = ft.handle_payload(_payload("fetch_file", {"path": "file.bin"}))

    assert response["ok"] is False
    assert response["error_code"] == "artifact_write_failed"


def test_fetch_accepts_public_sdk_artifact_write_result_without_finalized(monkeypatch):
    fake = FakeClient(body=b"abc")
    monkeypatch.setattr(ft, "_client_for", lambda _config: fake)

    def _write(_payload, chunks, **_kwargs):
        body = b"".join(chunks)
        return {
            "artifact_handle": "art_out",
            "size_bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }

    monkeypatch.setattr(ft, "write_artifact_stream", _write)
    response = ft.handle_payload(_payload("fetch_file", {"path": "file.bin"}))

    assert response["ok"] is True
    assert response["result"]["artifact_handle"] == "art_out"


def test_fetch_requires_complete_artifact_write_result(monkeypatch):
    fake = FakeClient(body=b"abc")
    monkeypatch.setattr(ft, "_client_for", lambda _config: fake)

    for result in (
        {
            "artifact_handle": "art_out",
            "sha256": hashlib.sha256(b"abc").hexdigest(),
            "finalized": True,
        },
        {"artifact_handle": "art_out", "size_bytes": 3, "finalized": True},
        {
            "artifact_handle": "art_out",
            "size_bytes": 3,
            "sha256": hashlib.sha256(b"abc").hexdigest(),
            "finalized": False,
        },
    ):
        monkeypatch.setattr(ft, "write_artifact_stream", MagicMock(return_value=result))
        response = ft.handle_payload(_payload("fetch_file", {"path": "file.bin"}))

        assert response["ok"] is False
        assert response["error_code"] == "artifact_write_failed"


def test_upload_test_mode_suppresses_before_network_or_artifact(monkeypatch):
    monkeypatch.setattr(ft, "_client_for", MagicMock(side_effect=AssertionError("no network")))
    monkeypatch.setattr(
        ft, "stream_artifact_bytes", MagicMock(side_effect=AssertionError("no read"))
    )

    response = ft.handle_payload(
        _payload(
            "upload_file",
            {"artifact_handle": "art_1", "remote_path": "out.csv"},
            runtime_context={"test_mode": True},
        )
    )

    assert response["ok"] is True
    assert response["external_effect_status"] == "suppressed"


def test_malformed_test_mode_is_rejected_before_connection_validation(monkeypatch):
    monkeypatch.setattr(ft, "_client_for", MagicMock(side_effect=AssertionError("no network")))
    response = ft.handle_payload(
        {
            "runtime_context": {"test_mode": "definitely"},
            "action": {
                "action_id": "upload_file",
                "input": {"artifact_handle": "art_1", "remote_path": "out.csv"},
                "target": {
                    "connection": {"connection_type_id": "ftp", "config": {}, "secrets": {}}
                },
            },
        }
    )

    assert response["ok"] is False
    assert response["error_code"] == "invalid_payload"


def test_upload_test_mode_suppresses_before_connection_validation(monkeypatch):
    monkeypatch.setattr(ft, "_client_for", MagicMock(side_effect=AssertionError("no network")))
    monkeypatch.setattr(
        ft, "stream_artifact_bytes", MagicMock(side_effect=AssertionError("no read"))
    )

    response = ft.handle_payload(
        {
            "runtime_context": {"test_mode": True},
            "action": {
                "action_id": "upload_file",
                "input": {"artifact_handle": "art_1", "remote_path": "out.csv"},
                "target": {
                    "connection": {"connection_type_id": "ftp", "config": {}, "secrets": {}}
                },
            },
        }
    )

    assert response["ok"] is True
    assert response["external_effect_status"] == "suppressed"


def test_secret_values_preserve_leading_and_trailing_whitespace():
    config = ft._connection_config(
        _payload(
            "list_files",
            {"path": "."},
            secrets={"username": " user ", "password": " secret ", "private_key_passphrase": ""},
        )
    )

    assert config.username == "user"
    assert config.password == " secret "


def test_non_object_payload_returns_structured_invalid_payload():
    response = ft.handle_payload(cast(Any, []))

    assert response["ok"] is False
    assert response["error_code"] == "invalid_payload"
    assert response["definitely_no_external_effect"] is True


def test_main_rejects_non_object_json_without_traceback():
    bundle_root = Path(__file__).resolve().parents[1]
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(
            item
            for item in [
                str(bundle_root),
                os.environ.get("PYTHONPATH", ""),
            ]
            if item
        ),
    }
    result = subprocess.run(
        [sys.executable, str(bundle_root / "main.py")],
        input="[]",
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )

    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error_code"] == "invalid_payload"


def test_upload_streams_artifact_and_reports_best_effort_overwrite(monkeypatch):
    fake = FakeClient()
    monkeypatch.setattr(ft, "_client_for", lambda _config: fake)
    monkeypatch.setattr(ft, "stream_artifact_bytes", lambda *args, **kwargs: iter([b"ab", b"cd"]))

    response = ft.handle_payload(
        _payload("upload_file", {"artifact_handle": "art_1", "remote_path": "out.csv"})
    )

    assert response["ok"] is True
    assert response["external_effect_status"] == "succeeded"
    assert fake.uploads == [("out.csv", b"abcd", False)]
    assert response["result"]["overwrite_protection"] == "best_effort"


def test_upload_known_collision_preserves_no_effect(monkeypatch):
    fake = FakeClient()
    fake.existing.add("out.csv")
    monkeypatch.setattr(ft, "_client_for", lambda _config: fake)
    monkeypatch.setattr(ft, "stream_artifact_bytes", lambda *args, **kwargs: iter([b"ab"]))

    response = ft.handle_payload(
        _payload("upload_file", {"artifact_handle": "art_1", "remote_path": "out.csv"})
    )

    assert response["ok"] is False
    assert response["error_code"] == "already_exists"
    assert response["definitely_no_external_effect"] is True
    assert fake.uploads == []


def test_upload_rejects_artifact_metadata_size_before_network(monkeypatch):
    client_for = MagicMock(side_effect=AssertionError("remote connection should not start"))
    stream = MagicMock(side_effect=AssertionError("artifact body should not stream"))
    monkeypatch.setattr(ft, "_client_for", client_for)
    monkeypatch.setattr(ft, "stream_artifact_bytes", stream)

    response = ft.handle_payload(
        _payload(
            "upload_file",
            {
                "artifact_handle": "art_1",
                "remote_path": "out.csv",
                "max_bytes": 3,
                "_artifact_size_bytes": 4,
            },
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "max_bytes_exceeded"
    client_for.assert_not_called()
    stream.assert_not_called()


def test_upload_rejects_input_grant_access_limit_before_network(monkeypatch):
    client_for = MagicMock(side_effect=AssertionError("remote connection should not start"))
    stream = MagicMock(side_effect=AssertionError("artifact body should not stream"))
    monkeypatch.setattr(ft, "_client_for", client_for)
    monkeypatch.setattr(ft, "stream_artifact_bytes", stream)
    payload = _payload(
        "upload_file",
        {"artifact_handle": "art_1", "remote_path": "out.csv", "_artifact_size_bytes": 4},
    )
    payload["artifacts"]["inputs"][0]["access"]["max_size_bytes"] = 3

    response = ft.handle_payload(payload)

    assert response["ok"] is False
    assert response["error_code"] == "max_bytes_exceeded"
    client_for.assert_not_called()
    stream.assert_not_called()


def test_ftp_upload_midstream_limit_reports_unknown_effect():
    class FakeFTP:
        def __init__(self) -> None:
            self.deleted: list[str] = []

        def storbinary(self, command, reader, blocksize):
            assert command.startswith("STOR ")
            while reader.read(1):
                pass

        def delete(self, path):
            self.deleted.append(path)

    config = ft.ConnectionConfig(
        connection_type="ftp",
        host="files.example.com",
        port=21,
        root_path=".",
        use_tls=True,
        allow_insecure_ftp=False,
        host_key_fingerprint="",
        connect_timeout=1,
        read_timeout=1,
        username="user",
        password="secret",
        private_key="",
        private_key_passphrase="",
    )
    client = ft.FTPClient(config)
    fake_ftp = FakeFTP()
    _attach_fake_ftp(client, fake_ftp)
    chunks, _state = ft._hashing_chunks([b"ab", b"cd"], max_bytes=3)

    try:
        client.upload_file("out.csv", chunks, overwrite=True)
    except ft.FileTransferError as exc:
        assert exc.code == "max_bytes_exceeded"
        assert exc.external_effect_status == "timeout_unknown"
        assert exc.definitely_no_external_effect is False
    else:
        raise AssertionError("upload should fail after the temp mutation starts")
    assert fake_ftp.deleted


def test_path_validation_rejects_empty_segments_without_protocol_calls(monkeypatch):
    client_for = MagicMock(side_effect=AssertionError("protocol should not run"))
    monkeypatch.setattr(ft, "_client_for", client_for)

    response = ft.handle_payload(_payload("fetch_file", {"path": "foo//bar"}))

    assert response["ok"] is False
    assert response["error_code"] == "invalid_path"
    client_for.assert_not_called()


def test_path_validation_rejects_escape_without_protocol_calls(monkeypatch):
    client_for = MagicMock(side_effect=AssertionError("protocol should not run"))
    monkeypatch.setattr(ft, "_client_for", client_for)

    response = ft.handle_payload(_payload("fetch_file", {"path": "../escape.csv"}))

    assert response["ok"] is False
    assert response["error_code"] == "invalid_path"
    client_for.assert_not_called()


def test_sftp_rejects_malformed_fingerprint_before_network(monkeypatch):
    monkeypatch.setattr(
        ft.socket, "create_connection", MagicMock(side_effect=AssertionError("no socket"))
    )

    response = ft.handle_payload(
        _payload(
            "list_files",
            {"path": "."},
            connection_type="sftp",
            config={"host_key_fingerprint": "bad"},
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "invalid_host_key_fingerprint"


def test_sftp_rejects_short_fingerprint_digest_before_network(monkeypatch):
    monkeypatch.setattr(
        ft.socket, "create_connection", MagicMock(side_effect=AssertionError("no socket"))
    )
    short_digest = base64.b64encode(b"too-short").decode("ascii").rstrip("=")

    response = ft.handle_payload(
        _payload(
            "list_files",
            {"path": "."},
            connection_type="sftp",
            config={"host_key_fingerprint": f"SHA256:{short_digest}"},
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "invalid_host_key_fingerprint"


def test_sftp_host_key_discovery_does_not_authenticate(monkeypatch):
    calls: list[str] = []
    transport_kwargs = {}
    key_blob = b"discovered-server-key"

    class FakeKey:
        def get_name(self):
            return "ssh-ed25519"

        def asbytes(self):
            return key_blob

    class FakeTransport:
        host_key_type = "ssh-ed25519"

        def __init__(self, sock, **kwargs):
            transport_kwargs.update(kwargs)
            calls.append("transport")

        def get_security_options(self):
            calls.append("security_options")
            return SimpleNamespace(key_types=("ssh-ed25519", "ssh-rsa"))

        def start_client(self, timeout=None):
            calls.append(f"start_client:{timeout}")

        def get_remote_server_key(self):
            calls.append("get_remote_server_key")
            return FakeKey()

        def auth_password(self, *args, **kwargs):
            raise AssertionError("discovery must not authenticate")

        def auth_publickey(self, *args, **kwargs):
            raise AssertionError("discovery must not authenticate")

        def close(self):
            calls.append("transport_close")

    monkeypatch.setitem(sys.modules, "paramiko", SimpleNamespace(Transport=FakeTransport))
    monkeypatch.setattr(ft, "resolve_pinned_ips", lambda *args, **kwargs: ["203.0.113.10"])
    monkeypatch.setattr(
        ft.socket,
        "create_connection",
        lambda *args, **kwargs: SimpleNamespace(
            getpeername=lambda: ("203.0.113.10", 22),
            settimeout=lambda _timeout: None,
            close=lambda: calls.append("socket_close"),
        ),
    )

    response = ft.handle_payload(
        {
            "contract_version": "extension_host_v1",
            "action": {
                "action_id": "discover_host_key",
                "target": {
                    "connection": {
                        "connection_type_id": "sftp",
                        "config": {"host": "files.example.com", "port": 22},
                    }
                },
                "input": {},
            },
        }
    )

    assert response == {
        "ok": True,
        "result": {
            "protocol": "sftp",
            "host_key_type": "ssh-ed25519",
            "host_key_fingerprint": _fingerprint(key_blob),
        },
    }
    assert transport_kwargs == {"disabled_algorithms": {"pubkeys": ["ssh-rsa"]}}
    assert calls == [
        "transport",
        "security_options",
        "start_client:15",
        "get_remote_server_key",
        "transport_close",
        "socket_close",
    ]


def test_socket_peer_mismatch_is_blocked():
    sock = SimpleNamespace(getpeername=lambda: ("198.51.100.99", 22))

    try:
        ft._verify_socket_peer(sock, "203.0.113.10", purpose="SFTP socket")
    except ft.FileTransferError as exc:
        assert exc.code == "network_blocked"
    else:
        raise AssertionError("peer mismatch must be blocked")


def test_sftp_verifies_host_key_before_auth(monkeypatch):
    calls: list[str] = []
    transport_kwargs = {}
    key_blob = b"server-key"

    class FakeKey:
        def get_name(self):
            return "ssh-ed25519"

        def asbytes(self):
            calls.append("host_key_read")
            return key_blob

    class FakeTransport:
        def __init__(self, sock, **kwargs):
            transport_kwargs.update(kwargs)
            calls.append("transport")

        def start_client(self, timeout=None):
            calls.append("start_client")

        def get_remote_server_key(self):
            calls.append("get_remote_server_key")
            return FakeKey()

        def auth_password(self, username, password, *, fallback=True):
            assert fallback is False
            calls.append("auth_password")

        def is_authenticated(self):
            return True

        def close(self):
            calls.append("transport_close")

        def get_security_options(self):
            return SimpleNamespace(key_types=("ssh-rsa", "ssh-ed25519"))

    class FakeSFTP:
        @classmethod
        def from_transport(cls, transport):
            calls.append("from_transport")
            return cls()

        def normalize(self, path):
            return "/root"

        def stat(self, path):
            return SimpleNamespace(st_mode=ft.stat.S_IFDIR)

        def listdir_attr(self, path):
            calls.append("listdir_attr")
            return []

        def close(self):
            calls.append("sftp_close")

    fake_paramiko = SimpleNamespace(Transport=FakeTransport, SFTPClient=FakeSFTP)
    monkeypatch.setitem(sys.modules, "paramiko", fake_paramiko)
    monkeypatch.setattr(ft, "resolve_pinned_ips", lambda *args, **kwargs: ["203.0.113.10"])
    monkeypatch.setattr(
        ft.socket,
        "create_connection",
        lambda *args, **kwargs: SimpleNamespace(
            getpeername=lambda: ("203.0.113.10", 22),
            settimeout=lambda _timeout: None,
            close=lambda: None,
        ),
    )

    response = ft.handle_payload(
        _payload(
            "list_files",
            {"path": "."},
            connection_type="sftp",
            secrets={"password": "secret", "private_key": ""},
        )
    )

    assert response["ok"] is True
    assert transport_kwargs == {"disabled_algorithms": {"pubkeys": ["ssh-rsa"]}}
    assert calls.index("get_remote_server_key") < calls.index("auth_password")
    assert "listdir_attr" in calls


def test_sftp_authentication_exception_is_authentication_failed(monkeypatch):
    class FakeAuthError(Exception):
        pass

    class FakeKey:
        def get_name(self):
            return "ssh-ed25519"

        def asbytes(self):
            return b"server-key"

    class FakeTransport:
        def __init__(self, sock, **kwargs):
            pass

        def start_client(self, timeout=None):
            pass

        def get_remote_server_key(self):
            return FakeKey()

        def auth_password(self, username, password, *, fallback=True):
            raise FakeAuthError("bad password")

        def close(self):
            pass

        def get_security_options(self):
            return SimpleNamespace(key_types=("ssh-rsa", "ssh-ed25519"))

    fake_paramiko = SimpleNamespace(
        Transport=FakeTransport,
        AuthenticationException=FakeAuthError,
    )
    monkeypatch.setitem(sys.modules, "paramiko", fake_paramiko)
    monkeypatch.setattr(ft, "resolve_pinned_ips", lambda *args, **kwargs: ["203.0.113.10"])
    monkeypatch.setattr(
        ft.socket,
        "create_connection",
        lambda *args, **kwargs: SimpleNamespace(
            getpeername=lambda: ("203.0.113.10", 22),
            settimeout=lambda _timeout: None,
            close=lambda: None,
        ),
    )

    response = ft.handle_payload(
        _payload(
            "list_files",
            {"path": "."},
            connection_type="sftp",
            secrets={"password": "secret", "private_key": ""},
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "authentication_failed"
    assert response["external_effect_status"] == "failed"
    assert response["definitely_no_external_effect"] is True


def test_sftp_allows_rsa_sha2_negotiated_host_key(monkeypatch):
    key_blob = b"rsa-server-key"

    class FakeKey:
        def get_name(self):
            return "ssh-rsa"

        def asbytes(self):
            return key_blob

    class FakeTransport:
        host_key_type = "rsa-sha2-512"

        def __init__(self, sock, **kwargs):
            pass

        def start_client(self, timeout=None):
            pass

        def get_remote_server_key(self):
            return FakeKey()

        def auth_password(self, username, password, *, fallback=True):
            assert fallback is False

        def is_authenticated(self):
            return True

        def close(self):
            pass

        def get_security_options(self):
            return SimpleNamespace(key_types=("ssh-rsa", "rsa-sha2-512", "ssh-ed25519"))

    class FakeSFTP:
        @classmethod
        def from_transport(cls, transport):
            return cls()

        def normalize(self, path):
            return "/root"

        def stat(self, path):
            return SimpleNamespace(st_mode=ft.stat.S_IFDIR)

        def listdir_attr(self, path):
            return []

        def close(self):
            pass

    fake_paramiko = SimpleNamespace(Transport=FakeTransport, SFTPClient=FakeSFTP)
    monkeypatch.setitem(sys.modules, "paramiko", fake_paramiko)
    monkeypatch.setattr(ft, "resolve_pinned_ips", lambda *args, **kwargs: ["203.0.113.10"])
    monkeypatch.setattr(
        ft.socket,
        "create_connection",
        lambda *args, **kwargs: SimpleNamespace(
            getpeername=lambda: ("203.0.113.10", 22),
            settimeout=lambda _timeout: None,
            close=lambda: None,
        ),
    )

    response = ft.handle_payload(
        _payload(
            "list_files",
            {"path": "."},
            connection_type="sftp",
            config={"host_key_fingerprint": _fingerprint(key_blob)},
            secrets={"password": "secret", "private_key": ""},
        )
    )

    assert response["ok"] is True


def test_sftp_rejects_mismatched_host_key_before_auth(monkeypatch):
    calls: list[str] = []

    class FakeKey:
        def get_name(self):
            return "ssh-ed25519"

        def asbytes(self):
            return b"other-key"

    class FakeTransport:
        def __init__(self, sock, **kwargs):
            pass

        def start_client(self, timeout=None):
            pass

        def get_remote_server_key(self):
            return FakeKey()

        def auth_password(self, username, password, *, fallback=True):
            assert fallback is False
            calls.append("auth_password")

        def close(self):
            pass

        def get_security_options(self):
            return SimpleNamespace(key_types=("ssh-rsa", "ssh-ed25519"))

    fake_paramiko = SimpleNamespace(Transport=FakeTransport)
    monkeypatch.setitem(sys.modules, "paramiko", fake_paramiko)
    monkeypatch.setattr(ft, "resolve_pinned_ips", lambda *args, **kwargs: ["203.0.113.10"])
    monkeypatch.setattr(
        ft.socket,
        "create_connection",
        lambda *args, **kwargs: SimpleNamespace(
            getpeername=lambda: ("203.0.113.10", 22),
            settimeout=lambda _timeout: None,
            close=lambda: None,
        ),
    )

    response = ft.handle_payload(_payload("list_files", {"path": "."}, connection_type="sftp"))

    assert response["ok"] is False
    assert response["error_code"] == "host_key_mismatch"
    assert calls == []


def test_sftp_connect_failure_closes_socket_and_transport(monkeypatch):
    closed: list[str] = []

    class FakeSock:
        def getpeername(self):
            return ("203.0.113.10", 22)

        def settimeout(self, timeout):
            pass

        def close(self):
            closed.append("sock")

    class FakeKey:
        def get_name(self):
            return "ssh-ed25519"

        def asbytes(self):
            return b"other-key"

    class FakeTransport:
        host_key_type = "ssh-ed25519"

        def __init__(self, sock, **kwargs):
            pass

        def get_security_options(self):
            return SimpleNamespace(key_types=("ssh-ed25519",))

        def start_client(self, timeout=None):
            pass

        def get_remote_server_key(self):
            return FakeKey()

        def close(self):
            closed.append("transport")

    monkeypatch.setitem(sys.modules, "paramiko", SimpleNamespace(Transport=FakeTransport))
    monkeypatch.setattr(ft, "resolve_pinned_ips", lambda *args, **kwargs: ["203.0.113.10"])
    monkeypatch.setattr(ft.socket, "create_connection", lambda *args, **kwargs: FakeSock())

    response = ft.handle_payload(_payload("list_files", {"path": "."}, connection_type="sftp"))

    assert response["ok"] is False
    assert response["error_code"] == "host_key_mismatch"
    assert closed == ["transport", "sock"]


def test_ftp_nlst_fallback_stops_callback_at_entry_501():
    class FakeFTP:
        def __init__(self):
            self.commands: list[str] = []

        def retrlines(self, command, callback):
            if command.startswith("MLSD"):
                raise ft.error_perm("500 MLSD unavailable")
            for idx in range(10_000):
                callback(f"{idx:05d}.csv")

        def voidcmd(self, command):
            self.commands.append(command)

        def size(self, path):
            assert self.commands[-1] == "TYPE I"
            return 1

    client = ft.FTPClient(
        ft.ConnectionConfig(
            connection_type="ftp",
            host="files.example.com",
            port=21,
            root_path=".",
            use_tls=False,
            allow_insecure_ftp=True,
            host_key_fingerprint="",
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    fake_ftp = FakeFTP()
    _attach_fake_ftp(client, fake_ftp)

    entries, truncated = client.list_dir(".")

    assert len(entries) == 500
    assert truncated is True
    assert "TYPE I" in fake_ftp.commands


def test_ftp_mlsd_stops_callback_at_entry_501():
    class FakeFTP:
        def retrlines(self, command, callback):
            assert command.startswith("MLSD")
            for idx in range(10_000):
                callback(f"type=file;size=1;modify=20260101000000; {idx:05d}.csv")

    client = ft.FTPClient(
        ft.ConnectionConfig(
            connection_type="ftp",
            host="files.example.com",
            port=21,
            root_path=".",
            use_tls=False,
            allow_insecure_ftp=True,
            host_key_fingerprint="",
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    _attach_fake_ftp(client, FakeFTP())

    entries, truncated = client.list_dir(".")

    assert len(entries) == 500
    assert truncated is True


def test_sftp_uses_iterative_listing_and_stops_at_entry_501():
    class Attr:
        def __init__(self, filename):
            self.filename = filename
            self.st_mode = 0
            self.st_size = 1
            self.st_mtime = 1

    class FakeSFTP:
        def normalize(self, path):
            return "/root"

        def listdir_iter(self, path, read_aheads=1):
            for idx in range(10_000):
                yield Attr(f"{idx:05d}.csv")

    client = ft.SFTPClient(
        ft.ConnectionConfig(
            connection_type="sftp",
            host="files.example.com",
            port=22,
            root_path=".",
            use_tls=True,
            allow_insecure_ftp=False,
            host_key_fingerprint=_fingerprint(),
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    client._sftp = FakeSFTP()
    client._root = "/root"

    entries, truncated = client.list_dir(".")

    assert len(entries) == 500
    assert truncated is True


def test_sftp_normalize_error_fails_closed():
    class FakeSFTP:
        def normalize(self, path):
            raise OSError("temporary metadata failure")

    client = ft.SFTPClient(
        ft.ConnectionConfig(
            connection_type="sftp",
            host="files.example.com",
            port=22,
            root_path=".",
            use_tls=True,
            allow_insecure_ftp=False,
            host_key_fingerprint=_fingerprint(),
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    client._sftp = FakeSFTP()
    client._root = "/root"

    try:
        list(client.stream_file("file.csv"))
    except ft.FileTransferError as exc:
        assert exc.code == "invalid_path"
    else:
        raise AssertionError("normalize failure must not fail open")


def test_sftp_uses_canonical_path_for_open_after_validation():
    opened: list[str] = []

    class FakeHandle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def read(self, size):
            return b""

    class FakeSFTP:
        def normalize(self, path):
            if path == "/root/link/file.csv":
                return "/root/real/file.csv"
            return path

        def open(self, path, mode):
            opened.append(path)
            return FakeHandle()

    client = ft.SFTPClient(
        ft.ConnectionConfig(
            connection_type="sftp",
            host="files.example.com",
            port=22,
            root_path=".",
            use_tls=True,
            allow_insecure_ftp=False,
            host_key_fingerprint=_fingerprint(),
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    client._sftp = FakeSFTP()
    client._root = "/root"

    assert list(client.stream_file("link/file.csv")) == []
    assert opened == ["/root/real/file.csv"]


def test_sftp_root_path_must_be_existing_directory():
    class FakeSFTP:
        def normalize(self, path):
            return "/root-file"

        def stat(self, path):
            return SimpleNamespace(st_mode=ft.stat.S_IFREG)

    client = ft.SFTPClient(
        ft.ConnectionConfig(
            connection_type="sftp",
            host="files.example.com",
            port=22,
            root_path=".",
            use_tls=True,
            allow_insecure_ftp=False,
            host_key_fingerprint=_fingerprint(),
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    client._sftp = FakeSFTP()

    try:
        client._canonical_root(".")
    except ft.FileTransferError as exc:
        assert exc.code == "invalid_connection"
    else:
        raise AssertionError("SFTP root file must not be accepted as a directory")


def test_upload_metadata_timeout_does_not_mutate_destination(monkeypatch):
    class UnknownMetadataClient(FakeClient):
        def upload_file(self, remote_path, chunks, *, overwrite):
            raise ft.FileTransferError(
                "metadata_unknown",
                "Could not verify destination state",
                external_effect_status="failed",
                definitely_no_external_effect=True,
            )

    fake = UnknownMetadataClient()
    monkeypatch.setattr(ft, "_client_for", lambda _config: fake)
    monkeypatch.setattr(ft, "stream_artifact_bytes", lambda *args, **kwargs: iter([b"ab"]))

    response = ft.handle_payload(
        _payload("upload_file", {"artifact_handle": "art_1", "remote_path": "out.csv"})
    )

    assert response["ok"] is False
    assert response["error_code"] == "metadata_unknown"
    assert response["definitely_no_external_effect"] is True
    assert fake.uploads == []


def test_ftp_550_does_not_mean_absent_for_overwrite_probe():
    class FakeFTP:
        def voidcmd(self, command):
            assert command == "TYPE I"

        def size(self, path):
            raise ft.error_perm("550 permission denied")

    client = ft.FTPClient(
        ft.ConnectionConfig(
            connection_type="ftp",
            host="files.example.com",
            port=21,
            root_path=".",
            use_tls=False,
            allow_insecure_ftp=True,
            host_key_fingerprint="",
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    _attach_fake_ftp(client, FakeFTP())

    try:
        client.upload_file("out.csv", [b"body"], overwrite=False)
    except ft.FileTransferError as exc:
        assert exc.code == "metadata_unknown"
        assert exc.definitely_no_external_effect is True
    else:
        raise AssertionError("FTP 550 must not be treated as absent")


def test_ftp_missing_destination_is_free_for_overwrite_probe():
    class FakeFTP:
        def __init__(self):
            self.commands: list[str] = []

        def voidcmd(self, command):
            self.commands.append(command)

        def size(self, path):
            assert self.commands[-1] == "TYPE I"
            raise ft.error_perm("550 No such file or directory")

    client = ft.FTPClient(
        ft.ConnectionConfig(
            connection_type="ftp",
            host="files.example.com",
            port=21,
            root_path=".",
            use_tls=False,
            allow_insecure_ftp=True,
            host_key_fingerprint="",
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    fake_ftp = FakeFTP()
    _attach_fake_ftp(client, fake_ftp)

    assert client._remote_exists("new.csv") is False
    assert fake_ftp.commands == ["TYPE I"]


def test_ftp_login_530_is_authentication_failed(monkeypatch):
    class FakeFTP:
        sock = None

        def __init__(self, **_kwargs):
            pass

        def connect(self, host, port, timeout=None):
            pass

        def login(self, username, password):
            raise ft.error_perm("530 Login incorrect")

        def set_pasv(self, value):
            pass

        def close(self):
            pass

    monkeypatch.setattr(ft, "resolve_pinned_ips", lambda *args, **kwargs: ["203.0.113.10"])
    monkeypatch.setattr(ft, "_PinnedFTP", FakeFTP)

    config = ft.ConnectionConfig(
        connection_type="ftp",
        host="files.example.com",
        port=21,
        root_path=".",
        use_tls=False,
        allow_insecure_ftp=True,
        host_key_fingerprint="",
        connect_timeout=15,
        read_timeout=30,
        username="user",
        password="wrong",
        private_key="",
        private_key_passphrase="",
    )

    try:
        with ft.FTPClient(config):
            pass
    except ft.FileTransferError as exc:
        assert exc.code == "authentication_failed"
        assert exc.external_effect_status == "failed"
        assert exc.definitely_no_external_effect is True
    else:
        raise AssertionError("FTP 530 must map to authentication_failed")


def test_ftps_enters_private_data_mode_after_login(monkeypatch):
    calls: list[str] = []

    class FakeFTPTLS(ft.FTP_TLS):
        sock = None

        def __init__(self, **_kwargs):
            pass

        def connect(
            self,
            host: str = "",
            port: int = 0,
            timeout: float = 0.0,
            source_address: tuple[str, int] | None = None,
        ) -> str:
            calls.append("connect")
            return "connected"

        def auth(self):
            calls.append("auth")

        def login(
            self,
            user: str = "",
            passwd: str = "",
            acct: str = "",
            secure: bool = True,
        ) -> str:
            calls.append("login")
            return "logged in"

        def prot_p(self):
            calls.append("prot_p")

        def set_pasv(self, value):
            calls.append("set_pasv")

        def cwd(self, path):
            calls.append("cwd")

        def pwd(self):
            return "/"

        def close(self):
            calls.append("close")

        def quit(self):
            calls.append("quit")

    monkeypatch.setattr(ft, "resolve_pinned_ips", lambda *args, **kwargs: ["203.0.113.10"])
    monkeypatch.setattr(ft, "_PinnedFTPTLS", FakeFTPTLS)

    config = ft.ConnectionConfig(
        connection_type="ftp",
        host="files.example.com",
        port=21,
        root_path=".",
        use_tls=True,
        allow_insecure_ftp=False,
        host_key_fingerprint="",
        connect_timeout=15,
        read_timeout=30,
        username="user",
        password="password",
        private_key="",
        private_key_passphrase="",
    )

    with ft.FTPClient(config):
        pass

    assert calls[:5] == ["connect", "auth", "login", "prot_p", "set_pasv"]


def test_ftp_exact_fetch_maps_missing_550_to_not_found():
    class FakeFTP:
        def __init__(self):
            self.commands: list[str] = []

        def voidcmd(self, command):
            self.commands.append(command)

        def size(self, path):
            assert self.commands[-1] == "TYPE I"
            raise ft.error_perm("550 No such file or directory")

    client = ft.FTPClient(
        ft.ConnectionConfig(
            connection_type="ftp",
            host="files.example.com",
            port=21,
            root_path=".",
            use_tls=False,
            allow_insecure_ftp=True,
            host_key_fingerprint="",
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    fake_ftp = FakeFTP()
    _attach_fake_ftp(client, fake_ftp)

    try:
        client.stat_file("missing.csv")
    except ft.FileTransferError as exc:
        assert exc.code == "not_found"
    else:
        raise AssertionError("missing FTP 550 should be not_found")


def test_ftp_stream_file_switches_to_binary_type():
    calls: list[str] = []

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def settimeout(self, timeout):
            calls.append(f"timeout:{timeout}")

        def recv(self, size):
            return b""

    class FakeFTP:
        def voidcmd(self, command):
            calls.append(command)

        def transfercmd(self, command):
            calls.append(command)
            return FakeConn()

        def voidresp(self):
            calls.append("voidresp")

    client = ft.FTPClient(
        ft.ConnectionConfig(
            connection_type="ftp",
            host="files.example.com",
            port=21,
            root_path=".",
            use_tls=False,
            allow_insecure_ftp=True,
            host_key_fingerprint="",
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    _attach_fake_ftp(client, FakeFTP())

    assert list(client.stream_file("file.bin")) == []
    assert calls[0] == "TYPE I"


def test_ftp_stream_file_revalidates_path_before_retr():
    class FakeFTP:
        def voidcmd(self, command):
            raise AssertionError("TYPE I should not run for invalid paths")

        def transfercmd(self, command):
            raise AssertionError("RETR should not run for invalid paths")

    client = ft.FTPClient(
        ft.ConnectionConfig(
            connection_type="ftp",
            host="files.example.com",
            port=21,
            root_path=".",
            use_tls=False,
            allow_insecure_ftp=True,
            host_key_fingerprint="",
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    _attach_fake_ftp(client, FakeFTP())

    try:
        list(client.stream_file("foo//bar.csv"))
    except ft.FileTransferError as exc:
        assert exc.code == "invalid_path"
    else:
        raise AssertionError("FTP stream_file must revalidate path before RETR")


def test_ftp_upload_verifies_final_size_after_rename():
    class FakeFTP:
        def __init__(self):
            self.renamed = False
            self.commands: list[str] = []

        def voidcmd(self, command):
            self.commands.append(command)

        def size(self, path):
            assert self.commands[-1] == "TYPE I"
            if path == "out.csv" and self.renamed:
                return 2
            raise ft.error_perm("550 missing")

        def storbinary(self, command, fp, blocksize=8192):
            while fp.read(blocksize):
                pass

        def rename(self, source, dest):
            self.renamed = True

        def delete(self, path):
            pass

    client = ft.FTPClient(
        ft.ConnectionConfig(
            connection_type="ftp",
            host="files.example.com",
            port=21,
            root_path=".",
            use_tls=False,
            allow_insecure_ftp=True,
            host_key_fingerprint="",
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    _attach_fake_ftp(client, FakeFTP())

    try:
        client.upload_file("out.csv", [b"abcd"], overwrite=True)
    except ft.FileTransferError as exc:
        assert exc.code == "transfer_failed"
        assert exc.definitely_no_external_effect is False
    else:
        raise AssertionError("final size mismatch must fail")


def test_ftp_upload_requires_confirmed_final_size_after_rename():
    class FakeFTP:
        def __init__(self):
            self.commands: list[str] = []

        def voidcmd(self, command):
            self.commands.append(command)

        def storbinary(self, command, fp, blocksize=8192):
            while fp.read(blocksize):
                pass

        def rename(self, source, dest):
            pass

        def size(self, path):
            assert self.commands[-1] == "TYPE I"

        def delete(self, path):
            pass

    client = ft.FTPClient(
        ft.ConnectionConfig(
            connection_type="ftp",
            host="files.example.com",
            port=21,
            root_path=".",
            use_tls=False,
            allow_insecure_ftp=True,
            host_key_fingerprint="",
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    _attach_fake_ftp(client, FakeFTP())

    try:
        client.upload_file("out.csv", [b"body"], overwrite=True)
    except ft.FileTransferError as exc:
        assert exc.code == "metadata_unknown"
        assert exc.external_effect_status == "timeout_unknown"
        assert exc.definitely_no_external_effect is False
    else:
        raise AssertionError("unknown final size must fail")


def test_ftp_upload_failure_after_stor_started_is_possible_external_effect():
    class FakeFTP:
        def size(self, path):
            raise ft.error_perm("550 permission denied")

        def storbinary(self, command, fp, blocksize=8192):
            raise OSError("server accepted STOR then failed before data")

        def delete(self, path):
            pass

    client = ft.FTPClient(
        ft.ConnectionConfig(
            connection_type="ftp",
            host="files.example.com",
            port=21,
            root_path=".",
            use_tls=False,
            allow_insecure_ftp=True,
            host_key_fingerprint="",
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    _attach_fake_ftp(client, FakeFTP())

    try:
        client.upload_file("out.csv", [b"body"], overwrite=True)
    except ft.FileTransferError as exc:
        assert exc.external_effect_status == "timeout_unknown"
        assert exc.definitely_no_external_effect is False
    else:
        raise AssertionError("STOR failure must fail")


def test_upload_lazy_artifact_read_error_reports_artifact_read_failed(monkeypatch):
    def _broken_stream(*args, **kwargs):
        def _iter():
            yield b"ok"
            raise ft.ArtifactAccessError("grant expired")

        return _iter()

    fake = FakeClient()
    monkeypatch.setattr(ft, "_client_for", lambda _config: fake)
    monkeypatch.setattr(ft, "stream_artifact_bytes", _broken_stream)

    response = ft.handle_payload(
        _payload("upload_file", {"artifact_handle": "art_1", "remote_path": "out.csv"})
    )

    assert response["ok"] is False
    assert response["error_code"] == "artifact_read_failed"


def test_sftp_overwrite_existing_destination_uses_posix_rename():
    class FakeHandle:
        def __init__(self, sftp, path):
            self._sftp = sftp
            self._path = path

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def write(self, chunk):
            self._sftp.files[self._path] = self._sftp.files.get(self._path, b"") + chunk

        def flush(self):
            pass

    class FakeSFTP:
        def __init__(self):
            self.files = {"/root/out.csv": b"old"}
            self.posix_renamed = []

        def normalize(self, path):
            return path if path.startswith("/") else f"/root/{path}".replace("/./", "/")

        def stat(self, path):
            if path not in self.files:
                raise FileNotFoundError(path)
            return SimpleNamespace(st_size=len(self.files[path]))

        def open(self, path, mode):
            assert mode == "xb"
            return FakeHandle(self, path)

        def rename(self, source, dest):
            raise AssertionError("regular rename must not overwrite an existing SFTP file")

        def posix_rename(self, source, dest):
            self.files[dest] = self.files.pop(source)
            self.posix_renamed.append((source, dest))

        def remove(self, path):
            self.files.pop(path, None)

    client = ft.SFTPClient(
        ft.ConnectionConfig(
            connection_type="sftp",
            host="files.example.com",
            port=22,
            root_path=".",
            use_tls=True,
            allow_insecure_ftp=False,
            host_key_fingerprint=_fingerprint(),
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    fake = FakeSFTP()
    client._sftp = fake
    client._root = "/root"

    result = client.upload_file("out.csv", [b"body"], overwrite=True)

    assert result["remote_size_bytes"] == 4
    assert fake.files["/root/out.csv"] == b"body"
    assert fake.posix_renamed[0][1] == "/root/out.csv"


def test_sftp_overwrite_existing_destination_unsupported_posix_rename_is_unknown_effect():
    class FakeHandle:
        def __init__(self, sftp, path):
            self._sftp = sftp
            self._path = path

        def __enter__(self):
            self._sftp.opened.append(self._path)
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def write(self, chunk):
            self._sftp.files[self._path] = self._sftp.files.get(self._path, b"") + chunk

        def flush(self):
            pass

    class FakeSFTP:
        def __init__(self):
            self.files = {"/root/out.csv": b"old"}
            self.opened = []
            self.removed = []

        def normalize(self, path):
            return path if path.startswith("/") else f"/root/{path}".replace("/./", "/")

        def stat(self, path):
            if path in self.files:
                return SimpleNamespace(st_size=len(self.files[path]))
            raise FileNotFoundError(path)

        def open(self, path, mode):
            assert mode == "xb"
            return FakeHandle(self, path)

        def posix_rename(self, source, dest):
            raise OSError("Operation unsupported")

        def remove(self, path):
            self.removed.append(path)
            self.files.pop(path, None)

    client = ft.SFTPClient(
        ft.ConnectionConfig(
            connection_type="sftp",
            host="files.example.com",
            port=22,
            root_path=".",
            use_tls=True,
            allow_insecure_ftp=False,
            host_key_fingerprint=_fingerprint(),
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    fake = FakeSFTP()
    client._sftp = fake
    client._root = "/root"

    try:
        client.upload_file("out.csv", [b"body"], overwrite=True)
    except ft.FileTransferError as exc:
        assert exc.code == "not_supported_by_server"
        assert exc.external_effect_status == "timeout_unknown"
        assert exc.definitely_no_external_effect is False
        assert fake.opened
        assert fake.removed == fake.opened
        assert fake.files["/root/out.csv"] == b"old"
    else:
        raise AssertionError("unsupported SFTP posix_rename must fail")


def test_sftp_upload_requires_confirmed_final_size_after_rename():
    class FakeHandle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def write(self, chunk):
            pass

        def flush(self):
            pass

    class FakeSFTP:
        def __init__(self):
            self.renamed = False

        def normalize(self, path):
            return path if path.startswith("/") else f"/root/{path}".replace("/./", "/")

        def open(self, path, mode):
            return FakeHandle()

        def rename(self, source, dest):
            self.renamed = True

        def stat(self, path):
            if path == "/root/out.csv" and not self.renamed:
                raise FileNotFoundError(path)
            return SimpleNamespace(st_size=None)

        def remove(self, path):
            pass

    client = ft.SFTPClient(
        ft.ConnectionConfig(
            connection_type="sftp",
            host="files.example.com",
            port=22,
            root_path=".",
            use_tls=True,
            allow_insecure_ftp=False,
            host_key_fingerprint=_fingerprint(),
            connect_timeout=15,
            read_timeout=30,
            username="user",
            password="password",
            private_key="",
            private_key_passphrase="",
        )
    )
    client._sftp = FakeSFTP()
    client._root = "/root"

    try:
        client.upload_file("out.csv", [b"body"], overwrite=True)
    except ft.FileTransferError as exc:
        assert exc.code == "metadata_unknown"
        assert exc.external_effect_status == "timeout_unknown"
        assert exc.definitely_no_external_effect is False
    else:
        raise AssertionError("unknown SFTP final size must fail")


# ---------------------------------------------------------------------------
# The connection root is referenced one documented way
# ---------------------------------------------------------------------------


def test_list_files_accepts_the_connection_root(monkeypatch):
    entries = [ft.RemoteEntry(name="DistFeed.csv", path="DistFeed.csv", size_bytes=3)]
    monkeypatch.setattr(ft, "_client_for", lambda _config: FakeClient(entries=entries))

    response = ft.handle_payload(_payload("list_files", {"path": "."}))

    assert response["ok"] is True
    assert [item["name"] for item in response["result"]["files"]] == ["DistFeed.csv"]


def test_fetch_file_accepts_the_connection_root_as_the_glob_directory(monkeypatch):
    """`.` is the connection root for both operations, not just for list_files.

    `path` was validated with `allow_empty=True` for `list_files` and
    `allow_empty=False` for `fetch_file`, so the root the one operation accepted
    the other rejected with "Path must not contain dot segments" — and a glob
    against the connection root was impossible.
    """
    entries = [ft.RemoteEntry(name="DistFeed.csv", path="DistFeed.csv", size_bytes=3)]
    fake = FakeClient(entries=entries, body=b"abc")
    monkeypatch.setattr(ft, "_client_for", lambda _config: fake)

    def _write(_payload, chunks, **_kwargs):
        body = b"".join(chunks)
        return {
            "artifact_handle": "art_out",
            "size_bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }

    monkeypatch.setattr(ft, "write_artifact_stream", _write)

    response = ft.handle_payload(_payload("fetch_file", {"path": ".", "name_glob": "*.csv"}))

    assert response["ok"] is True, response
    assert response["result"]["remote_path"] == "DistFeed.csv"


def test_fetch_file_without_a_glob_still_requires_a_file_path(monkeypatch):
    """Without a glob, `path` names a file, so the root is not a usable value."""
    monkeypatch.setattr(ft, "_client_for", lambda _config: FakeClient())

    response = ft.handle_payload(_payload("fetch_file", {"path": "."}))

    assert response["ok"] is False
    assert response["error_code"] == "invalid_path"
    assert "name_glob" in response["error"], response["error"]


@pytest.mark.parametrize(
    "path",
    ["../secrets.csv", "/etc/passwd", "in/../../out.csv", "in\\out.csv", "in/./out.csv"],
)
def test_traversal_protection_is_unchanged(monkeypatch, path):
    monkeypatch.setattr(ft, "_client_for", lambda _config: FakeClient())

    for operation, extra in (("list_files", {}), ("fetch_file", {"name_glob": "*.csv"})):
        response = ft.handle_payload(_payload(operation, {"path": path, **extra}))
        assert response["ok"] is False, (operation, path)
        assert response["error_code"] == "invalid_path"
