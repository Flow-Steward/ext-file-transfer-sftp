"""The connection form: each protocol sees only its own fields, secrets stay secret."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

BUNDLE_ROOT = Path(__file__).resolve().parents[1]


def _form() -> dict[str, Any]:
    return yaml.safe_load(
        (BUNDLE_ROOT / "ui/components/file_transfer_connection_form.yaml").read_text()
    )


def _visible(field: dict[str, Any], protocol: str) -> bool:
    for condition in field.get("visible_if", []):
        if "eq" in condition and condition["eq"] != protocol:
            return False
        if "in" in condition and protocol not in condition["in"]:
            return False
    return True


def _fields_for(protocol: str) -> dict[str, dict[str, Any]]:
    return {row["path"]: row for row in _form()["fields"] if _visible(row, protocol)}


def test_picker_offers_the_three_form_protocols():
    (picker,) = [row for row in _form()["fields"] if row["path"] == "protocol"]

    assert [option["value"] for option in picker["options"]] == ["sftp", "ftp", "s3"]
    assert set(_form()["data"]["connection_types"]) == {"sftp", "ftp", "s3"}


def test_s3_sees_no_ftp_or_sftp_secrets_and_keys_are_secret_widgets():
    fields = _fields_for("s3")

    assert not {"host", "port", "username", "password", "private_key"} & set(fields)
    for path in ("access_key_id", "secret_access_key", "session_token"):
        assert fields[path]["widget"] == "secret"
    assert fields["endpoint_url"]["required"] is True


def test_ftp_and_sftp_keep_their_fields_and_never_see_s3_keys():
    for protocol in ("ftp", "sftp"):
        fields = _fields_for(protocol)
        assert {"host", "port", "root_path", "username", "password"} <= set(fields)
        assert not {"endpoint_url", "bucket", "access_key_id", "secret_access_key"} & set(fields)
    assert "private_key" in _fields_for("sftp")
    assert "private_key" not in _fields_for("ftp")


def test_s3_variant_declares_config_and_secret_fields():
    variant = _form()["data"]["connection_types"]["s3"]

    assert variant["required_secret_fields"] == ["access_key_id", "secret_access_key"]
    assert set(variant["secret_fields"]) == {"access_key_id", "secret_access_key", "session_token"}
    assert "access_key_id" not in variant["config_fields"]


def test_host_key_confirmation_runs_only_for_sftp():
    (action,) = _form()["data"]["pre_save_actions"]

    assert action["action_id"] == "discover_host_key"
    assert {"path": "protocol", "eq": "sftp"} in action["run_when"]


def test_dropbox_is_connected_through_oauth_not_this_form():
    assert "dropbox" not in _form()["data"]["connection_types"]
    page = yaml.safe_load((BUNDLE_ROOT / "ui/pages/dropbox-setup.yaml").read_text())
    assert any(
        row.get("data", {}).get("oauth_intent") == "dropbox_connect" for row in page["components"]
    )
