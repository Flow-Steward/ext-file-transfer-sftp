"""The Dropbox OAuth declaration: one fixed grant, Core-owned tokens, no extra reach."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

BUNDLE_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SCOPES = ["files.metadata.read", "files.content.read", "files.content.write"]


def _yaml(rel: str) -> Any:
    return yaml.safe_load((BUNDLE_ROOT / rel).read_text())


def _provider() -> dict[str, Any]:
    providers = _yaml("extension.yaml")["runtime"]["extension_contract_v2"]["oauth_providers"]
    assert [row["provider_id"] for row in providers] == ["dropbox_oauth"]
    return providers[0]


def _dropbox_type() -> dict[str, Any]:
    rows = _yaml("contracts/connection_types.yaml")["connection_types"]
    (row,) = [row for row in rows if row["connection_type_id"] == "dropbox"]
    return row


def test_provider_uses_fixed_dropbox_endpoints_with_pkce():
    provider = _provider()

    assert provider["flow"] == {"type": "authorization_code", "pkce": "s256"}
    assert provider["authorization_endpoint"] == {"url": "https://www.dropbox.com/oauth2/authorize"}
    assert provider["token_endpoint"] == {
        "url": "https://api.dropboxapi.com/oauth2/token",
        "client_auth_method": "client_secret_post",
    }
    # Core's generic revocation is an RFC 7009 form; Dropbox revokes with a Bearer call.
    assert "revocation_endpoint" not in provider
    assert provider["callback_id"] == "oauth_authorization"


def test_one_intent_with_offline_access_and_no_scope_parameter():
    (intent,) = _provider()["authorization_intents"]

    assert intent["intent_id"] == "dropbox_connect"
    assert intent["static_parameters"] == {"token_access_type": "offline"}
    assert "user_inputs" not in intent


def test_app_secret_is_an_encrypted_credential():
    fields = {row["field_id"]: row for row in _provider()["credential_fields"]}

    assert set(fields) == {"client_id", "client_secret"}
    assert fields["client_secret"]["secret"] is True
    assert fields["client_secret"]["value_type"] == "secret"
    assert fields["client_secret"]["required"] is True
    assert "browser_exposable" not in fields["client_secret"]


def test_connection_requests_exactly_the_three_file_scopes():
    auth = _dropbox_type()["auth"]

    assert auth == {
        "type": "oauth2",
        "provider_id": "dropbox_oauth",
        "scopes": {"required": REQUIRED_SCOPES, "optional": []},
    }


def test_runtime_receives_only_an_access_token():
    secret_schema = _dropbox_type()["secret_schema"]

    assert set(secret_schema["properties"]) == {"access_token"}
    assert secret_schema["additionalProperties"] is False


def test_oauth_callback_is_declared_and_not_connection_scoped():
    callbacks = _yaml("extension.yaml")["callbacks"]

    assert callbacks == [
        {
            "callback_id": "oauth_authorization",
            "purpose": "oauth_authorization",
            "methods": ["GET"],
            "connection_scoped": False,
        }
    ]


def test_app_setup_and_account_connect_share_one_dropbox_page():
    # Core renders the app configuration and the account Connect form together
    # when the provider's setup_page_id itself declares the connection form.
    provider = _provider()
    page = _yaml("ui/pages/dropbox.yaml")
    (form,) = [row for row in page["components"] if row["type"] == "connection_form"]
    anchors = {row["anchor_id"] for row in page["components"] if "anchor_id" in row}

    assert page["page_id"] == provider["setup_page_id"] == provider["help_page_id"] == "dropbox"
    assert form["data"] == {
        "oauth_provider_id": "dropbox_oauth",
        "connection_type": "dropbox",
        "oauth_intent": "dropbox_connect",
    }
    assert set(provider["error_help_anchors"].values()) <= anchors
    manifest = (BUNDLE_ROOT / "ui/ui_manifest.yaml").read_text()
    assert "ref: pages/dropbox.yaml" in manifest
    assert "dropbox-setup" not in manifest
    assert not (BUNDLE_ROOT / "ui/pages/dropbox-setup.yaml").exists()
