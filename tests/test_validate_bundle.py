from __future__ import annotations

from scripts import validate_bundle


def _extension(**contract: object) -> dict[str, object]:
    return {"runtime": {"extension_contract_v2": contract}}


def test_inline_oauth_provider_is_not_a_file_reference():
    extension = _extension(
        connection_types="contracts/connection_types.yaml",
        oauth_providers=[
            {
                "provider_id": "dropbox_oauth",
                "flow": {"type": "authorization_code", "pkce": "s256"},
                "token_endpoint": {"url": "https://api.dropboxapi.com/oauth2/token"},
            }
        ],
    )

    assert validate_bundle._referenced_paths(extension) == ["contracts/connection_types.yaml"]


def test_missing_contract_file_is_still_reported(monkeypatch, tmp_path):
    (tmp_path / "extension.yaml").write_text(
        "manifest_version: 2\n"
        "extension_id: flowsteward.file-transfer\n"
        "version: 0.0.0\n"
        "kind: tool_provider\n"
        "runtime:\n"
        "  extension_contract_v2:\n"
        "    connection_types: contracts/missing.yaml\n"
        "    oauth_providers: [{provider_id: dropbox_oauth}]\n"
    )
    monkeypatch.setattr(validate_bundle, "BUNDLE_ROOT", tmp_path)
    errors: list[str] = []

    extension = validate_bundle._load_yaml("extension.yaml", errors)
    missing = [
        path
        for path in validate_bundle._referenced_paths(extension)
        if not (tmp_path / path).is_file()
    ]

    assert errors == []
    assert missing == ["contracts/missing.yaml"]
