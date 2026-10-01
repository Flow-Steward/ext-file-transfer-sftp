from __future__ import annotations

from flowsteward_extension_sdk.testing import (
    ERROR_MISSING_SPEC,
    IntegrationManifest,
    IntegrationOperation,
    resolve_integration_contract,
)


def _file_transfer_manifest() -> IntegrationManifest:
    return IntegrationManifest(
        manifest_id="flowsteward.file-transfer",
        service="file transfer",
        primitive_type="connector",
        semantic_roles=("file-transfer", "ftp", "ftps", "sftp"),
        supported_url_schemes=("ftp", "ftps", "sftp"),
        required_connection_roles=("ftp", "ftps", "sftp"),
        operations=(
            IntegrationOperation(
                operation_id="fetch_file",
                side_effect="read",
                required_inputs=("connection_ref", "path"),
                outputs=("artifact_handle",),
                accepted_connection_roles=("ftp", "ftps", "sftp"),
            ),
            IntegrationOperation(
                operation_id="inspect_local_config",
                side_effect="read",
                accepted_connection_roles=(),
            ),
        ),
    )


def test_ai_builder_http_url_requires_http_contract_not_file_transfer() -> None:
    result = resolve_integration_contract(
        service="external_service",
        requested_action="download supplier feed",
        integration_kind="rest",
        request_text="Download https://example.test/inventory.csv into an artifact.",
        manifests=[_file_transfer_manifest()],
    )

    assert result.decision == ERROR_MISSING_SPEC
    assert result.steps == []
    assert result.primitive_type == ""


def test_ai_builder_sftp_url_can_ground_file_transfer_fetch() -> None:
    result = resolve_integration_contract(
        service="file transfer",
        requested_action="fetch supplier feed",
        integration_kind="connector",
        request_text="Fetch sftp://supplier.example.com/incoming/inventory.csv into an artifact.",
        manifests=[_file_transfer_manifest()],
        selected_operation_id="fetch_file",
        available_connection_roles=["sftp"],
    )

    assert result.decision == "build"
    assert result.primitive_type == "connector"
    assert result.manifest_id == "flowsteward.file-transfer"
    assert [step.step_kind for step in result.steps] == ["connector"]
    assert [step.operation_id for step in result.steps] == ["fetch_file"]


def test_selected_connection_free_operation_does_not_inherit_manifest_roles() -> None:
    result = resolve_integration_contract(
        service="file transfer",
        requested_action="inspect local config",
        integration_kind="connector",
        request_text="Inspect local configuration",
        manifests=[_file_transfer_manifest()],
        selected_operation_id="inspect_local_config",
    )

    assert result.decision == "build"
    assert [step.step_kind for step in result.steps] == ["connector"]
    assert [step.operation_id for step in result.steps] == ["inspect_local_config"]
