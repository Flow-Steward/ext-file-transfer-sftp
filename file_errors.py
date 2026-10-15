"""Safe errors shared by every file connection and the common operation layer."""

from __future__ import annotations

from typing import Any


class FileTransferError(ValueError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        external_effect_status: str | None = None,
        definitely_no_external_effect: bool = True,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.external_effect_status = external_effect_status
        self.definitely_no_external_effect = definitely_no_external_effect


def unknown_outcome(code: str, message: str) -> FileTransferError:
    """A failure after a remote mutation may have committed: never report it as no effect."""
    return FileTransferError(
        code,
        message,
        external_effect_status="timeout_unknown",
        definitely_no_external_effect=False,
    )


def failure_response(code: str, message: str, **fields: Any) -> dict[str, Any]:
    return {
        "ok": False,
        "error_code": code,
        "error": message,
        "errors": [{"code": code, "message": message}],
        **fields,
    }
