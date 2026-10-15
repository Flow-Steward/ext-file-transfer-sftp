"""The three workflow operations, the same for every connection type.

Nothing here knows which provider sits behind a connection: the factory picks the
class, and this layer owns payload parsing, file selection, byte limits, hashing,
artifact grants and the shape of results.
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import hmac
import math
import os
import time
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from flowsteward_extension_sdk import (
    ArtifactAccessError,
    PinnedPeerError,
    find_artifact_descriptor,
    stream_artifact_bytes,
    write_artifact_stream,
)

import file_transfer_extension as protocol
from connection_factory import (
    connection_payload,
    discover_host_key,
    open_file_connection,
    verify_connection,
)
from file_connections import (
    RAW_SCAN_BUDGET,
    STREAM_CHUNK_BYTES,
    Deadline,
    ListRequest,
    RemoteFile,
    UploadOptions,
)
from file_errors import FileTransferError, failure_response, unknown_outcome

try:
    from flowsteward_extension_sdk import report_progress
except ImportError:  # a Core with an SDK older than 0.3.0 shows no progress

    def report_progress(
        message: str = "", *, done: int | None = None, total: int | None = None
    ) -> None:
        return None


MAX_TRANSFER_BYTES = 200 * 1024 * 1024
MIN_TRANSFER_BYTES = 1024 * 1024
MAX_CONFIGURED_TRANSFER_BYTES = 10 * 1024 * 1024 * 1024
EXTENSION_ARTIFACT_MAX_BYTES_ENV = "FS_EXTENSION_ARTIFACT_MAX_BYTES"
MAX_LIST_LIMIT = 500
DEFAULT_LIST_LIMIT = 200
ARTIFACT_BINDING_KEY = "fetched_file"
UPLOAD_ARTIFACT_BINDING_KEY = "source_artifact"
ARTIFACT_FILENAME = "download.bin"
OCTET_STREAM = "application/octet-stream"
SELECTORS = ("only", "latest_modified", "latest_name")


def _effective_max_bytes(input_payload: dict[str, Any], descriptor_limit: int | None = None) -> int:
    configured_limit = _configured_artifact_max_bytes()
    requested = protocol._strict_int(
        input_payload.get("max_bytes"),
        default=configured_limit,
        field="max_bytes",
        error_code="invalid_payload",
        minimum=1,
    )
    caps = [requested, configured_limit]
    if descriptor_limit:
        caps.append(int(descriptor_limit))
    return min(caps)


def _configured_artifact_max_bytes() -> int:
    try:
        configured = int(str(os.environ.get(EXTENSION_ARTIFACT_MAX_BYTES_ENV) or "").strip())
    except (TypeError, ValueError):
        configured = MAX_TRANSFER_BYTES
    return max(MIN_TRANSFER_BYTES, min(configured, MAX_CONFIGURED_TRANSFER_BYTES))


def _artifact_output_limit(payload: dict[str, Any]) -> int | None:
    artifacts = protocol._as_dict(payload.get("artifacts"))
    for row in protocol._as_list(artifacts.get("outputs")):
        descriptor = protocol._as_dict(row)
        if str(descriptor.get("binding_key") or "") == ARTIFACT_BINDING_KEY:
            access = protocol._as_dict(descriptor.get("access"))
            value = (
                access.get("max_size_bytes")
                or descriptor.get("max_size_bytes")
                or descriptor.get("size_limit_bytes")
            )
            return protocol._as_int(value, 0) or None
    for key in ("artifact_outputs", "artifacts", "outputs"):
        for row in protocol._as_list(payload.get(key)):
            descriptor = protocol._as_dict(row)
            if str(descriptor.get("binding_key") or "") == ARTIFACT_BINDING_KEY:
                value = descriptor.get("max_size_bytes") or descriptor.get("size_limit_bytes")
                return protocol._as_int(value, 0) or None
    return None


def _artifact_input_size(payload: dict[str, Any], *, artifact_handle: str) -> int | None:
    descriptor = find_artifact_descriptor(
        payload,
        artifact_id=artifact_handle,
        binding_key=UPLOAD_ARTIFACT_BINDING_KEY,
        role="input",
    )
    for key in ("size_bytes", "content_length", "byte_length"):
        value = descriptor.get(key)
        if value is not None:
            size = protocol._as_int(value, -1)
            return size if size >= 0 else None
    return None


def _signed_source_size(payload: dict[str, Any], *, artifact_handle: str) -> int | None:
    """The input's byte size, but only when the signed grant vouches for it.

    Core signs an input grant with ``access.max_size_bytes`` set to the stored
    artifact's exact size; ``size_bytes`` alone is unsigned descriptor metadata
    (a test harness leaves it at 0 after a streamed write). A size the grant
    does not confirm is unknown, never assumed.
    """
    descriptor = find_artifact_descriptor(
        payload,
        artifact_id=artifact_handle,
        binding_key=UPLOAD_ARTIFACT_BINDING_KEY,
        role="input",
    )
    size = _artifact_input_size(payload, artifact_handle=artifact_handle)
    signed = protocol._as_int(protocol._as_dict(descriptor.get("access")).get("max_size_bytes"), -1)
    return size if size is not None and size == signed else None


def _artifact_input_limit(payload: dict[str, Any], *, artifact_handle: str) -> int | None:
    descriptor = find_artifact_descriptor(
        payload,
        artifact_id=artifact_handle,
        binding_key=UPLOAD_ARTIFACT_BINDING_KEY,
        role="input",
    )
    access = protocol._as_dict(descriptor.get("access"))
    value = (
        access.get("max_size_bytes")
        or descriptor.get("max_size_bytes")
        or descriptor.get("size_limit_bytes")
    )
    limit = protocol._as_int(value, 0)
    return limit if limit > 0 else None


def _artifact_timeout(payload: dict[str, Any], deadline: Deadline) -> float:
    """Per-request artifact timeout: the connection's read timeout, never past the deadline."""
    settings = protocol._connection_settings(connection_payload(payload))
    read_timeout = protocol._clamp_timeout(
        settings.get("read_timeout_seconds"), default=30, maximum=300
    )
    return max(1.0, min(read_timeout, deadline.remaining()))


def _sensitive_values(payload: dict[str, Any]) -> list[str]:
    connection = connection_payload(payload)
    config = protocol._as_dict(
        connection.get("config")
        or connection.get("connection_config")
        or connection.get("provider_config")
    )
    secrets = protocol._as_dict(connection.get("secrets"))
    values: list[str] = []
    for source in (config, secrets):
        for key, value in source.items():
            key_text = str(key).lower()
            if any(
                token in key_text
                for token in ("password", "secret", "private_key", "token", "access_key")
            ):
                text = str(value or "")
                if text:
                    values.append(text)
    return values


def _redact_error(message: Any, payload: dict[str, Any]) -> str:
    text = str(message)
    for value in sorted(_sensitive_values(payload), key=len, reverse=True):
        if value:
            text = text.replace(value, "[redacted]")
    return text


def _filter_files(
    files: Iterable[RemoteFile],
    *,
    name_glob: str,
    limit: int,
    raw_truncated: bool,
) -> tuple[list[RemoteFile], bool]:
    pattern = protocol._as_str(name_glob)
    if pattern and "/" in pattern:
        raise FileTransferError("invalid_payload", "name_glob must match basenames only")
    filtered = [row for row in files if not pattern or fnmatch.fnmatchcase(row.name, pattern)]
    filtered.sort(key=lambda row: row.name)
    truncated = raw_truncated or len(filtered) > limit
    return filtered[:limit], truncated


def _file_dict(row: RemoteFile) -> dict[str, Any]:
    return {
        "name": row.name,
        "size_bytes": row.size_bytes,
        "modified_at": row.modified_at,
    }


def _select_file(files: list[RemoteFile], *, selector: str, protocol_name: str) -> RemoteFile:
    if not files:
        raise FileTransferError("not_found", "No matching file was found")
    if selector == "only":
        if len(files) != 1:
            raise FileTransferError("ambiguous_match", "More than one file matched")
        return files[0]
    if selector == "latest_name":
        return max(files, key=lambda row: row.name)
    if selector == "latest_modified":
        if any(row.raw_modified is None for row in files):
            raise FileTransferError(
                "not_supported_by_server",
                f"{protocol_name.upper()} did not provide reliable modification metadata",
            )
        return max(files, key=lambda row: (row.raw_modified or 0, row.name))
    raise FileTransferError(
        "invalid_payload", "select must be only, latest_modified, or latest_name"
    )


PROGRESS_MIN_INTERVAL_SECONDS = 1.0
_MEGABYTE = 1024 * 1024


def _transfer_progress(
    verb: str,
    name: str,
    *,
    total_bytes: int | None,
    clock: Callable[[], float] = time.monotonic,
) -> Callable[[int, bool], None]:
    """Report a transfer in whole megabytes, at most once a second and always at the end.

    With a known size the step shows "N of M" megabytes; without one, how much has moved.
    """
    total_mb = math.ceil(total_bytes / _MEGABYTE) if total_bytes else None
    last = {"mb": 0, "at": float("-inf")}

    def report(size_bytes: int, finished: bool) -> None:
        done_mb = size_bytes // _MEGABYTE
        if finished and total_mb:
            done_mb = total_mb
        now = clock()
        if not finished and (
            done_mb <= last["mb"] or now - last["at"] < PROGRESS_MIN_INTERVAL_SECONDS
        ):
            return
        if finished and done_mb == 0:
            return  # under a megabyte: nothing worth a progress line
        last["mb"], last["at"] = done_mb, now
        if total_mb:
            report_progress(f"{verb} {name} (MB)", done=done_mb, total=total_mb)
        else:
            report_progress(f"{verb} {name}: {done_mb} MB so far", done=done_mb)

    return report


def _hashing_chunks(
    chunks: Iterable[bytes],
    *,
    max_bytes: int,
    progress: Callable[[int, bool], None] | None = None,
    expected_size: int | None = None,
    deadline: Deadline | None = None,
) -> tuple[Iterator[bytes], dict[str, Any]]:
    """Count, hash and bound one pass over a stream.

    ``expected_size`` is a trusted source size (the signed artifact descriptor): a
    stream that ends early or runs past it fails before the iterator ends, so a
    connection never commits a short or padded upload. ``state["complete"]`` turns
    true only when the source was read to its end.
    """
    state: dict[str, Any] = {"size_bytes": 0, "sha256": hashlib.sha256(), "complete": False}

    def _iter() -> Iterator[bytes]:
        for chunk in chunks:
            if deadline is not None:
                deadline.check()
            data = bytes(chunk)
            state["size_bytes"] += len(data)
            if state["size_bytes"] > max_bytes:
                raise FileTransferError("max_bytes_exceeded", "Transfer exceeded max_bytes")
            if expected_size is not None and state["size_bytes"] > expected_size:
                raise FileTransferError(
                    "artifact_read_failed", "Artifact stream ran past its recorded size"
                )
            state["sha256"].update(data)
            if progress is not None:
                progress(state["size_bytes"], False)
            yield data
        if expected_size is not None and state["size_bytes"] != expected_size:
            raise FileTransferError(
                "artifact_read_failed", "Artifact stream ended before its recorded size"
            )
        state["complete"] = True
        if progress is not None:
            progress(state["size_bytes"], True)

    return _iter(), state


def _close_stream(chunks: Iterable[bytes]) -> None:
    close = getattr(chunks, "close", None)
    if callable(close):
        # Cleanup must not mask the outcome the caller is already reporting.
        with contextlib.suppress(Exception):
            close()


def _handle_list_files(payload: dict[str, Any], deadline: Deadline) -> dict[str, Any]:
    input_payload = protocol._input_payload(payload)
    if "path" not in input_payload or protocol._as_str(input_payload.get("path")) == "":
        raise FileTransferError("invalid_payload", "path is required")
    path = protocol._validate_root_relative_path(input_payload.get("path"), allow_empty=True)
    limit = protocol._strict_int(
        input_payload.get("limit"),
        default=DEFAULT_LIST_LIMIT,
        field="limit",
        error_code="invalid_payload",
        minimum=1,
        maximum=MAX_LIST_LIMIT,
    )
    name_glob = protocol._as_str(input_payload.get("name_glob"))
    if name_glob and "/" in name_glob:
        raise FileTransferError("invalid_payload", "name_glob must match basenames only")
    with open_file_connection(payload, deadline=deadline) as connection:
        page = connection.list_files(ListRequest(path=path, limit=RAW_SCAN_BUDGET))
    filtered, truncated = _filter_files(
        page.files, name_glob=name_glob, limit=limit, raw_truncated=page.truncated
    )
    return {
        "ok": True,
        "result": {"files": [_file_dict(row) for row in filtered], "truncated": truncated},
    }


def _handle_fetch_file(payload: dict[str, Any], deadline: Deadline) -> dict[str, Any]:
    input_payload = protocol._input_payload(payload)
    max_bytes = _effective_max_bytes(input_payload, _artifact_output_limit(payload))
    name_glob = protocol._as_str(input_payload.get("name_glob"))
    # `path` is a directory when a glob selects the file inside it, and the file
    # itself otherwise. The connection root is `.` in the directory case, exactly
    # as it is for list_files; validating it as a file path made the root the one
    # place a glob could not be used.
    raw_path = protocol._as_str(input_payload.get("path"))
    if not name_glob and raw_path.strip() in {"", "."}:
        raise FileTransferError(
            "invalid_path",
            "path must name a file when no name_glob is given; "
            "to fetch from the connection root, pass path '.' together with a name_glob",
        )
    path = protocol._validate_root_relative_path(
        input_payload.get("path"), allow_empty=bool(name_glob)
    )
    selector = protocol._as_str(input_payload.get("select") or "only")
    if name_glob and "/" in name_glob:
        raise FileTransferError("invalid_payload", "name_glob must match basenames only")
    if name_glob and selector not in SELECTORS:
        raise FileTransferError(
            "invalid_payload", "select must be only, latest_modified, or latest_name"
        )
    protocol_name = protocol._connection_type_id(payload) or "remote"
    with open_file_connection(payload, deadline=deadline) as connection:
        if name_glob:
            page = connection.list_files(ListRequest(path=path, limit=RAW_SCAN_BUDGET))
            if page.truncated:
                raise FileTransferError(
                    "directory_too_large",
                    f"Directory exceeded {RAW_SCAN_BUDGET} raw entries",
                )
            filtered, _ = _filter_files(
                page.files,
                name_glob=name_glob,
                limit=RAW_SCAN_BUDGET,
                raw_truncated=False,
            )
            selected = _select_file(filtered, selector=selector, protocol_name=protocol_name)
            remote_path = selected.remote_path
            download = connection.fetch_file(remote_path)
        else:
            remote_path = path
            download = connection.fetch_file(remote_path)
            selected = download.file
        metadata_size = download.file.size_bytes
        try:
            if metadata_size is not None and metadata_size > max_bytes:
                raise FileTransferError("max_bytes_exceeded", "Remote file exceeds max_bytes")
            chunks, state = _hashing_chunks(
                download.chunks,
                max_bytes=max_bytes,
                progress=_transfer_progress(
                    "Downloading", selected.name, total_bytes=metadata_size
                ),
                deadline=deadline,
            )
            try:
                write_result = write_artifact_stream(
                    payload,
                    chunks,
                    binding_key=ARTIFACT_BINDING_KEY,
                    content_type=OCTET_STREAM,
                    timeout_seconds=_artifact_timeout(payload, deadline),
                )
            except ArtifactAccessError as exc:
                raise FileTransferError("artifact_write_failed", str(exc)) from exc
        finally:
            _close_stream(download.chunks)
    sha256 = state["sha256"].hexdigest()
    artifact_handle = _validate_artifact_write_result(
        write_result, size_bytes=state["size_bytes"], sha256=sha256
    )
    return {
        "ok": True,
        "result": {
            "artifact_handle": artifact_handle,
            "artifact_filename": ARTIFACT_FILENAME,
            "source_filename": selected.name,
            "remote_path": remote_path,
            "sha256": sha256,
            "size_bytes": state["size_bytes"],
        },
    }


def _validate_artifact_write_result(
    write_result: dict[str, Any], *, size_bytes: int, sha256: str
) -> str:
    if not isinstance(write_result, dict):
        raise FileTransferError(
            "artifact_write_failed", "Artifact write returned an invalid result"
        )
    artifact_handle = protocol._as_str(
        write_result.get("artifact_handle") or write_result.get("artifact_id")
    )
    if not artifact_handle:
        raise FileTransferError("artifact_write_failed", "Artifact write did not return a handle")
    reported_size = write_result.get("size_bytes")
    if reported_size is None:
        raise FileTransferError("artifact_write_failed", "Artifact write did not return size_bytes")
    if protocol._as_int(reported_size, -1) != size_bytes:
        raise FileTransferError(
            "artifact_write_failed", "Artifact write size did not match streamed bytes"
        )
    reported_sha = protocol._as_str(
        write_result.get("sha256")
        or write_result.get("checksum_sha256")
        or write_result.get("checksum")
    )
    if not reported_sha:
        raise FileTransferError("artifact_write_failed", "Artifact write did not return sha256")
    if not hmac.compare_digest(reported_sha, sha256):
        raise FileTransferError(
            "artifact_write_failed", "Artifact write checksum did not match streamed bytes"
        )
    finalized = write_result.get("finalized")
    if finalized is False:
        raise FileTransferError("artifact_write_failed", "Artifact write was not finalized")
    return artifact_handle


def _input_artifact_handle(input_payload: dict[str, Any]) -> str:
    value = input_payload.get("artifact_handle") or input_payload.get("artifact_id")
    if isinstance(value, dict):
        value = value.get("artifact_handle") or value.get("artifact_id")
    handle = protocol._as_str(value)
    if not handle:
        raise FileTransferError("invalid_payload", "artifact_handle is required")
    return handle


def _handle_upload_file(payload: dict[str, Any], deadline: Deadline) -> dict[str, Any]:
    input_payload = protocol._input_payload(payload)
    artifact_handle = _input_artifact_handle(input_payload)
    remote_path = protocol._validate_root_relative_path(
        input_payload.get("remote_path"), allow_empty=False
    )
    overwrite = protocol._as_bool(input_payload.get("overwrite"), default=False)
    try:
        artifact_limit = _artifact_input_limit(payload, artifact_handle=artifact_handle)
    except ArtifactAccessError as exc:
        raise FileTransferError("artifact_read_failed", str(exc)) from exc
    max_bytes = _effective_max_bytes(input_payload, artifact_limit)
    try:
        artifact_size = _artifact_input_size(payload, artifact_handle=artifact_handle)
        source_size = _signed_source_size(payload, artifact_handle=artifact_handle)
        if artifact_size is not None and artifact_size > max_bytes:
            raise FileTransferError("max_bytes_exceeded", "Artifact exceeds max_bytes")
        artifact_stream = stream_artifact_bytes(
            payload,
            artifact_id=artifact_handle,
            binding_key=UPLOAD_ARTIFACT_BINDING_KEY,
            chunk_size=STREAM_CHUNK_BYTES,
            timeout_seconds=_artifact_timeout(payload, deadline),
        )
    except ArtifactAccessError as exc:
        raise FileTransferError("artifact_read_failed", str(exc)) from exc
    chunks, state = _hashing_chunks(
        artifact_stream,
        max_bytes=max_bytes,
        progress=_transfer_progress(
            "Uploading", protocol._basename(remote_path), total_bytes=artifact_size
        ),
        expected_size=source_size,
        deadline=deadline,
    )
    options = UploadOptions(overwrite=overwrite, max_bytes=max_bytes, source_size_bytes=source_size)
    try:
        with open_file_connection(payload, deadline=deadline) as connection:
            result = connection.upload_file(remote_path, chunks, options)
    except ArtifactAccessError as exc:
        raise FileTransferError("artifact_read_failed", str(exc)) from exc
    finally:
        _close_stream(artifact_stream)
    if not state["complete"]:
        raise unknown_outcome(
            "transfer_failed", "Upload reported a commit before the whole artifact was read"
        )
    if result.remote_size_bytes is not None and result.remote_size_bytes != state["size_bytes"]:
        raise unknown_outcome(
            "transfer_failed", "Remote size after upload did not match the uploaded bytes"
        )
    return {
        "ok": True,
        "result": {
            "uploaded": True,
            "remote_path": remote_path,
            "sha256": state["sha256"].hexdigest(),
            "size_bytes": state["size_bytes"],
            "overwrite_protection": result.overwrite_protection,
            "external_effect_status": "succeeded",
        },
        "external_effect_status": "succeeded",
    }


def _suppressed_upload_response() -> dict[str, Any]:
    return {
        "ok": True,
        "result": {
            "uploaded": False,
            "external_effect_status": "suppressed",
            "definitely_no_external_effect": True,
        },
        "external_effect_status": "suppressed",
        "definitely_no_external_effect": True,
    }


_OPERATIONS: dict[str, Callable[[dict[str, Any], Deadline], dict[str, Any]]] = {
    "list_files": _handle_list_files,
    "fetch_file": _handle_fetch_file,
    "upload_file": _handle_upload_file,
}


def handle_payload(payload: dict[str, Any]) -> dict[str, Any]:
    redaction_payload = payload if isinstance(payload, dict) else {}
    try:
        if not isinstance(payload, dict):
            raise FileTransferError("invalid_payload", "Request payload must be a JSON object")
        deadline = Deadline.for_invocation()
        operation = protocol._operation_id(payload)
        runtime_context = protocol._as_dict(payload.get("runtime_context"))
        if operation == "upload_file" and protocol._as_bool(runtime_context.get("test_mode")):
            return _suppressed_upload_response()
        if operation == "discover_host_key":
            return {"ok": True, "result": discover_host_key(payload)}
        if operation == "test_connection":
            return {"ok": True, "result": verify_connection(payload, deadline=deadline)}
        handler = _OPERATIONS.get(operation)
        if handler is None:
            raise FileTransferError("unknown_action", "Unsupported file transfer action")
        return handler(payload, deadline)
    except (PinnedPeerError, TimeoutError) as exc:
        return failure_response(
            "network_blocked",
            _redact_error(exc, redaction_payload),
            definitely_no_external_effect=True,
            external_effect_status="failed",
        )
    except FileTransferError as exc:
        payload_out = failure_response(
            exc.code,
            _redact_error(exc, redaction_payload),
            definitely_no_external_effect=exc.definitely_no_external_effect,
        )
        if exc.external_effect_status:
            payload_out["external_effect_status"] = exc.external_effect_status
        elif exc.definitely_no_external_effect:
            payload_out["external_effect_status"] = "failed"
        return payload_out
    except Exception as exc:
        return failure_response(
            "transfer_failed",
            _redact_error(exc, redaction_payload),
            definitely_no_external_effect=False,
            external_effect_status="timeout_unknown",
        )
