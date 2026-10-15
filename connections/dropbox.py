"""Dropbox connections over the public SDK's pinned HTTPS opener.

Only two fixed origins are ever contacted, with the connection's current access
token; Core owns the OAuth exchange, refresh and disconnect, so no client,
token or response is kept beyond one invocation. Listing pages are bounded by
the raw scan budget, downloads stream, and uploads above one buffer go through
an upload session committed only after the source was read to its end.
"""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request

from flowsteward_extension_sdk import open_pinned_url, parse_retry_after

import file_transfer_extension as protocol
from file_connections import (
    STREAM_CHUNK_BYTES,
    Deadline,
    FilePage,
    ListRequest,
    RemoteDownload,
    RemoteFile,
    UploadOptions,
    UploadResult,
)
from file_errors import FileTransferError, unknown_outcome

API_ORIGIN = "https://api.dropboxapi.com"
CONTENT_ORIGIN = "https://content.dropboxapi.com"
MiB = 1024 * 1024
#: Largest upload sent in one request; the upload-session piece size above it.
UPLOAD_PIECE_BYTES = 8 * MiB
LIST_RESPONSE_LIMIT = 2 * MiB
METADATA_RESPONSE_LIMIT = 256 * 1024
ERROR_RESPONSE_LIMIT = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 30.0
READ_ATTEMPTS = 3
OCTET_STREAM = "application/octet-stream"


class _DropboxHTTPError(Exception):
    def __init__(self, status: int, summary: str, retry_after: float | None) -> None:
        super().__init__(f"Dropbox HTTP {status}")
        self.status = status
        self.summary = summary
        self.retry_after = retry_after


def api_arg(value: Mapping[str, Any]) -> str:
    """``Dropbox-API-Arg`` must be ASCII: every other character goes out as ``\\uXXXX``."""
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).replace("\x7f", "\\u007f")


class DropboxConnection:
    """One invocation with one connection-scoped access token."""

    def __init__(
        self,
        *,
        access_token: str,
        root_path: str,
        deadline: Deadline,
        opener: Callable[..., Any] | None = None,
        api_origin: str = API_ORIGIN,
        content_origin: str = CONTENT_ORIGIN,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._token = access_token
        self._root = root_path
        self._deadline = deadline
        self._opener = opener or open_pinned_url
        self._api_origin = api_origin
        self._content_origin = content_origin
        self._sleep = sleep or time.sleep

    # -- the three operations -------------------------------------------------

    def list_files(self, request: ListRequest) -> FilePage:
        budget = max(1, int(request.limit))
        page = self._rpc_read(
            "files/list_folder",
            {
                "path": self._provider_path(request.path),
                "recursive": False,
                "limit": min(budget + 1, 2000),
                "include_deleted": False,
                "include_non_downloadable_files": False,
            },
            limit=LIST_RESPONSE_LIMIT,
        )
        files: list[RemoteFile] = []
        raw_seen = 0
        while True:
            entries = page.get("entries")
            if not isinstance(entries, list):
                raise FileTransferError(
                    "provider_unavailable", "Dropbox returned an invalid listing"
                )
            for entry in entries:
                raw_seen += 1
                if raw_seen > budget:
                    return FilePage(files=tuple(files), truncated=True)
                remote = _listed_file(entry, directory=request.path)
                if remote is not None:
                    files.append(remote)
            if page.get("has_more") is not True:
                return FilePage(files=tuple(files), truncated=False)
            cursor = page.get("cursor")
            if not isinstance(cursor, str) or not cursor or len(cursor) > 8192:
                raise FileTransferError(
                    "provider_unavailable", "Dropbox returned an invalid cursor"
                )
            page = self._rpc_read(
                "files/list_folder/continue", {"cursor": cursor}, limit=LIST_RESPONSE_LIMIT
            )

    def fetch_file(self, path: str) -> RemoteDownload:
        response = self._with_read_retries(
            lambda: self._open(
                f"{self._content_origin}/2/files/download",
                headers={"Dropbox-API-Arg": api_arg({"path": self._provider_path(path)})},
                data=b"",
                purpose="Dropbox download",
            )
        )
        try:
            header = str(response.headers.get("Dropbox-API-Result") or "")
            if len(header) > METADATA_RESPONSE_LIMIT:
                raise FileTransferError(
                    "provider_unavailable", "Dropbox file metadata is too large"
                )
            metadata = _decode(header.encode("utf-8"))
        except BaseException:
            with contextlib.suppress(Exception):
                response.close()
            raise
        name = str(metadata.get("name") or protocol._basename(path))
        remote = RemoteFile(
            name=name,
            remote_path=path,
            size_bytes=_optional_size(metadata.get("size")),
            modified_at=_iso(metadata.get("server_modified")),
            raw_modified=_epoch(metadata.get("server_modified")),
        )
        return RemoteDownload(file=remote, chunks=_ResponseChunks(response, self._deadline))

    def upload_file(
        self, remote_path: str, chunks: Iterable[bytes], options: UploadOptions
    ) -> UploadResult:
        target = self._provider_path(remote_path)
        self._require_parent_folder(remote_path)
        commit = {
            "path": target,
            "mode": "overwrite" if options.overwrite else "add",
            "autorename": False,
            "mute": True,
            "strict_conflict": False,
        }
        pieces = _pieces(chunks, UPLOAD_PIECE_BYTES)
        first = next(pieces, b"")
        pending = next(pieces, None)
        if pending is None:
            metadata = self._commit("files/upload", commit, first)
        else:
            session = self._content_write("files/upload_session/start", {"close": False}, first)
            session_id = session.get("session_id")
            if not isinstance(session_id, str) or not session_id:
                raise FileTransferError(
                    "provider_unavailable", "Dropbox returned an invalid upload session"
                )
            offset = len(first)
            while True:
                following = next(pieces, None)
                cursor = {"session_id": session_id, "offset": offset}
                if following is None:
                    # Only reached once the source iterator ended cleanly.
                    metadata = self._commit(
                        "files/upload_session/finish",
                        {"cursor": cursor, "commit": commit},
                        pending,
                    )
                    break
                self._content_write(
                    "files/upload_session/append_v2", {"cursor": cursor, "close": False}, pending
                )
                offset += len(pending)
                pending = following
        return UploadResult(
            remote_path=remote_path,
            remote_size_bytes=_optional_size(metadata.get("size")),
            overwrite_protection="atomic",
        )

    # -- setup check --------------------------------------------------------

    def check_root(self) -> None:
        """Read one entry of the configured root: no write, no account-wide listing."""
        self._rpc_read(
            "files/list_folder",
            {"path": self._provider_path("."), "recursive": False, "limit": 1},
            limit=LIST_RESPONSE_LIMIT,
        )

    # -- requests -----------------------------------------------------------

    def _provider_path(self, relative: str) -> str:
        parts = [part for part in (self._root, relative) if part and part != "."]
        return "/" + "/".join(parts) if parts else ""

    def _require_parent_folder(self, remote_path: str) -> None:
        parent = remote_path.rpartition("/")[0] or "."
        provider_parent = self._provider_path(parent)
        if not provider_parent:
            return  # the API root always exists and has no metadata of its own
        try:
            metadata = self._rpc_read(
                "files/get_metadata", {"path": provider_parent}, limit=METADATA_RESPONSE_LIMIT
            )
        except FileTransferError as exc:
            if exc.code == "not_found":
                raise FileTransferError("not_found", "Destination folder was not found") from exc
            raise
        if metadata.get(".tag") != "folder":
            raise FileTransferError("not_found", "Destination folder was not found")

    def _open(self, url: str, *, headers: Mapping[str, str], data: bytes, purpose: str) -> Any:
        if not url.startswith((f"{self._api_origin}/", f"{self._content_origin}/")):
            raise FileTransferError("network_blocked", "Refusing a non-Dropbox origin")
        if self._deadline.expired():
            raise FileTransferError("timeout", "Dropbox operation exceeded its deadline")
        request = Request(
            url,
            method="POST",
            data=data,
            headers={
                "Content-Type": OCTET_STREAM
                if "Dropbox-API-Arg" in headers
                else "application/json",
                **headers,
                "Authorization": f"Bearer {self._token}",
            },
        )
        timeout = max(1.0, min(REQUEST_TIMEOUT_SECONDS, self._deadline.remaining()))
        try:
            return self._opener(request, timeout_seconds=timeout, purpose=purpose)
        except HTTPError as exc:
            raise _http_error(exc) from exc
        except ValueError as exc:
            # The SDK refuses a target (blocked address, pinning) before anything is sent;
            # PinnedPeerError is one of these.
            raise FileTransferError("network_blocked", f"{purpose}: target is not allowed") from exc
        except TimeoutError as exc:
            raise FileTransferError("timeout", f"{purpose} timed out") from exc
        except OSError as exc:
            raise FileTransferError(
                "provider_unavailable", f"{purpose} failed: {type(exc).__name__}"
            ) from exc

    def _with_read_retries(self, call: Callable[[], Any]) -> Any:
        """Reads only: at most three attempts, waiting for Retry-After within the deadline."""
        for attempt in range(1, READ_ATTEMPTS + 1):
            try:
                return call()
            except _DropboxHTTPError as exc:
                retryable = exc.status == 429 or exc.status >= 500
                wait = exc.retry_after if exc.retry_after is not None else float(attempt)
                if not retryable or attempt == READ_ATTEMPTS or wait >= self._deadline.remaining():
                    raise _read_error(exc) from exc
                self._sleep(wait)
        raise AssertionError("unreachable")  # pragma: no cover

    def _rpc_read(self, route: str, body: Mapping[str, Any], *, limit: int) -> dict[str, Any]:
        raw = json.dumps(body, separators=(",", ":")).encode("utf-8")

        def _call() -> dict[str, Any]:
            with self._open(
                f"{self._api_origin}/2/{route}", headers={}, data=raw, purpose=f"Dropbox {route}"
            ) as response:
                return _decode(_read_response(response, limit, purpose=f"Dropbox {route}"))

        return self._with_read_retries(_call)

    def _content_write(self, route: str, arg: Mapping[str, Any], body: bytes) -> dict[str, Any]:
        """A session step before the commit: a failure here leaves no visible file."""
        try:
            with self._open(
                f"{self._content_origin}/2/{route}",
                headers={"Dropbox-API-Arg": api_arg(arg)},
                data=body,
                purpose=f"Dropbox {route}",
            ) as response:
                raw = _read_response(response, METADATA_RESPONSE_LIMIT, purpose=f"Dropbox {route}")
        except _DropboxHTTPError as exc:
            raise _read_error(exc) from exc
        return _decode(raw) if raw.strip() not in {b"", b"null"} else {}

    def _commit(self, route: str, arg: Mapping[str, Any], body: bytes) -> dict[str, Any]:
        """The one request that can create the file; its outcome is unknown unless answered."""
        try:
            with self._open(
                f"{self._content_origin}/2/{route}",
                headers={"Dropbox-API-Arg": api_arg(arg)},
                data=body,
                purpose=f"Dropbox {route}",
            ) as response:
                raw = _read_bounded(response, METADATA_RESPONSE_LIMIT)
        except _DropboxHTTPError as exc:
            if exc.status >= 500:
                raise unknown_outcome(
                    "timeout_unknown", f"Dropbox commit failed with HTTP {exc.status}"
                ) from exc
            raise _read_error(exc) from exc
        except FileTransferError as exc:
            if exc.code in {"timeout", "provider_unavailable"}:
                raise unknown_outcome("timeout_unknown", str(exc)) from exc
            raise
        except OSError as exc:  # the request went out; the answer did not come back whole
            raise unknown_outcome(
                "timeout_unknown", f"Dropbox commit was interrupted: {type(exc).__name__}"
            ) from exc
        try:
            return _decode(raw)
        except FileTransferError as exc:
            raise unknown_outcome("timeout_unknown", "Dropbox commit response was invalid") from exc


class _ResponseChunks:
    """A one-shot download stream; closing it closes the HTTP response."""

    def __init__(self, response: Any, deadline: Deadline) -> None:
        self._response = response
        self._deadline = deadline
        self._closed = False

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        if self._closed:
            raise StopIteration
        if self._deadline.expired():
            self.close()
            raise FileTransferError("timeout", "Dropbox download exceeded its deadline")
        read = getattr(self._response, "read1", None) or self._response.read
        try:
            chunk = read(STREAM_CHUNK_BYTES)
        except OSError as exc:
            self.close()
            raise FileTransferError(
                "provider_unavailable", f"Dropbox download was interrupted: {type(exc).__name__}"
            ) from exc
        if not chunk:
            self.close()
            raise StopIteration
        return bytes(chunk)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            with contextlib.suppress(Exception):
                self._response.close()


def _pieces(chunks: Iterable[bytes], size: int) -> Iterator[bytes]:
    """Re-slice a stream into pieces of exactly ``size`` bytes (the last may be shorter)."""
    buffer = bytearray()
    for chunk in chunks:
        buffer.extend(chunk)
        while len(buffer) >= size:
            yield bytes(buffer[:size])
            del buffer[:size]
    if buffer:
        yield bytes(buffer)


def _listed_file(entry: Any, *, directory: str) -> RemoteFile | None:
    if not isinstance(entry, dict) or entry.get(".tag") != "file":
        return None
    name = entry.get("name")
    if not isinstance(name, str):
        return None
    try:
        remote_path = protocol._join_remote_path(directory, name)
    except FileTransferError:
        return None  # counted against the scan budget, but not representable here
    return RemoteFile(
        name=name,
        remote_path=remote_path,
        size_bytes=_optional_size(entry.get("size")),
        modified_at=_iso(entry.get("server_modified")),
        raw_modified=_epoch(entry.get("server_modified")),
    )


def _optional_size(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _epoch(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


def _iso(value: Any) -> str | None:
    epoch = _epoch(value)
    return protocol._epoch_to_iso(epoch) if epoch is not None else None


def _read_response(response: Any, limit: int, *, purpose: str) -> bytes:
    """A bounded read of a request that changes nothing; a broken answer is just a failure."""
    try:
        return _read_bounded(response, limit)
    except OSError as exc:
        raise FileTransferError(
            "provider_unavailable", f"{purpose} was interrupted: {type(exc).__name__}"
        ) from exc


def _read_bounded(response: Any, limit: int) -> bytes:
    buffer = bytearray()
    while True:
        chunk = response.read(min(64 * 1024, limit + 1 - len(buffer)))
        if not chunk:
            return bytes(buffer)
        buffer.extend(chunk)
        if len(buffer) > limit:
            raise FileTransferError("provider_unavailable", "Dropbox response exceeded its limit")


def _decode(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FileTransferError("provider_unavailable", "Dropbox returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise FileTransferError("provider_unavailable", "Dropbox returned invalid JSON")
    return value


def _http_error(exc: HTTPError) -> _DropboxHTTPError:
    try:
        raw = _read_bounded(exc, ERROR_RESPONSE_LIMIT)
    except Exception:
        raw = b""
    finally:
        with contextlib.suppress(Exception):
            exc.close()
    try:
        body = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, ValueError):
        body = {}
    summary = str(body.get("error_summary") or "") if isinstance(body, dict) else ""
    headers = getattr(exc, "headers", None)
    retry_after = parse_retry_after(headers.get("Retry-After")) if headers is not None else None
    return _DropboxHTTPError(int(exc.code), summary, retry_after)


def _read_error(exc: _DropboxHTTPError) -> FileTransferError:
    """Map a Dropbox answer that definitely changed nothing to a safe error."""
    summary = exc.summary
    if exc.status == 401:
        if summary.startswith("missing_scope"):
            return FileTransferError(
                "permission_denied", "The Dropbox authorization is missing a required scope"
            )
        return FileTransferError(
            "authorization_required", "Dropbox authorization expired; connect the account again"
        )
    if exc.status == 403:
        return FileTransferError("permission_denied", "Dropbox refused access to this path")
    if exc.status == 429:
        return FileTransferError("rate_limited", "Dropbox rate limit reached")
    if exc.status == 409:
        if "/conflict" in summary:
            return FileTransferError("already_exists", "Remote path already exists")
        if "not_found" in summary or "not_file" in summary or "not_folder" in summary:
            return FileTransferError("not_found", "Remote path was not found")
        if "malformed_path" in summary:
            return FileTransferError("invalid_path", "Dropbox rejected the path")
        if "insufficient_space" in summary:
            return FileTransferError("not_supported_by_server", "Dropbox account is out of space")
        return FileTransferError("provider_unavailable", "Dropbox rejected the request")
    if 300 <= exc.status < 400:
        return FileTransferError("network_blocked", "Dropbox answered with a redirect")
    return FileTransferError("provider_unavailable", f"Dropbox answered HTTP {exc.status}")


def open_dropbox(payload: dict[str, Any], deadline: Deadline) -> DropboxConnection:
    """Validate a Dropbox connection before any network use."""
    connection = protocol._connection_payload(payload)
    settings = protocol._connection_settings(connection)
    secrets = protocol._as_dict(connection.get("secrets"))
    root_path = protocol._validate_root_relative_path(settings.get("root_path"), allow_empty=True)
    token = protocol._as_secret_str(secrets.get("access_token")).strip()
    if not token:
        raise FileTransferError(
            "authorization_required", "Dropbox is not authorized; connect the account first"
        )
    return DropboxConnection(access_token=token, root_path=root_path, deadline=deadline)
