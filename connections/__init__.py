"""One class per connection type, each implementing ``file_connections.FileConnection``."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from file_connections import (
    FilePage,
    ListRequest,
    RemoteDownload,
    RemoteFile,
    UploadOptions,
    UploadResult,
)


class ProtocolClientConnection:
    """Adapts a proven FTP/SFTP client to the file-connection interface.

    The client keeps its own sockets, host-key checks and temporary-file uploads;
    this adapter only translates values. Metadata from this invocation's listing
    is reused for a fetch of a listed file, as the protocol layer always did, so a
    glob fetch does not need a second per-file lookup the server may not support.
    """

    def __init__(self, client: Any) -> None:
        self._client = client
        self._listed: dict[str, RemoteFile] = {}

    def list_files(self, request: ListRequest) -> FilePage:
        entries, truncated = self._client.list_dir(request.path)
        files = tuple(_remote_file(entry) for entry in entries)
        self._listed = {row.remote_path: row for row in files}
        return FilePage(files=files, truncated=bool(truncated))

    def fetch_file(self, path: str) -> RemoteDownload:
        listed = self._listed.get(path)
        remote = listed if listed is not None else _remote_file(self._client.stat_file(path))
        return RemoteDownload(file=remote, chunks=self._client.stream_file(path))

    def upload_file(
        self, remote_path: str, chunks: Iterable[bytes], options: UploadOptions
    ) -> UploadResult:
        result = self._client.upload_file(remote_path, chunks, overwrite=options.overwrite)
        result = result if isinstance(result, dict) else {}
        size = result.get("remote_size_bytes")
        return UploadResult(
            remote_path=remote_path,
            remote_size_bytes=int(size) if size is not None else None,
            overwrite_protection=(
                "atomic" if result.get("overwrite_protection") == "atomic" else "best_effort"
            ),
        )


def _remote_file(entry: Any) -> RemoteFile:
    return RemoteFile(
        name=entry.name,
        remote_path=entry.path,
        size_bytes=entry.size_bytes,
        modified_at=entry.modified_at,
        raw_modified=entry.raw_modified,
    )
