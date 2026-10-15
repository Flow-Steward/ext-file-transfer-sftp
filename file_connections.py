"""The one interface every file connection implements, and the values it exchanges.

A connection knows its protocol, its authorization and its provider's quirks. The
common operation layer (``file_operations``) owns everything else: payload
parsing, file selection, artifacts, byte limits and the shape of results.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal, Protocol

from file_errors import FileTransferError

#: Raw entries a connection may inspect for one listing, whatever it filters out.
RAW_SCAN_BUDGET = 500
#: Largest piece of a file that crosses the interface at once.
STREAM_CHUNK_BYTES = 1024 * 1024

OPERATION_TIMEOUT_ENV = "FS_EXTENSION_OPERATION_TIMEOUT_SECONDS"
DEFAULT_OPERATION_TIMEOUT_SECONDS = 300
MIN_OPERATION_TIMEOUT_SECONDS = 30
MAX_OPERATION_TIMEOUT_SECONDS = 3600


@dataclass(frozen=True)
class ListRequest:
    """A directory relative to the connection root (``.`` is the root itself)."""

    path: str
    limit: int = RAW_SCAN_BUDGET


@dataclass(frozen=True)
class RemoteFile:
    """A regular file. Unknown metadata is ``None``, never an invented zero."""

    name: str
    remote_path: str
    size_bytes: int | None = None
    modified_at: str | None = None
    raw_modified: float | None = None


@dataclass(frozen=True)
class FilePage:
    """Regular files of one directory; ``truncated`` means the raw scan was incomplete."""

    files: tuple[RemoteFile, ...]
    truncated: bool


@dataclass(frozen=True)
class RemoteDownload:
    """Metadata and a one-shot stream, consumed while the connection is still open."""

    file: RemoteFile
    chunks: Iterable[bytes]


@dataclass(frozen=True)
class UploadOptions:
    overwrite: bool
    max_bytes: int
    source_size_bytes: int | None


@dataclass(frozen=True)
class UploadResult:
    """A confirmed commit. ``remote_size_bytes`` is what the provider reports."""

    remote_path: str
    remote_size_bytes: int | None
    overwrite_protection: Literal["atomic", "best_effort"]


class FileConnection(Protocol):
    def list_files(self, request: ListRequest) -> FilePage: ...

    def fetch_file(self, path: str) -> RemoteDownload: ...

    def upload_file(
        self, remote_path: str, chunks: Iterable[bytes], options: UploadOptions
    ) -> UploadResult: ...


def configured_operation_timeout_seconds() -> int:
    """The host's operation timeout, clamped exactly as the host clamps it."""
    try:
        configured = int(str(os.environ.get(OPERATION_TIMEOUT_ENV) or "").strip())
    except (TypeError, ValueError):
        configured = DEFAULT_OPERATION_TIMEOUT_SECONDS
    return max(MIN_OPERATION_TIMEOUT_SECONDS, min(configured, MAX_OPERATION_TIMEOUT_SECONDS))


class Deadline:
    """One monotonic deadline for the whole invocation; socket timeouts never extend it."""

    def __init__(self, seconds: float, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._expires_at = clock() + seconds

    @classmethod
    def for_invocation(cls) -> Deadline:
        return cls(configured_operation_timeout_seconds())

    def remaining(self) -> float:
        return max(0.0, self._expires_at - self._clock())

    def expired(self) -> bool:
        return self.remaining() <= 0

    def check(self) -> None:
        if self.expired():
            raise FileTransferError("timeout", "Operation deadline exceeded")
