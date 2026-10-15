"""Validate a connection payload and open the one class that serves its type.

The mapping from ``connection_type_id`` to a class is closed: there are no
protocol strings, storage options or URL schemes chosen by a workflow. Every
invocation opens its own client and closes it on success, error or abandonment.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import Any

import file_transfer_extension as protocol
from connections.ftp import FTPConnection
from connections.sftp import SFTPConnection
from file_connections import Deadline, FileConnection
from file_errors import FileTransferError


def connection_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    return protocol._connection_payload(dict(payload))


@contextmanager
def _open_protocol_client(payload: dict[str, Any], deadline: Deadline) -> Iterator[FileConnection]:
    config = protocol._connection_config(payload)
    connection_class = SFTPConnection if config.connection_type == "sftp" else FTPConnection
    with protocol._client_for(config) as client:
        yield connection_class(client)


def _test_protocol_client(payload: dict[str, Any], deadline: Deadline) -> dict[str, Any]:
    config = protocol._connection_config(payload)
    with protocol._client_for(config):
        return {
            "protocol": config.connection_type,
            "use_tls": config.use_tls if config.connection_type == "ftp" else None,
        }


@dataclass(frozen=True)
class _ConnectionType:
    open: Callable[[dict[str, Any], Deadline], AbstractContextManager[FileConnection]]
    test: Callable[[dict[str, Any], Deadline], dict[str, Any]]


_PROTOCOL_CLIENT = _ConnectionType(open=_open_protocol_client, test=_test_protocol_client)

_CONNECTION_TYPES: dict[str, _ConnectionType] = {
    "ftp": _PROTOCOL_CLIENT,
    "ftps": _PROTOCOL_CLIENT,
    "ftp_tls": _PROTOCOL_CLIENT,
    "sftp": _PROTOCOL_CLIENT,
}


def _connection_type(payload: dict[str, Any]) -> _ConnectionType:
    type_id = protocol._connection_type_id(payload)
    kind = _CONNECTION_TYPES.get(type_id)
    if kind is None:
        raise FileTransferError("invalid_connection", "Connection type must be ftp or sftp")
    return kind


def open_file_connection(
    payload: Mapping[str, Any], *, deadline: Deadline | None = None
) -> AbstractContextManager[FileConnection]:
    """Validate the connection before any network use and open its class."""
    data = dict(payload)
    return _connection_type(data).open(data, deadline or Deadline.for_invocation())


def verify_connection(
    payload: Mapping[str, Any], *, deadline: Deadline | None = None
) -> dict[str, Any]:
    """The hidden setup check: connect, and for cloud types read the configured root."""
    data = dict(payload)
    return _connection_type(data).test(data, deadline or Deadline.for_invocation())


def discover_host_key(payload: Mapping[str, Any]) -> dict[str, Any]:
    """The hidden SFTP setup step that reads a server's host key before it is trusted."""
    discovery = protocol._discover_sftp_host_key(protocol._host_key_discovery_config(dict(payload)))
    return {"protocol": "sftp", **discovery}
