from __future__ import annotations

import base64
import contextlib
import errno
import fnmatch
import hashlib
import hmac
import io
import math
import os
import posixpath
import socket
import ssl
import stat
import time
import uuid
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

# FTP/FTPS is the extension's explicit protocol surface; hosts still pass SSRF policy.
from ftplib import FTP, FTP_TLS, error_perm  # nosec B402
from pathlib import PurePosixPath
from typing import Any

from flowsteward_extension_sdk import (
    ArtifactAccessError,
    PinnedPeerError,
    find_artifact_descriptor,
    resolve_pinned_ips,
    stream_artifact_bytes,
    write_artifact_stream,
)

try:
    from flowsteward_extension_sdk import report_progress
except ImportError:  # a Core with an SDK older than 0.3.0 shows no progress

    def report_progress(
        message: str = "", *, done: int | None = None, total: int | None = None
    ) -> None:
        return None


_MESSAGE_SFTP_FINGERPRINT_IS_MALFORMED = "SFTP fingerprint is malformed"
_MESSAGE_REMOTE_PATH_ALREADY_EXISTS = "Remote path already exists"
_MESSAGE_REMOTE_FILE_WAS_NOT_FOUND = "Remote file was not found"

EXTENSION_ID = "flowsteward.file-transfer"
MAX_TRANSFER_BYTES = 200 * 1024 * 1024
MIN_TRANSFER_BYTES = 1024 * 1024
MAX_CONFIGURED_TRANSFER_BYTES = 10 * 1024 * 1024 * 1024
EXTENSION_ARTIFACT_MAX_BYTES_ENV = "FS_EXTENSION_ARTIFACT_MAX_BYTES"
MAX_RAW_DIRECTORY_ENTRIES = 500
MAX_LIST_LIMIT = 500
STREAM_CHUNK_BYTES = 1024 * 1024
ARTIFACT_BINDING_KEY = "fetched_file"
UPLOAD_ARTIFACT_BINDING_KEY = "source_artifact"
ARTIFACT_FILENAME = "download.bin"
OCTET_STREAM = "application/octet-stream"
FINGERPRINT_PREFIX = "SHA256:"
ALLOWED_HOST_KEY_PREFIXES = ("ssh-ed25519", "ecdsa-sha2-nistp", "rsa-sha2-")
DISALLOWED_SFTP_KEY_TYPES = ("ssh-rsa", "ssh-dss")
DISALLOWED_SFTP_PUBKEY_ALGORITHMS = ("ssh-rsa",)


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


class _DirectoryLimitReached(RuntimeError):
    pass


@dataclass(frozen=True)
class ConnectionConfig:
    connection_type: str
    host: str
    port: int
    root_path: str
    use_tls: bool
    allow_insecure_ftp: bool
    host_key_fingerprint: str
    connect_timeout: float
    read_timeout: float
    username: str
    password: str
    private_key: str
    private_key_passphrase: str


@dataclass(frozen=True)
class HostKeyDiscoveryConfig:
    host: str
    port: int
    connect_timeout: float
    read_timeout: float


@dataclass(frozen=True)
class RemoteEntry:
    name: str
    path: str
    size_bytes: int | None = None
    modified_at: str | None = None
    kind: str = "file"
    raw_modified: float | None = None


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _as_str(value: Any) -> str:
    return str(value or "").strip()


def _as_secret_str(value: Any) -> str:
    return "" if value is None else str(value)


def _has_control_characters(value: str) -> bool:
    return any(ord(ch) < 32 or ch == "\x7f" for ch in value)


def _reject_command_injection(value: str, *, field: str) -> None:
    if "\r" in value or "\n" in value or "\x00" in value:
        raise FileTransferError(
            "invalid_connection", f"{field} must not contain command separators"
        )


def _as_bool(value: Any, *, default: bool = False, error_code: str = "invalid_payload") -> bool:
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return default
    if isinstance(value, int) and not isinstance(value, bool):
        if value in {0, 1}:
            return bool(value)
        raise FileTransferError(error_code, "Boolean value must be true or false")
    text = _as_str(value).lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise FileTransferError(error_code, "Boolean value must be true or false")


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _strict_int(
    value: Any,
    *,
    default: int | None = None,
    field: str,
    error_code: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if value is None or value == "":
        if default is None:
            raise FileTransferError(error_code, f"{field} is required")
        parsed = default
    elif isinstance(value, bool):
        raise FileTransferError(error_code, f"{field} must be an integer")
    elif isinstance(value, int):
        parsed = value
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise FileTransferError(error_code, f"{field} must be an integer")
        parsed = int(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text or any(ch in text for ch in ".eE"):
            raise FileTransferError(error_code, f"{field} must be an integer")
        try:
            parsed = int(text, 10)
        except Exception as exc:
            raise FileTransferError(error_code, f"{field} must be an integer") from exc
    else:
        raise FileTransferError(error_code, f"{field} must be an integer")
    if minimum is not None and parsed < minimum:
        raise FileTransferError(error_code, f"{field} must be at least {minimum}")
    if maximum is not None and parsed > maximum:
        raise FileTransferError(error_code, f"{field} must be at most {maximum}")
    return parsed


def _strict_float(
    value: Any,
    *,
    default: float,
    field: str,
    error_code: str,
    minimum: float,
    maximum: float,
) -> float:
    if value is None or value == "":
        parsed = default
    elif isinstance(value, bool):
        raise FileTransferError(error_code, f"{field} must be a finite number")
    else:
        try:
            parsed = float(value)
        except Exception as exc:
            raise FileTransferError(error_code, f"{field} must be a finite number") from exc
    if not math.isfinite(parsed):
        raise FileTransferError(error_code, f"{field} must be a finite number")
    if parsed < minimum or parsed > maximum:
        raise FileTransferError(error_code, f"{field} must be within allowed bounds")
    return parsed


def _clamp_timeout(value: Any, *, default: float, maximum: float) -> float:
    return _strict_float(
        value,
        default=default,
        field="Timeout",
        error_code="invalid_connection",
        minimum=1,
        maximum=maximum,
    )


def _input_payload(payload: dict[str, Any]) -> dict[str, Any]:
    action = _as_dict(payload.get("action"))
    action_input = _as_dict(action.get("input"))
    if action_input:
        return action_input
    request = _as_dict(payload.get("request"))
    if request:
        return request
    action_payload = _as_dict(payload.get("action_payload"))
    action_payload_input = _as_dict(action_payload.get("input"))
    if action_payload_input:
        return action_payload_input
    return _as_dict(payload.get("input"))


def _operation_id(payload: dict[str, Any]) -> str:
    action = _as_dict(payload.get("action"))
    return _as_str(
        action.get("action_id")
        or action.get("operation_id")
        or payload.get("operation_id")
        or payload.get("action")
    )


def _connection_payload(payload: dict[str, Any]) -> dict[str, Any]:
    action = _as_dict(payload.get("action"))
    target = _as_dict(action.get("target"))
    connection = _as_dict(target.get("connection"))
    if connection:
        return connection
    action_payload = _as_dict(payload.get("action_payload"))
    action_payload_target = _as_dict(action_payload.get("target"))
    connection = _as_dict(action_payload_target.get("connection"))
    if connection:
        return connection
    target = _as_dict(payload.get("target"))
    connection = _as_dict(target.get("connection"))
    if connection:
        return connection
    provider = _as_dict(payload.get("provider"))
    return {
        "connection_type_id": provider.get("connection_type_id"),
        "config": _as_dict(provider.get("provider_config") or provider.get("config")),
        "secrets": _as_dict(provider.get("secrets")),
    }


def _connection_config(payload: dict[str, Any]) -> ConnectionConfig:
    connection = _connection_payload(payload)
    config = _as_dict(
        connection.get("config")
        or connection.get("connection_config")
        or connection.get("provider_config")
    )
    secrets = _as_dict(connection.get("secrets"))
    connection_type = _as_str(
        connection.get("connection_type_id")
        or connection.get("connection_type")
        or connection.get("type")
        or config.get("connection_type_id")
        or config.get("connection_type")
        or config.get("protocol")
    ).lower()
    if connection_type in {"ftps", "ftp_tls"}:
        connection_type = "ftp"
        config.setdefault("use_tls", True)
    if connection_type not in {"ftp", "sftp"}:
        raise FileTransferError("invalid_connection", "Connection type must be ftp or sftp")

    host = _as_str(config.get("host"))
    if not host:
        raise FileTransferError("invalid_connection", "Connection host is required")
    _reject_command_injection(host, field="Connection host")
    port = _strict_int(
        config.get("port"),
        default=22 if connection_type == "sftp" else 21,
        field="Connection port",
        error_code="invalid_connection",
        minimum=1,
        maximum=65535,
    )
    root_path = _as_str(config.get("root_path") or ".")
    if _has_control_characters(root_path):
        raise FileTransferError(
            "invalid_connection", "Connection root_path contains control characters"
        )
    connect_timeout = _clamp_timeout(config.get("connect_timeout_seconds"), default=15, maximum=60)
    read_timeout = _clamp_timeout(config.get("read_timeout_seconds"), default=30, maximum=300)
    username = _as_str(secrets.get("username") or config.get("username"))
    password = _as_secret_str(secrets.get("password"))
    private_key = _as_secret_str(secrets.get("private_key"))
    private_key_passphrase = _as_secret_str(secrets.get("private_key_passphrase"))
    use_tls = _as_bool(config.get("use_tls"), default=True, error_code="invalid_connection")
    allow_insecure_ftp = _as_bool(
        config.get("allow_insecure_ftp"), default=False, error_code="invalid_connection"
    )
    fingerprint = _as_str(config.get("host_key_fingerprint"))

    if connection_type == "ftp":
        _reject_command_injection(root_path, field="FTP root_path")
        _reject_command_injection(username, field="FTP username")
        _reject_command_injection(password, field="FTP password")
        if _as_str(config.get("password")):
            raise FileTransferError(
                "invalid_connection", "FTP password must be supplied as a connection secret"
            )
        if not username or not password:
            raise FileTransferError("invalid_connection", "FTP username and password are required")
        if not use_tls and not allow_insecure_ftp:
            raise FileTransferError(
                "insecure_ftp_not_acknowledged",
                "Plaintext FTP requires allow_insecure_ftp=true",
            )
    else:
        if not username:
            raise FileTransferError("invalid_connection", "SFTP username is required")
        if bool(password) == bool(private_key):
            raise FileTransferError(
                "invalid_connection", "SFTP requires exactly one of password or private_key"
            )
        if password and private_key_passphrase:
            raise FileTransferError(
                "invalid_connection",
                "SFTP private_key_passphrase is only valid with private_key authentication",
            )
        _validate_fingerprint(fingerprint)
    return ConnectionConfig(
        connection_type=connection_type,
        host=host,
        port=port,
        root_path=root_path,
        use_tls=use_tls,
        allow_insecure_ftp=allow_insecure_ftp,
        host_key_fingerprint=fingerprint,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        username=username,
        password=password,
        private_key=private_key,
        private_key_passphrase=private_key_passphrase,
    )


def _host_key_discovery_config(payload: dict[str, Any]) -> HostKeyDiscoveryConfig:
    connection = _connection_payload(payload)
    config = _as_dict(
        connection.get("config")
        or connection.get("connection_config")
        or connection.get("provider_config")
    )
    connection_type = _as_str(
        connection.get("connection_type_id")
        or connection.get("connection_type")
        or connection.get("type")
        or config.get("connection_type_id")
        or config.get("connection_type")
        or config.get("protocol")
    ).lower()
    if connection_type != "sftp":
        raise FileTransferError(
            "invalid_connection", "Host key discovery is only available for SFTP"
        )
    host = _as_str(config.get("host"))
    if not host:
        raise FileTransferError("invalid_connection", "Connection host is required")
    _reject_command_injection(host, field="Connection host")
    port = _strict_int(
        config.get("port"),
        default=22,
        field="Connection port",
        error_code="invalid_connection",
        minimum=1,
        maximum=65535,
    )
    return HostKeyDiscoveryConfig(
        host=host,
        port=port,
        connect_timeout=_clamp_timeout(
            config.get("connect_timeout_seconds"), default=15, maximum=60
        ),
        read_timeout=_clamp_timeout(config.get("read_timeout_seconds"), default=30, maximum=300),
    )


def _validate_fingerprint(fingerprint: str) -> None:
    if not fingerprint:
        raise FileTransferError(
            "invalid_host_key_fingerprint",
            "SFTP host key fingerprint is required. Use OpenSSH SHA256:<base64> form "
            "and verify it with the server owner before saving the connection.",
        )
    if not fingerprint.startswith(FINGERPRINT_PREFIX):
        raise FileTransferError(
            "invalid_host_key_fingerprint",
            "SFTP host key fingerprint must use OpenSSH SHA256:<base64> form",
        )
    digest = fingerprint[len(FINGERPRINT_PREFIX) :]
    if not digest or "=" in digest:
        raise FileTransferError(
            "invalid_host_key_fingerprint", _MESSAGE_SFTP_FINGERPRINT_IS_MALFORMED
        )
    try:
        decoded = base64.b64decode(digest + "=" * (-len(digest) % 4), validate=True)
    except Exception as exc:
        raise FileTransferError(
            "invalid_host_key_fingerprint", _MESSAGE_SFTP_FINGERPRINT_IS_MALFORMED
        ) from exc
    canonical = base64.b64encode(decoded).decode("ascii").rstrip("=")
    if len(decoded) != 32 or not hmac.compare_digest(canonical, digest):
        raise FileTransferError(
            "invalid_host_key_fingerprint", _MESSAGE_SFTP_FINGERPRINT_IS_MALFORMED
        )


def _canonical_fingerprint(key_blob: bytes) -> str:
    digest = base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")
    return f"{FINGERPRINT_PREFIX}{digest}"


def _validate_root_relative_path(value: Any, *, allow_empty: bool = False) -> str:
    text = str(value or "")
    if allow_empty and text.strip() in {"", "."}:
        return "."
    if not text and allow_empty:
        return "."
    if not text:
        raise FileTransferError("invalid_path", "Path is required")
    if text.startswith("/") or "\\" in text:
        raise FileTransferError("invalid_path", "Path must be root-relative POSIX")
    if any(ord(ch) < 32 or ch == "\x7f" for ch in text):
        raise FileTransferError("invalid_path", "Path contains control characters")
    parts = text.split("/")
    if any(part == "" for part in parts):
        raise FileTransferError("invalid_path", "Path must not contain empty segments")
    if not parts and not allow_empty:
        raise FileTransferError("invalid_path", "Path is required")
    if any(part in {".", ".."} for part in parts):
        raise FileTransferError("invalid_path", "Path must not contain dot segments")
    return "/".join(parts) if parts else "."


def _join_remote_path(directory: str, name: str) -> str:
    safe_name = _validate_root_relative_path(name)
    if "/" in safe_name:
        raise FileTransferError("invalid_path", "Filename must be a basename")
    safe_dir = _validate_root_relative_path(directory, allow_empty=True)
    return safe_name if safe_dir == "." else f"{safe_dir}/{safe_name}"


def _basename(path: str) -> str:
    return PurePosixPath(path).name


def _effective_max_bytes(input_payload: dict[str, Any], descriptor_limit: int | None = None) -> int:
    configured_limit = _configured_artifact_max_bytes()
    requested = _strict_int(
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
        configured = int(str(os.environ.get("FS_EXTENSION_ARTIFACT_MAX_BYTES") or "").strip())
    except (TypeError, ValueError):
        configured = MAX_TRANSFER_BYTES
    return max(MIN_TRANSFER_BYTES, min(configured, MAX_CONFIGURED_TRANSFER_BYTES))


def _ftp_550_is_not_found(exc: error_perm) -> bool:
    text = str(exc).lower()
    return any(
        token in text
        for token in (
            "not found",
            "no such",
            "not exist",
            "doesn't exist",
            "does not exist",
            "missing",
        )
    )


def _artifact_output_limit(payload: dict[str, Any]) -> int | None:
    artifacts = _as_dict(payload.get("artifacts"))
    for row in _as_list(artifacts.get("outputs")):
        descriptor = _as_dict(row)
        if str(descriptor.get("binding_key") or "") == ARTIFACT_BINDING_KEY:
            access = _as_dict(descriptor.get("access"))
            value = (
                access.get("max_size_bytes")
                or descriptor.get("max_size_bytes")
                or descriptor.get("size_limit_bytes")
            )
            return _as_int(value, 0) or None
    for key in ("artifact_outputs", "artifacts", "outputs"):
        for row in _as_list(payload.get(key)):
            descriptor = _as_dict(row)
            if str(descriptor.get("binding_key") or "") == ARTIFACT_BINDING_KEY:
                value = descriptor.get("max_size_bytes") or descriptor.get("size_limit_bytes")
                return _as_int(value, 0) or None
    return None


def _verify_socket_peer(sock: Any, pinned_ip: str, *, purpose: str) -> None:
    try:
        peer = sock.getpeername()
    except Exception as exc:
        raise FileTransferError("network_blocked", f"Could not verify {purpose} peer") from exc
    peer_host = str(peer[0] if isinstance(peer, tuple) and peer else "")
    if peer_host != pinned_ip:
        raise FileTransferError(
            "network_blocked",
            f"{purpose} connected to unexpected peer {peer_host or '<unknown>'}",
        )


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
            size = _as_int(value, -1)
            return size if size >= 0 else None
    return None


def _artifact_input_limit(payload: dict[str, Any], *, artifact_handle: str) -> int | None:
    descriptor = find_artifact_descriptor(
        payload,
        artifact_id=artifact_handle,
        binding_key=UPLOAD_ARTIFACT_BINDING_KEY,
        role="input",
    )
    access = _as_dict(descriptor.get("access"))
    value = (
        access.get("max_size_bytes")
        or descriptor.get("max_size_bytes")
        or descriptor.get("size_limit_bytes")
    )
    limit = _as_int(value, 0)
    return limit if limit > 0 else None


def _sensitive_values(payload: dict[str, Any]) -> list[str]:
    connection = _connection_payload(payload)
    config = _as_dict(
        connection.get("config")
        or connection.get("connection_config")
        or connection.get("provider_config")
    )
    secrets = _as_dict(connection.get("secrets"))
    values: list[str] = []
    for source in (config, secrets):
        for key, value in source.items():
            key_text = str(key).lower()
            if any(token in key_text for token in ("password", "secret", "private_key", "token")):
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


class _PinnedFTP(FTP):
    def __init__(self, *, original_host: str, pinned_ip: str, timeout: float) -> None:
        super().__init__(timeout=timeout)
        self.original_host = original_host
        self.pinned_ip = pinned_ip
        self.host = original_host

    def connect(self, host: str = "", port: int = 0, timeout: float = -999, source_address=None):
        _ = host
        self.host = self.original_host
        self.port = int(port or self.port or 21)
        if timeout != -999:
            self.timeout = timeout
        self.sock = socket.create_connection(
            (self.pinned_ip, self.port),
            self.timeout,
            source_address,
        )
        _verify_socket_peer(self.sock, self.pinned_ip, purpose="FTP control socket")
        self.af = self.sock.family
        self.file = self.sock.makefile("r", encoding=self.encoding)
        self.welcome = self.getresp()
        return self.welcome

    def makepasv(self):
        _host, port = super().makepasv()
        if not 1 <= int(port) <= 65535:
            raise FileTransferError("invalid_passive_port", "FTP passive port is invalid")
        return self.pinned_ip, int(port)

    def ntransfercmd(self, cmd, rest=None):
        conn, size = super().ntransfercmd(cmd, rest)
        _verify_socket_peer(conn, self.pinned_ip, purpose="FTP passive data socket")
        return conn, size


class _PinnedFTPTLS(FTP_TLS):
    def __init__(
        self,
        *,
        original_host: str,
        pinned_ip: str,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(timeout=timeout, context=context)
        self.original_host = original_host
        self.pinned_ip = pinned_ip
        self.host = original_host

    def connect(self, host: str = "", port: int = 0, timeout: float = -999, source_address=None):
        _ = host
        self.host = self.original_host
        self.port = int(port or self.port or 21)
        if timeout != -999:
            self.timeout = timeout
        self.sock = socket.create_connection(
            (self.pinned_ip, self.port),
            self.timeout,
            source_address,
        )
        _verify_socket_peer(self.sock, self.pinned_ip, purpose="FTPS control socket")
        self.af = self.sock.family
        self.file = self.sock.makefile("r", encoding=self.encoding)
        self.welcome = self.getresp()
        return self.welcome

    def makepasv(self):
        _host, port = super().makepasv()
        if not 1 <= int(port) <= 65535:
            raise FileTransferError("invalid_passive_port", "FTP passive port is invalid")
        return self.pinned_ip, int(port)

    def ntransfercmd(self, cmd, rest=None):
        conn, size = super().ntransfercmd(cmd, rest)
        _verify_socket_peer(conn, self.pinned_ip, purpose="FTPS passive data socket")
        return conn, size


class FTPClient:
    def __init__(self, config: ConnectionConfig) -> None:
        self.config = config
        self._ftp: FTP | FTP_TLS | None = None

    def __enter__(self) -> FTPClient:
        ips = resolve_pinned_ips(self.config.host, port=self.config.port, purpose="FTP server")
        pinned_ip = ips[0]
        if self.config.use_tls:
            context = ssl.create_default_context()
            ftp: FTP | FTP_TLS = _PinnedFTPTLS(
                original_host=self.config.host,
                pinned_ip=pinned_ip,
                timeout=self.config.connect_timeout,
                context=context,
            )
        else:
            ftp = _PinnedFTP(
                original_host=self.config.host,
                pinned_ip=pinned_ip,
                timeout=self.config.connect_timeout,
            )
        try:
            ftp.connect(self.config.host, self.config.port, timeout=self.config.connect_timeout)
            if isinstance(ftp, FTP_TLS):
                ftp.auth()
            try:
                ftp.login(self.config.username, self.config.password)
            except error_perm as exc:
                if str(exc).startswith("530"):
                    raise FileTransferError(
                        "authentication_failed",
                        "FTP authentication failed",
                        external_effect_status="failed",
                        definitely_no_external_effect=True,
                    ) from exc
                raise
            if isinstance(ftp, FTP_TLS):
                ftp.prot_p()
            ftp.set_pasv(True)
            if ftp.sock is not None:
                ftp.sock.settimeout(self.config.read_timeout)
            ftp.cwd(self.config.root_path or ".")
            if not _as_str(ftp.pwd()):
                raise FileTransferError("invalid_connection", "FTP root_path could not be verified")
            self._ftp = ftp
            return self
        except Exception:
            with contextlib.suppress(Exception):
                ftp.close()
            raise

    def __exit__(self, exc_type, exc, tb) -> None:
        ftp = self._ftp
        if ftp is not None:
            try:
                ftp.quit()
            except Exception:
                ftp.close()

    @property
    def ftp(self) -> FTP | FTP_TLS:
        if self._ftp is None:
            raise RuntimeError("FTP client is not connected")
        return self._ftp

    def list_dir(self, path: str) -> tuple[list[RemoteEntry], bool]:
        entries: list[RemoteEntry] = []
        truncated = False
        raw_count = 0

        def _append_mlsd(line: str) -> None:
            nonlocal raw_count, truncated
            raw_count += 1
            if raw_count > MAX_RAW_DIRECTORY_ENTRIES:
                truncated = True
                raise _DirectoryLimitReached()
            facts_text, separator, raw_name = str(line).partition(" ")
            if not separator:
                return
            facts: dict[str, str] = {}
            for raw_fact in facts_text.split(";"):
                if "=" not in raw_fact:
                    continue
                key, value = raw_fact.split("=", 1)
                facts[key.lower()] = value
            name = raw_name.strip()
            if name in {"", ".", ".."}:
                return
            fact_type = str(facts.get("type") or "file").lower()
            if fact_type == "dir" or fact_type in {"os.unix=slink", "slink"}:
                return
            entries.append(
                RemoteEntry(
                    name=name,
                    path=_join_remote_path(path, name),
                    size_bytes=_as_int(facts.get("size"), -1)
                    if str(facts.get("size") or "").isdigit()
                    else None,
                    modified_at=_ftp_modify_to_iso(facts.get("modify")),
                    raw_modified=_ftp_modify_to_epoch(facts.get("modify")),
                    kind=fact_type,
                )
            )

        try:
            with contextlib.suppress(_DirectoryLimitReached):
                self.ftp.retrlines(f"MLSD {path}", _append_mlsd)
            return entries, truncated
        except Exception as exc:
            if raw_count:
                raise FileTransferError(
                    "transfer_failed", f"FTP MLSD failed after partial listing: {exc}"
                ) from exc
            entries = []
            truncated = False
            raw_count = 0

            def _append(raw_name: str) -> None:
                nonlocal raw_count, truncated
                raw_count += 1
                if raw_count > MAX_RAW_DIRECTORY_ENTRIES:
                    truncated = True
                    raise _DirectoryLimitReached()
                name = posixpath.basename(str(raw_name).rstrip("/"))
                if name in {"", ".", ".."}:
                    return
                remote_path = _join_remote_path(path, name)
                try:
                    size = self._size(remote_path)
                except Exception:
                    return
                entries.append(
                    RemoteEntry(
                        name=name,
                        path=remote_path,
                        size_bytes=int(size) if size is not None else None,
                    )
                )

            with contextlib.suppress(_DirectoryLimitReached):
                self.ftp.retrlines(f"NLST {path}", _append)
            return entries, truncated

    def _size(self, path: str) -> int | None:
        self.ftp.voidcmd("TYPE I")
        size = self.ftp.size(path)
        return int(size) if size is not None else None

    def stream_file(self, path: str) -> Iterator[bytes]:
        path = _validate_root_relative_path(path, allow_empty=False)
        self.ftp.voidcmd("TYPE I")
        with self.ftp.transfercmd(f"RETR {path}") as conn:
            conn.settimeout(self.config.read_timeout)
            while True:
                data = conn.recv(STREAM_CHUNK_BYTES)
                if not data:
                    break
                yield data
        self.ftp.voidresp()

    def stat_file(self, path: str) -> RemoteEntry:
        path = _validate_root_relative_path(path, allow_empty=False)
        try:
            size = self._size(path)
        except error_perm as exc:
            if str(exc).startswith("550"):
                if _ftp_550_is_not_found(exc):
                    raise FileTransferError(
                        "not_found", _MESSAGE_REMOTE_FILE_WAS_NOT_FOUND
                    ) from exc
                raise FileTransferError(
                    "not_supported_by_server",
                    f"FTP SIZE could not confirm file metadata: {exc}",
                ) from exc
            raise FileTransferError("not_supported_by_server", f"FTP SIZE failed: {exc}") from exc
        except Exception as exc:
            raise FileTransferError(
                "not_supported_by_server", f"FTP metadata lookup failed: {exc}"
            ) from exc
        return RemoteEntry(
            name=_basename(path), path=path, size_bytes=int(size) if size is not None else None
        )

    def upload_file(
        self, remote_path: str, chunks: Iterable[bytes], *, overwrite: bool
    ) -> dict[str, Any]:
        temp_path = _temporary_remote_path(remote_path)
        if not overwrite and self._remote_exists(remote_path):
            raise FileTransferError(
                "already_exists",
                _MESSAGE_REMOTE_PATH_ALREADY_EXISTS,
                external_effect_status="failed",
                definitely_no_external_effect=True,
            )
        reader = _ChunkReader(chunks)
        mutation_started = False
        try:
            mutation_started = True
            self.ftp.storbinary(f"STOR {temp_path}", reader, blocksize=STREAM_CHUNK_BYTES)
            if not overwrite and self._remote_exists(
                remote_path,
                definitely_no_external_effect=False,
            ):
                raise FileTransferError(
                    "already_exists",
                    _MESSAGE_REMOTE_PATH_ALREADY_EXISTS,
                    external_effect_status="timeout_unknown",
                    definitely_no_external_effect=False,
                )
            self.ftp.rename(temp_path, remote_path)
            final_size = self._remote_size(remote_path, definitely_no_external_effect=False)
            if final_size is None:
                raise FileTransferError(
                    "metadata_unknown",
                    "FTP final object size could not be confirmed",
                    external_effect_status="timeout_unknown",
                    definitely_no_external_effect=False,
                )
            if final_size != reader.bytes_read:
                raise FileTransferError(
                    "transfer_failed",
                    "FTP final object size did not match uploaded bytes",
                    external_effect_status="timeout_unknown",
                    definitely_no_external_effect=False,
                )
            return {"overwrite_protection": "best_effort", "remote_size_bytes": final_size}
        except FileTransferError as exc:
            with _suppress_remote_errors():
                self.ftp.delete(temp_path)
            if mutation_started and exc.definitely_no_external_effect:
                raise FileTransferError(
                    exc.code,
                    str(exc),
                    external_effect_status="timeout_unknown",
                    definitely_no_external_effect=False,
                ) from exc
            raise
        except ArtifactAccessError as exc:
            with _suppress_remote_errors():
                self.ftp.delete(temp_path)
            raise FileTransferError(
                "artifact_read_failed",
                str(exc),
                external_effect_status="timeout_unknown" if mutation_started else "failed",
                definitely_no_external_effect=not mutation_started,
            ) from exc
        except Exception as exc:
            with _suppress_remote_errors():
                self.ftp.delete(temp_path)
            raise FileTransferError(
                "transfer_failed",
                f"FTP upload failed: {exc}",
                external_effect_status="timeout_unknown" if mutation_started else "failed",
                definitely_no_external_effect=not mutation_started,
            ) from exc

    def _remote_size(self, path: str, *, definitely_no_external_effect: bool = True) -> int | None:
        try:
            return self._size(path)
        except Exception as exc:
            raise FileTransferError(
                "metadata_unknown",
                f"Could not verify FTP path size: {exc}",
                external_effect_status=(
                    "failed" if definitely_no_external_effect else "timeout_unknown"
                ),
                definitely_no_external_effect=definitely_no_external_effect,
            ) from exc

    def _remote_exists(self, path: str, *, definitely_no_external_effect: bool = True) -> bool:
        try:
            self._size(path)
            return True
        except error_perm as exc:
            if str(exc).startswith("550") and _ftp_550_is_not_found(exc):
                return False
            raise FileTransferError(
                "metadata_unknown",
                f"Could not verify FTP destination state: {exc}",
                external_effect_status=(
                    "failed" if definitely_no_external_effect else "timeout_unknown"
                ),
                definitely_no_external_effect=definitely_no_external_effect,
            ) from exc
        except Exception as exc:
            raise FileTransferError(
                "metadata_unknown",
                f"Could not verify FTP destination state: {exc}",
                external_effect_status=(
                    "failed" if definitely_no_external_effect else "timeout_unknown"
                ),
                definitely_no_external_effect=definitely_no_external_effect,
            ) from exc

    def exists(self, path: str) -> bool:
        try:
            return self._remote_exists(path)
        except FileTransferError:
            return False


class _suppress_remote_errors:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        return True


class _ChunkReader:
    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._iterator = iter(chunks)
        self._buffer = bytearray()
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        while size < 0 or len(self._buffer) < size:
            try:
                chunk = bytes(next(self._iterator))
                self.bytes_read += len(chunk)
                self._buffer.extend(chunk)
            except StopIteration:
                break
        if size < 0:
            size = len(self._buffer)
        out = bytes(self._buffer[:size])
        del self._buffer[:size]
        return out


def _ftp_modify_to_iso(value: Any) -> str | None:
    epoch = _ftp_modify_to_epoch(value)
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")


def _ftp_modify_to_epoch(value: Any) -> float | None:
    text = _as_str(value)
    if len(text) < 14 or not text[:14].isdigit():
        return None
    try:
        return datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC).timestamp()
    except Exception:
        return None


def _sftp_host_key_identity(key: Any, transport: Any) -> tuple[str, str]:
    key_type = str(getattr(transport, "host_key_type", "") or key.get_name() or "")
    if key_type.startswith(DISALLOWED_SFTP_KEY_TYPES) or not key_type.startswith(
        ALLOWED_HOST_KEY_PREFIXES
    ):
        raise FileTransferError("unsupported_host_key", "SFTP host key algorithm is not allowed")
    return key_type, _canonical_fingerprint(bytes(key.asbytes()))


class SFTPClient:
    def __init__(self, config: ConnectionConfig) -> None:
        self.config = config
        self._sock: socket.socket | None = None
        self._transport: Any = None
        self._sftp: Any = None
        self._root: str = ""

    def __enter__(self) -> SFTPClient:
        try:
            import paramiko  # type: ignore[import-untyped]
        except Exception as exc:
            raise FileTransferError(
                "dependency_unavailable", "Paramiko is required from extension-local wheels"
            ) from exc
        ips = resolve_pinned_ips(self.config.host, port=self.config.port, purpose="SFTP server")
        sock = None
        transport = None
        sftp = None
        try:
            sock = socket.create_connection((ips[0], self.config.port), self.config.connect_timeout)
            _verify_socket_peer(sock, ips[0], purpose="SFTP socket")
            if hasattr(sock, "settimeout"):
                sock.settimeout(self.config.read_timeout)
            transport = paramiko.Transport(
                sock,
                disabled_algorithms={"pubkeys": list(DISALLOWED_SFTP_PUBKEY_ALGORITHMS)},
            )
            _harden_paramiko_security_options(transport)
            transport.start_client(timeout=self.config.connect_timeout)
            key = transport.get_remote_server_key()
            self._verify_host_key(key, transport)
            try:
                if self.config.password:
                    transport.auth_password(
                        self.config.username, self.config.password, fallback=False
                    )
                else:
                    pkey = _load_private_key(
                        paramiko, self.config.private_key, self.config.private_key_passphrase
                    )
                    transport.auth_publickey(self.config.username, pkey)
            except Exception as exc:
                auth_error = getattr(paramiko, "AuthenticationException", None)
                if auth_error is not None and isinstance(exc, auth_error):
                    raise FileTransferError(
                        "authentication_failed",
                        "SFTP authentication failed",
                        external_effect_status="failed",
                        definitely_no_external_effect=True,
                    ) from exc
                raise
            if not transport.is_authenticated():
                raise FileTransferError("authentication_failed", "SFTP authentication failed")
            sftp = paramiko.SFTPClient.from_transport(transport)
            self._sock = sock
            self._transport = transport
            self._sftp = sftp
            self._root = self._canonical_root(self.config.root_path)
            return self
        except Exception:
            for handle in (sftp, transport, sock):
                if handle is not None:
                    with contextlib.suppress(Exception):
                        handle.close()
            raise

    def __exit__(self, exc_type, exc, tb) -> None:
        for handle in (self._sftp, self._transport, self._sock):
            if handle is not None:
                with contextlib.suppress(Exception):
                    handle.close()

    @property
    def sftp(self) -> Any:
        if self._sftp is None:
            raise RuntimeError("SFTP client is not connected")
        return self._sftp

    def _verify_host_key(self, key: Any, transport: Any) -> None:
        _key_type, actual = _sftp_host_key_identity(key, transport)
        if not hmac.compare_digest(actual, self.config.host_key_fingerprint):
            raise FileTransferError("host_key_mismatch", "SFTP host key fingerprint mismatch")

    def _canonical_root(self, root_path: str) -> str:
        root = _as_str(root_path or ".")
        normalized = self.sftp.normalize(root)
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        normalized = normalized.rstrip("/") or "/"
        try:
            attr = self.sftp.stat(normalized)
            mode = int(getattr(attr, "st_mode", 0) or 0)
        except Exception as exc:
            raise FileTransferError(
                "invalid_connection",
                f"SFTP root_path must be an existing directory: {exc}",
            ) from exc
        if not stat.S_ISDIR(mode):
            raise FileTransferError(
                "invalid_connection", "SFTP root_path must be an existing directory"
            )
        return normalized

    def _canonical_under_root(self, remote_path: str, *, parent: bool = False) -> str:
        lexical = _validate_root_relative_path(remote_path, allow_empty=True)
        candidate = self._root if lexical == "." else f"{self._root.rstrip('/')}/{lexical}"
        target = posixpath.dirname(candidate) if parent else candidate
        try:
            normalized = self.sftp.normalize(target)
        except Exception as exc:
            raise FileTransferError(
                "invalid_path",
                f"SFTP canonical path validation failed: {exc}",
            ) from exc
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        root = self._root.rstrip("/")
        if normalized != root and not normalized.startswith(f"{root}/"):
            raise FileTransferError("invalid_path", "SFTP path escapes connection root")
        if parent:
            return f"{normalized.rstrip('/')}/{_basename(remote_path)}"
        return normalized

    def list_dir(self, path: str) -> tuple[list[RemoteEntry], bool]:
        remote_dir = self._canonical_under_root(path)
        entries: list[RemoteEntry] = []
        truncated = False
        rows = (
            self.sftp.listdir_iter(remote_dir, read_aheads=1)
            if hasattr(self.sftp, "listdir_iter")
            else iter(self.sftp.listdir_attr(remote_dir))
        )
        raw_count = 0
        for attr in rows:
            raw_count += 1
            if raw_count > MAX_RAW_DIRECTORY_ENTRIES:
                truncated = True
                break
            name = str(attr.filename)
            if name in {"", ".", ".."}:
                continue
            mode = int(getattr(attr, "st_mode", 0) or 0)
            if stat.S_ISLNK(mode) or stat.S_ISDIR(mode):
                continue
            mtime = getattr(attr, "st_mtime", None)
            entries.append(
                RemoteEntry(
                    name=name,
                    path=_join_remote_path(path, name),
                    size_bytes=int(attr.st_size)
                    if getattr(attr, "st_size", None) is not None
                    else None,
                    modified_at=_epoch_to_iso(mtime),
                    raw_modified=float(mtime) if mtime is not None else None,
                )
            )
        return entries, truncated

    def stream_file(self, path: str) -> Iterator[bytes]:
        remote = self._canonical_under_root(path)
        with self.sftp.open(remote, "rb") as handle:
            channel = handle.get_channel() if hasattr(handle, "get_channel") else None
            if channel is not None and hasattr(channel, "settimeout"):
                channel.settimeout(self.config.read_timeout)
            while True:
                chunk = handle.read(STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                yield bytes(chunk)

    def stat_file(self, path: str) -> RemoteEntry:
        remote = self._canonical_under_root(path)
        try:
            attr = self.sftp.stat(remote)
        except FileNotFoundError as exc:
            raise FileTransferError("not_found", _MESSAGE_REMOTE_FILE_WAS_NOT_FOUND) from exc
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.ENOENT:
                raise FileTransferError("not_found", _MESSAGE_REMOTE_FILE_WAS_NOT_FOUND) from exc
            raise FileTransferError(
                "metadata_unknown", f"SFTP metadata lookup failed: {exc}"
            ) from exc
        mode = int(getattr(attr, "st_mode", 0) or 0)
        if stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
            raise FileTransferError("not_found", "Remote path is not a regular file")
        return RemoteEntry(
            name=_basename(path),
            path=path,
            size_bytes=int(attr.st_size) if getattr(attr, "st_size", None) is not None else None,
            modified_at=_epoch_to_iso(getattr(attr, "st_mtime", None)),
            raw_modified=float(getattr(attr, "st_mtime", 0) or 0) or None,
        )

    def upload_file(
        self, remote_path: str, chunks: Iterable[bytes], *, overwrite: bool
    ) -> dict[str, Any]:
        final_path = self._canonical_under_root(remote_path, parent=True)
        final_path = f"{posixpath.dirname(final_path).rstrip('/')}/{_basename(remote_path)}"
        temp_path = _temporary_remote_path(final_path)
        overwrite_existing = False
        if overwrite:
            overwrite_existing = self._remote_exists(final_path)
        elif self._remote_exists(final_path):
            raise FileTransferError(
                "already_exists",
                _MESSAGE_REMOTE_PATH_ALREADY_EXISTS,
                external_effect_status="failed",
                definitely_no_external_effect=True,
            )
        bytes_written = 0
        mutation_started = False
        try:
            mutation_started = True
            with self.sftp.open(temp_path, "xb") as handle:
                channel = handle.get_channel() if hasattr(handle, "get_channel") else None
                if channel is not None and hasattr(channel, "settimeout"):
                    channel.settimeout(self.config.read_timeout)
                for chunk in chunks:
                    bytes_written += len(chunk)
                    handle.write(chunk)
                if hasattr(handle, "flush"):
                    handle.flush()
            if overwrite:
                if overwrite_existing or self._remote_exists(
                    final_path,
                    definitely_no_external_effect=False,
                ):
                    self._posix_rename(temp_path, final_path)
                else:
                    self.sftp.rename(temp_path, final_path)
            else:
                if self._remote_exists(
                    final_path,
                    definitely_no_external_effect=False,
                ):
                    raise FileTransferError(
                        "already_exists",
                        _MESSAGE_REMOTE_PATH_ALREADY_EXISTS,
                        external_effect_status="timeout_unknown",
                        definitely_no_external_effect=False,
                    )
                self.sftp.rename(temp_path, final_path)
            final_size = self._remote_size(final_path, definitely_no_external_effect=False)
            if final_size is None:
                raise FileTransferError(
                    "metadata_unknown",
                    "SFTP final object size could not be confirmed",
                    external_effect_status="timeout_unknown",
                    definitely_no_external_effect=False,
                )
            if final_size != bytes_written:
                raise FileTransferError(
                    "transfer_failed",
                    "SFTP final object size did not match uploaded bytes",
                    external_effect_status="timeout_unknown",
                    definitely_no_external_effect=False,
                )
            return {"overwrite_protection": "best_effort", "remote_size_bytes": final_size}
        except FileTransferError as exc:
            with _suppress_remote_errors():
                self.sftp.remove(temp_path)
            if mutation_started and exc.definitely_no_external_effect:
                raise FileTransferError(
                    exc.code,
                    str(exc),
                    external_effect_status="timeout_unknown",
                    definitely_no_external_effect=False,
                ) from exc
            raise
        except ArtifactAccessError as exc:
            with _suppress_remote_errors():
                self.sftp.remove(temp_path)
            raise FileTransferError(
                "artifact_read_failed",
                str(exc),
                external_effect_status="timeout_unknown" if mutation_started else "failed",
                definitely_no_external_effect=not mutation_started,
            ) from exc
        except Exception as exc:
            with _suppress_remote_errors():
                self.sftp.remove(temp_path)
            raise FileTransferError(
                "transfer_failed",
                f"SFTP upload failed: {exc}",
                external_effect_status="timeout_unknown" if mutation_started else "failed",
                definitely_no_external_effect=not mutation_started,
            ) from exc

    def _posix_rename(self, source: str, dest: str) -> None:
        try:
            self.sftp.posix_rename(source, dest)
        except AttributeError as exc:
            raise FileTransferError(
                "not_supported_by_server",
                "SFTP client does not expose atomic overwrite support",
                external_effect_status="timeout_unknown",
                definitely_no_external_effect=False,
            ) from exc
        except Exception as exc:
            if _sftp_operation_unsupported(exc):
                raise FileTransferError(
                    "not_supported_by_server",
                    "SFTP server does not support atomic overwrite of an existing destination",
                    external_effect_status="timeout_unknown",
                    definitely_no_external_effect=False,
                ) from exc
            raise

    def _remote_size(self, path: str, *, definitely_no_external_effect: bool = True) -> int | None:
        try:
            attr = self.sftp.stat(path)
            value = getattr(attr, "st_size", None)
            return int(value) if value is not None else None
        except Exception as exc:
            raise FileTransferError(
                "metadata_unknown",
                f"Could not verify SFTP path size: {exc}",
                external_effect_status=(
                    "failed" if definitely_no_external_effect else "timeout_unknown"
                ),
                definitely_no_external_effect=definitely_no_external_effect,
            ) from exc

    def _remote_exists(self, path: str, *, definitely_no_external_effect: bool = True) -> bool:
        try:
            self.sftp.stat(path)
            return True
        except FileNotFoundError:
            return False
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.ENOENT:
                return False
            raise FileTransferError(
                "metadata_unknown",
                f"Could not verify SFTP destination state: {exc}",
                external_effect_status=(
                    "failed" if definitely_no_external_effect else "timeout_unknown"
                ),
                definitely_no_external_effect=definitely_no_external_effect,
            ) from exc
        except Exception as exc:
            raise FileTransferError(
                "metadata_unknown",
                f"Could not verify SFTP destination state: {exc}",
                external_effect_status=(
                    "failed" if definitely_no_external_effect else "timeout_unknown"
                ),
                definitely_no_external_effect=definitely_no_external_effect,
            ) from exc

    def exists(self, path: str) -> bool:
        try:
            return self._remote_exists(path)
        except FileTransferError:
            return False


def _harden_paramiko_security_options(transport: Any) -> None:
    options = (
        transport.get_security_options() if hasattr(transport, "get_security_options") else None
    )
    if options is None or not hasattr(options, "key_types"):
        return
    options.key_types = tuple(
        key_type
        for key_type in tuple(options.key_types)
        if not str(key_type).startswith(DISALLOWED_SFTP_KEY_TYPES)
    )


def _discover_sftp_host_key(config: HostKeyDiscoveryConfig) -> dict[str, str]:
    try:
        import paramiko
    except Exception as exc:
        raise FileTransferError(
            "dependency_unavailable", "Paramiko is required from extension-local wheels"
        ) from exc
    ips = resolve_pinned_ips(config.host, port=config.port, purpose="SFTP server")
    sock = None
    transport = None
    try:
        sock = socket.create_connection((ips[0], config.port), config.connect_timeout)
        _verify_socket_peer(sock, ips[0], purpose="SFTP socket")
        if hasattr(sock, "settimeout"):
            sock.settimeout(config.read_timeout)
        transport = paramiko.Transport(
            sock,
            disabled_algorithms={"pubkeys": list(DISALLOWED_SFTP_PUBKEY_ALGORITHMS)},
        )
        _harden_paramiko_security_options(transport)
        transport.start_client(timeout=config.connect_timeout)
        key_type, fingerprint = _sftp_host_key_identity(
            transport.get_remote_server_key(), transport
        )
        return {"host_key_type": key_type, "host_key_fingerprint": fingerprint}
    finally:
        for handle in (transport, sock):
            if handle is not None:
                with contextlib.suppress(Exception):
                    handle.close()


def _sftp_operation_unsupported(exc: Exception) -> bool:
    unsupported_errnos = {
        value
        for value in (
            getattr(errno, "ENOSYS", None),
            getattr(errno, "EOPNOTSUPP", None),
            getattr(errno, "ENOTSUP", None),
        )
        if isinstance(value, int)
    }
    err_no = getattr(exc, "errno", None)
    if isinstance(err_no, int) and err_no in unsupported_errnos:
        return True
    text = str(exc).strip().lower()
    return any(
        phrase in text
        for phrase in (
            "operation unsupported",
            "unsupported operation",
            "not supported",
            "not implemented",
        )
    )


def _load_private_key(paramiko: Any, private_key: str, passphrase: str) -> Any:
    errors: list[str] = []
    for key_cls_name in ("Ed25519Key", "ECDSAKey", "RSAKey"):
        key_cls = getattr(paramiko, key_cls_name, None)
        if key_cls is None:
            continue
        try:
            return key_cls.from_private_key(
                io.StringIO(private_key),
                password=passphrase or None,
            )
        except Exception as exc:
            errors.append(str(exc))
    raise FileTransferError("invalid_private_key", "SFTP private key could not be loaded")


def _epoch_to_iso(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), UTC).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _temporary_remote_path(remote_path: str) -> str:
    directory = posixpath.dirname(remote_path)
    name = posixpath.basename(remote_path)
    temp_name = f".{name}.flowsteward-{uuid.uuid4().hex}.tmp"
    return f"{directory}/{temp_name}" if directory else temp_name


def _client_for(config: ConnectionConfig):
    return SFTPClient(config) if config.connection_type == "sftp" else FTPClient(config)


def _filter_entries(
    entries: list[RemoteEntry],
    *,
    name_glob: str,
    limit: int,
    raw_truncated: bool,
) -> tuple[list[RemoteEntry], bool]:
    pattern = _as_str(name_glob)
    if pattern and "/" in pattern:
        raise FileTransferError("invalid_payload", "name_glob must match basenames only")
    filtered = [
        entry for entry in entries if not pattern or fnmatch.fnmatchcase(entry.name, pattern)
    ]
    filtered.sort(key=lambda entry: entry.name)
    truncated = raw_truncated or len(filtered) > limit
    return filtered[:limit], truncated


def _entry_dict(entry: RemoteEntry) -> dict[str, Any]:
    return {
        "name": entry.name,
        "size_bytes": entry.size_bytes,
        "modified_at": entry.modified_at,
    }


def _select_entry(entries: list[RemoteEntry], *, selector: str, protocol: str) -> RemoteEntry:
    if not entries:
        raise FileTransferError("not_found", "No matching file was found")
    if selector == "only":
        if len(entries) != 1:
            raise FileTransferError("ambiguous_match", "More than one file matched")
        return entries[0]
    if selector == "latest_name":
        return max(entries, key=lambda entry: entry.name)
    if selector == "latest_modified":
        if any(entry.raw_modified is None for entry in entries):
            raise FileTransferError(
                "not_supported_by_server",
                f"{protocol.upper()} did not provide reliable modification metadata",
            )
        return max(entries, key=lambda entry: (entry.raw_modified or 0, entry.name))
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
) -> tuple[Iterator[bytes], dict[str, Any]]:
    state: dict[str, Any] = {"size_bytes": 0, "sha256": hashlib.sha256()}

    def _iter() -> Iterator[bytes]:
        for chunk in chunks:
            data = bytes(chunk)
            state["size_bytes"] += len(data)
            if state["size_bytes"] > max_bytes:
                raise FileTransferError("max_bytes_exceeded", "Transfer exceeded max_bytes")
            state["sha256"].update(data)
            if progress is not None:
                progress(state["size_bytes"], False)
            yield data
        if progress is not None:
            progress(state["size_bytes"], True)

    return _iter(), state


def _handle_list_files(payload: dict[str, Any], config: ConnectionConfig) -> dict[str, Any]:
    input_payload = _input_payload(payload)
    if "path" not in input_payload or _as_str(input_payload.get("path")) == "":
        raise FileTransferError("invalid_payload", "path is required")
    path = _validate_root_relative_path(input_payload.get("path"), allow_empty=True)
    limit = _strict_int(
        input_payload.get("limit"),
        default=200,
        field="limit",
        error_code="invalid_payload",
        minimum=1,
        maximum=MAX_LIST_LIMIT,
    )
    with _client_for(config) as client:
        entries, raw_truncated = client.list_dir(path)
    filtered, truncated = _filter_entries(
        entries,
        name_glob=_as_str(input_payload.get("name_glob")),
        limit=limit,
        raw_truncated=raw_truncated,
    )
    return {
        "ok": True,
        "result": {"files": [_entry_dict(row) for row in filtered], "truncated": truncated},
    }


def _handle_test_connection(config: ConnectionConfig) -> dict[str, Any]:
    with _client_for(config):
        return {
            "ok": True,
            "result": {
                "protocol": config.connection_type,
                "use_tls": config.use_tls if config.connection_type == "ftp" else None,
            },
        }


def _handle_discover_host_key(payload: dict[str, Any]) -> dict[str, Any]:
    discovery = _discover_sftp_host_key(_host_key_discovery_config(payload))
    return {"ok": True, "result": {"protocol": "sftp", **discovery}}


def _handle_fetch_file(payload: dict[str, Any], config: ConnectionConfig) -> dict[str, Any]:
    input_payload = _input_payload(payload)
    max_bytes = _effective_max_bytes(input_payload, _artifact_output_limit(payload))
    name_glob = _as_str(input_payload.get("name_glob"))
    # `path` is a directory when a glob selects the file inside it, and the file
    # itself otherwise. The connection root is `.` in the directory case, exactly
    # as it is for list_files; validating it as a file path made the root the one
    # place a glob could not be used.
    raw_path = _as_str(input_payload.get("path"))
    if not name_glob and raw_path.strip() in {"", "."}:
        raise FileTransferError(
            "invalid_path",
            "path must name a file when no name_glob is given; "
            "to fetch from the connection root, pass path '.' together with a name_glob",
        )
    path = _validate_root_relative_path(input_payload.get("path"), allow_empty=bool(name_glob))
    selector = _as_str(input_payload.get("select") or "only")
    with _client_for(config) as client:
        if name_glob:
            entries, raw_truncated = client.list_dir(path)
            if raw_truncated:
                raise FileTransferError("directory_too_large", "Directory exceeded 500 raw entries")
            filtered, _ = _filter_entries(
                entries,
                name_glob=name_glob,
                limit=MAX_RAW_DIRECTORY_ENTRIES,
                raw_truncated=False,
            )
            selected = _select_entry(filtered, selector=selector, protocol=config.connection_type)
            remote_path = selected.path
            metadata_size = selected.size_bytes
        else:
            remote_path = path
            selected = client.stat_file(remote_path)
            metadata_size = selected.size_bytes
        if metadata_size is not None and metadata_size > max_bytes:
            raise FileTransferError("max_bytes_exceeded", "Remote file exceeds max_bytes")
        chunks, state = _hashing_chunks(
            client.stream_file(remote_path),
            max_bytes=max_bytes,
            progress=_transfer_progress("Downloading", selected.name, total_bytes=metadata_size),
        )
        try:
            write_result = write_artifact_stream(
                payload,
                chunks,
                binding_key=ARTIFACT_BINDING_KEY,
                content_type=OCTET_STREAM,
                timeout_seconds=config.read_timeout,
            )
        except ArtifactAccessError as exc:
            raise FileTransferError("artifact_write_failed", str(exc)) from exc
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
    artifact_handle = _as_str(
        write_result.get("artifact_handle") or write_result.get("artifact_id")
    )
    if not artifact_handle:
        raise FileTransferError("artifact_write_failed", "Artifact write did not return a handle")
    reported_size = write_result.get("size_bytes")
    if reported_size is None:
        raise FileTransferError("artifact_write_failed", "Artifact write did not return size_bytes")
    if _as_int(reported_size, -1) != size_bytes:
        raise FileTransferError(
            "artifact_write_failed", "Artifact write size did not match streamed bytes"
        )
    reported_sha = _as_str(
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
    handle = _as_str(value)
    if not handle:
        raise FileTransferError("invalid_payload", "artifact_handle is required")
    return handle


def _handle_upload_file(payload: dict[str, Any], config: ConnectionConfig) -> dict[str, Any]:
    input_payload = _input_payload(payload)
    artifact_handle = _input_artifact_handle(input_payload)
    remote_path = _validate_root_relative_path(input_payload.get("remote_path"), allow_empty=False)
    overwrite = _as_bool(input_payload.get("overwrite"), default=False)
    try:
        artifact_limit = _artifact_input_limit(payload, artifact_handle=artifact_handle)
    except ArtifactAccessError as exc:
        raise FileTransferError("artifact_read_failed", str(exc)) from exc
    max_bytes = _effective_max_bytes(input_payload, artifact_limit)
    try:
        artifact_size = _artifact_input_size(payload, artifact_handle=artifact_handle)
        if artifact_size is not None and artifact_size > max_bytes:
            raise FileTransferError("max_bytes_exceeded", "Artifact exceeds max_bytes")
        artifact_stream = stream_artifact_bytes(
            payload,
            artifact_id=artifact_handle,
            binding_key=UPLOAD_ARTIFACT_BINDING_KEY,
            chunk_size=STREAM_CHUNK_BYTES,
            timeout_seconds=config.read_timeout,
        )
    except ArtifactAccessError as exc:
        raise FileTransferError("artifact_read_failed", str(exc)) from exc
    chunks, state = _hashing_chunks(
        artifact_stream,
        max_bytes=max_bytes,
        progress=_transfer_progress("Uploading", _basename(remote_path), total_bytes=artifact_size),
    )
    try:
        with _client_for(config) as client:
            result = client.upload_file(remote_path, chunks, overwrite=overwrite)
    except ArtifactAccessError as exc:
        raise FileTransferError("artifact_read_failed", str(exc)) from exc
    return {
        "ok": True,
        "result": {
            "uploaded": True,
            "remote_path": remote_path,
            "sha256": state["sha256"].hexdigest(),
            "size_bytes": state["size_bytes"],
            "overwrite_protection": result.get("overwrite_protection") or "best_effort",
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


def _failure_response(code: str, message: str, **fields: Any) -> dict[str, Any]:
    return {
        "ok": False,
        "error_code": code,
        "error": message,
        "errors": [{"code": code, "message": message}],
        **fields,
    }


def handle_payload(payload: dict[str, Any]) -> dict[str, Any]:
    redaction_payload = payload if isinstance(payload, dict) else {}
    try:
        if not isinstance(payload, dict):
            raise FileTransferError("invalid_payload", "Request payload must be a JSON object")
        operation = _operation_id(payload)
        runtime_context = _as_dict(payload.get("runtime_context"))
        if operation == "upload_file" and _as_bool(runtime_context.get("test_mode")):
            return _suppressed_upload_response()
        if operation == "discover_host_key":
            return _handle_discover_host_key(payload)
        config = _connection_config(payload)
        if operation == "test_connection":
            return _handle_test_connection(config)
        if operation == "list_files":
            return _handle_list_files(payload, config)
        if operation == "fetch_file":
            return _handle_fetch_file(payload, config)
        if operation == "upload_file":
            return _handle_upload_file(payload, config)
        raise FileTransferError("unknown_action", "Unsupported file transfer action")
    except (PinnedPeerError, TimeoutError) as exc:
        return _failure_response(
            "network_blocked",
            _redact_error(exc, redaction_payload),
            definitely_no_external_effect=True,
            external_effect_status="failed",
        )
    except FileTransferError as exc:
        payload_out = _failure_response(
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
        return _failure_response(
            "transfer_failed",
            _redact_error(exc, redaction_payload),
            definitely_no_external_effect=False,
            external_effect_status="timeout_unknown",
        )
