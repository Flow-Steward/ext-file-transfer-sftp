"""S3-compatible connections over an isolated aiobotocore client.

The client is built per invocation from the connection's explicit keys only: no
environment, profile, config file, instance metadata or plugin is consulted, no
proxy is used and botocore never retries. Every TCP connection goes to the one
endpoint address validated before the client existed, with TLS checked against
the configured host name. The bucket and root prefix are fixed for the whole
invocation; a new object is created only with a conditional write.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import os
import re
import socket
from collections.abc import Awaitable, Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import aiobotocore.session
import botocore.configprovider
import botocore.exceptions
import botocore.plugin
from aiobotocore.config import AioConfig
from aiobotocore.credentials import AioCredentialResolver
from aiohttp.abc import AbstractResolver
from flowsteward_extension_sdk import resolve_pinned_ips

import file_transfer_extension as protocol
from connections import exact_pieces
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

MiB = 1024 * 1024
#: Size of every multipart part but the last.
UPLOAD_PART_BYTES = 8 * MiB
READ_ATTEMPTS = 3
#: Time allowed to abort our own multipart upload once the operation has failed.
ABORT_GRACE_SECONDS = 10.0
OCTET_STREAM = "application/octet-stream"
_REGION_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_PATH_STYLE_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_VIRTUAL_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")


@dataclass(frozen=True)
class S3Config:
    endpoint_url: str
    host: str
    port: int
    region: str
    bucket: str
    root_prefix: str
    addressing_style: str
    connect_timeout: float
    read_timeout: float
    access_key_id: str
    secret_access_key: str
    session_token: str

    @property
    def request_host(self) -> str:
        """The host name every request is sent to and every certificate is checked against."""
        return f"{self.bucket}.{self.host}" if self.addressing_style == "virtual" else self.host


def parse_s3_config(payload: dict[str, Any]) -> S3Config:
    """Validate an S3 connection before any network use."""
    connection = protocol._connection_payload(payload)
    settings = protocol._connection_settings(connection)
    secrets = protocol._as_dict(connection.get("secrets"))

    endpoint_url = protocol._as_str(settings.get("endpoint_url"))
    parts = urlsplit(endpoint_url)
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise FileTransferError("invalid_connection", "S3 endpoint port is invalid") from exc
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise FileTransferError(
            "invalid_connection",
            "S3 endpoint must be an https origin without credentials, path, query or fragment",
        )
    host = parts.hostname.lower()
    region = protocol._as_str(settings.get("region"))
    if not _REGION_RE.fullmatch(region):
        raise FileTransferError("invalid_connection", "S3 region is required")
    addressing_style = protocol._as_str(settings.get("addressing_style") or "path").lower()
    if addressing_style not in {"path", "virtual"}:
        raise FileTransferError("invalid_connection", "S3 addressing_style must be path or virtual")
    bucket = protocol._as_str(settings.get("bucket"))
    bucket_re = _VIRTUAL_BUCKET_RE if addressing_style == "virtual" else _PATH_STYLE_BUCKET_RE
    if not bucket_re.fullmatch(bucket) or ".." in bucket:
        raise FileTransferError(
            "invalid_connection",
            "S3 bucket name is invalid"
            + (" for virtual-host addressing" if addressing_style == "virtual" else ""),
        )
    raw_prefix = settings.get("root_prefix")
    root_prefix = (
        ""
        if raw_prefix in (None, "", ".")
        else protocol._validate_root_relative_path(raw_prefix, allow_empty=False)
    )
    access_key_id = protocol._as_secret_str(secrets.get("access_key_id"))
    secret_access_key = protocol._as_secret_str(secrets.get("secret_access_key"))
    session_token = protocol._as_secret_str(secrets.get("session_token"))
    if not access_key_id or not secret_access_key:
        # Refused here, before a client exists: there is no other credential source.
        raise FileTransferError(
            "invalid_connection", "S3 access_key_id and secret_access_key are required"
        )
    for value, field in (
        (access_key_id, "access_key_id"),
        (secret_access_key, "secret_access_key"),
        (session_token, "session_token"),
    ):
        if protocol._has_control_characters(value):
            raise FileTransferError("invalid_connection", f"S3 {field} is malformed")
    return S3Config(
        endpoint_url=f"https://{host}" + (f":{parts.port}" if parts.port else ""),
        host=host,
        port=port,
        region=region,
        bucket=bucket,
        root_prefix=root_prefix,
        addressing_style=addressing_style,
        connect_timeout=protocol._clamp_timeout(
            settings.get("connect_timeout_seconds"), default=15, maximum=60
        ),
        read_timeout=protocol._clamp_timeout(
            settings.get("read_timeout_seconds"), default=30, maximum=300
        ),
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token,
    )


class _PinnedResolver(AbstractResolver):
    """Resolves only the configured request host, and only to the validated address."""

    def __init__(self, host: str, ip: str) -> None:
        self._host = host
        self._ip = ip

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> list[Any]:
        if host.lower().rstrip(".") != self._host:
            raise OSError("S3 request host is not the configured endpoint")
        return [
            {
                "hostname": host,  # TLS server name and certificate check use the real name
                "host": self._ip,
                "port": port,
                "family": socket.AF_INET6 if ":" in self._ip else socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
        ]

    async def close(self) -> None:
        return None


class _PinnedSocketFactory:
    """Creates a socket only for the validated (address, port); IP-literal URLs included."""

    def __init__(self, ip: str, port: int) -> None:
        self._allowed = (ip, port)

    def __call__(self, addr_info: Any) -> socket.socket:
        family, type_, proto, _canonname, sockaddr = addr_info
        if (str(sockaddr[0]), int(sockaddr[1])) != self._allowed:
            raise OSError("S3 connection target is outside the configured endpoint")
        return socket.socket(family=family, type=type_, proto=proto)


def _isolated_session() -> aiobotocore.session.AioSession:
    """A session that reads no AWS_* variable or AWS file and has no credential providers."""
    session_vars = {
        name: (None, None, default, convert)
        for name, (
            _config,
            _env,
            default,
            convert,
        ) in botocore.configprovider.BOTOCORE_DEFAUT_SESSION_VARIABLES.items()
    }
    session_vars.update(
        {
            "profile": (None, None, None, None),
            "config_file": (None, None, os.devnull, None),
            "credentials_file": (None, None, os.devnull, None),
            "data_path": (None, None, None, None),
            "ca_bundle": (None, None, None, None),
            "region": (None, None, None, None),
            "ignore_configured_endpoint_urls": (None, None, True, None),
            "defaults_mode": (None, None, "legacy", None),
            "retry_mode": (None, None, "standard", None),
            "max_attempts": (None, None, 1, int),
            "request_checksum_calculation": (None, None, "when_required", None),
            "response_checksum_validation": (None, None, "when_required", None),
            "use_dualstack_endpoint": (None, None, False, None),
            "use_fips_endpoint": (None, None, False, None),
            "ec2_metadata_service_endpoint": (None, None, None, None),
        }
    )
    session = aiobotocore.session.AioSession(session_vars=session_vars)
    session.register_component("credential_provider", AioCredentialResolver(providers=[]))
    return session


class _Timeout(Exception):
    pass


class S3Connection:
    """One invocation, one client, one event loop; all closed on exit."""

    def __init__(
        self,
        config: S3Config,
        deadline: Deadline,
        *,
        verify: bool | str | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._config = config
        self._deadline = deadline
        # The host's trust store (SSL_CERT_FILE is passed to extensions on purpose);
        # AWS_CA_BUNDLE and every other AWS_* variable are ignored.
        self._verify = verify if verify is not None else (os.environ.get("SSL_CERT_FILE") or True)
        self._sleep = sleep
        self._loop: asyncio.AbstractEventLoop | None = None
        self._client_context: Any = None
        self._client: Any = None

    # -- lifecycle ------------------------------------------------------------

    def open(self) -> S3Connection:
        config = self._config
        (pinned_ip, *_rest) = resolve_pinned_ips(
            config.request_host, port=config.port, purpose="S3 endpoint"
        )
        # An experimental botocore switch can import modules named in the environment.
        botocore.plugin.set_plugin_context(botocore.plugin.PluginContext(plugins="DISABLED"))
        for name in ("botocore", "aiobotocore"):
            logging.getLogger(name).setLevel(logging.WARNING)  # DEBUG would log headers
        client_config = AioConfig(
            region_name=config.region,
            signature_version="s3v4",
            s3={"addressing_style": config.addressing_style},
            proxies={},  # empty, not None: None makes botocore read *_PROXY variables
            retries={"total_max_attempts": 1, "mode": "standard"},
            max_pool_connections=1,
            connect_timeout=config.connect_timeout,
            read_timeout=config.read_timeout,
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
            connector_args={
                "resolver": _PinnedResolver(config.request_host, pinned_ip),
                "socket_factory": _PinnedSocketFactory(pinned_ip, config.port),
                "use_dns_cache": False,
            },
        )
        self._loop = asyncio.new_event_loop()
        self._client_context = _isolated_session().create_client(
            "s3",
            endpoint_url=config.endpoint_url,
            region_name=config.region,
            aws_access_key_id=config.access_key_id,
            aws_secret_access_key=config.secret_access_key,
            aws_session_token=config.session_token or None,
            verify=self._verify,
            config=client_config,
        )
        try:
            self._client = self._run(self._client_context.__aenter__())
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        loop, self._loop = self._loop, None
        context, self._client_context = self._client_context, None
        if loop is None:
            return
        try:
            if context is not None and self._client is not None:
                with contextlib.suppress(Exception):
                    loop.run_until_complete(
                        asyncio.wait_for(context.__aexit__(None, None, None), ABORT_GRACE_SECONDS)
                    )
        finally:
            self._client = None
            loop.close()

    # -- the three operations -------------------------------------------------

    def list_files(self, request: ListRequest) -> FilePage:
        budget = max(1, int(request.limit))
        prefix = self._directory_prefix(request.path)
        files: list[RemoteFile] = []
        raw_seen = 0
        token: str | None = None
        while True:
            arguments: dict[str, Any] = {
                "Bucket": self._config.bucket,
                "Prefix": prefix,
                "Delimiter": "/",
                "MaxKeys": min(1000, budget + 1 - raw_seen),
            }
            if token:
                arguments["ContinuationToken"] = token
            page = self._read(functools.partial(self._client.list_objects_v2, **arguments))
            for _common_prefix in page.get("CommonPrefixes") or []:
                raw_seen += 1
                if raw_seen > budget:
                    return FilePage(files=tuple(files), truncated=True)
            for item in page.get("Contents") or []:
                raw_seen += 1
                if raw_seen > budget:
                    return FilePage(files=tuple(files), truncated=True)
                remote = _object_file(item, prefix=prefix, directory=request.path)
                if remote is not None:
                    files.append(remote)
            if not page.get("IsTruncated"):
                files.sort(key=lambda row: row.name)
                return FilePage(files=tuple(files), truncated=False)
            token = page.get("NextContinuationToken")
            if not isinstance(token, str) or not token:
                raise FileTransferError("provider_unavailable", "S3 returned an invalid listing")

    def fetch_file(self, path: str) -> RemoteDownload:
        key = self._key(path)
        response = self._read(lambda: self._client.get_object(Bucket=self._config.bucket, Key=key))
        body = response["Body"]
        modified = response.get("LastModified")
        remote = RemoteFile(
            name=protocol._basename(path),
            remote_path=path,
            size_bytes=_optional_size(response.get("ContentLength")),
            modified_at=_iso(modified),
            raw_modified=_epoch(modified),
        )
        return RemoteDownload(file=remote, chunks=_BodyChunks(self, body))

    def upload_file(
        self, remote_path: str, chunks: Iterable[bytes], options: UploadOptions
    ) -> UploadResult:
        key = self._key(remote_path)
        condition = {} if options.overwrite else {"IfNoneMatch": "*"}
        # Always multipart, even for one small part: the commit is then
        # CompleteMultipartUpload, a POST. aiohttp silently resends an idempotent
        # request (PutObject is a PUT) once after a dropped connection, and a
        # resent conditional create would turn our own committed write into a
        # false "already exists". Parts are invisible until the commit, so a
        # resent part changes nothing.
        self._multipart(key, _at_least_one(exact_pieces(chunks, UPLOAD_PART_BYTES)), condition)
        return UploadResult(
            remote_path=remote_path, remote_size_bytes=None, overwrite_protection="atomic"
        )

    def check_root(self) -> None:
        """Read at most one key below the root prefix: no write, no bucket enumeration."""
        prefix = f"{self._config.root_prefix}/" if self._config.root_prefix else ""
        self._read(
            lambda: self._client.list_objects_v2(
                Bucket=self._config.bucket, Prefix=prefix, Delimiter="/", MaxKeys=1
            )
        )

    # -- paths --------------------------------------------------------------

    def _key(self, relative: str) -> str:
        parts = [part for part in (self._config.root_prefix, relative) if part and part != "."]
        return "/".join(parts)

    def _directory_prefix(self, relative: str) -> str:
        key = self._key(relative)
        return f"{key}/" if key else ""

    # -- requests -----------------------------------------------------------

    def _run(self, awaitable: Awaitable[Any], *, grace: float | None = None) -> Any:
        if self._loop is None:
            raise RuntimeError("S3 connection is not open")
        remaining = grace if grace is not None else self._deadline.remaining()
        if remaining <= 0:
            with contextlib.suppress(Exception):
                awaitable.close()  # type: ignore[attr-defined]
            raise _Timeout()
        try:
            return self._loop.run_until_complete(asyncio.wait_for(awaitable, remaining))
        except TimeoutError as exc:
            raise _Timeout() from exc

    def _read(self, call: Callable[[], Awaitable[Any]]) -> Any:
        """A request that changes nothing: three attempts at most, within the deadline."""
        for attempt in range(1, READ_ATTEMPTS + 1):
            try:
                return self._run(call())
            except botocore.exceptions.ClientError as exc:
                status = _status(exc)
                retryable = status == 429 or status >= 500 or _code(exc) == "SlowDown"
                if (
                    not retryable
                    or attempt == READ_ATTEMPTS
                    or attempt >= self._deadline.remaining()
                ):
                    raise _read_error(exc) from exc
                (self._sleep or _blocking_sleep)(float(attempt))
            except _Timeout as exc:
                raise FileTransferError("timeout", "S3 request exceeded the deadline") from exc
            except (botocore.exceptions.BotoCoreError, OSError) as exc:
                raise _transport_error(exc) from exc
        raise AssertionError("unreachable")  # pragma: no cover

    def _write(self, call: Callable[[], Awaitable[Any]]) -> Any:
        """A step before the commit: whatever happens, no object becomes visible."""
        try:
            return self._run(call())
        except botocore.exceptions.ClientError as exc:
            raise _read_error(exc) from exc
        except _Timeout as exc:
            raise FileTransferError("timeout", "S3 request exceeded the deadline") from exc
        except (botocore.exceptions.BotoCoreError, OSError) as exc:
            raise _transport_error(exc) from exc

    def _commit(self, call: Callable[[], Awaitable[Any]]) -> Any:
        """The one request that creates or replaces the object; never repeated."""
        try:
            return self._run(call())
        except botocore.exceptions.ClientError as exc:
            status = _status(exc)
            if status >= 500 and _code(exc) not in {"NotImplemented"}:
                raise unknown_outcome(
                    "timeout_unknown", f"S3 commit failed with HTTP {status}"
                ) from exc
            raise _commit_error(exc) from exc
        except _Timeout as exc:
            raise unknown_outcome("timeout_unknown", "S3 commit exceeded the deadline") from exc
        except (botocore.exceptions.BotoCoreError, OSError) as exc:
            if isinstance(exc, botocore.exceptions.EndpointConnectionError):
                raise _transport_error(exc) from exc  # never connected: nothing was sent
            raise unknown_outcome(
                "timeout_unknown", f"S3 commit was interrupted: {type(exc).__name__}"
            ) from exc

    def _multipart(self, key: str, pieces: Iterator[bytes], condition: dict[str, str]) -> None:
        bucket = self._config.bucket
        created = self._write(
            lambda: self._client.create_multipart_upload(
                Bucket=bucket, Key=key, ContentType=OCTET_STREAM
            )
        )
        upload_id = created.get("UploadId")
        if not isinstance(upload_id, str) or not upload_id:
            raise FileTransferError("provider_unavailable", "S3 returned an invalid upload id")
        parts: list[dict[str, Any]] = []
        try:
            for number, piece in enumerate(pieces, start=1):
                answer = self._write(
                    functools.partial(
                        self._client.upload_part,
                        Bucket=bucket,
                        Key=key,
                        UploadId=upload_id,
                        PartNumber=number,
                        Body=piece,
                    )
                )
                parts.append({"PartNumber": number, "ETag": answer.get("ETag")})
            self._commit(
                lambda: self._client.complete_multipart_upload(
                    Bucket=bucket,
                    Key=key,
                    UploadId=upload_id,
                    MultipartUpload={"Parts": parts},
                    **condition,
                )
            )
        except FileTransferError as exc:
            if exc.external_effect_status != "timeout_unknown":
                self._abort(key, upload_id)
            raise
        except BaseException:
            self._abort(key, upload_id)
            raise

    def _abort(self, key: str, upload_id: str) -> None:
        """Remove our own unfinished parts; never touches an existing object."""
        with contextlib.suppress(Exception):
            self._run(
                self._client.abort_multipart_upload(
                    Bucket=self._config.bucket, Key=key, UploadId=upload_id
                ),
                grace=ABORT_GRACE_SECONDS,
            )


class _BodyChunks:
    """A one-shot object stream read in pieces of at most 1 MiB."""

    def __init__(self, connection: S3Connection, body: Any) -> None:
        self._connection = connection
        self._body = body
        self._closed = False

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        if self._closed:
            raise StopIteration
        try:
            chunk = self._connection._run(self._body.read(STREAM_CHUNK_BYTES))
        except _Timeout as exc:
            self.close()
            raise FileTransferError("timeout", "S3 download exceeded the deadline") from exc
        except (botocore.exceptions.BotoCoreError, OSError) as exc:
            self.close()
            raise FileTransferError(
                "provider_unavailable", f"S3 download was interrupted: {type(exc).__name__}"
            ) from exc
        if not chunk:
            self.close()
            raise StopIteration
        return bytes(chunk)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            with contextlib.suppress(Exception):
                self._body.close()


def _blocking_sleep(seconds: float) -> None:
    import time

    time.sleep(seconds)


def _at_least_one(pieces: Iterator[bytes]) -> Iterator[bytes]:
    """An empty file is still one (empty) part."""
    sent = False
    for piece in pieces:
        sent = True
        yield piece
    if not sent:
        yield b""


def _object_file(item: Any, *, prefix: str, directory: str) -> RemoteFile | None:
    if not isinstance(item, dict):
        return None
    key = item.get("Key")
    if not isinstance(key, str) or not key.startswith(prefix):
        return None
    name = key[len(prefix) :]
    if not name or name.endswith("/"):
        return None  # a directory marker, not a file
    try:
        remote_path = protocol._join_remote_path(directory, name)
    except FileTransferError:
        return None  # counted against the scan budget, but not representable as a path
    modified = item.get("LastModified")
    return RemoteFile(
        name=name,
        remote_path=remote_path,
        size_bytes=_optional_size(item.get("Size")),
        modified_at=_iso(modified),
        raw_modified=_epoch(modified),
    )


def _optional_size(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _epoch(value: Any) -> float | None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        return None
    return value.timestamp()


def _iso(value: Any) -> str | None:
    epoch = _epoch(value)
    return protocol._epoch_to_iso(epoch) if epoch is not None else None


def _status(exc: botocore.exceptions.ClientError) -> int:
    metadata = exc.response.get("ResponseMetadata") or {}
    try:
        return int(metadata.get("HTTPStatusCode") or 0)
    except (TypeError, ValueError):
        return 0


def _code(exc: botocore.exceptions.ClientError) -> str:
    return str((exc.response.get("Error") or {}).get("Code") or "")


def _read_error(exc: botocore.exceptions.ClientError) -> FileTransferError:
    """An S3 answer that definitely changed nothing."""
    status, code = _status(exc), _code(exc)
    if code in {"InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken", "InvalidToken"}:
        return FileTransferError("authentication_failed", "S3 rejected the connection keys")
    if code == "NoSuchBucket":
        return FileTransferError("invalid_connection", "S3 bucket was not found")
    if status == 404 or code in {"NoSuchKey", "NotFound"}:
        return FileTransferError("not_found", "Remote file was not found")
    if status == 403:
        return FileTransferError("permission_denied", "S3 refused access to this path")
    if status == 429 or code == "SlowDown":
        return FileTransferError("rate_limited", "S3 rate limit reached")
    if 300 <= status < 400:
        return FileTransferError("network_blocked", "S3 answered with a redirect")
    return FileTransferError("provider_unavailable", f"S3 answered HTTP {status or 'error'}")


def _commit_error(exc: botocore.exceptions.ClientError) -> FileTransferError:
    status, code = _status(exc), _code(exc)
    if status in {409, 412} or code in {"PreconditionFailed", "ConditionalRequestConflict"}:
        return FileTransferError("already_exists", "Remote path already exists")
    if status == 501 or code == "NotImplemented":
        return FileTransferError(
            "not_supported_by_server", "This S3 service does not support conditional writes"
        )
    return _read_error(exc)


def _transport_error(exc: BaseException) -> FileTransferError:
    if isinstance(exc, botocore.exceptions.SSLError):
        return FileTransferError("network_blocked", "S3 endpoint TLS verification failed")
    return FileTransferError(
        "provider_unavailable", f"S3 endpoint is unreachable: {type(exc).__name__}"
    )


def open_s3(payload: dict[str, Any], deadline: Deadline) -> S3Connection:
    """Validate the connection, then build its client; the caller must close it."""
    return S3Connection(parse_s3_config(payload), deadline).open()
