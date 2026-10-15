"""A small S3-compatible server over TLS on loopback, for transport-level tests.

It speaks just enough of the S3 REST API for the S3 connection: ListObjectsV2
with a delimiter, GetObject, PutObject with If-None-Match, and multipart
uploads. Hooks let a test answer a route with an error, a redirect or a dropped
connection. A second listener on another loopback address is the decoy: any
request it receives means traffic left the configured endpoint.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ssl
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
ENDPOINT_HOST = "s3.test"
SERVER_IP = "127.0.0.1"
DECOY_IP = "127.0.0.2"
LAST_MODIFIED = dt.datetime(2026, 10, 1, 10, 0, tzinfo=dt.UTC)


def write_certificates(directory: Path, names: list[str]) -> tuple[Path, Path, Path]:
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake s3 ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    paths = (directory / "ca.pem", directory / "cert.pem", directory / "key.pem")
    paths[0].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths[1].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    paths[2].write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return paths


def s3_error(status: int, code: str, headers: dict[str, str] | None = None) -> web.Response:
    body = f"<Error><Code>{code}</Code><Message>{code}</Message></Error>"
    return web.Response(
        status=status, body=body.encode(), content_type="application/xml", headers=headers
    )


@dataclass
class Seen:
    method: str
    host: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body_len: int


@dataclass
class FakeS3:
    bucket: str = "data"
    objects: dict[str, bytes] = field(default_factory=dict)
    uploads: dict[str, dict[int, bytes]] = field(default_factory=dict)
    aborted: list[str] = field(default_factory=list)
    seen: list[Seen] = field(default_factory=list)
    decoy_seen: list[str] = field(default_factory=list)
    hooks: dict[str, Callable[[web.Request], Any]] = field(default_factory=dict)
    page_size: int = 1000
    port: int = 0
    decoy_port: int = 0

    # -- server lifecycle --------------------------------------------------------

    def start(self, cert: Path, key: Path) -> None:
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self._thread = threading.Thread(target=self._serve, args=(context,), daemon=True)
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("fake S3 did not start")

    def _serve(self, context: ssl.SSLContext) -> None:
        asyncio.set_event_loop(self._loop)

        async def _start() -> None:
            app = web.Application(client_max_size=64 * 1024 * 1024)
            app.router.add_route("*", "/{tail:.*}", self._handle)
            self._runner = web.AppRunner(app)
            await self._runner.setup()
            site = web.TCPSite(self._runner, SERVER_IP, 0, ssl_context=context)
            await site.start()
            self.port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
            decoy = web.Application()
            decoy.router.add_route("*", "/{tail:.*}", self._decoy)
            self._decoy_runner = web.AppRunner(decoy)
            await self._decoy_runner.setup()
            decoy_site = web.TCPSite(self._decoy_runner, DECOY_IP, 0, ssl_context=context)
            await decoy_site.start()
            self.decoy_port = decoy_site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

        self._loop.run_until_complete(_start())
        self._ready.set()
        self._loop.run_forever()

    def stop(self) -> None:
        async def _stop() -> None:
            await self._runner.cleanup()
            await self._decoy_runner.cleanup()

        asyncio.run_coroutine_threadsafe(_stop(), self._loop).result(10)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(10)
        self._loop.close()

    # -- request handling ------------------------------------------------------

    async def _decoy(self, request: web.Request) -> web.Response:
        self.decoy_seen.append(f"{request.method} {request.host}{request.path_qs}")
        return web.Response(text="decoy")

    def routes(self) -> list[str]:
        return [_route(seen.method, seen.query) for seen in self.seen]

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        body = await request.read()
        query = dict(request.query)
        host = request.host.split(":")[0]
        self.seen.append(
            Seen(request.method, host, request.path, query, dict(request.headers), len(body))
        )
        route = _route(request.method, query)
        hook = self.hooks.get(route)
        if hook is not None:
            result = hook(request)
            if asyncio.iscoroutine(result):
                result = await result
            if result is not None:
                return result
        if host == f"{self.bucket}.{ENDPOINT_HOST}":
            bucket, key = self.bucket, request.path.lstrip("/")
        else:
            bucket, _, key = request.path.lstrip("/").partition("/")
        if bucket != self.bucket:
            return s3_error(404, "NoSuchBucket")
        handler = getattr(self, "_" + route)
        return await handler(request, key, body, query)

    async def _list(self, request, key, body, query) -> web.Response:
        prefix = query.get("prefix", "")
        delimiter = query.get("delimiter", "")
        max_keys = int(query.get("max-keys", "1000"))
        start = int(query.get("continuation-token", "0") or 0)
        rows: list[tuple[str, str]] = []
        seen_prefixes: set[str] = set()
        for name in sorted(self.objects):
            if not name.startswith(prefix):
                continue
            rest = name[len(prefix) :]
            if delimiter and delimiter in rest:
                common = prefix + rest.split(delimiter, 1)[0] + delimiter
                if common not in seen_prefixes:
                    seen_prefixes.add(common)
                    rows.append(("prefix", common))
                continue
            rows.append(("key", name))
        page = rows[start : start + min(max_keys, self.page_size)]
        more = start + len(page) < len(rows)
        parts = [f'<ListBucketResult xmlns="{NS}"><Name>{self.bucket}</Name>']
        parts.append(f"<Prefix>{escape(prefix)}</Prefix><KeyCount>{len(page)}</KeyCount>")
        parts.append(f"<MaxKeys>{max_keys}</MaxKeys><IsTruncated>{str(more).lower()}</IsTruncated>")
        if more:
            parts.append(f"<NextContinuationToken>{start + len(page)}</NextContinuationToken>")
        for kind, value in page:
            if kind == "prefix":
                parts.append(f"<CommonPrefixes><Prefix>{escape(value)}</Prefix></CommonPrefixes>")
            else:
                parts.append(
                    f"<Contents><Key>{escape(value)}</Key>"
                    f"<LastModified>{LAST_MODIFIED.strftime('%Y-%m-%dT%H:%M:%S.000Z')}</LastModified>"
                    f'<ETag>"e"</ETag><Size>{len(self.objects[value])}</Size>'
                    "<StorageClass>STANDARD</StorageClass></Contents>"
                )
        parts.append("</ListBucketResult>")
        return web.Response(body="".join(parts).encode(), content_type="application/xml")

    async def _get(self, request, key, body, query) -> web.StreamResponse:
        if key not in self.objects:
            return s3_error(404, "NoSuchKey")
        data = self.objects[key]
        response = web.StreamResponse(
            headers={
                "Content-Length": str(len(data)),
                "Last-Modified": LAST_MODIFIED.strftime("%a, %d %b %Y %H:%M:%S GMT"),
                "ETag": '"e"',
            }
        )
        await response.prepare(request)
        for offset in range(0, len(data), 256 * 1024):
            await response.write(data[offset : offset + 256 * 1024])
        await response.write_eof()
        return response

    async def _put(self, request, key, body, query) -> web.Response:
        if request.headers.get("If-None-Match") == "*" and key in self.objects:
            return s3_error(412, "PreconditionFailed")
        self.objects[key] = body
        return web.Response(headers={"ETag": '"e"'})

    async def _create_multipart(self, request, key, body, query) -> web.Response:
        upload_id = uuid.uuid4().hex
        self.uploads[upload_id] = {}
        xml = (
            f'<InitiateMultipartUploadResult xmlns="{NS}"><Bucket>{self.bucket}</Bucket>'
            f"<Key>{escape(key)}</Key><UploadId>{upload_id}</UploadId>"
            "</InitiateMultipartUploadResult>"
        )
        return web.Response(body=xml.encode(), content_type="application/xml")

    async def _upload_part(self, request, key, body, query) -> web.Response:
        self.uploads[query["uploadId"]][int(query["partNumber"])] = body
        return web.Response(headers={"ETag": f'"p{query["partNumber"]}"'})

    async def _complete_multipart(self, request, key, body, query) -> web.Response:
        if request.headers.get("If-None-Match") == "*" and key in self.objects:
            return s3_error(412, "PreconditionFailed")
        parts = self.uploads.pop(query["uploadId"])
        self.objects[key] = b"".join(parts[number] for number in sorted(parts))
        xml = (
            f'<CompleteMultipartUploadResult xmlns="{NS}"><Bucket>{self.bucket}</Bucket>'
            f'<Key>{escape(key)}</Key><ETag>"m"</ETag></CompleteMultipartUploadResult>'
        )
        return web.Response(body=xml.encode(), content_type="application/xml")

    async def _abort_multipart(self, request, key, body, query) -> web.Response:
        self.uploads.pop(query["uploadId"], None)
        self.aborted.append(query["uploadId"])
        return web.Response(status=204)


def _route(method: str, query: dict[str, str]) -> str:
    if method == "GET" and query.get("list-type") == "2":
        return "list"
    if method == "POST" and "uploads" in query:
        return "create_multipart"
    if method == "PUT" and "uploadId" in query:
        return "upload_part"
    if method == "POST" and "uploadId" in query:
        return "complete_multipart"
    if method == "DELETE" and "uploadId" in query:
        return "abort_multipart"
    return {"GET": "get", "PUT": "put"}.get(method, "unsupported")
