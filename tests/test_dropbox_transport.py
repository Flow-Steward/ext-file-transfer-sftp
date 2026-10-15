"""Dropbox requests through the SDK's real pinned HTTPS opener, against a loopback TLS server.

Loopback is only reachable because the test sets the host's private-network
switch for itself; the connection under test never learns about it.
"""

from __future__ import annotations

import datetime as dt
import json
import ssl
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from connections import dropbox as dbx
from file_connections import Deadline, ListRequest
from file_errors import FileTransferError

MiB = 1024 * 1024


def _cert(tmp: Path, hostname: str) -> tuple[Path, Path, Path]:
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test ca")])
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
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, cert_path, key_path = tmp / "ca.pem", tmp / "cert.pem", tmp / "key.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, *args: object) -> None:
        return None

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        self.server.seen.append((self.path, self.headers.get("Authorization"), body))
        route = self.path.removeprefix("/2/")
        if route == "files/list_folder":
            entries = [{".tag": "file", "name": f"{i}.csv", "size": i} for i in range(3)]
            self._json({"entries": entries, "has_more": False, "cursor": "c"})
        elif route == "files/download":
            data = b"d" * (2 * MiB + 3)
            self.send_response(200)
            self.send_header("Dropbox-API-Result", json.dumps({"name": "a.bin", "size": len(data)}))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif route == "files/get_metadata":
            self.send_response(307)
            self.send_header("Location", self.server.elsewhere)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def _json(self, value: object) -> None:
        raw = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _Server(ThreadingHTTPServer):
    seen: list[tuple[str, str | None, bytes]]
    elsewhere: str


def _serve(cert: Path, key: Path) -> tuple[_Server, threading.Thread]:
    server = _Server(("127.0.0.1", 0), _Handler)
    server.seen = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def tls_dropbox(tmp_path, monkeypatch) -> Iterator[tuple[_Server, str]]:
    ca, cert, key = _cert(tmp_path, "localhost")
    monkeypatch.setenv("SSL_CERT_FILE", str(ca))
    monkeypatch.setenv("FS_ALLOW_PRIVATE_REMOTE_URLS", "1")
    server, thread = _serve(cert, key)
    elsewhere, other_thread = _serve(cert, key)
    server.elsewhere = f"https://localhost:{elsewhere.server_address[1]}/2/files/get_metadata"
    try:
        yield server, f"https://localhost:{server.server_address[1]}"
        assert elsewhere.seen == [], "a redirect must never reach another origin"
    finally:
        for running in (server, elsewhere):
            running.shutdown()
            running.server_close()
        thread.join(5)
        other_thread.join(5)


def _connection(origin: str, *, token: str = "tok-live") -> dbx.DropboxConnection:
    return dbx.DropboxConnection(
        access_token=token,
        root_path=".",
        deadline=Deadline(60),
        api_origin=origin,
        content_origin=origin,
    )


def test_listing_through_the_real_pinned_opener(tls_dropbox):
    server, origin = tls_dropbox

    page = _connection(origin).list_files(ListRequest(path=".", limit=500))

    assert [row.name for row in page.files] == ["0.csv", "1.csv", "2.csv"]
    assert server.seen[0][1] == "Bearer tok-live"


def test_download_streams_through_http_client(tls_dropbox):
    _server, origin = tls_dropbox

    download = _connection(origin).fetch_file("a.bin")
    sizes = [len(chunk) for chunk in download.chunks]

    assert sum(sizes) == 2 * MiB + 3
    assert max(sizes) <= MiB


def test_redirect_is_refused_and_never_followed(tls_dropbox):
    _server, origin = tls_dropbox

    with pytest.raises(FileTransferError) as raised:
        _connection(origin)._rpc_read("files/get_metadata", {"path": "/x"}, limit=1024)

    assert raised.value.code == "network_blocked"


def test_tls_hostname_is_verified(tmp_path, monkeypatch):
    ca, cert, key = _cert(tmp_path, "not-dropbox.example")
    monkeypatch.setenv("SSL_CERT_FILE", str(ca))
    monkeypatch.setenv("FS_ALLOW_PRIVATE_REMOTE_URLS", "1")
    server, thread = _serve(cert, key)
    try:
        origin = f"https://localhost:{server.server_address[1]}"
        with pytest.raises(FileTransferError) as raised:
            _connection(origin).list_files(ListRequest(path=".", limit=500))
        assert raised.value.code == "provider_unavailable"
        assert server.seen == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_loopback_is_blocked_without_the_private_network_switch(tls_dropbox, monkeypatch):
    server, origin = tls_dropbox
    monkeypatch.delenv("FS_ALLOW_PRIVATE_REMOTE_URLS")

    with pytest.raises(FileTransferError) as raised:
        _connection(origin).list_files(ListRequest(path=".", limit=500))

    assert raised.value.code == "network_blocked"
    assert raised.value.definitely_no_external_effect is True
    assert server.seen == []


def test_non_dropbox_origin_is_refused_before_any_request():
    connection = _connection("https://api.dropboxapi.com")

    with pytest.raises(FileTransferError) as raised:
        connection._open(
            "https://evil.example/2/files/list_folder", headers={}, data=b"", purpose="x"
        )

    assert raised.value.code == "network_blocked"
