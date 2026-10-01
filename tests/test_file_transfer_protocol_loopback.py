from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import posixpath
import socket
import socketserver
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import file_transfer_extension as ft

FTP_HOSTNAME = "files.loopback.test"
FTPS_HOSTNAME = "secure-files.loopback.test"
SFTP_HOSTNAME = "sftp.loopback.test"


def _fingerprint(blob: bytes) -> str:
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _ftp_config(*, host: str, port: int, use_tls: bool) -> ft.ConnectionConfig:
    return ft.ConnectionConfig(
        connection_type="ftp",
        host=host,
        port=port,
        root_path=".",
        use_tls=use_tls,
        allow_insecure_ftp=not use_tls,
        host_key_fingerprint="",
        connect_timeout=5,
        read_timeout=5,
        username="user",
        password="secret",
        private_key="",
        private_key_passphrase="",
    )


def _sftp_config(*, port: int, host_key: Any, password: str = "secret") -> ft.ConnectionConfig:
    return ft.ConnectionConfig(
        connection_type="sftp",
        host=SFTP_HOSTNAME,
        port=port,
        root_path="jail",
        use_tls=True,
        allow_insecure_ftp=False,
        host_key_fingerprint=_fingerprint(bytes(host_key.asbytes())),
        connect_timeout=5,
        read_timeout=5,
        username="user",
        password=password,
        private_key="",
        private_key_passphrase="",
    )


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _FTPHandler(socketserver.BaseRequestHandler):
    server: _FTPServer

    def setup(self) -> None:
        self._reader = self.request.makefile("rb")
        self._data_listener: socket.socket | None = None

    def finish(self) -> None:
        with contextlib.suppress(Exception):
            self._reader.close()
        if self._data_listener is not None:
            with contextlib.suppress(Exception):
                self._data_listener.close()

    def handle(self) -> None:
        self._send("220 loopback ready")
        while True:
            line = self._readline()
            if line is None:
                return
            command, argument = self._parse(line)
            self.server.commands.append(command if not argument else f"{command} {argument}")
            if command == "AUTH" and argument.upper() == "TLS" and self.server.ssl_context:
                self._send("234 proceed with negotiation")
                self._reader.close()
                self.request = self.server.ssl_context.wrap_socket(
                    self.request,
                    server_side=True,
                )
                self._reader = self.request.makefile("rb")
            elif command == "USER":
                self._send("331 password required")
            elif command == "PASS":
                self._send("230 logged in")
            elif command == "PBSZ":
                self._send("200 PBSZ=0")
            elif command == "PROT":
                self.server.prot_private = argument.upper() == "P"
                self._send("200 private data channel enabled")
            elif command == "TYPE":
                self._send("200 type set")
            elif command == "CWD":
                self._send("250 directory changed")
            elif command == "PWD":
                self._send('257 "/"')
            elif command == "PASV":
                self._enter_passive_mode()
            elif command == "MLSD":
                self._send_directory_listing()
            elif command == "SIZE":
                self._send_size(argument)
            elif command == "RETR":
                self._send_file(argument)
            elif command == "QUIT":
                self._send("221 bye")
                return
            else:
                self._send("502 command not implemented")

    def _readline(self) -> str | None:
        raw = self._reader.readline()
        if not raw:
            return None
        return raw.decode("utf-8", errors="replace").rstrip("\r\n")

    @staticmethod
    def _parse(line: str) -> tuple[str, str]:
        command, separator, argument = line.partition(" ")
        return command.upper(), argument.strip() if separator else ""

    def _send(self, line: str) -> None:
        self.request.sendall(f"{line}\r\n".encode())

    def _enter_passive_mode(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self._data_listener = listener
        port = int(listener.getsockname()[1])
        p1, p2 = divmod(port, 256)
        host = self.server.passive_advertised_host.replace(".", ",")
        self._send(f"227 Entering Passive Mode ({host},{p1},{p2})")

    def _send_directory_listing(self) -> None:
        rows = []
        for child in sorted(self.server.root.iterdir()):
            if child.is_file():
                rows.append(
                    f"type=file;size={child.stat().st_size};modify=20260711120000; {child.name}"
                )
        self._send_data(("\r\n".join(rows) + "\r\n").encode("utf-8"))

    def _send_size(self, argument: str) -> None:
        path = self.server.root / posixpath.basename(argument)
        if not path.is_file():
            self._send("550 No such file")
            return
        self._send(f"213 {path.stat().st_size}")

    def _send_file(self, argument: str) -> None:
        path = self.server.root / posixpath.basename(argument)
        if not path.is_file():
            self._send("550 No such file")
            return
        self._send_data(path.read_bytes())

    def _send_data(self, payload: bytes) -> None:
        if self._data_listener is None:
            self._send("425 passive mode required")
            return
        self._send("150 opening data connection")
        conn, _addr = self._data_listener.accept()
        try:
            if self.server.ssl_context and self.server.prot_private:
                conn = self.server.ssl_context.wrap_socket(conn, server_side=True)
                self.server.data_tls_sessions += 1
            conn.sendall(payload)
        finally:
            with contextlib.suppress(Exception):
                conn.close()
            with contextlib.suppress(Exception):
                self._data_listener.close()
            self._data_listener = None
        self._send("226 transfer complete")


class _FTPServer(_ThreadedTCPServer):
    def __init__(
        self,
        root: Path,
        *,
        use_tls: bool = False,
        ssl_context: ssl.SSLContext | None = None,
        passive_advertised_host: str = "127.0.0.1",
    ) -> None:
        super().__init__(("127.0.0.1", 0), _FTPHandler)
        self.root = root
        self.ssl_context = ssl_context if use_tls else None
        self.passive_advertised_host = passive_advertised_host
        self.commands: list[str] = []
        self.prot_private = False
        self.data_tls_sessions = 0
        self.sni_names: list[str | None] = []
        if self.ssl_context is not None:
            self.ssl_context.set_servername_callback(cast(Any, self._record_sni))
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def __enter__(self) -> _FTPServer:
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()
        self.server_close()
        self._thread.join(timeout=2)

    def _record_sni(
        self,
        _sock: ssl.SSLSocket | ssl.SSLObject,
        server_name: str | None,
        _context: ssl.SSLContext,
    ) -> None:
        self.sni_names.append(server_name)


def _ftps_contexts(tmp_path: Path, hostname: str) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path = tmp_path / "ftps.key"
    cert_path = tmp_path / "ftps.crt"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(cert_path), str(key_path))
    client_context = ssl.create_default_context(cafile=str(cert_path))
    client_context.check_hostname = True
    return server_context, client_context


def test_plain_ftp_loopback_ignores_pasv_host_and_streams_file(tmp_path, monkeypatch) -> None:
    (tmp_path / "data.txt").write_bytes(b"plain ftp payload")
    monkeypatch.setattr(ft, "resolve_pinned_ips", lambda *args, **kwargs: ["127.0.0.1"])

    with (
        _FTPServer(
            tmp_path,
            passive_advertised_host="203.0.113.77",
        ) as server,
        ft.FTPClient(_ftp_config(host=FTP_HOSTNAME, port=server.port, use_tls=False)) as client,
    ):
        entries, truncated = client.list_dir(".")
        body = b"".join(client.stream_file("data.txt"))

    assert truncated is False
    assert [entry.name for entry in entries] == ["data.txt"]
    assert body == b"plain ftp payload"
    assert any(command == "PASV" for command in server.commands)
    assert server.passive_advertised_host == "203.0.113.77"


def test_ftps_loopback_verifies_hostname_and_uses_private_data_tls(
    tmp_path,
    monkeypatch,
) -> None:
    (tmp_path / "data.txt").write_bytes(b"ftps payload")
    server_context, client_context = _ftps_contexts(tmp_path, FTPS_HOSTNAME)
    monkeypatch.setattr(ft, "resolve_pinned_ips", lambda *args, **kwargs: ["127.0.0.1"])
    monkeypatch.setattr(ft.ssl, "create_default_context", lambda: client_context)

    with (
        _FTPServer(tmp_path, use_tls=True, ssl_context=server_context) as server,
        ft.FTPClient(_ftp_config(host=FTPS_HOSTNAME, port=server.port, use_tls=True)) as client,
    ):
        body = b"".join(client.stream_file("data.txt"))

    assert body == b"ftps payload"
    assert FTPS_HOSTNAME in server.sni_names
    assert server.prot_private is True
    assert server.data_tls_sessions >= 1
    assert server.commands.index("PASS secret") < server.commands.index("PBSZ 0")
    assert server.commands.index("PBSZ 0") < server.commands.index("PROT P")


class _PasswordSFTPServer:
    def __init__(self, paramiko: Any) -> None:
        self._paramiko = paramiko

    def check_auth_password(self, username: str, password: str) -> int:
        if username == "user" and password == "secret":
            return int(self._paramiko.AUTH_SUCCESSFUL)
        return int(self._paramiko.AUTH_FAILED)

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def get_banner(self) -> tuple[None, None]:
        return None, None

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return int(self._paramiko.OPEN_SUCCEEDED)
        return int(self._paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def check_channel_subsystem_request(self, channel: Any, name: str) -> bool:
        transport = channel.get_transport()
        handler_class, args, kwargs = transport._get_subsystem_handler(name)
        if handler_class is None:
            return False
        handler = handler_class(channel, name, self, *args, **kwargs)
        handler.start()
        return True


class _LoopbackSFTPInterface:
    def __init__(self, server: Any, *args: Any, root: str, outside: str, **kwargs: Any) -> None:
        super().__init__(server, *args, **kwargs)  # type: ignore[call-arg]
        self._paramiko = __import__("paramiko")
        self.root = Path(root).resolve()
        self.outside = Path(outside).resolve()
        self.virtual_root = "/jail"

    def _local_path(self, path: str) -> Path:
        text = str(path or ".")
        if text in {"", "."} or text == self.virtual_root.lstrip("/"):
            text = self.virtual_root
        if not text.startswith("/"):
            text = f"{self.virtual_root}/{text}"
        normalized = posixpath.normpath(text)
        if normalized == self.virtual_root:
            return self.root
        if normalized.startswith(f"{self.virtual_root}/"):
            return self.root / normalized[len(self.virtual_root) + 1 :]
        if normalized.startswith("/outside/"):
            return self.outside / normalized[len("/outside/") :]
        return self.root / "__denied__"

    def _virtual_path_for(self, local_path: Path) -> str:
        resolved = local_path.resolve(strict=False)
        if resolved.is_relative_to(self.root):
            relative = resolved.relative_to(self.root)
            suffix = "" if str(relative) == "." else f"/{relative.as_posix()}"
            return f"{self.virtual_root}{suffix}"
        return f"/outside/{resolved.name}"

    def canonicalize(self, path: str) -> str:
        return self._virtual_path_for(self._local_path(path))

    def stat(self, path: str) -> Any:
        return self._attributes(path, follow_symlinks=True)

    def lstat(self, path: str) -> Any:
        return self._attributes(path, follow_symlinks=False)

    def list_folder(self, path: str) -> Any:
        local = self._local_path(path)
        if not local.is_dir():
            return self._paramiko.SFTP_NO_SUCH_FILE
        rows = []
        for child in sorted(local.iterdir()):
            rows.append(self._paramiko.SFTPAttributes.from_stat(child.lstat(), filename=child.name))
        return rows

    def open(self, path: str, flags: int, attr: Any) -> Any:
        del attr
        if flags & (os.O_WRONLY | os.O_RDWR):
            return self._paramiko.SFTP_PERMISSION_DENIED
        local = self._local_path(path)
        if not local.is_file():
            return self._paramiko.SFTP_NO_SUCH_FILE
        handle = self._paramiko.SFTPHandle(flags)
        handle.readfile = local.open("rb")
        return handle

    def _attributes(self, path: str, *, follow_symlinks: bool) -> Any:
        local = self._local_path(path)
        try:
            stat_result = local.stat() if follow_symlinks else local.lstat()
        except FileNotFoundError:
            return self._paramiko.SFTP_NO_SUCH_FILE
        return self._paramiko.SFTPAttributes.from_stat(stat_result)


class _SFTPLoopbackServer:
    def __init__(self, root: Path, outside: Path, host_key: Any) -> None:
        self.root = root
        self.outside = outside
        self.host_key = host_key
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._stop = threading.Event()
        self._transport: Any = None
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def port(self) -> int:
        return int(self._listener.getsockname()[1])

    def __enter__(self) -> _SFTPLoopbackServer:
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop.set()
        with contextlib.suppress(Exception):
            self._listener.close()
        if self._transport is not None:
            with contextlib.suppress(Exception):
                self._transport.close()
        self._thread.join(timeout=2)

    def _serve(self) -> None:
        try:
            client, _addr = self._listener.accept()
        except OSError:
            return
        paramiko = __import__("paramiko")
        transport = paramiko.Transport(client)
        self._transport = transport
        transport.add_server_key(self.host_key)
        transport.set_subsystem_handler(
            "sftp",
            paramiko.SFTPServer,
            type(
                "_BoundLoopbackSFTPInterface",
                (_LoopbackSFTPInterface, paramiko.SFTPServerInterface),
                {},
            ),
            root=str(self.root),
            outside=str(self.outside),
        )
        transport.start_server(server=_PasswordSFTPServer(paramiko))
        while not self._stop.is_set() and transport.is_active():
            time.sleep(0.05)
        transport.close()


def test_sftp_loopback_uses_real_paramiko_and_blocks_symlink_escape(
    tmp_path,
    monkeypatch,
) -> None:
    paramiko = __import__("paramiko")

    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "inside.txt").write_bytes(b"inside")
    (outside / "secret.txt").write_bytes(b"outside")
    (root / "link.txt").symlink_to(outside / "secret.txt")
    host_key = paramiko.RSAKey.generate(2048)
    monkeypatch.setattr(ft, "resolve_pinned_ips", lambda *args, **kwargs: ["127.0.0.1"])

    with (
        _SFTPLoopbackServer(root, outside, host_key) as server,
        ft.SFTPClient(_sftp_config(port=server.port, host_key=host_key)) as client,
    ):
        entries, truncated = client.list_dir(".")
        stat_result = client.stat_file("inside.txt")
        body = b"".join(client.stream_file("inside.txt"))
        with pytest.raises(ft.FileTransferError) as exc_info:
            list(client.stream_file("link.txt"))

    assert truncated is False
    assert [entry.name for entry in entries] == ["inside.txt"]
    assert stat_result.size_bytes == len(b"inside")
    assert body == b"inside"
    assert exc_info.value.code == "invalid_path"


def test_sftp_loopback_reports_real_authentication_failure(tmp_path, monkeypatch) -> None:
    paramiko = __import__("paramiko")
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    host_key = paramiko.RSAKey.generate(2048)
    monkeypatch.setattr(ft, "resolve_pinned_ips", lambda *args, **kwargs: ["127.0.0.1"])

    with (
        _SFTPLoopbackServer(root, outside, host_key) as server,
        pytest.raises(ft.FileTransferError) as exc_info,
        ft.SFTPClient(_sftp_config(port=server.port, host_key=host_key, password="wrong-password")),  # pragma: allowlist secret - fixture asserting a REJECTED password
    ):
        pass

    assert exc_info.value.code == "authentication_failed"
