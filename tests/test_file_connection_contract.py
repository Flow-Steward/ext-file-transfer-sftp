"""The common operation layer against a fake ``FileConnection``.

These tests pin the contract every connection class shares: the same three
operations, the same selection rules, byte limits, artifact checks and the
lifecycle of streams and connections, independent of any protocol.
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

import file_operations as ops
from file_connections import (
    FilePage,
    ListRequest,
    RemoteDownload,
    RemoteFile,
    UploadOptions,
    UploadResult,
)

BUNDLE_ROOT = Path(__file__).resolve().parents[1]
MiB = 1024 * 1024


class TrackedChunks:
    """A one-shot stream that records whether it was read to the end or closed."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._iterator = iter(chunks)
        self.closed = False
        self.exhausted = False

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        try:
            return next(self._iterator)
        except StopIteration:
            self.exhausted = True
            raise

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    def __init__(
        self,
        files: Iterable[RemoteFile] = (),
        *,
        truncated: bool = False,
        bodies: dict[str, bytes] | None = None,
        spool_uploads: bool = False,
    ) -> None:
        self.files = tuple(files)
        self.truncated = truncated
        self.bodies = bodies or {}
        self.spool_uploads = spool_uploads
        self.list_requests: list[ListRequest] = []
        self.fetched: list[str] = []
        self.streams: list[TrackedChunks] = []
        self.committed: dict[str, bytes] = {}
        self.upload_options: list[UploadOptions] = []
        self.closed = False

    def list_files(self, request: ListRequest) -> FilePage:
        self.list_requests.append(request)
        return FilePage(files=self.files, truncated=self.truncated)

    def fetch_file(self, path: str) -> RemoteDownload:
        self.fetched.append(path)
        listed = {row.remote_path: row for row in self.files}
        body = self.bodies.get(path, b"payload")
        remote = listed.get(path) or RemoteFile(
            name=Path(path).name, remote_path=path, size_bytes=len(body)
        )
        stream = TrackedChunks([body[i : i + MiB] for i in range(0, len(body), MiB)])
        self.streams.append(stream)
        return RemoteDownload(file=remote, chunks=stream)

    def upload_file(
        self, remote_path: str, chunks: Iterable[bytes], options: UploadOptions
    ) -> UploadResult:
        self.upload_options.append(options)
        if self.spool_uploads:
            # A provider that needs a seekable body spools once, then replays the spool.
            with tempfile.TemporaryFile() as spool:
                for chunk in chunks:
                    spool.write(chunk)
                for _attempt in range(2):
                    spool.seek(0)
                    body = spool.read()
        else:
            body = b"".join(chunks)
        # A commit only happens after the source stream ended cleanly.
        self.committed[remote_path] = body
        return UploadResult(
            remote_path=remote_path, remote_size_bytes=len(body), overwrite_protection="atomic"
        )


@pytest.fixture
def connection(monkeypatch) -> FakeConnection:
    fake = FakeConnection()
    _install(monkeypatch, fake)
    return fake


def _install(monkeypatch, fake: FakeConnection) -> None:
    @contextlib.contextmanager
    def _open(_payload, *, deadline=None):
        try:
            yield fake
        finally:
            fake.closed = True

    monkeypatch.setattr(ops, "open_file_connection", _open)


def _payload(operation: str, input_payload: dict[str, Any], **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "contract_version": "extension_host_v2",
        "runtime_context": extra.pop("runtime_context", {}),
        "action": {
            "action_id": operation,
            "target": {
                "connection": {
                    "connection_type_id": "fake",
                    "config": {},
                    "secrets": {"access_token": "token-value"},
                }
            },
            "input": input_payload,
        },
    }
    payload.update(extra)
    return payload


def _upload_payload(size_bytes: int | None, **input_extra: Any) -> dict[str, Any]:
    descriptor: dict[str, Any] = {
        "artifact_id": "art_in",
        "artifact_handle": "art_in",
        "binding_key": "source_artifact",
        "access": {"download_url": "file:///dev/null"},
    }
    if size_bytes is not None:
        descriptor["size_bytes"] = size_bytes
        descriptor["access"]["max_size_bytes"] = size_bytes  # Core signs the exact size
    return _payload(
        "upload_file",
        {"artifact_handle": "art_in", "remote_path": "out/report.csv", **input_extra},
        artifacts={"inputs": [descriptor]},
    )


def _capture_artifact(monkeypatch, *, finalized: bool | None = None, size_delta: int = 0):
    written: list[bytes] = []

    def _write(_payload, chunks, **_kwargs):
        body = b"".join(chunks)
        written.append(body)
        result: dict[str, Any] = {
            "artifact_handle": "art_out",
            "size_bytes": len(body) + size_delta,
            "sha256": hashlib.sha256(body).hexdigest(),
        }
        if finalized is not None:
            result["finalized"] = finalized
        return result

    monkeypatch.setattr(ops, "write_artifact_stream", _write)
    return written


def _file(name: str, *, directory: str = "in", **fields: Any) -> RemoteFile:
    return RemoteFile(name=name, remote_path=f"{directory}/{name}", **fields)


# --- the frozen external contract -------------------------------------------------


def test_existing_ftp_sftp_operation_ids_and_bindings_preserved():
    operations = yaml.safe_load((BUNDLE_ROOT / "contracts/operation_manifest.yaml").read_text())
    workflow_ops = {
        row["operation_id"]
        for row in operations["operations"]
        if row.get("workflow_visible", True) is not False
    }
    assert {"list_files", "fetch_file", "upload_file"} <= workflow_ops
    connection_types = yaml.safe_load((BUNDLE_ROOT / "contracts/connection_types.yaml").read_text())
    type_ids = {row["connection_type_id"] for row in connection_types["connection_types"]}
    assert {"ftp", "sftp"} <= type_ids
    manifest = yaml.safe_load((BUNDLE_ROOT / "extension.yaml").read_text())
    bindings = {
        (policy["operation_id"], row["binding_key"])
        for policy in manifest["artifact_policies"]
        for row in policy.get("outputs", []) + policy.get("inputs", [])
    }
    assert bindings == {("fetch_file", "fetched_file"), ("upload_file", "source_artifact")}
    assert manifest["extension_id"] == "flowsteward.file-transfer"
    assert manifest["required_scopes"] == ["extension:invoke", "artifact:read"]


def test_common_operations_do_not_branch_on_provider():
    tree = ast.parse((BUNDLE_ROOT / "file_operations.py").read_text())
    literals = {
        node.value.lower()
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert not literals & {"ftp", "ftps", "sftp", "s3", "dropbox"}


# --- list_files ------------------------------------------------------------------


def test_list_sorts_filters_and_uses_raw_budget(monkeypatch):
    fake = FakeConnection(
        [_file("b.csv", size_bytes=2), _file("a.csv", size_bytes=1), _file("c.txt")]
    )
    _install(monkeypatch, fake)

    response = ops.handle_payload(_payload("list_files", {"path": "in", "name_glob": "*.csv"}))

    assert response["ok"] is True
    assert [row["name"] for row in response["result"]["files"]] == ["a.csv", "b.csv"]
    assert response["result"]["truncated"] is False
    assert fake.list_requests == [ListRequest(path="in", limit=500)]
    assert fake.closed is True


def test_unknown_metadata_is_null(monkeypatch):
    _install(monkeypatch, FakeConnection([_file("a.csv")]))

    response = ops.handle_payload(_payload("list_files", {"path": "in"}))

    assert response["result"]["files"] == [
        {"name": "a.csv", "size_bytes": None, "modified_at": None}
    ]


def test_list_reports_incomplete_raw_scan_even_when_filter_matches_little(monkeypatch):
    _install(monkeypatch, FakeConnection([_file("a.csv")], truncated=True))

    response = ops.handle_payload(_payload("list_files", {"path": "in", "name_glob": "a.*"}))

    assert response["result"]["truncated"] is True


def test_list_glob_with_slash_is_rejected_before_connecting(monkeypatch):
    fake = FakeConnection()
    _install(monkeypatch, fake)

    response = ops.handle_payload(_payload("list_files", {"path": "in", "name_glob": "x/*.csv"}))

    assert response["error_code"] == "invalid_payload"
    assert fake.list_requests == []


# --- fetch_file ------------------------------------------------------------------


def test_fetch_source_filename_and_size_bytes_preserved(monkeypatch):
    body = b"x" * (MiB + 7)
    fake = FakeConnection(bodies={"in/report.csv": body})
    _install(monkeypatch, fake)
    written = _capture_artifact(monkeypatch)

    response = ops.handle_payload(_payload("fetch_file", {"path": "in/report.csv"}))

    assert response["ok"] is True
    assert response["result"] == {
        "artifact_handle": "art_out",
        "artifact_filename": "download.bin",
        "source_filename": "report.csv",
        "remote_path": "in/report.csv",
        "sha256": hashlib.sha256(body).hexdigest(),
        "size_bytes": len(body),
    }
    assert written == [body]
    assert "body" not in str(response) and "base64" not in str(response)


def test_glob_fetch_rejects_incomplete_scan(monkeypatch):
    fake = FakeConnection([_file("only.csv")], truncated=True)
    _install(monkeypatch, fake)
    _capture_artifact(monkeypatch)

    response = ops.handle_payload(_payload("fetch_file", {"path": "in", "name_glob": "*.csv"}))

    assert response["error_code"] == "directory_too_large"
    assert fake.fetched == []


@pytest.mark.parametrize(
    ("files", "select", "expected"),
    [
        ([], "only", "not_found"),
        ([_file("a.csv"), _file("b.csv")], "only", "ambiguous_match"),
        (
            [_file("a.csv", raw_modified=5.0), _file("b.csv")],
            "latest_modified",
            "not_supported_by_server",
        ),
        ([_file("a.csv")], "newest", "invalid_payload"),
    ],
)
def test_glob_selection_failures(monkeypatch, files, select, expected):
    fake = FakeConnection(files)
    _install(monkeypatch, fake)
    _capture_artifact(monkeypatch)

    response = ops.handle_payload(
        _payload("fetch_file", {"path": "in", "name_glob": "*.csv", "select": select})
    )

    assert response["error_code"] == expected
    assert fake.fetched == []


def test_latest_modified_ties_break_on_name(monkeypatch):
    files = [
        _file("a.csv", raw_modified=9.0),
        _file("c.csv", raw_modified=9.0),
        _file("b.csv", raw_modified=1.0),
    ]
    fake = FakeConnection(files)
    _install(monkeypatch, fake)
    _capture_artifact(monkeypatch)

    response = ops.handle_payload(
        _payload("fetch_file", {"path": "in", "name_glob": "*.csv", "select": "latest_modified"})
    )

    assert response["result"]["source_filename"] == "c.csv"
    assert fake.fetched == ["in/c.csv"]


def test_zero_byte_file_and_iterator_cleanup(monkeypatch):
    fake = FakeConnection(bodies={"in/empty.csv": b""})
    _install(monkeypatch, fake)
    _capture_artifact(monkeypatch)

    response = ops.handle_payload(_payload("fetch_file", {"path": "in/empty.csv"}))

    assert response["ok"] is True
    assert response["result"]["size_bytes"] == 0
    assert response["result"]["sha256"] == hashlib.sha256(b"").hexdigest()
    assert fake.streams[0].closed is True
    assert fake.closed is True


def test_failed_artifact_write_closes_stream_and_connection(monkeypatch):
    fake = FakeConnection(bodies={"in/a.csv": b"x" * (3 * MiB)})
    _install(monkeypatch, fake)

    def _broken_write(_payload, chunks, **_kwargs):
        next(iter(chunks))
        raise ops.ArtifactAccessError("grant expired")

    monkeypatch.setattr(ops, "write_artifact_stream", _broken_write)

    response = ops.handle_payload(_payload("fetch_file", {"path": "in/a.csv"}))

    assert response["error_code"] == "artifact_write_failed"
    assert fake.streams[0].closed is True
    assert fake.streams[0].exhausted is False
    assert fake.closed is True


def test_fetch_stops_at_effective_limit_without_trusting_metadata(monkeypatch):
    lying = RemoteFile(name="a.csv", remote_path="in/a.csv", size_bytes=None)
    fake = FakeConnection([lying], bodies={"in/a.csv": b"x" * (2 * MiB + 1)})
    _install(monkeypatch, fake)
    _capture_artifact(monkeypatch)

    response = ops.handle_payload(
        _payload("fetch_file", {"path": "in", "name_glob": "a.csv", "max_bytes": 2 * MiB})
    )

    assert response["error_code"] == "max_bytes_exceeded"
    assert fake.streams[0].exhausted is False
    assert fake.streams[0].closed is True


def test_host_artifact_finalize_is_verified(monkeypatch):
    _install(monkeypatch, FakeConnection(bodies={"in/a.csv": b"abc"}))
    _capture_artifact(monkeypatch, finalized=False)

    not_final = ops.handle_payload(_payload("fetch_file", {"path": "in/a.csv"}))

    _capture_artifact(monkeypatch, size_delta=1)
    wrong_size = ops.handle_payload(_payload("fetch_file", {"path": "in/a.csv"}))

    assert not_final["error_code"] == "artifact_write_failed"
    assert wrong_size["error_code"] == "artifact_write_failed"


# --- byte limits -----------------------------------------------------------------


def test_configured_limit_can_exceed_default_but_not_grant(monkeypatch):
    monkeypatch.setenv("FS_EXTENSION_ARTIFACT_MAX_BYTES", str(300 * MiB))

    assert ops._effective_max_bytes({}) == 300 * MiB
    assert ops._effective_max_bytes({}, 250 * MiB) == 250 * MiB
    assert ops._effective_max_bytes({"max_bytes": 5}, 250 * MiB) == 5
    assert ops._effective_max_bytes({"max_bytes": 400 * MiB}) == 300 * MiB

    monkeypatch.setenv("FS_EXTENSION_ARTIFACT_MAX_BYTES", str(50 * 1024 * MiB))
    assert ops._effective_max_bytes({}) == 10 * 1024 * MiB
    monkeypatch.setenv("FS_EXTENSION_ARTIFACT_MAX_BYTES", "1")
    assert ops._effective_max_bytes({}) == MiB


# --- upload_file -----------------------------------------------------------------


def test_upload_passes_trusted_options_and_reports_commit(monkeypatch, connection):
    monkeypatch.setattr(ops, "stream_artifact_bytes", lambda *a, **k: iter([b"ab", b"cd"]))

    response = ops.handle_payload(_upload_payload(4, overwrite=True))

    assert response["ok"] is True
    assert response["result"]["uploaded"] is True
    assert response["result"]["size_bytes"] == 4
    assert response["result"]["overwrite_protection"] == "atomic"
    assert connection.committed == {"out/report.csv": b"abcd"}
    assert connection.upload_options[0].overwrite is True
    assert connection.upload_options[0].source_size_bytes == 4
    assert connection.closed is True


@pytest.mark.parametrize(
    ("chunks", "code"),
    [([b"ab"], "artifact_read_failed"), ([b"abcd", b"ef"], "max_bytes_exceeded")],
)
def test_truncated_source_does_not_commit_upload(monkeypatch, connection, chunks, code):
    # A short stream fails its signed size; a padded one hits the grant's byte limit.
    monkeypatch.setattr(ops, "stream_artifact_bytes", lambda *a, **k: iter(chunks))

    response = ops.handle_payload(_upload_payload(4))

    assert response["ok"] is False
    assert response["error_code"] == code
    assert connection.committed == {}


def test_spool_replay_does_not_double_count(monkeypatch):
    fake = FakeConnection(spool_uploads=True)
    _install(monkeypatch, fake)
    body = b"z" * (MiB + 3)
    monkeypatch.setattr(
        ops, "stream_artifact_bytes", lambda *a, **k: iter([body[:MiB], body[MiB:]])
    )

    response = ops.handle_payload(_upload_payload(len(body)))

    assert response["ok"] is True
    assert response["result"]["size_bytes"] == len(body)
    assert response["result"]["sha256"] == hashlib.sha256(body).hexdigest()


def test_unknown_source_size_is_not_treated_as_zero(monkeypatch, connection):
    monkeypatch.setattr(ops, "stream_artifact_bytes", lambda *a, **k: iter([b"abc"]))

    response = ops.handle_payload(_upload_payload(None))

    assert response["ok"] is True
    assert connection.upload_options[0].source_size_bytes is None
    assert response["result"]["size_bytes"] == 3


def test_commit_with_mismatched_remote_size_stays_unknown(monkeypatch):
    class ShortCommit(FakeConnection):
        def upload_file(self, remote_path, chunks, options):
            body = b"".join(chunks)
            return UploadResult(remote_path, len(body) - 1, "atomic")

    _install(monkeypatch, ShortCommit())
    monkeypatch.setattr(ops, "stream_artifact_bytes", lambda *a, **k: iter([b"abcd"]))

    response = ops.handle_payload(_upload_payload(4))

    assert response["ok"] is False
    assert response["external_effect_status"] == "timeout_unknown"
    assert response["definitely_no_external_effect"] is False


def test_commit_before_source_end_is_never_reported_as_uploaded(monkeypatch):
    class EarlyCommit(FakeConnection):
        def upload_file(self, remote_path, chunks, options):
            first = next(iter(chunks))
            return UploadResult(remote_path, None, "atomic") if first else None

    _install(monkeypatch, EarlyCommit())
    monkeypatch.setattr(ops, "stream_artifact_bytes", lambda *a, **k: iter([b"ab", b"cd"]))

    response = ops.handle_payload(_upload_payload(None))

    assert response["ok"] is False
    assert response["external_effect_status"] == "timeout_unknown"


def test_test_mode_upload_never_opens_a_connection(monkeypatch):
    def _never(*_a, **_k):
        raise AssertionError("no connection in test mode")

    monkeypatch.setattr(ops, "open_file_connection", _never)

    response = ops.handle_payload({**_upload_payload(4), "runtime_context": {"test_mode": True}})

    assert response["ok"] is True
    assert response["external_effect_status"] == "suppressed"


def test_provider_errors_are_redacted(monkeypatch):
    class Leaky(FakeConnection):
        def list_files(self, request):
            raise RuntimeError("upstream said token-value is bad")

    _install(monkeypatch, Leaky())

    response = ops.handle_payload(_payload("list_files", {"path": "."}))

    assert "token-value" not in response["error"]
    assert "[redacted]" in response["error"]


def test_connection_is_closed_when_the_provider_raises(monkeypatch):
    class Failing(FakeConnection):
        def fetch_file(self, path):
            raise RuntimeError("boom")

    fake = Failing()
    _install(monkeypatch, fake)

    response = ops.handle_payload(_payload("fetch_file", {"path": "in/a.csv"}))

    assert response["ok"] is False
    assert fake.closed is True


def test_unsigned_descriptor_size_is_treated_as_unknown(monkeypatch, connection):
    payload = _upload_payload(4)
    del payload["artifacts"]["inputs"][0]["access"]["max_size_bytes"]
    monkeypatch.setattr(ops, "stream_artifact_bytes", lambda *a, **k: iter([b"abcdef"]))

    response = ops.handle_payload(payload)

    assert response["ok"] is True
    assert connection.upload_options[0].source_size_bytes is None
    assert connection.committed == {"out/report.csv": b"abcdef"}
