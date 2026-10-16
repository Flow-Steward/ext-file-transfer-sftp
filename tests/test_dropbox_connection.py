"""Dropbox connection behaviour through the common layer, against a fake Dropbox API."""

from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Callable
from email.message import Message
from typing import Any
from urllib.error import HTTPError, URLError

import pytest

import file_operations as ops
from connections import dropbox as dbx
from tests._host_scope import host_context

MiB = 1024 * 1024


class FakeResponse:
    def __init__(self, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self._body = io.BytesIO(body)
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def read1(self, size: int = -1) -> bytes:
        return self._body.read(min(size, 64 * 1024))

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _http_error(status: int, body: dict[str, Any] | None = None, **headers: str) -> HTTPError:
    hdrs = Message()
    for key, value in headers.items():
        hdrs[key.replace("_", "-")] = value
    raw = json.dumps(body or {}).encode()
    return HTTPError("https://api.dropboxapi.com/2/x", status, "err", hdrs, io.BytesIO(raw))


class FakeDropbox:
    """Routes requests by endpoint; files are keyed by (token, provider path)."""

    def __init__(self) -> None:
        self.files: dict[tuple[str, str], bytes] = {}
        self.folders: set[tuple[str, str]] = set()
        self.calls: list[dict[str, Any]] = []
        self.sessions: dict[str, bytearray] = {}
        self.override: dict[str, Callable[[dict[str, Any]], Any]] = {}
        self.list_entries: list[dict[str, Any]] | None = None
        self.page_size = 1000

    def __call__(self, request, *, timeout_seconds: float, purpose: str):
        route = request.full_url.split("/2/", 1)[1]
        token = request.get_header("Authorization").removeprefix("Bearer ")
        arg = request.get_header("Dropbox-api-arg")
        body = request.data if isinstance(request.data, bytes) else b""
        call = {
            "route": route,
            "token": token,
            "arg": json.loads(arg) if arg else json.loads(body or b"{}"),
            "arg_raw": arg,
            "body_len": len(body),
            "url": request.full_url,
            "timeout": timeout_seconds,
        }
        self.calls.append(call)
        if route in self.override:
            result = self.override[route](call)
            if isinstance(result, BaseException):
                raise result
            if result is not None:
                return result
        handler = getattr(self, "_" + route.replace("/", "_"))
        return handler(call, token, body)

    def routes(self) -> list[str]:
        return [call["route"] for call in self.calls]

    def _files_list_folder(self, call, token, body):
        entries = self.list_entries
        if entries is None:
            prefix = call["arg"]["path"] + "/"
            entries = [
                {
                    ".tag": "file",
                    "name": path[len(prefix) :],
                    "size": len(data),
                    "server_modified": "2026-10-01T10:00:00Z",
                }
                for (owner, path), data in sorted(self.files.items())
                if owner == token and path.startswith(prefix) and "/" not in path[len(prefix) :]
            ]
        return self._page(entries, 0)

    def _files_list_folder_continue(self, call, token, body):
        return self._page(self.list_entries or [], int(call["arg"]["cursor"]))

    def _page(self, entries, start):
        chunk = entries[start : start + self.page_size]
        more = start + self.page_size < len(entries)
        payload = {"entries": chunk, "has_more": more, "cursor": str(start + self.page_size)}
        return FakeResponse(json.dumps(payload).encode())

    def _files_get_metadata(self, call, token, body):
        if (token, call["arg"]["path"]) in self.folders:
            return FakeResponse(json.dumps({".tag": "folder", "name": "x"}).encode())
        raise _http_error(409, {"error_summary": "path/not_found/.."})

    def _files_download(self, call, token, body):
        path = call["arg"]["path"]
        if (token, path) not in self.files:
            raise _http_error(409, {"error_summary": "path/not_found/"})
        data = self.files[(token, path)]
        meta = {
            "name": path.rsplit("/", 1)[-1],
            "size": len(data),
            "server_modified": "2026-10-01T10:00:00Z",
        }
        return FakeResponse(data, {"Dropbox-API-Result": json.dumps(meta)})

    def _commit(self, token, commit, data):
        key = (token, commit["path"])
        if commit["mode"] == "add" and key in self.files:
            raise _http_error(409, {"error_summary": "path/conflict/file/.."})
        self.files[key] = bytes(data)
        return FakeResponse(json.dumps({"name": "x", "size": len(data)}).encode())

    def _files_upload(self, call, token, body):
        return self._commit(token, call["arg"], body)

    def _files_upload_session_start(self, call, token, body):
        session_id = f"s{len(self.sessions)}"
        self.sessions[session_id] = bytearray(body)
        return FakeResponse(json.dumps({"session_id": session_id}).encode())

    def _files_upload_session_append_v2(self, call, token, body):
        self.sessions[call["arg"]["cursor"]["session_id"]].extend(body)
        return FakeResponse(b"null")

    def _files_upload_session_finish(self, call, token, body):
        cursor = call["arg"]["cursor"]
        data = self.sessions[cursor["session_id"]]
        assert cursor["offset"] == len(data)
        data.extend(body)
        return self._commit(token, call["arg"]["commit"], data)


@pytest.fixture
def fake(monkeypatch) -> FakeDropbox:
    api = FakeDropbox()
    monkeypatch.setattr(dbx, "open_pinned_url", api)
    return api


def _payload(
    operation: str,
    input_payload: dict[str, Any],
    *,
    token: str = "tok-1",
    root_path: str = ".",
    **extra: Any,
) -> dict[str, Any]:
    payload = {
        "contract_version": "extension_host_v2",
        "runtime_context": host_context(extra.pop("runtime_context", {})),
        "action": {
            "action_id": operation,
            "target": {
                "connection": {
                    "connection_type_id": "dropbox",
                    "config": {"root_path": root_path},
                    "secrets": {"access_token": token},
                }
            },
            "input": input_payload,
        },
    }
    payload.update(extra)
    return payload


def _upload(monkeypatch, body: bytes, remote_path: str = "out/a.bin", **kwargs: Any):
    pieces = [body[i : i + MiB] for i in range(0, len(body), MiB)] or [b""]
    monkeypatch.setattr(ops, "stream_artifact_bytes", lambda *a, **k: iter(pieces))
    payload = _payload(
        "upload_file",
        {"artifact_handle": "art_in", "remote_path": remote_path, **kwargs.pop("input", {})},
        artifacts={
            "inputs": [
                {
                    "artifact_id": "art_in",
                    "artifact_handle": "art_in",
                    "binding_key": "source_artifact",
                    "size_bytes": len(body),
                    "access": {"download_url": "file:///dev/null", "max_size_bytes": len(body)},
                }
            ]
        },
        **kwargs,
    )
    return ops.handle_payload(payload)


def _capture_artifact(monkeypatch) -> list[bytes]:
    written: list[bytes] = []

    def _write(_payload, chunks, **_kwargs):
        body = b"".join(chunks)
        written.append(body)
        return {
            "artifact_handle": "art_out",
            "size_bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }

    monkeypatch.setattr(ops, "write_artifact_stream", _write)
    return written


# --- authorization and isolation ---------------------------------------------------


def test_missing_token_is_refused_before_network(fake):
    response = ops.handle_payload(_payload("list_files", {"path": "."}, token=""))

    assert response["error_code"] == "authorization_required"
    assert fake.calls == []


def test_rotated_token_uses_new_connection_client(fake):
    ops.handle_payload(_payload("list_files", {"path": "."}, token="old-token"))
    ops.handle_payload(_payload("list_files", {"path": "."}, token="new-token"))

    assert [call["token"] for call in fake.calls] == ["old-token", "new-token"]


def test_two_accounts_with_same_path_are_isolated(fake, monkeypatch):
    fake.files[("tok-a", "/in/report.csv")] = b"account a"
    fake.files[("tok-b", "/in/report.csv")] = b"account b"
    written = _capture_artifact(monkeypatch)

    first = ops.handle_payload(_payload("fetch_file", {"path": "in/report.csv"}, token="tok-a"))
    second = ops.handle_payload(_payload("fetch_file", {"path": "in/report.csv"}, token="tok-b"))

    assert first["ok"] and second["ok"]
    assert written == [b"account a", b"account b"]


@pytest.mark.parametrize("root_path", ["../escape", "/abs", "a//b", "a/./b", "a\\b"])
def test_root_path_cannot_escape_api_access_root(fake, root_path):
    response = ops.handle_payload(_payload("list_files", {"path": "."}, root_path=root_path))

    assert response["error_code"] == "invalid_path"
    assert fake.calls == []


def test_root_path_prefixes_every_provider_path(fake, monkeypatch):
    fake.files[("tok-1", "/team/in/a.csv")] = b"abc"
    _capture_artifact(monkeypatch)

    listed = ops.handle_payload(_payload("list_files", {"path": "in"}, root_path="team"))
    fetched = ops.handle_payload(_payload("fetch_file", {"path": "in/a.csv"}, root_path="team"))
    root = ops.handle_payload(_payload("list_files", {"path": "."}))

    assert root["ok"] is True

    assert [row["name"] for row in listed["result"]["files"]] == ["a.csv"]
    assert fetched["result"]["remote_path"] == "in/a.csv"
    assert fake.calls[1]["arg"] == {"path": "/team/in/a.csv"}
    assert fake.calls[-1]["arg"]["path"] == ""


def test_requests_carry_only_fixed_origins(fake, monkeypatch):
    fake.files[("tok-1", "/a.csv")] = b"abc"
    _capture_artifact(monkeypatch)

    ops.handle_payload(_payload("fetch_file", {"path": "a.csv"}))
    ops.handle_payload(_payload("list_files", {"path": "."}))

    assert {call["url"].split("/2/")[0] for call in fake.calls} == {
        "https://content.dropboxapi.com",
        "https://api.dropboxapi.com",
    }


def test_non_ascii_path_goes_out_as_ascii_header(fake, monkeypatch):
    fake.files[("tok-1", "/отчёт.csv")] = b"x"
    _capture_artifact(monkeypatch)

    response = ops.handle_payload(_payload("fetch_file", {"path": "отчёт.csv"}))

    assert response["ok"] is True
    assert fake.calls[0]["arg_raw"].isascii()


@pytest.mark.parametrize(
    ("summary", "code"),
    [
        ("missing_scope/..", "permission_denied"),
        ("expired_access_token/..", "authorization_required"),
        ("invalid_access_token/..", "authorization_required"),
    ],
)
def test_authorization_failures_are_normalized(fake, summary, code):
    fake.override["files/list_folder"] = lambda call: _http_error(401, {"error_summary": summary})

    response = ops.handle_payload(_payload("list_files", {"path": "."}))

    assert response["error_code"] == code
    assert "tok-1" not in json.dumps(response)


# --- listing -----------------------------------------------------------------------


def test_listing_is_bounded_and_reports_truncation(fake):
    fake.list_entries = [{".tag": "file", "name": f"{i:04d}.csv", "size": 1} for i in range(1200)]
    fake.page_size = 300

    response = ops.handle_payload(_payload("list_files", {"path": "in", "limit": 500}))

    assert response["result"]["truncated"] is True
    assert len(response["result"]["files"]) == 500
    assert fake.routes() == ["files/list_folder", "files/list_folder/continue"]
    assert fake.calls[0]["arg"]["limit"] == 501


def test_listing_keeps_only_regular_files_and_counts_everything(fake):
    fake.list_entries = [
        {".tag": "folder", "name": "sub"},
        {".tag": "deleted", "name": "gone.csv"},
        {".tag": "file", "name": "b.csv", "size": 2, "server_modified": "2026-10-01T10:00:00Z"},
        {".tag": "file", "name": "a.csv"},
    ]

    response = ops.handle_payload(_payload("list_files", {"path": "."}))

    assert response["result"] == {
        "files": [
            {"name": "a.csv", "size_bytes": None, "modified_at": None},
            {"name": "b.csv", "size_bytes": 2, "modified_at": "2026-10-01T10:00:00Z"},
        ],
        "truncated": False,
    }


def test_oversized_list_response_is_rejected(fake):
    huge = json.dumps({"entries": [], "has_more": False, "pad": "x" * (2 * MiB)}).encode()
    fake.override["files/list_folder"] = lambda call: FakeResponse(huge)

    response = ops.handle_payload(_payload("list_files", {"path": "."}))

    assert response["error_code"] == "provider_unavailable"


def test_rate_limit_is_bounded_by_deadline(fake, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(dbx.time, "sleep", sleeps.append)
    fake.override["files/list_folder"] = lambda call: _http_error(429, Retry_After="100000")

    response = ops.handle_payload(_payload("list_files", {"path": "."}))

    assert response["error_code"] == "rate_limited"
    assert sleeps == []
    assert fake.routes() == ["files/list_folder"]


def test_read_retries_at_most_three_attempts(fake, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(dbx.time, "sleep", sleeps.append)
    fake.override["files/list_folder"] = lambda call: _http_error(503, Retry_After="1")

    response = ops.handle_payload(_payload("list_files", {"path": "."}))

    assert response["error_code"] == "provider_unavailable"
    assert fake.routes() == ["files/list_folder"] * 3
    assert sleeps == [1.0, 1.0]


def test_listing_a_file_path_is_not_found(fake):
    fake.override["files/list_folder"] = lambda call: _http_error(
        409, {"error_summary": "path/not_folder/.."}
    )

    response = ops.handle_payload(_payload("list_files", {"path": "a.csv"}))

    assert response["error_code"] == "not_found"


# --- download ----------------------------------------------------------------------


def test_download_streams_and_closes_response(fake, monkeypatch):
    body = b"q" * (3 * MiB + 5)
    fake.files[("tok-1", "/big.bin")] = body
    responses: list[FakeResponse] = []

    def _download(call):
        response = fake._files_download(call, call["token"], b"")
        responses.append(response)
        return response

    fake.override["files/download"] = _download
    written = _capture_artifact(monkeypatch)

    response = ops.handle_payload(_payload("fetch_file", {"path": "big.bin"}))

    assert response["result"]["size_bytes"] == len(body)
    assert response["result"]["source_filename"] == "big.bin"
    assert written == [body]
    assert responses[0].closed is True


def test_download_over_limit_stops_and_closes(fake, monkeypatch):
    fake.files[("tok-1", "/big.bin")] = b"q" * (2 * MiB)
    responses: list[FakeResponse] = []

    def _download(call):
        response = fake._files_download(call, call["token"], b"")
        response.headers.replace_header(
            "Dropbox-API-Result", json.dumps({"name": "big.bin"})
        )  # no size: the stream itself must hit the limit
        responses.append(response)
        return response

    fake.override["files/download"] = _download
    _capture_artifact(monkeypatch)

    response = ops.handle_payload(_payload("fetch_file", {"path": "big.bin", "max_bytes": MiB}))

    assert response["error_code"] == "max_bytes_exceeded"
    assert responses[0].closed is True


def test_missing_file_is_not_found(fake, monkeypatch):
    _capture_artifact(monkeypatch)

    response = ops.handle_payload(_payload("fetch_file", {"path": "nope.csv"}))

    assert response["error_code"] == "not_found"


def test_glob_fetch_selects_through_listing(fake, monkeypatch):
    fake.files[("tok-1", "/in/a.csv")] = b"a"
    fake.files[("tok-1", "/in/b.csv")] = b"bb"
    written = _capture_artifact(monkeypatch)

    response = ops.handle_payload(
        _payload("fetch_file", {"path": "in", "name_glob": "*.csv", "select": "latest_name"})
    )

    assert response["result"]["source_filename"] == "b.csv"
    assert written == [b"bb"]


# --- upload ------------------------------------------------------------------------


def test_small_upload_is_one_request_with_add_mode(fake, monkeypatch):
    fake.folders.add(("tok-1", "/out"))

    response = _upload(monkeypatch, b"hello")

    assert response["ok"] is True
    assert response["result"]["overwrite_protection"] == "atomic"
    assert fake.routes() == ["files/get_metadata", "files/upload"]
    commit = fake.calls[-1]["arg"]
    assert commit["mode"] == "add" and commit["autorename"] is False
    # Identical contents must still conflict when overwrite is off.
    assert commit["strict_conflict"] is True
    assert fake.files[("tok-1", "/out/a.bin")] == b"hello"


def test_upload_to_root_skips_parent_lookup(fake, monkeypatch):
    response = _upload(monkeypatch, b"x", remote_path="a.bin")

    assert response["ok"] is True
    assert fake.routes() == ["files/upload"]


def test_large_upload_uses_session_without_full_buffer(fake, monkeypatch):
    fake.folders.add(("tok-1", "/out"))
    body = bytes(range(256)) * (20 * MiB // 256) + b"tail"

    response = _upload(monkeypatch, body)

    assert response["ok"] is True
    assert fake.routes() == [
        "files/get_metadata",
        "files/upload_session/start",
        "files/upload_session/append_v2",
        "files/upload_session/finish",
    ]
    assert max(call["body_len"] for call in fake.calls) <= dbx.UPLOAD_PIECE_BYTES
    assert fake.files[("tok-1", "/out/a.bin")] == body


def test_exact_multiple_of_piece_size_finishes_with_last_piece(fake, monkeypatch):
    fake.folders.add(("tok-1", "/out"))
    body = b"z" * (2 * dbx.UPLOAD_PIECE_BYTES)

    response = _upload(monkeypatch, body)

    assert response["ok"] is True
    assert fake.routes()[-2:] == ["files/upload_session/start", "files/upload_session/finish"]
    assert fake.files[("tok-1", "/out/a.bin")] == body


def test_missing_parent_is_rejected_before_upload(fake, monkeypatch):
    response = _upload(monkeypatch, b"hello")

    assert response["error_code"] == "not_found"
    assert response["definitely_no_external_effect"] is True
    assert fake.routes() == ["files/get_metadata"]


def test_conflict_without_overwrite_has_no_effect(fake, monkeypatch):
    fake.folders.add(("tok-1", "/out"))
    fake.files[("tok-1", "/out/a.bin")] = b"old"

    response = _upload(monkeypatch, b"new")

    assert response["error_code"] == "already_exists"
    assert response["definitely_no_external_effect"] is True
    assert fake.files[("tok-1", "/out/a.bin")] == b"old"


def test_overwrite_uses_overwrite_mode(fake, monkeypatch):
    fake.folders.add(("tok-1", "/out"))
    fake.files[("tok-1", "/out/a.bin")] = b"old"

    response = _upload(monkeypatch, b"new", input={"overwrite": True})

    assert response["ok"] is True
    assert fake.files[("tok-1", "/out/a.bin")] == b"new"
    assert fake.calls[-1]["arg"]["mode"] == "overwrite"
    assert fake.calls[-1]["arg"]["strict_conflict"] is False


def test_failure_before_commit_has_no_effect(fake, monkeypatch):
    fake.folders.add(("tok-1", "/out"))
    fake.override["files/upload_session/append_v2"] = lambda call: _http_error(503)

    response = _upload(monkeypatch, b"y" * (20 * MiB))

    assert response["ok"] is False
    assert response["definitely_no_external_effect"] is True
    assert "files/upload_session/finish" not in fake.routes()


@pytest.mark.parametrize(
    "failure",
    [URLError(TimeoutError("timed out")), _http_error(500)],
)
def test_session_finish_disconnect_stays_unknown(fake, monkeypatch, failure):
    fake.folders.add(("tok-1", "/out"))
    fake.override["files/upload_session/finish"] = lambda call: failure

    response = _upload(monkeypatch, b"y" * (9 * MiB))

    assert response["ok"] is False
    assert response["external_effect_status"] == "timeout_unknown"
    assert response["definitely_no_external_effect"] is False
    assert fake.routes().count("files/upload_session/finish") == 1


def test_broken_commit_answer_stays_unknown(fake, monkeypatch):
    class Broken(FakeResponse):
        def read(self, size: int = -1) -> bytes:
            raise TimeoutError("read timed out")

    fake.override["files/upload"] = lambda call: Broken()

    response = _upload(monkeypatch, b"hello", remote_path="a.bin")

    assert response["external_effect_status"] == "timeout_unknown"
    assert response["definitely_no_external_effect"] is False


def test_truncated_artifact_never_reaches_finish(fake, monkeypatch):
    fake.folders.add(("tok-1", "/out"))
    body = b"y" * (12 * MiB)
    monkeypatch.setattr(ops, "stream_artifact_bytes", lambda *a, **k: iter([body[: 9 * MiB]]))
    payload = _payload(
        "upload_file",
        {"artifact_handle": "art_in", "remote_path": "out/a.bin"},
        artifacts={
            "inputs": [
                {
                    "artifact_id": "art_in",
                    "artifact_handle": "art_in",
                    "binding_key": "source_artifact",
                    "size_bytes": len(body),
                    "access": {"download_url": "file:///dev/null", "max_size_bytes": len(body)},
                }
            ]
        },
    )

    response = ops.handle_payload(payload)

    assert response["error_code"] == "artifact_read_failed"
    assert "files/upload_session/finish" not in fake.routes()
    assert ("tok-1", "/out/a.bin") not in fake.files


def test_test_mode_upload_makes_no_dropbox_call(fake, monkeypatch):
    response = _upload(monkeypatch, b"x", runtime_context={"test_mode": True})

    assert response["external_effect_status"] == "suppressed"
    assert fake.calls == []


def test_setup_check_reads_one_root_entry(fake):
    response = ops.handle_payload(_payload("test_connection", {}))

    assert response["result"] == {"protocol": "dropbox", "use_tls": None}
    assert fake.routes() == ["files/list_folder"]
    assert fake.calls[0]["arg"]["limit"] == 1
