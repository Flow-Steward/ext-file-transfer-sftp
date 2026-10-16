"""S3 connection behaviour through the common layer, against a TLS fake S3 on loopback."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from typing import Any

import pytest
from aiohttp import web

import file_operations as ops
from connections import s3
from tests._fake_s3 import ENDPOINT_HOST, SERVER_IP, FakeS3, s3_error, write_certificates
from tests._host_scope import host_context

MiB = 1024 * 1024


@pytest.fixture
def server(tmp_path, monkeypatch) -> Iterator[FakeS3]:
    ca, cert, key = write_certificates(
        tmp_path, [ENDPOINT_HOST, f"data.{ENDPOINT_HOST}", "other.test"]
    )
    monkeypatch.setenv("SSL_CERT_FILE", str(ca))
    lookups: list[str] = []

    def _resolve(host: str, *, port: int, purpose: str) -> list[str]:
        lookups.append(host)
        return [SERVER_IP]

    monkeypatch.setattr(s3, "resolve_pinned_ips", _resolve)
    monkeypatch.setattr(s3, "_blocking_sleep", lambda seconds: None)
    fake = FakeS3()
    fake.lookups = lookups  # type: ignore[attr-defined]
    fake.start(cert, key)
    try:
        yield fake
    finally:
        fake.stop()


def _payload(
    server: FakeS3, operation: str, input_payload: dict[str, Any], **overrides: Any
) -> dict[str, Any]:
    config = {
        "endpoint_url": f"https://{ENDPOINT_HOST}:{server.port}",
        "region": "us-east-1",
        "bucket": "data",
        "root_prefix": "feeds",
        **overrides.pop("config", {}),
    }
    secrets = {
        "access_key_id": "AKIAEXPLICIT",
        "secret_access_key": "explicit-secret",
        **overrides.pop("secrets", {}),
    }
    payload: dict[str, Any] = {
        "contract_version": "extension_host_v2",
        "runtime_context": host_context(overrides.pop("runtime_context", {})),
        "action": {
            "action_id": operation,
            "target": {
                "connection": {"connection_type_id": "s3", "config": config, "secrets": secrets}
            },
            "input": input_payload,
        },
    }
    payload.update(overrides)
    return payload


def _capture_artifact(monkeypatch) -> list[list[bytes]]:
    written: list[list[bytes]] = []

    def _write(_payload, chunks, **_kwargs):
        pieces = list(chunks)
        written.append(pieces)
        body = b"".join(pieces)
        return {
            "artifact_handle": "art_out",
            "size_bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }

    monkeypatch.setattr(ops, "write_artifact_stream", _write)
    return written


def _upload(server: FakeS3, monkeypatch, body: bytes, **kwargs: Any) -> dict[str, Any]:
    pieces = [body[i : i + MiB] for i in range(0, len(body), MiB)] or [b""]
    declared = kwargs.pop("declared_size", len(body))
    monkeypatch.setattr(ops, "stream_artifact_bytes", lambda *a, **k: iter(pieces))
    payload = _payload(
        server,
        "upload_file",
        {"artifact_handle": "art_in", "remote_path": "out/a.bin", **kwargs.pop("input", {})},
        artifacts={
            "inputs": [
                {
                    "artifact_id": "art_in",
                    "artifact_handle": "art_in",
                    "binding_key": "source_artifact",
                    "size_bytes": declared,
                    "access": {"download_url": "file:///dev/null", "max_size_bytes": declared},
                }
            ]
        },
        **kwargs,
    )
    return ops.handle_payload(payload)


# --- listing -----------------------------------------------------------------------


def test_listing_stays_inside_bucket_prefix(server):
    server.objects.update(
        {
            "feeds/a.csv": b"a",
            "feeds/b.csv": b"bb",
            "feeds/": b"",
            "feeds/sub/": b"",
            "feeds/sub/c.csv": b"c",
            "feeds-old/x.csv": b"x",
            "feedsX.csv": b"x",
        }
    )

    response = ops.handle_payload(_payload(server, "list_files", {"path": "."}))

    assert response["result"] == {
        "files": [
            {"name": "a.csv", "size_bytes": 1, "modified_at": "2026-10-01T10:00:00Z"},
            {"name": "b.csv", "size_bytes": 2, "modified_at": "2026-10-01T10:00:00Z"},
        ],
        "truncated": False,
    }
    assert server.seen[0].query["prefix"] == "feeds/"
    assert server.seen[0].query["delimiter"] == "/"


def test_literal_names_are_kept_and_fetchable(server, monkeypatch):
    server.objects.update({"feeds/a%2Fb.csv": b"lit", "feeds/отчёт 1.csv": b"uni"})
    written = _capture_artifact(monkeypatch)

    listed = ops.handle_payload(_payload(server, "list_files", {"path": "."}))
    fetched = ops.handle_payload(_payload(server, "fetch_file", {"path": "a%2Fb.csv"}))

    assert [row["name"] for row in listed["result"]["files"]] == ["a%2Fb.csv", "отчёт 1.csv"]
    assert fetched["result"]["source_filename"] == "a%2Fb.csv"
    assert b"".join(written[0]) == b"lit"


@pytest.mark.parametrize("path", ["../x", "/abs", "a//b", "a/./b", "a\\b"])
def test_unsafe_paths_are_refused_before_network(server, path):
    response = ops.handle_payload(_payload(server, "fetch_file", {"path": path}))

    assert response["error_code"] == "invalid_path"
    assert server.seen == []


def test_listing_is_bounded_across_pages(server):
    server.objects.update({f"feeds/{i:04d}.csv": b"x" for i in range(1200)})
    server.page_size = 100

    response = ops.handle_payload(_payload(server, "list_files", {"path": ".", "limit": 500}))

    assert response["result"]["truncated"] is True
    assert len(response["result"]["files"]) == 500
    assert server.routes() == ["list"] * 6
    assert int(server.seen[-1].query["max-keys"]) == 1


def test_common_prefixes_count_against_the_budget(server):
    server.objects.update({f"feeds/d{i:04d}/f.csv": b"x" for i in range(600)})

    response = ops.handle_payload(_payload(server, "list_files", {"path": "."}))

    assert response["result"] == {"files": [], "truncated": True}


# --- download ----------------------------------------------------------------------


def test_download_streams_in_bounded_chunks(server, monkeypatch):
    body = bytes(range(256)) * (3 * MiB // 256) + b"end"
    server.objects["feeds/in/big.bin"] = body
    written = _capture_artifact(monkeypatch)

    response = ops.handle_payload(_payload(server, "fetch_file", {"path": "in/big.bin"}))

    assert response["result"]["size_bytes"] == len(body)
    assert b"".join(written[0]) == body
    assert max(len(piece) for piece in written[0]) <= MiB


def test_download_over_limit_is_refused(server, monkeypatch):
    server.objects["feeds/big.bin"] = b"x" * (2 * MiB)
    _capture_artifact(monkeypatch)

    response = ops.handle_payload(
        _payload(server, "fetch_file", {"path": "big.bin", "max_bytes": MiB})
    )

    assert response["error_code"] == "max_bytes_exceeded"


def test_missing_object_is_not_found(server, monkeypatch):
    _capture_artifact(monkeypatch)

    response = ops.handle_payload(_payload(server, "fetch_file", {"path": "nope.csv"}))

    assert response["error_code"] == "not_found"


def test_glob_fetch_selects_latest_name(server, monkeypatch):
    server.objects.update({"feeds/in/a.csv": b"a", "feeds/in/b.csv": b"b"})
    written = _capture_artifact(monkeypatch)

    response = ops.handle_payload(
        _payload(
            server, "fetch_file", {"path": "in", "name_glob": "*.csv", "select": "latest_name"}
        )
    )

    assert response["result"]["source_filename"] == "b.csv"
    assert b"".join(written[0]) == b"b"


def test_read_retries_are_bounded(server):
    server.hooks["list"] = lambda request: s3_error(503, "SlowDown")

    response = ops.handle_payload(_payload(server, "list_files", {"path": "."}))

    assert response["error_code"] == "rate_limited"
    assert server.routes() == ["list"] * 3


# --- upload ------------------------------------------------------------------------


def test_small_upload_commits_with_a_conditional_post(server, monkeypatch):
    response = _upload(server, monkeypatch, b"hello")

    assert response["ok"] is True
    assert response["result"]["overwrite_protection"] == "atomic"
    assert server.objects["feeds/out/a.bin"] == b"hello"
    assert server.routes() == ["create_multipart", "upload_part", "complete_multipart"]
    assert server.seen[-1].headers.get("If-None-Match") == "*"


def test_empty_file_is_one_empty_part(server, monkeypatch):
    response = _upload(server, monkeypatch, b"")

    assert response["ok"] is True
    assert server.objects["feeds/out/a.bin"] == b""
    assert server.routes() == ["create_multipart", "upload_part", "complete_multipart"]


def test_conditional_write_conflict_does_not_overwrite(server, monkeypatch):
    server.objects["feeds/out/a.bin"] = b"old"

    response = _upload(server, monkeypatch, b"new")

    assert response["error_code"] == "already_exists"
    assert response["definitely_no_external_effect"] is True
    assert server.objects["feeds/out/a.bin"] == b"old"


def test_overwrite_sends_no_condition(server, monkeypatch):
    server.objects["feeds/out/a.bin"] = b"old"

    response = _upload(server, monkeypatch, b"new", input={"overwrite": True})

    assert response["ok"] is True
    assert server.objects["feeds/out/a.bin"] == b"new"
    assert "If-None-Match" not in server.seen[-1].headers


def test_large_upload_uses_sequential_parts(server, monkeypatch):
    body = bytes(range(256)) * (20 * MiB // 256) + b"tail"

    response = _upload(server, monkeypatch, body)

    assert response["ok"] is True
    assert server.routes() == [
        "create_multipart",
        "upload_part",
        "upload_part",
        "upload_part",
        "complete_multipart",
    ]
    assert max(seen.body_len for seen in server.seen) <= s3.UPLOAD_PART_BYTES
    assert server.seen[-1].headers.get("If-None-Match") == "*"
    assert server.objects["feeds/out/a.bin"] == body


def test_multipart_conflict_aborts_own_upload(server, monkeypatch):
    server.objects["feeds/out/a.bin"] = b"old"

    response = _upload(server, monkeypatch, b"y" * (9 * MiB))

    assert response["error_code"] == "already_exists"
    assert server.objects["feeds/out/a.bin"] == b"old"
    assert len(server.aborted) == 1
    assert server.uploads == {}


def test_commit_disconnect_stays_unknown(server, monkeypatch):
    async def _drop(request: web.Request) -> web.Response:
        await request.read()
        assert request.transport is not None
        request.transport.abort()
        return web.Response()

    server.hooks["complete_multipart"] = _drop

    response = _upload(server, monkeypatch, b"y" * (9 * MiB))

    assert response["external_effect_status"] == "timeout_unknown"
    assert response["definitely_no_external_effect"] is False
    assert server.routes().count("complete_multipart") == 1
    assert server.aborted == []


def test_dropped_part_is_resent_but_commit_never_is(server, monkeypatch):
    """aiohttp resends an idempotent PUT once; only the POST commit must be single."""
    dropped: list[int] = []

    async def _drop_first(request: web.Request) -> web.Response | None:
        if dropped:
            return None
        dropped.append(1)
        await request.read()
        assert request.transport is not None
        request.transport.abort()
        return web.Response()

    server.hooks["upload_part"] = _drop_first

    response = _upload(server, monkeypatch, b"small")

    assert response["ok"] is True
    assert server.routes().count("complete_multipart") == 1
    assert server.objects["feeds/out/a.bin"] == b"small"


def test_unsupported_conditional_write_is_reported(server, monkeypatch):
    server.hooks["complete_multipart"] = lambda request: s3_error(501, "NotImplemented")

    response = _upload(server, monkeypatch, b"x")

    assert response["error_code"] == "not_supported_by_server"
    assert response["definitely_no_external_effect"] is True
    assert len(server.aborted) == 1


def test_truncated_source_aborts_and_never_completes(server, monkeypatch):
    response = _upload(server, monkeypatch, b"y" * (9 * MiB), declared_size=12 * MiB)

    assert response["error_code"] == "artifact_read_failed"
    assert "complete_multipart" not in server.routes()
    assert len(server.aborted) == 1
    assert "feeds/out/a.bin" not in server.objects


def test_test_mode_upload_makes_no_request(server, monkeypatch):
    response = _upload(server, monkeypatch, b"x", runtime_context={"test_mode": True})

    assert response["external_effect_status"] == "suppressed"
    assert server.seen == []


# --- setup check -------------------------------------------------------------------


def test_setup_check_reads_one_key_below_the_prefix(server):
    response = ops.handle_payload(_payload(server, "test_connection", {}))

    assert response["result"] == {"protocol": "s3", "use_tls": None}
    assert server.routes() == ["list"]
    assert server.seen[0].query["max-keys"] == "1"
    assert server.seen[0].query["prefix"] == "feeds/"
