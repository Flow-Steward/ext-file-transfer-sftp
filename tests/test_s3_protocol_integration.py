"""The S3 connection against a real S3-compatible service (MinIO, or an AWS test bucket).

Skipped unless FT_S3_IT_ENDPOINT is set. The service must already exist; this
test never creates buckets or accounts. Every object it writes lives under a
fresh prefix inside FT_S3_IT_PREFIX, and that prefix is emptied at the end.

    FT_S3_IT_ENDPOINT     https origin, e.g. https://s3.test
    FT_S3_IT_REGION       e.g. us-east-1
    FT_S3_IT_BUCKET       an existing bucket
    FT_S3_IT_KEY / FT_S3_IT_SECRET   keys allowed to list/read/write/abort there
    FT_S3_IT_PREFIX       parent prefix for this test's objects (default ft-it)
    FT_S3_IT_ADDRESSING   path, virtual, or both (default both)
    FT_S3_IT_PINNED_IP    only for a private test network: the service's address
    SSL_CERT_FILE         CA for a private test certificate
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

import file_operations as ops
from connections import s3

ENDPOINT = os.environ.get("FT_S3_IT_ENDPOINT", "")
pytestmark = pytest.mark.skipif(not ENDPOINT, reason="FT_S3_IT_ENDPOINT is not set")
MiB = 1024 * 1024
MODES = {
    "both": ["path", "virtual"],
    "path": ["path"],
    "virtual": ["virtual"],
}[os.environ.get("FT_S3_IT_ADDRESSING", "both")]


@pytest.fixture(params=MODES)
def target(request, monkeypatch) -> Iterator[dict[str, Any]]:
    pinned = os.environ.get("FT_S3_IT_PINNED_IP")
    if pinned:
        monkeypatch.setattr(s3, "resolve_pinned_ips", lambda host, *, port, purpose: [pinned])
    prefix = f"{os.environ.get('FT_S3_IT_PREFIX', 'ft-it').strip('/')}/{uuid.uuid4().hex}"
    config = {
        "endpoint_url": ENDPOINT,
        "region": os.environ["FT_S3_IT_REGION"],
        "bucket": os.environ["FT_S3_IT_BUCKET"],
        "root_prefix": prefix,
        "addressing_style": request.param,
    }
    secrets = {
        "access_key_id": os.environ["FT_S3_IT_KEY"],
        "secret_access_key": os.environ["FT_S3_IT_SECRET"],
    }
    yield {"config": config, "secrets": secrets}
    _empty_prefix(config, secrets)


def _connection(target: dict[str, Any]) -> s3.S3Connection:
    payload = {"action": {"target": {"connection": {"connection_type_id": "s3", **target}}}}
    from file_connections import Deadline

    return s3.S3Connection(s3.parse_s3_config(payload), Deadline(120)).open()


def _empty_prefix(config: dict[str, Any], secrets: dict[str, Any]) -> None:
    """Remove this test's own objects and unfinished uploads; nothing outside its prefix."""
    connection = _connection({"config": config, "secrets": secrets})
    client, bucket, prefix = connection._client, config["bucket"], config["root_prefix"] + "/"
    try:
        run = connection._run
        listed = run(client.list_objects_v2(Bucket=bucket, Prefix=prefix))
        for item in listed.get("Contents") or []:
            assert item["Key"].startswith(prefix)
            run(client.delete_object(Bucket=bucket, Key=item["Key"]))
        uploads = run(client.list_multipart_uploads(Bucket=bucket, Prefix=prefix))
        for upload in uploads.get("Uploads") or []:
            run(
                client.abort_multipart_upload(
                    Bucket=bucket, Key=upload["Key"], UploadId=upload["UploadId"]
                )
            )
    finally:
        connection.close()


def _open_uploads(target: dict[str, Any]) -> list[Any]:
    connection = _connection(target)
    try:
        prefix = target["config"]["root_prefix"] + "/"
        found = connection._run(
            connection._client.list_multipart_uploads(
                Bucket=target["config"]["bucket"], Prefix=prefix
            )
        )
        return list(found.get("Uploads") or [])
    finally:
        connection.close()


def _payload(target: dict[str, Any], operation: str, input_payload: dict[str, Any], **extra):
    payload = {
        "contract_version": "extension_host_v1",
        "runtime_context": {},
        "action": {
            "action_id": operation,
            "target": {"connection": {"connection_type_id": "s3", **target}},
            "input": input_payload,
        },
    }
    payload.update(extra)
    return payload


def _upload(target, monkeypatch, body: bytes, remote_path: str, **input_extra):
    pieces = [body[i : i + MiB] for i in range(0, len(body), MiB)] or [b""]
    monkeypatch.setattr(ops, "stream_artifact_bytes", lambda *a, **k: iter(pieces))
    descriptor = {
        "artifact_id": "art_in",
        "artifact_handle": "art_in",
        "binding_key": "source_artifact",
        "size_bytes": len(body),
        "access": {"download_url": "file:///dev/null", "max_size_bytes": len(body)},
    }
    return ops.handle_payload(
        _payload(
            target,
            "upload_file",
            {"artifact_handle": "art_in", "remote_path": remote_path, **input_extra},
            artifacts={"inputs": [descriptor]},
        )
    )


def _fetch(target, monkeypatch, path: str) -> tuple[dict[str, Any], bytes]:
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
    response = ops.handle_payload(_payload(target, "fetch_file", {"path": path}))
    return response, (written[0] if written else b"")


def test_setup_check(target):
    response = ops.handle_payload(_payload(target, "test_connection", {}))

    assert response["ok"] is True, response


def test_round_trip_small_large_and_empty(target, monkeypatch):
    bodies = {
        "small.csv": b"sku,qty\nA1,2\n",
        "large.bin": os.urandom(17 * MiB + 11),
        "empty.bin": b"",
    }
    for name, body in bodies.items():
        uploaded = _upload(target, monkeypatch, body, f"in/{name}")
        assert uploaded["ok"] is True, uploaded
        assert uploaded["result"]["sha256"] == hashlib.sha256(body).hexdigest()

    listed = ops.handle_payload(_payload(target, "list_files", {"path": "in"}))
    assert listed["ok"] is True, listed
    assert sorted(row["name"] for row in listed["result"]["files"]) == sorted(bodies)
    sizes = {row["name"]: row["size_bytes"] for row in listed["result"]["files"]}
    assert sizes == {name: len(body) for name, body in bodies.items()}

    for name, body in bodies.items():
        fetched, data = _fetch(target, monkeypatch, f"in/{name}")
        assert fetched["ok"] is True, fetched
        assert data == body
        assert fetched["result"]["sha256"] == hashlib.sha256(body).hexdigest()
    assert _open_uploads(target) == []


def test_conditional_create_never_overwrites(target, monkeypatch):
    first = _upload(target, monkeypatch, b"first", "out/report.csv")
    second_small = _upload(target, monkeypatch, b"second", "out/report.csv")
    second_large = _upload(target, monkeypatch, os.urandom(9 * MiB), "out/report.csv")
    _, data = _fetch(target, monkeypatch, "out/report.csv")

    assert first["ok"] is True, first
    assert second_small["error_code"] == "already_exists", second_small
    assert second_large["error_code"] == "already_exists", second_large
    assert second_large["definitely_no_external_effect"] is True
    assert data == b"first"
    assert _open_uploads(target) == []


def test_overwrite_replaces(target, monkeypatch):
    _upload(target, monkeypatch, b"first", "out/report.csv")
    replaced = _upload(target, monkeypatch, b"second", "out/report.csv", overwrite=True)
    _, data = _fetch(target, monkeypatch, "out/report.csv")

    assert replaced["ok"] is True, replaced
    assert data == b"second"


def test_listing_is_bounded_and_prefix_isolated(target, monkeypatch):
    connection = _connection(target)
    try:
        bucket, prefix = target["config"]["bucket"], target["config"]["root_prefix"]

        async def _put_many() -> None:
            for index in range(505):
                await connection._client.put_object(
                    Bucket=bucket, Key=f"{prefix}/many/{index:04d}.csv", Body=b"x"
                )
            await connection._client.put_object(
                Bucket=bucket, Key=f"{prefix}/many-old/x.csv", Body=b"x"
            )
            await connection._client.put_object(Bucket=bucket, Key=f"{prefix}/many/sub/", Body=b"")

        connection._run(_put_many())
    finally:
        connection.close()

    listed = ops.handle_payload(_payload(target, "list_files", {"path": "many", "limit": 500}))
    neighbour = ops.handle_payload(_payload(target, "list_files", {"path": "many-old"}))

    assert listed["result"]["truncated"] is True
    assert len(listed["result"]["files"]) == 500
    assert [row["name"] for row in neighbour["result"]["files"]] == ["x.csv"]


def test_missing_object_is_not_found(target, monkeypatch):
    response, _ = _fetch(target, monkeypatch, "nope.csv")

    assert response["error_code"] == "not_found"


def test_wrong_secret_is_an_authentication_failure(target):
    target = {**target, "secrets": {**target["secrets"], "secret_access_key": "wrong-secret"}}

    response = ops.handle_payload(_payload(target, "list_files", {"path": "."}))

    assert response["error_code"] in {"authentication_failed", "permission_denied"}
    assert "wrong-secret" not in str(response)
