"""The S3 network boundary: explicit keys only, one validated address, no redirects out."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from aiohttp import web

import file_operations as ops
from connections import s3
from tests._fake_s3 import DECOY_IP, ENDPOINT_HOST, SERVER_IP, FakeS3, write_certificates


@pytest.fixture
def lookups(monkeypatch) -> list[str]:
    seen: list[str] = []

    def _resolve(host: str, *, port: int, purpose: str) -> list[str]:
        seen.append(host)
        return [SERVER_IP]

    monkeypatch.setattr(s3, "resolve_pinned_ips", _resolve)
    return seen


def _start(tmp_path, monkeypatch, names: list[str]) -> FakeS3:
    ca, cert, key = write_certificates(tmp_path, names)
    monkeypatch.setenv("SSL_CERT_FILE", str(ca))
    fake = FakeS3()
    fake.start(cert, key)
    return fake


@pytest.fixture
def server(tmp_path, monkeypatch, lookups) -> Iterator[FakeS3]:
    fake = _start(tmp_path, monkeypatch, [ENDPOINT_HOST, f"data.{ENDPOINT_HOST}", "other.test"])
    try:
        yield fake
    finally:
        fake.stop()


def _payload(server: FakeS3, operation: str = "list_files", **overrides: Any) -> dict[str, Any]:
    config = {
        "endpoint_url": f"https://{ENDPOINT_HOST}:{server.port}",
        "region": "us-east-1",
        "bucket": "data",
        **overrides.pop("config", {}),
    }
    secrets = overrides.pop(
        "secrets", {"access_key_id": "AKIAEXPLICIT", "secret_access_key": "explicit-secret"}
    )
    return {
        "contract_version": "extension_host_v2",
        "runtime_context": {},
        "action": {
            "action_id": operation,
            "target": {
                "connection": {"connection_type_id": "s3", "config": config, "secrets": secrets}
            },
            "input": overrides.pop("input", {"path": "."}),
        },
    }


def _hostile_environment(monkeypatch, server: FakeS3) -> None:
    decoy = f"https://{DECOY_IP}:{server.decoy_port}"
    for name, value in {
        "AWS_ACCESS_KEY_ID": "AKIAHOSTILE",
        "AWS_SECRET_ACCESS_KEY": "hostile-secret",
        "AWS_SESSION_TOKEN": "hostile-token",
        "AWS_PROFILE": "hostile",
        "AWS_DEFAULT_REGION": "eu-hostile-1",
        "AWS_ENDPOINT_URL": decoy,
        "AWS_ENDPOINT_URL_S3": decoy,
        "AWS_CA_BUNDLE": "/nonexistent/ca.pem",
        "AWS_DEFAULTS_MODE": "auto",
        "AWS_EC2_METADATA_SERVICE_ENDPOINT": decoy,
        "AWS_MAX_ATTEMPTS": "9",
        "AWS_RETRY_MODE": "adaptive",
        "HTTPS_PROXY": decoy,
        "HTTP_PROXY": decoy,
        "ALL_PROXY": decoy,
        "BOTOCORE_EXPERIMENTAL__PLUGINS": "hostile=hostile_plugin_module",
    }.items():
        monkeypatch.setenv(name, value)


# --- credentials -------------------------------------------------------------------


def test_explicit_keys_win_over_a_hostile_environment(server, monkeypatch):
    _hostile_environment(monkeypatch, server)

    response = ops.handle_payload(_payload(server))

    assert response["ok"] is True
    authorization = server.seen[0].headers["Authorization"]
    assert "Credential=AKIAEXPLICIT/" in authorization
    assert "/us-east-1/s3/" in authorization
    assert "X-Amz-Security-Token" not in server.seen[0].headers
    assert server.decoy_seen == []


def test_missing_keys_are_refused_before_any_client(server, monkeypatch, lookups):
    _hostile_environment(monkeypatch, server)

    response = ops.handle_payload(_payload(server, secrets={}))

    assert response["error_code"] == "invalid_connection"
    assert lookups == []
    assert server.seen == []
    assert server.decoy_seen == []


def test_session_token_is_sent_only_when_configured(server):
    secrets = {
        "access_key_id": "ASIAEXPLICIT",
        "secret_access_key": "explicit-secret",
        "session_token": "explicit-token",
    }

    ops.handle_payload(_payload(server, secrets=secrets))

    assert server.seen[0].headers["X-Amz-Security-Token"] == "explicit-token"


# --- endpoint and addressing -------------------------------------------------------


def test_endpoint_is_resolved_once_per_invocation(server, lookups):
    server.objects.update({f"{i:04d}.csv": b"x" for i in range(30)})
    server.page_size = 10

    ops.handle_payload(_payload(server))

    assert lookups == [ENDPOINT_HOST]
    assert len(server.seen) == 3


def test_virtual_host_addressing_uses_the_bucket_host(server, lookups):
    response = ops.handle_payload(_payload(server, config={"addressing_style": "virtual"}))

    assert response["ok"] is True
    assert lookups == [f"data.{ENDPOINT_HOST}"]
    assert server.seen[0].host == f"data.{ENDPOINT_HOST}"
    assert server.seen[0].path == "/"


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://s3.test",
        "https://user:pass@s3.test",
        "https://s3.test/some/path",
        "https://s3.test/?x=1",
        "https://s3.test/#frag",
        "file:///etc/passwd",
    ],
)
def test_endpoint_must_be_a_bare_https_origin(server, endpoint, lookups):
    response = ops.handle_payload(_payload(server, config={"endpoint_url": endpoint}))

    assert response["error_code"] == "invalid_connection"
    assert lookups == []


def test_dotted_bucket_is_refused_for_virtual_hosts(server):
    response = ops.handle_payload(
        _payload(server, config={"bucket": "my.bucket", "addressing_style": "virtual"})
    )

    assert response["error_code"] == "invalid_connection"


# --- redirects ---------------------------------------------------------------------


@pytest.mark.parametrize("target", ["decoy", "other-host"])
def test_redirect_out_of_the_endpoint_is_never_followed(server, target):
    location = (
        f"https://{DECOY_IP}:{server.decoy_port}/data?list-type=2"
        if target == "decoy"
        else f"https://other.test:{server.port}/data?list-type=2"
    )
    server.hooks["list"] = lambda request: web.Response(status=307, headers={"Location": location})

    response = ops.handle_payload(_payload(server))

    assert response["ok"] is False
    assert server.decoy_seen == []
    assert all(seen.host == ENDPOINT_HOST for seen in server.seen)


# --- network policy ----------------------------------------------------------------


def test_private_endpoint_is_blocked_by_the_sdk_policy(tmp_path, monkeypatch):
    monkeypatch.delenv("FS_ALLOW_PRIVATE_REMOTE_URLS", raising=False)
    fake = _start(tmp_path, monkeypatch, [ENDPOINT_HOST])
    try:
        payload = _payload(fake, config={"endpoint_url": f"https://127.0.0.1:{fake.port}"})

        response = ops.handle_payload(payload)

        assert response["error_code"] == "network_blocked"
        assert response["definitely_no_external_effect"] is True
        assert fake.seen == []
    finally:
        fake.stop()


def test_certificate_for_another_name_is_rejected(tmp_path, monkeypatch, lookups):
    fake = _start(tmp_path, monkeypatch, ["not-the-endpoint.test"])
    try:
        response = ops.handle_payload(_payload(fake))

        assert response["ok"] is False
        assert response["error_code"] in {"network_blocked", "provider_unavailable"}
        assert fake.seen == []
    finally:
        fake.stop()


def test_errors_never_carry_keys(server):
    secrets = {"access_key_id": "AKIAEXPLICIT", "secret_access_key": "explicit-secret"}
    server.hooks["list"] = lambda request: web.Response(
        status=403,
        body=b"<Error><Code>AccessDenied</Code><Message>AKIAEXPLICIT explicit-secret</Message></Error>",
        content_type="application/xml",
    )

    response = ops.handle_payload(_payload(server, secrets=secrets))

    assert response["error_code"] == "permission_denied"
    assert "AKIAEXPLICIT" not in str(response)
    assert "explicit-secret" not in str(response)
