"""Behavioral controls for the exact, locally maintained AWS dependency graph."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import UTC, datetime

import pytest
from aiobotocore.config import AioConfig
from botocore.credentials import _parse_if_needed
from botocore.utils import parse_timestamp
from dateutil.parser import isoparse  # type: ignore[import-untyped]

from connections.s3 import _isolated_session


def test_async_presigned_posts_do_not_mutate_or_reuse_caller_conditions():
    """Match the botocore 1.43.127 ownership fix in its copied async counterpart."""
    conditions = [["starts-with", "$Content-Type", "text/"]]
    original = json.loads(json.dumps(conditions))

    async def run():
        async with _isolated_session().create_client(
            "s3",
            region_name="us-east-1",
            endpoint_url="https://s3.test",
            aws_access_key_id="EXPLICIT",
            aws_secret_access_key="explicit-secret",
            aws_session_token="explicit-token",
            config=AioConfig(
                signature_version="s3v4", proxies={}, retries={"total_max_attempts": 1}
            ),
        ) as client:
            first = await client.generate_presigned_post(
                Bucket="data", Key="first.txt", Conditions=conditions
            )
            second = await client.generate_presigned_post(
                Bucket="data", Key="second.txt", Conditions=conditions
            )
        return first, second

    first, second = asyncio.run(run())
    assert conditions == original
    first_policy = json.loads(base64.b64decode(first["fields"]["policy"]))
    second_policy = json.loads(base64.b64decode(second["fields"]["policy"]))
    assert {"key": "first.txt"} in first_policy["conditions"]
    assert {"key": "first.txt"} not in second_policy["conditions"]
    assert {"key": "second.txt"} in second_policy["conditions"]
    assert first["fields"]["x-amz-security-token"] == "explicit-token"


@pytest.mark.parametrize(
    "value",
    [
        "2026-11-10T09:08:07Z",
        "Tue, 10 Nov 2026 09:08:07 GMT",
        "2026-11-10T11:08:07+02:00",
        1794301687,
        "1794301687",
    ],
)
def test_aws_timestamp_parser_accepts_s3_wire_and_epoch_formats(value):
    assert parse_timestamp(value).astimezone(UTC) == datetime(2026, 11, 10, 9, 8, 7, tzinfo=UTC)


def test_credential_expiry_parser_retains_explicit_utc_offset():
    assert _parse_if_needed("2026-11-10T11:08:07+02:00").astimezone(UTC) == datetime(
        2026, 11, 10, 9, 8, 7, tzinfo=UTC
    )


@pytest.mark.parametrize("value", ["20200728121240", "2014- 4-21", "2_14-04-21"])
def test_dateutil_rejects_malformed_iso_numeric_fields(value):
    with pytest.raises(ValueError):
        isoparse(value)
