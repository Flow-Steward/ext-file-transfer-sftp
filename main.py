#!/usr/bin/env python3
"""FTP/FTPS/SFTP file transfer extension subprocess entrypoint."""

from __future__ import annotations

import json
import sys

import file_transfer_extension


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except Exception:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "invalid_json",
                    "error": "Request payload must be JSON",
                    "errors": [{"code": "invalid_json", "message": "Request payload must be JSON"}],
                    "external_effect_status": "failed",
                    "definitely_no_external_effect": True,
                }
            )
        )
        return 2
    if not isinstance(payload, dict):
        print(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "invalid_payload",
                    "error": "Request payload must be a JSON object",
                    "errors": [
                        {
                            "code": "invalid_payload",
                            "message": "Request payload must be a JSON object",
                        }
                    ],
                    "external_effect_status": "failed",
                    "definitely_no_external_effect": True,
                },
                sort_keys=True,
            )
        )
        return 2
    response = file_transfer_extension.handle_payload(payload)
    print(json.dumps(response, sort_keys=True))
    return 0 if response.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
