"""Reproduce the disclosed AWS compatibility forks from exact official PyPI wheels.

Usage: python scripts/rebuild_aws_wheels.py /path/to/official/wheels [output-directory]
Download URLs and hashes are recorded in dependency-sources.json. No network,
resolver, build backend or unrecorded source change runs in this transformation.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rebuild(row: dict, upstream_directory: Path, output_directory: Path) -> Path:
    upstream = upstream_directory / row["upstream_url"].rsplit("/", 1)[-1]
    data = upstream.read_bytes()
    if sha256(data) != row["upstream_sha256"]:
        raise ValueError(f"upstream hash mismatch: {upstream.name}")
    patch_data = (ROOT / row["patches"]).read_bytes()
    if sha256(patch_data) != row["patch_sha256"]:
        raise ValueError(f"patch hash mismatch: {row['patches']}")
    patches = json.loads(patch_data)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files = {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
    for patch in patches:
        original = files[patch["path"]]
        if sha256(original) != patch["sha256"]:
            raise ValueError(f"source hash mismatch: {patch['path']}")
        text = original.decode("utf-8")
        for old, new in patch["replacements"]:
            if text.count(old) != 1:
                raise ValueError(f"patch must match exactly once: {patch['path']}")
            text = text.replace(old, new, 1)
        files[patch["path"]] = text.encode("utf-8")
    old_info = f"{row['name'].replace('-', '_')}-{row['upstream_version']}.dist-info"
    new_info = f"{row['name'].replace('-', '_')}-{row['version']}.dist-info"
    files = {
        name.replace(old_info + "/", new_info + "/", 1): body
        for name, body in files.items()
        if name != old_info + "/RECORD"
    }
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, body in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
        writer.writerow([name, "sha256=" + digest, str(len(body))])
    writer.writerow([new_info + "/RECORD", "", ""])
    files[new_info + "/RECORD"] = record.getvalue().encode()
    output_directory.mkdir(parents=True, exist_ok=True)
    target = output_directory / row["wheel_filename"]
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, body in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 10, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, body, compresslevel=9)
    if row.get("wheel_sha256") and sha256(target.read_bytes()) != row["wheel_sha256"]:
        raise ValueError(f"rebuilt wheel hash mismatch: {target.name}")
    return target


def main() -> None:
    source = Path(sys.argv[1])
    destination = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "wheels"
    for row in json.loads((ROOT / "dependency-sources.json").read_text())["dependencies"]:
        print(rebuild(row, source, destination))


if __name__ == "__main__":
    main()
