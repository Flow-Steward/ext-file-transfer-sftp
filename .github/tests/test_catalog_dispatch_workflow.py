"""Run the actual catalog-notification shell steps with only GitHub I/O replaced."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


@pytest.fixture
def notification(tmp_path):
    job = yaml.safe_load(WORKFLOW.read_text())["jobs"]["announce_catalog"]
    scripts = [step["run"] for step in job["steps"]]
    capture = tmp_path / "requests.jsonl"
    binary = tmp_path / "gh"
    # This boundary stub has no network client and refuses every release mutation.
    binary.write_text(
        f"#!{sys.executable}\n"
        + r"""
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["DISPATCH_CAPTURE"]).open("a") as output:
    output.write(json.dumps(args) + "\n")
if args[:2] == ["release", "view"]:
    state = os.environ.get("SOURCE_RELEASE_STATE", "published")
    if state == "missing":
        print("Release not found", file=sys.stderr)
        sys.exit(1)
    print("true" if state == "draft" else "false")
elif args[:1] == ["api"]:
    status = os.environ.get("DISPATCH_RESPONSE", "204")
    if status != "204":
        print("Dispatch rejected: " + status, file=sys.stderr)
        sys.exit(1)
else:
    print("Unexpected or mutating GitHub command", file=sys.stderr)
    sys.exit(97)
"""
    )
    binary.chmod(0o700)
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ.get("PATH", ""),
        "SOURCE_REPOSITORY": "Flow-Steward/example-fixture",
        "RELEASE_TAG": "v1.2.0",
        "GH_TOKEN": uuid.uuid4().hex,
        "DISPATCH_CAPTURE": str(capture),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
    }

    def run(step: int, **overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", scripts[step]],
            cwd=tmp_path,
            env={**env, **overrides},
            capture_output=True,
            text=True,
            check=False,
        )

    def requests() -> list[list[str]]:
        if not capture.exists():
            return []
        return [json.loads(line) for line in capture.read_text().splitlines()]

    return run, requests, tmp_path


@pytest.mark.parametrize(
    ("state", "succeeds"), [("published", True), ("draft", False), ("missing", False)]
)
def test_only_an_existing_published_release_passes_verification(notification, state, succeeds):
    run, requests, _tmp_path = notification

    result = run(0, SOURCE_RELEASE_STATE=state)

    assert (result.returncode == 0) is succeeds, result.stderr
    assert requests() == [
        [
            "release",
            "view",
            "v1.2.0",
            "--repo",
            "Flow-Steward/example-fixture",
            "--json",
            "isDraft",
            "--jq",
            ".isDraft",
        ]
    ]
    if not succeeds:
        assert "::error::" in result.stdout


def test_an_empty_retry_tag_is_refused_before_any_github_request(notification):
    run, requests, _tmp_path = notification

    result = run(0, RELEASE_TAG="")

    assert result.returncode != 0
    assert "::error::" in result.stdout
    assert requests() == []


def test_dispatch_posts_the_catalog_event_and_original_release_identity(notification):
    run, requests, tmp_path = notification

    result = run(1)

    assert result.returncode == 0, result.stderr
    assert requests() == [
        [
            "api",
            "--hostname",
            "github.com",
            "--method",
            "POST",
            "repos/Flow-Steward/extensions/dispatches",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2026-03-10",
            "--raw-field",
            "event_type=extension-released",
            "--raw-field",
            "client_payload[repository]=Flow-Steward/example-fixture",
            "--raw-field",
            "client_payload[tag]=v1.2.0",
        ]
    ]
    assert "Catalog notification accepted" in (tmp_path / "summary.md").read_text()


@pytest.mark.parametrize("status", ["403", "404", "422", "transport-error"])
def test_dispatch_failure_is_visible_and_never_rewrites_the_release(notification, status):
    run, requests, tmp_path = notification

    result = run(1, DISPATCH_RESPONSE=status)

    assert result.returncode != 0
    assert "::error::Catalog notification failed" in result.stdout
    assert "remain published" in result.stdout
    assert len(requests()) == 1
    assert requests()[0][0] == "api"
    assert not (tmp_path / "summary.md").exists()


def test_a_missing_dispatch_credential_uses_scheduled_catalog_without_calling_github(notification):
    run, requests, _tmp_path = notification

    result = run(1, GH_TOKEN="")

    assert result.returncode == 0, result.stderr
    assert (
        "::notice::Catalog updates on schedule; instant notification not configured."
        in result.stdout
    )
    assert "::error::" not in result.stdout
    assert "Catalog notification accepted" not in result.stdout
    assert requests() == []


def test_a_retry_tag_is_always_data_in_both_shell_steps(notification):
    run, requests, tmp_path = notification
    marker = tmp_path / "injected"
    tag = f"v1.2.0; touch {marker}; $(touch {marker})"

    verified = run(0, RELEASE_TAG=tag)
    announced = run(1, RELEASE_TAG=tag)

    assert verified.returncode == 0, verified.stderr
    assert announced.returncode == 0, announced.stderr
    assert requests()[0][2] == tag
    assert requests()[1][-1] == f"client_payload[tag]={tag}"
    assert not marker.exists()


def test_repository_tooling_is_not_in_an_installed_archive(tmp_path, monkeypatch):
    repository_root = ROOT
    contract_path = Path(__file__).resolve().relative_to(repository_root).as_posix()
    package_path = repository_root / ".github" / "scripts" / "package_extension.py"
    spec = importlib.util.spec_from_file_location("extension_package_under_test", package_path)
    assert spec is not None and spec.loader is not None
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    # Include the proposed tooling file as if committed; no staging is needed.
    snapshot = {
        "extension.yaml": "extension_id: acme.packaging-probe\nversion: 1.0.0\n",
        "main.py": "print('runtime')\n",
        "tests/test_runtime.py": "def test_runtime(): pass\n",
        contract_path: Path(__file__).read_text(),
        ".github/scripts/package_extension.py": package_path.read_text(),
        ".github/workflows/release.yml": (
            repository_root / ".github/workflows/release.yml"
        ).read_text(),
    }
    for name, content in snapshot.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    monkeypatch.setattr(package, "ROOT", tmp_path)
    monkeypatch.setattr(
        package.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["git", "ls-files", "-z"], returncode=0, stdout="\0".join(snapshot) + "\0"
        ),
    )

    assert package.main() == 0

    archive = tmp_path / "dist" / "acme.packaging-probe-1.0.0.zip"
    with zipfile.ZipFile(archive) as bundle:
        assert sorted(bundle.namelist()) == [
            "acme_packaging_probe/extension.yaml",
            "acme_packaging_probe/main.py",
            "acme_packaging_probe/tests/test_runtime.py",
        ]
