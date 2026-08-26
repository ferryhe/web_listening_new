"""Authorized Phase 9 CLI canary; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring
# pylint: disable=too-many-boolean-expressions,too-many-locals

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from web_listening.result.model import Result

TARGETS = Path(__file__).with_name("phase_09_site_targets.json")
SMOKE_CATALOG = Path(__file__).parent / "catalog" / "smoke_site_catalog.json"
SITE_SKILLS = Path(__file__).parent / "catalog" / "site_skill_cases.json"
AUTHORIZED_WINDOW = "issue-10-2026-08-26-user-authorized"
PHASE_8B_CANONICAL_REQUEST_SHA256 = (
    "775dc2b617d54fcc28c517bda0f5a121fcec92b82d756438fb09dd6fae4467f7"
)


def _newline_canonical_sha256(content: bytes) -> str:
    text = content.decode("utf-8").replace("\r\n", "\n")
    canonical = text.replace("\n", "\r\n").encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _canonical_sha256(value: object) -> str:
    content = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def _load_snapshot() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    payload = json.loads(TARGETS.read_bytes())
    targets = payload.get("targets")
    if not isinstance(targets, list) or len(targets) != 1:
        pytest.fail("Phase 9 live snapshot must contain exactly one target")
    target = targets[0]
    if not isinstance(target, dict) or target.get("site_key") != "ipcc":
        pytest.fail("Phase 9 live snapshot must select only ipcc")
    expected_limits = {
        "max_content_reads_per_target": 1,
        "max_total_requests": 6,
        "max_bytes_per_response": 2 * 1024 * 1024,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
    }
    if payload.get("network_limits") != expected_limits:
        pytest.fail("Phase 9 network limits drifted from the authorized caps")
    for key, path in (
        ("source_catalog_sha256", SMOKE_CATALOG),
        ("site_skill_catalog_sha256", SITE_SKILLS),
    ):
        if _newline_canonical_sha256(path.read_bytes()).upper() != payload.get(key):
            pytest.fail(f"Phase 9 {key} drifted")

    smoke_rows = json.loads(SMOKE_CATALOG.read_bytes()).get("sites")
    cases = json.loads(SITE_SKILLS.read_bytes()).get("cases")
    if not isinstance(smoke_rows, list) or not isinstance(cases, list):
        pytest.fail("Phase 9 source catalogs are invalid")
    smoke = next((row for row in smoke_rows if row.get("site_key") == "ipcc"), None)
    case = next((row for row in cases if row.get("site_key") == "ipcc"), None)
    if not isinstance(smoke, dict) or not isinstance(case, dict):
        pytest.fail("Phase 9 IPCC source rows are missing")
    if (
        smoke["urls"]["monitor"] != target["url"]
        or smoke["allowed_origins"] != target["allowed_origins"]
        or smoke["historical_classification"]["expectation"]
        != target["historical_expectation"]
        or smoke["evidence_thresholds"]["monitor_min_words"]
        != target["monitor_min_words"]
        or smoke["provenance"] != target["provenance"]
        or smoke["tool_facts"] != target["tool_facts"]
        or case["site_skill"]["digest"] != target["site_skill_digest"]
    ):
        pytest.fail("Phase 9 target is not the audited IPCC catalog projection")

    canonical_request = payload.get("canonical_request")
    if not isinstance(canonical_request, dict):
        pytest.fail("Phase 9 canonical Request is missing")
    if payload.get("canonical_request_sha256") != PHASE_8B_CANONICAL_REQUEST_SHA256:
        pytest.fail("Phase 9 must preserve the exact Phase 8B canonical Request digest")
    expected_request = {
        "scope": {
            "seeds": [target["url"]],
            "allowed_origins": target["allowed_origins"],
            "include_paths": ["/**"],
            "content_types": ["html"],
        },
        "site_skill": case["site_skill"],
        "explore_all_tools": False,
        "budgets": {
            "max_requests": 12,
            "max_bytes": 2 * 1024 * 1024,
            "max_runtime_seconds": 30,
            "max_tool_attempts_per_target": 1,
        },
    }
    if canonical_request != expected_request:
        pytest.fail("Phase 9 Request drifted from the Phase 8B canonical fixture")
    if _canonical_sha256(canonical_request) != payload.get("canonical_request_sha256"):
        pytest.fail("Phase 9 canonical Request digest drifted")
    return payload, target, canonical_request


def _load_authorized_snapshot() -> (
    tuple[dict[str, object], dict[str, object], dict[str, object]]
):
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 9 CLI live test is offline by default")
    if os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW") != AUTHORIZED_WINDOW:
        pytest.fail("the exact Phase 9 authorized live window is required")
    if os.environ.get("WEB_LISTENING_LIVE_SITE") != "ipcc":
        pytest.fail("WEB_LISTENING_LIVE_SITE must select the frozen ipcc key")
    return _load_snapshot()


def _sanitize_artifact_stdout(stdout_json: object) -> dict[str, object]:
    if not isinstance(stdout_json, dict):
        return {"content_redacted": True}
    projection = {
        key: stdout_json.get(key)
        for key in (
            "artifact_id",
            "blob_sha256",
            "size_bytes",
            "mime_type",
            "content_encoding",
        )
    }
    projection["content_redacted"] = True
    content = stdout_json.get("content")
    if isinstance(content, str):
        try:
            decoded = base64.b64decode(content, validate=True)
        except ValueError:
            pass
        else:
            projection["content_sha256"] = hashlib.sha256(decoded).hexdigest()
    return projection


def _invoke(
    executable: str,
    argv: list[str],
    sanitized_argv: list[str],
    *,
    redact_artifact_content: bool = False,
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    completed = subprocess.run(
        [executable, *argv],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    try:
        stdout_json = json.loads(completed.stdout) if completed.stdout else None
    except json.JSONDecodeError:
        stdout_json = None
    evidence = {
        "argv": ["web-listening", *sanitized_argv],
        "exit_code": completed.returncode,
        "stdout_json": (
            _sanitize_artifact_stdout(stdout_json)
            if redact_artifact_content
            else stdout_json
        ),
        "stderr": completed.stderr,
    }
    return completed, evidence


def _emit(record: dict[str, object], capsys: pytest.CaptureFixture[str]) -> None:
    with capsys.disabled():
        print(json.dumps(record, ensure_ascii=True, sort_keys=True), flush=True)


def test_artifact_evidence_redacts_content_but_retains_safe_hash_metadata() -> None:
    content = b"private website bytes must not enter evidence"
    encoded = base64.b64encode(content).decode("ascii")
    artifact_stdout = {
        "artifact_id": "artifact-safe",
        "blob_sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
        "mime_type": "text/html",
        "content_encoding": "base64",
        "content": encoded,
        "unexpected": "must not pass the allowlist",
    }

    evidence = _sanitize_artifact_stdout(artifact_stdout)
    serialized = json.dumps(evidence, sort_keys=True)

    assert evidence == {
        "artifact_id": "artifact-safe",
        "blob_sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
        "mime_type": "text/html",
        "content_encoding": "base64",
        "content_redacted": True,
        "content_sha256": hashlib.sha256(content).hexdigest(),
    }
    assert "content" not in evidence
    assert encoded not in serialized
    assert content.decode("ascii") not in serialized
    assert "unexpected" not in serialized


def test_artifact_evidence_redacts_malformed_content_without_hashing() -> None:
    evidence = _sanitize_artifact_stdout(
        {
            "artifact_id": "artifact-malformed",
            "content_encoding": "base64",
            "content": "not base64!",
        }
    )

    assert evidence == {
        "artifact_id": "artifact-malformed",
        "blob_sha256": None,
        "size_bytes": None,
        "mime_type": None,
        "content_encoding": "base64",
        "content_redacted": True,
    }


def test_phase_09_snapshot_reuses_the_phase_8b_request_and_ipcc_projection() -> None:
    payload, target, request = _load_snapshot()

    assert payload["phase"] == "9"
    assert target["site_key"] == "ipcc"
    assert payload["canonical_request_sha256"] == _canonical_sha256(request)


def test_live_canary_source_uses_only_the_real_console_executable() -> None:
    source = inspect.getsource(test_phase_09_cli_live)

    assert source.count("_invoke(") == 3
    assert 'shutil.which("web-listening")' in source
    assert "RuntimeService" not in source
    assert "python -m" not in source
    assert "monkeypatch" not in source
    assert "mock" not in source.lower()
    assert 'assert attempt.outcome == "succeeded"' in source
    assert "assert len(result.artifacts) == 1" in source
    assert "assert not result.manifest.redirects" in source
    assert 'payload["network_limits"]["retry"] == 0' in source
    assert source.count("redact_artifact_content=True") == 1


@pytest.mark.parametrize("selector", [None, "", "https://www.ipcc.ch/", "other-site"])
def test_explicit_live_requires_the_exact_ipcc_selector(
    monkeypatch: pytest.MonkeyPatch, selector: str | None
) -> None:
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", AUTHORIZED_WINDOW)
    if selector is None:
        monkeypatch.delenv("WEB_LISTENING_LIVE_SITE", raising=False)
    else:
        monkeypatch.setenv("WEB_LISTENING_LIVE_SITE", selector)

    with pytest.raises(pytest.fail.Exception, match="frozen ipcc key"):
        _load_authorized_snapshot()


@pytest.mark.live
def test_phase_09_cli_live(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Acquire IPCC once, then reopen its Job and Artifact through the CLI."""
    payload, target, request = _load_authorized_snapshot()
    executable = shutil.which("web-listening")
    if executable is None:
        pytest.fail("the installed/worktree web-listening executable is required")
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    data_dir = tmp_path / "runtime-data"
    transport_cap_scope: dict[str, object] = {
        "phase_09_verifies": "Result-visible target usage",
        "result_visible_max_requests": 6,
        "cli_result_includes_robots_traffic": False,
        "total_transport_assurance": "unchanged Issue #32 audited governed path",
        "canonical_request_unchanged": True,
        "canonical_request_sha256": PHASE_8B_CANONICAL_REQUEST_SHA256,
    }
    record: dict[str, object] = {
        "schema_version": "phase-09-cli-live-evidence.v1",
        "authorization_window": AUTHORIZED_WINDOW,
        "snapshot_sha256": hashlib.sha256(TARGETS.read_bytes()).hexdigest(),
        "input": {
            "site_key": target["site_key"],
            "request": request,
            "canonical_request_sha256": payload["canonical_request_sha256"],
        },
        "network_limits": payload["network_limits"],
        "transport_cap_scope": transport_cap_scope,
        "commands": [],
        "id_mapping": {},
        "exit_behavior": "failure",
    }
    try:
        acquire, evidence = _invoke(
            executable,
            [
                "acquire",
                "--request",
                str(request_path),
                "--output",
                str(data_dir),
                "--json",
            ],
            [
                "acquire",
                "--request",
                "<request.json>",
                "--output",
                "<runtime-data>",
                "--json",
            ],
        )
        record["commands"].append(evidence)
        assert acquire.returncode == 0 and acquire.stderr == ""
        acquire_json = json.loads(acquire.stdout)
        result = Result.from_dict(acquire_json["result"])
        assert result.status.value == "completed"
        assert len(result.attempts) == 1
        attempt = result.attempts[0]
        assert attempt.outcome == "succeeded"
        assert result.usage.requests <= 6
        assert result.usage.bytes_received <= 2 * 1024 * 1024
        assert result.usage.tool_attempts == 1
        assert len(result.artifacts) == 1
        assert not result.manifest.redirects
        assert payload["network_limits"]["retry"] == 0
        assert payload["network_limits"]["concurrency"] == 1
        job_id = acquire_json["job_id"]
        artifact_id = acquire_json["result"]["artifacts"][0]["artifact_id"]
        transport_cap_scope["observed_result_requests"] = result.usage.requests
        record["result_visible_contract"] = {
            "successful_attempts": 1,
            "artifacts": 1,
            "target_redirects": 0,
            "synchronous_acquire_invocations": 1,
            "read_artifact_invocations": 1,
            "retry": 0,
        }

        get_job, evidence = _invoke(
            executable,
            ["get-job", job_id, "--output", str(data_dir), "--json"],
            ["get-job", job_id, "--output", "<runtime-data>", "--json"],
        )
        record["commands"].append(evidence)
        assert get_job.returncode == 0 and get_job.stderr == ""
        get_job_json = json.loads(get_job.stdout)
        assert get_job_json == acquire_json

        read_artifact, evidence = _invoke(
            executable,
            [
                "read-artifact",
                artifact_id,
                "--output",
                str(data_dir),
                "--json",
            ],
            [
                "read-artifact",
                artifact_id,
                "--output",
                "<runtime-data>",
                "--json",
            ],
            redact_artifact_content=True,
        )
        record["commands"].append(evidence)
        assert read_artifact.returncode == 0 and read_artifact.stderr == ""
        artifact_json = json.loads(read_artifact.stdout)
        content = base64.b64decode(artifact_json["content"], validate=True)
        evidence_hash = acquire_json["result"]["artifacts"][0]["sha256"]
        assert artifact_json["artifact_id"] == artifact_id
        assert artifact_json["content_encoding"] == "base64"
        assert len(content) == artifact_json["size_bytes"] <= 2 * 1024 * 1024
        assert hashlib.sha256(content).hexdigest() == evidence_hash
        assert artifact_json["blob_sha256"].removeprefix("sha256:") == evidence_hash

        record["id_mapping"] = {
            "acquire_job_id": job_id,
            "get_job_id": get_job_json["job_id"],
            "result_artifact_id": artifact_id,
            "read_artifact_id": artifact_json["artifact_id"],
        }
        record["exit_behavior"] = "pytest_pass"
    finally:
        _emit(record, capsys)
