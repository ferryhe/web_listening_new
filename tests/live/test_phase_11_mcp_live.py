"""Authorized Phase 11 MCP stdio canary; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring
# pylint: disable=too-many-boolean-expressions,too-many-locals,too-many-statements
# pylint: disable=import-error,too-many-arguments,too-many-branches
# pylint: disable=wrong-import-position

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="install the optional web-listening[mcp] extra")

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from web_listening.result.model import Result

ROOT = Path(__file__).parents[2]
TARGETS = Path(__file__).with_name("phase_11_site_targets.json")
PHASE_9_TARGETS = Path(__file__).with_name("phase_09_site_targets.json")
SMOKE_CATALOG = Path(__file__).parent / "catalog" / "smoke_site_catalog.json"
SITE_SKILLS = Path(__file__).parent / "catalog" / "site_skill_cases.json"
AUTHORIZED_WINDOW = "issue-12-2026-08-26-user-authorized"
CANONICAL_REQUEST_SHA256 = (
    "775dc2b617d54fcc28c517bda0f5a121fcec92b82d756438fb09dd6fae4467f7"
)
TOOL_NAMES = {
    "web_listening_acquire",
    "web_listening_get_job",
    "web_listening_read_artifact",
    "web_listening_validate_site_skill",
}


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
        pytest.fail("Phase 11 live snapshot must contain exactly one target")
    target = targets[0]
    if not isinstance(target, dict) or target.get("site_key") != "ipcc":
        pytest.fail("Phase 11 live snapshot must select only ipcc")
    expected_limits = {
        "max_content_reads_per_target": 1,
        "max_total_requests": 6,
        "max_bytes_per_response": 2 * 1024 * 1024,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
    }
    if payload.get("network_limits") != expected_limits:
        pytest.fail("Phase 11 network limits drifted from the authorized caps")
    for key, path in (
        ("source_catalog_sha256", SMOKE_CATALOG),
        ("site_skill_catalog_sha256", SITE_SKILLS),
    ):
        if _newline_canonical_sha256(path.read_bytes()).upper() != payload.get(key):
            pytest.fail(f"Phase 11 {key} drifted")

    smoke_rows = json.loads(SMOKE_CATALOG.read_bytes()).get("sites")
    cases = json.loads(SITE_SKILLS.read_bytes()).get("cases")
    if not isinstance(smoke_rows, list) or not isinstance(cases, list):
        pytest.fail("Phase 11 source catalogs are invalid")
    smoke = next((row for row in smoke_rows if row.get("site_key") == "ipcc"), None)
    case = next((row for row in cases if row.get("site_key") == "ipcc"), None)
    if not isinstance(smoke, dict) or not isinstance(case, dict):
        pytest.fail("Phase 11 IPCC source rows are missing")
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
        pytest.fail("Phase 11 target is not the audited IPCC catalog projection")

    canonical_request = payload.get("canonical_request")
    if not isinstance(canonical_request, dict):
        pytest.fail("Phase 11 canonical Request is missing")
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
    phase_9 = json.loads(PHASE_9_TARGETS.read_bytes())
    if canonical_request != expected_request:
        pytest.fail("Phase 11 Request drifted from the audited catalog projection")
    if canonical_request != phase_9.get("canonical_request"):
        pytest.fail("Phase 11 must reuse the exact Phase 9 canonical Request")
    if payload.get("canonical_request_sha256") != CANONICAL_REQUEST_SHA256:
        pytest.fail("Phase 11 must preserve the Phase 9 Request digest")
    if phase_9.get("canonical_request_sha256") != CANONICAL_REQUEST_SHA256:
        pytest.fail("Phase 9 canonical Request provenance drifted")
    if _canonical_sha256(canonical_request) != CANONICAL_REQUEST_SHA256:
        pytest.fail("Phase 11 canonical Request digest drifted")
    return payload, target, canonical_request


def _load_authorized_snapshot() -> (
    tuple[dict[str, object], dict[str, object], dict[str, object]]
):
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 11 MCP live test is offline by default")
    if os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW") != AUTHORIZED_WINDOW:
        pytest.fail("the exact Phase 11 authorized live window is required")
    if os.environ.get("WEB_LISTENING_LIVE_SITE") != "ipcc":
        pytest.fail("WEB_LISTENING_LIVE_SITE must select the frozen ipcc key")
    return _load_snapshot()


def _structured(result: object) -> dict[str, object]:
    value = getattr(result, "structuredContent")
    if not isinstance(value, dict):
        pytest.fail("MCP tool response must contain structured content")
    return value


def _sanitize_artifact(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {"content_redacted": True}
    projection = {
        key: value.get(key)
        for key in (
            "artifact_id",
            "blob_sha256",
            "size_bytes",
            "mime_type",
            "content_encoding",
        )
    }
    projection["content_redacted"] = True
    content = value.get("content")
    if isinstance(content, str):
        decoded = base64.b64decode(content, validate=True)
        projection["content_sha256"] = hashlib.sha256(decoded).hexdigest()
    return projection


def _exchange(
    name: str,
    arguments: dict[str, object],
    result: object,
    *,
    artifact: bool = False,
) -> dict[str, object]:
    response = _structured(result)
    if name == "web_listening_validate_site_skill":
        skill = arguments["site_skill"]
        assert isinstance(skill, dict)
        safe_arguments: object = {
            "site_skill": {
                "site_key": skill["site_key"],
                "digest": skill["digest"],
            }
        }
    else:
        safe_arguments = arguments
    return {
        "tool": name,
        "input": safe_arguments,
        "output": _sanitize_artifact(response) if artifact else response,
        "is_error": getattr(result, "isError"),
    }


def _emit(record: dict[str, object], capsys: pytest.CaptureFixture[str]) -> None:
    with capsys.disabled():
        print(json.dumps(record, ensure_ascii=True, sort_keys=True), flush=True)


async def _live_session(
    data_dir: Path,
    request: dict[str, object],
    record: dict[str, object],
) -> None:
    environment = {
        "PYTHONPATH": str(ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")
    }
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "web_listening.interfaces.mcp",
            "--data-dir",
            str(data_dir),
        ],
        cwd=ROOT,
        env=environment,
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            initialized = await session.initialize()
            listed = await session.list_tools()
            actual_names = [tool.name for tool in listed.tools]
            assert set(actual_names) == TOOL_NAMES
            assert initialized.capabilities.resources is None
            assert initialized.capabilities.prompts is None
            record["actual_tool_names"] = actual_names

            validate_arguments = {"site_skill": request["site_skill"]}
            validate = await session.call_tool(
                "web_listening_validate_site_skill", validate_arguments
            )
            assert validate.isError is False
            assert _structured(validate) == request["site_skill"]
            record["mcp_tool_exchanges"].append(
                _exchange(
                    "web_listening_validate_site_skill",
                    validate_arguments,
                    validate,
                )
            )

            acquire = await session.call_tool("web_listening_acquire", request)
            acquire_payload = _structured(acquire)
            record["mcp_tool_exchanges"].append(
                _exchange("web_listening_acquire", request, acquire)
            )
            assert acquire.isError is False
            result = Result.from_dict(acquire_payload["result"])
            assert result.status.value == "completed"
            assert len(result.attempts) == 1
            assert result.attempts[0].outcome == "succeeded"
            assert result.usage.requests <= 6
            assert result.usage.bytes_received <= 2 * 1024 * 1024
            assert result.usage.tool_attempts == 1
            assert len(result.artifacts) == 1
            assert not result.manifest.redirects
            job_id = acquire_payload["job_id"]
            artifact_evidence = result.artifacts[0]
            artifact_id = artifact_evidence.artifact_id

            get_arguments = {"job_id": job_id}
            get_job = await session.call_tool("web_listening_get_job", get_arguments)
            get_payload = _structured(get_job)
            record["mcp_tool_exchanges"].append(
                _exchange("web_listening_get_job", get_arguments, get_job)
            )
            assert get_job.isError is False
            assert get_payload == acquire_payload

            read_arguments = {"artifact_id": artifact_id}
            read_artifact = await session.call_tool(
                "web_listening_read_artifact", read_arguments
            )
            artifact_payload = _structured(read_artifact)
            record["mcp_tool_exchanges"].append(
                _exchange(
                    "web_listening_read_artifact",
                    read_arguments,
                    read_artifact,
                    artifact=True,
                )
            )
            assert read_artifact.isError is False
            content = base64.b64decode(artifact_payload["content"], validate=True)
            content_hash = hashlib.sha256(content).hexdigest()
            assert artifact_payload["artifact_id"] == artifact_id
            assert artifact_payload["content_encoding"] == "base64"
            assert len(content) == artifact_payload["size_bytes"] <= 2 * 1024 * 1024
            assert content_hash == artifact_evidence.sha256
            assert artifact_payload["blob_sha256"] == artifact_evidence.sha256

            error_arguments = {"job_id": "job-live-safe-missing"}
            error_call = await session.call_tool(
                "web_listening_get_job", error_arguments
            )
            error_payload = _structured(error_call)
            record["mcp_tool_exchanges"].append(
                _exchange("web_listening_get_job", error_arguments, error_call)
            )
            assert error_call.isError is True
            assert error_payload == {
                "error": {
                    "code": "job.not_found",
                    "message": "Resource was not found.",
                    "details": {},
                }
            }

            record["ids"] = {
                "acquisition_job_id": job_id,
                "get_job_id": get_payload["job_id"],
                "result_artifact_id": artifact_id,
                "read_artifact_id": artifact_payload["artifact_id"],
            }
            record["hashes_and_sizes"] = {
                "result_sha256": artifact_evidence.sha256,
                "artifact_sha256": content_hash,
                "result_size_bytes": artifact_evidence.size_bytes,
                "artifact_size_bytes": artifact_payload["size_bytes"],
            }
            record["error_envelope"] = error_payload
            record["runtime_correlation"] = {
                "acquire_job_equals_get_job": get_payload == acquire_payload,
                "result_schema_version": result.schema_version,
                "result_canonical_sha256": hashlib.sha256(
                    result.canonical_json_bytes()
                ).hexdigest(),
                "artifact_matches_result": content_hash == artifact_evidence.sha256,
                "result_visible_requests": result.usage.requests,
                "result_visible_bytes": result.usage.bytes_received,
                "successful_target_content_reads": 1,
                "fallbacks": 0,
                "retries": 0,
                "observed_historical_expectation": "pass_http -> completed",
            }
            record["exit_and_count_evidence"] = {
                "pytest_exit_code": 0,
                "mcp_stdio_sessions": 1,
                "tool_discovery_calls": 1,
                "application_tool_calls": 5,
                "target_sites": 1,
                "target_content_reads": 1,
                "tool_attempts": result.usage.tool_attempts,
                "outcome": "pytest_pass",
            }


def test_phase_11_snapshot_is_independent_and_reuses_the_phase_9_request() -> None:
    payload, target, request = _load_snapshot()

    assert payload["phase"] == "11"
    assert target["site_key"] == "ipcc"
    assert payload["canonical_request_sha256"] == _canonical_sha256(request)


def test_artifact_mcp_evidence_redacts_content_and_keeps_hash_metadata() -> None:
    content = b"website content must not enter live evidence"
    encoded = base64.b64encode(content).decode("ascii")

    evidence = _sanitize_artifact(
        {
            "artifact_id": "artifact-safe",
            "blob_sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "mime_type": "text/html",
            "content_encoding": "base64",
            "content": encoded,
            "unexpected": "excluded",
        }
    )
    serialized = json.dumps(evidence, sort_keys=True)

    assert evidence["content_redacted"] is True
    assert evidence["content_sha256"] == hashlib.sha256(content).hexdigest()
    assert "content" not in evidence
    assert encoded not in serialized
    assert "unexpected" not in serialized


def test_offline_default_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEB_LISTENING_RUN_LIVE", raising=False)

    with pytest.raises(pytest.skip.Exception):
        _load_authorized_snapshot()


@pytest.mark.parametrize("selector", [None, "", "https://www.ipcc.ch/", "other"])
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


def test_live_source_uses_complete_stdio_and_only_high_level_tools() -> None:
    source = inspect.getsource(_live_session)

    assert source.count("stdio_client(") == 1
    assert source.count("session.call_tool(") == 5
    assert "RuntimeService" not in source
    assert "runtime.run(" not in source
    assert "runtime.get_job(" not in source
    assert "runtime.read_artifact(" not in source
    assert "monkeypatch" not in source
    assert "mock" not in source.lower()
    assert "GovernedAccessGateway" not in source
    assert "PinnedHttpTransport" not in source


@pytest.mark.live
def test_phase_11_mcp_live(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Acquire IPCC once, then read its Job and Artifact through MCP stdio."""
    payload, target, request = _load_authorized_snapshot()
    record: dict[str, object] = {
        "schema_version": "phase-11-mcp-live-evidence.v1",
        "authorization_window": AUTHORIZED_WINDOW,
        "snapshot_sha256": hashlib.sha256(TARGETS.read_bytes()).hexdigest(),
        "input": {
            "site_key": target["site_key"],
            "request": request,
            "canonical_request_sha256": payload["canonical_request_sha256"],
        },
        "network_limits": payload["network_limits"],
        "transport_cap_scope": {
            "decision": "Phase 9 Decision B",
            "contract_visible_usage": "fail_closed",
            "total_transport_provenance": "unchanged Issue #32 audited governed path",
            "canonical_request_unchanged": True,
            "canonical_request_sha256": CANONICAL_REQUEST_SHA256,
            "total_transport_request_cap": 6,
            "lower_layer_instrumentation_added": False,
        },
        "actual_tool_names": [],
        "mcp_tool_exchanges": [],
        "ids": {},
        "hashes_and_sizes": {},
        "error_envelope": {},
        "runtime_correlation": {},
        "exit_and_count_evidence": {
            "pytest_exit_code": None,
            "mcp_stdio_sessions": 0,
            "application_tool_calls": 0,
            "target_content_reads": 0,
            "outcome": "failure",
        },
    }
    try:
        anyio.run(_live_session, tmp_path / "runtime-data", request, record)
    finally:
        _emit(record, capsys)
