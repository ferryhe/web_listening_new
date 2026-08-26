"""Authorized Phase 10 REST canary; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring
# pylint: disable=too-many-boolean-expressions,too-many-locals,too-many-statements
# pylint: disable=too-many-arguments,too-many-branches
# pylint: disable=wrong-import-position

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="install the optional web-listening[rest] extra")

from fastapi.testclient import TestClient  # pylint: disable=import-error

from web_listening.interfaces.rest import create_app
from web_listening.result.model import Result
from web_listening.runtime.service import RuntimeService

TARGETS = Path(__file__).with_name("phase_10_site_targets.json")
PHASE_9_TARGETS = Path(__file__).with_name("phase_09_site_targets.json")
SMOKE_CATALOG = Path(__file__).parent / "catalog" / "smoke_site_catalog.json"
SITE_SKILLS = Path(__file__).parent / "catalog" / "site_skill_cases.json"
AUTHORIZED_WINDOW = "issue-11-2026-08-26-user-authorized"
CANONICAL_REQUEST_SHA256 = (
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
        pytest.fail("Phase 10 live snapshot must contain exactly one target")
    target = targets[0]
    if not isinstance(target, dict) or target.get("site_key") != "ipcc":
        pytest.fail("Phase 10 live snapshot must select only ipcc")
    expected_limits = {
        "max_content_reads_per_target": 1,
        "max_total_requests": 6,
        "max_bytes_per_response": 2 * 1024 * 1024,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
    }
    if payload.get("network_limits") != expected_limits:
        pytest.fail("Phase 10 network limits drifted from the authorized caps")
    for key, path in (
        ("source_catalog_sha256", SMOKE_CATALOG),
        ("site_skill_catalog_sha256", SITE_SKILLS),
    ):
        if _newline_canonical_sha256(path.read_bytes()).upper() != payload.get(key):
            pytest.fail(f"Phase 10 {key} drifted")

    smoke_rows = json.loads(SMOKE_CATALOG.read_bytes()).get("sites")
    cases = json.loads(SITE_SKILLS.read_bytes()).get("cases")
    if not isinstance(smoke_rows, list) or not isinstance(cases, list):
        pytest.fail("Phase 10 source catalogs are invalid")
    smoke = next((row for row in smoke_rows if row.get("site_key") == "ipcc"), None)
    case = next((row for row in cases if row.get("site_key") == "ipcc"), None)
    if not isinstance(smoke, dict) or not isinstance(case, dict):
        pytest.fail("Phase 10 IPCC source rows are missing")
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
        pytest.fail("Phase 10 target is not the audited IPCC catalog projection")

    canonical_request = payload.get("canonical_request")
    if not isinstance(canonical_request, dict):
        pytest.fail("Phase 10 canonical Request is missing")
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
        pytest.fail("Phase 10 Request drifted from the audited catalog projection")
    if canonical_request != phase_9.get("canonical_request"):
        pytest.fail("Phase 10 must reuse the exact Phase 9 canonical Request")
    if payload.get("canonical_request_sha256") != CANONICAL_REQUEST_SHA256:
        pytest.fail("Phase 10 must preserve the Phase 9 Request digest")
    if phase_9.get("canonical_request_sha256") != CANONICAL_REQUEST_SHA256:
        pytest.fail("Phase 9 canonical Request provenance drifted")
    if _canonical_sha256(canonical_request) != CANONICAL_REQUEST_SHA256:
        pytest.fail("Phase 10 canonical Request digest drifted")
    return payload, target, canonical_request


def _load_authorized_snapshot() -> (
    tuple[dict[str, object], dict[str, object], dict[str, object]]
):
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 10 REST live test is offline by default")
    if os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW") != AUTHORIZED_WINDOW:
        pytest.fail("the exact Phase 10 authorized live window is required")
    if os.environ.get("WEB_LISTENING_LIVE_SITE") != "ipcc":
        pytest.fail("WEB_LISTENING_LIVE_SITE must select the frozen ipcc key")
    return _load_snapshot()


def _sanitize_artifact_response(value: object) -> dict[str, object]:
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
        try:
            decoded = base64.b64decode(content, validate=True)
        except ValueError:
            pass
        else:
            projection["content_sha256"] = hashlib.sha256(decoded).hexdigest()
    return projection


def _exchange(
    method: str,
    path: str,
    status_code: int,
    response_json: object,
    *,
    request_json: object = None,
    artifact: bool = False,
) -> dict[str, object]:
    return {
        "request": {"method": method, "path": path, "json": request_json},
        "response": {
            "status_code": status_code,
            "json": (
                _sanitize_artifact_response(response_json)
                if artifact
                else response_json
            ),
        },
    }


def _emit(record: dict[str, object], capsys: pytest.CaptureFixture[str]) -> None:
    with capsys.disabled():
        print(json.dumps(record, ensure_ascii=True, sort_keys=True), flush=True)


def test_phase_10_snapshot_is_independent_and_reuses_the_phase_9_request() -> None:
    payload, target, request = _load_snapshot()

    assert payload["phase"] == "10"
    assert target["site_key"] == "ipcc"
    assert payload["canonical_request_sha256"] == _canonical_sha256(request)


def test_artifact_http_evidence_redacts_content_and_keeps_hash_metadata() -> None:
    content = b"website content must not enter live evidence"
    encoded = base64.b64encode(content).decode("ascii")

    evidence = _sanitize_artifact_response(
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


def test_live_source_uses_local_asgi_and_only_the_real_runtime_service() -> None:
    source = inspect.getsource(test_phase_10_rest_live)

    assert source.count("RuntimeService.open(") == 1
    assert source.count("client.post(") == 1
    assert source.count("client.get(") == 2
    assert "runtime.run(" not in source
    assert "runtime.get_job(" not in source
    assert "runtime.read_artifact(" not in source
    assert "monkeypatch" not in source
    assert "mock" not in source.lower()
    assert "GovernedAccessGateway" not in source
    assert "PinnedHttpTransport" not in source
    assert 'payload["network_limits"]["retry"] == 0' in source


@pytest.mark.live
def test_phase_10_rest_live(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Acquire IPCC once, then read its Job and Artifact through local ASGI."""
    payload, target, request = _load_authorized_snapshot()
    runtime: RuntimeService | None = None
    record: dict[str, object] = {
        "schema_version": "phase-10-rest-live-evidence.v1",
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
            "total_transport_provenance": ("unchanged Issue #32 audited governed path"),
            "canonical_request_unchanged": True,
            "canonical_request_sha256": CANONICAL_REQUEST_SHA256,
            "total_transport_request_cap": 6,
            "lower_layer_instrumentation_added": False,
        },
        "http_exchanges": [],
        "statuses": [],
        "ids": {},
        "hashes_and_sizes": {},
        "runtime_correlation": {},
        "exit_and_count_evidence": {"local_asgi_calls": 0, "outcome": "failure"},
    }
    try:
        runtime = RuntimeService.open(tmp_path / "runtime-data")
        client = TestClient(create_app(lambda: runtime))

        acquire = client.post("/v1/acquisitions", json=request)
        acquire_json = acquire.json()
        record["http_exchanges"].append(
            _exchange(
                "POST",
                "/v1/acquisitions",
                acquire.status_code,
                acquire_json,
                request_json=request,
            )
        )
        assert acquire.status_code == 201
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
        artifact_evidence = result.artifacts[0]
        artifact_id = artifact_evidence.artifact_id

        get_job = client.get(f"/v1/jobs/{job_id}")
        get_job_json = get_job.json()
        record["http_exchanges"].append(
            _exchange("GET", f"/v1/jobs/{job_id}", get_job.status_code, get_job_json)
        )
        assert get_job.status_code == 200
        assert get_job_json == acquire_json

        read_artifact = client.get(f"/v1/artifacts/{artifact_id}")
        artifact_json = read_artifact.json()
        record["http_exchanges"].append(
            _exchange(
                "GET",
                f"/v1/artifacts/{artifact_id}",
                read_artifact.status_code,
                artifact_json,
                artifact=True,
            )
        )
        assert read_artifact.status_code == 200
        content = base64.b64decode(artifact_json["content"], validate=True)
        content_hash = hashlib.sha256(content).hexdigest()
        assert artifact_json["artifact_id"] == artifact_id
        assert artifact_json["content_encoding"] == "base64"
        assert len(content) == artifact_json["size_bytes"] <= 2 * 1024 * 1024
        assert content_hash == artifact_evidence.sha256
        assert artifact_json["blob_sha256"] == artifact_evidence.sha256

        record["statuses"] = [
            acquire.status_code,
            get_job.status_code,
            read_artifact.status_code,
        ]
        record["ids"] = {
            "acquisition_job_id": job_id,
            "get_job_id": get_job_json["job_id"],
            "result_artifact_id": artifact_id,
            "read_artifact_id": artifact_json["artifact_id"],
        }
        record["hashes_and_sizes"] = {
            "result_sha256": artifact_evidence.sha256,
            "artifact_sha256": content_hash,
            "result_size_bytes": artifact_evidence.size_bytes,
            "artifact_size_bytes": artifact_json["size_bytes"],
        }
        record["runtime_correlation"] = {
            "post_job_equals_get_job": get_job_json == acquire_json,
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
            "local_asgi_calls": 3,
            "application_endpoints_invoked": 3,
            "target_sites": 1,
            "target_content_reads": 1,
            "tool_attempts": result.usage.tool_attempts,
            "outcome": "pytest_pass",
        }
    finally:
        if runtime is not None:
            runtime.close()
        _emit(record, capsys)
