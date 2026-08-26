"""Authorized Phase 8B Runtime reopen canary; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring,protected-access
# pylint: disable=too-many-boolean-expressions,too-many-locals,too-many-statements

from __future__ import annotations

import hashlib
import inspect
import json
import os
from dataclasses import asdict
from pathlib import Path

import pytest

import web_listening.runtime.service as service_module
import web_listening.tool_registry.acquisition.builtins.web_http as web_http_module
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.runtime.service import RuntimeService
from web_listening.site_skill.validate import site_skill_from_mapping
from web_listening.tool_registry.runners.in_process import (
    GatewayEvidence,
    GatewayFailure,
    GatewayResult,
    GovernedAccessGateway,
    PinnedHttpTransport,
    TransportResponse,
)

TARGETS = Path(__file__).with_name("phase_08b_site_targets.json")
SMOKE_CATALOG = Path(__file__).parent / "catalog" / "smoke_site_catalog.json"
SITE_SKILLS = Path(__file__).parent / "catalog" / "site_skill_cases.json"
AUTHORIZED_WINDOW = "issue-32-2026-08-26-user-authorized"


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
        pytest.fail("Phase 8B live catalog must contain exactly one target")
    target = targets[0]
    if not isinstance(target, dict) or target.get("site_key") != "ipcc":
        pytest.fail("Phase 8B live catalog must select only ipcc")
    expected_target = {
        "site_key": "ipcc",
        "url": "https://www.ipcc.ch/",
        "allowed_origins": ["https://www.ipcc.ch"],
        "historical_expectation": "pass_http",
        "monitor_min_words": 300,
        "site_skill_case": "ipcc",
        "site_skill_digest": (
            "sha256:65886846062d93ebe8e4d9edef63c1c65fc37774749d731db086ed3a408b97be"
        ),
        "provenance": {
            "old_commit": "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5",
            "old_path": "config/smoke_site_catalog.json",
            "old_blob": "e50b2c0d29e1b3c5df6473409c1a33ad4ffee4c4",
            "old_site_key": "ipcc",
        },
        "tool_facts": {
            "tool_id": "acquisition.web_http",
            "version": "1.0.0",
            "category": "acquisition",
            "capabilities": ["http_get"],
            "recipe_id": "catalog-http",
        },
    }
    if target != expected_target:
        pytest.fail("Phase 8B target drifted from the audited IPCC catalog row")
    expected_limits = {
        "max_content_reads_per_target": 1,
        "max_total_requests": 6,
        "max_bytes_per_response": 2 * 1024 * 1024,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
    }
    if payload.get("network_limits") != expected_limits:
        pytest.fail("Phase 8B network limits drifted from the authorized caps")
    for key, path in (
        ("source_catalog_sha256", SMOKE_CATALOG),
        ("site_skill_catalog_sha256", SITE_SKILLS),
    ):
        if _newline_canonical_sha256(path.read_bytes()).upper() != payload.get(key):
            pytest.fail(f"Phase 8B {key} drifted")

    smoke_rows = json.loads(SMOKE_CATALOG.read_bytes()).get("sites")
    cases = json.loads(SITE_SKILLS.read_bytes()).get("cases")
    if not isinstance(smoke_rows, list) or not isinstance(cases, list):
        pytest.fail("Phase 8B source catalogs are invalid")
    smoke = next((row for row in smoke_rows if row.get("site_key") == "ipcc"), None)
    case = next((row for row in cases if row.get("site_key") == "ipcc"), None)
    if not isinstance(smoke, dict) or not isinstance(case, dict):
        pytest.fail("Phase 8B IPCC source rows are missing")
    if (
        smoke["urls"]["monitor"] != target["url"]
        or smoke["allowed_origins"] != target["allowed_origins"]
        or smoke["historical_classification"]["expectation"]
        != target["historical_expectation"]
        or smoke["evidence_thresholds"]["monitor_min_words"]
        != target["monitor_min_words"]
        or smoke["provenance"] != target["provenance"]
        or smoke["tool_facts"] != target["tool_facts"]
    ):
        pytest.fail("Phase 8B target is not an exact IPCC catalog projection")

    canonical_request = payload.get("canonical_request")
    if not isinstance(canonical_request, dict):
        pytest.fail("Phase 8B canonical Request is missing")
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
        pytest.fail("Phase 8B canonical Request drifted from audited inputs")
    if _canonical_sha256(canonical_request) != payload.get("canonical_request_sha256"):
        pytest.fail("Phase 8B canonical Request digest drifted")
    return payload, target, canonical_request


def _load_authorized_snapshot() -> (
    tuple[dict[str, object], dict[str, object], dict[str, object]]
):
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 8B Runtime persistence live test is offline by default")
    if os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW") != AUTHORIZED_WINDOW:
        pytest.fail("the exact Phase 8B authorized live window is required")
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE", "ipcc").strip() or "ipcc"
    if selector != "ipcc":
        pytest.fail("WEB_LISTENING_LIVE_SITE must select the frozen ipcc key")
    return _load_snapshot()


def _request_from_mapping(mapping: dict[str, object]) -> Request:
    scope = mapping["scope"]
    budgets = mapping["budgets"]
    assert isinstance(scope, dict) and isinstance(budgets, dict)
    return Request(
        Scope(
            seeds=tuple(scope["seeds"]),
            allowed_origins=tuple(scope["allowed_origins"]),
            include_paths=tuple(scope["include_paths"]),
            content_types=tuple(ContentType(value) for value in scope["content_types"]),
        ),
        site_skill_from_mapping(mapping["site_skill"]),
        mapping["explore_all_tools"],
        Budgets(
            budgets["max_requests"],
            budgets["max_bytes"],
            budgets["max_runtime_seconds"],
            budgets["max_tool_attempts_per_target"],
        ),
    )


class _RecordingGateway(GovernedAccessGateway):
    evidence: GatewayEvidence | None = None
    reads = 0

    def read(self, url: str) -> GatewayResult:
        type(self).reads += 1
        try:
            result = super().read(url)
        except GatewayFailure as exc:
            type(self).evidence = exc.evidence
            raise
        type(self).evidence = result.evidence
        return result


class _CappedTransport:
    total_requests = 0
    instances = 0

    def __init__(self) -> None:
        type(self).instances += 1
        self._transport = PinnedHttpTransport()

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> TransportResponse:
        if type(self).total_requests >= 6:
            raise TimeoutError
        type(self).total_requests += 1
        return self._transport.send(url, timeout=timeout, addresses=addresses)

    def close(self) -> None:
        self._transport.close()


def test_source_catalog_digests_and_canonical_request_are_stable() -> None:
    payload, target, canonical_request = _load_snapshot()

    assert target["url"] == "https://www.ipcc.ch/"
    assert payload["canonical_request_sha256"] == _canonical_sha256(canonical_request)


@pytest.mark.parametrize("authorized_window", [None, "wrong-window"])
def test_explicit_live_rejects_missing_or_wrong_authorized_window(
    monkeypatch: pytest.MonkeyPatch, authorized_window: str | None
) -> None:
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    if authorized_window is None:
        monkeypatch.delenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", raising=False)
    else:
        monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", authorized_window)

    with pytest.raises(pytest.fail.Exception, match="exact Phase 8B"):
        _load_authorized_snapshot()


def test_offline_default_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEB_LISTENING_RUN_LIVE", raising=False)

    with pytest.raises(pytest.skip.Exception):
        _load_authorized_snapshot()


def test_live_selector_cannot_inject_a_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", AUTHORIZED_WINDOW)
    monkeypatch.setenv("WEB_LISTENING_LIVE_SITE", "https://example.invalid/")

    with pytest.raises(pytest.fail.Exception, match="frozen ipcc key"):
        _load_authorized_snapshot()


def test_live_source_uses_one_run_then_public_reopen_reads() -> None:
    source = inspect.getsource(test_phase_08b_runtime_persistence_live)

    assert source.count("RuntimeService.open(") == 2
    assert source.count("first.run(") == 1
    assert source.count("second.get_job(") == 1
    assert source.count("second.read_artifact(") == 1
    assert "second._jobs" not in source
    assert "Registry(" not in source
    assert "ArtifactStore(" not in source
    assert "gateway.read(" not in source


def _emit(record: dict[str, object], capsys: pytest.CaptureFixture[str]) -> None:
    with capsys.disabled():
        print(json.dumps(record, sort_keys=True), flush=True)


@pytest.mark.live
def test_phase_08b_runtime_persistence_live(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Run IPCC once, then reopen by IDs without another network request."""
    payload, target, request_mapping = _load_authorized_snapshot()
    request = _request_from_mapping(request_mapping)
    request_digest = str(payload["canonical_request_sha256"])
    snapshot_digest = hashlib.sha256(TARGETS.read_bytes()).hexdigest()
    data_dir = tmp_path / "runtime-data"
    _RecordingGateway.evidence = None
    _RecordingGateway.reads = 0
    _CappedTransport.total_requests = 0
    _CappedTransport.instances = 0
    monkeypatch.setattr(web_http_module, "GovernedAccessGateway", _RecordingGateway)
    monkeypatch.setattr(service_module, "PinnedHttpTransport", _CappedTransport)
    first: RuntimeService | None = None
    second: RuntimeService | None = None
    record: dict[str, object] = {
        "schema_version": "phase-08b-live-evidence.v1",
        "authorization_window": AUTHORIZED_WINDOW,
        "snapshot_sha256": snapshot_digest,
        "input": {
            "site_key": target["site_key"],
            "target_url": target["url"],
            "allowed_origins": target["allowed_origins"],
            "explore_all_tools": request.explore_all_tools,
            "site_skill_digest": request.site_skill.digest,
            "canonical_request_sha256": request_digest,
            "budgets": asdict(request.budgets),
        },
        "first_runtime": {},
        "second_runtime": {},
        "result": {},
        "artifact": {},
        "network": {},
        "exit_behavior": "failure",
    }
    try:
        first = RuntimeService.open(data_dir)
        job = first.run(request)
        assert job.result is not None
        result = job.result
        assert result.status.value == "completed"
        artifact_evidence = result.artifacts[0]
        first_events = first._jobs.events(job.job_id)
        gateway = _RecordingGateway.evidence
        assert gateway is not None
        record["first_runtime"] = {
            "job_id": job.job_id,
            "status": job.status.value,
            "events": [asdict(event) for event in first_events],
        }
        first.close()
        first = None
        requests_before_reopen = _CappedTransport.total_requests
        reads_before_reopen = _RecordingGateway.reads

        second = RuntimeService.open(data_dir)
        restored_job = second.get_job(job.job_id)
        restored_artifact = second.read_artifact(artifact_evidence.artifact_id)
        second.close()
        second = None

        restored_hash = hashlib.sha256(restored_artifact.content).hexdigest()
        record["second_runtime"] = {
            "job_id": restored_job.job_id,
            "status": restored_job.status.value,
            "events": {
                "validated_by": "RuntimeService.get_job",
                "match_first_runtime": restored_job == job,
            },
        }
        record["result"] = {
            "status": result.status.value,
            "attempts": [attempt.to_dict() for attempt in result.attempts],
            "usage": result.usage.to_dict(),
            "errors": [error.to_dict() for error in result.errors],
            "redirects": [redirect.to_dict() for redirect in result.manifest.redirects],
            "requested_url": result.manifest.requested_url,
            "final_url": result.manifest.final_url,
            "http_status": result.manifest.http_status,
            "mime_type": result.manifest.mime_type,
        }
        record["artifact"] = {
            "artifact_id": restored_artifact.artifact_id,
            "blob_sha256": restored_artifact.blob_sha256,
            "size_bytes": restored_artifact.size_bytes,
            "media_type": restored_artifact.mime_type,
            "result_sha256": artifact_evidence.sha256,
            "read_sha256": restored_hash,
            "content_hash_equal": restored_hash == artifact_evidence.sha256,
        }
        record["network"] = {
            "requests": _CappedTransport.total_requests,
            "content_reads": _RecordingGateway.reads,
            "transport_instances": _CappedTransport.instances,
            "second_phase_requests": (
                _CappedTransport.total_requests - requests_before_reopen
            ),
            "second_phase_content_reads": (
                _RecordingGateway.reads - reads_before_reopen
            ),
            "redirects": [asdict(item) for item in gateway.redirects],
            "status": gateway.response_status,
            "mime_type": gateway.response_mime_type,
        }
        assert restored_job == job
        assert restored_artifact.artifact_id == artifact_evidence.artifact_id
        assert restored_artifact.blob_sha256 == artifact_evidence.sha256
        assert restored_artifact.size_bytes == artifact_evidence.size_bytes
        assert restored_artifact.mime_type == artifact_evidence.mime_type
        assert restored_hash == artifact_evidence.sha256
        assert requests_before_reopen == _CappedTransport.total_requests <= 6
        assert reads_before_reopen == _RecordingGateway.reads == 1
        assert _CappedTransport.instances == 1
        assert len(restored_artifact.content) <= 2 * 1024 * 1024
        files = {
            path.relative_to(data_dir).as_posix()
            for path in data_dir.rglob("*")
            if path.is_file()
        }
        assert "jobs.sqlite3" in files
        assert "artifacts/artifact.sqlite3" in files
        assert len(files) == 3
        assert len(files - {"jobs.sqlite3", "artifacts/artifact.sqlite3"}) == 1
        record["exit_behavior"] = "pytest_pass"
    finally:
        if second is not None:
            second.close()
        if first is not None:
            first.close()
        _emit(record, capsys)
