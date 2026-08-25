"""Explicitly authorized Phase 8 Runtime canary; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring,too-many-locals

from __future__ import annotations

import hashlib
import inspect
import json
import os
from dataclasses import asdict
from pathlib import Path

import pytest

import web_listening.runtime.workflow as workflow_module
import web_listening.tool_registry.acquisition.builtins.web_http as web_http_module
from web_listening.artifact.model import StoredObservation
from web_listening.artifact.observation import ObservationProposal
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.runtime.jobs import JobRepository
from web_listening.runtime.service import RuntimeService
from web_listening.site_skill.validate import site_skill_from_mapping
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners.in_process import (
    GatewayEvidence,
    GatewayFailure,
    GatewayResult,
    GovernedAccessGateway,
    PinnedHttpTransport,
    TransportResponse,
)

TARGETS = Path(__file__).with_name("phase_08_site_targets.json")
SOURCE_CATALOG = Path(__file__).parent / "catalog" / "dev_test_sites.json"
SITE_SKILLS = Path(__file__).parent / "catalog" / "site_skill_cases.json"
AUTHORIZED_WINDOW = "issue-9-20260825-authorized"


class _RecordingGateway(GovernedAccessGateway):
    """Retain public Gateway evidence from exactly one Runtime acquisition."""

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
    """Apply the live-only six-request ceiling around the real transport."""

    def __init__(self) -> None:
        self._transport = PinnedHttpTransport()
        self.requests = 0

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> TransportResponse:
        if self.requests >= 6:
            raise TimeoutError
        self.requests += 1
        return self._transport.send(url, timeout=timeout, addresses=addresses)

    def close(self) -> None:
        self._transport.close()


class _CountingStore(ArtifactStore):
    """Count only public Store calls made by Runtime and live verification."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.reads = 0
        self.writes = 0

    def commit_observation(self, proposal: ObservationProposal) -> StoredObservation:
        self.writes += 1
        return super().commit_observation(proposal)

    def get_observation(self, observation_id: str) -> StoredObservation:
        self.reads += 1
        return super().get_observation(observation_id)


def _load_authorized_target() -> tuple[dict[str, object], dict[str, object], str]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 8 Runtime live test is offline by default")
    if os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW") != AUTHORIZED_WINDOW:
        pytest.fail("the exact Phase 8 authorized live window is required")

    payload = json.loads(TARGETS.read_bytes())
    targets = payload.get("targets")
    if not isinstance(targets, list) or len(targets) != 1:
        pytest.fail("Phase 8 live catalog must contain exactly one target")
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE", "soa").strip() or "soa"
    by_key = {
        target.get("site_key"): target for target in targets if isinstance(target, dict)
    }
    if selector not in by_key:
        pytest.fail("WEB_LISTENING_LIVE_SITE must be an authorized catalog key")
    target = by_key[selector]
    expected_target = {
        "site_key": "soa",
        "url": "https://www.soa.org/",
        "allowed_origins": ["https://www.soa.org"],
        "historical_expectation": "dev_fixture",
        "monitor_min_words": 150,
        "site_skill_case": "soa",
        "site_skill_digest": (
            "sha256:889175f428f227000aeacfae1ebfda14704a9d469088c02b4a8745bfb732caf2"
        ),
        "provenance": {
            "old_commit": "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5",
            "old_path": "config/dev_test_sites.json",
            "old_blob": "922ddc452e6f8cb1e8e1eee78832ba178f915fe1",
            "old_site_key": "soa",
        },
        "tool_facts": {
            "tool_id": "acquisition.web_http",
            "version": "1.0.0",
            "category": "acquisition",
            "capabilities": ["http_get"],
        },
    }
    if target != expected_target:
        pytest.fail("Phase 8 target drifted from the audited SOA catalog row")
    expected_limits = {
        "max_content_reads_per_target": 1,
        "max_total_requests": 6,
        "max_bytes_per_response": 2 * 1024 * 1024,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
    }
    if payload.get("network_limits") != expected_limits:
        pytest.fail("Phase 8 network limits drifted from the authorized caps")
    if hashlib.sha256(SOURCE_CATALOG.read_bytes()).hexdigest().upper() != payload.get(
        "source_catalog_sha256"
    ):
        pytest.fail("Phase 8 source catalog digest drifted")

    cases = json.loads(SITE_SKILLS.read_bytes()).get("cases")
    if not isinstance(cases, list):
        pytest.fail("Site Skill cases are invalid")
    case = next(
        (item for item in cases if item.get("site_key") == target["site_skill_case"]),
        None,
    )
    if not isinstance(case, dict):
        pytest.fail("SOA Site Skill case is missing")
    return target, case, hashlib.sha256(TARGETS.read_bytes()).hexdigest()


@pytest.mark.parametrize("authorized_window", [None, "wrong-window"])
def test_explicit_live_rejects_missing_or_wrong_authorized_window(
    monkeypatch: pytest.MonkeyPatch, authorized_window: str | None
) -> None:
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    if authorized_window is None:
        monkeypatch.delenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", raising=False)
    else:
        monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", authorized_window)

    with pytest.raises(pytest.fail.Exception, match="exact Phase 8"):
        _load_authorized_target()


def test_offline_default_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEB_LISTENING_RUN_LIVE", raising=False)

    with pytest.raises(pytest.skip.Exception):
        _load_authorized_target()


def test_live_selector_cannot_inject_a_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", AUTHORIZED_WINDOW)
    monkeypatch.setenv("WEB_LISTENING_LIVE_SITE", "https://example.invalid/")

    with pytest.raises(pytest.fail.Exception, match="authorized catalog key"):
        _load_authorized_target()


def test_phase_08_snapshot_is_exact_soa_catalog_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", AUTHORIZED_WINDOW)
    monkeypatch.setenv("WEB_LISTENING_LIVE_SITE", "soa")

    target, case, snapshot_sha256 = _load_authorized_target()

    assert target["url"] == "https://www.soa.org/"
    assert target["site_skill_digest"] == case["site_skill"]["digest"]
    assert len(snapshot_sha256) == 64


def test_live_source_has_one_runtime_call_and_no_second_content_read() -> None:
    source = inspect.getsource(test_phase_08_runtime_live)
    workflow_source = inspect.getsource(workflow_module.run_single_target)

    assert source.count("service.run(") == 1
    assert "registry.invoke(" not in source
    assert "gateway.read(" not in source
    assert workflow_source.count("registry.invoke(") == 1


def _emit(record: dict[str, object], capsys: pytest.CaptureFixture[str]) -> None:
    with capsys.disabled():
        print(json.dumps(record, sort_keys=True), flush=True)


@pytest.mark.live
def test_phase_08_runtime_live(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Run one frozen SOA target through Runtime and its five public modules."""
    target, case, snapshot_sha256 = _load_authorized_target()
    url = str(target["url"])
    skill = site_skill_from_mapping(case["site_skill"])
    request = Request(
        Scope(
            seeds=(url,),
            allowed_origins=tuple(str(item) for item in target["allowed_origins"]),
            include_paths=("/**",),
            content_types=(ContentType.HTML,),
        ),
        skill,
        False,
        Budgets(12, 2 * 1024 * 1024, 30, 1),
    )
    _RecordingGateway.evidence = None
    _RecordingGateway.reads = 0
    monkeypatch.setattr(web_http_module, "GovernedAccessGateway", _RecordingGateway)
    transport = _CappedTransport()
    tool = WebHttpAcquisitionTool(lambda: transport)
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, tool)
    store = _CountingStore(tmp_path / "artifacts")
    jobs = JobRepository()
    service = RuntimeService(registry, store, jobs)
    record: dict[str, object] = {
        "schema_version": "phase-08-live-evidence.v1",
        "authorization_window_id": hashlib.sha256(
            AUTHORIZED_WINDOW.encode("utf-8")
        ).hexdigest(),
        "input": {
            "site_key": target["site_key"],
            "target_url": url,
            "site_skill_digest": skill.digest,
            "explore_all_tools": request.explore_all_tools,
        },
        "snapshot_sha256": snapshot_sha256,
        "limits": {
            "content_reads": 1,
            "max_total_requests": 6,
            "max_bytes_per_response": 2 * 1024 * 1024,
            "timeout_seconds": 30,
            "concurrency": 1,
            "retry": 0,
            "request_budgets": asdict(request.budgets),
        },
        "store": {"reads": 0, "writes": 0},
        "result": {},
        "exit_behavior": "failure",
    }
    try:
        job = service.run(request)
        assert job.result is not None
        result = job.result
        gateway = _RecordingGateway.evidence
        assert gateway is not None
        artifact = result.artifacts[0]
        replayed = store.get_observation(artifact.observation_id)
        words = len(replayed.content.decode("utf-8", errors="replace").split())
        record["job"] = {
            "job_id": job.job_id,
            "status_history": [event.status.value for event in jobs.events(job.job_id)],
            "events": [asdict(event) for event in jobs.events(job.job_id)],
            "final_status": job.status.value,
        }
        record["result"] = {
            "status": result.status.value,
            "result_sha256": hashlib.sha256(result.canonical_json_bytes()).hexdigest(),
            "manifest_sha256": hashlib.sha256(
                result.manifest.canonical_json_bytes()
            ).hexdigest(),
            "attempts": [attempt.to_dict() for attempt in result.attempts],
            "usage": result.usage.to_dict(),
            "blob_sha256": replayed.blob.sha256,
            "artifact_id": replayed.artifact.artifact_id,
            "observation_id": replayed.observation.observation_id,
            "requested_url": result.manifest.requested_url,
            "current_url": gateway.current_url,
            "final_url": result.manifest.final_url,
            "http_status": result.manifest.http_status,
            "mime_type": result.manifest.mime_type,
            "content_bytes": result.manifest.size_bytes,
            "content_sha256": result.manifest.sha256,
            "gateway": {
                "decisions": [asdict(item) for item in gateway.decisions],
                "robots": [asdict(item) for item in gateway.robots],
                "redirects": [asdict(item) for item in gateway.redirects],
                "usage": asdict(gateway.usage),
            },
            "threshold": {
                "name": "monitor_min_words",
                "expected": target["monitor_min_words"],
                "observed": words,
                "met": words >= int(target["monitor_min_words"]),
                "enforcement": "observational_only",
            },
        }
        record["store"] = {"reads": store.reads, "writes": store.writes}
        assert [event.status.value for event in jobs.events(job.job_id)] == [
            "submitted",
            "running",
            "completed",
        ]
        assert len(result.attempts) == 1
        assert result.usage.tool_attempts == 1
        assert _RecordingGateway.reads == 1
        assert gateway.usage.requests == transport.requests <= 6
        assert len(replayed.content) <= 2 * 1024 * 1024
        assert store.reads == store.writes == 1
        record["exit_behavior"] = "pytest_pass"
    finally:
        store.close()
        tool.close()
        _emit(record, capsys)
