"""Authorized Phase 19 agent-exploration evidence; offline by default."""

# pylint: disable=duplicate-code,missing-class-docstring,missing-function-docstring
# pylint: disable=protected-access,too-few-public-methods,too-many-locals

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import pytest

from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, Request
from web_listening.runtime.workflow import (
    BoundedActionProposal,
    ExplorationMetadata,
    run_agent_assisted_target,
)
from web_listening.site_skill.update import SiteSkillCandidate
from web_listening.site_skill.validate import (
    site_skill_from_mapping,
    site_skill_to_mapping,
)
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners import in_process as in_process_runner
from web_listening.tool_registry.runners.in_process import (
    PinnedHttpTransport,
    TransportResponse,
)

pytestmark = pytest.mark.live

SNAPSHOT = Path(__file__).with_name("phase_19_site_targets.json")
SMOKE_CATALOG = Path(__file__).parent / "catalog" / "smoke_site_catalog.json"
SKILL_CATALOG = Path(__file__).parent / "catalog" / "site_skill_cases.json"
SMOKE_SHA256 = "CE378F743C6363F1DC22A25758B958E3ADA695F8996B3F619AFA4CF0CD5D5322"
SKILL_SHA256 = "AE1CE1126EB475A21839FFEF178B68DC0806C19300C5347181197CD922E90BEC"
NOW = "2026-08-27T12:00:00Z"


def _load_snapshot() -> dict[str, object]:
    payload = json.loads(SNAPSHOT.read_bytes())
    smoke = json.loads(SMOKE_CATALOG.read_bytes())
    skills = json.loads(SKILL_CATALOG.read_bytes())
    if hashlib.sha256(SMOKE_CATALOG.read_bytes()).hexdigest().upper() != SMOKE_SHA256:
        pytest.fail("Phase 19 smoke catalog bytes drifted")
    if hashlib.sha256(SKILL_CATALOG.read_bytes()).hexdigest().upper() != SKILL_SHA256:
        pytest.fail("Phase 19 Site Skill catalog bytes drifted")
    if payload.get("source_catalogs") != [
        {
            "path": "tests/live/catalog/smoke_site_catalog.json",
            "sha256": SMOKE_SHA256,
            "sha256_basis": "raw_bytes",
        },
        {
            "path": "tests/live/catalog/site_skill_cases.json",
            "sha256": SKILL_SHA256,
            "sha256_basis": "raw_bytes",
        },
    ]:
        pytest.fail("Phase 19 source catalog evidence drifted")
    smoke_by_key = {item["site_key"]: item for item in smoke["sites"]}
    skill_by_key = {item["site_key"]: item for item in skills["cases"]}
    target = payload["target"]
    iea = smoke_by_key["iea"]
    if target != {
        "site_key": "iea",
        "monitor_url": iea["urls"]["monitor"],
        "tree_seed_url": iea["urls"]["tree_seed"],
        "allowed_origins": iea["allowed_origins"],
        "site_skill_digest": iea["site_skill_digest"],
        "site_skill": skill_by_key["iea"]["site_skill"],
        "provenance": iea["provenance"],
    }:
        pytest.fail("Phase 19 IEA snapshot drifted from audited catalog rows")
    ipcc = smoke_by_key["ipcc"]
    if payload["rejected_proposal"] != {
        "site_key": "ipcc",
        "target_url": ipcc["urls"]["monitor"],
        "provenance": ipcc["provenance"],
    }:
        pytest.fail("Phase 19 IPCC rejection fixture drifted")
    if payload.get("network_limits") != {
        "max_targets": 2,
        "max_total_requests": 12,
        "max_total_response_bytes": 4 * 1024 * 1024,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
    }:
        pytest.fail("Phase 19 network limits drifted")
    return payload


def _authorized_snapshot() -> dict[str, object]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 19 agent exploration live test is offline by default")
    if not os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip():
        pytest.fail("a non-empty Phase 19 authorized live window is required")
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE")
    if selector is not None and selector.strip() != "iea":
        pytest.fail("WEB_LISTENING_LIVE_SITE must be iea")
    return _load_snapshot()


class _NetworkBudget:
    def __init__(self, requests: int, response_bytes: int, timeout: int) -> None:
        self.max_requests = requests
        self.max_response_bytes = response_bytes
        self.requests = 0
        self.response_bytes = 0
        self.deadline = time.monotonic() + timeout
        self.sends: list[str] = []

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline - time.monotonic())


class _CappedResponse:
    def __init__(self, response: TransportResponse, budget: _NetworkBudget) -> None:
        self.status = response.status
        self.headers = response.headers
        self.peer_ip = response.peer_ip
        self._response = response
        self._budget = budget

    def read(self, max_bytes: int) -> bytes:
        remaining = self._budget.max_response_bytes - self._budget.response_bytes
        if self._budget.remaining_seconds <= 0 or remaining <= 0:
            raise TimeoutError
        try:
            content = self._response.read(min(max_bytes, remaining))
        except in_process_runner._PartialBodyRead as exc:
            self._budget.response_bytes += len(exc.partial)
            raise
        self._budget.response_bytes += len(content)
        return content

    def set_timeout(self, timeout: float) -> None:
        remaining = self._budget.remaining_seconds
        if remaining <= 0:
            raise TimeoutError
        setter = getattr(self._response, "set_timeout", None)
        if callable(setter):
            setter(min(timeout, remaining))

    def close(self) -> None:
        self._response.close()


class _CappedTransport:
    def __init__(self, budget: _NetworkBudget) -> None:
        self._budget = budget
        self._transport = PinnedHttpTransport()

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> _CappedResponse:
        if (
            self._budget.remaining_seconds <= 0
            or self._budget.requests >= self._budget.max_requests
        ):
            raise TimeoutError
        self._budget.requests += 1
        self._budget.sends.append(url)
        response = self._transport.send(
            url,
            timeout=min(timeout, self._budget.remaining_seconds),
            addresses=addresses,
        )
        return _CappedResponse(response, self._budget)

    def close(self) -> None:
        self._transport.close()


@dataclass(slots=True)
class _ControlledInitialFailure:
    delegate: WebHttpAcquisitionTool
    initial_url: str
    manifest = WEB_HTTP_MANIFEST
    calls: list[str] = field(default_factory=list)

    def acquire(
        self, tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        self.calls.append(tool_input.target_url)
        output = self.delegate.acquire(tool_input)
        if tool_input.target_url == self.initial_url and isinstance(
            output, AcquisitionOutput
        ):
            return AcquisitionFailure(
                output.tool_id,
                output.tool_version,
                "web_http.failure",
                requests=output.requests,
                bytes_received=output.bytes_received,
                runtime_ms=output.runtime_ms,
            )
        return output

    def close(self) -> None:
        self.delegate.close()


@dataclass(slots=True)
class _OfflineInitialFailure:
    manifest = WEB_HTTP_MANIFEST
    calls: list[str] = field(default_factory=list)

    def acquire(self, tool_input: AcquisitionInput) -> AcquisitionFailure:
        self.calls.append(tool_input.target_url)
        return AcquisitionFailure(
            self.manifest.tool_id,
            self.manifest.version,
            "web_http.failure",
        )


@dataclass(slots=True)
class _StoreSpy:
    store: ArtifactStore
    commits: int = 0

    def commit_observation(self, proposal):
        self.commits += 1
        return self.store.commit_observation(proposal)

    def read_artifact(self, artifact_id: str):
        return self.store.read_artifact(artifact_id)


@dataclass(slots=True)
class _FixedExplorer:
    target_url: str
    tool_id: str = WEB_HTTP_MANIFEST.tool_id
    seen: list[ExplorationMetadata] = field(default_factory=list)
    proposals: list[BoundedActionProposal] = field(default_factory=list)

    def propose(self, metadata: ExplorationMetadata) -> BoundedActionProposal:
        self.seen.append(metadata)
        runtime_seconds = max(1, metadata.remaining_runtime_ms // 1_000)
        proposal = BoundedActionProposal(
            "acquire_url",
            self.target_url,
            self.tool_id,
            Budgets(
                metadata.remaining_requests,
                metadata.remaining_bytes,
                runtime_seconds,
                1,
            ),
        )
        self.proposals.append(proposal)
        return proposal


def _request(payload: dict[str, object]) -> Request:
    skill = site_skill_from_mapping(payload["target"]["site_skill"])
    return Request(skill.scope, skill, False, skill.budgets)


def _candidate_mapping(candidate: SiteSkillCandidate | None) -> object:
    return None if candidate is None else site_skill_to_mapping(candidate.skill)


def test_phase_19_snapshot_and_selector_are_strict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _load_snapshot()
    source = Path(__file__).read_text(encoding="utf-8")
    assert payload["phase"] == "19"
    assert "WEB_LISTENING_LIVE_SITE" in source
    forbidden_url_override = "WEB_LISTENING_LIVE_" + "URL"
    assert forbidden_url_override not in source
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "review-window")
    monkeypatch.setenv("WEB_LISTENING_LIVE_SITE", "ipcc")
    with pytest.raises(pytest.fail.Exception, match="must be iea"):
        _authorized_snapshot()


def test_phase_19_agent_exploration_live(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    payload = _authorized_snapshot()
    limits = payload["network_limits"]
    budget = _NetworkBudget(
        int(limits["max_total_requests"]),
        int(limits["max_total_response_bytes"]),
        int(limits["timeout_seconds"]),
    )
    request = _request(payload)
    active_digest = request.site_skill.digest
    monitor_url = request.scope.seeds[0]
    allowed_explorer = _FixedExplorer(payload["target"]["tree_seed_url"])
    live_tool = _ControlledInitialFailure(
        WebHttpAcquisitionTool(
            lambda: _CappedTransport(budget), runtime_deadline=budget.deadline
        ),
        monitor_url,
    )
    live_registry = Registry()
    live_registry.register(WEB_HTTP_MANIFEST, live_tool)
    live_store = ArtifactStore(tmp_path / "live-artifacts")
    live_spy = _StoreSpy(live_store)
    try:
        allowed = run_agent_assisted_target(
            request,
            live_registry,
            live_spy,
            run_id="live-phase-19-allowed",
            clock=lambda: NOW,
            explorer=allowed_explorer,
        )
    finally:
        live_store.close()
        live_tool.close()

    rejected_explorer = _FixedExplorer(payload["rejected_proposal"]["target_url"])
    offline_tool = _OfflineInitialFailure()
    rejected_registry = Registry()
    rejected_registry.register(WEB_HTTP_MANIFEST, offline_tool)
    rejected_store = ArtifactStore(tmp_path / "rejected-artifacts")
    rejected_spy = _StoreSpy(rejected_store)
    try:
        rejected = run_agent_assisted_target(
            request,
            rejected_registry,
            rejected_spy,
            run_id="live-phase-19-rejected",
            clock=lambda: NOW,
            explorer=rejected_explorer,
        )
    finally:
        rejected_store.close()

    evidence = {
        "phase_19_live_evidence": {
            "authorized_window": "present",
            "limits": limits,
            "proposer": {
                "allowed_input": asdict(allowed_explorer.seen[0]),
                "rejected_input": asdict(rejected_explorer.seen[0]),
                "body_fields_present": False,
                "call_counts": [
                    len(allowed_explorer.seen),
                    len(rejected_explorer.seen),
                ],
            },
            "proposals": [
                asdict(item)
                for item in (
                    allowed_explorer.proposals[0],
                    rejected_explorer.proposals[0],
                )
            ],
            "decisions": {
                "allowed": {"allowed": allowed.allowed, "code": allowed.code},
                "rejected": {
                    "allowed": rejected.allowed,
                    "code": rejected.code,
                },
            },
            "gateway": {
                "governed_target_invocations": live_tool.calls,
                "transport_sends": budget.sends,
                "ipcc_target_reads": 0,
                "ipcc_observations": rejected_spy.commits,
                "ipcc_initial_fixture_invocations": offline_tool.calls,
            },
            "attempts": {
                "allowed": [item.to_dict() for item in allowed.result.attempts],
                "rejected": [item.to_dict() for item in rejected.result.attempts],
            },
            "usage": {
                "allowed": allowed.result.usage.to_dict(),
                "rejected": rejected.result.usage.to_dict(),
                "network_requests": budget.requests,
                "network_response_bytes": budget.response_bytes,
            },
            "candidate": _candidate_mapping(allowed.candidate),
            "active_digest": {
                "before": active_digest,
                "after": request.site_skill.digest,
            },
            "result": allowed.result.to_dict(),
            "acceptance_mapping": {
                "AC-2": "proposer inputs/body_fields_present/call_counts",
                "AC-3": "decisions/rejected + gateway/ipcc_*",
                "AC-4": "attempts + usage + governed_target_invocations",
                "AC-5": "candidate + active_digest",
                "AC-7": "limits + proposals + gateway + result",
            },
        }
    }
    with capfd.disabled():
        print(json.dumps(evidence, sort_keys=True))

    assert allowed.allowed is True
    assert allowed.code == "exploration.succeeded"
    assert allowed.candidate is not None
    assert allowed.result.status.value == "partial"
    assert allowed_explorer.seen[0].active_site_skill_digest == active_digest
    assert not hasattr(allowed_explorer.seen[0], "body")
    assert live_tool.calls == [monitor_url, payload["target"]["tree_seed_url"]]
    assert live_spy.commits >= 1
    assert request.site_skill.digest == active_digest
    assert allowed.candidate.skill.previous_digest == active_digest
    assert rejected.allowed is False
    assert rejected.code == "scope.origin_not_allowed"
    assert rejected.candidate is None
    assert rejected_spy.commits == 0
    assert payload["rejected_proposal"]["target_url"] not in offline_tool.calls
    assert payload["rejected_proposal"]["target_url"] not in budget.sends
    assert budget.requests <= 12
    assert budget.response_bytes <= 4 * 1024 * 1024
    assert float(limits["timeout_seconds"]) <= 30
    assert limits["concurrency"] == 1
    assert limits["retry"] == 0
