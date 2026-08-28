"""Authorized Phase 18B deterministic site-explore evidence; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring,protected-access
# pylint: disable=too-few-public-methods

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import pytest

from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.runtime.site_explore import run_site_explore
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.discovery.builtins.html_links import (
    HTML_LINKS_MANIFEST,
    HtmlLinksDiscoveryTool,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners import in_process as in_process_runner
from web_listening.tool_registry.runners.in_process import (
    PinnedHttpTransport,
    TransportResponse,
)

TARGETS = Path(__file__).with_name("phase_18b_site_targets.json")
SMOKE_CATALOG = Path(__file__).parent / "catalog" / "smoke_site_catalog.json"
SKILL_CATALOG = Path(__file__).parent / "catalog" / "site_skill_cases.json"
SMOKE_SHA256 = "CE378F743C6363F1DC22A25758B958E3ADA695F8996B3F619AFA4CF0CD5D5322"
SKILL_SHA256 = "AE1CE1126EB475A21839FFEF178B68DC0806C19300C5347181197CD922E90BEC"


def _load_snapshot() -> tuple[dict[str, object], dict[str, object]]:
    payload = json.loads(TARGETS.read_bytes())
    target = payload.get("target")
    skill_case = payload.get("site_skill_case")
    if not isinstance(target, dict) or target.get("site_key") != "ipcc":
        pytest.fail("Phase 18B must retain exactly the audited IPCC row")
    if payload.get("source_catalog_sha256") != SMOKE_SHA256:
        pytest.fail("Phase 18B smoke catalog digest drifted")
    if payload.get("source_site_skill_catalog_sha256") != SKILL_SHA256:
        pytest.fail("Phase 18B Site Skill catalog digest drifted")
    if hashlib.sha256(SMOKE_CATALOG.read_bytes()).hexdigest().upper() != SMOKE_SHA256:
        pytest.fail("Phase 18B smoke source bytes drifted")
    if hashlib.sha256(SKILL_CATALOG.read_bytes()).hexdigest().upper() != SKILL_SHA256:
        pytest.fail("Phase 18B Site Skill source bytes drifted")
    smoke_rows = json.loads(SMOKE_CATALOG.read_bytes()).get("sites")
    skill_rows = json.loads(SKILL_CATALOG.read_bytes()).get("cases")
    if not isinstance(smoke_rows, list) or not isinstance(skill_rows, list):
        pytest.fail("Phase 18B source catalogs are invalid")
    if target != next(item for item in smoke_rows if item.get("site_key") == "ipcc"):
        pytest.fail("Phase 18B target drifted from the audited catalog")
    if skill_case != next(
        item for item in skill_rows if item.get("site_key") == "ipcc"
    ):
        pytest.fail("Phase 18B Site Skill provenance drifted")
    expected_limits = {
        "max_sites": 1,
        "max_seeds": 1,
        "max_acquired_candidates": 2,
        "max_total_requests": 20,
        "max_total_response_bytes": 8 * 1024 * 1024,
        "timeout_seconds": 60,
        "concurrency": 1,
        "retry": 0,
    }
    if payload.get("network_limits") != expected_limits:
        pytest.fail("Phase 18B network limits drifted")
    return payload, target


def _authorized_target() -> tuple[dict[str, object], dict[str, object]]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 18B site-explore live test is offline by default")
    if not os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip():
        pytest.fail("a non-empty Phase 18B authorized live window is required")
    return _load_snapshot()


class _NetworkBudget:
    def __init__(
        self,
        requests: int,
        response_bytes: int,
        timeout: int,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_requests = requests
        self.max_response_bytes = response_bytes
        self.requests = 0
        self.response_bytes = 0
        self._clock = clock
        self.deadline = clock() + timeout

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline - self._clock())


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
        response = self._transport.send(
            url,
            timeout=min(timeout, self._budget.remaining_seconds),
            addresses=addresses,
        )
        return _CappedResponse(response, self._budget)

    def close(self) -> None:
        self._transport.close()


def _request(target: dict[str, object]) -> Request:
    url = str(target["urls"]["monitor"])
    return Request(
        Scope(
            (url,),
            tuple(target["allowed_origins"]),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(20, 8 * 1024 * 1024, 60, 4),
    )


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_phase_18b_snapshot_is_exact_and_bounded() -> None:
    payload, target = _load_snapshot()

    assert payload["phase"] == "18B"
    assert target["historical_classification"]["expectation"] == "pass_http"
    assert target["provenance"]["old_commit"] == (
        "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5"
    )
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden_token = "WEB_LISTENING_" + "LIVE_URL"
    assert forbidden_token not in source
    runtime_call = "run_site_" + "explore("
    assert source.count(runtime_call) == 1


@pytest.mark.live
def test_phase_18b_site_explore_live(tmp_path: Path) -> None:
    payload, target = _authorized_target()
    limits = payload["network_limits"]
    budget = _NetworkBudget(
        limits["max_total_requests"],
        limits["max_total_response_bytes"],
        limits["timeout_seconds"],
    )
    request = _request(target)
    acquisition = WebHttpAcquisitionTool(
        lambda: _CappedTransport(budget), runtime_deadline=budget.deadline
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "phase-18b-artifacts")
    active_digest_before = None

    result = run_site_explore(
        request,
        registry,
        store,
        run_id="phase-18b-ipcc",
        clock=_now,
    )

    successful_candidates = tuple(
        attempt.requested_url
        for attempt in result.attempts
        if attempt.outcome == "succeeded"
        and attempt.requested_url not in request.scope.seeds
    )
    discovered = {
        url: source
        for evidence in result.discovery
        for url, source in zip(evidence.candidates, evidence.discovered_from)
    }
    evidence = {
        "phase_18b_live_evidence": {
            "authorized_window": os.environ["WEB_LISTENING_LIVE_AUTHORIZED_WINDOW"],
            "collected": 1,
            "passed": int(result.status.value == "completed"),
            "skipped": 0,
            "site_key": target["site_key"],
            "request": {
                "seeds": list(request.scope.seeds),
                "allowed_origins": list(request.scope.allowed_origins),
                "include_paths": list(request.scope.include_paths),
                "budgets": {
                    "max_requests": request.budgets.max_requests,
                    "max_bytes": request.budgets.max_bytes,
                    "max_runtime_seconds": request.budgets.max_runtime_seconds,
                    "max_tool_attempts": (request.budgets.max_tool_attempts_per_target),
                },
            },
            "discovery": [item.to_dict() for item in result.discovery],
            "gateway_attempts": [item.to_dict() for item in result.attempts],
            "usage": result.usage.to_dict(),
            "physical_network": {
                "requests": budget.requests,
                "response_bytes": budget.response_bytes,
                "timeout_seconds": limits["timeout_seconds"],
                "concurrency": limits["concurrency"],
                "retry": limits["retry"],
            },
            "successful_candidates": list(successful_candidates),
            "observations": [
                {
                    "canonical_url": page.canonical_url,
                    "observation_id": page.observation_id,
                    "artifact_id": page.artifact_id,
                    "content_digest": page.content_digest,
                }
                for page in result.site_state.pages
            ],
            "site_state_complete": result.site_state.complete,
            "site_skill_candidate_digest": (
                None
                if result.site_skill_candidate is None
                else result.site_skill_candidate.digest
            ),
            "candidate_inactive": result.site_skill_candidate is not None,
            "active_digest_before": active_digest_before,
            "active_digest_after": None,
            "stop_reason": result.stop_reason,
            "errors": [error.to_dict() for error in result.errors],
        }
    }
    print(json.dumps(evidence, sort_keys=True))

    assert result.status.value == "completed"
    assert result.exploration_complete is True
    assert result.site_skill_candidate is not None
    assert 1 <= len(successful_candidates) <= 2
    assert all(url in discovered for url in successful_candidates)
    assert all(discovered[url] in request.scope.seeds for url in successful_candidates)
    assert budget.requests <= 20
    assert budget.response_bytes <= 8 * 1024 * 1024
    assert active_digest_before is None
    assert result.site_skill_used is None
    acquisition.close()
    store.close()
