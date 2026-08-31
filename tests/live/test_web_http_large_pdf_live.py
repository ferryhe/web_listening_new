"""Authorized large-PDF web_http evidence; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring,protected-access
# pylint: disable=too-few-public-methods,too-many-locals

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
from web_listening.runtime.workflow import run_single_target
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners import in_process as in_process_runner
from web_listening.tool_registry.runners.in_process import (
    PinnedHttpTransport,
    TransportResponse,
)

TARGETS = Path(__file__).with_name("web_http_large_pdf_target.json")
DEV_CATALOG = Path(__file__).parent / "catalog" / "dev_test_sites.json"
CATALOG_SHA256 = "3074C31AC5370D0D6E1C1025D28E08CCCAAD042F976547540F420FAEF81CAED3"
EXPECTED_LIMITS = {
    "max_sites": 1,
    "max_total_requests": 12,
    "max_total_response_bytes": 8 * 1024 * 1024,
    "timeout_seconds": 60,
    "concurrency": 1,
    "retry": 0,
}


def _catalog_sha256(content: bytes) -> str:
    canonical = content.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    return hashlib.sha256(canonical).hexdigest().upper()


def _load_snapshot() -> (
    tuple[dict[str, object], dict[str, object]]
):  # pylint: disable=too-many-boolean-expressions
    payload = json.loads(TARGETS.read_bytes())
    target = payload.get("target")
    source_catalog = payload.get("source_catalog")
    if payload.get("schema_version") != "web-http-large-pdf-target.v1":
        pytest.fail("large-PDF target schema drifted")
    if payload.get("network_limits") != EXPECTED_LIMITS:
        pytest.fail("large-PDF network limits drifted")
    if source_catalog != {
        "path": "tests/live/catalog/dev_test_sites.json",
        "sha256": CATALOG_SHA256,
        "sha256_basis": "catalog bytes canonicalized to CRLF",
    }:
        pytest.fail("large-PDF source catalog identity drifted")
    if _catalog_sha256(DEV_CATALOG.read_bytes()) != CATALOG_SHA256:
        pytest.fail("large-PDF source catalog bytes drifted")
    if not isinstance(target, dict):
        pytest.fail("large-PDF target is invalid")
    dev_rows = json.loads(DEV_CATALOG.read_bytes()).get("sites")
    if not isinstance(dev_rows, list):
        pytest.fail("large-PDF source catalog is invalid")
    source = next(
        (row for row in dev_rows if row.get("site_key") == "iaa"),
        None,
    )
    if not isinstance(source, dict):
        pytest.fail("large-PDF source row is missing")
    if (
        target.get("site_key") != source.get("site_key")
        or target.get("source_url") != source.get("urls", {}).get("document")
        or target.get("allowed_origins") != source.get("allowed_origins")
        or target.get("historical_expectation")
        != source.get("historical_classification", {}).get("expectation")
    ):
        pytest.fail("large-PDF target drifted from the audited IAA catalog row")
    expected_target_url = (
        "https://actuaries.org/app/uploads/2026/01/2016AnnualReportEN.pdf"
    )
    provenance = target.get("provenance")
    if (
        target.get("target_url") != expected_target_url
        or target.get("expected_mime_type") != "application/pdf"
        or target.get("minimum_size_bytes") != 2 * 1024 * 1024 + 1
        or not isinstance(provenance, dict)
        or provenance.get("issue_69_source_artifact_sha256")
        != "181a7852c90043001e92f35f85a13cd7db2402a88b11f47f487655b31c4bf26d"
        or provenance.get("issue_69_target_url_sha256")
        != hashlib.sha256(expected_target_url.encode("utf-8")).hexdigest()
        or provenance.get("observed_error_code") != "registry.output_limit"
    ):
        pytest.fail("large-PDF target drifted from the preserved Issue 69 evidence")
    return payload, target


def _authorized_target() -> tuple[dict[str, object], dict[str, object]]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("large-PDF live test is offline by default")
    if not os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip():
        pytest.fail("a non-empty large-PDF authorized live window is required")
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE", "iaa").strip() or "iaa"
    if selector != "iaa":
        pytest.fail("WEB_LISTENING_LIVE_SITE must be the authorized IAA key")
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
        self.started_at = clock()
        self.deadline = self.started_at + timeout

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline - self._clock())

    @property
    def elapsed_seconds(self) -> float:
        return max(0.0, self._clock() - self.started_at)


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
        self._response.set_timeout(min(timeout, remaining))

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


def _url_id(value: str | None) -> str | None:
    if value is None:
        return None
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _error_code(error) -> str | None:
    return None if error is None else error.code


def _evidence_packet(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    target: dict[str, object],
    snapshot_sha256: str,
    request: Request,
    result,
    store: ArtifactStore,
    budget: _NetworkBudget,
) -> dict[str, object]:
    artifacts = []
    for artifact in result.artifacts:
        stored = store.get_observation(artifact.observation_id)
        artifacts.append(
            {
                "artifact_id": artifact.artifact_id,
                "observation_id": artifact.observation_id,
                "role": artifact.role,
                "source_url_id": _url_id(artifact.source_url),
                "mime_type": artifact.mime_type,
                "size_bytes": artifact.size_bytes,
                "sha256": artifact.sha256,
                "stored_content_sha256": hashlib.sha256(stored.content).hexdigest(),
                "stored_size_bytes": len(stored.content),
                "lineage": [],
            }
        )
    return {
        "schema_version": "web-http-large-pdf-live-evidence.v1",
        "observed_at": _now(),
        "authorization_window_id": _url_id(
            os.environ["WEB_LISTENING_LIVE_AUTHORIZED_WINDOW"]
        ),
        "snapshot_sha256": snapshot_sha256,
        "site_key": target["site_key"],
        "request": {
            "seed_url_id": _url_id(request.scope.seeds[0]),
            "allowed_origin_ids": [
                _url_id(origin) for origin in request.scope.allowed_origins
            ],
            "include_paths": list(request.scope.include_paths),
            "content_types": [item.value for item in request.scope.content_types],
            "site_skill": None,
            "explore_all_tools": request.explore_all_tools,
            "budgets": {
                "max_requests": request.budgets.max_requests,
                "max_bytes": request.budgets.max_bytes,
                "max_runtime_seconds": request.budgets.max_runtime_seconds,
                "max_tool_attempts_per_target": (
                    request.budgets.max_tool_attempts_per_target
                ),
            },
        },
        "result": {
            "schema_version": result.schema_version,
            "status": result.status.value,
            "site_skill_used": None,
            "site_skill_update": None,
            "errors": [_error_code(error) for error in result.errors],
        },
        "manifest": {
            "schema_version": result.manifest.schema_version,
            "requested_url_id": _url_id(result.manifest.requested_url),
            "current_url_id": _url_id(result.manifest.current_url),
            "final_url_id": _url_id(result.manifest.final_url),
            "http_status": result.manifest.http_status,
            "mime_type": result.manifest.mime_type,
            "size_bytes": result.manifest.size_bytes,
            "sha256": result.manifest.sha256,
            "tool_id": result.manifest.tool_id,
            "tool_version": result.manifest.tool_version,
            "redirects": [
                {
                    "order": redirect.order,
                    "from_url_id": _url_id(redirect.from_url),
                    "to_url_id": _url_id(redirect.to_url),
                    "http_status": redirect.http_status,
                    "decision": redirect.decision,
                }
                for redirect in result.manifest.redirects
            ],
        },
        "artifacts": artifacts,
        "attempts": [
            {
                "order": attempt.order,
                "attempt_id": attempt.attempt_id,
                "outcome": attempt.outcome,
                "tool_id": attempt.tool_id,
                "tool_version": attempt.tool_version,
                "requested_url_id": _url_id(attempt.requested_url),
                "final_url_id": _url_id(attempt.final_url),
                "http_status": attempt.http_status,
                "requests": attempt.requests,
                "bytes_received": attempt.bytes_received,
                "runtime_ms": attempt.runtime_ms,
                "error_code": _error_code(attempt.error),
            }
            for attempt in result.attempts
        ],
        "usage": result.usage.to_dict(),
        "physical_network": {
            "requests": budget.requests,
            "response_bytes": budget.response_bytes,
            "runtime_seconds": round(budget.elapsed_seconds, 6),
            "concurrency": 1,
            "retry": 0,
        },
    }


def test_large_pdf_snapshot_is_fixed_audited_and_bounded() -> None:
    payload, target = _load_snapshot()

    assert payload["network_limits"] == EXPECTED_LIMITS
    assert target["site_key"] == "iaa"
    assert target["minimum_size_bytes"] > 2 * 1024 * 1024
    assert target["expected_mime_type"] == "application/pdf"
    assert target["provenance"]["observed_bytes_received"] < 8 * 1024 * 1024


def test_large_pdf_live_is_offline_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("WEB_LISTENING_RUN_LIVE", raising=False)

    with pytest.raises(pytest.skip.Exception):
        _authorized_target()


def test_large_pdf_live_selector_cannot_inject_a_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "test-window")
    monkeypatch.setenv("WEB_LISTENING_LIVE_SITE", "https://example.invalid/")

    with pytest.raises(pytest.fail.Exception, match="authorized IAA key"):
        _authorized_target()


@pytest.mark.live
def test_web_http_large_pdf_live(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Acquire one fixed IAA PDF through Registry and Runtime under hard caps."""
    payload, target = _authorized_target()
    limits = payload["network_limits"]
    budget = _NetworkBudget(
        limits["max_total_requests"],
        limits["max_total_response_bytes"],
        limits["timeout_seconds"],
    )
    transport = _CappedTransport(budget)
    tool = WebHttpAcquisitionTool(
        lambda: transport,
        runtime_deadline=budget.deadline,
    )
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, tool)
    store = ArtifactStore(tmp_path / "artifacts")
    target_url = target["target_url"]
    request = Request(
        Scope(
            (target_url,),
            tuple(target["allowed_origins"]),
            ("/**",),
            (ContentType.FILE,),
        ),
        None,
        False,
        Budgets(12, 8 * 1024 * 1024, 60, 1),
    )
    result = run_single_target(
        request,
        registry,
        store,
        run_id="issue-70-web-http-large-pdf-live",
        clock=_now,
    )
    snapshot_sha256 = hashlib.sha256(TARGETS.read_bytes()).hexdigest()
    packet = _evidence_packet(
        target,
        snapshot_sha256,
        request,
        result,
        store,
        budget,
    )
    try:
        assert result.status.value == "completed", packet["result"]
        assert not result.errors, packet["result"]
        assert len(result.artifacts) == 1, packet["artifacts"]
        artifact = result.artifacts[0]
        assert artifact.role == "source"
        assert artifact.mime_type == target["expected_mime_type"]
        assert artifact.size_bytes >= target["minimum_size_bytes"]
        assert artifact.size_bytes <= request.budgets.max_bytes
        stored = store.get_observation(artifact.observation_id)
        assert stored.content.startswith(b"%PDF-")
        assert len(stored.content) == artifact.size_bytes
        assert hashlib.sha256(stored.content).hexdigest() == artifact.sha256
        assert not stored.lineage
        assert result.manifest.artifacts == result.artifacts
        assert result.manifest.mime_type == "application/pdf"
        assert result.manifest.size_bytes == artifact.size_bytes
        assert result.manifest.sha256 == artifact.sha256
        assert len(result.attempts) == 1
        attempt = result.attempts[0]
        assert attempt.outcome == "succeeded"
        assert attempt.error is None
        assert attempt.http_status == 200
        assert attempt.tool_id == WEB_HTTP_MANIFEST.tool_id
        assert attempt.tool_version == WEB_HTTP_MANIFEST.version
        assert result.usage.bytes_received == budget.response_bytes
        assert result.usage.requests == budget.requests
        assert budget.requests <= limits["max_total_requests"]
        assert budget.response_bytes <= limits["max_total_response_bytes"]
        assert budget.elapsed_seconds <= limits["timeout_seconds"]
    finally:
        store.close()
        tool.close()
        with capsys.disabled():
            print(
                json.dumps(
                    {"web_http_large_pdf_live_evidence": packet}, sort_keys=True
                ),
                flush=True,
            )
