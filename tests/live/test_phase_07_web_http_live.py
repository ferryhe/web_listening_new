"""Explicitly authorized Phase 7 web_http canary; offline by default."""

# pylint: disable=duplicate-code

from __future__ import annotations

import hashlib
import inspect
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pytest

import web_listening.tool_registry.acquisition.builtins.web_http as web_http_module
from web_listening.request.model import Budgets, ContentType, Request, Scope
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
from web_listening.tool_registry.runners.in_process import (
    GatewayEvidence,
    GatewayFailure,
    GatewayResult,
    GovernedAccessGateway,
    PinnedHttpTransport,
)

TARGETS = Path(__file__).with_name("phase_07_site_targets.json")
AUTHORIZED_WINDOW = "issue-8-20260825-authorized"


class _RecordingGateway(GovernedAccessGateway):
    """Retain sanitized public evidence from the one real gateway read."""

    evidence: GatewayEvidence | None = None

    def read(self, url: str) -> GatewayResult:
        try:
            result = super().read(url)
        except GatewayFailure as exc:
            type(self).evidence = exc.evidence
            raise
        type(self).evidence = result.evidence
        return result


def _load_authorized_target() -> tuple[dict[str, object], str]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 7 web_http live test is offline by default")
    if os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW") != AUTHORIZED_WINDOW:
        pytest.fail("the exact Phase 7 authorized live window is required")

    payload = json.loads(TARGETS.read_bytes())
    targets = payload.get("targets")
    if not isinstance(targets, list) or len(targets) != 1:
        pytest.fail("Phase 7 live catalog must contain exactly one target")
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE", "ipcc").strip() or "ipcc"
    by_key = {
        target.get("site_key"): target for target in targets if isinstance(target, dict)
    }
    if selector not in by_key:
        pytest.fail("WEB_LISTENING_LIVE_SITE must be an authorized catalog key")
    target = by_key[selector]
    expected = {
        "site_key": "ipcc",
        "url": "https://www.ipcc.ch/",
        "allowed_origins": ["https://www.ipcc.ch"],
        "historical_expectation": "pass_http",
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
    if target != expected:
        pytest.fail("Phase 7 target drifted from the audited IPCC catalog row")
    expected_limits = {
        "max_content_reads_per_target": 1,
        "max_total_requests": 6,
        "max_bytes_per_response": 2 * 1024 * 1024,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
    }
    if payload.get("network_limits") != expected_limits:
        pytest.fail("Phase 7 network limits drifted from the authorized caps")
    return target, hashlib.sha256(TARGETS.read_bytes()).hexdigest()


@pytest.mark.parametrize("authorized_window", [None, "wrong-window"])
def test_explicit_live_rejects_missing_or_wrong_authorized_window(
    monkeypatch: pytest.MonkeyPatch, authorized_window: str | None
) -> None:
    """An explicit live opt-in cannot bypass the exact window gate."""
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    if authorized_window is None:
        monkeypatch.delenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", raising=False)
    else:
        monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", authorized_window)

    with pytest.raises(pytest.fail.Exception, match="exact Phase 7"):
        _load_authorized_target()


def test_offline_default_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """Normal local and CI runs never access the network."""
    monkeypatch.delenv("WEB_LISTENING_RUN_LIVE", raising=False)

    with pytest.raises(pytest.skip.Exception):
        _load_authorized_target()


def test_live_selector_accepts_only_the_frozen_catalog_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The selector narrows a snapshot key and cannot inject a URL."""
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", AUTHORIZED_WINDOW)
    monkeypatch.setenv("WEB_LISTENING_LIVE_SITE", "https://example.invalid/")

    with pytest.raises(pytest.fail.Exception, match="authorized catalog key"):
        _load_authorized_target()


def test_live_record_contains_current_url_without_an_extra_read() -> None:
    """Both live outcomes expose current URL while invoking the tool once."""
    source = inspect.getsource(test_phase_07_web_http_live)

    assert source.count('"current_url": gateway_evidence.current_url') == 2
    assert source.count("registry.invoke(") == 1
    assert "gateway.read(" not in source


def _emit(record: dict[str, object], capsys: pytest.CaptureFixture[str]) -> None:
    with capsys.disabled():
        print(json.dumps(record, sort_keys=True), flush=True)


@pytest.mark.live
def test_phase_07_web_http_live(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invoke web_http through Registry and one real governed gateway."""
    target, snapshot_sha256 = _load_authorized_target()
    url = str(target["url"])
    request = Request(
        Scope(
            seeds=(url,),
            allowed_origins=tuple(str(item) for item in target["allowed_origins"]),
            include_paths=("/**",),
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
        None,
        False,
        Budgets(6, 2 * 1024 * 1024, 30, 1),
    )
    _RecordingGateway.evidence = None
    monkeypatch.setattr(web_http_module, "GovernedAccessGateway", _RecordingGateway)
    tool = WebHttpAcquisitionTool(PinnedHttpTransport)
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, tool)
    record: dict[str, object] = {
        "schema_version": "phase-07-live-evidence.v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "authorization_window_id": hashlib.sha256(
            AUTHORIZED_WINDOW.encode("utf-8")
        ).hexdigest(),
        "input": {"site_key": target["site_key"], "target_url": url},
        "snapshot_sha256": snapshot_sha256,
        "limits": {
            "content_reads": 1,
            "max_total_requests": 6,
            "max_bytes_per_response": 2 * 1024 * 1024,
            "timeout_seconds": 30,
            "concurrency": 1,
            "retry": 0,
        },
        "tool": {
            "tool_id": WEB_HTTP_MANIFEST.tool_id,
            "version": WEB_HTTP_MANIFEST.version,
        },
        "artifact_store_writes": 0,
        "result": {},
        "exit_behavior": "failure",
    }
    try:
        output = registry.invoke(
            WEB_HTTP_MANIFEST.tool_id, AcquisitionInput(request, url)
        )
        gateway_evidence = _RecordingGateway.evidence
        assert gateway_evidence is not None
        if isinstance(output, AcquisitionFailure):
            record["result"] = {
                "outcome": "failed_or_rejected",
                "requested_url": gateway_evidence.requested_url,
                "current_url": gateway_evidence.current_url,
                "final_url": gateway_evidence.final_url,
                "status": gateway_evidence.response_status,
                "mime_type": gateway_evidence.response_mime_type,
                "content_bytes": gateway_evidence.content_bytes,
                "content_sha256": gateway_evidence.content_sha256,
                "redirects": [asdict(item) for item in gateway_evidence.redirects],
                "access_decisions": [
                    asdict(item) for item in gateway_evidence.decisions
                ],
                "robots_decisions": [asdict(item) for item in gateway_evidence.robots],
                "usage": asdict(gateway_evidence.usage),
                "stable_error": output.code,
            }
            record["exit_behavior"] = "acquisition_failure"
            pytest.fail(f"web_http returned {output.code}")
        assert isinstance(output, AcquisitionOutput)
        record["result"] = {
            "outcome": "success",
            "requested_url": output.requested_url,
            "current_url": gateway_evidence.current_url,
            "final_url": output.final_url,
            "status": output.status_code,
            "mime_type": output.mime_type,
            "content_bytes": len(output.body),
            "content_sha256": output.sha256,
            "redirects": [asdict(item) for item in output.redirects],
            "access_decisions": [asdict(item) for item in gateway_evidence.decisions],
            "robots_decisions": [asdict(item) for item in gateway_evidence.robots],
            "usage": asdict(gateway_evidence.usage),
            "runtime_ms": output.runtime_ms,
            "stable_error": None,
            "historical_expected": target["historical_expectation"],
            "observed": "pass_http",
        }
        assert gateway_evidence.usage.requests <= 6
        assert len(output.body) <= 2 * 1024 * 1024
        assert 200 <= output.status_code < 300
        assert output.sha256 == hashlib.sha256(output.body).hexdigest()
        record["exit_behavior"] = "pytest_pass"
    finally:
        tool.close()
        _emit(record, capsys)
