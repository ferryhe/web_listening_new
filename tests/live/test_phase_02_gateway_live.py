"""Explicitly authorized Phase 2 IPCC gateway canary; offline by default."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pytest

from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.tool_registry.runners.in_process import (
    GatewayFailure,
    GovernedAccessGateway,
    PinnedHttpTransport,
)

TARGETS = Path(__file__).with_name("phase_02_site_targets.json")


def _authorized_target() -> tuple[dict[str, object], str, str]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 2 live gateway test is offline by default")
    window = os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip()
    if not window:
        pytest.skip("a nonempty authorized live window is required")
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE", "").strip()
    if selector and selector != "ipcc":
        pytest.skip("the Phase 2 site filter does not select ipcc")

    raw = TARGETS.read_bytes()
    payload = json.loads(raw)
    targets = payload.get("targets")
    if not isinstance(targets, list) or len(targets) != 1:
        pytest.fail("Phase 2 live catalog must contain exactly one target")
    target = targets[0]
    if not isinstance(target, dict) or target.get("site_key") != "ipcc":
        pytest.fail("Phase 2 live catalog must select only ipcc")
    return target, hashlib.sha256(raw).hexdigest(), window


def _emit_evidence(
    record: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    packet = json.dumps(record, sort_keys=True)
    with capsys.disabled():
        print(packet, flush=True)


@pytest.mark.parametrize(
    ("selector", "should_skip"),
    [("", False), ("ipcc", False), ("other-site", True)],
)
def test_authorized_target_uses_optional_site_filter(
    monkeypatch: pytest.MonkeyPatch, selector: str, should_skip: bool
) -> None:
    """The optional selector narrows but never supplies the frozen target."""
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "offline-gate")
    if selector:
        monkeypatch.setenv("WEB_LISTENING_LIVE_SITE", selector)
    else:
        monkeypatch.delenv("WEB_LISTENING_LIVE_SITE", raising=False)

    if should_skip:
        with pytest.raises(pytest.skip.Exception):
            _authorized_target()
        return

    try:
        target, catalog_sha256, window = _authorized_target()
    except pytest.skip.Exception as exc:
        pytest.fail(f"an allowed optional selector was skipped: {exc}")
    assert target["site_key"] == "ipcc"
    assert catalog_sha256
    assert window == "offline-gate"


def test_emit_evidence_bypasses_quiet_capture(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The evidence packet is visible while ordinary pytest capture stays empty."""
    _emit_evidence({"offline_evidence_marker": "phase-02-visible"}, capsys)

    assert capsys.readouterr().out == ""


@pytest.mark.live
def test_phase_02_gateway_live(capsys: pytest.CaptureFixture[str]) -> None:
    """Read the frozen IPCC target once through the governed gateway."""
    target, catalog_sha256, window = _authorized_target()
    url = str(target["url"])
    origins = tuple(str(item) for item in target["allowed_origins"])
    request = Request(
        scope=Scope(
            seeds=(url,),
            allowed_origins=origins,
            include_paths=("/**",),
            content_types=(ContentType.HTML,),
        ),
        site_skill=None,
        explore_all_tools=False,
        budgets=Budgets(
            max_requests=6,
            max_bytes=2 * 1024 * 1024,
            max_runtime_seconds=30,
            max_tool_attempts_per_target=1,
        ),
    )
    gateway = GovernedAccessGateway(request, PinnedHttpTransport())
    record: dict[str, object] = {
        "schema_version": "phase-02-live-evidence.v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "authorization_window_id": hashlib.sha256(window.encode("utf-8")).hexdigest(),
        "catalog": {
            "path": "tests/live/phase_02_site_targets.json",
            "sha256": catalog_sha256,
            "source_repo_commit": ("9fe9ea53104dd008086dfa0e86c35c50b75f4ce5"),
            "source_path": target["source_path"],
            "profile_source_path": target["profile_source_path"],
            "site_key": target["site_key"],
            "historical_expectation": target["historical_expectation"],
        },
        "limits": {
            "content_reads": 1,
            "max_total_requests": 6,
            "max_bytes_per_response": 2 * 1024 * 1024,
            "timeout_seconds": 30,
            "concurrency": 1,
            "retry": 0,
        },
        "requested_url": url,
        "result": {},
        "exit_behavior": "failure",
    }
    try:
        result = gateway.read(url)
        record["result"] = {
            "outcome": "allow",
            "requested_url": result.requested_url,
            "current_url": result.current_url,
            "final_url": result.final_url,
            "redirects": [asdict(item) for item in result.evidence.redirects],
            "access_decisions": [asdict(item) for item in result.evidence.decisions],
            "robots_decisions": [asdict(item) for item in result.evidence.robots],
            "status": result.status_code,
            "mime_type": result.mime_type,
            "content_bytes": len(result.body),
            "content_sha256": result.sha256,
            "usage": asdict(result.evidence.usage),
            "stable_error": None,
            "observed_expectation": (
                "pass_http" if 200 <= result.status_code < 300 else "http_error"
            ),
        }
        assert result.evidence.usage.requests <= 6
        assert len(result.body) <= 2 * 1024 * 1024
        assert 200 <= result.status_code < 300
        record["exit_behavior"] = "pytest_pass"
    except GatewayFailure as exc:
        record["result"] = {
            "outcome": "rejected_or_failed",
            "requested_url": exc.evidence.requested_url,
            "current_url": exc.evidence.current_url,
            "final_url": exc.evidence.final_url,
            "redirects": [asdict(item) for item in exc.evidence.redirects],
            "access_decisions": [asdict(item) for item in exc.evidence.decisions],
            "robots_decisions": [asdict(item) for item in exc.evidence.robots],
            "status": exc.evidence.response_status,
            "mime_type": exc.evidence.response_mime_type,
            "content_bytes": exc.evidence.content_bytes,
            "content_sha256": exc.evidence.content_sha256,
            "usage": asdict(exc.evidence.usage),
            "stable_error": exc.code,
        }
        record["exit_behavior"] = "gateway_failure"
        raise
    finally:
        gateway.close()
        _emit_evidence(record, capsys)
