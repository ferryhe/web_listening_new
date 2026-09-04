"""Authorized fixed canary for Runtime active-Transform composition."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.runtime.service import RuntimeService
from web_listening.tool_registry.lifecycle import ToolLifecycle
from web_listening.tool_registry.manifest import ToolCategory

pytestmark = pytest.mark.live

ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "tests/fixtures/tools/external_transform/1.0.0"
TARGETS = Path(__file__).with_name("runtime_active_transform_targets.json")
TOOL_ID = "external.basic_html_markdown"
VERSION = "1.0.0"


def _authorized_snapshot() -> tuple[dict[str, object], dict[str, object]]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Issue 88 live test is offline by default")
    if not os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip():
        pytest.fail("a non-empty authorized live window is required")
    payload = json.loads(TARGETS.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "issue-88-runtime-active-transform-live.v1"
    assert payload["limits"] == {
        "max_targets": 1,
        "max_requests": 6,
        "max_bytes": 4 * 1024 * 1024,
        "max_seconds": 30,
        "concurrency": 1,
        "retry": 0,
    }
    targets = payload["targets"]
    assert isinstance(targets, list) and len(targets) == 1
    target = targets[0]
    assert target == {
        "site_key": "example",
        "url": "https://example.com/",
        "allowed_origins": ["https://example.com"],
        "include_paths": ["/**"],
        "content_type": "html",
    }
    return payload, target


def test_runtime_uses_active_external_transform_with_bounded_metadata_evidence(
    tmp_path: Path,
) -> None:
    payload, target = _authorized_snapshot()
    limits = payload["limits"]
    assert isinstance(limits, dict)
    data_dir = tmp_path / "runtime"
    lifecycle = ToolLifecycle(data_dir)
    lifecycle.install(SOURCE)
    lifecycle.qualify(ToolCategory.TRANSFORM, TOOL_ID, VERSION)
    lifecycle.activate(ToolCategory.TRANSFORM, TOOL_ID, VERSION)
    budgets = Budgets(
        limits["max_requests"], limits["max_bytes"], limits["max_seconds"], 2
    )
    request = Request(
        Scope(
            (target["url"],),
            tuple(target["allowed_origins"]),
            tuple(target["include_paths"]),
            (ContentType.HTML,),
        ),
        None,
        False,
        budgets,
    )

    service = RuntimeService.open(data_dir)
    try:
        job = service.run(request)
        assert job.result is not None
        result = job.result
        assert result.status.value == "completed"
        assert result.usage.requests <= limits["max_requests"]
        assert result.usage.bytes_received <= limits["max_bytes"]
        assert result.usage.runtime_ms <= limits["max_seconds"] * 1000
        transform_attempt = result.attempts[-1]
        assert (transform_attempt.tool_id, transform_attempt.tool_version) == (
            TOOL_ID,
            VERSION,
        )
        assert transform_attempt.outcome == "succeeded"
        assert tuple(item.role for item in result.artifacts) == ("source", "derived")
        derived = service.read_artifact(result.artifacts[-1].artifact_id)
        assert derived.mime_type == "text/markdown"
        assert derived.size_bytes > 0
        assert result.artifacts[-1].lineage
    finally:
        service.close()
