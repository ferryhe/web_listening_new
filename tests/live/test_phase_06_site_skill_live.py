"""Explicitly authorized Phase 6 IPCC Site Skill canary; offline by default."""

# pylint: disable=duplicate-code

from __future__ import annotations

import hashlib
import json
import os
import re
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.site_skill.resolve import resolve_site_skill
from web_listening.site_skill.validate import site_skill_from_mapping
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners.in_process import (
    GatewayFailure,
    GovernedAccessGateway,
    PinnedHttpTransport,
)

LIVE = Path(__file__).parent
TARGETS = LIVE / "phase_06_site_targets.json"
CATALOG = LIVE / "catalog" / "smoke_site_catalog.json"
CASES = LIVE / "catalog" / "site_skill_cases.json"
AUTHORIZED_WINDOW = "issue-7-20260825-authorized"


@dataclass(slots=True)
class _MetadataOnlyAcquisitionTool:
    manifest: ToolManifest

    def acquire(self, _tool_input: object) -> None:
        """Prove metadata resolution never invokes the registered method."""
        raise AssertionError("Site Skill resolution must never execute a tool")


def _assert_target_binding(
    target: dict[str, object],
    catalog_row: dict[str, object],
    case: dict[str, object],
) -> None:
    try:
        site_skill = case["site_skill"]
        bound = (
            target["site_key"] == catalog_row["site_key"] == case["site_key"] == "ipcc"
            and target["site_skill_case"]
            == catalog_row["site_skill_case"]
            == case["site_key"]
            and target["provenance"] == catalog_row["provenance"] == case["provenance"]
            and target["url"] == catalog_row["urls"]["monitor"]
            and target["allowed_origins"] == catalog_row["allowed_origins"]
            and target["site_skill_digest"]
            == catalog_row["site_skill_digest"]
            == site_skill["digest"]
            and target["historical_expectation"]
            == catalog_row["historical_classification"]["expectation"]
            and target["minimum_words"]
            == catalog_row["evidence_thresholds"]["monitor_min_words"]
            == site_skill["success_checks"]["minimum_words"]
            and catalog_row["tool_facts"] == site_skill["tool"]
        )
    except (KeyError, TypeError):
        bound = False
    if not bound:
        pytest.fail("Phase 6 target drifted from the normalized catalog")


def _load_authorized_target() -> tuple[dict[str, object], dict[str, object], str]:
    """Load only an explicitly authorized normalized catalog target."""
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 6 live Site Skill test is offline by default")
    if os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW") != AUTHORIZED_WINDOW:
        pytest.skip("the exact Phase 6 authorized live window is required")

    catalog_raw = CATALOG.read_bytes()
    catalog = json.loads(catalog_raw)
    targets = json.loads(TARGETS.read_bytes())["targets"]
    cases = json.loads(CASES.read_bytes())["cases"]
    catalog_by_key = {row["site_key"]: row for row in catalog["sites"]}
    target_by_key = {row["site_key"]: row for row in targets}
    case_by_key = {row["site_key"]: row for row in cases}
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE", "ipcc").strip() or "ipcc"
    if selector not in catalog_by_key:
        pytest.fail("WEB_LISTENING_LIVE_SITE must be an existing catalog key")
    if selector not in target_by_key:
        pytest.skip("the existing catalog key is not an authorized Phase 6 target")
    if len(targets) > 2:
        pytest.fail("Phase 6 target count exceeds the frozen limit")

    target = target_by_key[selector]
    catalog_row = catalog_by_key[selector]
    case = case_by_key[selector]
    _assert_target_binding(target, catalog_row, case)
    return target, case, hashlib.sha256(catalog_raw).hexdigest()


def test_target_binding_rejects_coordinated_drift_before_gateway() -> None:
    """Every target claim is bound before transport construction or access."""
    target = json.loads(TARGETS.read_bytes())["targets"][0]
    catalog_row = next(
        row
        for row in json.loads(CATALOG.read_bytes())["sites"]
        if row["site_key"] == "ipcc"
    )
    case = next(
        row
        for row in json.loads(CASES.read_bytes())["cases"]
        if row["site_key"] == "ipcc"
    )
    mutations = (
        lambda item: item.__setitem__("site_skill_case", "different-case"),
        lambda item: item["provenance"].__setitem__("old_site_key", "different"),
        lambda item: item.__setitem__("minimum_words", 299),
    )
    for mutate in mutations:
        changed = deepcopy(target)
        mutate(changed)
        with pytest.raises(pytest.fail.Exception, match="target drifted"):
            _assert_target_binding(changed, catalog_row, case)


def _registry_for(case: dict[str, object]) -> Registry:
    skill = site_skill_from_mapping(case["site_skill"])
    manifest = ToolManifest(
        skill.tool.tool_id,
        skill.tool.version,
        skill.tool.category,
        ToolDistribution.BUILTIN,
        skill.tool.capabilities,
        ToolLimits(30, 2 * 1024 * 1024, 2 * 1024 * 1024),
        HealthStatus.HEALTHY,
        QualificationStatus.QUALIFIED,
    )
    registry = Registry()
    registry.register(manifest, _MetadataOnlyAcquisitionTool(manifest))
    return registry


def _emit(record: dict[str, object], capsys: pytest.CaptureFixture[str]) -> None:
    with capsys.disabled():
        print(json.dumps(record, sort_keys=True), flush=True)


@pytest.mark.live
def test_phase_06_site_skill_live(capsys: pytest.CaptureFixture[str]) -> None:
    """Resolve normalized IPCC data, then perform one governed content read."""
    target, case, catalog_sha256 = _load_authorized_target()
    skill = site_skill_from_mapping(case["site_skill"])
    request = Request(
        scope=Scope(
            seeds=skill.scope.seeds,
            allowed_origins=skill.scope.allowed_origins,
            include_paths=("/**",),
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
        site_skill=None,
        explore_all_tools=False,
        budgets=Budgets(12, 2 * 1024 * 1024, 30, 1),
    )
    resolution = resolve_site_skill(request, skill, _registry_for(case))
    assert resolution.eligible, resolution.reasons

    gateway = GovernedAccessGateway(resolution.request, PinnedHttpTransport())
    record: dict[str, object] = {
        "schema_version": "phase-06-live-evidence.v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "authorization_window_id": hashlib.sha256(
            AUTHORIZED_WINDOW.encode("utf-8")
        ).hexdigest(),
        "catalog": {
            "path": "tests/live/catalog/smoke_site_catalog.json",
            "sha256": catalog_sha256,
            "site_key": target["site_key"],
            "site_skill_digest": skill.digest,
            "provenance": target["provenance"],
        },
        "limits": {
            "targets": 1,
            "content_reads_per_target": 1,
            "max_total_requests": 12,
            "max_bytes_per_response": 2 * 1024 * 1024,
            "timeout_seconds": 30,
            "concurrency": 1,
            "retry": 0,
        },
        "requested_url": target["url"],
        "scope_intersection": {
            "seeds": list(resolution.request.scope.seeds),
            "allowed_origins": list(resolution.request.scope.allowed_origins),
            "include_paths": list(resolution.request.scope.include_paths),
            "content_types": [
                item.value for item in resolution.request.scope.content_types
            ],
        },
        "tool_eligibility": {
            "tool_id": skill.tool.tool_id,
            "version": skill.tool.version,
            "eligible": resolution.eligible,
            "reasons": list(resolution.reasons),
        },
        "result": {},
        "exit_behavior": "failure",
    }
    try:
        result = gateway.read(str(target["url"]))
        words = len(re.findall(r"\w+", result.body.decode("utf-8", errors="ignore")))
        observed = (
            "pass_http"
            if 200 <= result.status_code < 300 and words >= int(target["minimum_words"])
            else "threshold_miss"
        )
        record["result"] = {
            "outcome": "allow",
            "requested_url": result.requested_url,
            "current_url": result.current_url,
            "final_url": result.final_url,
            "policy_scope_decisions": [
                asdict(item) for item in result.evidence.decisions
            ],
            "robots_decisions": [asdict(item) for item in result.evidence.robots],
            "redirect_decisions": [asdict(item) for item in result.evidence.redirects],
            "status": result.status_code,
            "mime_type": result.mime_type,
            "content_bytes": len(result.body),
            "content_sha256": result.sha256,
            "word_count": words,
            "usage": asdict(result.evidence.usage),
            "stable_error": None,
            "historical_to_observed_drift": {
                "historical": target["historical_expectation"],
                "observed": observed,
                "drifted": target["historical_expectation"] != observed,
            },
        }
        assert result.evidence.usage.requests <= 12
        assert len(result.body) <= 2 * 1024 * 1024
        assert observed == target["historical_expectation"]
        record["exit_behavior"] = "pytest_pass"
    except GatewayFailure as exc:
        record["result"] = {
            "outcome": "rejected_or_failed",
            "requested_url": exc.evidence.requested_url,
            "current_url": exc.evidence.current_url,
            "final_url": exc.evidence.final_url,
            "policy_scope_decisions": [asdict(item) for item in exc.evidence.decisions],
            "robots_decisions": [asdict(item) for item in exc.evidence.robots],
            "redirect_decisions": [asdict(item) for item in exc.evidence.redirects],
            "status": exc.evidence.response_status,
            "mime_type": exc.evidence.response_mime_type,
            "content_bytes": exc.evidence.content_bytes,
            "content_sha256": exc.evidence.content_sha256,
            "usage": asdict(exc.evidence.usage),
            "stable_error": exc.code,
            "historical_to_observed_drift": {
                "historical": target["historical_expectation"],
                "observed": "gateway_failure",
                "drifted": True,
            },
        }
        record["exit_behavior"] = "gateway_failure"
        raise
    finally:
        gateway.close()
        _emit(record, capsys)
