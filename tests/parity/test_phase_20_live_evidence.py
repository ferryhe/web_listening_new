"""Offline regressions for Phase 20 Live evidence projection and invocation shape."""

# pylint: disable=import-outside-toplevel,missing-function-docstring
# pylint: disable=too-many-branches,too-many-lines,too-many-locals
# pylint: disable=too-few-public-methods

from __future__ import annotations

import inspect
import json
import runpy
import subprocess
import sys
from copy import deepcopy
from dataclasses import asdict
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
LIVE = runpy.run_path(str(ROOT / "tests" / "live" / "test_phase_20_parity_live.py"))
COMPARE = LIVE["COMPARE"]
CASE_EVIDENCE = LIVE["_case_evidence"]
LIVE_SEMANTICS = LIVE["_live_semantics"]
OLD_INVOCATION = LIVE["_old_invocation_descriptor"]
NEW_INVOCATION = LIVE["_new_invocation_descriptor"]
OUTER_INVOCATION = LIVE["_outer_invocation_descriptor"]

_LIMITS = {
    "max_targets": 2,
    "max_total_requests": 8,
    "max_total_response_bytes": 4 * 1024 * 1024,
    "timeout_seconds": 30,
    "concurrency": 1,
    "retry": 0,
}
_CASES = [
    {
        "case_id": kind,
        "request_digest": f"{kind}-digest",
        "requested_url": f"https://example.test/{kind}",
        "minimum_words": 1,
        "minimum_document_links": 1 if kind == "document" else 0,
    }
    for kind in ("monitor", "document")
]
_CANDIDATE_HEAD_REVISION = "f" * 40


def _failure_record(*, legacy: bool) -> dict[str, object]:
    descriptor = {
        "schema_version": "phase-20-request-descriptor.v1",
        "scope": {
            "seeds": ["https://example.test/"],
            "allowed_origins": ["https://example.test"],
            "include_paths": ["/**"],
            "content_types": ["html"],
        },
        "request": {"site_skill": "N/A", "explore_all_tools": False},
        "budgets": {
            "max_requests": 4,
            "max_bytes": 2 * 1024 * 1024,
            "max_runtime_seconds": 28,
            "max_tool_attempts_per_target": 1,
        },
    }
    record = dict.fromkeys(
        (
            "final_url",
            "status",
            "mime_type",
            "content_sha256",
            "content_bytes",
            "word_count",
            "document_link_count",
        )
    )
    record.update(
        {
            "case_id": "monitor",
            "request_descriptor": descriptor,
            "request_digest": LIVE["_descriptor_digest"](descriptor),
            "requested_url": "https://example.test/",
            "redirects": [],
            "artifact": {"availability": "N/A" if legacy else "none"},
            "observation": {"availability": "N/A" if legacy else "none"},
            "manifest": {"availability": "N/A" if legacy else "present"},
            "outcome": "failure",
            "attempts": (
                "N/A"
                if legacy
                else [{"outcome": "failed", "error": {"code": "robots.timeout"}}]
            ),
            "usage": {
                "requests": None if legacy else 1,
                "target_bytes": None if legacy else 0,
                "tool_attempts": "N/A" if legacy else 1,
                "bytes_basis": "N/A" if legacy else "aggregate_gateway",
                "within_budget": True,
            },
            "error": (
                {"error_code": "robots.timeout"}
                if legacy
                else [{"code": "robots.timeout"}]
            ),
        }
    )
    return record


def test_old_and_new_failure_records_emit_complete_blocker_without_type_error() -> None:
    case = {
        "case_id": "monitor",
        "request_digest": "digest",
        "requested_url": "https://example.test/",
        "minimum_words": 1,
        "minimum_document_links": 1,
    }
    target = {"historical_expectation": "dev_fixture"}

    evidence, failures = CASE_EVIDENCE(
        case,
        target,
        _failure_record(legacy=True),
        _failure_record(legacy=False),
    )

    assert evidence["old_threshold"]["minimum_words"]["observed"] == 0
    assert evidence["new_threshold"]["minimum_document_links"]["observed"] == 0
    assert evidence["old"]["error"]["error_code"] == "robots.timeout"
    assert evidence["new"]["error"][0]["code"] == "robots.timeout"
    assert evidence["difference"]["classification"] == "blocker"
    assert failures == [
        "monitor:old_threshold",
        "monitor:new_threshold",
        "monitor:semantic_difference",
    ]


def test_release_run_contract_rejects_selector_summary_and_requires_three_sites() -> (
    None
):
    contract = LIVE["_release_run_contract"]
    diagnostic = contract(
        "soa",
        {
            "site_keys": ["soa"],
            "passed": 1,
            "skipped": 2,
            "xfailed": 0,
        },
    )

    assert diagnostic["mode"] == "single-site-diagnostic"
    assert diagnostic["selected_site_keys"] == ["soa"]
    assert diagnostic["required_summary"] == {
        "site_keys": ["soa", "cas", "iaa"],
        "passed": 3,
        "skipped": 0,
        "xfailed": 0,
    }
    assert diagnostic["final_release_evidence"] is False
    assert diagnostic["unselected_site_outcome"] == "failure"

    final = contract(
        "",
        {
            "site_keys": ["soa", "cas", "iaa"],
            "passed": 3,
            "skipped": 0,
            "xfailed": 0,
            "warnings": 1,
        },
    )
    assert final["mode"] == "final-release"
    assert final["selected_site_keys"] == ["soa", "cas", "iaa"]
    assert final["final_release_evidence"] is True

    incomplete = contract(
        "",
        {
            "site_keys": ["soa", "cas", "iaa"],
            "passed": 2,
            "skipped": 1,
            "xfailed": 0,
        },
    )
    assert incomplete["final_release_evidence"] is False


def _semantic_record() -> dict[str, object]:
    return {
        "artifact": {
            "availability": "present",
            "count": 1,
            "items": [
                {
                    "artifact_id": "artifact-1",
                    "observation_id": "observation-1",
                    "mime_type": "text/html",
                    "size_bytes": 100,
                    "sha256": "a" * 64,
                }
            ],
        },
        "manifest": {
            "availability": "present",
            "value": {
                "mime_type": "text/html",
                "size_bytes": 100,
                "sha256": "a" * 64,
                "tool_id": "acquisition.web_http",
                "tool_version": "1.0.0",
                "artifacts": [
                    {
                        "artifact_id": "artifact-1",
                        "observation_id": "observation-1",
                    }
                ],
            },
        },
        "observation": {
            "availability": "present",
            "count": 1,
            "items": [
                {
                    "observation_id": "observation-1",
                    "artifact_id": "artifact-1",
                }
            ],
        },
        "outcome": "success",
        "requested_url": "https://example.test/report",
        "final_url": "https://example.test/final",
        "status": 503,
        "mime_type": "text/html",
        "content_sha256": "a" * 64,
        "content_bytes": 100,
        "redirects": [
            {
                "from_url": "https://example.test/report",
                "to_url": "https://example.test/final",
                "status": 302,
            }
        ],
        "attempts": [
            {
                "outcome": "succeeded",
                "tool_id": "acquisition.web_http",
                "tool_version": "1.0.0",
            }
        ],
        "usage": {
            "requests": 2,
            "transport_requests": 2,
            "bytes_received": 100,
            "transport_response_bytes": 100,
            "target_bytes": 100,
            "tool_attempts": 1,
            "bytes_basis": "target_body",
            "within_budget": True,
        },
        "error": None,
    }


@pytest.mark.parametrize(
    ("dimension", "expected_field"),
    [
        ("redirects", "redirects"),
        ("attempt_count", "attempts.count"),
        ("attempt_outcome", "attempts.outcomes"),
        ("error_code", "error.codes"),
        ("usage_requests", "usage.requests_match_transport"),
        ("transport_usage_requests", "usage.requests_match_transport"),
        ("usage_bytes", "usage.target_bytes"),
        ("result_usage_bytes", "usage.bytes_received_matches_transport"),
        ("transport_usage_bytes", "usage.bytes_received_matches_transport"),
        ("usage_tool_attempts", "usage.tool_attempts"),
        ("usage_within_budget", "usage.within_budget"),
    ],
)
def test_live_semantic_dimension_drift_is_a_blocker(
    dimension: str, expected_field: str
) -> None:
    original = _semantic_record()
    changed = deepcopy(original)
    if dimension == "redirects":
        changed["redirects"][0]["status"] = 301
    elif dimension == "attempt_count":
        changed["attempts"].append({"outcome": "failed"})
    elif dimension == "attempt_outcome":
        changed["attempts"][0]["outcome"] = "completed"
    elif dimension == "error_code":
        changed["error"] = [{"code": "gateway.timeout"}]
    elif dimension == "usage_requests":
        changed["usage"]["requests"] = 3
    elif dimension == "transport_usage_requests":
        changed["usage"]["transport_requests"] = 3
    elif dimension == "usage_bytes":
        changed["usage"]["target_bytes"] = 101
    elif dimension == "result_usage_bytes":
        changed["usage"]["bytes_received"] = 101
    elif dimension == "transport_usage_bytes":
        changed["usage"]["transport_response_bytes"] = 101
    elif dimension == "usage_tool_attempts":
        changed["usage"]["tool_attempts"] = 2
    else:
        changed["usage"]["within_budget"] = False

    comparison = COMPARE(LIVE_SEMANTICS(original), LIVE_SEMANTICS(changed), {})

    assert comparison["classification"] == "blocker"
    assert expected_field in {item["field"] for item in comparison["blockers"]}


@pytest.mark.parametrize(
    ("field", "changed_value"),
    [
        ("availability", "none"),
        ("codes", ["changed.code"]),
        ("messages", ["changed message"]),
        ("retryable", [False]),
        ("details", [{"reason": "changed"}]),
        ("error_types", ["ChangedError"]),
    ],
)
def test_live_error_leaf_drift_is_a_blocker(field: str, changed_value: object) -> None:
    original = _semantic_record()
    original["outcome"] = "failure"
    original["error"] = [
        {
            "code": "robots.timeout",
            "message": "Acquisition did not complete.",
            "retryable": "N/A",
            "details": {},
            "error_type": "N/A",
        }
    ]
    changed = deepcopy(original)
    if field == "availability":
        changed["error"] = None
    else:
        child_field = "error_type" if field == "error_types" else field
        if child_field in {"codes", "messages", "retryable", "details"}:
            child_field = {
                "codes": "code",
                "messages": "message",
                "retryable": "retryable",
                "details": "details",
            }[child_field]
        changed["error"][0][child_field] = changed_value[0]

    comparison = COMPARE(LIVE_SEMANTICS(original), LIVE_SEMANTICS(changed), {})

    assert comparison["classification"] == "blocker"
    assert f"error.{field}" in {item["field"] for item in comparison["blockers"]}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("bytes_received", None),
        ("bytes_received", -1),
        ("bytes_received", True),
        ("bytes_received", 1.0),
        ("bytes_received", "100"),
        ("transport_response_bytes", None),
        ("transport_response_bytes", -1),
        ("transport_response_bytes", True),
        ("transport_response_bytes", 1.0),
        ("transport_response_bytes", "100"),
    ],
)
def test_new_result_and_transport_byte_evidence_shape_drift_is_a_blocker(
    field: str, value: object
) -> None:
    original = _semantic_record()
    changed = deepcopy(original)
    changed["usage"][field] = value

    comparison = COMPARE(LIVE_SEMANTICS(original), LIVE_SEMANTICS(changed), {})

    assert comparison["classification"] == "blocker"
    assert f"usage.{field}_exact" in {item["field"] for item in comparison["blockers"]}


@pytest.mark.parametrize("field", ["bytes_received", "transport_response_bytes"])
def test_missing_new_case_byte_evidence_is_a_blocker(field: str) -> None:
    original = _semantic_record()
    changed = deepcopy(original)
    changed["usage"].pop(field)

    comparison = COMPARE(LIVE_SEMANTICS(original), LIVE_SEMANTICS(changed), {})

    assert comparison["classification"] == "blocker"
    assert f"usage.{field}_exact" in {item["field"] for item in comparison["blockers"]}


def test_new_case_transport_bytes_reconcile_with_system_total() -> None:
    gate = LIVE["_new_usage_failures"]
    result = {
        "cases": [
            {
                "usage": {
                    "requests": 2,
                    "transport_requests": 2,
                    "bytes_received": 40,
                    "transport_response_bytes": 40,
                }
            },
            {
                "usage": {
                    "requests": 2,
                    "transport_requests": 2,
                    "bytes_received": 60,
                    "transport_response_bytes": 60,
                }
            },
        ],
        "budget": {
            "requests": 4,
            "case_request_total": 4,
            "response_bytes": 100,
            "case_response_bytes_total": 100,
        },
    }

    assert gate(result) == []
    for field, value in (
        ("case_usage", 41),
        ("declared_total", 99),
        ("transport_total", 101),
    ):
        changed = deepcopy(result)
        if field == "case_usage":
            changed["cases"][0]["usage"]["bytes_received"] = value
        elif field == "declared_total":
            changed["budget"]["case_response_bytes_total"] = value
        else:
            changed["budget"]["response_bytes"] = value
        assert gate(changed)


def test_old_and_new_case_request_counts_reconcile_with_system_total() -> None:
    old_gate = LIVE["_old_usage_failures"]
    new_gate = LIVE["_new_usage_failures"]
    old_cases = [_legacy_usage_fixture(), _legacy_usage_fixture()]
    old_response_total = sum(item.pop("_accounted_bytes") for item in old_cases)
    robots_bytes = LIVE["LEGACY_HELPERS"]["_ROBOTS_RESPONSE_BYTES_PER_CASE"]
    old = {
        "cases": [{"usage": item} for item in old_cases],
        "budget": {
            "requests": 4,
            "response_bytes": old_response_total,
            "robots_response_bytes_upper_bound": robots_bytes * 2,
        },
    }
    new = {
        "cases": [
            {
                "usage": {
                    "requests": 2,
                    "transport_requests": 2,
                    "bytes_received": 40,
                    "transport_response_bytes": 40,
                }
            },
            {
                "usage": {
                    "requests": 2,
                    "transport_requests": 2,
                    "bytes_received": 60,
                    "transport_response_bytes": 60,
                }
            },
        ],
        "budget": {
            "requests": 4,
            "case_request_total": 4,
            "response_bytes": 100,
            "case_response_bytes_total": 100,
        },
    }

    assert old_gate(old) == []
    assert new_gate(new) == []

    aggregate_drift = deepcopy(new)
    aggregate_drift["budget"]["requests"] = 5
    assert "new_system:usage_requests_reconciliation" in new_gate(aggregate_drift)

    case_drift = deepcopy(new)
    case_drift["cases"][0]["usage"]["requests"] = 3
    assert "new_system:usage_requests_consistency" in new_gate(case_drift)

    old_drift = deepcopy(old)
    old_drift["budget"]["requests"] = 5
    assert "old_system:usage_requests_reconciliation" in old_gate(old_drift)

    old_case_drift = deepcopy(old)
    old_case_drift["cases"][0]["usage"]["requests"] = 3
    assert "old_system:usage_requests_reconciliation" in old_gate(old_case_drift)


@pytest.mark.parametrize("invalid", ["missing", None, -1, True, 1.0, "2"])
@pytest.mark.parametrize(
    ("system", "field"),
    [("old", "requests"), ("new", "requests"), ("new", "transport_requests")],
)
def test_case_request_count_shape_drift_is_fail_closed(
    system: str, field: str, invalid: object
) -> None:
    gate = LIVE[f"_{system}_usage_failures"]
    result = {
        "cases": [
            {
                "usage": {
                    "requests": 2,
                    "transport_requests": 2,
                    "bytes_received": 0,
                    "transport_response_bytes": 0,
                }
            },
            {
                "usage": {
                    "requests": 2,
                    "transport_requests": 2,
                    "bytes_received": 0,
                    "transport_response_bytes": 0,
                }
            },
        ],
        "budget": {
            "requests": 4,
            "case_request_total": 4,
            "response_bytes": 0,
            "case_response_bytes_total": 0,
        },
    }
    if invalid == "missing":
        result["cases"][0]["usage"].pop(field)
    else:
        result["cases"][0]["usage"][field] = invalid

    assert f"{system}_system:usage_requests_evidence" in gate(result)


def _legacy_usage_fixture(*, failure: bool = False) -> dict[str, object]:
    robots_bytes = LIVE["LEGACY_HELPERS"]["_ROBOTS_RESPONSE_BYTES_PER_CASE"]
    upper_bound = 2 * 1024 * 1024
    return {
        "requests": 4 if failure else 2,
        "requests_upper_bound": 4,
        "response_bytes": upper_bound if failure else 100,
        "response_bytes_upper_bound": upper_bound,
        "target_bytes": 1536 * 1024 if failure else 90,
        "tool_attempts": "N/A",
        "bytes_basis": "per_case_upper_bound" if failure else "target_body",
        "within_budget": True,
        "_accounted_bytes": upper_bound if failure else 100 + robots_bytes,
    }


@pytest.mark.parametrize(
    "field",
    [
        "requests",
        "requests_upper_bound",
        "response_bytes",
        "response_bytes_upper_bound",
        "target_bytes",
        "tool_attempts",
        "bytes_basis",
        "within_budget",
    ],
)
def test_legacy_usage_normal_schema_rejects_missing_and_malformed_fields(
    field: str,
) -> None:
    validate = LIVE["LEGACY_HELPERS"]["_usage_is_complete"]
    valid = _legacy_usage_fixture()
    valid.pop("_accounted_bytes")
    assert validate(valid) is True

    missing = deepcopy(valid)
    missing.pop(field)
    assert validate(missing) is False

    malformed = deepcopy(valid)
    malformed[field] = {
        "tool_attempts": 0,
        "bytes_basis": "unexpected",
        "within_budget": "yes",
    }.get(field, True)
    assert validate(malformed) is False


def test_legacy_case_bytes_reconcile_with_system_total_and_fail_closed() -> None:
    gate = LIVE["_old_usage_failures"]
    success = _legacy_usage_fixture()
    failure = _legacy_usage_fixture(failure=True)
    accounted = success.pop("_accounted_bytes") + failure.pop("_accounted_bytes")
    robots_bytes = LIVE["LEGACY_HELPERS"]["_ROBOTS_RESPONSE_BYTES_PER_CASE"]
    result = {
        "cases": [{"usage": success}, {"usage": failure}],
        "budget": {
            "requests": 6,
            "response_bytes": accounted,
            "robots_response_bytes_upper_bound": robots_bytes * 2,
        },
    }
    assert gate(result) == []

    for field, value in (
        ("response_bytes", -1),
        ("response_bytes_upper_bound", 1.0),
        ("target_bytes", True),
        ("bytes_basis", "unexpected"),
    ):
        changed = deepcopy(result)
        changed["cases"][0]["usage"][field] = value
        assert "old_system:usage_bytes_evidence" in gate(changed)

    drift = deepcopy(result)
    drift["budget"]["response_bytes"] += 1
    assert "old_system:usage_bytes_reconciliation" in gate(drift)


@pytest.mark.parametrize(
    ("system", "canonical"),
    [
        (
            "old",
            {
                "error_code": "robots.timeout",
                "message": "access failed closed",
                "retryable": True,
                "details": "N/A",
                "error_type": "N/A",
            },
        ),
        (
            "new",
            [
                {
                    "code": "robots.timeout",
                    "message": "Acquisition did not complete.",
                    "retryable": "N/A",
                    "details": {},
                    "error_type": "N/A",
                }
            ],
        ),
    ],
)
def test_child_error_schema_rejects_each_missing_or_invalid_leaf(
    system: str, canonical: object
) -> None:
    validate = (
        LIVE["LEGACY_HELPERS"]["_error_is_complete"]
        if system == "old"
        else LIVE["NEW_HELPERS"]["_error_shape"]
    )
    assert validate(canonical) is True
    for field in ("message", "retryable", "details", "error_type"):
        missing = deepcopy(canonical)
        target = missing if system == "old" else missing[0]
        target.pop(field)
        assert validate(missing) is False
        invalid = deepcopy(canonical)
        target = invalid if system == "old" else invalid[0]
        target[field] = []
        assert validate(invalid) is False


@pytest.mark.parametrize(
    ("dimension", "expected_field"),
    [
        ("artifact_count", "artifact.count"),
        ("artifact_sha", "artifact.sha_matches_http"),
        ("artifact_size", "artifact.size_matches_http"),
        ("artifact_mime", "artifact.mime_matches_http"),
        ("observation_count", "observation.count"),
        ("observation_artifact_link", "observation.links_match_artifact"),
        ("manifest_artifact_link", "manifest.links_match_artifact"),
        ("manifest_sha", "manifest.sha_matches_http"),
        ("manifest_size", "manifest.size_matches_http"),
        ("manifest_mime", "manifest.mime_matches_http"),
        ("manifest_tool_id", "manifest.tool_id"),
        ("manifest_tool_version", "manifest.tool_version"),
        ("attempt_tool_id", "attempts.tool_ids"),
        ("attempt_tool_version", "attempts.tool_versions"),
    ],
)
def test_artifact_observation_manifest_consistency_drift_is_a_blocker(
    dimension: str, expected_field: str
) -> None:
    original = _semantic_record()
    changed = deepcopy(original)
    if dimension == "artifact_count":
        changed["artifact"]["count"] = 2
    elif dimension == "artifact_sha":
        changed["artifact"]["items"][0]["sha256"] = "b" * 64
    elif dimension == "artifact_size":
        changed["artifact"]["items"][0]["size_bytes"] = 101
    elif dimension == "artifact_mime":
        changed["artifact"]["items"][0]["mime_type"] = "application/pdf"
    elif dimension == "observation_count":
        changed["observation"]["count"] = 2
    elif dimension == "observation_artifact_link":
        changed["observation"]["items"][0]["artifact_id"] = "artifact-2"
    elif dimension == "manifest_artifact_link":
        changed["manifest"]["value"]["artifacts"][0]["artifact_id"] = "artifact-2"
    elif dimension == "manifest_sha":
        changed["manifest"]["value"]["sha256"] = "b" * 64
    elif dimension == "manifest_size":
        changed["manifest"]["value"]["size_bytes"] = 101
    elif dimension == "manifest_mime":
        changed["manifest"]["value"]["mime_type"] = "application/pdf"
    elif dimension == "manifest_tool_id":
        changed["manifest"]["value"]["tool_id"] = "acquisition.other"
    elif dimension == "manifest_tool_version":
        changed["manifest"]["value"]["tool_version"] = "2.0.0"
    elif dimension == "attempt_tool_id":
        changed["attempts"][0]["tool_id"] = "acquisition.other"
    else:
        changed["attempts"][0]["tool_version"] = "2.0.0"

    comparison = COMPARE(LIVE_SEMANTICS(original), LIVE_SEMANTICS(changed), {})

    assert comparison["classification"] == "blocker"
    assert expected_field in {item["field"] for item in comparison["blockers"]}


@pytest.mark.parametrize("system", ["old", "new"])
def test_system_time_budget_gate_rejects_overrun_missing_and_invalid_evidence(
    system: str,
) -> None:
    gate = LIVE["_live_budget_failures"]
    valid = {
        "requests": 1,
        "response_bytes": 1,
        "elapsed_seconds": 1.5,
        "max_seconds": 30,
    }

    assert gate(system, valid, _LIMITS) == []
    overrun = {**valid, "elapsed_seconds": 31}
    assert gate(system, overrun, _LIMITS) == [f"{system}_system:time_budget"]
    wrong_max = {**valid, "max_seconds": 29}
    assert gate(system, wrong_max, _LIMITS) == [f"{system}_system:time_budget"]

    missing_elapsed = dict(valid)
    missing_elapsed.pop("elapsed_seconds")
    missing_max = dict(valid)
    missing_max.pop("max_seconds")
    invalid_budgets = [missing_elapsed, missing_max]
    for value in (True, float("nan"), float("inf"), "N/A"):
        invalid_budgets.append({**valid, "elapsed_seconds": value})
        invalid_budgets.append({**valid, "max_seconds": value})
    for invalid in invalid_budgets:
        assert f"{system}_system:time_evidence" in gate(system, invalid, _LIMITS)


def test_invocation_evidence_distinguishes_both_processes_and_outer_pytest() -> None:
    old = OLD_INVOCATION("<pytest-temp>/old-9fe9ea5")
    new = NEW_INVOCATION("f" * 40)
    outer = OUTER_INVOCATION()

    assert old == {
        "kind": "subprocess",
        "command": [
            "<current-python>",
            "<issue-worktree>/tests/parity/legacy_live_probe.py",
        ],
        "cwd": "<pytest-temp>/old-9fe9ea5",
    }
    assert new == {
        "kind": "subprocess",
        "command": [
            "<current-python>",
            "<issue-worktree>/tests/parity/new_live_probe.py",
        ],
        "cwd": "<issue-worktree>",
        "revision": "f" * 40,
    }
    assert outer == {
        "kind": "outer-pytest",
        "command": [
            "python",
            "-m",
            "pytest",
            "-q",
            "-m",
            "live",
            "tests/live/test_phase_20_parity_live.py",
        ],
        "process_return_code": "recorded-by-live-test-agent",
    }


def test_old_and_new_build_independent_request_descriptors_from_call_inputs() -> None:
    from web_listening.request.model import Budgets, ContentType, Request, Scope

    new_helpers = LIVE["NEW_HELPERS"]
    limits = {
        "max_requests": 4,
        "max_bytes": 2 * 1024 * 1024,
        "max_runtime_seconds": 28,
        "max_tool_attempts_per_target": 1,
    }
    old_descriptor = LIVE["LEGACY_HELPERS"]["_request_descriptor"](
        requested_url="https://example.test/monitor",
        allowed_origins=("https://example.test",),
        request_limits=limits,
    )
    request = Request(
        Scope(
            ("https://example.test/monitor",),
            ("https://example.test",),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(4, 2 * 1024 * 1024, 28, 1),
    )
    new_descriptor = new_helpers["_request_descriptor"](request)

    assert old_descriptor == new_descriptor
    assert old_descriptor is not new_descriptor
    assert old_descriptor["scope"] is not new_descriptor["scope"]
    assert "site_skill_digest" not in json.dumps(old_descriptor, sort_keys=True)
    assert LIVE["LEGACY_HELPERS"]["_request_digest"](old_descriptor) == new_helpers[
        "_request_digest"
    ](new_descriptor)


@pytest.mark.parametrize(
    ("path", "changed"),
    [
        (("scope", "seeds"), ["https://example.test/other"]),
        (("scope", "allowed_origins"), ["https://other.test"]),
        (("scope", "include_paths"), ["/other/**"]),
        (("scope", "content_types"), ["file"]),
        (("request", "site_skill"), "present"),
        (("request", "explore_all_tools"), True),
        (("budgets", "max_requests"), 3),
        (("budgets", "max_bytes"), 1024),
        (("budgets", "max_runtime_seconds"), 27),
        (("budgets", "max_tool_attempts_per_target"), 2),
    ],
)
def test_every_request_descriptor_governance_drift_is_a_blocker(
    path: tuple[str, str], changed: object
) -> None:
    descriptor = {
        "schema_version": "phase-20-request-descriptor.v1",
        "scope": {
            "seeds": ["https://example.test/monitor"],
            "allowed_origins": ["https://example.test"],
            "include_paths": ["/**"],
            "content_types": ["html"],
        },
        "request": {"site_skill": "N/A", "explore_all_tools": False},
        "budgets": {
            "max_requests": 4,
            "max_bytes": 2 * 1024 * 1024,
            "max_runtime_seconds": 28,
            "max_tool_attempts_per_target": 1,
        },
    }
    new_descriptor = deepcopy(descriptor)
    new_descriptor[path[0]][path[1]] = changed
    old_record = _failure_record(legacy=True)
    new_record = _failure_record(legacy=True)
    for record, value, helpers in (
        (old_record, descriptor, LIVE["LEGACY_HELPERS"]),
        (new_record, new_descriptor, LIVE["NEW_HELPERS"]),
    ):
        record["request_descriptor"] = value
        record["request_digest"] = helpers["_request_digest"](value)
    case = {
        "case_id": "monitor",
        "requested_url": "https://example.test/monitor",
        "minimum_words": 1,
        "minimum_document_links": 0,
    }

    evidence, failures = CASE_EVIDENCE(
        case,
        {"historical_expectation": "dev_fixture"},
        old_record,
        new_record,
    )

    assert evidence["request_provenance"]["same_descriptor"] is False
    assert "monitor:request_descriptor" in failures


_PROCESS_FAILURES = {
    "spawn": ("legacy.process_spawn", "not-started", "N/A"),
    "timeout": ("legacy.process_timeout", "timeout", "N/A"),
    "no-output": ("legacy.no_output", "exited-without-evidence", 7),
    "parse": ("legacy.output_parse", "invalid-evidence", 7),
    "schema": ("legacy.output_schema", "invalid-evidence", 7),
}


@pytest.mark.parametrize("scenario", list(_PROCESS_FAILURES))
def test_legacy_process_failures_return_complete_case_blockers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scenario: str,
) -> None:
    error_code, process_outcome, return_code = _PROCESS_FAILURES[scenario]

    def fake_run(*_args, **_kwargs):
        if scenario == "spawn":
            raise OSError("spawn failed")
        if scenario == "timeout":
            raise subprocess.TimeoutExpired(["python"], 30)
        stdout = ""
        if scenario == "parse":
            stdout = "not-json"
        elif scenario == "schema":
            stdout = json.dumps({"cases": [], "budget": {}})
        return subprocess.CompletedProcess(["python"], 7, stdout, "")

    monkeypatch.setattr(LIVE["LEGACY_HELPERS"]["subprocess"], "run", fake_run)
    invocation = OLD_INVOCATION("<pytest-temp>/old-9fe9ea5")
    payload = {
        "old_commit": LIVE["OLD_COMMIT"],
        "environment": {"verification": "matched"},
        "governed_network_timeout_seconds": LIVE["_LEGACY_NETWORK_TIMEOUT_SECONDS"],
        "limits": _LIMITS,
        "cases": _CASES,
    }

    evidence = LIVE["_run_legacy_process"](
        ["python", "probe.py"], tmp_path, {}, payload, invocation
    )

    assert evidence["process_outcome"] == process_outcome
    assert evidence["process_return_code"] == return_code
    assert evidence["invocation"] == invocation
    assert evidence["budget"]["requests"] == _LIMITS["max_total_requests"]
    assert evidence["budget"]["response_bytes"] == _LIMITS["max_total_response_bytes"]
    assert len(evidence["cases"]) == len(_CASES)
    for case, record in zip(_CASES, evidence["cases"], strict=True):
        assert record["requested_url"] == case["requested_url"]
        assert record["usage"]["within_budget"] is True
        assert record["error"]["error_code"] == error_code
        new = _failure_record(legacy=False)
        new.update(
            {
                "case_id": case["case_id"],
                "request_digest": case["request_digest"],
                "requested_url": case["requested_url"],
            }
        )
        comparison, failures = CASE_EVIDENCE(
            case, {"historical_expectation": "dev_fixture"}, record, new
        )
        assert comparison["old_threshold"]["minimum_words"]["observed"] == 0
        assert comparison["difference"]["classification"] == "blocker"
        assert f"{case['case_id']}:semantic_difference" in failures


@pytest.mark.parametrize("scenario", list(_PROCESS_FAILURES))
def test_new_process_failures_return_complete_case_blockers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scenario: str,
) -> None:
    helpers = LIVE["NEW_HELPERS"]
    suffix, process_outcome, return_code = _PROCESS_FAILURES[scenario]
    error_code = suffix.replace("legacy.", "new.")

    def fake_run(*_args, **_kwargs):
        if scenario == "spawn":
            raise OSError("spawn failed")
        if scenario == "timeout":
            raise subprocess.TimeoutExpired(["python"], 30)
        stdout = ""
        if scenario == "parse":
            stdout = "not-json"
        elif scenario == "schema":
            stdout = json.dumps({"cases": [], "budget": {}})
        return subprocess.CompletedProcess(["python"], 7, stdout, "")

    monkeypatch.setattr(helpers["subprocess"], "run", fake_run)
    invocation = NEW_INVOCATION("f" * 40)
    payload = {
        "environment": {"revision": "f" * 40, "verification": "matched"},
        "governed_network_timeout_seconds": LIVE["_LEGACY_NETWORK_TIMEOUT_SECONDS"],
        "limits": _LIMITS,
        "cases": _CASES,
        "target": {
            "site_key": "soa",
            "allowed_origins": ["https://example.test"],
        },
    }

    evidence = helpers["_run_process"](
        ["python", "probe.py"], tmp_path, {}, payload, invocation
    )

    assert evidence["process_outcome"] == process_outcome
    assert evidence["process_return_code"] == return_code
    assert evidence["invocation"] == invocation
    assert len(evidence["cases"]) == 2
    assert evidence["budget"]["requests"] == "N/A"
    assert evidence["budget"]["case_request_total"] == "N/A"
    assert evidence["budget"]["response_bytes"] == "N/A"
    assert evidence["budget"]["case_response_bytes_total"] == "N/A"
    for record in evidence["cases"]:
        assert record["request_descriptor"] == "N/A"
        assert record["request_digest"] == "N/A"
        assert record["usage"]["requests"] == "N/A"
        assert record["usage"]["transport_requests"] == "N/A"
        assert record["usage"]["bytes_received"] == "N/A"
        assert record["usage"]["transport_response_bytes"] == "N/A"
        assert record["error"][0]["code"] == error_code


@pytest.mark.parametrize("partial", ["missing-dimensions", "bad-nested-shape"])
def test_parseable_partial_legacy_output_becomes_complete_schema_blockers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, partial: str
) -> None:
    invocation = OLD_INVOCATION("<pytest-temp>/old-9fe9ea5")
    payload = {
        "old_commit": LIVE["OLD_COMMIT"],
        "environment": {"verification": "matched"},
        "governed_network_timeout_seconds": LIVE["_LEGACY_NETWORK_TIMEOUT_SECONDS"],
        "limits": _LIMITS,
        "cases": _CASES,
    }
    child = LIVE["_legacy_failure_evidence"](
        payload,
        invocation,
        {
            "error_code": "legacy.fixture",
            "error_type": "FixtureError",
            "process_outcome": "fixture",
            "process_return_code": 7,
        },
    )
    if partial == "missing-dimensions":
        for record in child["cases"]:
            for field in ("artifact", "observation", "manifest"):
                record.pop(field)
    else:
        child["cases"][0]["artifact"] = {"availability": []}
        child["cases"][1]["usage"]["within_budget"] = "yes"

    monkeypatch.setattr(
        LIVE["LEGACY_HELPERS"]["subprocess"],
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["python"], 7, json.dumps(child), ""
        ),
    )
    evidence = LIVE["_run_legacy_process"](
        ["python", "probe.py"], tmp_path, {}, payload, invocation
    )

    assert len(evidence["cases"]) == 2
    for case, record in zip(_CASES, evidence["cases"], strict=True):
        assert record["error"]["error_code"] == "legacy.output_schema"
        new = _failure_record(legacy=False)
        new.update(
            {
                "case_id": case["case_id"],
                "request_digest": case["request_digest"],
                "requested_url": case["requested_url"],
            }
        )
        comparison, failures = CASE_EVIDENCE(
            case, {"historical_expectation": "dev_fixture"}, record, new
        )
        assert comparison["difference"]["classification"] == "blocker"
        assert f"{case['case_id']}:semantic_difference" in failures


def test_parseable_malformed_legacy_budget_becomes_complete_schema_blockers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    invocation = OLD_INVOCATION("<pytest-temp>/old-9fe9ea5")
    payload = {
        "old_commit": LIVE["OLD_COMMIT"],
        "environment": {"verification": "matched"},
        "governed_network_timeout_seconds": LIVE["_LEGACY_NETWORK_TIMEOUT_SECONDS"],
        "limits": _LIMITS,
        "cases": _CASES,
    }
    child = LIVE["_legacy_failure_evidence"](
        payload,
        invocation,
        {
            "error_code": "legacy.fixture",
            "error_type": "FixtureError",
            "process_outcome": "fixture",
            "process_return_code": 7,
        },
    )
    child["budget"] = {
        "requests": 8,
        "requests_basis": "exact fixture counts",
        "max_requests": 8,
        "response_bytes": 4 * 1024 * 1024,
        "response_bytes_basis": "exact fixture bytes",
        "robots_response_bytes_upper_bound": 1024 * 1024,
        "max_response_bytes": 4 * 1024 * 1024,
        "elapsed_seconds": 1.0,
        "max_seconds": 30,
        "governed_network_seconds": 28,
        "outer_process_max_seconds": 30,
        "concurrency": 1,
        "retry": 0,
    }
    validate = LIVE["LEGACY_HELPERS"]["_output_is_complete"]
    assert validate(child, payload) is True
    mutations = [
        *(("missing", field, None) for field in child["budget"]),
        ("wrong", "max_requests", 8.0),
        ("wrong", "max_response_bytes", 4 * 1024 * 1024 - 1),
        ("wrong", "max_seconds", 29),
        ("wrong", "outer_process_max_seconds", 29),
        ("wrong", "governed_network_seconds", 30),
        ("wrong", "concurrency", 2),
        ("wrong", "retry", 1),
        ("wrong", "requests", 9),
        ("wrong", "response_bytes", 4 * 1024 * 1024 + 1),
        ("wrong", "robots_response_bytes_upper_bound", 0),
        ("wrong", "requests_basis", ""),
        ("wrong", "response_bytes_basis", " "),
        ("extra", "unexpected", 1),
    ]
    for operation, field, value in mutations:
        malformed = deepcopy(child)
        if operation == "missing":
            malformed["budget"].pop(field)
        else:
            malformed["budget"][field] = value
        monkeypatch.setattr(
            LIVE["LEGACY_HELPERS"]["subprocess"],
            "run",
            lambda *_args, output=json.dumps(malformed), **_kwargs: (
                subprocess.CompletedProcess(["python"], 7, output, "")
            ),
        )
        evidence = LIVE["_run_legacy_process"](
            ["python", "probe.py"], tmp_path, {}, payload, invocation
        )
        assert len(evidence["cases"]) == 2
        assert all(
            record["error"]["error_code"] == "legacy.output_schema"
            for record in evidence["cases"]
        )


def test_legacy_deadline_is_strictly_inside_the_outer_process_limit() -> None:
    assert (
        0
        < LIVE["_LEGACY_NETWORK_TIMEOUT_SECONDS"]
        < (LIVE["_LEGACY_PROCESS_TIMEOUT_SECONDS"])
    )
    assert LIVE["_LEGACY_PROCESS_TIMEOUT_SECONDS"] <= _LIMITS["timeout_seconds"]


def _matching_legacy_fingerprint() -> dict[str, object]:
    expected = deepcopy(LIVE["_LEGACY_ENVIRONMENT_ALLOWLIST"])
    actual = deepcopy(expected)
    actual["python"] = {
        "implementation": "cpython",
        "major": 3,
        "minor": 12,
        "version": "3.12.13",
        "executable": "<controlled-legacy-python>",
        "executable_path_sha256": "a" * 64,
        "executable_sha256": "b" * 64,
    }
    return actual


def test_legacy_environment_accepts_complete_python_312_closure() -> None:
    actual = _matching_legacy_fingerprint()

    assert set(actual["imports"]) == {
        "annotated_types",
        "click",
        "httpx",
        "idna",
        "pydantic",
        "pydantic_core",
        "pygments",
        "typing_extensions",
        "typing_inspection",
        "yaml",
    }
    assert LIVE["_legacy_environment_matches"](actual) is True


@pytest.mark.parametrize("drift", ["pydantic-missing", "core-record", "python-311"])
def test_legacy_environment_drift_blocks_before_spawn_with_complete_cases(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, drift: str
) -> None:
    actual = _matching_legacy_fingerprint()
    if drift == "pydantic-missing":
        actual["imports"].pop("pydantic")
    elif drift == "core-record":
        actual["imports"]["pydantic_core"]["record_sha256"] = "0" * 64
    else:
        actual["python"].update({"minor": 11, "version": "3.11.9"})
    assert LIVE["_legacy_environment_matches"](actual) is False

    expected = LIVE["_LEGACY_ENVIRONMENT_ALLOWLIST"]
    run_old = LIVE["_run_old"]
    monkeypatch.setitem(
        run_old.__globals__,
        "_verify_old_http_profile_provenance",
        lambda: asdict(
            LIVE["HTTP_PROFILE_COMPATIBILITY"]["FROZEN_OLD_HTTP_PROFILE_PROVENANCE"]
        ),
    )
    monkeypatch.setitem(
        run_old.__globals__,
        "_extract_old_checkout",
        lambda _path: (tmp_path / "old-9fe9ea5", expected["source"]),
    )
    monkeypatch.setitem(
        run_old.__globals__,
        "_legacy_environment_fingerprint",
        lambda: {key: actual[key] for key in ("python", "imports")},
    )
    monkeypatch.setitem(
        run_old.__globals__,
        "_run_legacy_process",
        lambda *_args, **_kwargs: pytest.fail("legacy process must not spawn"),
    )

    evidence = run_old(
        tmp_path,
        {"allowed_origins": ["https://example.test"]},
        _CASES,
        _LIMITS,
        {
            "window_digest": "window-digest",
            "candidate_identity": _fixture_candidate_identity(tmp_path),
        },
    )

    assert evidence["environment"]["verification"] == "mismatch"
    assert evidence["process_outcome"] == "environment-mismatch"
    assert all(
        row["error"]["error_code"] == "legacy.environment_mismatch"
        for row in evidence["cases"]
    )
    assert len(evidence["cases"]) == 2
    assert ".venv" not in inspect.getsource(run_old)


def _boundary_system_result(*, legacy: bool) -> dict[str, object]:
    records = []
    for case in _CASES:
        record = _failure_record(legacy=legacy)
        record.update(
            {
                "case_id": case["case_id"],
                "request_digest": case["request_digest"],
                "requested_url": case["requested_url"],
            }
        )
        records.append(record)
    result = {
        "environment": {"verification": "fixture"},
        "cases": records,
        "budget": {
            "requests": 8,
            "max_requests": 8,
            "response_bytes": 4 * 1024 * 1024,
            "max_response_bytes": 4 * 1024 * 1024,
            "elapsed_seconds": 1,
            "max_seconds": 30,
        },
        "invocation": OLD_INVOCATION("<pytest-temp>/old-9fe9ea5"),
    }
    if legacy:
        result.update({"process_outcome": "exited-failure", "process_return_code": 1})
    else:
        result["invocation"] = NEW_INVOCATION("f" * 40)
        result.update({"process_outcome": "exited-failure", "process_return_code": 1})
    return result


@pytest.mark.parametrize(
    ("boundary", "error_code"),
    [
        ("old", "phase20.old_boundary"),
        ("new", "phase20.new_boundary"),
    ],
)
def test_system_boundary_exception_produces_two_complete_blocker_cases(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boundary: str,
    error_code: str,
) -> None:
    evaluate = LIVE["_evaluate_live_boundaries"]

    def raise_boundary(*_args, **_kwargs):
        raise RuntimeError("offline boundary failure")

    monkeypatch.setitem(
        evaluate.__globals__,
        "_run_old",
        (
            raise_boundary
            if boundary == "old"
            else lambda *_args: _boundary_system_result(legacy=True)
        ),
    )
    monkeypatch.setitem(
        evaluate.__globals__,
        "_run_new",
        (
            raise_boundary
            if boundary == "new"
            else lambda *_args: _boundary_system_result(legacy=False)
        ),
    )
    evidence = {"cases": [], "classification": "blocker"}
    candidate_identity = _fixture_candidate_identity(tmp_path)

    result = evaluate(
        evidence,
        tmp_path,
        {
            "site_key": "soa",
            "allowed_origins": ["https://example.test"],
            "historical_expectation": "dev_fixture",
        },
        _CASES,
        {
            "limits": _LIMITS,
            "window_digest": "window-digest",
            "candidate_identity": candidate_identity,
        },
    )

    assert result is evidence
    assert result["classification"] == "blocker"
    assert len(result["cases"]) == 2
    assert result["release_gate_failures"]
    for case in result["cases"]:
        failed_record = case[boundary]
        expected_error = (
            failed_record["error"]["error_code"]
            if boundary == "old"
            else failed_record["error"][0]["code"]
        )
        assert expected_error == error_code
        if boundary == "new":
            assert failed_record["request_descriptor"] == "N/A"
            assert failed_record["request_digest"] == "N/A"
            assert failed_record["usage"] == {
                "requests": "N/A",
                "transport_requests": "N/A",
                "bytes_received": "N/A",
                "transport_response_bytes": "N/A",
                "target_bytes": "N/A",
                "tool_attempts": "N/A",
                "bytes_basis": "N/A: child did not provide evidence",
                "within_budget": False,
            }
        assert case[f"{boundary}_threshold"]["met"] is False
        assert case["difference"]["classification"] == "blocker"
    if boundary == "new":
        assert result["new_budget"]["requests"] == "N/A"
        assert result["new_budget"]["case_request_total"] == "N/A"
        assert result["new_budget"]["response_bytes"] == "N/A"
        assert result["new_budget"]["case_response_bytes_total"] == "N/A"
        assert result["new_invocation"] == NEW_INVOCATION(
            _CANDIDATE_HEAD_REVISION, result["new_candidate_identity"]
        )
        assert result["new_environment"]["revision"] == _CANDIDATE_HEAD_REVISION
        assert result["new_environment"]["verification"] == "boundary-failure"
        assert result["new_process_outcome"] == "boundary-failure"
        assert result["new_process_return_code"] == "N/A"
    assert f"{boundary}_system:time_evidence" in result["release_gate_failures"]
    assert f"{boundary}_system:failure" in result["release_gate_failures"]


def test_new_runtime_without_result_uses_complete_exception_boundary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    helpers = LIVE["NEW_HELPERS"]
    execute = helpers["_execute"]
    replacements = {
        "_NetworkBudget": lambda _limits, _seconds: SimpleNamespace(
            max_response_bytes=4 * 1024 * 1024,
            response_bytes=0,
            max_requests=8,
            requests=0,
            remaining_seconds=30,
            started=0,
        ),
        "Registry": lambda: SimpleNamespace(register=lambda *_args: None),
        "WebHttpAcquisitionTool": lambda _factory: SimpleNamespace(close=lambda: None),
        "ArtifactStore": lambda _path: SimpleNamespace(close=lambda: None),
        "JobRepository": object,
        "RuntimeService": lambda *_args, **_kwargs: SimpleNamespace(
            run=lambda _request: SimpleNamespace(result=None)
        ),
        "_request_descriptor": lambda _request: {},
        "_request_digest": lambda _descriptor: "digest",
    }
    for name, replacement in replacements.items():
        monkeypatch.setitem(execute.__globals__, name, replacement)
    payload = {
        "environment": {"revision": "f" * 40, "verification": "matched"},
        "governed_network_timeout_seconds": 28,
        "limits": _LIMITS,
        "cases": _CASES,
        "target": {"site_key": "soa", "allowed_origins": ["https://example.test"]},
        "artifact_root": str(tmp_path / "new-artifacts"),
    }

    with pytest.raises(RuntimeError, match="no Result"):
        execute(payload)
    monkeypatch.setattr(
        helpers["subprocess"],
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["python"], 1, "", "RuntimeError"
        ),
    )
    evidence = helpers["_run_process"](
        ["python", "probe.py"],
        tmp_path,
        {},
        payload,
        NEW_INVOCATION("f" * 40),
    )

    assert evidence["process_outcome"] == "exited-without-evidence"
    assert evidence["process_return_code"] == 1
    assert len(evidence["cases"]) == 2
    for case, record in zip(_CASES, evidence["cases"], strict=True):
        assert record["error"][0]["code"] == "new.no_output"
        old = _failure_record(legacy=True)
        old.update(
            {
                "case_id": case["case_id"],
                "request_digest": case["request_digest"],
                "requested_url": case["requested_url"],
            }
        )
        comparison, failures = CASE_EVIDENCE(
            case, {"historical_expectation": "dev_fixture"}, old, record
        )
        assert comparison["difference"]["classification"] == "blocker"
        assert f"{case['case_id']}:semantic_difference" in failures


def test_aggregate_time_budget_emits_complete_per_case_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    helpers = LIVE["NEW_HELPERS"]
    execute = helpers["_execute"]
    budget = SimpleNamespace(
        max_response_bytes=4 * 1024 * 1024,
        response_bytes=0,
        max_requests=8,
        requests=0,
        remaining_seconds=0,
        started=helpers["time"].monotonic(),
    )
    replacements = {
        "_NetworkBudget": lambda _limits, _seconds: budget,
        "Registry": lambda: SimpleNamespace(register=lambda *_args: None),
        "WebHttpAcquisitionTool": lambda _factory: SimpleNamespace(close=lambda: None),
        "ArtifactStore": lambda _path: SimpleNamespace(close=lambda: None),
        "JobRepository": object,
        "RuntimeService": lambda *_args, **_kwargs: SimpleNamespace(),
    }
    for name, replacement in replacements.items():
        monkeypatch.setitem(execute.__globals__, name, replacement)
    payload = {
        "environment": {"revision": "f" * 40, "verification": "matched"},
        "governed_network_timeout_seconds": 28,
        "limits": _LIMITS,
        "cases": _CASES,
        "target": {"site_key": "soa", "allowed_origins": ["https://example.test"]},
        "artifact_root": str(tmp_path / "new-artifacts"),
    }

    evidence = execute(payload)

    expected_error = [
        {
            "code": "phase20.aggregate_budget",
            "message": "Aggregate time budget was exhausted before this case.",
            "retryable": False,
            "details": {},
            "error_type": "N/A",
        }
    ]
    assert [record["error"] for record in evidence["cases"]] == [
        expected_error,
        expected_error,
    ]
    assert helpers["_output_is_complete"](evidence, payload) is True


@pytest.mark.parametrize("system", ["old", "new"])
def test_malformed_system_counts_keep_two_comparisons_and_add_evidence_blocker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, system: str
) -> None:
    evaluate = LIVE["_evaluate_live_boundaries"]
    candidate_identity = _fixture_candidate_identity(tmp_path)
    missing = object()
    invalid_values = (missing, None, "1", 1.0, float("nan"), float("inf"), -1, True)
    for field in ("requests", "response_bytes"):
        for invalid in invalid_values:
            old = _boundary_system_result(legacy=True)
            new = _boundary_system_result(legacy=False)
            malformed = old if system == "old" else new
            if invalid is missing:
                malformed["budget"].pop(field)
            else:
                malformed["budget"][field] = invalid
            monkeypatch.setitem(
                evaluate.__globals__, "_run_old", lambda *_args, value=old: value
            )
            monkeypatch.setitem(
                evaluate.__globals__, "_run_new", lambda *_args, value=new: value
            )

            evidence = evaluate(
                {"cases": [], "classification": "blocker"},
                tmp_path,
                {
                    "site_key": "soa",
                    "allowed_origins": ["https://example.test"],
                    "historical_expectation": "dev_fixture",
                },
                _CASES,
                {
                    "limits": _LIMITS,
                    "window_digest": "window-digest",
                    "candidate_identity": candidate_identity,
                },
            )

            assert len(evidence["cases"]) == 2
            assert evidence["classification"] == "blocker"
            assert (
                f"{system}_system:count_evidence" in evidence["release_gate_failures"]
            )


def _candidate_fixture(tmp_path: Path) -> tuple[Path, list[str]]:
    required = list(LIVE["_REQUIRED_CANDIDATE_PATHS"])
    for index, relative in enumerate(required):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"candidate-{index}\n".encode("utf-8"))
    return tmp_path, required


def _fixture_candidate_identity(
    tmp_path: Path, head_revision: str = _CANDIDATE_HEAD_REVISION
) -> dict[str, object]:
    root, candidates = _candidate_fixture(tmp_path / "candidate-identity")
    return LIVE["_candidate_identity_from_paths"](
        root,
        candidates,
        LIVE["BASE_REVISION"],
        head_revision,
        LIVE["CANDIDATE_BRANCH"],
    )


def test_candidate_identity_changes_for_every_required_candidate_byte(
    tmp_path: Path,
) -> None:
    root, candidates = _candidate_fixture(tmp_path)
    build = LIVE["_candidate_identity_from_paths"]
    baseline = build(
        root,
        candidates,
        LIVE["BASE_REVISION"],
        _CANDIDATE_HEAD_REVISION,
        LIVE["CANDIDATE_BRANCH"],
    )

    assert baseline["candidate_paths"] == sorted(candidates)
    assert set(candidates) == {
        "README.md",
        "docs/parity-report.md",
        "docs/release-checklist.md",
        "tests/live/phase_20_site_targets.json",
        "tests/live/test_phase_20_parity_live.py",
        "tests/parity/fixtures/legacy/access-rejection-error-v1.sample.json",
        "tests/parity/fixtures/legacy/capture-result-v1.sample.json",
        "tests/parity/fixtures/phase_20_offline_corpus.json",
        "tests/parity/legacy_live_probe.py",
        "tests/parity/new_live_probe.py",
        "tests/parity/phase_20_runner.py",
        "tests/parity/test_phase_20_live_evidence.py",
        "tests/parity/test_phase_20_parity.py",
    }
    for relative in candidates:
        path = root / relative
        original = path.read_bytes()
        path.write_bytes(original + b"drift")
        changed = build(
            root,
            candidates,
            LIVE["BASE_REVISION"],
            _CANDIDATE_HEAD_REVISION,
            LIVE["CANDIDATE_BRANCH"],
        )
        assert changed["aggregate_sha256"] != baseline["aggregate_sha256"]
        path.write_bytes(original)


def test_candidate_identity_rejects_scope_missing_unreadable_and_nonregular(
    tmp_path: Path,
) -> None:
    root, candidates = _candidate_fixture(tmp_path)
    build = LIVE["_candidate_identity_from_paths"]

    outside = root / "src" / "unexpected.py"
    outside.parent.mkdir(parents=True)
    outside.write_text("unexpected", encoding="utf-8")
    with pytest.raises(ValueError, match="whitelist"):
        build(
            root,
            [*candidates, "src/unexpected.py"],
            LIVE["BASE_REVISION"],
            _CANDIDATE_HEAD_REVISION,
            LIVE["CANDIDATE_BRANCH"],
        )
    allowed_extra = root / "tests" / "parity" / "extra.py"
    allowed_extra.write_text("extra", encoding="utf-8")
    with pytest.raises(ValueError, match="path set"):
        build(
            root,
            [*candidates, "tests/parity/extra.py"],
            LIVE["BASE_REVISION"],
            _CANDIDATE_HEAD_REVISION,
            LIVE["CANDIDATE_BRANCH"],
        )
    with pytest.raises(ValueError, match="required"):
        build(
            root,
            candidates[1:],
            LIVE["BASE_REVISION"],
            _CANDIDATE_HEAD_REVISION,
            LIVE["CANDIDATE_BRANCH"],
        )
    with pytest.raises(ValueError, match="read"):
        build(
            root,
            candidates,
            LIVE["BASE_REVISION"],
            _CANDIDATE_HEAD_REVISION,
            LIVE["CANDIDATE_BRANCH"],
            reader=lambda _path: (_ for _ in ()).throw(OSError("unreadable")),
        )
    nonregular = root / candidates[0]
    nonregular.unlink()
    nonregular.mkdir()
    with pytest.raises(ValueError, match="regular"):
        build(
            root,
            candidates,
            LIVE["BASE_REVISION"],
            _CANDIDATE_HEAD_REVISION,
            LIVE["CANDIDATE_BRANCH"],
        )


def test_candidate_identity_binds_each_probe_and_fail_closes_every_drift(
    tmp_path: Path,
) -> None:
    root, candidates = _candidate_fixture(tmp_path)
    identity = LIVE["_candidate_identity_from_paths"](
        root,
        candidates,
        LIVE["BASE_REVISION"],
        _CANDIDATE_HEAD_REVISION,
        LIVE["CANDIDATE_BRANCH"],
    )
    old_binding = LIVE["_candidate_binding"](
        identity, "tests/parity/legacy_live_probe.py"
    )
    new_binding = LIVE["_candidate_binding"](identity, "tests/parity/new_live_probe.py")
    old = {
        "candidate_identity": old_binding,
        "environment": {"candidate_identity": old_binding},
        "invocation": OLD_INVOCATION("<pytest-temp>/old-9fe9ea5", old_binding),
    }
    new = {
        "candidate_identity": new_binding,
        "environment": {"candidate_identity": new_binding},
        "invocation": NEW_INVOCATION(_CANDIDATE_HEAD_REVISION, new_binding),
    }

    assert (
        old_binding["probe_sha256"]
        == identity["files"][old_binding["probe_path"]]["raw_sha256"]
    )
    assert (
        new_binding["probe_sha256"]
        == identity["files"][new_binding["probe_path"]]["raw_sha256"]
    )
    assert (
        LIVE["_candidate_identity_failures"](identity, deepcopy(identity), old, new)
        == []
    )
    for field, changed_value in (
        ("base_revision", "0" * 40),
        ("head_revision", "0" * 40),
        ("branch", "other-branch"),
        ("candidate_paths", identity["candidate_paths"][:-1]),
    ):
        changed = deepcopy(identity)
        changed[field] = changed_value
        assert LIVE["_candidate_identity_failures"](identity, changed, old, new) == [
            "candidate_identity:drift"
        ]
    for leaf, changed_value in (("raw_sha256", "0" * 64), ("size_bytes", 999)):
        changed = deepcopy(identity)
        changed["files"]["tests/parity/phase_20_runner.py"][leaf] = changed_value
        assert LIVE["_candidate_identity_failures"](identity, changed, old, new) == [
            "candidate_identity:drift"
        ]
    changed_old = deepcopy(old)
    changed_old["invocation"]["candidate_identity"]["probe_sha256"] = "0" * 64
    assert LIVE["_candidate_identity_failures"](
        identity, identity, changed_old, new
    ) == ["candidate_identity:drift"]
    head_drift = LIVE["_candidate_identity_from_paths"](
        root,
        candidates,
        LIVE["BASE_REVISION"],
        "e" * 40,
        LIVE["CANDIDATE_BRANCH"],
    )
    assert LIVE["_candidate_identity_failures"](identity, head_drift, old, new) == [
        "candidate_identity:drift"
    ]


def test_candidate_identity_is_recomputed_after_both_system_boundaries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, candidates = _candidate_fixture(tmp_path / "candidate")
    build = LIVE["_candidate_identity_from_paths"]
    bind = LIVE["_candidate_binding"]
    before = build(
        root,
        candidates,
        LIVE["BASE_REVISION"],
        _CANDIDATE_HEAD_REVISION,
        LIVE["CANDIDATE_BRANCH"],
    )
    runner = root / "tests" / "parity" / "phase_20_runner.py"
    runner.write_bytes(runner.read_bytes() + b"post-child-drift")
    after = build(
        root,
        candidates,
        LIVE["BASE_REVISION"],
        _CANDIDATE_HEAD_REVISION,
        LIVE["CANDIDATE_BRANCH"],
    )

    def bound_result(*, legacy: bool) -> dict[str, object]:
        result = _boundary_system_result(legacy=legacy)
        probe = (
            "tests/parity/legacy_live_probe.py"
            if legacy
            else "tests/parity/new_live_probe.py"
        )
        binding = bind(before, probe)
        result["candidate_identity"] = binding
        result["environment"]["candidate_identity"] = binding
        result["invocation"] = (
            OLD_INVOCATION("<pytest-temp>/old-9fe9ea5", binding)
            if legacy
            else NEW_INVOCATION(_CANDIDATE_HEAD_REVISION, binding)
        )
        return result

    evaluate = LIVE["_evaluate_live_boundaries"]
    monkeypatch.setitem(
        evaluate.__globals__, "_run_old", lambda *_args: bound_result(legacy=True)
    )
    monkeypatch.setitem(
        evaluate.__globals__, "_run_new", lambda *_args: bound_result(legacy=False)
    )
    monkeypatch.setitem(evaluate.__globals__, "_candidate_identity", lambda: after)
    evidence = evaluate(
        {"cases": [], "classification": "blocker"},
        tmp_path,
        {
            "site_key": "soa",
            "allowed_origins": ["https://example.test"],
            "historical_expectation": "dev_fixture",
        },
        _CASES,
        {
            "limits": _LIMITS,
            "window_digest": "window-digest",
            "candidate_identity": before,
        },
    )

    assert evidence["candidate_identity"]["frozen"] == before
    assert evidence["candidate_identity"]["observed_after"] == after
    assert evidence["candidate_identity"]["verification"] == "drift"
    assert "candidate_identity:drift" in evidence["release_gate_failures"]


def _mock_candidate_git(
    monkeypatch: pytest.MonkeyPatch,
    extra_untracked: tuple[str, ...] = (),
    **changes: object,
) -> tuple[object, list[tuple[str, ...]]]:
    identity = LIVE["_candidate_identity"]
    required = tuple(LIVE["_REQUIRED_CANDIDATE_PATHS"])
    integrated = changes.get(
        "integrated", tuple(path for path in required if path != "README.md")
    )
    head = str(changes.get("head", "1" * 40))
    branch = str(changes.get("branch", LIVE["CANDIDATE_BRANCH"]))
    calls: list[tuple[str, ...]] = []

    def encode(paths: object) -> bytes:
        if not isinstance(paths, tuple):
            raise AssertionError("mock Git paths must be a tuple")
        return ("\0".join(paths) + ("\0" if paths else "")).encode("utf-8")

    ancestry_call = (
        "merge-base",
        "--is-ancestor",
        LIVE["BASE_REVISION"],
        head,
    )
    responses = {
        ("rev-parse", "HEAD"): f"{head}\n".encode("ascii"),
        ("branch", "--show-current"): f"{branch}\n".encode("utf-8"),
        ancestry_call: b"",
        (
            "diff",
            "--name-only",
            "--diff-filter=A",
            "-z",
            LIVE["BASE_REVISION"],
            head,
            "--",
        ): encode(integrated),
        (
            "diff",
            "--name-only",
            "--diff-filter=CDMRTUXB",
            "-z",
            LIVE["BASE_REVISION"],
            head,
            "--",
        ): encode(changes.get("integrated_forbidden", ())),
        (
            "diff",
            "--name-only",
            "--diff-filter=M",
            "-z",
            head,
            "--",
        ): encode(changes.get("overlay", ("README.md",))),
        (
            "diff",
            "--name-only",
            "--diff-filter=ACDRTUXB",
            "-z",
            head,
            "--",
        ): encode(changes.get("overlay_forbidden", ())),
        ("ls-files", "--others", "--exclude-standard", "-z"): encode(extra_untracked),
    }

    def output(*arguments: str) -> bytes:
        calls.append(arguments)
        if arguments == ancestry_call and changes.get("ancestor") is False:
            raise subprocess.CalledProcessError(1, arguments)
        try:
            return responses[arguments]
        except KeyError as exc:
            raise AssertionError(arguments) from exc

    monkeypatch.setitem(identity.__globals__, "_git_output", output)
    return identity, calls


def test_candidate_identity_accepts_integrated_prerequisite_and_readme_overlay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity, calls = _mock_candidate_git(monkeypatch)
    required = tuple(LIVE["_REQUIRED_CANDIDATE_PATHS"])

    candidate = identity()

    assert candidate["schema_version"] == "phase-20-candidate-identity.v2"
    assert candidate["base_revision"] == LIVE["BASE_REVISION"]
    assert candidate["head_revision"] == "1" * 40
    assert candidate["branch"] == LIVE["CANDIDATE_BRANCH"]
    assert candidate["candidate_paths"] == sorted(required)
    assert (
        "merge-base",
        "--is-ancestor",
        LIVE["BASE_REVISION"],
        "1" * 40,
    ) in calls


def test_run_new_uses_candidate_head_in_environment_invocation_and_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    current_head = "2" * 40
    candidate = _fixture_candidate_identity(tmp_path, current_head)
    captured: dict[str, object] = {}

    def run_process(command, cwd, environment, payload, invocation):
        captured.update(
            command=command,
            cwd=cwd,
            environment=environment,
            payload=payload,
            invocation=invocation,
        )
        return {}

    run_new = LIVE["_run_new"]
    monkeypatch.setitem(run_new.__globals__, "_run_new_process", run_process)

    result = run_new(
        tmp_path,
        {"site_key": "soa", "allowed_origins": ["https://example.test"]},
        _CASES,
        _LIMITS,
        {"window_digest": "window-digest", "candidate_identity": candidate},
    )

    binding = result["candidate_identity"]
    assert binding["head_revision"] == current_head
    assert captured["payload"]["environment"]["revision"] == current_head
    assert captured["invocation"] == NEW_INVOCATION(current_head, binding)


def test_candidate_identity_rejects_premerge_untracked_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    required = tuple(LIVE["_REQUIRED_CANDIDATE_PATHS"])
    integrated = tuple(path for path in required if path != "README.md")
    identity, _calls = _mock_candidate_git(
        monkeypatch,
        integrated,
        head=LIVE["BASE_REVISION"],
        integrated=(),
    )

    with pytest.raises(ValueError, match="integrated"):
        identity()


@pytest.mark.parametrize(
    "case",
    [
        "integrated_missing",
        "integrated_extra",
        "integrated_forbidden",
        "overlay_missing",
        "overlay_extra",
        "overlay_forbidden",
        "untracked_extra",
        "base_ancestry",
        "branch",
    ],
)
def test_candidate_identity_rejects_every_integrated_or_overlay_drift(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    required = tuple(LIVE["_REQUIRED_CANDIDATE_PATHS"])
    integrated = tuple(path for path in required if path != "README.md")
    arguments: dict[str, object] = {}
    if case == "integrated_missing":
        arguments["integrated"] = integrated[:-1]
    elif case == "integrated_extra":
        arguments["integrated"] = (*integrated, "tests/parity/extra.py")
    elif case == "integrated_forbidden":
        arguments["integrated_forbidden"] = ("README.md",)
    elif case == "overlay_missing":
        arguments["overlay"] = ()
    elif case == "overlay_extra":
        arguments["overlay"] = ("README.md", "docs/parity-report.md")
    elif case == "overlay_forbidden":
        arguments["overlay_forbidden"] = ("README.md",)
    elif case == "untracked_extra":
        arguments["extra_untracked"] = ("tests/parity/extra.py",)
    elif case == "base_ancestry":
        arguments["ancestor"] = False
    elif case == "branch":
        arguments["branch"] = "other-branch"

    identity, _calls = _mock_candidate_git(monkeypatch, **arguments)

    with pytest.raises(ValueError, match="candidate identity"):
        identity()


@pytest.mark.parametrize(
    "unexpected",
    [
        "src/unexpected.pyc",
        ".pytest_cache/unexpected.txt",
        "foo.egg-info/PKG-INFO",
    ],
)
def test_git_returned_cache_named_path_is_not_filtered_and_blocks(
    monkeypatch: pytest.MonkeyPatch, unexpected: str
) -> None:
    identity, _calls = _mock_candidate_git(monkeypatch, (unexpected,))

    with pytest.raises(ValueError, match="whitelist"):
        identity()


def test_git_exclude_standard_is_the_only_untracked_ignore_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity_function, calls = _mock_candidate_git(monkeypatch)
    identity = identity_function()

    assert identity["schema_version"] == "phase-20-candidate-identity.v2"
    assert identity["base_revision"] == LIVE["BASE_REVISION"]
    assert identity["head_revision"] == "1" * 40
    assert identity["branch"] == LIVE["CANDIDATE_BRANCH"]
    assert identity["candidate_paths"] == sorted(LIVE["_REQUIRED_CANDIDATE_PATHS"])
    assert len(identity["aggregate_sha256"]) == 64
    assert ("ls-files", "--others", "--exclude-standard", "-z") in calls
    assert "_candidate_cache_path" not in inspect.getsource(identity_function)


def _profile_descriptor_dict(descriptor: object) -> dict[str, object]:
    value = asdict(descriptor)
    value["fields"] = [list(item) for item in value["fields"]]
    return value


def _legacy_child_round_trip(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    child_failure: bool,
) -> dict[str, object]:
    legacy = LIVE["LEGACY_HELPERS"]
    compatibility = LIVE["HTTP_PROFILE_COMPATIBILITY"]
    fingerprint = {
        "python": {"implementation": "cpython", "major": 3, "minor": 12},
        "imports": {},
    }
    payload = {
        "old_commit": LIVE["OLD_COMMIT"],
        "environment": {"fingerprint": fingerprint, "verification": "matched"},
        "governed_network_timeout_seconds": LIVE["_LEGACY_NETWORK_TIMEOUT_SECONDS"],
        "limits": _LIMITS,
        "cases": _CASES,
        "allowed_origins": ["https://example.test"],
        "authority_sha256": "a" * 64,
        "http_profile": {
            "provenance": asdict(compatibility["FROZEN_OLD_HTTP_PROFILE_PROVENANCE"]),
            "identity": dict(compatibility["FROZEN_OLD_GATEWAY_IDENTITY"]),
        },
    }

    class AccessRejectedError(Exception):
        """Offline child access failure."""

    class GovernedReadGateway:
        """Minimal governed-read seam that exercises the real probe main."""

        def __init__(self, gateway: object, *, max_body_bytes: int) -> None:
            self.gateway = gateway
            self.max_body_bytes = max_body_bytes

        def read(self, url: str, *, max_body_bytes: int) -> object:
            del max_body_bytes
            identity = self.gateway.config.identity
            self.gateway.transport.request(
                url,
                user_agent=identity.user_agent,
                identity_sha256=identity.identity_sha256,
            )
            if child_failure:
                raise AccessRejectedError("offline child failure")
            body = b"<html><body>offline profile evidence</body></html>"
            return SimpleNamespace(
                access_decision=SimpleNamespace(redirect_hops=[]),
                wire_bytes=len(body),
                body=body,
                final_url=url,
                status_code=200,
                content_type="text/html",
                sha256="b" * 64,
            )

        def close(self) -> None:
            return None

    fake_modules = {
        "web_listening.blocks.access_gateway": SimpleNamespace(
            AccessGateway=lambda config, *, transport: SimpleNamespace(
                config=config, transport=transport
            ),
            AccessGatewayConfig=SimpleNamespace,
        ),
        "web_listening.blocks.governed_read": SimpleNamespace(
            ROLLBACK_REQUIRED_READ_ERRORS=(RuntimeError,),
            AccessRejectedError=AccessRejectedError,
            GovernedReadGateway=GovernedReadGateway,
            access_rejection_payload=lambda _exc: {
                "error_code": "offline.denied",
                "error_type": "AccessRejectedError",
            },
            governed_read_failure_payload=lambda _exc: {
                "error_code": "offline.failure",
                "error_type": "RuntimeError",
            },
        ),
        "web_listening.blocks.site_diagnostic": SimpleNamespace(
            SafePinnedTransport=lambda **_kwargs: SimpleNamespace(
                request=lambda url, **_request_kwargs: {"url": url}
            ),
            normalize_http_url=lambda url: (url, "https://example.test"),
        ),
        "web_listening.contracts.site_diagnostic": SimpleNamespace(
            DiagnosticIdentity=SimpleNamespace,
        ),
    }
    for name, value in fake_modules.items():
        monkeypatch.setitem(sys.modules, name, value)
    monkeypatch.setitem(
        legacy["main"].__globals__, "_environment_fingerprint", lambda: fingerprint
    )
    monkeypatch.setattr(legacy["sys"], "stdin", StringIO(json.dumps(payload)))

    if child_failure:
        with pytest.raises(SystemExit, match="1"):
            legacy["main"]()
    else:
        legacy["main"]()
    child_stdout = capsys.readouterr().out
    child_return_code = 1 if child_failure else 0
    monkeypatch.setattr(
        legacy["subprocess"],
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["python", "legacy_live_probe.py"],
            child_return_code,
            child_stdout,
            "",
        ),
    )
    return legacy["_run_process"](
        ["python", "legacy_live_probe.py"],
        ROOT,
        {},
        payload,
        OLD_INVOCATION("<pytest-temp>/old-9fe9ea5"),
    )


def _fixed_new_profile_result() -> dict[str, object]:
    compatibility = LIVE["HTTP_PROFILE_COMPATIBILITY"]
    descriptor = _profile_descriptor_dict(
        compatibility["describe_http_profile"](
            LIVE["NEW_HELPERS"]["WEB_HTTP_REQUEST_PROFILE"]
        )
    )
    profile = LIVE["_http_profile_system_evidence"](
        _CASES,
        provenance="N/A",
        identity="N/A",
        authority=deepcopy(descriptor),
        observations=[[deepcopy(descriptor)], [deepcopy(descriptor)]],
    )
    return {
        "http_profile": profile,
        "cases": [{"usage": {"transport_requests": 1}} for _case in _CASES],
    }


@pytest.mark.parametrize("child_failure", [False, True], ids=["success", "failure"])
def test_legacy_child_json_round_trip_preserves_strict_profile_evidence(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    child_failure: bool,
) -> None:
    compatibility = LIVE["HTTP_PROFILE_COMPATIBILITY"]
    old = _legacy_child_round_trip(monkeypatch, capsys, child_failure=child_failure)

    rows, blockers = LIVE["_http_profile_compatibility_gate"](
        old, _fixed_new_profile_result(), _CASES
    )

    assert tuple(old["http_profile"]["provenance"]) == tuple(
        compatibility["OldHttpProfileProvenance"].__dataclass_fields__
    )
    assert tuple(old["http_profile"]["identity"]) == tuple(
        compatibility["FROZEN_OLD_GATEWAY_IDENTITY"]
    )
    assert blockers == []
    assert {row["kind"] for row in rows} == {"explained_fixed_difference"}
    assert {row["code"] for row in rows} == {"profile.fixed_old_accept_encoding"}


def test_legacy_child_identity_order_survives_after_provenance_is_restored(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    compatibility = LIVE["HTTP_PROFILE_COMPATIBILITY"]
    old = _legacy_child_round_trip(monkeypatch, capsys, child_failure=False)
    old["http_profile"]["provenance"] = asdict(
        compatibility["FROZEN_OLD_HTTP_PROFILE_PROVENANCE"]
    )

    rows, blockers = LIVE["_http_profile_compatibility_gate"](
        old, _fixed_new_profile_result(), _CASES
    )

    assert {row["code"] for row in rows} == {"profile.fixed_old_accept_encoding"}
    assert blockers == []


@pytest.mark.parametrize(
    ("mapping_name", "expected_code"),
    [
        ("provenance", "profile.old_provenance_mismatch"),
        ("identity", "profile.old_identity_recipe_mismatch"),
    ],
)
@pytest.mark.parametrize("drift", ["missing", "extra", "order", "value", "digest"])
def test_legacy_child_profile_mapping_drift_remains_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mapping_name: str,
    expected_code: str,
    drift: str,
) -> None:
    old = _legacy_child_round_trip(monkeypatch, capsys, child_failure=False)
    mapping = old["http_profile"][mapping_name]
    if drift == "missing":
        mapping.pop(next(iter(mapping)))
    elif drift == "extra":
        mapping["unexpected"] = "drift"
    elif drift == "order":
        old["http_profile"][mapping_name] = dict(reversed(tuple(mapping.items())))
    elif drift == "value":
        mapping["repository" if mapping_name == "provenance" else "user_agent"] = (
            "drift"
        )
    else:
        mapping[
            "transport_blob_sha" if mapping_name == "provenance" else "identity_sha256"
        ] = "0" * (40 if mapping_name == "provenance" else 64)

    rows, blockers = LIVE["_http_profile_compatibility_gate"](
        old, _fixed_new_profile_result(), _CASES
    )

    assert blockers == ["monitor:http_profile", "document:http_profile"]
    assert {row["kind"] for row in rows} == {"blocker"}
    assert {row["code"] for row in rows} == {expected_code}


def _drift_profile_descriptor(descriptor: dict[str, object], drift: str) -> None:
    if drift == "missing":
        descriptor.pop("fields")
    elif drift == "extra":
        descriptor["unexpected"] = "drift"
    elif drift == "order":
        descriptor["fields"] = list(reversed(descriptor["fields"]))
    elif drift == "value":
        descriptor["fields"][0][1] = "drift"
    else:
        descriptor["sha256"] = "0" * 64


@pytest.mark.parametrize("system", ["old", "new"])
@pytest.mark.parametrize("target", ["authority", "profile"])
@pytest.mark.parametrize("drift", ["missing", "extra", "order", "value", "digest"])
def test_profile_authority_and_descriptor_drift_remain_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    system: str,
    target: str,
    drift: str,
) -> None:
    old = _legacy_child_round_trip(monkeypatch, capsys, child_failure=False)
    new = _fixed_new_profile_result()
    profile = (old if system == "old" else new)["http_profile"]
    descriptors = [profile["authority"]]
    if target == "profile":
        for row in profile["cases"]:
            descriptors.extend(row["observations"])
            descriptors.append(row["collapsed"])
    seen: set[int] = set()
    for descriptor in descriptors:
        if id(descriptor) not in seen:
            seen.add(id(descriptor))
            _drift_profile_descriptor(descriptor, drift)

    rows, blockers = LIVE["_http_profile_compatibility_gate"](old, new, _CASES)

    assert blockers == ["monitor:http_profile", "document:http_profile"]
    assert {row["kind"] for row in rows} == {"blocker"}
    if target == "profile":
        suffix = "sha256_drift" if drift == "digest" else "fields_drift"
        assert {row["code"] for row in rows} == {f"profile.{system}_{suffix}"}


def test_legacy_setup_failure_keeps_strict_profile_shape_before_child_spawn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_old = LIVE["_run_old"]
    monkeypatch.setitem(
        run_old.__globals__,
        "_verify_old_http_profile_provenance",
        lambda: (_ for _ in ()).throw(OSError("offline provenance setup")),
    )
    monkeypatch.setitem(
        run_old.__globals__,
        "_run_legacy_process",
        lambda *_args, **_kwargs: pytest.fail("legacy child must not start"),
    )

    evidence = run_old(
        tmp_path,
        {"allowed_origins": ["https://example.test"]},
        _CASES,
        _LIMITS,
        {
            "window_digest": "window-digest",
            "candidate_identity": _fixture_candidate_identity(tmp_path),
        },
    )

    assert evidence["environment"]["verification"] == "setup-failure"
    assert evidence["process_outcome"] == "not-started"
    assert evidence["process_return_code"] == "N/A"
    assert evidence["http_profile"] == LIVE["LEGACY_HELPERS"][
        "_empty_http_profile_evidence"
    ](_CASES)
    assert [record["error"]["error_code"] for record in evidence["cases"]] == [
        "legacy.setup_failure",
        "legacy.setup_failure",
    ]
    rows, blockers = LIVE["_http_profile_compatibility_gate"](
        evidence, _fixed_new_profile_result(), _CASES
    )
    assert blockers == ["monitor:http_profile", "document:http_profile"]
    assert {row["kind"] for row in rows} == {"blocker"}
    assert {row["code"] for row in rows} == {"profile.old_provenance_mismatch"}


def test_legacy_spawn_and_boundary_failures_keep_strict_profile_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = LIVE["LEGACY_HELPERS"]
    invocation = OLD_INVOCATION("<pytest-temp>/old-9fe9ea5")
    payload = {
        "old_commit": LIVE["OLD_COMMIT"],
        "environment": {"verification": "matched"},
        "governed_network_timeout_seconds": LIVE["_LEGACY_NETWORK_TIMEOUT_SECONDS"],
        "limits": _LIMITS,
        "cases": _CASES,
    }
    monkeypatch.setattr(
        legacy["subprocess"],
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline spawn")),
    )
    spawn = legacy["_run_process"](
        ["python", "legacy_live_probe.py"], ROOT, {}, payload, invocation
    )
    context = {
        "system": "old",
        "old_commit": payload["old_commit"],
        "environment": payload["environment"],
        "governed_network_timeout_seconds": payload["governed_network_timeout_seconds"],
        "limits": payload["limits"],
        "cases": payload["cases"],
        "invocation": invocation,
    }
    boundary = legacy["_call_boundary"](
        lambda: (_ for _ in ()).throw(RuntimeError("offline boundary")), context
    )

    assert set(spawn) == set(boundary)
    assert (
        spawn["http_profile"]
        == boundary["http_profile"]
        == legacy["_empty_http_profile_evidence"](_CASES)
    )
    for failure in (spawn, boundary):
        rows, blockers = LIVE["_http_profile_compatibility_gate"](
            failure, _fixed_new_profile_result(), _CASES
        )
        assert blockers == ["monitor:http_profile", "document:http_profile"]
        assert {row["kind"] for row in rows} == {"blocker"}
        assert {row["code"] for row in rows} == {"profile.old_provenance_mismatch"}


def test_prerequisite_sync_base_and_fixed_old_profile_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compatibility = LIVE["HTTP_PROFILE_COMPATIBILITY"]
    legacy_main = inspect.getsource(LIVE["LEGACY_HELPERS"]["main"])
    frozen = compatibility["FROZEN_OLD_HTTP_PROFILE_PROVENANCE"]
    expected_refs = {
        frozen.commit_sha: frozen.commit_sha,
        **{
            f"{frozen.commit_sha}:{getattr(frozen, path_field)}": getattr(
                frozen, blob_field
            )
            for path_field, blob_field in (
                ("identity_contract_path", "identity_contract_blob_sha"),
                ("transport_path", "transport_blob_sha"),
                ("gateway_path", "gateway_blob_sha"),
                ("caller_path", "caller_blob_sha"),
            )
        },
    }
    observed_refs = []

    def fixed_git_object(command, **_kwargs):
        reference = command[-1]
        observed_refs.append(reference)
        return subprocess.CompletedProcess(
            command, 0, f"{expected_refs[reference]}\n", ""
        )

    verify = LIVE["_verify_old_http_profile_provenance"]
    monkeypatch.setattr(verify.__globals__["subprocess"], "run", fixed_git_object)

    assert LIVE["BASE_REVISION"] == "9450cb5968b3a24be50284a502c5adba696b20e6"
    assert verify() == asdict(frozen)
    assert observed_refs == list(expected_refs)
    assert dict(compatibility["FROZEN_OLD_GATEWAY_IDENTITY"]) == {
        "identity_id": "web-listening-runtime-v2",
        "product_token": "web-listening",
        "user_agent": "web-listening/0.1",
        "identity_sha256": (
            "de7b07e47b4bb10246395f550e81ce66dabc9680747bbf8cb881109a194e70a5"
        ),
    }
    assert "build_runtime_read_gateway" not in legacy_main
    for constructor in (
        "DiagnosticIdentity",
        "AccessGatewayConfig",
        "AccessGateway",
        "SafePinnedTransport",
        "GovernedReadGateway",
    ):
        assert constructor in legacy_main


def test_fixed_old_profile_provenance_fails_closed_when_git_object_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verify = LIVE["_verify_old_http_profile_provenance"]

    def missing_object(command, **_kwargs):
        raise subprocess.CalledProcessError(128, command)

    monkeypatch.setattr(verify.__globals__["subprocess"], "run", missing_object)

    with pytest.raises(subprocess.CalledProcessError):
        verify()


def test_profile_failure_evidence_is_same_shaped_and_explicitly_unobserved() -> None:
    old = LIVE["LEGACY_HELPERS"]["_empty_http_profile_evidence"](_CASES)
    new = LIVE["NEW_HELPERS"]["_empty_http_profile_evidence"](_CASES)

    assert (
        set(old)
        == set(new)
        == {
            "schema_version",
            "provenance",
            "identity",
            "authority",
            "cases",
        }
    )
    assert old == new
    assert [row["case_id"] for row in old["cases"]] == [
        "monitor",
        "document",
    ]
    assert all(
        row["request_count"] == 0
        and row["observations"] == []
        and row["collapsed"] == "N/A"
        for row in old["cases"]
    )


def test_profile_observers_bind_each_real_transport_call_to_its_authority() -> None:
    compatibility = LIVE["HTTP_PROFILE_COMPATIBILITY"]
    legacy = LIVE["LEGACY_HELPERS"]
    current = LIVE["NEW_HELPERS"]

    class OldTransport:
        """Minimal offline legacy transport delegate."""

        def request(self, url: str, **kwargs: object) -> object:
            return {"url": url, **kwargs}

    old_observations: list[dict[str, object]] = []
    old_transport = legacy["_ProfileEvidenceTransport"](
        OldTransport(),
        old_observations,
        compatibility["FROZEN_OLD_GATEWAY_IDENTITY"],
    )
    old_identity = compatibility["FROZEN_OLD_GATEWAY_IDENTITY"]
    old_transport.request(
        "https://example.test/",
        user_agent=old_identity["user_agent"],
        identity_sha256=old_identity["identity_sha256"],
    )
    assert old_observations == [
        _profile_descriptor_dict(
            compatibility["describe_http_profile"](
                compatibility["FROZEN_OLD_HTTP_REQUEST_PROFILE"]
            )
        )
    ]

    class NewTransport:
        """Minimal offline current transport delegate."""

        def send(self, url: str, **kwargs: object) -> object:
            return SimpleNamespace(
                url=url,
                status=200,
                headers={},
                peer_ip="203.0.113.1",
                **kwargs,
            )

        def close(self) -> None:
            return None

    budget = SimpleNamespace(
        max_requests=8,
        requests=0,
        remaining_seconds=28,
    )
    new_observations: list[dict[str, object]] = []
    new_transport = current["_CappedTransport"](
        budget, new_observations, transport=NewTransport()
    )
    new_transport.send("https://example.test/", timeout=28, addresses=("203.0.113.1",))
    assert (
        current["WEB_HTTP_REQUEST_PROFILE"]
        is current["in_process_runner"].WEB_HTTP_REQUEST_PROFILE
    )
    assert new_observations == [
        _profile_descriptor_dict(
            compatibility["describe_http_profile"](current["WEB_HTTP_REQUEST_PROFILE"])
        )
    ]


def test_profile_gate_accepts_only_the_fixed_pair_and_blocks_every_drift() -> None:
    compatibility = LIVE["HTTP_PROFILE_COMPATIBILITY"]
    build = LIVE["_http_profile_system_evidence"]
    classify = LIVE["_http_profile_compatibility_gate"]
    old_descriptor = _profile_descriptor_dict(
        compatibility["describe_http_profile"](
            compatibility["FROZEN_OLD_HTTP_REQUEST_PROFILE"]
        )
    )
    new_descriptor = _profile_descriptor_dict(
        compatibility["describe_http_profile"](
            LIVE["NEW_HELPERS"]["WEB_HTTP_REQUEST_PROFILE"]
        )
    )
    old = build(
        _CASES,
        provenance=asdict(compatibility["FROZEN_OLD_HTTP_PROFILE_PROVENANCE"]),
        identity=dict(compatibility["FROZEN_OLD_GATEWAY_IDENTITY"]),
        authority=deepcopy(old_descriptor),
        observations=[[deepcopy(old_descriptor)], [deepcopy(old_descriptor)]],
    )
    new = build(
        _CASES,
        provenance="N/A",
        identity="N/A",
        authority=deepcopy(new_descriptor),
        observations=[[deepcopy(new_descriptor)], [deepcopy(new_descriptor)]],
    )
    old_result = {
        "http_profile": old,
        "cases": [{"outcome": "success", "usage": {"requests": 1}} for _case in _CASES],
    }
    new_result = {
        "http_profile": new,
        "cases": [{"usage": {"transport_requests": 1}} for _case in _CASES],
    }

    accepted, failures = classify(old_result, new_result, _CASES)
    assert failures == []
    assert {row["kind"] for row in accepted} == {"explained_fixed_difference"}
    assert {row["code"] for row in accepted} == {"profile.fixed_old_accept_encoding"}

    for system, field in (
        (old, "provenance"),
        (old, "identity"),
        (old, "authority"),
        (new, "authority"),
    ):
        changed_old, changed_new = deepcopy(old), deepcopy(new)
        changed = changed_old if system is old else changed_new
        changed[field] = "drift"
        rows, blockers = classify(
            {**old_result, "http_profile": changed_old},
            {**new_result, "http_profile": changed_new},
            _CASES,
        )
        assert blockers
        assert {row["kind"] for row in rows} == {"blocker"}

    changed_new = deepcopy(new)
    changed_new["cases"][0]["observations"][0]["fields"][0][1] = "gzip"
    _rows, blockers = classify(
        old_result, {**new_result, "http_profile": changed_new}, _CASES
    )
    assert blockers == ["monitor:http_profile"]


def test_profile_blocker_prevents_content_comparison_but_keeps_two_cases(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evaluate = LIVE["_evaluate_live_boundaries"]
    old = _boundary_system_result(legacy=True)
    new = _boundary_system_result(legacy=False)
    old["http_profile"] = LIVE["_empty_http_profile_evidence"](_CASES)
    new["http_profile"] = LIVE["_empty_http_profile_evidence"](_CASES)
    monkeypatch.setitem(evaluate.__globals__, "_run_old", lambda *_args: old)
    monkeypatch.setitem(evaluate.__globals__, "_run_new", lambda *_args: new)
    monkeypatch.setitem(
        evaluate.__globals__,
        "_case_evidence",
        lambda *_args: (_ for _ in ()).throw(AssertionError("content compared")),
    )
    candidate_identity = _fixture_candidate_identity(tmp_path)

    evidence = evaluate(
        {"cases": [], "classification": "blocker"},
        tmp_path,
        {
            "site_key": "soa",
            "allowed_origins": ["https://example.test"],
            "historical_expectation": "dev_fixture",
        },
        _CASES,
        {
            "limits": _LIMITS,
            "window_digest": "window-digest",
            "candidate_identity": candidate_identity,
        },
    )

    assert len(evidence["cases"]) == 2
    assert all(
        item["difference"]["classification"] == "blocker" for item in evidence["cases"]
    )
    assert {item["case_id"] for item in evidence["http_profile_compatibility"]} == {
        "monitor",
        "document",
    }
