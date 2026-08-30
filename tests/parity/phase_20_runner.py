"""Small, offline-only Phase 20 semantic parity runner."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REQUIRED_DIMENSIONS = {
    "artifact",
    "attempt",
    "content",
    "contract",
    "error",
    "http",
    "manifest",
    "observation",
    "outcome",
    "tool_id",
    "usage",
}
_PHASE_20_SITE_KEYS = ("soa", "cas", "iaa")


def release_run_contract(
    selector: str, summary: dict[str, object] | None = None
) -> dict[str, object]:
    """Classify a diagnostic selection or exact final three-site summary."""
    selector = selector.strip()
    if selector and selector not in _PHASE_20_SITE_KEYS:
        raise ValueError("WEB_LISTENING_LIVE_SITE must be soa, cas, or iaa")
    required_summary = {
        "site_keys": list(_PHASE_20_SITE_KEYS),
        "passed": len(_PHASE_20_SITE_KEYS),
        "skipped": 0,
        "xfailed": 0,
    }
    summary_matches = summary is not None and all(
        summary.get(field) == expected for field, expected in required_summary.items()
    )
    diagnostic = bool(selector)
    if diagnostic:
        final_release_evidence: bool | None = False
    elif summary is None:
        final_release_evidence = None
    else:
        final_release_evidence = summary_matches
    return {
        "mode": "single-site-diagnostic" if diagnostic else "final-release",
        "selected_site_keys": ([selector] if diagnostic else list(_PHASE_20_SITE_KEYS)),
        "required_summary": required_summary,
        "summary_evaluated": summary is not None,
        "final_release_evidence": final_release_evidence,
        "unselected_site_outcome": "failure" if diagnostic else "not-applicable",
    }


def _finite_real(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _nonnegative_exact_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def live_budget_failures(
    system: str, budget: Mapping[str, Any], limits: Mapping[str, Any]
) -> list[str]:
    """Fail closed on aggregate counts and the frozen thirty-second time gate."""
    failures = []
    requests = budget.get("requests")
    response_bytes = budget.get("response_bytes")
    if not all(_nonnegative_exact_int(value) for value in (requests, response_bytes)):
        failures.append(f"{system}_system:count_evidence")
    else:
        if requests > int(limits["max_total_requests"]):
            failures.append(f"{system}_system:request_budget")
        if response_bytes > int(limits["max_total_response_bytes"]):
            failures.append(f"{system}_system:response_budget")
    elapsed = budget.get("elapsed_seconds")
    maximum = budget.get("max_seconds")
    if not _finite_real(elapsed) or not _finite_real(maximum):
        failures.append(f"{system}_system:time_evidence")
        return failures
    frozen_maximum = int(limits["timeout_seconds"])
    invalid_range = elapsed < 0 or maximum <= 0 or elapsed > maximum
    invalid_maximum = maximum != frozen_maximum or frozen_maximum != 30 or maximum > 30
    if invalid_range or invalid_maximum:
        failures.append(f"{system}_system:time_budget")
    return failures


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, Mapping):
        flattened: dict[str, Any] = {}
        for key in sorted(value):
            path = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(_flatten(value[key], path))
        return flattened
    return {prefix: value}


def _read_legacy_fixture(
    case: Mapping[str, Any], fixture_root: Path
) -> tuple[dict[str, Any], Mapping[str, Any]]:
    metadata = case.get("legacy_fixture")
    if not isinstance(metadata, Mapping):
        raise ValueError("offline case legacy fixture metadata is missing")
    snapshot_path = metadata.get("snapshot_path")
    expected_sha = metadata.get("sha256_lf")
    if not isinstance(snapshot_path, str) or not isinstance(expected_sha, str):
        raise ValueError("offline legacy fixture path or digest is invalid")
    raw = (fixture_root / snapshot_path).read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError("offline legacy fixture digest drifted")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("offline legacy fixture payload is invalid")
    return payload, metadata


def _normalize_field(
    field: str, value: Any, normalized_fields: Mapping[str, Any]
) -> Any:
    rule = normalized_fields.get(field)
    if not isinstance(rule, Mapping):
        raise ValueError(f"offline normalization rule for {field} is missing")
    return rule.get(value, value)


def project_legacy_case(
    case: Mapping[str, Any],
    fixture_root: Path,
    normalized_fields: Mapping[str, Any],
) -> dict[str, Any]:
    """Rebuild one old observation only from a frozen 9fe9ea5 fixture snapshot."""
    payload, metadata = _read_legacy_fixture(case, fixture_root)
    kind = metadata.get("projection_kind")
    if kind == "capture-result.v1":
        content = payload["content"]
        text = content["text"]
        if payload.get("schema_version") != kind or payload.get("error") is not None:
            raise ValueError("legacy capture fixture does not evidence success")
        expected_input = {"url": payload["final_url"], "body": text}
        projection = {
            "artifact": {
                "availability": "N/A",
                "count": "N/A",
                "mime_types": "N/A",
                "sha256": "N/A",
                "size_bytes": "N/A",
            },
            "attempt": {
                "availability": "N/A",
                "count": "N/A",
                "tool_ids": "N/A",
                "tool_versions": "N/A",
            },
            "content": {
                "availability": "present",
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "word_count": content["metadata"]["word_count"],
            },
            "contract": payload["schema_version"],
            "error": {
                "availability": "none",
                "codes": [],
                "count": 0,
                "details": [],
                "error_types": [],
                "messages": [],
                "retryable": [],
            },
            "http": {
                "final_url": payload["final_url"],
                "mime_type": content["media_type"],
                "requested_url": "N/A",
                "status": payload["status_code"],
            },
            "manifest": {
                "artifact_count": "N/A",
                "availability": "N/A",
                "content_matches_observation": "N/A",
                "links_match_artifact": "N/A",
                "mime_type": "N/A",
                "sha256": "N/A",
                "size_bytes": "N/A",
                "tool_id": "N/A",
                "tool_version": "N/A",
            },
            "observation": {
                "availability": "N/A",
                "content_matches_artifact": "N/A",
                "count": "N/A",
                "links_match_artifact": "N/A",
                "stored_content_sha256": "N/A",
                "stored_content_size_bytes": "N/A",
            },
            "outcome": "success" if payload["state"] == "succeeded" else "failure",
            "tool_id": _normalize_field(
                "tool_id", payload["executor_id"], normalized_fields
            ),
            "usage": {
                "bytes_received": "N/A",
                "requests": "N/A",
                "tool_attempts": "N/A",
            },
        }
    elif kind == "access-rejection-error.v1":
        origin = payload["evidence"]["canonical_origin"]
        default_port = 443 if origin["scheme"] == "https" else 80
        port = (
            ""
            if origin["effective_port"] == default_port
            else f":{origin['effective_port']}"
        )
        expected_input = {"url": f"{origin['scheme']}://{origin['host']}{port}/"}
        if payload.get("schema_version") != kind or payload.get("outcome") != "error":
            raise ValueError("legacy rejection fixture does not evidence failure")
        projection = {
            "artifact": {
                "availability": "N/A",
                "count": "N/A",
                "mime_types": "N/A",
                "sha256": "N/A",
                "size_bytes": "N/A",
            },
            "attempt": {
                "availability": "N/A",
                "count": "N/A",
                "tool_ids": "N/A",
                "tool_versions": "N/A",
            },
            "content": {
                "availability": "N/A",
                "sha256": "N/A",
                "word_count": "N/A",
            },
            "contract": payload["schema_version"],
            "error": {
                "availability": "present",
                "codes": [payload["reason_code"]],
                "count": 1,
                "details": ["N/A"],
                "error_types": ["N/A"],
                "messages": [payload["message"]],
                "retryable": [payload["retryable"]],
            },
            "http": {
                "final_url": "N/A",
                "mime_type": "N/A",
                "requested_url": expected_input["url"],
                "status": "N/A",
            },
            "manifest": {
                "artifact_count": "N/A",
                "availability": "N/A",
                "content_matches_observation": "N/A",
                "links_match_artifact": "N/A",
                "mime_type": "N/A",
                "sha256": "N/A",
                "size_bytes": "N/A",
                "tool_id": "N/A",
                "tool_version": "N/A",
            },
            "observation": {
                "availability": "N/A",
                "content_matches_artifact": "N/A",
                "count": "N/A",
                "links_match_artifact": "N/A",
                "stored_content_sha256": "N/A",
                "stored_content_size_bytes": "N/A",
            },
            "outcome": "failure",
            "tool_id": "N/A",
            "usage": {
                "bytes_received": "N/A",
                "requests": "N/A",
                "tool_attempts": "N/A",
            },
        }
    else:
        raise ValueError("offline legacy projection kind is invalid")
    if case.get("input") != expected_input:
        raise ValueError("offline case input is not derived from its legacy fixture")
    field_sources = metadata.get("field_sources")
    if not isinstance(field_sources, Mapping) or set(field_sources) != set(
        _flatten(projection)
    ):
        raise ValueError("offline legacy projection field sources are incomplete")
    if not all(
        isinstance(value, str) and value.strip() for value in field_sources.values()
    ):
        raise ValueError("offline legacy projection field source is invalid")
    return projection


def _normalization_rules(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    policy = payload.get("normalization_policy")
    if not isinstance(policy, dict) or set(policy) != {
        "ignored_fields",
        "normalized_fields",
    }:
        raise ValueError("offline normalization policy is not frozen")
    normalized_fields = policy["normalized_fields"]
    if not isinstance(normalized_fields, Mapping) or set(normalized_fields) != {
        "tool_id"
    }:
        raise ValueError("offline normalized fields drifted")
    return normalized_fields


def load_corpus(path: Path) -> dict[str, Any]:
    """Load the frozen, self-contained corpus and reject structural drift."""
    payload = json.loads(path.read_bytes())
    if payload.get("schema_version") != "phase-20-offline-parity.v1":
        raise ValueError("offline corpus schema drifted")
    commit = payload.get("old_commit")
    if not isinstance(commit, str) or _GIT_SHA.fullmatch(commit) is None:
        raise ValueError("offline corpus old commit is invalid")
    normalized_fields = _normalization_rules(payload)
    cases = payload.get("cases")
    if not isinstance(cases, list) or len(cases) < 2:
        raise ValueError("offline corpus requires success and failure cases")
    sources = payload.get("sources")
    if not isinstance(sources, list) or len(sources) != 2:
        raise ValueError("offline corpus fixed legacy sources are invalid")
    source_index = {
        item.get("path"): (item.get("snapshot_path"), item.get("sha256_lf"))
        for item in sources
        if isinstance(item, dict)
    }
    if len(source_index) != len(sources):
        raise ValueError("offline corpus fixed legacy sources are invalid")
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("offline corpus case is invalid")
        metadata = case.get("legacy_fixture")
        if not isinstance(metadata, dict) or source_index.get(
            metadata.get("source_path")
        ) != (
            metadata.get("snapshot_path"),
            metadata.get("sha256_lf"),
        ):
            raise ValueError("offline case source is not in the fixed source index")
        observed = case.get("old_observed")
        if not isinstance(observed, dict) or set(observed) != _REQUIRED_DIMENSIONS:
            raise ValueError("offline case dimensions drifted")
        if project_legacy_case(case, path.parent, normalized_fields) != observed:
            raise ValueError("offline old observation is not its fixture projection")
        accepted = case.get("accepted_differences")
        if not isinstance(accepted, dict):
            raise ValueError("accepted differences must be frozen per case")
    return payload


def normalize_result(
    result: Any,
    *,
    persistence: Mapping[str, Any],
    normalized_fields: Mapping[str, Any],
) -> dict[str, Any]:
    """Project the current Result onto observable cross-system semantics."""
    artifacts = list(result.artifacts)
    attempts = list(result.attempts)
    manifest = result.manifest
    completed = result.status.value == "completed"
    stored = persistence.get("observations")
    if not isinstance(stored, list) or not all(
        isinstance(item, dict) for item in stored
    ):
        raise ValueError("Result normalization requires persisted Observation evidence")
    if completed and len(stored) != 1:
        raise ValueError(
            "completed Result normalization requires one stored Observation"
        )
    stored_content = stored[0]["content"] if completed else None
    if completed and not isinstance(stored_content, bytes):
        raise ValueError("persisted Observation content must be bytes")
    artifact_pairs = sorted(
        (item.artifact_id, item.observation_id) for item in artifacts
    )
    stored_digests = [
        hashlib.sha256(item["content"]).hexdigest()
        for item in stored
        if isinstance(item.get("content"), bytes)
    ]
    stored_sizes = [
        len(item["content"])
        for item in stored
        if isinstance(item.get("content"), bytes)
    ]
    artifact_by_pair = {
        (item.artifact_id, item.observation_id): item for item in artifacts
    }
    stored_match = all(
        pair in artifact_by_pair
        and hashlib.sha256(item["content"]).hexdigest()
        == item.get("blob_sha256")
        == artifact_by_pair[pair].sha256
        and len(item["content"])
        == item.get("size_bytes")
        == artifact_by_pair[pair].size_bytes
        and item.get("mime_type") == artifact_by_pair[pair].mime_type
        for item in stored
        if isinstance(item.get("content"), bytes)
        for pair in [(item.get("artifact_id"), item.get("observation_id"))]
    ) and len(stored_digests) == len(stored)
    manifest_matches_stored: bool | str = "N/A"
    if completed:
        manifest_matches_stored = (
            manifest.sha256 == stored_digests[0]
            and manifest.size_bytes == stored_sizes[0]
            and manifest.mime_type == stored[0].get("mime_type")
        )
    return {
        "artifact": {
            "availability": "present" if artifacts else "none",
            "count": len(artifacts),
            "mime_types": [item.mime_type for item in artifacts],
            "sha256": [item.sha256 for item in artifacts],
            "size_bytes": [item.size_bytes for item in artifacts],
        },
        "attempt": {
            "availability": "present" if attempts else "none",
            "count": len(attempts),
            "tool_ids": [item.tool_id for item in attempts],
            "tool_versions": [item.tool_version for item in attempts],
        },
        "content": {
            "availability": "present" if completed else "N/A",
            "sha256": stored_digests[0] if completed else "N/A",
            "word_count": (
                len(
                    re.findall(r"\w+", stored_content.decode("utf-8", errors="replace"))
                )
                if completed
                else "N/A"
            ),
        },
        "contract": result.schema_version,
        "error": {
            "availability": "present" if result.errors else "none",
            "codes": [item.code for item in result.errors],
            "count": len(result.errors),
            "details": [dict(item.details) for item in result.errors],
            "error_types": ["N/A" for item in result.errors],
            "messages": [item.message for item in result.errors],
            "retryable": [getattr(item, "retryable", "N/A") for item in result.errors],
        },
        "http": {
            "final_url": manifest.final_url,
            "mime_type": manifest.mime_type,
            "requested_url": manifest.requested_url,
            "status": manifest.http_status,
        },
        "manifest": {
            "artifact_count": len(manifest.artifacts),
            "availability": "present",
            "content_matches_observation": manifest_matches_stored,
            "links_match_artifact": sorted(
                (item.artifact_id, item.observation_id) for item in manifest.artifacts
            )
            == artifact_pairs,
            "mime_type": manifest.mime_type,
            "sha256": manifest.sha256,
            "size_bytes": manifest.size_bytes,
            "tool_id": manifest.tool_id,
            "tool_version": manifest.tool_version,
        },
        "observation": {
            "availability": "present" if stored else "none",
            "content_matches_artifact": stored_match,
            "count": len(stored),
            "links_match_artifact": sorted(
                (item.get("artifact_id"), item.get("observation_id")) for item in stored
            )
            == artifact_pairs,
            "stored_content_sha256": stored_digests,
            "stored_content_size_bytes": stored_sizes,
        },
        "outcome": "success" if completed else "failure",
        "tool_id": _normalize_field(
            "tool_id",
            result.attempts[0].tool_id if result.attempts else "N/A",
            normalized_fields,
        ),
        "usage": {
            "bytes_received": result.usage.bytes_received,
            "requests": result.usage.requests,
            "tool_attempts": result.usage.tool_attempts,
        },
    }


def compare_semantics(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    accepted_differences: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify every semantic difference; unmatched differences block release."""
    old_fields = _flatten(old)
    new_fields = _flatten(new)
    accepted: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for field in sorted(set(old_fields) | set(new_fields)):
        old_value = old_fields.get(field)
        new_value = new_fields.get(field)
        if old_value == new_value:
            continue
        rule = accepted_differences.get(field)
        if (
            isinstance(rule, Mapping)
            and rule.get("old") == old_value
            and rule.get("new") == new_value
            and isinstance(rule.get("reason"), str)
            and rule["reason"].strip()
        ):
            accepted.append(
                {
                    "field": field,
                    "old": old_value,
                    "new": new_value,
                    "reason": rule["reason"],
                }
            )
        else:
            blockers.append(
                {
                    "field": field,
                    "old": old_value,
                    "new": new_value,
                    "reason": "unexplained semantic difference",
                }
            )
    classification = "blocker" if blockers else ("accepted" if accepted else "pass")
    return {
        "classification": classification,
        "accepted": accepted,
        "blockers": blockers,
    }


def run_nonproduction_rollback_drill(scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Exercise release selection and rollback as a pure non-production simulation."""
    releases = scenario["releases"]
    old = releases["old"]
    new = releases["new"]
    gates = {"contract": new["contract"], "health": new["health"]}
    recommendation = "go" if set(gates.values()) == {"pass"} else "no-go"
    if recommendation != "go":
        raise ValueError("new release failed the pre-switch gate")
    post_switch_health = scenario["new_post_switch_health"]
    rollback_release = "old" if post_switch_health != "pass" else None
    rollback_health = old["health"] if rollback_release else None
    evidence_retained = bool(scenario["retain_evidence"])
    result = (
        "rollback-pass"
        if rollback_release == "old" and rollback_health == "pass" and evidence_retained
        else "rollback-fail"
    )
    return {
        "environment": "non-production-simulation",
        "selected_release": "new",
        "switch_recommendation": recommendation,
        "pre_switch_gates": gates,
        "post_switch_health": post_switch_health,
        "rollback_release": rollback_release,
        "rollback_health": rollback_health,
        "evidence_retained": evidence_retained,
        "production_mutation": False,
        "result": result,
    }
