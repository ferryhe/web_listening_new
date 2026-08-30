"""Fixed old/new Phase 20 live parity; explicitly authorized and offline by default."""

# pylint: disable=broad-exception-caught,duplicate-code,missing-function-docstring
# pylint: disable=too-many-arguments,too-many-locals
# pylint: disable=protected-access,too-few-public-methods,too-many-lines
# pylint: disable=too-many-boolean-expressions

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import runpy
import subprocess
import sys
import tarfile
from dataclasses import asdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TARGETS = Path(__file__).with_name("phase_20_site_targets.json")
CATALOG = Path(__file__).parent / "catalog" / "dev_test_sites.json"
BASE_REVISION = "9450cb5968b3a24be50284a502c5adba696b20e6"
CANDIDATE_BRANCH = "codex/issue-21-phase20-parity"
OLD_REPOSITORY = ROOT.parent / "web_listening"
OLD_COMMIT = "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5"
LEGACY_PROBE = ROOT / "tests" / "parity" / "legacy_live_probe.py"
NEW_PROBE = ROOT / "tests" / "parity" / "new_live_probe.py"
HTTP_PROFILE_COMPATIBILITY = runpy.run_path(
    str(ROOT / "tests" / "parity" / "http_profile_compatibility.py")
)
PARITY = runpy.run_path(str(ROOT / "tests" / "parity" / "phase_20_runner.py"))
LEGACY_HELPERS = runpy.run_path(str(LEGACY_PROBE))
NEW_HELPERS = runpy.run_path(str(NEW_PROBE))
COMPARE = PARITY["compare_semantics"]
_release_run_contract = PARITY["release_run_contract"]
_live_budget_failures = PARITY["live_budget_failures"]
_legacy_environment_fingerprint = LEGACY_HELPERS["_environment_fingerprint"]
_legacy_failure_evidence = LEGACY_HELPERS["_failure_evidence"]
_new_failure_evidence = NEW_HELPERS["_failure_evidence"]
_run_legacy_process = LEGACY_HELPERS["_run_process"]
_run_new_process = NEW_HELPERS["_run_process"]
_call_system_boundary = LEGACY_HELPERS["_call_boundary"]
_classify_http_profile_compatibility = HTTP_PROFILE_COMPATIBILITY[
    "classify_http_profile_compatibility"
]
_HttpProfileDescriptor = HTTP_PROFILE_COMPATIBILITY["HttpProfileDescriptor"]
_OldHttpProfileProvenance = HTTP_PROFILE_COMPATIBILITY["OldHttpProfileProvenance"]
_HttpProfileCompatibilityKind = HTTP_PROFILE_COMPATIBILITY[
    "HttpProfileCompatibilityKind"
]
SITE_KEYS = ("soa", "cas", "iaa")
_LEGACY_PROCESS_TIMEOUT_SECONDS = 30
_LEGACY_NETWORK_TIMEOUT_SECONDS = 28
_LEGACY_ENVIRONMENT_ALLOWLIST = LEGACY_HELPERS["_LEGACY_ENVIRONMENT_ALLOWLIST"]
_LEGACY_ROBOTS_RESPONSE_BYTES_PER_CASE = LEGACY_HELPERS[
    "_ROBOTS_RESPONSE_BYTES_PER_CASE"
]
_REQUIRED_CANDIDATE_PATHS = tuple(
    sorted(
        {
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
    )
)
_INTEGRATED_CANDIDATE_PATHS = tuple(
    path for path in _REQUIRED_CANDIDATE_PATHS if path != "README.md"
)


def _legacy_environment_matches(actual: dict[str, object]) -> bool:
    return LEGACY_HELPERS["_fingerprint_matches"](actual, _LEGACY_ENVIRONMENT_ALLOWLIST)


def _verify_old_http_profile_provenance() -> dict[str, str]:
    frozen = HTTP_PROFILE_COMPATIBILITY["FROZEN_OLD_HTTP_PROFILE_PROVENANCE"]
    evidence = asdict(frozen)
    revision = subprocess.run(
        ["git", "-C", str(OLD_REPOSITORY), "rev-parse", frozen.commit_sha],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if revision != frozen.commit_sha:
        raise RuntimeError("fixed old HTTP profile commit is unavailable")
    for path_field, blob_field in (
        ("identity_contract_path", "identity_contract_blob_sha"),
        ("transport_path", "transport_blob_sha"),
        ("gateway_path", "gateway_blob_sha"),
        ("caller_path", "caller_blob_sha"),
    ):
        path = getattr(frozen, path_field)
        observed = subprocess.run(
            [
                "git",
                "-C",
                str(OLD_REPOSITORY),
                "rev-parse",
                f"{frozen.commit_sha}:{path}",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if observed != getattr(frozen, blob_field):
            raise RuntimeError(f"fixed old HTTP profile blob drifted: {path}")
    return evidence


def _profile_case_evidence(
    case: dict[str, object], observations: list[dict[str, object]]
) -> dict[str, object]:
    collapsed: object = "N/A"
    if observations and all(item == observations[0] for item in observations):
        collapsed = observations[0]
    elif observations:
        collapsed = "drift"
    return {
        "case_id": case["case_id"],
        "request_count": len(observations),
        "observations": observations,
        "collapsed": collapsed,
    }


def _http_profile_system_evidence(
    cases: list[dict[str, object]],
    *,
    provenance: object,
    identity: object,
    authority: object,
    observations: list[list[dict[str, object]]],
) -> dict[str, object]:
    if len(observations) != len(cases):
        raise ValueError("HTTP profile observations must match the frozen cases")
    return {
        "schema_version": "phase-20-http-profile-evidence.v1",
        "provenance": provenance,
        "identity": identity,
        "authority": authority,
        "cases": [
            _profile_case_evidence(case, rows)
            for case, rows in zip(cases, observations, strict=True)
        ],
    }


def _empty_http_profile_evidence(
    cases: list[dict[str, object]],
) -> dict[str, object]:
    return _http_profile_system_evidence(
        cases,
        provenance="N/A",
        identity="N/A",
        authority="N/A",
        observations=[[] for _case in cases],
    )


def _profile_descriptor(value: object):
    if not isinstance(value, dict) or set(value) != {"fields", "sha256"}:
        return _HttpProfileDescriptor(fields=(), sha256="N/A")
    fields = value["fields"]
    sha256 = value["sha256"]
    if (
        not isinstance(fields, list)
        or not isinstance(sha256, str)
        or not all(
            isinstance(item, list)
            and len(item) == 2
            and all(isinstance(leaf, str) for leaf in item)
            for item in fields
        )
    ):
        return _HttpProfileDescriptor(fields=(), sha256="N/A")
    return _HttpProfileDescriptor(
        fields=tuple((item[0], item[1]) for item in fields), sha256=sha256
    )


def _profile_row_descriptor(profile: object, index: int, case_id: str):
    invalid = _HttpProfileDescriptor(fields=(), sha256="N/A")
    if (
        not isinstance(profile, dict)
        or set(profile)
        != {"schema_version", "provenance", "identity", "authority", "cases"}
        or profile.get("schema_version") != "phase-20-http-profile-evidence.v1"
    ):
        return invalid
    authority = _profile_descriptor(profile.get("authority"))
    rows = profile.get("cases")
    if not isinstance(rows, list) or len(rows) <= index:
        return invalid
    row = rows[index]
    if (
        not isinstance(row, dict)
        or set(row) != {"case_id", "request_count", "observations", "collapsed"}
        or row.get("case_id") != case_id
    ):
        return invalid
    observations = row.get("observations")
    count = row.get("request_count")
    collapsed = _profile_descriptor(row.get("collapsed"))
    if (
        not _nonnegative_exact_int(count)
        or count < 1
        or not isinstance(observations, list)
        or len(observations) != count
        or any(_profile_descriptor(item) != collapsed for item in observations)
        or collapsed != authority
    ):
        return invalid
    return collapsed


def _profile_provenance(value: object):
    fields = tuple(_OldHttpProfileProvenance.__dataclass_fields__)
    if not isinstance(value, dict) or tuple(value) != fields:
        value = {}
    return _OldHttpProfileProvenance(
        **{field: value.get(field, "N/A") for field in fields}
    )


def _profile_classification_evidence(case_id: str, classification) -> dict[str, object]:
    return {
        "case_id": case_id,
        "kind": classification.kind.value,
        "code": classification.code,
        "old_profile_sha256": classification.old_profile_sha256,
        "new_profile_sha256": classification.new_profile_sha256,
        "differences": [asdict(item) for item in classification.differences],
    }


def _http_profile_compatibility_gate(
    old: dict[str, object],
    new: dict[str, object],
    cases: list[dict[str, object]],
) -> tuple[list[dict[str, object]], list[str]]:
    old_profile = old.get("http_profile")
    new_profile = new.get("http_profile")
    old_provenance = _profile_provenance(
        old_profile.get("provenance") if isinstance(old_profile, dict) else None
    )
    old_identity = (
        old_profile.get("identity") if isinstance(old_profile, dict) else None
    )
    if not isinstance(old_identity, dict):
        old_identity = {}
    rows = []
    failures = []
    for index, case in enumerate(cases):
        case_id = str(case["case_id"])
        old_descriptor = _profile_row_descriptor(old_profile, index, case_id)
        new_descriptor = _profile_row_descriptor(new_profile, index, case_id)
        if not (
            isinstance(new_profile, dict)
            and new_profile.get("provenance") == "N/A"
            and new_profile.get("identity") == "N/A"
        ):
            new_descriptor = _HttpProfileDescriptor(fields=(), sha256="N/A")
        old_records = old.get("cases")
        new_records = new.get("cases")
        old_record = (
            old_records[index]
            if isinstance(old_records, list) and len(old_records) > index
            else None
        )
        new_record = (
            new_records[index]
            if isinstance(new_records, list) and len(new_records) > index
            else None
        )
        old_profile_row = (
            old_profile["cases"][index]
            if isinstance(old_profile, dict)
            and isinstance(old_profile.get("cases"), list)
            and len(old_profile["cases"]) > index
            else None
        )
        new_profile_row = (
            new_profile["cases"][index]
            if isinstance(new_profile, dict)
            and isinstance(new_profile.get("cases"), list)
            and len(new_profile["cases"]) > index
            else None
        )
        old_usage = old_record.get("usage") if isinstance(old_record, dict) else None
        new_usage = new_record.get("usage") if isinstance(new_record, dict) else None
        if (
            isinstance(old_record, dict)
            and old_record.get("outcome") == "success"
            and (
                not isinstance(old_profile_row, dict)
                or not isinstance(old_usage, dict)
                or old_profile_row.get("request_count") != old_usage.get("requests")
            )
        ):
            old_descriptor = _HttpProfileDescriptor(fields=(), sha256="N/A")
        if (
            not isinstance(new_profile_row, dict)
            or not isinstance(new_usage, dict)
            or new_profile_row.get("request_count")
            != new_usage.get("transport_requests")
        ):
            new_descriptor = _HttpProfileDescriptor(fields=(), sha256="N/A")
        classification = _classify_http_profile_compatibility(
            old_descriptor,
            new_descriptor,
            old_provenance=old_provenance,
            old_identity=old_identity,
        )
        rows.append(_profile_classification_evidence(case_id, classification))
        if classification.kind is _HttpProfileCompatibilityKind.BLOCKER:
            failures.append(f"{case_id}:http_profile")
    return rows, failures


_FIXED_PYTEST_COMMAND = (
    "python -m pytest -q -m live tests/live/test_phase_20_parity_live.py"
).split()
_LIVE_ACCEPTED = {
    "artifact.availability": {
        "old": "N/A",
        "new": "present",
        "reason": "The fixed legacy live canary reads bytes but does not persist Artifacts.",
    },
    "artifact.count": {
        "old": "N/A",
        "new": 1,
        "reason": "The fixed legacy gateway exposes no first-class Artifact count.",
    },
    "artifact.sha_matches_http": {
        "old": "N/A",
        "new": True,
        "reason": "Legacy exposes body SHA only; the new Artifact must match it.",
    },
    "artifact.size_matches_http": {
        "old": "N/A",
        "new": True,
        "reason": "Legacy exposes body size only; the new Artifact must match it.",
    },
    "artifact.mime_matches_http": {
        "old": "N/A",
        "new": True,
        "reason": "Legacy exposes HTTP MIME only; the new Artifact must match it.",
    },
    "manifest.availability": {
        "old": "N/A",
        "new": "present",
        "reason": "The fixed legacy live canary has no Result Manifest output surface.",
    },
    "manifest.artifact_count": {
        "old": "N/A",
        "new": 1,
        "reason": "The fixed legacy gateway has no Manifest artifact collection.",
    },
    "manifest.links_match_artifact": {
        "old": "N/A",
        "new": True,
        "reason": "The new Manifest relationship must be internally consistent.",
    },
    "manifest.sha_matches_http": {
        "old": "N/A",
        "new": True,
        "reason": "The new Manifest SHA must match the comparable HTTP body SHA.",
    },
    "manifest.size_matches_http": {
        "old": "N/A",
        "new": True,
        "reason": "The new Manifest size must match the comparable HTTP body size.",
    },
    "manifest.mime_matches_http": {
        "old": "N/A",
        "new": True,
        "reason": "The new Manifest MIME must match the comparable HTTP MIME.",
    },
    "manifest.tool_id": {
        "old": "N/A",
        "new": "acquisition.web_http",
        "reason": "Legacy has no Manifest tool field; new evidence freezes the tool.",
    },
    "manifest.tool_version": {
        "old": "N/A",
        "new": "1.0.0",
        "reason": "Legacy has no Manifest tool version; new evidence freezes it.",
    },
    "observation.availability": {
        "old": "N/A",
        "new": "present",
        "reason": "The fixed legacy live canary does not persist Observations.",
    },
    "observation.count": {
        "old": "N/A",
        "new": 1,
        "reason": "The fixed legacy gateway exposes no first-class Observation count.",
    },
    "observation.links_match_artifact": {
        "old": "N/A",
        "new": True,
        "reason": "New Observation-to-Artifact identity must be internally consistent.",
    },
    "attempts.availability": {
        "old": "N/A",
        "new": "present",
        "reason": "The fixed legacy gateway exposes no Result Attempt contract.",
    },
    "attempts.count": {
        "old": "N/A",
        "new": 1,
        "reason": "The fixed legacy gateway exposes no Result Attempt count.",
    },
    "attempts.outcomes": {
        "old": "N/A",
        "new": ["succeeded"],
        "reason": "The fixed legacy gateway exposes no Result Attempt outcomes.",
    },
    "attempts.tool_ids": {
        "old": "N/A",
        "new": ["acquisition.web_http"],
        "reason": "Legacy has no Attempt tool field; the new tool identity is frozen.",
    },
    "attempts.tool_versions": {
        "old": "N/A",
        "new": ["1.0.0"],
        "reason": "Legacy has no Attempt version; the new tool version is frozen.",
    },
    "usage.tool_attempts": {
        "old": "N/A",
        "new": 1,
        "reason": "The fixed legacy gateway exposes no tool-attempt Usage count.",
    },
    "usage.bytes_received_availability": {
        "old": "N/A",
        "new": "present",
        "reason": "Legacy has no comparable Result Usage byte-count surface.",
    },
    "usage.bytes_received_exact": {
        "old": "N/A",
        "new": True,
        "reason": "New Result Usage bytes must be a nonnegative exact integer.",
    },
    "usage.transport_response_bytes_exact": {
        "old": "N/A",
        "new": True,
        "reason": "New per-case governed transport bytes must be exact integers.",
    },
    "usage.bytes_received_matches_transport": {
        "old": "N/A",
        "new": True,
        "reason": "New Result Usage bytes must match its governed transport delta.",
    },
    "usage.result_requests_availability": {
        "old": "N/A",
        "new": "present",
        "reason": "Legacy has no Result Usage surface; its gateway count remains raw evidence.",
    },
    "usage.result_requests_exact": {
        "old": "N/A",
        "new": True,
        "reason": "New Result Usage requests must be a nonnegative exact integer.",
    },
    "usage.transport_requests_exact": {
        "old": "N/A",
        "new": True,
        "reason": "New per-case governed transport requests must be exact integers.",
    },
    "usage.requests_match_transport": {
        "old": "N/A",
        "new": True,
        "reason": "New Result Usage requests must match its governed transport delta.",
    },
}


def _old_invocation_descriptor(
    cwd: str, candidate_identity: dict[str, object] | None = None
) -> dict[str, object]:
    descriptor = {
        "kind": "subprocess",
        "command": [
            "<current-python>",
            "<issue-worktree>/tests/parity/legacy_live_probe.py",
        ],
        "cwd": cwd,
    }
    if candidate_identity is not None:
        descriptor["candidate_identity"] = candidate_identity
    return descriptor


def _new_invocation_descriptor(
    revision: str, candidate_identity: dict[str, object] | None = None
) -> dict[str, object]:
    descriptor = {
        "kind": "subprocess",
        "command": [
            "<current-python>",
            "<issue-worktree>/tests/parity/new_live_probe.py",
        ],
        "cwd": "<issue-worktree>",
        "revision": revision,
    }
    if candidate_identity is not None:
        descriptor["candidate_identity"] = candidate_identity
    return descriptor


def _outer_invocation_descriptor() -> dict[str, object]:
    return {
        "kind": "outer-pytest",
        "command": list(_FIXED_PYTEST_COMMAND),
        "process_return_code": "recorded-by-live-test-agent",
    }


def _candidate_path_allowed(relative: str) -> bool:
    return relative in {
        "README.md",
        "docs/parity-report.md",
        "docs/release-checklist.md",
        "tests/live/phase_20_site_targets.json",
        "tests/live/test_phase_20_parity_live.py",
    } or relative.startswith("tests/parity/")


def _candidate_identity_from_paths(
    root: Path,
    candidate_paths: list[str] | tuple[str, ...],
    base_revision: str,
    head_revision: str,
    branch: str,
    *,
    reader=None,
) -> dict[str, object]:
    if (
        not re.fullmatch(r"[0-9a-f]{40}", base_revision)
        or not re.fullmatch(r"[0-9a-f]{40}", head_revision)
        or not branch.strip()
    ):
        raise ValueError("candidate identity base or branch is invalid")
    if len(candidate_paths) != len(set(candidate_paths)):
        raise ValueError("candidate identity paths are not unique")
    paths = sorted(candidate_paths)
    if not set(_REQUIRED_CANDIDATE_PATHS).issubset(paths):
        raise ValueError("candidate identity required paths are missing")
    root = root.resolve()
    files: dict[str, dict[str, object]] = {}
    for relative in paths:
        if (
            not isinstance(relative, str)
            or not relative
            or "\\" in relative
            or relative.startswith("/")
            or ".." in Path(relative).parts
        ):
            raise ValueError("candidate identity path is outside the Issue whitelist")
        if not _candidate_path_allowed(relative):
            raise ValueError("candidate identity path is outside the Issue whitelist")
        path = root.joinpath(*relative.split("/"))
        try:
            resolved = path.resolve(strict=False)
        except OSError as exc:
            raise ValueError("candidate identity path cannot be resolved") from exc
        if root not in resolved.parents or path.is_symlink() or not path.is_file():
            raise ValueError("candidate identity path is not a regular file")
        try:
            raw = reader(path) if reader is not None else path.read_bytes()
        except OSError as exc:
            raise ValueError("candidate identity file read failed") from exc
        if not isinstance(raw, bytes):
            raise ValueError("candidate identity reader did not return bytes")
        files[relative] = {
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        }
    if set(paths) != set(_REQUIRED_CANDIDATE_PATHS):
        raise ValueError("candidate identity path set drifted")
    material: dict[str, object] = {
        "schema_version": "phase-20-candidate-identity.v2",
        "base_revision": base_revision,
        "head_revision": head_revision,
        "branch": branch,
        "candidate_paths": paths,
        "files": files,
    }
    aggregate = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {**material, "aggregate_sha256": aggregate}


def _git_output(*arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=True,
        capture_output=True,
    ).stdout


def _candidate_identity() -> dict[str, object]:
    revision = _git_output("rev-parse", "HEAD").decode("ascii").strip()
    branch = _git_output("branch", "--show-current").decode("utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or branch != CANDIDATE_BRANCH:
        raise ValueError("candidate identity base or branch drifted")

    try:
        _git_output("merge-base", "--is-ancestor", BASE_REVISION, revision)
    except subprocess.CalledProcessError as exc:
        raise ValueError("candidate identity base ancestry drifted") from exc

    def git_paths(*arguments: str) -> list[str]:
        try:
            return [
                item
                for item in _git_output(*arguments).decode("utf-8").split("\0")
                if item
            ]
        except UnicodeDecodeError as exc:
            raise ValueError(
                "candidate identity contains a non-UTF-8 Git path"
            ) from exc

    integrated = git_paths(
        "diff",
        "--name-only",
        "--diff-filter=A",
        "-z",
        BASE_REVISION,
        revision,
        "--",
    )
    integrated_forbidden = git_paths(
        "diff",
        "--name-only",
        "--diff-filter=CDMRTUXB",
        "-z",
        BASE_REVISION,
        revision,
        "--",
    )
    if (
        sorted(integrated) != list(_INTEGRATED_CANDIDATE_PATHS)
        or len(integrated) != len(set(integrated))
        or integrated_forbidden
    ):
        raise ValueError("candidate identity integrated paths drifted")

    overlay = git_paths("diff", "--name-only", "--diff-filter=M", "-z", revision, "--")
    overlay_forbidden = git_paths(
        "diff",
        "--name-only",
        "--diff-filter=ACDRTUXB",
        "-z",
        revision,
        "--",
    )
    untracked = git_paths("ls-files", "--others", "--exclude-standard", "-z")
    if any(
        not path
        or "\\" in path
        or path.startswith("/")
        or ".." in Path(path).parts
        or not _candidate_path_allowed(path)
        for path in untracked
    ):
        raise ValueError("candidate identity path is outside the Issue whitelist")
    if overlay != ["README.md"] or overlay_forbidden or untracked:
        raise ValueError("candidate identity README overlay drifted")

    paths = list(_REQUIRED_CANDIDATE_PATHS)
    return _candidate_identity_from_paths(ROOT, paths, BASE_REVISION, revision, branch)


def _candidate_binding(
    identity: dict[str, object], probe_path: str
) -> dict[str, object]:
    try:
        file_identity = identity["files"][probe_path]
        return {
            "schema_version": identity["schema_version"],
            "candidate_aggregate_sha256": identity["aggregate_sha256"],
            "base_revision": identity["base_revision"],
            "head_revision": identity["head_revision"],
            "branch": identity["branch"],
            "probe_path": probe_path,
            "probe_sha256": file_identity["raw_sha256"],
            "probe_size_bytes": file_identity["size_bytes"],
        }
    except (KeyError, TypeError) as exc:
        raise ValueError("candidate identity probe binding is incomplete") from exc


def _candidate_identity_is_complete(identity: object) -> bool:
    if not isinstance(identity, dict) or set(identity) != {
        "schema_version",
        "base_revision",
        "head_revision",
        "branch",
        "candidate_paths",
        "files",
        "aggregate_sha256",
    }:
        return False
    material = {
        key: value for key, value in identity.items() if key != "aggregate_sha256"
    }
    expected = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return (
        identity["schema_version"] == "phase-20-candidate-identity.v2"
        and identity["base_revision"] == BASE_REVISION
        and isinstance(identity["head_revision"], str)
        and re.fullmatch(r"[0-9a-f]{40}", identity["head_revision"]) is not None
        and identity["branch"] == CANDIDATE_BRANCH
        and identity["candidate_paths"] == sorted(identity["candidate_paths"])
        and set(identity["candidate_paths"]) == set(identity["files"])
        and identity["aggregate_sha256"] == expected
    )


def _candidate_identity_failures(
    before: dict[str, object],
    after: dict[str, object],
    old: dict[str, object],
    new: dict[str, object],
) -> list[str]:
    try:
        expected_old = _candidate_binding(before, "tests/parity/legacy_live_probe.py")
        expected_new = _candidate_binding(before, "tests/parity/new_live_probe.py")
        stable = (
            _candidate_identity_is_complete(before)
            and _candidate_identity_is_complete(after)
            and before == after
        )
        bound = all(
            result.get("candidate_identity") == expected
            and result.get("environment", {}).get("candidate_identity") == expected
            and result.get("invocation", {}).get("candidate_identity") == expected
            for result, expected in ((old, expected_old), (new, expected_new))
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        stable = False
        bound = False
    return [] if stable and bound else ["candidate_identity:drift"]


def _catalog_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest().upper()


def _catalog_git_blob_bytes(content: bytes) -> bytes:
    return content.replace(b"\r\n", b"\n")


def _projection(row: dict[str, object]) -> dict[str, object]:
    urls = row["urls"]
    thresholds = row["evidence_thresholds"]
    return {
        "site_key": row["site_key"],
        "monitor_url": urls["monitor"],
        "document_url": urls["document"],
        "allowed_origins": row["allowed_origins"],
        "historical_expectation": row["historical_classification"]["expectation"],
        "thresholds": {
            "monitor_min_words": thresholds["monitor_min_words"],
            "document_min_words": thresholds["document_min_words"],
            "document_min_links": thresholds["document_min_links"],
        },
        "site_skill_digest": row["site_skill_digest"],
        "provenance": row["provenance"],
    }


def _load_snapshot() -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    snapshot = json.loads(TARGETS.read_bytes())
    catalog_bytes = _catalog_git_blob_bytes(CATALOG.read_bytes())
    catalog = json.loads(catalog_bytes)
    rows = catalog.get("sites")
    targets = snapshot.get("targets")
    if not isinstance(rows, list) or not isinstance(targets, list):
        pytest.fail("Phase 20 target or source catalog is invalid")
    expected = [_projection(row) for row in rows if row.get("site_key") in SITE_KEYS]
    if targets != expected or [row.get("site_key") for row in targets] != list(
        SITE_KEYS
    ):
        pytest.fail("Phase 20 targets drifted from the three audited catalog rows")
    if snapshot.get("old_commit") != OLD_COMMIT:
        pytest.fail("Phase 20 fixed old commit drifted")
    if _catalog_sha256(catalog_bytes) != snapshot.get("source_catalog_sha256"):
        pytest.fail("Phase 20 catalog raw digest drifted")
    expected_limits = {
        "max_targets": 2,
        "max_total_requests": 8,
        "max_total_response_bytes": 4 * 1024 * 1024,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
    }
    if snapshot.get("network_limits_per_system_per_site") != expected_limits:
        pytest.fail("Phase 20 network limits drifted")
    return snapshot, {str(row["site_key"]): row for row in targets}


def _authorized_target(site_key: str) -> tuple[dict[str, object], dict[str, object]]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 20 live parity is offline by default")
    if not os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip():
        pytest.fail("a non-empty Phase 20 authorized live window is required")
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE", "").strip()
    try:
        run_contract = _release_run_contract(selector)
    except ValueError as exc:
        pytest.fail(str(exc))
    if run_contract["mode"] == "single-site-diagnostic" and selector != site_key:
        pytest.fail(
            "single-site diagnostic excludes this site and cannot produce "
            "final release evidence"
        )
    snapshot, targets = _load_snapshot()
    return snapshot, targets[site_key]


def test_phase_20_snapshot_is_exact_three_row_projection() -> None:
    snapshot, targets = _load_snapshot()

    assert tuple(targets) == SITE_KEYS
    assert snapshot["source_catalog_sha256"] == (
        "B13747A4516810BED5AB5FF164EFC3FD9F5F1C91B51FF3DCE5708A23724A0E6E"
    )


def test_catalog_git_blob_digest_is_stable_across_checkout_line_endings() -> None:
    lf_content = b"{}\n"
    crlf_content = b"{}\r\n"

    assert _catalog_git_blob_bytes(lf_content) == lf_content
    assert _catalog_git_blob_bytes(crlf_content) == lf_content
    assert _catalog_sha256(_catalog_git_blob_bytes(lf_content)) == _catalog_sha256(
        _catalog_git_blob_bytes(crlf_content)
    )


def test_legacy_probe_hard_partitions_every_case_under_aggregate_caps() -> None:
    probe = runpy.run_path(str(LEGACY_PROBE))

    request_limit, body_limit, robots_limit = probe["_case_limits"](
        {
            "max_total_requests": 8,
            "max_total_response_bytes": 4 * 1024 * 1024,
        },
        2,
    )

    assert request_limit * 2 == 8
    assert body_limit * 2 + robots_limit * 2 == 4 * 1024 * 1024


def test_legacy_failure_record_predeclares_complete_na_evidence() -> None:
    probe = runpy.run_path(str(LEGACY_PROBE))
    record = probe["_base_record"](
        {"case_id": "monitor", "request_digest": "digest", "requested_url": "url"},
        request_upper_bound=4,
        response_bytes_upper_bound=2 * 1024 * 1024,
    )

    assert record["final_url"] is None
    assert record["redirects"] == []
    assert record["status"] is None
    assert record["mime_type"] is None
    assert record["usage"] == {
        "requests": None,
        "requests_upper_bound": 4,
        "response_bytes": None,
        "response_bytes_upper_bound": 2 * 1024 * 1024,
        "target_bytes": None,
        "tool_attempts": "N/A",
        "bytes_basis": "N/A",
        "within_budget": True,
    }
    assert record["attempts"] == "N/A"


def test_offline_default_skips_before_snapshot_or_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("WEB_LISTENING_RUN_LIVE", raising=False)

    with pytest.raises(pytest.skip.Exception):
        _authorized_target("soa")


def test_enabled_live_requires_nonempty_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    monkeypatch.delenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", raising=False)

    with pytest.raises(pytest.fail.Exception, match="non-empty"):
        _authorized_target("soa")


def test_live_selector_cannot_inject_a_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "authorized")
    monkeypatch.setenv("WEB_LISTENING_LIVE_SITE", "https://example.invalid/")

    with pytest.raises(pytest.fail.Exception, match="soa, cas, or iaa"):
        _authorized_target("soa")


def test_live_source_accepts_only_the_three_governance_environment_names() -> None:
    names = set(
        re.findall(
            r'os\.environ\.get\("([A-Z0-9_]+)"',
            inspect.getsource(sys.modules[__name__]),
        )
    )

    assert names == {
        "WEB_LISTENING_LIVE_AUTHORIZED_WINDOW",
        "WEB_LISTENING_LIVE_SITE",
        "WEB_LISTENING_RUN_LIVE",
    }


def _cases(target: dict[str, object]) -> list[dict[str, object]]:
    thresholds = target["thresholds"]
    cases = []
    for kind in ("monitor", "document"):
        requested_url = str(target[f"{kind}_url"])
        cases.append(
            {
                "case_id": kind,
                "requested_url": requested_url,
                "minimum_words": thresholds[f"{kind}_min_words"],
                "minimum_document_links": (
                    thresholds["document_min_links"] if kind == "document" else 0
                ),
            }
        )
    return cases


def _extract_old_checkout(destination: Path) -> tuple[Path, dict[str, str]]:
    destination.mkdir(parents=True, exist_ok=True)
    old_checkout = destination / f"old-{OLD_COMMIT[:7]}"
    old_checkout.mkdir()
    revision = subprocess.run(
        ["git", "-C", str(OLD_REPOSITORY), "rev-parse", OLD_COMMIT],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if revision != OLD_COMMIT:
        raise RuntimeError("legacy repository does not contain the fixed commit")
    archive = destination / "old.tar"
    subprocess.run(
        [
            "git",
            "-C",
            str(OLD_REPOSITORY),
            "archive",
            "--format=tar",
            f"--output={archive}",
            OLD_COMMIT,
        ],
        check=True,
        capture_output=True,
    )
    source = {
        "commit": revision,
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    }
    if source != _LEGACY_ENVIRONMENT_ALLOWLIST["source"]:
        raise RuntimeError("fixed legacy archive fingerprint drifted")
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        if any(
            Path(member.name).is_absolute() or ".." in Path(member.name).parts
            for member in members
        ):
            raise RuntimeError("fixed legacy archive contains an unsafe path")
        bundle.extractall(old_checkout)  # nosec B202 - fixed trusted Git commit
    return old_checkout, source


def _run_old(
    tmp_path: Path,
    target: dict[str, object],
    cases: list[dict[str, object]],
    limits: dict[str, object],
    run_context: dict[str, object],
) -> dict[str, object]:
    window_digest = str(run_context["window_digest"])
    candidate_identity = run_context["candidate_identity"]
    if not isinstance(candidate_identity, dict):
        raise ValueError("candidate identity is unavailable")
    binding = _candidate_binding(
        candidate_identity, "tests/parity/legacy_live_probe.py"
    )
    invocation = _old_invocation_descriptor(
        f"<pytest-temp>/old-{OLD_COMMIT[:7]}", binding
    )
    environment_evidence: dict[str, object] = {
        "checkout": f"<pytest-temp>/old-{OLD_COMMIT[:7]}",
        "authorization_window_sha256": window_digest,
        "candidate_identity": binding,
        "expected_fingerprint": _LEGACY_ENVIRONMENT_ALLOWLIST,
        "verification": "not-run",
    }
    preliminary_payload = {
        "old_commit": OLD_COMMIT,
        "environment": environment_evidence,
        "governed_network_timeout_seconds": _LEGACY_NETWORK_TIMEOUT_SECONDS,
        "limits": limits,
        "cases": cases,
    }
    try:
        profile_provenance = _verify_old_http_profile_provenance()
        checkout, source = _extract_old_checkout(tmp_path)
    except (OSError, RuntimeError, subprocess.SubprocessError, tarfile.TarError) as exc:
        environment_evidence["verification"] = "setup-failure"
        result = _legacy_failure_evidence(
            preliminary_payload,
            invocation,
            {
                "error_code": "legacy.setup_failure",
                "error_type": type(exc).__name__,
                "process_outcome": "not-started",
                "process_return_code": "N/A",
            },
        )
        result["candidate_identity"] = binding
        return result
    fingerprint = _legacy_environment_fingerprint()
    fingerprint["source"] = source
    environment_evidence["fingerprint"] = fingerprint
    if not _legacy_environment_matches(fingerprint):
        environment_evidence["verification"] = "mismatch"
        result = _legacy_failure_evidence(
            preliminary_payload,
            invocation,
            {
                "error_code": "legacy.environment_mismatch",
                "error_type": "FingerprintMismatch",
                "process_outcome": "environment-mismatch",
                "process_return_code": "N/A",
            },
        )
        result["candidate_identity"] = binding
        return result
    environment_evidence["verification"] = "matched"
    payload = {
        "old_commit": OLD_COMMIT,
        "environment": environment_evidence,
        "governed_network_timeout_seconds": _LEGACY_NETWORK_TIMEOUT_SECONDS,
        "allowed_origins": target["allowed_origins"],
        "allowed_domains": [
            str(origin).split("://", 1)[1] for origin in target["allowed_origins"]
        ],
        "authority_sha256": hashlib.sha256(
            json.dumps(cases, sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "http_profile": {
            "provenance": profile_provenance,
            "identity": dict(HTTP_PROFILE_COMPATIBILITY["FROZEN_OLD_GATEWAY_IDENTITY"]),
        },
        "limits": limits,
        "cases": cases,
    }
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(checkout)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    command = [sys.executable, str(LEGACY_PROBE)]
    result = _run_legacy_process(command, checkout, environment, payload, invocation)
    result["candidate_identity"] = binding
    return result


def _run_new(
    tmp_path: Path,
    target: dict[str, object],
    cases: list[dict[str, object]],
    limits: dict[str, object],
    run_context: dict[str, object],
) -> dict[str, object]:
    window_digest = str(run_context["window_digest"])
    candidate_identity = run_context["candidate_identity"]
    if not isinstance(candidate_identity, dict):
        raise ValueError("candidate identity is unavailable")
    revision = str(candidate_identity["head_revision"])
    binding = _candidate_binding(candidate_identity, "tests/parity/new_live_probe.py")
    invocation = _new_invocation_descriptor(revision, binding)
    payload = {
        "environment": {
            "checkout": "<issue-worktree>",
            "revision": revision,
            "python": sys.version.split()[0],
            "authorization_window_sha256": window_digest,
            "candidate_identity": binding,
            "verification": "matched",
        },
        "governed_network_timeout_seconds": _LEGACY_NETWORK_TIMEOUT_SECONDS,
        "limits": limits,
        "cases": cases,
        "target": {
            "site_key": target["site_key"],
            "allowed_origins": target["allowed_origins"],
        },
        "artifact_root": str(tmp_path / "new-artifacts"),
    }
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    result = _run_new_process(
        [sys.executable, str(NEW_PROBE)], ROOT, environment, payload, invocation
    )
    result["candidate_identity"] = binding
    return result


def _call_new_boundary(operation, context: dict[str, object]) -> dict[str, object]:
    try:
        return operation()
    except Exception as exc:
        payload = {
            "environment": context["environment"],
            "governed_network_timeout_seconds": context[
                "governed_network_timeout_seconds"
            ],
            "limits": context["limits"],
            "cases": context["cases"],
        }
        return _new_failure_evidence(
            payload,
            context["invocation"],
            {
                "error_code": "phase20.new_boundary",
                "error_type": type(exc).__name__,
                "process_outcome": "boundary-failure",
                "process_return_code": "N/A",
            },
        )


def _error_semantics(error: object) -> dict[str, object]:
    if error is None:
        return {
            "availability": "none",
            "codes": [],
            "count": 0,
            "details": [],
            "error_types": [],
            "messages": [],
            "retryable": [],
        }
    if isinstance(error, dict):
        items = [error]
    elif isinstance(error, list) and error:
        items = error
    else:
        items = [None]
    mappings = [item if isinstance(item, dict) else {} for item in items]
    return {
        "availability": "present" if all(mappings) else "invalid",
        "codes": [
            item.get("code")
            or item.get("error_code")
            or item.get("reason_code")
            or "N/A"
            for item in mappings
        ],
        "count": len(items),
        "details": [item.get("details", "N/A") for item in mappings],
        "error_types": [item.get("error_type", "N/A") for item in mappings],
        "messages": [item.get("message", "N/A") for item in mappings],
        "retryable": [item.get("retryable", "N/A") for item in mappings],
    }


def _attempt_semantics(attempts: object) -> dict[str, object]:
    if attempts == "N/A":
        return {
            "availability": "N/A",
            "count": "N/A",
            "outcomes": "N/A",
            "tool_ids": "N/A",
            "tool_versions": "N/A",
        }
    if not isinstance(attempts, list):
        return {
            "availability": "N/A",
            "count": "N/A",
            "outcomes": "N/A",
            "tool_ids": "N/A",
            "tool_versions": "N/A",
        }
    return {
        "availability": "present",
        "count": len(attempts),
        "outcomes": [
            item.get("outcome", "N/A") if isinstance(item, dict) else "N/A"
            for item in attempts
        ],
        "tool_ids": [
            item.get("tool_id", "N/A") if isinstance(item, dict) else "N/A"
            for item in attempts
        ],
        "tool_versions": [
            item.get("tool_version", "N/A") if isinstance(item, dict) else "N/A"
            for item in attempts
        ],
    }


def _redirect_semantics(redirects: object) -> list[dict[str, object]]:
    if not isinstance(redirects, list):
        return []
    return [
        {
            "from_url": item.get("from_url"),
            "to_url": item.get("to_url"),
            "status": item.get("status", item.get("http_status")),
        }
        for item in redirects
        if isinstance(item, dict)
    ]


def _artifact_semantics(record: dict[str, object]) -> dict[str, object]:
    artifact = record.get("artifact")
    if not isinstance(artifact, dict) or artifact.get("availability") == "N/A":
        return {
            "availability": "N/A",
            "count": "N/A",
            "sha_matches_http": "N/A",
            "size_matches_http": "N/A",
            "mime_matches_http": "N/A",
        }
    items = artifact.get("items")
    if not isinstance(items, list) or not items:
        matches = {"sha": "N/A", "size": "N/A", "mime": "N/A"}
    else:
        matches = {
            "sha": all(
                isinstance(item, dict)
                and item.get("sha256") == record.get("content_sha256")
                for item in items
            ),
            "size": all(
                isinstance(item, dict)
                and item.get("size_bytes") == record.get("content_bytes")
                for item in items
            ),
            "mime": all(
                isinstance(item, dict)
                and item.get("mime_type") == record.get("mime_type")
                for item in items
            ),
        }
    return {
        "availability": artifact.get("availability", "N/A"),
        "count": artifact.get("count", "N/A"),
        "sha_matches_http": matches["sha"],
        "size_matches_http": matches["size"],
        "mime_matches_http": matches["mime"],
    }


def _identity_pairs(items: object) -> object:
    if not isinstance(items, list):
        return "N/A"
    if not all(isinstance(item, dict) for item in items):
        return "invalid"
    return sorted(
        (str(item.get("artifact_id")), str(item.get("observation_id")))
        for item in items
    )


def _observation_semantics(record: dict[str, object]) -> dict[str, object]:
    observation = record.get("observation")
    artifact = record.get("artifact")
    if not isinstance(observation, dict) or observation.get("availability") == "N/A":
        return {
            "availability": "N/A",
            "count": "N/A",
            "links_match_artifact": "N/A",
        }
    observation_pairs = _identity_pairs(observation.get("items"))
    artifact_pairs = (
        _identity_pairs(artifact.get("items")) if isinstance(artifact, dict) else "N/A"
    )
    return {
        "availability": observation.get("availability", "N/A"),
        "count": observation.get("count", "N/A"),
        "links_match_artifact": observation_pairs == artifact_pairs,
    }


def _manifest_semantics(record: dict[str, object]) -> dict[str, object]:
    manifest = record.get("manifest")
    artifact = record.get("artifact")
    if not isinstance(manifest, dict) or manifest.get("availability") == "N/A":
        return {
            "availability": "N/A",
            "artifact_count": "N/A",
            "links_match_artifact": "N/A",
            "sha_matches_http": "N/A",
            "size_matches_http": "N/A",
            "mime_matches_http": "N/A",
            "tool_id": "N/A",
            "tool_version": "N/A",
        }
    value = manifest.get("value")
    if not isinstance(value, dict):
        value = {}
    manifest_artifacts = value.get("artifacts")
    artifact_items = artifact.get("items") if isinstance(artifact, dict) else "N/A"
    return {
        "availability": manifest.get("availability", "N/A"),
        "artifact_count": (
            len(manifest_artifacts) if isinstance(manifest_artifacts, list) else "N/A"
        ),
        "links_match_artifact": _identity_pairs(manifest_artifacts)
        == _identity_pairs(artifact_items),
        "sha_matches_http": value.get("sha256") == record.get("content_sha256"),
        "size_matches_http": value.get("size_bytes") == record.get("content_bytes"),
        "mime_matches_http": value.get("mime_type") == record.get("mime_type"),
        "tool_id": value.get("tool_id", "N/A"),
        "tool_version": value.get("tool_version", "N/A"),
    }


def _nonnegative_exact_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _usage_semantics(record: dict[str, object]) -> dict[str, object]:
    usage = record["usage"]
    legacy_surface = record.get("attempts") == "N/A"
    if legacy_surface:
        request_evidence = {
            "result_requests_availability": "N/A",
            "result_requests_exact": "N/A",
            "transport_requests_exact": "N/A",
            "requests_match_transport": "N/A",
        }
        byte_evidence = {
            "bytes_received_availability": "N/A",
            "bytes_received_exact": "N/A",
            "transport_response_bytes_exact": "N/A",
            "bytes_received_matches_transport": "N/A",
        }
    else:
        result_requests = usage.get("requests")
        transport_requests = usage.get("transport_requests")
        result_requests_exact = _nonnegative_exact_int(result_requests)
        transport_requests_exact = _nonnegative_exact_int(transport_requests)
        request_evidence = {
            "result_requests_availability": (
                "present"
                if "requests" in usage and "transport_requests" in usage
                else "missing"
            ),
            "result_requests_exact": result_requests_exact,
            "transport_requests_exact": transport_requests_exact,
            "requests_match_transport": (
                result_requests_exact
                and transport_requests_exact
                and result_requests == transport_requests
            ),
        }
        received = usage.get("bytes_received")
        transported = usage.get("transport_response_bytes")
        received_exact = _nonnegative_exact_int(received)
        transported_exact = _nonnegative_exact_int(transported)
        byte_evidence = {
            "bytes_received_availability": (
                "present"
                if "bytes_received" in usage and "transport_response_bytes" in usage
                else "missing"
            ),
            "bytes_received_exact": received_exact,
            "transport_response_bytes_exact": transported_exact,
            "bytes_received_matches_transport": (
                received_exact and transported_exact and received == transported
            ),
        }
    return {
        "bytes_basis": usage.get("bytes_basis", "N/A"),
        "target_bytes": usage.get("target_bytes"),
        "tool_attempts": usage.get("tool_attempts", "N/A"),
        "within_budget": usage.get("within_budget", False),
        **request_evidence,
        **byte_evidence,
    }


def _live_semantics(record: dict[str, object]) -> dict[str, object]:
    return {
        "artifact": _artifact_semantics(record),
        "attempts": _attempt_semantics(record.get("attempts")),
        "error": _error_semantics(record.get("error")),
        "http": {
            "content_sha256": record.get("content_sha256"),
            "final_url": record.get("final_url"),
            "mime_type": record.get("mime_type"),
            "requested_url": record["requested_url"],
            "status": record.get("status"),
        },
        "manifest": _manifest_semantics(record),
        "observation": _observation_semantics(record),
        "outcome": record["outcome"],
        "redirects": _redirect_semantics(record.get("redirects")),
        "usage": _usage_semantics(record),
    }


def _request_usage_failures(
    system: str, result: dict[str, object], *, transport_surface: bool
) -> list[str]:
    failures = []
    cases = result.get("cases")
    budget = result.get("budget")
    if not isinstance(cases, list) or not isinstance(budget, dict):
        return [f"{system}_system:usage_requests_evidence"]
    case_total = 0
    for record in cases:
        usage = record.get("usage") if isinstance(record, dict) else None
        if not isinstance(usage, dict):
            failures.append(f"{system}_system:usage_requests_evidence")
            continue
        result_requests = usage.get("requests")
        if not _nonnegative_exact_int(result_requests):
            failures.append(f"{system}_system:usage_requests_evidence")
            continue
        if transport_surface:
            transport_requests = usage.get("transport_requests")
            if not _nonnegative_exact_int(transport_requests):
                failures.append(f"{system}_system:usage_requests_evidence")
                continue
            case_total += transport_requests
            if result_requests != transport_requests:
                failures.append(f"{system}_system:usage_requests_consistency")
        else:
            case_total += result_requests
    system_total = budget.get("requests")
    declared_total = (
        budget.get("case_request_total") if transport_surface else case_total
    )
    if not _nonnegative_exact_int(system_total) or not _nonnegative_exact_int(
        declared_total
    ):
        failures.append(f"{system}_system:usage_requests_evidence")
    elif case_total != declared_total or declared_total != system_total:
        failures.append(f"{system}_system:usage_requests_reconciliation")
    return list(dict.fromkeys(failures))


def _old_usage_failures(result: dict[str, object]) -> list[str]:
    failures = _request_usage_failures("old", result, transport_surface=False)
    cases = result.get("cases")
    budget = result.get("budget")
    if not isinstance(cases, list) or not cases or not isinstance(budget, dict):
        failures.append("old_system:usage_bytes_evidence")
        return list(dict.fromkeys(failures))
    required = {
        "requests",
        "requests_upper_bound",
        "response_bytes",
        "response_bytes_upper_bound",
        "target_bytes",
        "tool_attempts",
        "bytes_basis",
        "within_budget",
    }
    accounted_total = 0
    for record in cases:
        usage = record.get("usage") if isinstance(record, dict) else None
        if not isinstance(usage, dict) or set(usage) != required:
            failures.append("old_system:usage_bytes_evidence")
            continue
        counts = [
            usage.get("requests"),
            usage.get("requests_upper_bound"),
            usage.get("response_bytes"),
            usage.get("response_bytes_upper_bound"),
            usage.get("target_bytes"),
        ]
        if not all(_nonnegative_exact_int(value) for value in counts):
            failures.append("old_system:usage_bytes_evidence")
            continue
        requests, request_upper, response, response_upper, target_bytes = counts
        basis = usage.get("bytes_basis")
        valid_relationship = (
            0 < request_upper
            and requests <= request_upper
            and 0 < response_upper
            and target_bytes <= response <= response_upper
            and response_upper >= _LEGACY_ROBOTS_RESPONSE_BYTES_PER_CASE
            and target_bytes <= response_upper - _LEGACY_ROBOTS_RESPONSE_BYTES_PER_CASE
            and usage.get("tool_attempts") == "N/A"
            and usage.get("within_budget") is True
            and basis in {"target_body", "per_case_upper_bound"}
            and (
                basis != "per_case_upper_bound"
                or (
                    response == response_upper
                    and target_bytes
                    <= response - _LEGACY_ROBOTS_RESPONSE_BYTES_PER_CASE
                )
            )
        )
        if not valid_relationship:
            failures.append("old_system:usage_bytes_evidence")
            continue
        accounted_total += response + (
            _LEGACY_ROBOTS_RESPONSE_BYTES_PER_CASE if basis == "target_body" else 0
        )
    system_total = budget.get("response_bytes")
    robots_total = budget.get("robots_response_bytes_upper_bound")
    if not _nonnegative_exact_int(system_total) or robots_total != (
        _LEGACY_ROBOTS_RESPONSE_BYTES_PER_CASE * len(cases)
    ):
        failures.append("old_system:usage_bytes_evidence")
    elif accounted_total != system_total:
        failures.append("old_system:usage_bytes_reconciliation")
    return list(dict.fromkeys(failures))


def _new_usage_failures(result: dict[str, object]) -> list[str]:
    failures = _request_usage_failures("new", result, transport_surface=True)
    cases = result.get("cases")
    budget = result.get("budget")
    if not isinstance(cases, list) or not isinstance(budget, dict):
        failures.append("new_system:usage_bytes_evidence")
        return list(dict.fromkeys(failures))
    case_transport_total = 0
    for record in cases:
        usage = record.get("usage") if isinstance(record, dict) else None
        if not isinstance(usage, dict):
            failures.append("new_system:usage_bytes_evidence")
            continue
        received = usage.get("bytes_received")
        transported = usage.get("transport_response_bytes")
        if not _nonnegative_exact_int(received) or not _nonnegative_exact_int(
            transported
        ):
            failures.append("new_system:usage_bytes_evidence")
            continue
        case_transport_total += transported
        if received != transported:
            failures.append("new_system:usage_bytes_consistency")
    declared_total = budget.get("case_response_bytes_total")
    transport_total = budget.get("response_bytes")
    if not _nonnegative_exact_int(declared_total) or not _nonnegative_exact_int(
        transport_total
    ):
        failures.append("new_system:usage_bytes_evidence")
    elif case_transport_total != declared_total or declared_total != transport_total:
        failures.append("new_system:usage_bytes_reconciliation")
    return list(dict.fromkeys(failures))


def _threshold(case: dict[str, object], record: dict[str, object]) -> dict[str, object]:
    words = record.get("word_count")
    links = record.get("document_link_count")
    observed_words = 0 if words in {None, "N/A"} else int(words)
    observed_links = 0 if links in {None, "N/A"} else int(links)
    minimum_words = int(case["minimum_words"])
    minimum_links = int(case["minimum_document_links"])
    return {
        "minimum_words": {"expected": minimum_words, "observed": observed_words},
        "minimum_document_links": {
            "expected": minimum_links,
            "observed": observed_links,
        },
        "met": observed_words >= minimum_words and observed_links >= minimum_links,
    }


def _descriptor_digest(descriptor: object) -> str | None:
    if not isinstance(descriptor, dict):
        return None
    return hashlib.sha256(
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _case_evidence(
    case: dict[str, object],
    target: dict[str, object],
    old_record: dict[str, object],
    new_record: dict[str, object],
) -> tuple[dict[str, object], list[str]]:
    failures = []
    old_descriptor = old_record.get("request_descriptor")
    new_descriptor = new_record.get("request_descriptor")
    old_digest = old_record.get("request_digest")
    new_digest = new_record.get("request_digest")
    old_verified = _descriptor_digest(old_descriptor) == old_digest
    new_verified = _descriptor_digest(new_descriptor) == new_digest
    if not old_verified or not new_verified:
        failures.append(f"{case['case_id']}:request_evidence")
    if old_descriptor != new_descriptor:
        failures.append(f"{case['case_id']}:request_descriptor")
    if old_digest != new_digest:
        failures.append(f"{case['case_id']}:request_digest")
    comparison = COMPARE(
        _live_semantics(old_record),
        _live_semantics(new_record),
        _LIVE_ACCEPTED,
    )
    old_threshold = _threshold(case, old_record)
    new_threshold = _threshold(case, new_record)
    if not old_threshold["met"]:
        failures.append(f"{case['case_id']}:old_threshold")
    if not new_threshold["met"]:
        failures.append(f"{case['case_id']}:new_threshold")
    if comparison["classification"] == "blocker":
        failures.append(f"{case['case_id']}:semantic_difference")
    return (
        {
            "case_id": case["case_id"],
            "request_digest": {"old": old_digest, "new": new_digest},
            "request_provenance": {
                "old_descriptor": old_descriptor,
                "new_descriptor": new_descriptor,
                "old_digest_verified": old_verified,
                "new_digest_verified": new_verified,
                "same_descriptor": old_descriptor == new_descriptor,
                "same_digest": old_digest == new_digest,
            },
            "requested_url": case["requested_url"],
            "old": old_record,
            "new": new_record,
            "old_threshold": old_threshold,
            "new_threshold": new_threshold,
            "expected_to_observed": {
                "expected": target["historical_expectation"],
                "old": ("dev_fixture" if old_threshold["met"] else "threshold_miss"),
                "new": ("dev_fixture" if new_threshold["met"] else "threshold_miss"),
            },
            "difference": comparison,
        },
        failures,
    )


def _profile_blocked_case_evidence(
    case: dict[str, object],
    target: dict[str, object],
    old_record: dict[str, object],
    new_record: dict[str, object],
) -> tuple[dict[str, object], list[str]]:
    failures = []
    old_descriptor = old_record.get("request_descriptor")
    new_descriptor = new_record.get("request_descriptor")
    old_digest = old_record.get("request_digest")
    new_digest = new_record.get("request_digest")
    old_verified = _descriptor_digest(old_descriptor) == old_digest
    new_verified = _descriptor_digest(new_descriptor) == new_digest
    if not old_verified or not new_verified:
        failures.append(f"{case['case_id']}:request_evidence")
    if old_descriptor != new_descriptor:
        failures.append(f"{case['case_id']}:request_descriptor")
    if old_digest != new_digest:
        failures.append(f"{case['case_id']}:request_digest")
    old_threshold = _threshold(case, old_record)
    new_threshold = _threshold(case, new_record)
    if not old_threshold["met"]:
        failures.append(f"{case['case_id']}:old_threshold")
    if not new_threshold["met"]:
        failures.append(f"{case['case_id']}:new_threshold")
    return (
        {
            "case_id": case["case_id"],
            "request_digest": {"old": old_digest, "new": new_digest},
            "request_provenance": {
                "old_descriptor": old_descriptor,
                "new_descriptor": new_descriptor,
                "old_digest_verified": old_verified,
                "new_digest_verified": new_verified,
                "same_descriptor": old_descriptor == new_descriptor,
                "same_digest": old_digest == new_digest,
            },
            "requested_url": case["requested_url"],
            "old": old_record,
            "new": new_record,
            "old_threshold": old_threshold,
            "new_threshold": new_threshold,
            "expected_to_observed": {
                "expected": target["historical_expectation"],
                "old": "not-compared: HTTP profile blocker",
                "new": "not-compared: HTTP profile blocker",
            },
            "difference": {
                "classification": "blocker",
                "accepted": [],
                "blockers": [
                    {
                        "field": "http_profile",
                        "old": "blocked",
                        "new": "blocked",
                        "reason": "HTTP profile compatibility failed before content comparison",
                    }
                ],
            },
        },
        failures,
    )


def _evaluate_live_boundaries(
    evidence: dict[str, object],
    tmp_path: Path,
    target: dict[str, object],
    cases: list[dict[str, object]],
    run_context: dict[str, object],
) -> dict[str, object]:
    limits = run_context["limits"]
    window_digest = str(run_context["window_digest"])
    candidate_before = run_context.get("candidate_identity")
    if not isinstance(candidate_before, dict):
        candidate_before = _candidate_identity()
        run_context = {**run_context, "candidate_identity": candidate_before}
    old_binding = _candidate_binding(
        candidate_before, "tests/parity/legacy_live_probe.py"
    )
    new_binding = _candidate_binding(candidate_before, "tests/parity/new_live_probe.py")
    new_revision = str(candidate_before["head_revision"])
    old_context = {
        "system": "old",
        "old_commit": OLD_COMMIT,
        "environment": {
            "checkout": f"<pytest-temp>/old-{OLD_COMMIT[:7]}",
            "authorization_window_sha256": window_digest,
            "candidate_identity": old_binding,
            "verification": "boundary-failure",
        },
        "governed_network_timeout_seconds": _LEGACY_NETWORK_TIMEOUT_SECONDS,
        "limits": limits,
        "cases": cases,
        "invocation": _old_invocation_descriptor(
            f"<pytest-temp>/old-{OLD_COMMIT[:7]}", old_binding
        ),
    }
    new_context = {
        "system": "new",
        "environment": {
            "checkout": "<issue-worktree>",
            "revision": new_revision,
            "python": sys.version.split()[0],
            "authorization_window_sha256": window_digest,
            "candidate_identity": new_binding,
            "verification": "boundary-failure",
        },
        "governed_network_timeout_seconds": _LEGACY_NETWORK_TIMEOUT_SECONDS,
        "limits": limits,
        "cases": cases,
        "invocation": _new_invocation_descriptor(new_revision, new_binding),
    }
    old = _call_system_boundary(
        lambda: _run_old(
            tmp_path / "legacy",
            target,
            cases,
            limits,
            run_context,
        ),
        old_context,
    )
    new = _call_new_boundary(
        lambda: _run_new(
            tmp_path,
            target,
            cases,
            limits,
            run_context,
        ),
        new_context,
    )
    old["candidate_identity"] = old_binding
    new["candidate_identity"] = new_binding
    try:
        candidate_after = _candidate_identity()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        candidate_after = {
            "schema_version": "phase-20-candidate-identity.v2",
            "verification": "failed-after-child-execution",
            "error_type": type(exc).__name__,
        }
    candidate_failures = _candidate_identity_failures(
        candidate_before, candidate_after, old, new
    )
    evidence.update(
        {
            "candidate_identity": {
                "frozen": candidate_before,
                "observed_after": candidate_after,
                "verification": "stable" if not candidate_failures else "drift",
            },
            "old_candidate_identity": old_binding,
            "old_environment": old["environment"],
            "old_budget": old["budget"],
            "old_invocation": old["invocation"],
            "old_process_outcome": old["process_outcome"],
            "old_process_return_code": old["process_return_code"],
            "new_candidate_identity": new_binding,
            "new_environment": new["environment"],
            "new_budget": new["budget"],
            "new_invocation": new["invocation"],
            "new_process_outcome": new["process_outcome"],
            "new_process_return_code": new["process_return_code"],
        }
    )
    profile_compatibility, profile_failures = _http_profile_compatibility_gate(
        old, new, cases
    )
    evidence.update(
        {
            "old_http_profile": old.get("http_profile"),
            "new_http_profile": new.get("http_profile"),
            "http_profile_compatibility": profile_compatibility,
        }
    )
    comparisons = []
    gate_failures = [*candidate_failures, *profile_failures]
    for case, old_record, new_record in zip(
        cases, old["cases"], new["cases"], strict=True
    ):
        evidence_builder = (
            _profile_blocked_case_evidence if profile_failures else _case_evidence
        )
        comparison, case_failures = evidence_builder(
            case, target, old_record, new_record
        )
        comparisons.append(comparison)
        gate_failures.extend(case_failures)
    if old["process_return_code"] != 0:
        gate_failures.append("old_system:failure")
    if new["process_return_code"] != 0:
        gate_failures.append("new_system:failure")
    for system, result in (("old", old), ("new", new)):
        gate_failures.extend(_live_budget_failures(system, result["budget"], limits))
    gate_failures.extend(_old_usage_failures(old))
    gate_failures.extend(_new_usage_failures(new))
    evidence.update(
        {
            "cases": comparisons,
            "classification": "blocker" if gate_failures else "accepted",
            "release_gate_failures": gate_failures,
            "expected_outer_pytest_outcome": (
                "failure" if gate_failures else "success"
            ),
        }
    )
    return evidence


def _emit(record: dict[str, object], capsys: pytest.CaptureFixture[str]) -> None:
    with capsys.disabled():
        print(json.dumps(record, sort_keys=True), flush=True)


@pytest.mark.live
@pytest.mark.parametrize("site_key", SITE_KEYS)
def test_phase_20_parity_live(
    site_key: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    snapshot, target = _authorized_target(site_key)
    limits = snapshot["network_limits_per_system_per_site"]
    cases = _cases(target)
    authorized_window = os.environ["WEB_LISTENING_LIVE_AUTHORIZED_WINDOW"].strip()
    window_digest = hashlib.sha256(authorized_window.encode("utf-8")).hexdigest()
    run_contract = _release_run_contract(os.environ.get("WEB_LISTENING_LIVE_SITE", ""))
    evidence: dict[str, object] = {
        "schema_version": "phase-20-live-parity-evidence.v1",
        "site_key": site_key,
        "old_commit": OLD_COMMIT,
        "source_catalog_sha256": snapshot["source_catalog_sha256"],
        "target_snapshot_sha256": hashlib.sha256(TARGETS.read_bytes()).hexdigest(),
        "authorization_window_sha256": window_digest,
        "site_skill_digest": target["site_skill_digest"],
        "provenance": target["provenance"],
        "limits": limits,
        "outer_invocation": _outer_invocation_descriptor(),
        "release_run_contract": run_contract,
        "cases": [],
        "classification": "blocker",
    }
    try:
        try:
            candidate_identity = _candidate_identity()
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            evidence.update(
                {
                    "candidate_identity": {
                        "schema_version": "phase-20-candidate-identity.v2",
                        "verification": "failed-before-child-execution",
                        "error_type": type(exc).__name__,
                    },
                    "release_gate_failures": ["candidate_identity:drift"],
                    "expected_outer_pytest_outcome": "failure",
                }
            )
            pytest.fail("Phase 20 candidate identity could not be frozen")
        _evaluate_live_boundaries(
            evidence,
            tmp_path,
            target,
            cases,
            {
                "limits": limits,
                "window_digest": window_digest,
                "candidate_identity": candidate_identity,
            },
        )
        if run_contract["mode"] == "single-site-diagnostic":
            evidence["release_gate_failures"].append("run:single_site_diagnostic")
            evidence["classification"] = "blocker"
            evidence["expected_outer_pytest_outcome"] = "failure"
        assert not evidence["release_gate_failures"], evidence
    finally:
        _emit(evidence, capsys)
