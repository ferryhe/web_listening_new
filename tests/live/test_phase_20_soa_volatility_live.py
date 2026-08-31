"""One bounded, interleaved SOA volatility diagnosis; offline by default."""

# pylint: disable=broad-exception-caught,duplicate-code,missing-function-docstring
# pylint: disable=too-many-arguments,too-many-locals,too-many-statements
# pylint: disable=too-many-boolean-expressions,too-many-branches
# pylint: disable=too-many-lines,too-many-return-statements

from __future__ import annotations

import hashlib
import json
import math
import os
import runpy
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TARGETS = Path(__file__).with_name("phase_20_site_targets.json")
LEGACY_PROBE = ROOT / "tests" / "parity" / "legacy_live_probe.py"
NEW_PROBE = ROOT / "tests" / "parity" / "new_live_probe.py"
PHASE_20_LIVE = runpy.run_path(
    str(Path(__file__).with_name("test_phase_20_parity_live.py"))
)
LEGACY_HELPERS = runpy.run_path(str(LEGACY_PROBE))
NEW_HELPERS = runpy.run_path(str(NEW_PROBE))
VOLATILITY = runpy.run_path(
    str(ROOT / "tests" / "parity" / "phase_20_soa_volatility.py")
)

OLD_COMMIT = PHASE_20_LIVE["OLD_COMMIT"]
EXECUTION_ORDER = VOLATILITY["SAMPLE_ORDER"]
CLASSIFICATIONS = VOLATILITY["CLASSIFICATIONS"]
SAMPLE_LIMITS = {
    "max_targets": 2,
    "max_total_requests": 4,
    "max_total_response_bytes": 2 * 1024 * 1024,
    "timeout_seconds": 15,
    "concurrency": 1,
    "retry": 0,
}
GOVERNED_NETWORK_SECONDS = 13
OUTER_HARD_DEADLINE_SECONDS = 65
DELIVERY_STATE = Path(r"C:\Project\web_listening_new_delivery_state")
_WORKER_ARGUMENT = "--phase-20-soa-volatility-worker"
_ROBOTS_RESPONSE_BYTES_PER_CASE = LEGACY_HELPERS["_ROBOTS_RESPONSE_BYTES_PER_CASE"]
_build_evidence = VOLATILITY["build_evidence"]
_evidence_json = VOLATILITY["evidence_json"]
_safe_url_descriptor = VOLATILITY["safe_url_descriptor"]
_sanitize_errors = VOLATILITY["sanitize_errors"]
_url_is_safe = VOLATILITY["_url_is_safe"]
_SUCCESS_CORE_KEYS = {
    "classification",
    "limits",
    "samples",
    "schema_version",
    "system_totals",
}
_SUCCESS_EVIDENCE_KEYS = _SUCCESS_CORE_KEYS | {
    "authorization_window_sha256",
    "execution_order",
    "http_profile_checks",
    "old_commit",
    "outer_budget",
    "provenance",
    "site_key",
    "source_catalog_sha256",
    "target_snapshot_sha256",
    "profile_validation_inputs",
}
_CANONICAL_CORE_KEYS = _SUCCESS_CORE_KEYS - {"schema_version"}
_EVIDENCE_PREDICATE_ORDER = (
    "evidence.top_level_shape",
    "evidence.schema_version",
    "evidence.sample_order",
    "evidence.canonical_core",
    "evidence.fixed_metadata",
    "evidence.fixed_digests",
    "evidence.execution_order",
    "evidence.fixed_requested_url",
    "evidence.allowed_final_origin",
    "evidence.outer_budget",
    "evidence.profile_validation_inputs",
    "evidence.profile_recomputation",
    "evidence.profile_check_schema",
)
_EVIDENCE_REASON_CODES = frozenset(_EVIDENCE_PREDICATE_ORDER)
_BUNDLE_REASON_CODES = frozenset(
    {"bundle.destination_exists", "bundle.prevalidation_failed", "bundle.write_failed"}
)


def _load_soa_target() -> (
    tuple[dict[str, object], dict[str, object], list[dict[str, object]]]
):
    snapshot, targets = PHASE_20_LIVE["_load_snapshot"]()
    target = targets.get("soa")
    if not isinstance(target, dict) or target.get("site_key") != "soa":
        pytest.fail("the fixed SOA target is unavailable")
    cases = PHASE_20_LIVE["_cases"](target)
    if [case.get("case_id") for case in cases] != ["monitor", "document"]:
        pytest.fail("the fixed SOA monitor/document case set drifted")
    return snapshot, target, cases


def _authorized_window_digest() -> str:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("SOA volatility diagnosis is offline by default")
    window = os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip()
    if not window:
        pytest.fail("a non-empty authorized live window is required")
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE", "").strip()
    if selector not in {"", "soa"}:
        pytest.fail("SOA volatility diagnosis accepts only WEB_LISTENING_LIVE_SITE=soa")
    return hashlib.sha256(window.encode("utf-8")).hexdigest()


def _offline_cases() -> list[dict[str, object]]:
    return [
        {
            "case_id": "monitor",
            "requested_url": "https://www.soa.org/",
            "minimum_words": 150,
            "minimum_document_links": 0,
        },
        {
            "case_id": "document",
            "requested_url": ("https://www.soa.org/publications/publications-landing/"),
            "minimum_words": 150,
            "minimum_document_links": 1,
        },
    ]


def _profile_descriptor_payload(profile: Mapping[str, str]) -> dict[str, object]:
    authority = PHASE_20_LIVE["HTTP_PROFILE_COMPATIBILITY"]
    descriptor = authority["describe_http_profile"](profile)
    return {
        "fields": [[key, value] for key, value in descriptor.fields],
        "sha256": descriptor.sha256,
    }


def _offline_http_profile(
    system: str, cases: list[dict[str, object]]
) -> dict[str, object]:
    authority = PHASE_20_LIVE["HTTP_PROFILE_COMPATIBILITY"]
    if system == "old":
        profile = authority["FROZEN_OLD_HTTP_REQUEST_PROFILE"]
        frozen_provenance = authority["FROZEN_OLD_HTTP_PROFILE_PROVENANCE"]
        provenance = {
            key: getattr(frozen_provenance, key)
            for key in frozen_provenance.__dataclass_fields__
        }
        identity: object = dict(authority["FROZEN_OLD_GATEWAY_IDENTITY"])
    else:
        profile = authority["WEB_HTTP_REQUEST_PROFILE"]
        provenance = "N/A"
        identity = "N/A"
    descriptor = _profile_descriptor_payload(profile)
    return PHASE_20_LIVE["_http_profile_system_evidence"](
        cases,
        provenance=provenance,
        identity=identity,
        authority=descriptor,
        observations=[[descriptor, descriptor] for _case in cases],
    )


def _offline_child_fixture(system: str) -> dict[str, object]:
    fixed_cases = _offline_cases()
    cases = []
    for index, case in enumerate(fixed_cases):
        usage = (
            {
                "requests": 2,
                "response_bytes": 100,
                "target_bytes": 100,
                "bytes_basis": "target_body",
                "within_budget": True,
            }
            if system == "old"
            else {
                "requests": 2,
                "transport_requests": 2,
                "bytes_received": 100,
                "transport_response_bytes": 100,
                "target_bytes": 100,
                "bytes_basis": "target_body",
                "within_budget": True,
            }
        )
        cases.append(
            {
                "case_id": case["case_id"],
                "requested_url": case["requested_url"],
                "final_url": case["requested_url"],
                "status": 200,
                "mime_type": "text/html",
                "content_sha256": ("a" if index == 0 else "b") * 64,
                "content_bytes": 100,
                "word_count": 150,
                "document_link_count": 1 if case["case_id"] == "document" else 0,
                "outcome": "success",
                "usage": usage,
                "error": None,
            }
        )
    response_bytes = (
        200 + 2 * _ROBOTS_RESPONSE_BYTES_PER_CASE if system == "old" else 200
    )
    return {
        "http_profile": _offline_http_profile(system, fixed_cases),
        "cases": cases,
        "budget": {
            "requests": 4,
            "response_bytes": response_bytes,
            "elapsed_seconds": 1.0,
            "max_requests": SAMPLE_LIMITS["max_total_requests"],
            "max_response_bytes": SAMPLE_LIMITS["max_total_response_bytes"],
            "max_seconds": SAMPLE_LIMITS["timeout_seconds"],
            "governed_network_seconds": GOVERNED_NETWORK_SECONDS,
            "concurrency": 1,
            "retry": 0,
        },
    }


def _finite_nonnegative(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _process_failure(system: str, suffix: str, error_type: str) -> dict[str, str]:
    return {"code": f"{system}.{suffix}", "error_type": error_type}


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            process_group_id = getattr(os, "getpgid")(process.pid)
            getattr(os, "killpg")(process_group_id, getattr(signal, "SIGKILL"))
        except (OSError, ProcessLookupError):
            pass
    if process.poll() is None:
        process.kill()


def _supervise_worker(
    command: list[str], payload: dict[str, object], *, timeout_seconds: float
) -> tuple[dict[str, object] | None, dict[str, object]]:
    environment = os.environ.copy()
    for name in (
        "WEB_LISTENING_RUN_LIVE",
        "WEB_LISTENING_LIVE_AUTHORIZED_WINDOW",
        "WEB_LISTENING_LIVE_SITE",
    ):
        environment.pop(name, None)
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    process_group: dict[str, object]
    if os.name == "nt":
        process_group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    else:
        process_group = {"start_new_session": True}
    try:
        process = subprocess.Popen(  # pylint: disable=consider-using-with
            command,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **process_group,
        )
    except OSError as exc:
        return None, {
            "outcome": "not-started",
            "return_code": "N/A",
            "errors": [
                _process_failure("volatility", "worker_spawn", type(exc).__name__)
            ],
        }
    try:
        stdout, _stderr = process.communicate(
            json.dumps(payload), timeout=timeout_seconds
        )
    except subprocess.TimeoutExpired:
        _terminate_process_tree(process)
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
        return None, {
            "outcome": "outer-deadline",
            "return_code": "N/A",
            "errors": [
                {
                    "code": "volatility.outer_deadline",
                    "error_type": "TimeoutExpired",
                }
            ],
        }
    if process.returncode != 0:
        return None, {
            "outcome": "exited-failure",
            "return_code": process.returncode,
            "errors": [_process_failure("volatility", "worker_failure", "WorkerError")],
        }
    lines = [line for line in stdout.splitlines() if line.strip()]
    try:
        evidence = json.loads(lines[-1])
    except (IndexError, json.JSONDecodeError):
        evidence = None
    if not isinstance(evidence, dict):
        return None, {
            "outcome": "invalid-evidence",
            "return_code": process.returncode,
            "errors": [_process_failure("volatility", "worker_output", "SchemaError")],
        }
    return evidence, {
        "outcome": "exited-success",
        "return_code": process.returncode,
        "errors": [],
    }


def _run_probe_process(
    command: list[str],
    cwd: Path,
    environment: dict[str, str],
    payload: dict[str, object],
    *,
    system: str,
    outer_deadline: float,
) -> tuple[dict[str, object] | None, dict[str, object]]:
    remaining = outer_deadline - time.monotonic()
    if remaining <= 0:
        return None, {
            "outcome": "outer-deadline",
            "return_code": "N/A",
            "errors": [_process_failure(system, "outer_deadline", "TimeoutError")],
        }
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=min(SAMPLE_LIMITS["timeout_seconds"], remaining),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, {
            "outcome": "timeout",
            "return_code": "N/A",
            "errors": [_process_failure(system, "process_timeout", "TimeoutExpired")],
        }
    except OSError as exc:
        return None, {
            "outcome": "not-started",
            "return_code": "N/A",
            "errors": [_process_failure(system, "process_spawn", type(exc).__name__)],
        }
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        return None, {
            "outcome": "exited-without-evidence",
            "return_code": completed.returncode,
            "errors": [_process_failure(system, "no_output", "NoOutput")],
        }
    try:
        output = json.loads(lines[-1])
    except json.JSONDecodeError:
        return None, {
            "outcome": "invalid-evidence",
            "return_code": completed.returncode,
            "errors": [_process_failure(system, "output_parse", "JSONDecodeError")],
        }
    if not isinstance(output, dict):
        return None, {
            "outcome": "invalid-evidence",
            "return_code": completed.returncode,
            "errors": [_process_failure(system, "output_schema", "SchemaError")],
        }
    success = completed.returncode == 0
    return output, {
        "outcome": "exited-success" if success else "exited-failure",
        "return_code": completed.returncode,
        "errors": (
            [] if success else [_process_failure(system, "process_failure", "N/A")]
        ),
    }


def _normalized_usage(record: Mapping[str, object], system: str) -> dict[str, object]:
    raw = record.get("usage")
    raw = raw if isinstance(raw, Mapping) else {}
    if system == "old":
        requests = raw.get("requests")
        response_bytes = raw.get("response_bytes")
        if _nonnegative_int(response_bytes) and raw.get("bytes_basis") == "target_body":
            response_bytes += _ROBOTS_RESPONSE_BYTES_PER_CASE
    else:
        requests = raw.get("transport_requests")
        response_bytes = raw.get("transport_response_bytes")
    return {
        "requests": requests,
        "response_bytes": response_bytes,
        "target_bytes": raw.get("target_bytes"),
        "within_budget": raw.get("within_budget") is True,
    }


def _normalized_case(
    raw: object,
    expected: Mapping[str, object],
    system: str,
) -> dict[str, object]:
    record = raw if isinstance(raw, Mapping) else {}
    errors = _sanitize_errors(record.get("error"))
    requested = _safe_url_descriptor(record.get("requested_url"))
    expected_requested = _safe_url_descriptor(expected["requested_url"])
    if record.get("case_id") != expected["case_id"] or requested != expected_requested:
        errors = _sanitize_errors(
            [*errors, {"code": "volatility.case_schema", "error_type": "SchemaError"}]
        )
    expected_thresholds = {
        "minimum_words": expected.get("minimum_words"),
        "minimum_document_links": expected.get("minimum_document_links"),
    }
    observed_thresholds = {
        "word_count": record.get("word_count"),
        "document_link_count": record.get("document_link_count"),
    }
    thresholds_met = (
        _nonnegative_int(expected_thresholds["minimum_words"])
        and _nonnegative_int(expected_thresholds["minimum_document_links"])
        and _nonnegative_int(observed_thresholds["word_count"])
        and _nonnegative_int(observed_thresholds["document_link_count"])
        and observed_thresholds["word_count"] >= expected_thresholds["minimum_words"]
        and observed_thresholds["document_link_count"]
        >= expected_thresholds["minimum_document_links"]
    )
    if not thresholds_met:
        errors = _sanitize_errors(
            [
                *errors,
                {
                    "code": "volatility.threshold_not_met",
                    "error_type": "ThresholdError",
                },
            ]
        )
    return {
        "case_id": expected["case_id"],
        "outcome": record.get("outcome", "failure"),
        "status": record.get("status"),
        "mime_type": record.get("mime_type"),
        "requested_url": requested,
        "final_url": _safe_url_descriptor(record.get("final_url")),
        "content_sha256": record.get("content_sha256"),
        "content_bytes": record.get("content_bytes"),
        "thresholds": {
            "expected": expected_thresholds,
            "observed": observed_thresholds,
            "met": thresholds_met,
        },
        "usage": _normalized_usage(record, system),
        "error": errors,
    }


def _normalized_budget(
    raw: object, normalized_cases: list[dict[str, object]]
) -> dict[str, object]:
    budget = raw if isinstance(raw, Mapping) else {}
    requests = budget.get("requests")
    response_bytes = budget.get("response_bytes")
    elapsed = budget.get("elapsed_seconds")
    declared = {
        "max_requests": budget.get("max_requests"),
        "max_response_bytes": budget.get("max_response_bytes"),
        "max_seconds": budget.get("max_seconds"),
        "governed_network_seconds": budget.get("governed_network_seconds"),
        "concurrency": budget.get("concurrency"),
        "retry": budget.get("retry"),
    }
    counts = [
        case["usage"][field]
        for case in normalized_cases
        for field in ("requests", "response_bytes")
    ]
    within = (
        _nonnegative_int(requests)
        and _nonnegative_int(response_bytes)
        and _finite_nonnegative(elapsed)
        and declared
        == {
            "max_requests": SAMPLE_LIMITS["max_total_requests"],
            "max_response_bytes": SAMPLE_LIMITS["max_total_response_bytes"],
            "max_seconds": SAMPLE_LIMITS["timeout_seconds"],
            "governed_network_seconds": GOVERNED_NETWORK_SECONDS,
            "concurrency": 1,
            "retry": 0,
        }
        and all(_nonnegative_int(value) for value in counts)
        and sum(case["usage"]["requests"] for case in normalized_cases) == requests
        and sum(case["usage"]["response_bytes"] for case in normalized_cases)
        == response_bytes
        and requests <= SAMPLE_LIMITS["max_total_requests"]
        and response_bytes <= SAMPLE_LIMITS["max_total_response_bytes"]
        and elapsed <= SAMPLE_LIMITS["timeout_seconds"]
    )
    return {
        "requests": requests,
        "response_bytes": response_bytes,
        "elapsed_seconds": elapsed,
        **declared,
        "within_budget": within,
    }


def _normalize_child(
    raw: object,
    process: Mapping[str, object],
    *,
    system: str,
    sequence: int,
    sample_number: int,
    cases: list[dict[str, object]],
) -> dict[str, object]:
    output = raw if isinstance(raw, Mapping) else {}
    raw_cases = output.get("cases")
    raw_cases = raw_cases if isinstance(raw_cases, list) else []
    by_id = {
        item.get("case_id"): item
        for item in raw_cases
        if isinstance(item, Mapping) and isinstance(item.get("case_id"), str)
    }
    case_set_is_exact = (
        len(raw_cases) == len(cases)
        and len(by_id) == len(raw_cases)
        and set(by_id) == {case["case_id"] for case in cases}
    )
    normalized_cases = [
        _normalized_case(by_id.get(case["case_id"]), case, system) for case in cases
    ]
    errors = _sanitize_errors(process.get("errors"))
    if (
        process.get("outcome") != "exited-success" or process.get("return_code") != 0
    ) and not errors:
        errors = [{"code": f"{system}.process_failure", "error_type": "N/A"}]
    if not isinstance(raw, Mapping) or not case_set_is_exact:
        errors = _sanitize_errors(
            [
                *errors,
                {"code": f"{system}.output_schema", "error_type": "SchemaError"},
            ]
        )
    return {
        "sequence": sequence,
        "system": system,
        "sample": sample_number,
        "process_outcome": process.get("outcome", "invalid-evidence"),
        "process_return_code": process.get("return_code", "N/A"),
        "cases": normalized_cases,
        "budget": _normalized_budget(output.get("budget"), normalized_cases),
        "error": errors,
    }


def _prepare_old_context(
    tmp_path: Path,
    window_digest: str,
) -> dict[str, object]:
    try:
        provenance = PHASE_20_LIVE["_verify_old_http_profile_provenance"]()
        checkout, source = PHASE_20_LIVE["_extract_old_checkout"](tmp_path)
        fingerprint = PHASE_20_LIVE["_legacy_environment_fingerprint"]()
        fingerprint["source"] = source
    except (
        OSError,
        RuntimeError,
        ValueError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ) as exc:
        return {
            "ready": False,
            "errors": [_process_failure("old", "setup_failure", type(exc).__name__)],
        }
    if not PHASE_20_LIVE["_legacy_environment_matches"](fingerprint):
        return {
            "ready": False,
            "errors": [
                _process_failure("old", "environment_mismatch", "FingerprintMismatch")
            ],
        }
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(checkout)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    return {
        "ready": True,
        "checkout": checkout,
        "environment": environment,
        "environment_evidence": {
            "fingerprint": fingerprint,
            "authorization_window_sha256": window_digest,
            "verification": "matched",
        },
        "profile_provenance": provenance,
    }


def _run_old_sample(
    old_context: Mapping[str, object],
    target: Mapping[str, object],
    cases: list[dict[str, object]],
    *,
    sequence: int,
    sample_number: int,
    outer_deadline: float,
) -> tuple[dict[str, object], dict[str, object] | None]:
    payload = {
        "old_commit": OLD_COMMIT,
        "environment": old_context["environment_evidence"],
        "governed_network_timeout_seconds": GOVERNED_NETWORK_SECONDS,
        "allowed_origins": target["allowed_origins"],
        "allowed_domains": [
            str(origin).split("://", 1)[1] for origin in target["allowed_origins"]
        ],
        "authority_sha256": hashlib.sha256(
            json.dumps(cases, sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "http_profile": {
            "provenance": old_context["profile_provenance"],
            "identity": dict(
                PHASE_20_LIVE["HTTP_PROFILE_COMPATIBILITY"][
                    "FROZEN_OLD_GATEWAY_IDENTITY"
                ]
            ),
        },
        "limits": SAMPLE_LIMITS,
        "cases": cases,
    }
    raw, process = _run_probe_process(
        [sys.executable, str(LEGACY_PROBE)],
        old_context["checkout"],
        old_context["environment"],
        payload,
        system="old",
        outer_deadline=outer_deadline,
    )
    return (
        _normalize_child(
            raw,
            process,
            system="old",
            sequence=sequence,
            sample_number=sample_number,
            cases=cases,
        ),
        raw,
    )


def _run_new_sample(
    tmp_path: Path,
    target: Mapping[str, object],
    cases: list[dict[str, object]],
    window_digest: str,
    *,
    sequence: int,
    sample_number: int,
    outer_deadline: float,
) -> tuple[dict[str, object], dict[str, object] | None]:
    revision = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    payload = {
        "environment": {
            "checkout": "<issue-worktree>",
            "revision": revision,
            "python": sys.version.split()[0],
            "authorization_window_sha256": window_digest,
            "verification": "matched",
        },
        "governed_network_timeout_seconds": GOVERNED_NETWORK_SECONDS,
        "limits": SAMPLE_LIMITS,
        "cases": cases,
        "target": {
            "site_key": target["site_key"],
            "allowed_origins": target["allowed_origins"],
        },
        "artifact_root": str(tmp_path / f"new-sample-{sample_number}"),
    }
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    raw, process = _run_probe_process(
        [sys.executable, str(NEW_PROBE)],
        ROOT,
        environment,
        payload,
        system="new",
        outer_deadline=outer_deadline,
    )
    return (
        _normalize_child(
            raw,
            process,
            system="new",
            sequence=sequence,
            sample_number=sample_number,
            cases=cases,
        ),
        raw,
    )


def _profile_descriptor_evidence_is_safe(value: object) -> bool:
    if value == "N/A":
        return True
    if not isinstance(value, dict) or set(value) != {"fields", "sha256"}:
        return False
    fields = value["fields"]
    sha256 = value["sha256"]
    field_names = set(
        PHASE_20_LIVE["HTTP_PROFILE_COMPATIBILITY"]["WEB_HTTP_REQUEST_PROFILE"]
    )
    return (
        isinstance(fields, list)
        and len(fields) == len(field_names)
        and all(
            isinstance(item, list)
            and len(item) == 2
            and item[0] in field_names
            and isinstance(item[1], str)
            for item in fields
        )
        and {item[0] for item in fields} == field_names
        and isinstance(sha256, str)
        and len(sha256) == 64
        and all(character in "0123456789abcdef" for character in sha256)
    )


def _profile_case_evidence_is_safe(value: object, case_id: str) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "case_id",
        "collapsed",
        "observations",
        "request_count",
    }:
        return False
    observations = value["observations"]
    request_count = value["request_count"]
    if (
        value["case_id"] != case_id
        or not _nonnegative_int(request_count)
        or request_count > SAMPLE_LIMITS["max_total_requests"]
        or not isinstance(observations, list)
        or request_count != len(observations)
        or not all(
            _profile_descriptor_evidence_is_safe(item) and item != "N/A"
            for item in observations
        )
    ):
        return False
    collapsed = value["collapsed"]
    expected_collapsed: object = "N/A"
    if observations and all(item == observations[0] for item in observations):
        expected_collapsed = observations[0]
    elif observations:
        expected_collapsed = "drift"
    return collapsed == expected_collapsed


def _profile_evidence_is_safe(
    value: object, system: str, cases: list[dict[str, object]]
) -> bool:
    if value == "N/A":
        return True
    if not isinstance(value, dict) or set(value) != {
        "authority",
        "cases",
        "identity",
        "provenance",
        "schema_version",
    }:
        return False
    authority = PHASE_20_LIVE["HTTP_PROFILE_COMPATIBILITY"]
    frozen_provenance = authority["FROZEN_OLD_HTTP_PROFILE_PROVENANCE"]
    expected_provenance = {
        key: getattr(frozen_provenance, key)
        for key in frozen_provenance.__dataclass_fields__
    }
    expected_identity = dict(authority["FROZEN_OLD_GATEWAY_IDENTITY"])
    provenance = value["provenance"]
    identity = value["identity"]
    rows = value["cases"]
    return (
        value["schema_version"] == "phase-20-http-profile-evidence.v1"
        and (
            (system == "old" and provenance in ("N/A", expected_provenance))
            or (system == "new" and provenance == "N/A")
        )
        and (
            (system == "old" and identity in ("N/A", expected_identity))
            or (system == "new" and identity == "N/A")
        )
        and _profile_descriptor_evidence_is_safe(value["authority"])
        and isinstance(rows, list)
        and len(rows) == len(cases)
        and all(
            _profile_case_evidence_is_safe(row, str(case["case_id"]))
            for row, case in zip(rows, cases, strict=True)
        )
    )


def _profile_validation_inputs(
    raw_results: Mapping[tuple[str, int], object],
    cases: list[dict[str, object]],
) -> list[dict[str, object]]:
    inputs = []
    for sample_number in (1, 2):
        row: dict[str, object] = {"sample": sample_number}
        for system in ("old", "new"):
            raw = raw_results.get((system, sample_number))
            profile = raw.get("http_profile") if isinstance(raw, dict) else None
            row[system] = (
                json.loads(json.dumps(profile))
                if _profile_evidence_is_safe(profile, system, cases)
                else "N/A"
            )
        inputs.append(row)
    return inputs


def _profile_validation_inputs_are_valid(
    value: object, cases: list[dict[str, object]]
) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 2
        and all(
            isinstance(row, dict)
            and set(row) == {"new", "old", "sample"}
            and row["sample"] == sample_number
            and _profile_evidence_is_safe(row["old"], "old", cases)
            and _profile_evidence_is_safe(row["new"], "new", cases)
            for sample_number, row in enumerate(value, start=1)
        )
    )


def _recomputed_profile_checks(
    validation_inputs: list[dict[str, object]],
    samples: list[dict[str, object]],
    cases: list[dict[str, object]],
) -> list[dict[str, object]]:
    checks = []
    authority = PHASE_20_LIVE["HTTP_PROFILE_COMPATIBILITY"]
    frozen_provenance = authority["FROZEN_OLD_HTTP_PROFILE_PROVENANCE"]
    frozen_identity = authority["FROZEN_OLD_GATEWAY_IDENTITY"]
    for sample_number, validation_input in enumerate(validation_inputs, start=1):
        system_samples = {
            sample["system"]: sample
            for sample in samples
            if sample["sample"] == sample_number
        }
        old_profile = validation_input["old"]
        if isinstance(old_profile, dict):
            old_profile = dict(old_profile)
            provenance = old_profile["provenance"]
            identity = old_profile["identity"]
            if isinstance(provenance, dict):
                old_profile["provenance"] = {
                    key: provenance[key]
                    for key in frozen_provenance.__dataclass_fields__
                }
            if isinstance(identity, dict):
                old_profile["identity"] = {
                    key: identity[key] for key in frozen_identity
                }
        old = {
            "http_profile": old_profile,
            "cases": [
                {
                    "outcome": row["outcome"],
                    "usage": {"requests": row["usage"]["requests"]},
                }
                for row in system_samples["old"]["cases"]
            ],
        }
        new = {
            "http_profile": validation_input["new"],
            "cases": [
                {
                    "usage": {"transport_requests": row["usage"]["requests"]},
                }
                for row in system_samples["new"]["cases"]
            ],
        }
        rows, failures = PHASE_20_LIVE["_http_profile_compatibility_gate"](
            old, new, cases
        )
        blockers = sorted(set(failures))
        checks.append(
            {
                "sample": sample_number,
                "cases": [
                    {
                        "case_id": row.get("case_id", "N/A"),
                        "kind": row.get("kind", "inconclusive"),
                        "code": row.get("code", "profile.evidence_invalid"),
                    }
                    for row in rows
                ],
                "within_authority": not blockers,
                "blockers": blockers,
            }
        )
    return checks


def _profile_checks(
    validation_inputs: list[dict[str, object]],
    cases: list[dict[str, object]],
    samples: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not _profile_validation_inputs_are_valid(validation_inputs, cases):
        raise ValueError("profile validation inputs are not safe")
    checks = _recomputed_profile_checks(validation_inputs, samples, cases)
    for check in checks:
        if check["blockers"]:
            for sample in samples:
                if sample["sample"] == check["sample"]:
                    sample["error"] = _sanitize_errors(
                        [
                            *sample["error"],
                            {
                                "code": "volatility.http_profile_blocker",
                                "error_type": "N/A",
                            },
                        ]
                    )
    return checks


def _run_diagnosis(tmp_path: Path, window_digest: str) -> dict[str, object]:
    started = time.monotonic()
    outer_deadline = started + OUTER_HARD_DEADLINE_SECONDS
    snapshot, target, cases = _load_soa_target()
    old_context = _prepare_old_context(tmp_path / "legacy", window_digest)
    samples: list[dict[str, object]] = []
    raw_results: dict[tuple[str, int], object] = {}
    for sequence, (system, sample_number) in enumerate(EXECUTION_ORDER, start=1):
        try:
            if system == "old" and old_context.get("ready") is True:
                sample, raw = _run_old_sample(
                    old_context,
                    target,
                    cases,
                    sequence=sequence,
                    sample_number=sample_number,
                    outer_deadline=outer_deadline,
                )
            elif system == "old":
                process = {
                    "outcome": "not-started",
                    "return_code": "N/A",
                    "errors": old_context.get("errors", []),
                }
                sample = _normalize_child(
                    None,
                    process,
                    system="old",
                    sequence=sequence,
                    sample_number=sample_number,
                    cases=cases,
                )
                raw = None
            else:
                sample, raw = _run_new_sample(
                    tmp_path,
                    target,
                    cases,
                    window_digest,
                    sequence=sequence,
                    sample_number=sample_number,
                    outer_deadline=outer_deadline,
                )
        except Exception as exc:
            sample = _normalize_child(
                None,
                {
                    "outcome": "boundary-failure",
                    "return_code": "N/A",
                    "errors": [
                        _process_failure(system, "boundary", type(exc).__name__)
                    ],
                },
                system=system,
                sequence=sequence,
                sample_number=sample_number,
                cases=cases,
            )
            raw = None
        samples.append(sample)
        raw_results[(system, sample_number)] = raw
    profile_validation_inputs = _profile_validation_inputs(raw_results, cases)
    profile_checks = _profile_checks(profile_validation_inputs, cases, samples)
    elapsed = round(time.monotonic() - started, 3)
    outer_within_budget = elapsed <= OUTER_HARD_DEADLINE_SECONDS
    if not outer_within_budget:
        for sample in samples:
            sample["error"] = _sanitize_errors(
                [
                    *sample["error"],
                    {
                        "code": "volatility.outer_deadline",
                        "error_type": "TimeoutError",
                    },
                ]
            )
    evidence = _build_evidence(samples)
    evidence.update(
        {
            "site_key": "soa",
            "old_commit": OLD_COMMIT,
            "source_catalog_sha256": snapshot["source_catalog_sha256"],
            "target_snapshot_sha256": hashlib.sha256(TARGETS.read_bytes()).hexdigest(),
            "authorization_window_sha256": window_digest,
            "provenance": target["provenance"],
            "execution_order": [
                {
                    "sequence": sequence,
                    "system": system,
                    "sample": sample_number,
                }
                for sequence, (system, sample_number) in enumerate(
                    EXECUTION_ORDER, start=1
                )
            ],
            "http_profile_checks": profile_checks,
            "profile_validation_inputs": profile_validation_inputs,
            "outer_budget": {
                "elapsed_seconds": elapsed,
                "hard_deadline_seconds": OUTER_HARD_DEADLINE_SECONDS,
                "within_budget": outer_within_budget,
            },
        }
    )
    return evidence


def _supervised_failure_evidence(
    process: Mapping[str, object],
    elapsed_seconds: float,
    *,
    worker_validation: Mapping[str, object] | None = None,
    audit_bundle: Mapping[str, object] | None = None,
) -> dict[str, object]:
    errors = _sanitize_errors(process.get("errors")) or [
        {"code": "volatility.worker_failure", "error_type": "WorkerError"}
    ]
    process_outcome = process.get("outcome")
    if process_outcome not in {
        "exited-failure",
        "invalid-evidence",
        "not-started",
        "outer-deadline",
    }:
        process_outcome = "invalid-evidence"
    return_code = process.get("return_code", "N/A")
    if not isinstance(return_code, int) or isinstance(return_code, bool):
        return_code = "N/A"
    samples = []
    fixed_cases = _offline_cases()
    for sequence, (system, sample_number) in enumerate(EXECUTION_ORDER, start=1):
        samples.append(
            {
                "sequence": sequence,
                "system": system,
                "sample": sample_number,
                "process_outcome": "not-observed",
                "process_return_code": "N/A",
                "cases": [
                    {
                        "case_id": case["case_id"],
                        "outcome": "not-observed",
                        "status": None,
                        "mime_type": None,
                        "requested_url": _safe_url_descriptor(case["requested_url"]),
                        "final_url": _safe_url_descriptor(None),
                        "content_sha256": None,
                        "content_bytes": None,
                        "thresholds": {
                            "expected": {
                                "minimum_words": case["minimum_words"],
                                "minimum_document_links": case[
                                    "minimum_document_links"
                                ],
                            },
                            "observed": {
                                "word_count": None,
                                "document_link_count": None,
                            },
                            "met": False,
                        },
                        "usage": {
                            "requests": "N/A",
                            "response_bytes": "N/A",
                            "target_bytes": "N/A",
                            "within_budget": False,
                        },
                        "error": errors,
                    }
                    for case in fixed_cases
                ],
                "budget": {
                    "requests": "N/A",
                    "response_bytes": "N/A",
                    "elapsed_seconds": "N/A",
                    "max_requests": SAMPLE_LIMITS["max_total_requests"],
                    "max_response_bytes": SAMPLE_LIMITS["max_total_response_bytes"],
                    "max_seconds": SAMPLE_LIMITS["timeout_seconds"],
                    "governed_network_seconds": GOVERNED_NETWORK_SECONDS,
                    "concurrency": 1,
                    "retry": 0,
                    "within_budget": False,
                },
                "error": errors,
            }
        )
    evidence = _build_evidence(samples)
    evidence.update(
        {
            "site_key": "soa",
            "execution_order": [
                {"sequence": sequence, "system": system, "sample": sample_number}
                for sequence, (system, sample_number) in enumerate(
                    EXECUTION_ORDER, start=1
                )
            ],
            "outer_budget": {
                "elapsed_seconds": round(elapsed_seconds, 3),
                "hard_deadline_seconds": OUTER_HARD_DEADLINE_SECONDS,
                "within_budget": process.get("outcome") != "outer-deadline"
                and elapsed_seconds <= OUTER_HARD_DEADLINE_SECONDS,
            },
            "worker_process": {
                "outcome": process_outcome,
                "return_code": return_code,
                "error": errors,
            },
            "error": errors,
        }
    )
    if worker_validation is not None:
        evidence["worker_validation"] = dict(worker_validation)
    if audit_bundle is not None:
        evidence["audit_bundle"] = dict(audit_bundle)
    return evidence


def _expected_execution_order() -> list[dict[str, object]]:
    return [
        {"sequence": sequence, "system": system, "sample": sample_number}
        for sequence, (system, sample_number) in enumerate(EXECUTION_ORDER, start=1)
    ]


def _authorized_profile_nonblocker() -> tuple[str, str] | None:
    authority = PHASE_20_LIVE["HTTP_PROFILE_COMPATIBILITY"]
    try:
        result = authority["classify_http_profile_compatibility"](
            authority["describe_http_profile"](
                authority["FROZEN_OLD_HTTP_REQUEST_PROFILE"]
            ),
            authority["describe_http_profile"](authority["WEB_HTTP_REQUEST_PROFILE"]),
            old_provenance=authority["FROZEN_OLD_HTTP_PROFILE_PROVENANCE"],
            old_identity=authority["FROZEN_OLD_GATEWAY_IDENTITY"],
        )
        authorized = (result.kind.value, result.code)
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    if authorized != (
        "explained_fixed_difference",
        "profile.fixed_old_accept_encoding",
    ):
        return None
    return authorized


def _profile_checks_are_valid(value: object, samples: list[dict[str, object]]) -> bool:
    authorized_nonblocker = _authorized_profile_nonblocker()
    if authorized_nonblocker is None:
        return False
    if not isinstance(value, list) or len(value) != 2:
        return False
    for sample_number, check in enumerate(value, start=1):
        if not isinstance(check, dict) or set(check) != {
            "blockers",
            "cases",
            "sample",
            "within_authority",
        }:
            return False
        rows = check["cases"]
        blockers = check["blockers"]
        if (
            check["sample"] != sample_number
            or not isinstance(rows, list)
            or not isinstance(blockers, list)
            or blockers != sorted(set(blockers))
            or not all(isinstance(item, str) and item for item in blockers)
            or not isinstance(check["within_authority"], bool)
            or check["within_authority"] != (not blockers)
        ):
            return False
        if rows:
            if len(rows) != len(VOLATILITY["CASE_IDS"]):
                return False
            expected_blockers = []
            for case_id, row in zip(VOLATILITY["CASE_IDS"], rows, strict=True):
                if not isinstance(row, dict) or set(row) != {
                    "case_id",
                    "code",
                    "kind",
                }:
                    return False
                kind = row["kind"]
                code = row["code"]
                if (
                    row["case_id"] != case_id
                    or kind
                    not in {"blocker", "exact_match", "explained_fixed_difference"}
                    or not isinstance(code, str)
                    or not code.startswith("profile.")
                ):
                    return False
                if kind == "blocker":
                    expected_blockers.append(f"{case_id}:http_profile")
                elif (kind, code) != authorized_nonblocker:
                    return False
            if blockers != sorted(expected_blockers):
                return False
        elif blockers not in (
            ["profile.evidence_invalid"],
            ["profile.evidence_missing"],
        ):
            return False
        expected_sample_error = not check["within_authority"]
        round_samples = [
            sample for sample in samples if sample.get("sample") == sample_number
        ]
        if len(round_samples) != 2 or any(
            (
                "volatility.http_profile_blocker"
                in {item.get("code") for item in sample["error"]}
            )
            != expected_sample_error
            for sample in round_samples
        ):
            return False
    return True


def _fixed_url_predicates(
    samples: list[dict[str, object]],
    target: dict[str, object],
    cases: list[dict[str, object]],
) -> tuple[bool, bool]:
    allowed_origins = target.get("allowed_origins")
    if not isinstance(allowed_origins, list) or not allowed_origins:
        return False, False
    allowed = set()
    for origin in allowed_origins:
        descriptor = _safe_url_descriptor(origin)
        if not _url_is_safe(descriptor):
            return False, False
        allowed.add(
            (
                descriptor["scheme"],
                descriptor["host"],
                descriptor["effective_port"],
            )
        )
    requested_urls_match = True
    final_origins_match = True
    unavailable = _safe_url_descriptor(None)
    for sample in samples:
        rows = sample.get("cases")
        if not isinstance(rows, list) or len(rows) != len(cases):
            return False, False
        for row, case in zip(rows, cases, strict=True):
            if not isinstance(row, dict):
                return False, False
            requested = row.get("requested_url")
            final = row.get("final_url")
            failed = row.get("outcome") == "failure"
            requested_urls_match = requested_urls_match and (
                requested == _safe_url_descriptor(case["requested_url"])
                or (failed and requested == unavailable)
            )
            final_origins_match = final_origins_match and (
                (
                    _url_is_safe(final)
                    and (
                        final["scheme"],
                        final["host"],
                        final["effective_port"],
                    )
                    in allowed
                )
                or (failed and final == unavailable)
            )
    return requested_urls_match, final_origins_match


def _fixed_urls_are_valid(
    samples: list[dict[str, object]],
    target: dict[str, object],
    cases: list[dict[str, object]],
) -> bool:
    return all(_fixed_url_predicates(samples, target, cases))


def _success_evidence_audit(evidence: object, window_digest: str) -> dict[str, object]:
    predicates = {reason: False for reason in _EVIDENCE_PREDICATE_ORDER}
    record = evidence if isinstance(evidence, dict) else {}
    predicates["evidence.top_level_shape"] = (
        isinstance(evidence, dict) and set(evidence) == _SUCCESS_EVIDENCE_KEYS
    )
    predicates["evidence.schema_version"] = (
        record.get("schema_version") == "phase-20-soa-volatility-evidence.v1"
    )
    samples = record.get("samples")
    predicates["evidence.sample_order"] = (
        isinstance(samples, list)
        and len(samples) == len(EXECUTION_ORDER)
        and all(isinstance(sample, dict) for sample in samples)
        and [(sample.get("system"), sample.get("sample")) for sample in samples]
        == list(EXECUTION_ORDER)
    )
    canonical_core = None
    try:
        if isinstance(samples, list):
            canonical_core = _build_evidence(samples)
    except (KeyError, OverflowError, TypeError, ValueError):
        canonical_core = None
    predicates["evidence.canonical_core"] = canonical_core is not None and all(
        record.get(key) == canonical_core[key] for key in _CANONICAL_CORE_KEYS
    )

    target = None
    cases = None
    try:
        snapshot, target, cases = _load_soa_target()
        target_snapshot_sha256 = hashlib.sha256(TARGETS.read_bytes()).hexdigest()
        predicates["evidence.fixed_metadata"] = (
            record.get("site_key") == "soa"
            and record.get("old_commit") == OLD_COMMIT
            and record.get("authorization_window_sha256") == window_digest
            and record.get("provenance") == target["provenance"]
        )
        predicates["evidence.fixed_digests"] = (
            record.get("source_catalog_sha256") == snapshot["source_catalog_sha256"]
            and record.get("target_snapshot_sha256") == target_snapshot_sha256
        )
        predicates["evidence.execution_order"] = (
            record.get("execution_order") == _expected_execution_order()
        )
        if isinstance(samples, list):
            requested_urls, final_origins = _fixed_url_predicates(
                samples, target, cases
            )
            predicates["evidence.fixed_requested_url"] = requested_urls
            predicates["evidence.allowed_final_origin"] = final_origins
    except (KeyError, OSError, TypeError, ValueError, pytest.fail.Exception):
        target = None
        cases = None

    outer = record.get("outer_budget")
    predicates["evidence.outer_budget"] = (
        isinstance(outer, dict)
        and set(outer) == {"elapsed_seconds", "hard_deadline_seconds", "within_budget"}
        and _finite_nonnegative(outer.get("elapsed_seconds"))
        and outer.get("hard_deadline_seconds") == OUTER_HARD_DEADLINE_SECONDS
        and outer.get("within_budget") is True
        and outer["elapsed_seconds"] <= OUTER_HARD_DEADLINE_SECONDS
    )

    validation_inputs = record.get("profile_validation_inputs")
    if cases is not None:
        predicates["evidence.profile_validation_inputs"] = (
            _profile_validation_inputs_are_valid(validation_inputs, cases)
        )
    if (
        predicates["evidence.profile_validation_inputs"]
        and isinstance(samples, list)
        and cases is not None
    ):
        try:
            recomputed_checks = _recomputed_profile_checks(
                validation_inputs, samples, cases
            )
            predicates["evidence.profile_recomputation"] = (
                record.get("http_profile_checks") == recomputed_checks
            )
        except (KeyError, OverflowError, TypeError, ValueError):
            pass
    if isinstance(samples, list):
        try:
            predicates["evidence.profile_check_schema"] = _profile_checks_are_valid(
                record.get("http_profile_checks"), samples
            )
        except (KeyError, OverflowError, TypeError, ValueError):
            pass
    reason_codes = [
        reason for reason in _EVIDENCE_PREDICATE_ORDER if not predicates[reason]
    ]
    return {
        "outcome": "valid" if not reason_codes else "invalid",
        "reason_codes": reason_codes,
        "predicates": predicates,
    }


def _success_evidence_is_valid(evidence: object, window_digest: str) -> bool:
    return _success_evidence_audit(evidence, window_digest)["outcome"] == "valid"


def _safe_worker_projection(
    evidence: object, audit: Mapping[str, object]
) -> dict[str, object]:
    record = evidence if isinstance(evidence, Mapping) else {}
    samples = record.get("samples")
    source = samples if isinstance(samples, list) else []
    try:
        canonical = _build_evidence(source)
    except (KeyError, OverflowError, TypeError, ValueError):
        canonical = _build_evidence([])
    content = []
    for sample in canonical["samples"]:
        sample_row = {
            "sequence": (
                sample["sequence"] if _nonnegative_int(sample["sequence"]) else "N/A"
            ),
            "system": sample["system"] if sample["system"] in {"old", "new"} else "N/A",
            "sample": sample["sample"] if _nonnegative_int(sample["sample"]) else "N/A",
            "cases": [],
        }
        for case in sample["cases"]:
            sha256 = case["content_sha256"]
            size = case["content_bytes"]
            sample_row["cases"].append(
                {
                    "case_id": (
                        case["case_id"]
                        if case["case_id"] in VOLATILITY["CASE_IDS"]
                        else "N/A"
                    ),
                    "content_sha256": (
                        sha256
                        if isinstance(sha256, str)
                        and len(sha256) == 64
                        and all(character in "0123456789abcdef" for character in sha256)
                        else "N/A"
                    ),
                    "content_bytes": size if _nonnegative_int(size) else "N/A",
                }
            )
        content.append(sample_row)
    return {
        "schema_version": "phase-20-soa-audit-projection.v1",
        "worker_validation": {
            "outcome": audit["outcome"],
            "reason_codes": list(audit["reason_codes"]),
            "predicates": dict(audit["predicates"]),
        },
        "worker_shape": {
            "top_level_key_count": len(record),
            "sample_count": len(source),
        },
        "canonical_core": {
            "classification": canonical["classification"],
            "sample_count": len(canonical["samples"]),
            "sha256": hashlib.sha256(
                _evidence_json(canonical).encode("utf-8")
            ).hexdigest(),
        },
        "sample_content": content,
    }


def _bundle_result(
    candidate: Path,
    *,
    outcome: str,
    manifest_sha256: str = "N/A",
    file_count: int = 0,
    reason_codes: list[str] | None = None,
) -> dict[str, object]:
    codes = reason_codes or []
    if any(code not in _BUNDLE_REASON_CODES for code in codes):
        codes = ["bundle.prevalidation_failed"]
    return {
        "outcome": outcome,
        "bundle_path": str(candidate),
        "manifest_sha256": manifest_sha256,
        "file_count": file_count,
        "reason_codes": codes,
    }


def _prevalidate_audit_bundle_destination(base: Path, window_digest: str) -> Path:
    if (
        not isinstance(window_digest, str)
        or len(window_digest) != 64
        or any(character not in "0123456789abcdef" for character in window_digest)
    ):
        raise ValueError("authorization digest is invalid")
    resolved_base = base.resolve(strict=True)
    if not resolved_base.is_dir():
        raise OSError("audit bundle base is not a directory")
    candidate = (resolved_base / f"issue-67-soa-audit-{window_digest}").resolve(
        strict=False
    )
    if candidate.parent != resolved_base:
        raise ValueError("audit bundle destination is outside its fixed base")
    if candidate.exists():
        raise FileExistsError("audit bundle destination already exists")
    return candidate


def _audit_artifact_sources(worker_root: Path) -> list[tuple[Path, Path]]:
    sources = []
    for sample_number in (1, 2):
        sample_root = (worker_root / f"new-sample-{sample_number}").resolve(
            strict=False
        )
        database = sample_root / "artifact.sqlite3"
        if database.is_file() and not database.is_symlink():
            sources.append(
                (database.resolve(strict=True), Path(sample_root.name) / database.name)
            )
        blob_root = sample_root / "blobs"
        if not blob_root.is_dir() or blob_root.is_symlink():
            continue
        for blob in sorted(blob_root.rglob("*.blob")):
            relative = blob.relative_to(blob_root)
            parts = relative.parts
            filename = blob.name
            sha256 = filename.removesuffix(".blob")
            if (
                not blob.is_file()
                or blob.is_symlink()
                or len(parts) != 2
                or len(parts[0]) != 2
                or len(sha256) != 64
                or parts[0] != sha256[:2]
                or any(character not in "0123456789abcdef" for character in sha256)
            ):
                continue
            resolved = blob.resolve(strict=True)
            if sample_root not in resolved.parents:
                continue
            sources.append((resolved, Path(sample_root.name) / "blobs" / relative))
    return sorted(sources, key=lambda item: item[1].as_posix())


def _manifest_file_row(path: Path, relative: Path) -> dict[str, object]:
    return {
        "path": relative.as_posix(),
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _persist_audit_bundle(
    candidate: Path,
    worker_root: Path,
    projection: Mapping[str, object],
    window_digest: str,
) -> dict[str, object]:
    staging = None
    try:
        if candidate.exists():
            return _bundle_result(
                candidate,
                outcome="failed",
                reason_codes=["bundle.destination_exists"],
            )
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".{candidate.name}.staging-", dir=str(candidate.parent)
            )
        )
        rows = []
        projection_path = staging / "projection.json"
        projection_path.write_text(_evidence_json(projection), encoding="utf-8")
        rows.append(_manifest_file_row(projection_path, Path("projection.json")))
        for source, relative in _audit_artifact_sources(worker_root):
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            rows.append(_manifest_file_row(destination, relative))
        rows.sort(key=lambda row: row["path"])
        manifest = {
            "schema_version": "phase-20-soa-audit-manifest.v1",
            "authorization_window_sha256": window_digest,
            "files": rows,
        }
        manifest_path = staging / "manifest.json"
        manifest_path.write_text(_evidence_json(manifest), encoding="utf-8")
        manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        if candidate.exists():
            raise FileExistsError("audit bundle destination appeared during staging")
        staging.rename(candidate)
        staging = None
        return _bundle_result(
            candidate,
            outcome="persisted",
            manifest_sha256=manifest_sha256,
            file_count=len(rows),
        )
    except FileExistsError:
        return _bundle_result(
            candidate,
            outcome="failed",
            reason_codes=["bundle.destination_exists"],
        )
    except (OSError, TypeError, ValueError):
        return _bundle_result(
            candidate,
            outcome="failed",
            reason_codes=["bundle.write_failed"],
        )
    finally:
        if staging is not None and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _run_supervised_diagnosis(
    tmp_path: Path,
    window_digest: str,
    *,
    bundle_base: Path | None = None,
) -> dict[str, object]:
    started = time.monotonic()
    candidate = None
    if bundle_base is not None:
        candidate_hint = (
            bundle_base.resolve(strict=False) / f"issue-67-soa-audit-{window_digest}"
        )
        try:
            candidate = _prevalidate_audit_bundle_destination(
                bundle_base, window_digest
            )
        except FileExistsError:
            return _supervised_failure_evidence(
                {
                    "outcome": "not-started",
                    "errors": [
                        {
                            "code": "volatility.bundle_failure",
                            "error_type": "N/A",
                        }
                    ],
                },
                time.monotonic() - started,
                audit_bundle=_bundle_result(
                    candidate_hint,
                    outcome="failed",
                    reason_codes=["bundle.destination_exists"],
                ),
            )
        except (OSError, TypeError, ValueError):
            return _supervised_failure_evidence(
                {
                    "outcome": "not-started",
                    "errors": [
                        {
                            "code": "volatility.bundle_failure",
                            "error_type": "N/A",
                        }
                    ],
                },
                time.monotonic() - started,
                audit_bundle=_bundle_result(
                    candidate_hint,
                    outcome="failed",
                    reason_codes=["bundle.prevalidation_failed"],
                ),
            )
    evidence, process = _supervise_worker(
        [sys.executable, "-B", str(Path(__file__).resolve()), _WORKER_ARGUMENT],
        {"tmp_path": str(tmp_path), "window_digest": window_digest},
        timeout_seconds=OUTER_HARD_DEADLINE_SECONDS,
    )
    worker_validation = _success_evidence_audit(evidence, window_digest)
    projection = _safe_worker_projection(evidence, worker_validation)
    audit_bundle = (
        _persist_audit_bundle(candidate, tmp_path, projection, window_digest)
        if candidate is not None
        else None
    )
    elapsed = time.monotonic() - started
    if elapsed > OUTER_HARD_DEADLINE_SECONDS:
        return _supervised_failure_evidence(
            {
                "outcome": "outer-deadline",
                "return_code": "N/A",
                "errors": [
                    {
                        "code": "volatility.outer_deadline",
                        "error_type": "TimeoutExpired",
                    }
                ],
            },
            elapsed,
            worker_validation=worker_validation,
            audit_bundle=audit_bundle,
        )
    if audit_bundle is not None and audit_bundle["outcome"] != "persisted":
        return _supervised_failure_evidence(
            {
                "outcome": "invalid-evidence",
                "errors": [
                    {
                        "code": "volatility.bundle_failure",
                        "error_type": "N/A",
                    }
                ],
            },
            elapsed,
            worker_validation=worker_validation,
            audit_bundle=audit_bundle,
        )
    if process.get("outcome") != "exited-success" or not isinstance(evidence, dict):
        return _supervised_failure_evidence(
            process,
            elapsed,
            worker_validation=worker_validation,
            audit_bundle=audit_bundle,
        )
    if worker_validation["outcome"] != "valid":
        return _supervised_failure_evidence(
            {
                "outcome": "invalid-evidence",
                "errors": [
                    {
                        "code": "volatility.worker_output",
                        "error_type": "SchemaError",
                    }
                ],
            },
            elapsed,
            worker_validation=worker_validation,
            audit_bundle=audit_bundle,
        )
    evidence.pop("profile_validation_inputs")
    evidence["outer_budget"] = {
        "elapsed_seconds": round(elapsed, 3),
        "hard_deadline_seconds": OUTER_HARD_DEADLINE_SECONDS,
        "within_budget": elapsed <= OUTER_HARD_DEADLINE_SECONDS,
    }
    evidence["worker_validation"] = worker_validation
    if audit_bundle is not None:
        evidence["audit_bundle"] = audit_bundle
    return evidence


def _worker_main() -> int:
    try:
        payload = json.loads(sys.stdin.read())
        if not isinstance(payload, dict) or set(payload) != {
            "tmp_path",
            "window_digest",
        }:
            return 2
        tmp_path = payload["tmp_path"]
        window_digest = payload["window_digest"]
        if (
            not isinstance(tmp_path, str)
            or not tmp_path
            or not isinstance(window_digest, str)
            or len(window_digest) != 64
            or any(character not in "0123456789abcdef" for character in window_digest)
        ):
            return 2
        print(
            _evidence_json(_run_diagnosis(Path(tmp_path), window_digest)),
            flush=True,
        )
    except Exception:  # worker errors are reduced by the supervisor
        return 1
    return 0


@pytest.mark.live
def test_phase_20_soa_volatility_live(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    window_digest = _authorized_window_digest()
    evidence: dict[str, object] = {
        "schema_version": "phase-20-soa-volatility-evidence.v1",
        "site_key": "soa",
        "classification": "inconclusive",
    }
    try:
        evidence = _run_supervised_diagnosis(
            tmp_path, window_digest, bundle_base=DELIVERY_STATE
        )
        assert evidence["classification"] in CLASSIFICATIONS
        assert [
            (sample["system"], sample["sample"]) for sample in evidence["samples"]
        ] == list(EXECUTION_ORDER)
        assert evidence["outer_budget"]["within_budget"] is True
    finally:
        with capsys.disabled():
            print(_evidence_json(evidence), flush=True)


if __name__ == "__main__":
    if sys.argv[1:] != [_WORKER_ARGUMENT]:
        raise SystemExit(2)
    raise SystemExit(_worker_main())
