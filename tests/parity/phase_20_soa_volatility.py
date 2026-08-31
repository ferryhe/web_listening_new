"""Pure offline classification for the bounded Phase 20 SOA diagnosis."""

# pylint: disable=too-many-boolean-expressions,too-many-return-statements

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

CLASSIFICATIONS = (
    "stable_match",
    "site_dynamic",
    "stable_cross_system_mismatch",
    "inconclusive",
)
CASE_IDS = ("monitor", "document")
SAMPLE_ORDER = (("old", 1), ("new", 1), ("old", 2), ("new", 2))
CASE_THRESHOLDS = {
    "monitor": {"minimum_words": 150, "minimum_document_links": 0},
    "document": {"minimum_words": 150, "minimum_document_links": 1},
}

_PER_SAMPLE_LIMITS = {
    "max_requests": 4,
    "max_response_bytes": 2 * 1024 * 1024,
    "max_seconds": 15,
    "governed_network_seconds": 13,
}
_PER_SYSTEM_LIMITS = {
    "max_requests": 8,
    "max_response_bytes": 4 * 1024 * 1024,
    "max_seconds": 30,
}
_OUTER_HARD_DEADLINE_SECONDS = 65
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_MIME_TYPE = re.compile(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+\Z")
_STABLE_ERROR_CODES = frozenset(
    {
        "new.boundary",
        "new.no_output",
        "new.outer_deadline",
        "new.output_parse",
        "new.output_schema",
        "new.process_failure",
        "new.process_spawn",
        "new.process_timeout",
        "old.boundary",
        "old.environment_mismatch",
        "old.no_output",
        "old.outer_deadline",
        "old.output_parse",
        "old.output_schema",
        "old.process_failure",
        "old.process_spawn",
        "old.process_timeout",
        "old.setup_failure",
        "volatility.case_schema",
        "volatility.bundle_failure",
        "volatility.http_profile_blocker",
        "volatility.outer_deadline",
        "volatility.threshold_not_met",
        "volatility.unsafe_error",
        "volatility.worker_failure",
        "volatility.worker_output",
        "volatility.worker_spawn",
    }
)
_STABLE_ERROR_TYPES = frozenset(
    {
        "FingerprintMismatch",
        "JSONDecodeError",
        "N/A",
        "NoOutput",
        "RuntimeError",
        "SchemaError",
        "ThresholdError",
        "TimeoutError",
        "TimeoutExpired",
        "WorkerError",
    }
)
_URL_KEYS = {
    "effective_port",
    "host",
    "path_sha256",
    "query_delimiter_present",
    "query_present",
    "query_sha256",
    "scheme",
}
_ERROR_KEYS = {"code", "error_type"}
_USAGE_KEYS = {"requests", "response_bytes", "target_bytes", "within_budget"}
_EXPECTED_THRESHOLD_KEYS = {"minimum_document_links", "minimum_words"}
_OBSERVED_THRESHOLD_KEYS = {"document_link_count", "word_count"}
_THRESHOLD_KEYS = {"expected", "met", "observed"}
_BUDGET_KEYS = {
    "concurrency",
    "elapsed_seconds",
    "governed_network_seconds",
    "max_requests",
    "max_response_bytes",
    "max_seconds",
    "requests",
    "response_bytes",
    "retry",
    "within_budget",
}
_CASE_KEYS = {
    "case_id",
    "content_bytes",
    "content_sha256",
    "error",
    "final_url",
    "mime_type",
    "outcome",
    "requested_url",
    "status",
    "thresholds",
    "usage",
}
_SAMPLE_KEYS = {
    "budget",
    "cases",
    "error",
    "process_outcome",
    "process_return_code",
    "sample",
    "sequence",
    "system",
}


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _finite_nonnegative_real(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def safe_url_descriptor(value: object) -> dict[str, object]:
    """Return a credential-free URL descriptor; invalid input stays non-sensitive."""
    invalid: dict[str, object] = {
        "scheme": "N/A",
        "host": "N/A",
        "effective_port": "N/A",
        "path_sha256": "N/A",
        "query_delimiter_present": False,
        "query_present": False,
        "query_sha256": "N/A",
    }
    if not isinstance(value, str):
        return invalid
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if (
            scheme not in {"http", "https"}
            or not host
            or parsed.username is not None
            or parsed.password is not None
        ):
            return invalid
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return invalid
    path = parsed.path or "/"
    query_delimiter_present = "?" in value.split("#", 1)[0]
    return {
        "scheme": scheme,
        "host": host,
        "effective_port": port,
        "path_sha256": hashlib.sha256(path.encode("utf-8")).hexdigest(),
        "query_delimiter_present": query_delimiter_present,
        "query_present": bool(parsed.query),
        "query_sha256": hashlib.sha256(parsed.query.encode("utf-8")).hexdigest(),
    }


def sanitize_errors(value: object) -> list[dict[str, str]]:
    """Keep stable codes/types only; discard messages, details, and credentials."""
    if value is None or value == []:
        return []
    if isinstance(value, BaseException):
        items: list[object] = [
            {"code": "volatility.unsafe_error", "error_type": type(value).__name__}
        ]
    elif isinstance(value, Mapping):
        items = [value]
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        items = list(value)
    else:
        items = [
            {"code": "volatility.unsafe_error", "error_type": type(value).__name__}
        ]
    sanitized = set()
    for item in items:
        mapping = item if isinstance(item, Mapping) else {}
        code = (
            mapping.get("code")
            or mapping.get("error_code")
            or mapping.get("reason_code")
        )
        if not isinstance(code, str) or code not in _STABLE_ERROR_CODES:
            code = "volatility.unsafe_error"
        error_type = mapping.get("error_type", "N/A")
        if not isinstance(error_type, str) or error_type not in _STABLE_ERROR_TYPES:
            error_type = "N/A"
        sanitized.add((code, error_type))
    return [
        {"code": code, "error_type": error_type}
        for code, error_type in sorted(sanitized)
    ]


def _errors_are_safe(value: object) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, dict)
        and set(item) == _ERROR_KEYS
        and isinstance(item["code"], str)
        and item["code"] in _STABLE_ERROR_CODES
        and isinstance(item["error_type"], str)
        and item["error_type"] in _STABLE_ERROR_TYPES
        for item in value
    )


def _url_is_safe(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == _URL_KEYS
        and value["scheme"] in {"http", "https"}
        and isinstance(value["host"], str)
        and bool(value["host"])
        and value["host"] == value["host"].lower()
        and not any(marker in value["host"] for marker in "@/?# ")
        and isinstance(value["effective_port"], int)
        and not isinstance(value["effective_port"], bool)
        and 0 < value["effective_port"] <= 65535
        and isinstance(value["path_sha256"], str)
        and _SHA256.fullmatch(value["path_sha256"]) is not None
        and isinstance(value["query_delimiter_present"], bool)
        and isinstance(value["query_present"], bool)
        and isinstance(value["query_sha256"], str)
        and _SHA256.fullmatch(value["query_sha256"]) is not None
        and value["query_present"] == (value["query_sha256"] != _EMPTY_SHA256)
        and (not value["query_present"] or value["query_delimiter_present"])
    )


def _same_origin(left: Mapping[str, object], right: Mapping[str, object]) -> bool:
    return all(left[key] == right[key] for key in ("scheme", "host", "effective_port"))


def _usage_is_valid(value: object, content_bytes: int) -> bool:
    if not isinstance(value, dict) or set(value) != _USAGE_KEYS:
        return False
    requests = value["requests"]
    response_bytes = value["response_bytes"]
    target_bytes = value["target_bytes"]
    return (
        all(_nonnegative_int(item) for item in (requests, response_bytes, target_bytes))
        and requests >= 1
        and target_bytes == content_bytes
        and target_bytes <= response_bytes
        and value["within_budget"] is True
    )


def _thresholds_are_valid(value: object, case_id: str) -> bool:
    if not isinstance(value, dict) or set(value) != _THRESHOLD_KEYS:
        return False
    expected = value["expected"]
    observed = value["observed"]
    if (
        not isinstance(expected, dict)
        or set(expected) != _EXPECTED_THRESHOLD_KEYS
        or not all(_nonnegative_int(expected[key]) for key in expected)
        or expected != CASE_THRESHOLDS.get(case_id)
        or not isinstance(observed, dict)
        or set(observed) != _OBSERVED_THRESHOLD_KEYS
    ):
        return False
    word_count = observed["word_count"]
    document_link_count = observed["document_link_count"]
    met = (
        _nonnegative_int(word_count)
        and _nonnegative_int(document_link_count)
        and word_count >= expected["minimum_words"]
        and document_link_count >= expected["minimum_document_links"]
    )
    return value["met"] is True and met


def _case_is_valid(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != _CASE_KEYS:
        return False
    content_bytes = value["content_bytes"]
    content_sha256 = value["content_sha256"]
    requested = value["requested_url"]
    final = value["final_url"]
    return (
        value["case_id"] in CASE_IDS
        and value["outcome"] == "success"
        and _nonnegative_int(value["status"])
        and 200 <= value["status"] < 300
        and isinstance(value["mime_type"], str)
        and _MIME_TYPE.fullmatch(value["mime_type"]) is not None
        and _url_is_safe(requested)
        and _url_is_safe(final)
        and _same_origin(requested, final)
        and isinstance(content_sha256, str)
        and _SHA256.fullmatch(content_sha256) is not None
        and _nonnegative_int(content_bytes)
        and (content_bytes == 0) == (content_sha256 == _EMPTY_SHA256)
        and _thresholds_are_valid(value["thresholds"], value["case_id"])
        and (value["thresholds"]["expected"]["minimum_words"] == 0 or content_bytes > 0)
        and _usage_is_valid(value["usage"], content_bytes)
        and value["error"] == []
        and _errors_are_safe(value["error"])
    )


def _budget_is_valid(value: object, cases: Sequence[Mapping[str, object]]) -> bool:
    if not isinstance(value, dict) or set(value) != _BUDGET_KEYS:
        return False
    requests = value["requests"]
    response_bytes = value["response_bytes"]
    elapsed = value["elapsed_seconds"]
    fixed_integer_fields = (*_PER_SAMPLE_LIMITS, "concurrency", "retry")
    expected = all(
        _nonnegative_int(value[key]) for key in fixed_integer_fields
    ) and all(value[key] == limit for key, limit in _PER_SAMPLE_LIMITS.items())
    totals_match = (
        sum(case["usage"]["requests"] for case in cases) == requests
        and sum(case["usage"]["response_bytes"] for case in cases) == response_bytes
    )
    return (
        expected
        and value["concurrency"] == 1
        and value["retry"] == 0
        and all(_nonnegative_int(item) for item in (requests, response_bytes))
        and _finite_nonnegative_real(elapsed)
        and requests <= value["max_requests"]
        and response_bytes <= value["max_response_bytes"]
        and elapsed <= value["max_seconds"]
        and value["within_budget"] is True
        and totals_match
    )


def _ordered_cases(value: object) -> list[dict[str, object]] | None:
    if not isinstance(value, list) or len(value) != len(CASE_IDS):
        return None
    if not all(_case_is_valid(item) for item in value):
        return None
    by_id = {item["case_id"]: item for item in value}
    if set(by_id) != set(CASE_IDS) or len(by_id) != len(value):
        return None
    return [by_id[case_id] for case_id in CASE_IDS]


def _samples_are_valid(samples: object) -> bool:
    if not isinstance(samples, list) or len(samples) != len(SAMPLE_ORDER):
        return False
    system_totals = {
        system: {"requests": 0, "response_bytes": 0, "elapsed_seconds": 0.0}
        for system in ("old", "new")
    }
    cases_by_id = {case_id: [] for case_id in CASE_IDS}
    for sequence, (sample, expected_identity) in enumerate(
        zip(samples, SAMPLE_ORDER, strict=True), start=1
    ):
        if not isinstance(sample, dict) or set(sample) != _SAMPLE_KEYS:
            return False
        if (
            not _nonnegative_int(sample["sequence"])
            or sample["sequence"] != sequence
            or sample["system"] != expected_identity[0]
            or not _nonnegative_int(sample["sample"])
            or sample["sample"] != expected_identity[1]
            or sample["process_outcome"] != "exited-success"
            or not _nonnegative_int(sample["process_return_code"])
            or sample["process_return_code"] != 0
            or sample["error"] != []
            or not _errors_are_safe(sample["error"])
        ):
            return False
        cases = _ordered_cases(sample["cases"])
        if cases is None or not _budget_is_valid(sample["budget"], cases):
            return False
        for case in cases:
            cases_by_id[case["case_id"]].append(case)
        totals = system_totals[sample["system"]]
        totals["requests"] += sample["budget"]["requests"]
        totals["response_bytes"] += sample["budget"]["response_bytes"]
        totals["elapsed_seconds"] += sample["budget"]["elapsed_seconds"]
    for totals in system_totals.values():
        if any(
            totals[field] > maximum
            for field, maximum in (
                ("requests", _PER_SYSTEM_LIMITS["max_requests"]),
                ("response_bytes", _PER_SYSTEM_LIMITS["max_response_bytes"]),
                ("elapsed_seconds", _PER_SYSTEM_LIMITS["max_seconds"]),
            )
        ):
            return False
    for rows in cases_by_id.values():
        shape = (
            rows[0]["status"],
            rows[0]["mime_type"],
            rows[0]["requested_url"],
            rows[0]["final_url"],
        )
        if any(
            (
                row["status"],
                row["mime_type"],
                row["requested_url"],
                row["final_url"],
            )
            != shape
            for row in rows[1:]
        ):
            return False
        sizes_by_sha: dict[str, int] = {}
        for row in rows:
            previous = sizes_by_sha.setdefault(
                row["content_sha256"], row["content_bytes"]
            )
            if previous != row["content_bytes"]:
                return False
    return True


def _case_classification(samples: list[dict[str, object]], case_id: str) -> str:
    rows = [
        next(case for case in sample["cases"] if case["case_id"] == case_id)
        for sample in samples
    ]
    old = {rows[index]["content_sha256"] for index in (0, 2)}
    new = {rows[index]["content_sha256"] for index in (1, 3)}
    if len(old | new) == 1:
        return "stable_match"
    if len(old) == len(new) == 1:
        return "stable_cross_system_mismatch"
    if len(old) > 1 and len(new) > 1:
        return "site_dynamic"
    return "inconclusive"


def classify_samples(samples: object) -> str:
    """Classify complete monitor+document evidence and otherwise fail closed."""
    if not _samples_are_valid(samples):
        return "inconclusive"
    case_results = {_case_classification(samples, case_id) for case_id in CASE_IDS}
    if "inconclusive" in case_results:
        return "inconclusive"
    decisive = case_results - {"stable_match"}
    if not decisive:
        return "stable_match"
    if decisive == {"site_dynamic"}:
        return "site_dynamic"
    if decisive == {"stable_cross_system_mismatch"}:
        return "stable_cross_system_mismatch"
    return "inconclusive"


def _canonical_url(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return safe_url_descriptor(None)
    return {key: value.get(key, "N/A") for key in sorted(_URL_KEYS)}


def _canonical_case(value: object) -> dict[str, object]:
    mapping = value if isinstance(value, Mapping) else {}
    usage = mapping.get("usage") if isinstance(mapping.get("usage"), Mapping) else {}
    thresholds = (
        mapping.get("thresholds")
        if isinstance(mapping.get("thresholds"), Mapping)
        else {}
    )
    expected = (
        thresholds.get("expected")
        if isinstance(thresholds.get("expected"), Mapping)
        else {}
    )
    observed = (
        thresholds.get("observed")
        if isinstance(thresholds.get("observed"), Mapping)
        else {}
    )
    return {
        "case_id": mapping.get("case_id", "N/A"),
        "outcome": mapping.get("outcome", "failure"),
        "status": mapping.get("status"),
        "mime_type": mapping.get("mime_type"),
        "requested_url": _canonical_url(mapping.get("requested_url")),
        "final_url": _canonical_url(mapping.get("final_url")),
        "content_sha256": mapping.get("content_sha256"),
        "content_bytes": mapping.get("content_bytes"),
        "thresholds": {
            "expected": {
                key: expected.get(key) for key in sorted(_EXPECTED_THRESHOLD_KEYS)
            },
            "observed": {
                key: observed.get(key) for key in sorted(_OBSERVED_THRESHOLD_KEYS)
            },
            "met": thresholds.get("met") is True,
        },
        "usage": {key: usage.get(key) for key in sorted(_USAGE_KEYS)},
        "error": sanitize_errors(mapping.get("error")),
    }


def _canonical_sample(value: object) -> dict[str, object]:
    mapping = value if isinstance(value, Mapping) else {}
    raw_cases = mapping.get("cases")
    raw_cases = raw_cases if isinstance(raw_cases, list) else []
    canonical_cases = [_canonical_case(case) for case in raw_cases]
    canonical_cases.sort(
        key=lambda case: (
            (
                CASE_IDS.index(case["case_id"])
                if case["case_id"] in CASE_IDS
                else len(CASE_IDS)
            ),
            str(case["case_id"]),
        )
    )
    budget = mapping.get("budget") if isinstance(mapping.get("budget"), Mapping) else {}
    return {
        "sequence": mapping.get("sequence"),
        "system": mapping.get("system", "N/A"),
        "sample": mapping.get("sample"),
        "process_outcome": mapping.get("process_outcome", "N/A"),
        "process_return_code": mapping.get("process_return_code", "N/A"),
        "cases": canonical_cases,
        "budget": {key: budget.get(key) for key in sorted(_BUDGET_KEYS)},
        "error": sanitize_errors(mapping.get("error")),
    }


def _system_totals(samples: object) -> dict[str, dict[str, object]]:
    totals: dict[str, dict[str, object]] = {
        system: {
            "requests": 0,
            "response_bytes": 0,
            "elapsed_seconds": 0.0,
            "within_budget": True,
        }
        for system in ("old", "new")
    }
    if not isinstance(samples, list):
        return totals
    for sample in samples:
        if not isinstance(sample, Mapping) or sample.get("system") not in totals:
            continue
        budget = sample.get("budget")
        if not isinstance(budget, Mapping):
            totals[sample["system"]]["within_budget"] = False
            continue
        system = totals[sample["system"]]
        for field in ("requests", "response_bytes", "elapsed_seconds"):
            value = budget.get(field)
            if not _finite_nonnegative_real(value):
                system[field] = "N/A"
                system["within_budget"] = False
            elif system[field] != "N/A":
                system[field] += value
    for system in totals.values():
        if system["within_budget"] is False:
            continue
        system["within_budget"] = all(
            system[field] <= maximum
            for field, maximum in (
                ("requests", _PER_SYSTEM_LIMITS["max_requests"]),
                ("response_bytes", _PER_SYSTEM_LIMITS["max_response_bytes"]),
                ("elapsed_seconds", _PER_SYSTEM_LIMITS["max_seconds"]),
            )
        )
    return totals


def build_evidence(samples: object) -> dict[str, object]:
    """Build the deterministic, safe JSON evidence envelope."""
    source = samples if isinstance(samples, list) else []
    return {
        "schema_version": "phase-20-soa-volatility-evidence.v1",
        "limits": {
            "per_sample": dict(_PER_SAMPLE_LIMITS),
            "per_system": dict(_PER_SYSTEM_LIMITS),
            "outer_hard_deadline_seconds": _OUTER_HARD_DEADLINE_SECONDS,
            "concurrency": 1,
            "retry": 0,
        },
        "samples": [_canonical_sample(sample) for sample in source],
        "system_totals": _system_totals(source),
        "classification": classify_samples(samples),
    }


def evidence_json(evidence: Mapping[str, object]) -> str:
    """Serialize evidence with one deterministic JSON representation."""
    return json.dumps(
        evidence,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
