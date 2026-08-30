"""Run the fixed legacy governed-read surface inside an extracted checkout."""

# pylint: disable=import-error,import-outside-toplevel,broad-exception-caught
# pylint: disable=missing-function-docstring,no-name-in-module,too-many-locals
# pylint: disable=duplicate-code,too-many-statements,too-many-lines
# pylint: disable=too-few-public-methods,too-many-return-statements

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import math
import re
import subprocess
import sys
import time
from collections.abc import Mapping
from datetime import timedelta
from html.parser import HTMLParser
from pathlib import Path

_ROBOTS_RESPONSE_BYTES_PER_CASE = 512 * 1024
_RUNTIME_DISTRIBUTIONS = (
    ("annotated_types", "annotated-types"),
    ("click", "click"),
    ("httpx", "httpx"),
    ("idna", "idna"),
    ("pydantic", "pydantic"),
    ("pydantic_core", "pydantic_core"),
    ("pygments", "Pygments"),
    ("typing_extensions", "typing_extensions"),
    ("typing_inspection", "typing-inspection"),
    ("yaml", "PyYAML"),
)
_LEGACY_ENVIRONMENT_ALLOWLIST = {
    "python": {"implementation": "cpython", "major": 3, "minor": 12},
    "imports": {
        "annotated_types": {
            "distribution": "annotated-types",
            "version": "0.8.0",
            "module_sha256": "a7104a4d439b27a9f74fc0be236b9ba1b7831e6044026802a205abc1298a9bc8",
            "record_sha256": "3999aa3e7cd1afa1ae67b55bf5b04bbc3ca55fdd6c7dcfe571b1aad05da849af",
        },
        "click": {
            "distribution": "click",
            "version": "8.5.0",
            "module_sha256": "5abfc54d37d47cc788b7e7a05e9514787f8c5a0b7db429d0f24d748ac89964ca",
            "record_sha256": "4a523c0c5110a56f01ccedcea0dd40973a227083ead89333427baf414cb21c95",
        },
        "httpx": {
            "distribution": "httpx",
            "version": "0.28.1",
            "module_sha256": "0ac6997bac998f4ac783adf6d8058a587193315afdb718047c3e4fdff46bcfad",
            "record_sha256": "167d3fdc01ae4df2c6f27edc08258417ed4fb89eed4eb7d5b1ef1242d31d3a72",
        },
        "idna": {
            "distribution": "idna",
            "version": "3.19",
            "module_sha256": "8514c3ed53136a3596ebdf512fa487bbdd7da5a99adcaed82e0363d2c306d3af",
            "record_sha256": "3ff9f0b977f1c7619cdef69c72033d54d4ad8aaf5117b3df270e215647e33f45",
        },
        "pydantic": {
            "distribution": "pydantic",
            "version": "2.13.4",
            "module_sha256": "e62127278c07bf5384cdd2903f368a69929f3b8a524000bae4e0eb608ebf4bc6",
            "record_sha256": "961389739a4b3e924d2da2248f92dcf035b3a0cb45168a1b2790be21dba19e6d",
        },
        "pydantic_core": {
            "distribution": "pydantic_core",
            "version": "2.46.4",
            "module_sha256": "e644150a9eac4372c4ff826c8f614df288a561e39250e96c58e447f17806c6bf",
            "record_sha256": "3a804f1dcad67692d7faed9dbb37595678654a1cfccda37f9e2bd01aeef51b05",
        },
        "pygments": {
            "distribution": "Pygments",
            "version": "2.21.0",
            "module_sha256": "83fe99688e06ed80d7d44d325f79027de83a434c60f249bceffd67fda3e7d2b1",
            "record_sha256": "149ba876dcb44ae7aaba8f805bd814a3e565317628e89e4c168b03b9cc97db83",
        },
        "typing_extensions": {
            "distribution": "typing_extensions",
            "version": "4.16.0",
            "module_sha256": "4040ca1a1ecbee00d1385c12a93084d1c5bd46f0b774f07e5ae7e91c4f55e696",
            "record_sha256": "a346a921aa5be35b34ced3258614183d152887b954caaae5de2a94be72d5f2ec",
        },
        "typing_inspection": {
            "distribution": "typing-inspection",
            "version": "0.4.4",
            "module_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "record_sha256": "06f60204c0b7d67df21f09681e2db4781ef463cad5fb7dfc7a749b232a0ec8ae",
        },
        "yaml": {
            "distribution": "PyYAML",
            "version": "6.0.3",
            "module_sha256": "b19dfcc333d6a75dfd73073901164507252f271b41d3b5f7d85510033a0547a7",
            "record_sha256": "c55b91c92f924915927c027b1ffc40d102325d0ad29b4c89f0534ac977024f56",
        },
    },
    "source": {
        "commit": "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5",
        "archive_sha256": "cb7a83f5979a852e27c4dc6f24b31850420c037470d1cd13eae01aaace775f74",
    },
}


def _http_profile_descriptor(
    fields: tuple[tuple[str, str], ...],
) -> dict[str, object]:
    profile = dict(fields)
    return {
        "fields": [list(item) for item in fields],
        "sha256": hashlib.sha256(
            json.dumps(
                profile,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest(),
    }


def _profile_case_evidence(
    case: Mapping[str, object], observations: list[dict[str, object]]
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


def _empty_http_profile_evidence(cases: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "phase-20-http-profile-evidence.v1",
        "provenance": "N/A",
        "identity": "N/A",
        "authority": "N/A",
        "cases": [_profile_case_evidence(case, []) for case in cases],
    }


class _ProfileEvidenceTransport:
    """Observe the exact governed transport call before delegating it unchanged."""

    def __init__(
        self,
        transport: object,
        observations: list[dict[str, object]],
        identity: Mapping[str, str],
    ) -> None:
        self._transport = transport
        self._observations = observations
        self._identity = dict(identity)

    def request(
        self,
        url: str,
        *,
        user_agent: str,
        identity_sha256: str,
        progress=None,
    ):
        if (
            user_agent != self._identity["user_agent"]
            or identity_sha256 != self._identity["identity_sha256"]
        ):
            raise ValueError("legacy gateway identity changed at transport boundary")
        fields = (
            ("accept_encoding", "identity, gzip"),
            ("connection", "close"),
            ("method", "GET"),
            ("user_agent", user_agent),
        )
        self._observations.append(_http_profile_descriptor(fields))
        return self._transport.request(
            url,
            user_agent=user_agent,
            identity_sha256=identity_sha256,
            progress=progress,
        )


class _PageEvidence(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text: list[str] = []
        self.document_links = 0

    def handle_data(self, data: str) -> None:
        self.text.append(data)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = next((value for name, value in attrs if name == "href"), None)
        if href and re.search(r"\.(?:pdf|docx?|xlsx?)(?:[?#]|$)", href, re.I):
            self.document_links += 1


def _page_evidence(body: bytes) -> tuple[int, int]:
    parser = _PageEvidence()
    parser.feed(body.decode("utf-8", errors="replace"))
    return len(re.findall(r"\w+", " ".join(parser.text))), parser.document_links


def _case_limits(limits: dict[str, object], case_count: int) -> tuple[int, int, int]:
    if case_count < 1:
        raise ValueError("legacy live probe requires at least one case")
    request_limit = int(limits["max_total_requests"]) // case_count
    robots_limit = _ROBOTS_RESPONSE_BYTES_PER_CASE
    body_limit = (
        int(limits["max_total_response_bytes"]) - robots_limit * case_count
    ) // case_count
    if request_limit < 2 or body_limit < 1:
        raise ValueError(
            "legacy per-case partition cannot cover robots and target reads"
        )
    return request_limit, body_limit, robots_limit


def _request_descriptor(
    *,
    requested_url: str,
    allowed_origins: tuple[str, ...],
    request_limits: dict[str, int],
) -> dict[str, object]:
    return {
        "schema_version": "phase-20-request-descriptor.v1",
        "scope": {
            "seeds": [requested_url],
            "allowed_origins": list(allowed_origins),
            "include_paths": ["/**"],
            "content_types": ["html"],
        },
        "request": {"site_skill": "N/A", "explore_all_tools": False},
        "budgets": dict(request_limits),
    }


def _request_digest(descriptor: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _base_record(
    case: dict[str, object],
    *,
    request_upper_bound: int,
    response_bytes_upper_bound: int,
) -> dict[str, object]:
    return {
        "case_id": case["case_id"],
        "request_descriptor": "N/A",
        "request_digest": "N/A",
        "requested_url": case["requested_url"],
        "final_url": None,
        "redirects": [],
        "status": None,
        "mime_type": None,
        "content_sha256": None,
        "content_bytes": None,
        "word_count": None,
        "document_link_count": None,
        "artifact": {"availability": "N/A", "reason": "gateway-only probe"},
        "observation": {"availability": "N/A", "reason": "gateway-only probe"},
        "manifest": {"availability": "N/A", "reason": "gateway-only probe"},
        "outcome": "failure",
        "attempts": "N/A",
        "usage": {
            "requests": None,
            "requests_upper_bound": request_upper_bound,
            "response_bytes": None,
            "response_bytes_upper_bound": response_bytes_upper_bound,
            "target_bytes": None,
            "tool_attempts": "N/A",
            "bytes_basis": "N/A",
            "within_budget": True,
        },
        "error": None,
    }


def _apply_failure_usage(
    record: dict[str, object],
    *,
    request_limit: int,
    body_limit: int,
    robots_limit: int,
) -> None:
    record["usage"].update(
        {
            "requests": request_limit,
            "response_bytes": body_limit + robots_limit,
            "target_bytes": body_limit,
            "bytes_basis": "per_case_upper_bound",
        }
    )


def _distribution_fingerprint(
    module_name: str, distribution_name: str
) -> dict[str, str]:
    try:
        module = importlib.import_module(module_name)
        distribution = importlib.metadata.distribution(distribution_name)
        record = distribution.read_text("RECORD")
        if not module.__file__ or record is None:
            raise ValueError("distribution fingerprint inputs are unavailable")
        return {
            "distribution": distribution_name,
            "version": distribution.version,
            "module_sha256": hashlib.sha256(
                Path(module.__file__).read_bytes()
            ).hexdigest(),
            "record_sha256": hashlib.sha256(record.encode("utf-8")).hexdigest(),
        }
    except (
        ImportError,
        importlib.metadata.PackageNotFoundError,
        OSError,
        ValueError,
    ) as exc:
        return {
            "distribution": distribution_name,
            "status": "unavailable",
            "error_type": type(exc).__name__,
        }


def _environment_fingerprint() -> dict[str, object]:
    executable = Path(sys.executable).resolve()
    return {
        "python": {
            "implementation": sys.implementation.name,
            "major": sys.version_info.major,
            "minor": sys.version_info.minor,
            "version": sys.version.split()[0],
            "executable": "<controlled-legacy-python>",
            "executable_path_sha256": hashlib.sha256(
                str(executable).encode("utf-8")
            ).hexdigest(),
            "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        },
        "imports": {
            name: _distribution_fingerprint(name, distribution)
            for name, distribution in _RUNTIME_DISTRIBUTIONS
        },
    }


def _fingerprint_matches(
    actual: dict[str, object], expected: dict[str, object]
) -> bool:
    try:
        actual_python = actual["python"]
        expected_python = expected["python"]
        return (
            actual_python["implementation"] == expected_python["implementation"]
            and actual_python["major"] == expected_python["major"]
            and actual_python["minor"] == expected_python["minor"]
            and actual["imports"] == expected["imports"]
            and ("source" not in expected or actual.get("source") == expected["source"])
        )
    except (KeyError, TypeError):
        return False


def _failure_evidence(
    payload: dict[str, object],
    invocation: dict[str, object],
    failure: dict[str, object],
) -> dict[str, object]:
    cases = payload["cases"]
    limits = payload["limits"]
    request_limit, body_limit, robots_limit = _case_limits(limits, len(cases))
    records = []
    for case in cases:
        record = _base_record(
            case,
            request_upper_bound=request_limit,
            response_bytes_upper_bound=body_limit + robots_limit,
        )
        _apply_failure_usage(
            record,
            request_limit=request_limit,
            body_limit=body_limit,
            robots_limit=robots_limit,
        )
        record["error"] = {
            "error_code": failure["error_code"],
            "message": "N/A",
            "retryable": "N/A",
            "details": "N/A",
            "error_type": failure["error_type"],
        }
        records.append(record)
    return {
        "old_commit": payload["old_commit"],
        "environment": payload["environment"],
        "http_profile": _empty_http_profile_evidence(cases),
        "cases": records,
        "budget": {
            "requests": int(limits["max_total_requests"]),
            "requests_basis": "aggregate upper bound after missing child evidence",
            "max_requests": int(limits["max_total_requests"]),
            "response_bytes": int(limits["max_total_response_bytes"]),
            "response_bytes_basis": "aggregate upper bound after missing child evidence",
            "max_response_bytes": int(limits["max_total_response_bytes"]),
            "elapsed_seconds": "N/A",
            "max_seconds": int(limits["timeout_seconds"]),
            "governed_network_seconds": payload["governed_network_timeout_seconds"],
            "concurrency": 1,
            "retry": 0,
        },
        "invocation": invocation,
        "process_outcome": failure["process_outcome"],
        "process_return_code": failure["process_return_code"],
    }


def _boundary_failure_evidence(
    context: dict[str, object], failure: dict[str, object]
) -> dict[str, object]:
    if context["system"] != "old":
        raise ValueError("legacy boundary helper only accepts the old system")
    payload = {
        "old_commit": context["old_commit"],
        "environment": context["environment"],
        "governed_network_timeout_seconds": context["governed_network_timeout_seconds"],
        "limits": context["limits"],
        "cases": context["cases"],
    }
    return _failure_evidence(payload, context["invocation"], failure)


def _call_boundary(operation, context: dict[str, object]) -> dict[str, object]:
    try:
        return operation()
    except Exception as exc:
        return _boundary_failure_evidence(
            context,
            {
                "error_code": f"phase20.{context['system']}_boundary",
                "error_type": type(exc).__name__,
                "process_outcome": "boundary-failure",
                "process_return_code": "N/A",
            },
        )


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _finite_real(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _optional_nonnegative_int(value: object) -> bool:
    return value is None or _nonnegative_int(value)


def _optional_text(value: object) -> bool:
    return value is None or isinstance(value, str)


def _profile_descriptor_is_complete(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"fields", "sha256"}:
        return False
    fields = value["fields"]
    if not isinstance(fields, list) or not fields:
        return False
    if not all(
        isinstance(item, list)
        and len(item) == 2
        and all(isinstance(leaf, str) and leaf for leaf in item)
        for item in fields
    ):
        return False
    return (
        _http_profile_descriptor(tuple((item[0], item[1]) for item in fields)) == value
    )


def _http_profile_is_complete(
    value: object, expected_cases: list[dict[str, object]]
) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "provenance",
        "identity",
        "authority",
        "cases",
    }:
        return False
    if value["schema_version"] != "phase-20-http-profile-evidence.v1":
        return False
    if value["provenance"] != "N/A" and not isinstance(value["provenance"], dict):
        return False
    if value["identity"] != "N/A" and not isinstance(value["identity"], dict):
        return False
    if value["authority"] != "N/A" and not _profile_descriptor_is_complete(
        value["authority"]
    ):
        return False
    rows = value["cases"]
    if not isinstance(rows, list) or len(rows) != len(expected_cases):
        return False
    for case, row in zip(expected_cases, rows, strict=True):
        if not isinstance(row, dict) or set(row) != {
            "case_id",
            "request_count",
            "observations",
            "collapsed",
        }:
            return False
        observations = row["observations"]
        count = row["request_count"]
        if (
            row["case_id"] != case["case_id"]
            or not _nonnegative_int(count)
            or not isinstance(observations, list)
            or len(observations) != count
            or not all(_profile_descriptor_is_complete(item) for item in observations)
        ):
            return False
        expected: object = "N/A"
        if observations and all(item == observations[0] for item in observations):
            expected = observations[0]
        elif observations:
            expected = "drift"
        if row["collapsed"] != expected:
            return False
    return True


def _availability_is_complete(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    availability = value.get("availability")
    return isinstance(availability, str) and availability in {
        "N/A",
        "none",
        "present",
    }


def _redirects_are_complete(value: object) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, dict)
        and {"from_url", "to_url", "status"} <= set(item)
        and _optional_text(item["from_url"])
        and _optional_text(item["to_url"])
        and _optional_nonnegative_int(item["status"])
        for item in value
    )


def _attempts_are_complete(value: object) -> bool:
    return value == "N/A" or (
        isinstance(value, list)
        and all(
            isinstance(item, dict) and isinstance(item.get("outcome"), str)
            for item in value
        )
    )


def _usage_is_complete(value: object) -> bool:
    required = {
        "bytes_basis",
        "requests",
        "requests_upper_bound",
        "response_bytes",
        "response_bytes_upper_bound",
        "target_bytes",
        "tool_attempts",
        "within_budget",
    }
    if not isinstance(value, dict) or set(value) != required:
        return False
    requests = value["requests"]
    request_upper = value["requests_upper_bound"]
    response_bytes = value["response_bytes"]
    response_upper = value["response_bytes_upper_bound"]
    target_bytes = value["target_bytes"]
    exact_counts = all(
        _nonnegative_int(item)
        for item in (
            requests,
            request_upper,
            response_bytes,
            response_upper,
            target_bytes,
        )
    )
    if not exact_counts:
        return False
    basis = value["bytes_basis"]
    relationships = (
        0 < request_upper
        and requests <= request_upper
        and 0 < response_upper
        and target_bytes <= response_bytes <= response_upper
        and (
            basis == "target_body"
            or (basis == "per_case_upper_bound" and response_bytes == response_upper)
        )
    )
    return (
        relationships
        and value["tool_attempts"] == "N/A"
        and value["within_budget"] is True
    )


def _error_is_complete(value: object) -> bool:
    if value is None:
        return True
    required = {"error_code", "message", "retryable", "details", "error_type"}
    if not isinstance(value, dict) or set(value) != required:
        return False
    return (
        isinstance(value["error_code"], str)
        and bool(value["error_code"])
        and isinstance(value["message"], str)
        and bool(value["message"])
        and (isinstance(value["retryable"], bool) or value["retryable"] == "N/A")
        and value["details"] == "N/A"
        and isinstance(value["error_type"], str)
        and bool(value["error_type"])
    )


def _error_evidence(value: dict[str, object]) -> dict[str, object]:
    code = value.get("error_code") or value.get("reason_code")
    return {
        "error_code": code,
        "message": value.get("message", "N/A"),
        "retryable": value.get("retryable", "N/A"),
        "details": "N/A",
        "error_type": value.get("error_type", "N/A"),
    }


def _legacy_record_is_complete(
    record: object, expected_case: dict[str, object]
) -> bool:
    required = {
        "artifact",
        "attempts",
        "case_id",
        "content_bytes",
        "content_sha256",
        "document_link_count",
        "error",
        "final_url",
        "manifest",
        "mime_type",
        "observation",
        "outcome",
        "redirects",
        "request_descriptor",
        "request_digest",
        "requested_url",
        "status",
        "usage",
        "word_count",
    }
    return (
        isinstance(record, dict)
        and required <= set(record)
        and record.get("case_id") == expected_case.get("case_id")
        and record.get("requested_url") == expected_case.get("requested_url")
        and _request_evidence_is_complete(
            record["request_descriptor"], record["request_digest"]
        )
        and _optional_text(record["final_url"])
        and _redirects_are_complete(record["redirects"])
        and _optional_nonnegative_int(record["status"])
        and _optional_text(record["mime_type"])
        and _optional_text(record["content_sha256"])
        and _optional_nonnegative_int(record["content_bytes"])
        and _optional_nonnegative_int(record["word_count"])
        and _optional_nonnegative_int(record["document_link_count"])
        and _availability_is_complete(record["artifact"])
        and _availability_is_complete(record["observation"])
        and _availability_is_complete(record["manifest"])
        and _attempts_are_complete(record["attempts"])
        and isinstance(record["outcome"], str)
        and record["outcome"] in {"success", "failure"}
        and _usage_is_complete(record["usage"])
        and _error_is_complete(record["error"])
    )


def _request_evidence_is_complete(descriptor: object, digest: object) -> bool:
    if descriptor == "N/A":
        return digest == "N/A"
    if not isinstance(descriptor, dict) or not isinstance(digest, str):
        return False
    required = {"schema_version", "scope", "request", "budgets"}
    scope = descriptor.get("scope")
    request = descriptor.get("request")
    budgets = descriptor.get("budgets")
    return (
        set(descriptor) == required
        and descriptor["schema_version"] == "phase-20-request-descriptor.v1"
        and isinstance(scope, dict)
        and set(scope) == {"seeds", "allowed_origins", "include_paths", "content_types"}
        and all(isinstance(scope[key], list) for key in scope)
        and isinstance(request, dict)
        and request == {"site_skill": "N/A", "explore_all_tools": False}
        and isinstance(budgets, dict)
        and set(budgets)
        == {
            "max_requests",
            "max_bytes",
            "max_runtime_seconds",
            "max_tool_attempts_per_target",
        }
        and all(_nonnegative_int(value) for value in budgets.values())
        and digest == _request_digest(descriptor)
    )


def _legacy_budget_is_complete(budget: object, payload: dict[str, object]) -> bool:
    if not isinstance(budget, dict):
        return False
    required = {
        "requests",
        "requests_basis",
        "response_bytes",
        "response_bytes_basis",
        "max_requests",
        "max_response_bytes",
        "robots_response_bytes_upper_bound",
        "elapsed_seconds",
        "max_seconds",
        "governed_network_seconds",
        "outer_process_max_seconds",
        "concurrency",
        "retry",
    }
    if set(budget) != required:
        return False
    integer_fields = required - {
        "requests_basis",
        "response_bytes_basis",
        "elapsed_seconds",
    }
    elapsed = budget.get("elapsed_seconds")
    maximum = budget.get("max_seconds")
    limits = payload["limits"]
    governed = budget["governed_network_seconds"]
    integer_shape = all(_nonnegative_int(budget[key]) for key in integer_fields)
    bases_are_present = all(
        isinstance(budget[key], str) and bool(budget[key].strip())
        for key in ("requests_basis", "response_bytes_basis")
    )
    declared_limits_match = (
        budget["max_requests"] == int(limits["max_total_requests"])
        and budget["max_response_bytes"] == int(limits["max_total_response_bytes"])
        and maximum
        == budget["outer_process_max_seconds"]
        == int(limits["timeout_seconds"])
        == 30
    )
    actual_counts_fit = (
        budget["requests"] <= budget["max_requests"]
        and budget["response_bytes"] <= budget["max_response_bytes"]
    )
    robots_match = (
        budget["robots_response_bytes_upper_bound"]
        == _ROBOTS_RESPONSE_BYTES_PER_CASE * len(payload["cases"])
        <= budget["max_response_bytes"]
    )
    time_matches = (
        _finite_real(elapsed)
        and 0 <= elapsed <= maximum
        and governed == int(payload["governed_network_timeout_seconds"])
        and 0 < governed < maximum
    )
    execution_shape = budget["concurrency"] == 1 and budget["retry"] == 0
    return all(
        (
            integer_shape,
            bases_are_present,
            declared_limits_match,
            actual_counts_fit,
            robots_match,
            time_matches,
            execution_shape,
        )
    )


def _output_is_complete(evidence: object, payload: dict[str, object]) -> bool:
    if not isinstance(evidence, dict) or evidence.get("old_commit") != payload.get(
        "old_commit"
    ):
        return False
    if evidence.get("environment") != payload.get("environment"):
        return False
    if not _http_profile_is_complete(evidence.get("http_profile"), payload["cases"]):
        return False
    records, expected_cases = evidence.get("cases"), payload["cases"]
    budget = evidence.get("budget")
    if not isinstance(records, list) or len(records) != len(expected_cases):
        return False
    if not _legacy_budget_is_complete(budget, payload):
        return False
    records_are_complete = all(
        _legacy_record_is_complete(record, case)
        for case, record in zip(expected_cases, records, strict=True)
    )
    if not records_are_complete:
        return False
    request_limit, body_limit, robots_limit = _case_limits(
        payload["limits"], len(records)
    )
    expected_response_upper = body_limit + robots_limit
    usage_limits_match = all(
        record["usage"]["requests_upper_bound"] == request_limit
        and record["usage"]["response_bytes_upper_bound"] == expected_response_upper
        and record["usage"]["target_bytes"] <= body_limit
        and (
            record["usage"]["bytes_basis"] != "per_case_upper_bound"
            or record["usage"]["target_bytes"]
            <= record["usage"]["response_bytes"] - robots_limit
        )
        for record in records
    )
    response_total = sum(
        record["usage"]["response_bytes"]
        + (robots_limit if record["usage"]["bytes_basis"] == "target_body" else 0)
        for record in records
    )
    return (
        usage_limits_match
        and sum(record["usage"]["requests"] for record in records) == budget["requests"]
        and response_total == budget["response_bytes"]
    )


def _run_process(
    command: list[str],
    cwd: Path,
    environment: dict[str, str],
    payload: dict[str, object],
    invocation: dict[str, object],
) -> dict[str, object]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=int(payload["limits"]["timeout_seconds"]),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return _failure_evidence(
            payload,
            invocation,
            {
                "error_code": "legacy.process_timeout",
                "error_type": type(exc).__name__,
                "process_outcome": "timeout",
                "process_return_code": "N/A",
            },
        )
    except OSError as exc:
        return _failure_evidence(
            payload,
            invocation,
            {
                "error_code": "legacy.process_spawn",
                "error_type": type(exc).__name__,
                "process_outcome": "not-started",
                "process_return_code": "N/A",
            },
        )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        return _failure_evidence(
            payload,
            invocation,
            {
                "error_code": "legacy.no_output",
                "error_type": "NoOutput",
                "process_outcome": "exited-without-evidence",
                "process_return_code": completed.returncode,
            },
        )
    try:
        evidence = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        return _failure_evidence(
            payload,
            invocation,
            {
                "error_code": "legacy.output_parse",
                "error_type": type(exc).__name__,
                "process_outcome": "invalid-evidence",
                "process_return_code": completed.returncode,
            },
        )
    if not _output_is_complete(evidence, payload):
        return _failure_evidence(
            payload,
            invocation,
            {
                "error_code": "legacy.output_schema",
                "error_type": "SchemaError",
                "process_outcome": "invalid-evidence",
                "process_return_code": completed.returncode,
            },
        )
    evidence.update(
        {
            "invocation": invocation,
            "process_outcome": (
                "exited-success" if completed.returncode == 0 else "exited-failure"
            ),
            "process_return_code": completed.returncode,
        }
    )
    return evidence


def main() -> None:
    from web_listening.blocks.access_gateway import AccessGateway, AccessGatewayConfig
    from web_listening.blocks.governed_read import (
        ROLLBACK_REQUIRED_READ_ERRORS,
        AccessRejectedError,
        GovernedReadGateway,
        access_rejection_payload,
        governed_read_failure_payload,
    )
    from web_listening.blocks.site_diagnostic import (
        SafePinnedTransport,
        normalize_http_url,
    )
    from web_listening.contracts.site_diagnostic import DiagnosticIdentity

    payload = json.load(sys.stdin)
    expected_runtime = payload["environment"]["fingerprint"]
    expected_runtime = {
        "python": expected_runtime["python"],
        "imports": expected_runtime["imports"],
    }
    if not _fingerprint_matches(_environment_fingerprint(), expected_runtime):
        raise RuntimeError("legacy dependency fingerprint changed after validation")
    governed_seconds = int(payload["governed_network_timeout_seconds"])
    deadline = time.monotonic() + governed_seconds
    request_limit, body_limit, robots_limit = _case_limits(
        payload["limits"], len(payload["cases"])
    )
    request_limits = {
        "max_requests": request_limit,
        "max_bytes": body_limit + robots_limit,
        "max_runtime_seconds": governed_seconds,
        "max_tool_attempts_per_target": 1,
    }
    request_count = 0
    response_bytes = 0
    records: list[dict[str, object]] = []
    profile_cases: list[dict[str, object]] = []
    observed_identity: dict[str, str] | None = None
    profile_authority: object = "N/A"
    failed = False
    for case in payload["cases"]:
        record = _base_record(
            case,
            request_upper_bound=request_limit,
            response_bytes_upper_bound=body_limit + robots_limit,
        )
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            failed = True
            record["error"] = _error_evidence(
                {
                    "error_code": "legacy.aggregate_timeout",
                    "error_type": "TimeoutError",
                }
            )
            _apply_failure_usage(
                record,
                request_limit=request_limit,
                body_limit=body_limit,
                robots_limit=robots_limit,
            )
            request_count += request_limit
            response_bytes += body_limit + robots_limit
            records.append(record)
            profile_cases.append(_profile_case_evidence(case, []))
            continue
        descriptor = _request_descriptor(
            requested_url=case["requested_url"],
            allowed_origins=tuple(payload["allowed_origins"]),
            request_limits=request_limits,
        )
        record["request_descriptor"] = descriptor
        record["request_digest"] = _request_digest(descriptor)
        gateway = None
        profile_observations: list[dict[str, object]] = []
        try:
            expected_identity = dict(payload["http_profile"]["identity"])
            identity = DiagnosticIdentity(**expected_identity)
            actual_identity = {
                "identity_id": identity.identity_id,
                "product_token": identity.product_token,
                "user_agent": identity.user_agent,
                "identity_sha256": identity.identity_sha256,
            }
            if actual_identity != expected_identity:
                raise ValueError("legacy identity construction changed")
            if observed_identity is None:
                observed_identity = actual_identity
            elif observed_identity != actual_identity:
                raise ValueError("legacy identity changed between cases")
            profile_authority = _http_profile_descriptor(
                (
                    ("accept_encoding", "identity, gzip"),
                    ("connection", "close"),
                    ("method", "GET"),
                    ("user_agent", identity.user_agent),
                )
            )
            origins = frozenset(
                normalize_http_url(str(url))[1] for url in payload["allowed_origins"]
            )
            transport = _ProfileEvidenceTransport(
                SafePinnedTransport(timeout=float(remaining_seconds)),
                profile_observations,
                actual_identity,
            )
            gateway = GovernedReadGateway(
                AccessGateway(
                    AccessGatewayConfig(
                        identity=identity,
                        allowed_origins=origins,
                        diagnostic_artifact_sha256=payload["authority_sha256"],
                        pacing_interval=timedelta(seconds=1),
                        budget_limit=request_limit,
                    ),
                    transport=transport,
                ),
                max_body_bytes=body_limit,
            )
            result = gateway.read(case["requested_url"], max_body_bytes=body_limit)
            redirects = [
                {
                    "from_url": hop.source_url,
                    "to_url": hop.canonical_target_url,
                    "status": hop.http_status,
                }
                for hop in result.access_decision.redirect_hops
            ]
            requests = len(profile_observations)
            request_count += requests
            target_response_bytes = max(result.wire_bytes, len(result.body))
            response_bytes += robots_limit + target_response_bytes
            words, document_links = _page_evidence(result.body)
            record.update(
                {
                    "outcome": "success",
                    "final_url": result.final_url,
                    "redirects": redirects,
                    "status": result.status_code,
                    "mime_type": result.content_type.split(";", 1)[0].lower(),
                    "content_sha256": result.sha256,
                    "content_bytes": len(result.body),
                    "word_count": words,
                    "document_link_count": document_links,
                    "usage": {
                        "requests": requests,
                        "requests_upper_bound": request_limit,
                        "response_bytes": target_response_bytes,
                        "response_bytes_upper_bound": body_limit + robots_limit,
                        "target_bytes": len(result.body),
                        "tool_attempts": "N/A",
                        "bytes_basis": "target_body",
                        "within_budget": True,
                    },
                }
            )
        except AccessRejectedError as exc:
            failed = True
            request_count += request_limit
            response_bytes += body_limit + robots_limit
            record.update(
                {
                    "outcome": "failure",
                    "error": _error_evidence(access_rejection_payload(exc)),
                }
            )
            _apply_failure_usage(
                record,
                request_limit=request_limit,
                body_limit=body_limit,
                robots_limit=robots_limit,
            )
        except ROLLBACK_REQUIRED_READ_ERRORS as exc:
            failed = True
            request_count += request_limit
            response_bytes += body_limit + robots_limit
            record.update(
                {
                    "outcome": "failure",
                    "error": _error_evidence(governed_read_failure_payload(exc)),
                }
            )
            _apply_failure_usage(
                record,
                request_limit=request_limit,
                body_limit=body_limit,
                robots_limit=robots_limit,
            )
        except Exception as exc:
            failed = True
            request_count += request_limit
            response_bytes += body_limit + robots_limit
            record.update(
                {
                    "outcome": "failure",
                    "error": _error_evidence(
                        {
                            "error_code": "legacy.unexpected",
                            "error_type": type(exc).__name__,
                        }
                    ),
                }
            )
            _apply_failure_usage(
                record,
                request_limit=request_limit,
                body_limit=body_limit,
                robots_limit=robots_limit,
            )
        finally:
            if gateway is not None:
                gateway.close()
        profile_cases.append(_profile_case_evidence(case, profile_observations))
        records.append(record)
    output = {
        "old_commit": payload["old_commit"],
        "environment": payload["environment"],
        "http_profile": {
            "schema_version": "phase-20-http-profile-evidence.v1",
            "provenance": payload["http_profile"]["provenance"],
            "identity": observed_identity if observed_identity is not None else "N/A",
            "authority": profile_authority,
            "cases": profile_cases,
        },
        "cases": records,
        "budget": {
            "requests": request_count,
            "requests_basis": "exact on success; per-case upper bound on failure",
            "max_requests": payload["limits"]["max_total_requests"],
            "response_bytes": response_bytes,
            "response_bytes_basis": (
                "target wire/decoded maximum on success or per-case upper bound on "
                "failure, plus frozen robots upper bound"
            ),
            "robots_response_bytes_upper_bound": robots_limit * len(payload["cases"]),
            "max_response_bytes": payload["limits"]["max_total_response_bytes"],
            "elapsed_seconds": round(
                governed_seconds - max(0.0, deadline - time.monotonic()),
                3,
            ),
            "max_seconds": payload["limits"]["timeout_seconds"],
            "governed_network_seconds": governed_seconds,
            "outer_process_max_seconds": payload["limits"]["timeout_seconds"],
            "concurrency": 1,
            "retry": 0,
        },
    }
    print(json.dumps(output), flush=True)
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
