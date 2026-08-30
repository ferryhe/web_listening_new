"""Run the current governed acquisition path as a bounded child process."""

# pylint: disable=duplicate-code,missing-function-docstring,too-many-locals
# pylint: disable=too-many-statements
# pylint: disable=protected-access,too-few-public-methods,too-many-return-statements

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
import sys
import time
from html.parser import HTMLParser
from pathlib import Path

from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.runtime.jobs import JobRepository
from web_listening.runtime.service import RuntimeService
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners import in_process as in_process_runner
from web_listening.tool_registry.runners.in_process import (
    WEB_HTTP_REQUEST_PROFILE,
    WEB_HTTP_REQUEST_PROFILE_SHA256,
    PinnedHttpTransport,
    TransportResponse,
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


class _NetworkBudget:
    def __init__(self, limits: dict[str, object], governed_seconds: int) -> None:
        self.max_requests = int(limits["max_total_requests"])
        self.max_response_bytes = int(limits["max_total_response_bytes"])
        self.max_seconds = governed_seconds
        self.started = time.monotonic()
        self.requests = 0
        self.response_bytes = 0

    @property
    def remaining_seconds(self) -> float:
        return self.max_seconds - (time.monotonic() - self.started)


def _http_profile_descriptor() -> dict[str, object]:
    fields = tuple(WEB_HTTP_REQUEST_PROFILE.items())
    return {
        "fields": [list(item) for item in fields],
        "sha256": hashlib.sha256(
            json.dumps(
                dict(fields),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest(),
    }


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


def _empty_http_profile_evidence(cases: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "phase-20-http-profile-evidence.v1",
        "provenance": "N/A",
        "identity": "N/A",
        "authority": "N/A",
        "cases": [_profile_case_evidence(case, []) for case in cases],
    }


class _CappedResponse:
    def __init__(self, response: TransportResponse, budget: _NetworkBudget) -> None:
        self.status = response.status
        self.headers = response.headers
        self.peer_ip = response.peer_ip
        self._response = response
        self._budget = budget

    def read(self, max_bytes: int) -> bytes:
        remaining = self._budget.max_response_bytes - self._budget.response_bytes
        if self._budget.remaining_seconds <= 0 or remaining <= 0:
            raise TimeoutError
        try:
            content = self._response.read(min(max_bytes, remaining))
        except in_process_runner._PartialBodyRead as exc:
            self._budget.response_bytes += len(exc.partial)
            raise
        self._budget.response_bytes += len(content)
        return content

    def set_timeout(self, timeout: float) -> None:
        setter = getattr(self._response, "set_timeout", None)
        if callable(setter):
            setter(min(timeout, self._budget.remaining_seconds))

    def close(self) -> None:
        self._response.close()


class _CappedTransport:
    def __init__(
        self,
        budget: _NetworkBudget,
        profile_observations: list[dict[str, object]],
        *,
        transport=None,
    ) -> None:
        self._budget = budget
        self._profile_observations = profile_observations
        self._transport = transport if transport is not None else PinnedHttpTransport()

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> _CappedResponse:
        remaining = self._budget.remaining_seconds
        if self._budget.requests >= self._budget.max_requests or remaining <= 0:
            raise TimeoutError
        self._budget.requests += 1
        descriptor = _http_profile_descriptor()
        if descriptor["sha256"] != WEB_HTTP_REQUEST_PROFILE_SHA256:
            raise RuntimeError("new HTTP request profile authority drifted")
        self._profile_observations.append(descriptor)
        response = self._transport.send(
            url, timeout=min(timeout, remaining), addresses=addresses
        )
        return _CappedResponse(response, self._budget)

    def close(self) -> None:
        self._transport.close()


def _request_descriptor(request: Request) -> dict[str, object]:
    return {
        "schema_version": "phase-20-request-descriptor.v1",
        "scope": {
            "seeds": list(request.scope.seeds),
            "allowed_origins": list(request.scope.allowed_origins),
            "include_paths": list(request.scope.include_paths),
            "content_types": [item.value for item in request.scope.content_types],
        },
        "request": {
            "site_skill": "N/A" if request.site_skill is None else "present",
            "explore_all_tools": request.explore_all_tools,
        },
        "budgets": {
            "max_requests": request.budgets.max_requests,
            "max_bytes": request.budgets.max_bytes,
            "max_runtime_seconds": request.budgets.max_runtime_seconds,
            "max_tool_attempts_per_target": (
                request.budgets.max_tool_attempts_per_target
            ),
        },
    }


def _request_digest(descriptor: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _base_record(case: dict[str, object]) -> dict[str, object]:
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
        "outcome": "failure",
        "artifact": {"availability": "none", "count": 0, "items": []},
        "observation": {"availability": "none", "count": 0, "items": []},
        "manifest": {"availability": "none", "value": None},
        "attempts": [],
        "usage": {
            "requests": 0,
            "transport_requests": 0,
            "bytes_received": 0,
            "transport_response_bytes": 0,
            "target_bytes": 0,
            "tool_attempts": 0,
            "bytes_basis": "not-run",
            "within_budget": True,
        },
        "error": None,
    }


def _failure_evidence(
    payload: dict[str, object],
    invocation: dict[str, object],
    failure: dict[str, object],
) -> dict[str, object]:
    limits = payload["limits"]
    records = []
    for case in payload["cases"]:
        record = _base_record(case)
        record["usage"].update(
            {
                "requests": "N/A",
                "transport_requests": "N/A",
                "bytes_received": "N/A",
                "transport_response_bytes": "N/A",
                "target_bytes": "N/A",
                "tool_attempts": "N/A",
                "bytes_basis": "N/A: child did not provide evidence",
                "within_budget": False,
            }
        )
        record["error"] = [
            {
                "code": failure["error_code"],
                "message": "N/A",
                "retryable": "N/A",
                "details": "N/A",
                "error_type": failure["error_type"],
            }
        ]
        records.append(record)
    return {
        "environment": payload["environment"],
        "http_profile": _empty_http_profile_evidence(payload["cases"]),
        "cases": records,
        "budget": {
            "requests": "N/A",
            "case_request_total": "N/A",
            "max_requests": int(limits["max_total_requests"]),
            "response_bytes": "N/A",
            "case_response_bytes_total": "N/A",
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


def _request_evidence_is_complete(descriptor: object, digest: object) -> bool:
    if descriptor == "N/A":
        return digest == "N/A"
    if not isinstance(descriptor, dict) or not isinstance(digest, str):
        return False
    try:
        return (
            set(descriptor) == {"schema_version", "scope", "request", "budgets"}
            and descriptor["schema_version"] == "phase-20-request-descriptor.v1"
            and isinstance(descriptor["scope"], dict)
            and set(descriptor["scope"])
            == {"seeds", "allowed_origins", "include_paths", "content_types"}
            and isinstance(descriptor["request"], dict)
            and set(descriptor["request"]) == {"site_skill", "explore_all_tools"}
            and isinstance(descriptor["budgets"], dict)
            and set(descriptor["budgets"])
            == {
                "max_requests",
                "max_bytes",
                "max_runtime_seconds",
                "max_tool_attempts_per_target",
            }
            and all(
                isinstance(values, list)
                and all(isinstance(item, str) for item in values)
                for values in descriptor["scope"].values()
            )
            and descriptor["request"]
            == {"site_skill": "N/A", "explore_all_tools": False}
            and all(
                isinstance(value, int) and not isinstance(value, bool) and value > 0
                for value in descriptor["budgets"].values()
            )
            and digest == _request_digest(descriptor)
        )
    except (KeyError, TypeError):
        return False


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


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
    observed = {
        "fields": fields,
        "sha256": hashlib.sha256(
            json.dumps(
                dict((item[0], item[1]) for item in fields),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest(),
    }
    return observed == value


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
    if (
        value["schema_version"] != "phase-20-http-profile-evidence.v1"
        or value["provenance"] != "N/A"
        or value["identity"] != "N/A"
        or not _profile_descriptor_is_complete(value["authority"])
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


def _optional_text(value: object) -> bool:
    return value is None or isinstance(value, str)


def _artifact_shape(value: object) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("items"), list):
        return False
    items = value["items"]
    return (
        value.get("availability") in {"present", "none"}
        and _nonnegative_int(value.get("count"))
        and value["count"] == len(items)
        and all(
            isinstance(item, dict)
            and all(
                isinstance(item.get(key), str)
                for key in (
                    "artifact_id",
                    "observation_id",
                    "mime_type",
                    "sha256",
                )
            )
            and _nonnegative_int(item.get("size_bytes"))
            for item in items
        )
    )


def _observation_shape(value: object) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("items"), list):
        return False
    items = value["items"]
    return (
        value.get("availability") in {"present", "none"}
        and _nonnegative_int(value.get("count"))
        and value["count"] == len(items)
        and all(
            isinstance(item, dict)
            and isinstance(item.get("artifact_id"), str)
            and isinstance(item.get("observation_id"), str)
            for item in items
        )
    )


def _manifest_shape(value: object) -> bool:
    if not isinstance(value, dict) or value.get("availability") not in {
        "present",
        "none",
    }:
        return False
    manifest = value.get("value")
    if value["availability"] == "none":
        return manifest is None
    if not isinstance(manifest, dict) or not isinstance(
        manifest.get("artifacts"), list
    ):
        return False
    return (
        all(
            key in manifest
            for key in (
                "sha256",
                "size_bytes",
                "mime_type",
                "tool_id",
                "tool_version",
            )
        )
        and all(
            isinstance(item, dict)
            and isinstance(item.get("artifact_id"), str)
            and isinstance(item.get("observation_id"), str)
            for item in manifest["artifacts"]
        )
        and _optional_text(manifest["sha256"])
        and (manifest["size_bytes"] is None or _nonnegative_int(manifest["size_bytes"]))
        and _optional_text(manifest["mime_type"])
        and _optional_text(manifest["tool_id"])
        and _optional_text(manifest["tool_version"])
    )


def _attempts_shape(value: object) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, dict)
        and isinstance(item.get("outcome"), str)
        and isinstance(item.get("tool_id"), str)
        and isinstance(item.get("tool_version"), str)
        for item in value
    )


def _error_shape(value: object) -> bool:
    if value is None:
        return True
    required = {"code", "message", "retryable", "details", "error_type"}
    if not isinstance(value, list) or not value:
        return False
    return all(
        isinstance(item, dict)
        and set(item) == required
        and isinstance(item["code"], str)
        and bool(item["code"])
        and isinstance(item["message"], str)
        and bool(item["message"])
        and (isinstance(item["retryable"], bool) or item["retryable"] == "N/A")
        and (
            item["details"] == "N/A"
            or (
                isinstance(item["details"], dict)
                and all(
                    isinstance(key, str) and isinstance(detail, str)
                    for key, detail in item["details"].items()
                )
            )
        )
        and isinstance(item["error_type"], str)
        and bool(item["error_type"])
        for item in value
    )


def _usage_shape(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    return (
        all(
            _nonnegative_int(value.get(key))
            for key in (
                "requests",
                "transport_requests",
                "bytes_received",
                "transport_response_bytes",
                "target_bytes",
                "tool_attempts",
            )
        )
        and value["requests"] == value["transport_requests"]
        and value["bytes_received"] == value["transport_response_bytes"]
        and isinstance(value.get("bytes_basis"), str)
        and isinstance(value.get("within_budget"), bool)
    )


def _record_is_complete(record: object, expected: dict[str, object]) -> bool:
    if not isinstance(record, dict):
        return False
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
    try:
        return (
            required <= set(record)
            and record["case_id"] == expected["case_id"]
            and record["requested_url"] == expected["requested_url"]
            and _request_evidence_is_complete(
                record["request_descriptor"], record["request_digest"]
            )
            and isinstance(record["redirects"], list)
            and all(isinstance(item, dict) for item in record["redirects"])
            and _artifact_shape(record["artifact"])
            and _observation_shape(record["observation"])
            and _manifest_shape(record["manifest"])
            and _attempts_shape(record["attempts"])
            and _usage_shape(record["usage"])
            and _optional_text(record["final_url"])
            and _optional_text(record["mime_type"])
            and _optional_text(record["content_sha256"])
            and (record["status"] is None or _nonnegative_int(record["status"]))
            and (
                record["content_bytes"] is None
                or _nonnegative_int(record["content_bytes"])
            )
            and (record["word_count"] is None or _nonnegative_int(record["word_count"]))
            and (
                record["document_link_count"] is None
                or _nonnegative_int(record["document_link_count"])
            )
            and record["outcome"] in {"success", "failure"}
            and _error_shape(record["error"])
        )
    except (KeyError, TypeError):
        return False


def _budget_is_complete(budget: object, payload: dict[str, object]) -> bool:
    if not isinstance(budget, dict):
        return False
    limits = payload["limits"]
    try:
        elapsed = budget["elapsed_seconds"]
        return (
            isinstance(elapsed, (int, float))
            and not isinstance(elapsed, bool)
            and math.isfinite(elapsed)
            and 0 <= elapsed <= int(limits["timeout_seconds"])
            and budget["max_seconds"] == int(limits["timeout_seconds"]) == 30
            and budget["governed_network_seconds"]
            == int(payload["governed_network_timeout_seconds"])
            == 28
            and budget["max_requests"] == int(limits["max_total_requests"]) == 8
            and budget["max_response_bytes"]
            == int(limits["max_total_response_bytes"])
            == 4 * 1024 * 1024
            and _nonnegative_int(budget["requests"])
            and budget["requests"] <= budget["max_requests"]
            and _nonnegative_int(budget["case_request_total"])
            and budget["case_request_total"] == budget["requests"]
            and _nonnegative_int(budget["response_bytes"])
            and budget["response_bytes"] <= budget["max_response_bytes"]
            and _nonnegative_int(budget["case_response_bytes_total"])
            and budget["case_response_bytes_total"] == budget["response_bytes"]
            and budget["concurrency"] == 1
            and budget["retry"] == 0
        )
    except (KeyError, TypeError):
        return False


def _output_is_complete(evidence: object, payload: dict[str, object]) -> bool:
    if not isinstance(evidence, dict) or evidence.get("environment") != payload.get(
        "environment"
    ):
        return False
    if not _http_profile_is_complete(evidence.get("http_profile"), payload["cases"]):
        return False
    records = evidence.get("cases")
    expected = payload["cases"]
    shape_is_complete = (
        isinstance(records, list)
        and len(records) == len(expected)
        and _budget_is_complete(evidence.get("budget"), payload)
        and all(
            _record_is_complete(record, case)
            for case, record in zip(expected, records, strict=True)
        )
    )
    if not shape_is_complete:
        return False
    case_request_total = sum(
        record["usage"]["transport_requests"] for record in records
    )
    case_response_total = sum(
        record["usage"]["transport_response_bytes"] for record in records
    )
    return (
        case_request_total == evidence["budget"]["case_request_total"]
        and case_response_total == evidence["budget"]["case_response_bytes_total"]
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
        failure = ("new.process_timeout", "timeout", "N/A", exc)
    except OSError as exc:
        failure = ("new.process_spawn", "not-started", "N/A", exc)
    else:
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        if not lines:
            failure = (
                "new.no_output",
                "exited-without-evidence",
                completed.returncode,
                RuntimeError(),
            )
        else:
            try:
                evidence = json.loads(lines[-1])
            except json.JSONDecodeError as exc:
                failure = (
                    "new.output_parse",
                    "invalid-evidence",
                    completed.returncode,
                    exc,
                )
            else:
                if _output_is_complete(evidence, payload):
                    evidence.update(
                        {
                            "invocation": invocation,
                            "process_outcome": (
                                "exited-success"
                                if completed.returncode == 0
                                else "exited-failure"
                            ),
                            "process_return_code": completed.returncode,
                        }
                    )
                    return evidence
                failure = (
                    "new.output_schema",
                    "invalid-evidence",
                    completed.returncode,
                    TypeError(),
                )
    return _failure_evidence(
        payload,
        invocation,
        {
            "error_code": failure[0],
            "error_type": type(failure[3]).__name__,
            "process_outcome": failure[1],
            "process_return_code": failure[2],
        },
    )


def _execute(payload: dict[str, object]) -> dict[str, object]:
    limits = payload["limits"]
    governed_seconds = int(payload["governed_network_timeout_seconds"])
    budget = _NetworkBudget(limits, governed_seconds)
    profile_observations: list[dict[str, object]] = []
    registry = Registry()
    tool = WebHttpAcquisitionTool(
        lambda: _CappedTransport(budget, profile_observations)
    )
    registry.register(WEB_HTTP_MANIFEST, tool)
    store = ArtifactStore(Path(payload["artifact_root"]))
    identifiers = iter(
        f"phase20-{payload['target']['site_key']}-{index}" for index in range(2)
    )
    service = RuntimeService(
        registry,
        store,
        JobRepository(),
        job_id_factory=lambda: next(identifiers),
    )
    records = []
    profile_cases = []
    request_count = int(limits["max_total_requests"]) // len(payload["cases"])
    response_bytes = int(limits["max_total_response_bytes"]) // len(payload["cases"])
    try:
        for case in payload["cases"]:
            record = _base_record(case)
            profile_start = len(profile_observations)
            case_requests_before = budget.requests
            case_response_bytes_before = budget.response_bytes
            if budget.remaining_seconds <= 0:
                record["error"] = [{"code": "phase20.aggregate_budget"}]
                records.append(record)
                profile_cases.append(_profile_case_evidence(case, []))
                continue
            request = Request(
                Scope(
                    (str(case["requested_url"]),),
                    tuple(str(item) for item in payload["target"]["allowed_origins"]),
                    ("/**",),
                    (ContentType.HTML,),
                ),
                None,
                False,
                Budgets(request_count, response_bytes, governed_seconds, 1),
            )
            descriptor = _request_descriptor(request)
            record["request_descriptor"] = descriptor
            record["request_digest"] = _request_digest(descriptor)
            job = service.run(request)
            if job.result is None:
                raise RuntimeError("new Runtime returned no Result")
            result = job.result
            artifacts = list(result.artifacts)
            stored_rows = [
                store.get_observation(item.observation_id) for item in artifacts
            ]
            usage = result.usage.to_dict()
            case_transport_response_bytes = (
                budget.response_bytes - case_response_bytes_before
            )
            case_transport_requests = budget.requests - case_requests_before
            usage.update(
                {
                    "transport_requests": case_transport_requests,
                    "transport_response_bytes": case_transport_response_bytes,
                    "target_bytes": (
                        result.manifest.size_bytes
                        if result.status.value == "completed"
                        else result.usage.bytes_received
                    ),
                    "bytes_basis": (
                        "target_body"
                        if result.status.value == "completed"
                        else "aggregate_gateway"
                    ),
                    "within_budget": (
                        budget.requests <= budget.max_requests
                        and budget.response_bytes <= budget.max_response_bytes
                    ),
                }
            )
            record.update(
                {
                    "outcome": (
                        "success" if result.status.value == "completed" else "failure"
                    ),
                    "artifact": {
                        "availability": "present" if artifacts else "none",
                        "count": len(artifacts),
                        "items": [item.to_dict() for item in artifacts],
                    },
                    "observation": {
                        "availability": "present" if stored_rows else "none",
                        "count": len(stored_rows),
                        "items": [
                            {
                                "observation_id": row.observation.observation_id,
                                "artifact_id": row.observation.artifact_id,
                            }
                            for row in stored_rows
                        ],
                    },
                    "manifest": {
                        "availability": "present",
                        "value": result.manifest.to_dict(),
                    },
                    "attempts": [item.to_dict() for item in result.attempts],
                    "usage": usage,
                    "error": (
                        [
                            {
                                "code": item.code,
                                "message": item.message,
                                "retryable": "N/A",
                                "details": dict(item.details),
                                "error_type": "N/A",
                            }
                            for item in result.errors
                        ]
                        or None
                    ),
                }
            )
            if result.status.value == "completed":
                stored = stored_rows[0]
                words, document_links = _page_evidence(stored.content)
                record.update(
                    {
                        "final_url": result.manifest.final_url,
                        "redirects": [
                            item.to_dict() for item in result.manifest.redirects
                        ],
                        "status": result.manifest.http_status,
                        "mime_type": result.manifest.mime_type,
                        "content_sha256": result.manifest.sha256,
                        "content_bytes": result.manifest.size_bytes,
                        "word_count": words,
                        "document_link_count": document_links,
                    }
                )
            profile_cases.append(
                _profile_case_evidence(case, profile_observations[profile_start:])
            )
            records.append(record)
    finally:
        store.close()
        tool.close()
    return {
        "environment": payload["environment"],
        "http_profile": {
            "schema_version": "phase-20-http-profile-evidence.v1",
            "provenance": "N/A",
            "identity": "N/A",
            "authority": _http_profile_descriptor(),
            "cases": profile_cases,
        },
        "cases": records,
        "budget": {
            "requests": budget.requests,
            "case_request_total": sum(
                row["usage"]["transport_requests"] for row in records
            ),
            "max_requests": budget.max_requests,
            "response_bytes": budget.response_bytes,
            "case_response_bytes_total": sum(
                row["usage"]["transport_response_bytes"] for row in records
            ),
            "max_response_bytes": budget.max_response_bytes,
            "elapsed_seconds": round(time.monotonic() - budget.started, 3),
            "max_seconds": limits["timeout_seconds"],
            "governed_network_seconds": governed_seconds,
            "concurrency": 1,
            "retry": 0,
        },
    }


def main() -> None:
    payload = json.load(sys.stdin)
    output = _execute(payload)
    print(json.dumps(output, sort_keys=True), flush=True)
    if any(record["outcome"] != "success" for record in output["cases"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
