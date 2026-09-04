"""Strict acquisition handoff contract and canonical fixture tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import json
import tomllib
from copy import deepcopy
from pathlib import Path

import pytest

from web_listening.result.handoff import (
    AcquisitionHandoff,
    HandoffValidationError,
    make_handoff,
)

ROOT = Path(__file__).parents[2]
FIXTURES = Path(__file__).parent / "fixtures"
SCHEMA = ROOT / "schemas" / "acquisition-handoff.v1.schema.json"
NAMES = ("completed", "partial", "rejected", "failed")


def _payload(name: str = "completed") -> dict[str, object]:
    path = FIXTURES / f"acquisition-handoff-{name}.v1.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _payload_with_transform() -> dict[str, object]:
    payload = _payload("partial")
    result = json.loads((FIXTURES / "partial.v1.json").read_text(encoding="utf-8"))
    derived = result["artifacts"][1]
    tool_id = "simple_html_markdown"
    tool_version = "1.0.0"
    derived["source_url"] = f"urn:web-listening:transform:{tool_id}:{tool_version}"
    derived.update(
        {
            "tool_id": tool_id,
            "tool_version": tool_version,
            "content_ref": f"/v1/artifacts/{derived['artifact_id']}",
        }
    )
    payload["artifacts"].append(derived)
    payload["attempts"].append(
        {
            "schema_version": "web-listening-attempt.v1",
            "order": 1,
            "attempt_id": "attempt-transform-1",
            "outcome": "succeeded",
            "tool_id": tool_id,
            "tool_version": tool_version,
            "started_at": "2026-08-25T15:00:02Z",
            "finished_at": "2026-08-25T15:00:03Z",
            "requested_url": payload["artifacts"][0]["source_url"],
            "final_url": None,
            "http_status": None,
            "error": None,
            "requests": 0,
            "bytes_received": 0,
            "runtime_ms": 5,
        }
    )
    payload["usage"]["tool_attempts"] = 2
    payload.pop("handoff_id")
    return make_handoff(payload).to_dict()


@pytest.mark.parametrize("name", NAMES)
def test_canonical_fixtures_are_strict_schema_valid_and_canonical(name: str) -> None:
    raw = (FIXTURES / f"acquisition-handoff-{name}.v1.json").read_bytes()
    handoff = AcquisitionHandoff.from_json(raw)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert (
        schema["properties"]["schema_version"]["const"]
        == handoff.to_dict()["schema_version"]
    )
    assert raw == handoff.canonical_json_bytes() + b"\n"
    assert "manifest_id" not in handoff.to_dict()
    assert handoff.to_dict()["schema_version"] != "web-listening-manifest.v1"


def test_duplicate_keys_are_rejected_at_every_depth() -> None:
    for raw in (
        '{"x":1,"x":2}',
        '{"x":{"y":1,"y":2}}',
        '{"x":[{"y":1,"y":2}]}',
    ):
        with pytest.raises(HandoffValidationError, match="handoff.duplicate_key"):
            AcquisitionHandoff.from_json(raw)


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        (lambda value: value.__setitem__("extra", 1), "schema.unknown_fields"),
        (lambda value: value.pop("usage"), "schema.missing_fields"),
        (lambda value: value.__setitem__("run_id", "other"), "handoff.run_id_mismatch"),
        (
            lambda value: value["source"].__setitem__(
                "source_id", "https://other.test/"
            ),
            "handoff.source_id_mismatch",
        ),
        (
            lambda value: value["producer"].__setitem__("version", "0.1.0"),
            "handoff.producer_invalid",
        ),
        (
            lambda value: value.__setitem__("handoff_id", "0" * 64),
            "handoff.id_mismatch",
        ),
    ),
)
def test_tampered_contract_fails_closed(mutation: object, code: str) -> None:
    payload = deepcopy(_payload())
    mutation(payload)  # type: ignore[operator]
    with pytest.raises(HandoffValidationError, match=code):
        AcquisitionHandoff.from_dict(payload)


@pytest.mark.parametrize(
    "unsafe",
    (
        "https://user:password@example.test/",
        "authorization=Bearer abcdefgh",
        "cookie=sessionid%3Dabcdef",
        "/tmp/private/artifact.bin",
        "https://example.test/%2561uthorization%253Dbearer%2520abcdefgh",
    ),
)
def test_sensitive_and_local_values_fail_closed(unsafe: str) -> None:
    payload = deepcopy(_payload("failed"))
    payload["errors"][0]["details"]["unsafe"] = unsafe  # type: ignore[index]
    with pytest.raises(HandoffValidationError):
        AcquisitionHandoff.from_dict(payload)


def test_construction_detaches_all_nested_caller_owned_json() -> None:
    payload = _payload()
    handoff = AcquisitionHandoff.from_dict(payload)
    expected_bytes = handoff.canonical_json_bytes()
    expected_payload = handoff.to_dict()

    payload["producer"]["version"] = "tampered"  # type: ignore[index]
    payload["artifacts"][0]["tool_id"] = "tampered"  # type: ignore[index]
    payload["source"]["redirects"][0]["to_url"] = "https://other.test/"  # type: ignore[index]

    assert handoff.to_dict() == expected_payload
    assert handoff.canonical_json_bytes() == expected_bytes
    assert AcquisitionHandoff.from_json(expected_bytes) == handoff


@pytest.mark.parametrize(
    ("name", "mutation", "code"),
    (
        (
            "completed",
            lambda value: value["errors"].append(
                {"code": "gateway.timeout", "message": "Failed", "details": {}}
            ),
            "result.completed_has_failure",
        ),
        (
            "partial",
            lambda value: value["errors"].clear(),
            "result.partial_requires_failure",
        ),
        (
            "rejected",
            lambda value: value["errors"].clear(),
            "result.rejected_requires_error",
        ),
        (
            "failed",
            lambda value: value["errors"].clear(),
            "result.failed_requires_error",
        ),
    ),
)
def test_parser_rejects_impossible_result_status_variants(
    name: str, mutation: object, code: str
) -> None:
    payload = _payload(name)
    mutation(payload)  # type: ignore[operator]
    with pytest.raises(HandoffValidationError, match=code):
        AcquisitionHandoff.from_dict(payload)


def test_parser_and_schema_reject_local_artifact_file_uri() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    payload = _payload()
    payload["artifacts"][0]["source_url"] = "file:///tmp/private.bin"  # type: ignore[index]
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(payload)
    with pytest.raises(HandoffValidationError):
        AcquisitionHandoff.from_dict(payload)


@pytest.mark.parametrize("name", ("completed", "partial"))
def test_schema_rejects_impossible_success_status_variants(name: str) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    payload = _payload(name)
    if name == "completed":
        payload["errors"].append(
            {"code": "gateway.timeout", "message": "Failed", "details": {}}
        )
    else:
        payload["errors"].clear()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(payload)


@pytest.mark.parametrize("name", ("rejected", "failed"))
def test_no_artifact_handoff_rejects_final_url(name: str) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    payload = _payload(name)
    payload["source"]["final_url"] = payload["source"]["current_url"]  # type: ignore[index]
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(payload)
    with pytest.raises(HandoffValidationError, match="manifest.artifact_required"):
        AcquisitionHandoff.from_dict(payload)


def test_rejected_redirect_must_end_the_chain() -> None:
    payload = _payload("failed")
    requested = payload["source"]["requested_url"]  # type: ignore[index]
    payload["source"]["redirects"] = [  # type: ignore[index]
        {
            "order": 0,
            "from_url": requested,
            "to_url": "https://other.test/rejected",
            "http_status": 302,
            "decision": "rejected",
        },
        {
            "order": 1,
            "from_url": requested,
            "to_url": "https://other.test/followed",
            "http_status": 302,
            "decision": "followed",
        },
    ]

    with pytest.raises(HandoffValidationError, match="redirect.chain_invalid"):
        AcquisitionHandoff.from_dict(payload)


def test_successful_handoff_rejects_rejected_redirect_evidence() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    payload = _payload("completed")
    payload["source"]["redirects"][0]["decision"] = "rejected"  # type: ignore[index]
    payload["source"]["current_url"] = payload["source"]["requested_url"]  # type: ignore[index]
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(payload)
    with pytest.raises(HandoffValidationError, match="redirect.chain_invalid"):
        AcquisitionHandoff.from_dict(payload)


def test_schema_limits_rejected_redirect_to_one_terminal_decision() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    payload = _payload("failed")
    requested = payload["source"]["requested_url"]  # type: ignore[index]
    rejected = {
        "order": 0,
        "from_url": requested,
        "to_url": "https://other.test/rejected",
        "http_status": 302,
        "decision": "rejected",
    }
    payload["source"]["redirects"] = [  # type: ignore[index]
        rejected,
        {**rejected, "order": 1},
    ]
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(payload)


def test_valid_transform_handoff_is_accepted() -> None:
    AcquisitionHandoff.from_dict(_payload_with_transform())


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["attempts"][1].__setitem__(
            "requested_url", "https://other.test/unrelated"
        ),
        lambda value: value["artifacts"].pop(),
        lambda value: value["artifacts"].append(deepcopy(value["artifacts"][1])),
        lambda value: value["artifacts"][1].__setitem__(
            "source_url", "urn:web-listening:transform:other:1.0.0"
        ),
        lambda value: value["artifacts"][1].__setitem__("tool_id", "other"),
    ),
)
def test_transform_attempt_artifact_bijection_fails_closed(mutation: object) -> None:
    payload = _payload_with_transform()
    mutation(payload)  # type: ignore[operator]

    with pytest.raises(HandoffValidationError):
        AcquisitionHandoff.from_dict(payload)


def test_duplicate_successful_transform_attempts_are_rejected() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    payload = _payload_with_transform()
    duplicate = deepcopy(payload["attempts"][1])
    duplicate.update({"order": 2, "attempt_id": "attempt-transform-2"})
    payload["attempts"].append(duplicate)
    payload["usage"]["tool_attempts"] = 3

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(payload)
    with pytest.raises(
        HandoffValidationError, match="manifest.success_cardinality_invalid"
    ):
        AcquisitionHandoff.from_dict(payload)


@pytest.mark.parametrize("fact", ("observation", "attempt"))
def test_facts_after_generated_at_are_rejected(fact: str) -> None:
    payload = _payload("completed")
    future = "2099-01-01T00:00:00Z"
    if fact == "observation":
        payload["artifacts"][0]["observed_at"] = future
    else:
        payload["attempts"][0]["started_at"] = future
        payload["attempts"][0]["finished_at"] = future

    with pytest.raises(HandoffValidationError, match="job.time_invalid"):
        AcquisitionHandoff.from_dict(payload)


@pytest.mark.parametrize(
    "location",
    (
        "source_id",
        "requested_url",
        "current_url",
        "final_url",
        "redirect_from",
        "redirect_to",
        "artifact_source",
        "attempt_requested",
        "attempt_final",
    ),
)
@pytest.mark.parametrize(
    "unsafe",
    (
        "https://user:password@example.test/report",
        "https://user@example.test/report",
        "https://user%40example.test/report",
    ),
)
def test_schema_and_parser_reject_http_userinfo_everywhere(
    location: str, unsafe: str
) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    payload = _payload("completed")
    if location.startswith("redirect_"):
        key = "from_url" if location.endswith("from") else "to_url"
        payload["source"]["redirects"][0][key] = unsafe  # type: ignore[index]
    elif location == "artifact_source":
        payload["artifacts"][0]["source_url"] = unsafe  # type: ignore[index]
    elif location.startswith("attempt_"):
        key = "requested_url" if location.endswith("requested") else "final_url"
        payload["attempts"][0][key] = unsafe  # type: ignore[index]
    else:
        payload["source"][location] = unsafe  # type: ignore[index]
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(payload)
    with pytest.raises(HandoffValidationError, match="result.sensitive_data"):
        AcquisitionHandoff.from_dict(payload)


@pytest.mark.parametrize(
    "url", ("https://[2001:db8::1]:8443/report", "http://example.test:8080/report")
)
def test_schema_and_parser_keep_valid_ipv6_and_port_urls(url: str) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    payload = _payload("failed")
    payload["source"].update(  # type: ignore[union-attr]
        {"source_id": url, "requested_url": url, "current_url": url}
    )
    payload["attempts"][0]["requested_url"] = url  # type: ignore[index]
    payload.pop("handoff_id")
    handoff = make_handoff(payload)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(handoff.to_dict())


def _assert_schema_and_parser_reject(payload: dict[str, object]) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(payload)
    with pytest.raises(HandoffValidationError):
        AcquisitionHandoff.from_dict(payload)


def _failed_payload_for_url(url: str) -> dict[str, object]:
    payload = _payload("failed")
    payload["source"].update(  # type: ignore[union-attr]
        {"source_id": url, "requested_url": url, "current_url": url}
    )
    payload["attempts"][0]["requested_url"] = url  # type: ignore[index]
    return payload


@pytest.mark.parametrize(
    "url",
    (
        "https://example.test:0/",
        "https://example.test:65536/",
        "https://exa_mple.test/",
        "https://999.999.999.999/",
        "https://-bad.example/",
        "https://bad-.example/",
        f"https://{'x' * 64}.example/",
        "https://example.test:%31/",
        "https://example.test:abc/",
        "https://%6xample.test/",
        "https://example.test/%zz",
        "https://2001:db8::1/",
    ),
)
def test_schema_and_parser_reject_invalid_url_authorities(url: str) -> None:
    _assert_schema_and_parser_reject(_failed_payload_for_url(url))


@pytest.mark.parametrize(
    "url",
    (
        "https://example.test:1/",
        "https://example.test:65535/",
        "https://example.test:0001/",
        "https://example.test:065535/",
        "https://192.0.2.1/",
        "https://a/",
        "https://a-b.example.test/",
        "https://[2001:db8::1]/",
        "https://[2001:db8::1]:443/",
        "https://%65xample.test/",
    ),
)
def test_schema_and_parser_accept_valid_url_authorities(url: str) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    payload = _failed_payload_for_url(url)
    payload.pop("handoff_id")
    handoff = make_handoff(payload)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(handoff.to_dict())
    AcquisitionHandoff.from_dict(handoff.to_dict())


def test_schema_and_parser_reject_sha256_with_trailing_newline() -> None:
    payload = _payload()
    payload["handoff_id"] += "\n"  # type: ignore[operator]
    _assert_schema_and_parser_reject(payload)


@pytest.mark.parametrize("timestamp", ("2026-02-30T00:00:00Z", "2026-13-01T00:00:00Z"))
def test_schema_format_checker_rejects_impossible_calendar_dates(
    timestamp: str,
) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert (
        "jsonschema[format]>=4.0,<5"
        in project["project"]["optional-dependencies"]["dev"]
    )
    checker = jsonschema.FormatChecker()
    if "date-time" not in checker.checkers:
        pytest.skip("installed environment has not refreshed the declared dev extra")
    assert "date-time" in checker.checkers
    payload = _payload()
    payload["generated_at"] = timestamp
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema, format_checker=checker).validate(
            payload
        )
    with pytest.raises(HandoffValidationError, match="time.invalid"):
        AcquisitionHandoff.from_dict(payload)


@pytest.mark.parametrize("field", ("job_id", "run_id"))
@pytest.mark.parametrize("value", ("x" * 129, "", " padded", "padded ", "x\nvalue"))
def test_schema_and_parser_enforce_handoff_identifier_bounds(
    field: str, value: str
) -> None:
    payload = _payload()
    payload[field] = value
    _assert_schema_and_parser_reject(payload)


def test_schema_and_parser_require_success_final_url() -> None:
    payload = _payload()
    payload["source"]["final_url"] = None  # type: ignore[index]
    _assert_schema_and_parser_reject(payload)


@pytest.mark.parametrize(
    "mutation",
    (
        lambda attempt: attempt.__setitem__(
            "error", {"code": "tool.error", "message": "Failed", "details": {}}
        ),
        lambda attempt: attempt.update(
            {"final_url": None, "http_status": None, "requests": 1}
        ),
        lambda attempt: attempt.update(
            {"final_url": None, "http_status": None, "bytes_received": 1}
        ),
        lambda attempt: attempt.update({"http_status": None}),
        lambda attempt: attempt.update({"requests": 0}),
    ),
)
def test_schema_and_parser_enforce_succeeded_attempt_fields(mutation: object) -> None:
    payload = _payload()
    mutation(payload["attempts"][0])  # type: ignore[index,operator]
    _assert_schema_and_parser_reject(payload)


def test_schema_and_parser_require_failed_attempt_error() -> None:
    payload = _payload("failed")
    payload["attempts"][0]["error"] = None  # type: ignore[index]
    _assert_schema_and_parser_reject(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("final_url", "https://example.test/effect"),
        ("http_status", 503),
        ("requests", 1),
        ("bytes_received", 1),
        ("runtime_ms", 1),
        ("error", None),
    ),
)
def test_schema_and_parser_enforce_skipped_attempt_fields(
    field: str, value: object
) -> None:
    payload = _payload("failed")
    attempt = payload["attempts"][0]  # type: ignore[index]
    attempt.update(
        {
            "outcome": "skipped",
            "final_url": None,
            "http_status": None,
            "requests": 0,
            "bytes_received": 0,
            "runtime_ms": 0,
        }
    )
    attempt[field] = value
    _assert_schema_and_parser_reject(payload)


@pytest.mark.parametrize("field", ("attempt_id", "tool_id", "tool_version"))
def test_schema_and_parser_enforce_attempt_identifier_bounds(field: str) -> None:
    payload = _payload()
    payload["attempts"][0][field] = "x" * 129  # type: ignore[index]
    _assert_schema_and_parser_reject(payload)


@pytest.mark.parametrize("field", ("tool_id", "tool_version"))
def test_schema_and_parser_enforce_artifact_identifier_bounds(field: str) -> None:
    payload = _payload()
    payload["artifacts"][0][field] = "x" * 129  # type: ignore[index]
    _assert_schema_and_parser_reject(payload)


def test_schema_and_parser_forbid_source_lineage() -> None:
    payload = _payload()
    derived = json.loads((FIXTURES / "partial.v1.json").read_text(encoding="utf-8"))[
        "artifacts"
    ][1]
    payload["artifacts"][0]["lineage"] = derived["lineage"]  # type: ignore[index]
    _assert_schema_and_parser_reject(payload)


def test_schema_and_parser_require_exactly_one_source_artifact() -> None:
    payload = _payload_with_transform()
    payload["artifacts"][1].update(  # type: ignore[index]
        {
            "role": "source",
            "source_url": "https://example.test/second-source",
            "lineage": [],
        }
    )
    _assert_schema_and_parser_reject(payload)


@pytest.mark.parametrize("count", (0, 2))
def test_schema_and_parser_require_exactly_one_derived_lineage(count: int) -> None:
    payload = _payload_with_transform()
    lineage = payload["artifacts"][1]["lineage"]  # type: ignore[index]
    payload["artifacts"][1]["lineage"] = lineage * count  # type: ignore[index]
    _assert_schema_and_parser_reject(payload)


@pytest.mark.parametrize(
    "mutation",
    (
        lambda error: error.__setitem__("message", "x" * 513),
        lambda error: error.__setitem__("message", " padded"),
        lambda error: error.__setitem__("details", {"x" * 129: "value"}),
        lambda error: error.__setitem__("details", {"key": "x" * 513}),
        lambda error: error.__setitem__("details", {"key": ""}),
        lambda error: error.__setitem__("details", {"key\npart": "value"}),
    ),
)
def test_schema_and_parser_enforce_safe_error_local_bounds(mutation: object) -> None:
    payload = _payload("failed")
    mutation(payload["errors"][0])  # type: ignore[index,operator]
    _assert_schema_and_parser_reject(payload)


@pytest.mark.parametrize(
    ("location", "value"),
    (
        ("artifact_mime", "Text/HTML"),
        ("artifact_mime", "text/html; charset=utf-8"),
        ("artifact_mime", "text/html\n"),
        ("artifact_source", "https://example.test/" + "x" * 2030),
        ("attempt_url", "https://example.test/" + "x" * 2030),
    ),
)
def test_schema_and_parser_enforce_reused_scalar_bounds(
    location: str, value: str
) -> None:
    payload = _payload()
    if location == "artifact_mime":
        payload["artifacts"][0]["mime_type"] = value  # type: ignore[index]
    elif location == "artifact_source":
        payload["artifacts"][0]["source_url"] = value  # type: ignore[index]
    else:
        payload["attempts"][0]["requested_url"] = value  # type: ignore[index]
    _assert_schema_and_parser_reject(payload)
