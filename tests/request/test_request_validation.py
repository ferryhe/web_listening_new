"""Focused validation tests for the public Request contract."""

# pylint: disable=duplicate-code

from __future__ import annotations

from dataclasses import fields
from pathlib import Path

import pytest

from web_listening.request.model import Request, RequestValidationError
from web_listening.request.validate import request_from_json, request_from_mapping

FIXTURE = Path(__file__).parent / "fixtures" / "minimal_request.json"


def minimal_payload() -> dict[str, object]:
    """Return a fresh legal Request payload."""
    return {
        "scope": {
            "seeds": ["https://www.soa.org/"],
            "allowed_origins": ["https://www.soa.org"],
            "include_paths": ["/**"],
            "content_types": ["html"],
        },
        "site_skill": None,
        "explore_all_tools": False,
        "budgets": {
            "max_requests": 10,
            "max_bytes": 1_048_576,
            "max_runtime_seconds": 30,
            "max_tool_attempts_per_target": 2,
        },
    }


def test_minimal_request_fixture_is_accepted() -> None:
    """A sanitized offline fixture exercises the four-field public shape."""
    request = request_from_json(FIXTURE.read_text(encoding="utf-8"))

    assert tuple(field.name for field in fields(Request)) == (
        "scope",
        "site_skill",
        "explore_all_tools",
        "budgets",
    )
    assert request.scope.seeds == ("https://www.soa.org/",)
    assert request.explore_all_tools is False


def test_optional_request_values_use_readme_defaults() -> None:
    """The two README optional values do not add public inputs."""
    payload = minimal_payload()
    del payload["site_skill"]
    del payload["explore_all_tools"]

    request = request_from_mapping(payload)

    assert request.site_skill is None
    assert request.explore_all_tools is False


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda value: value["scope"].update(seeds=[]),
            "scope.empty_seeds",
        ),
        (
            lambda value: value["scope"].update(allowed_origins=[]),
            "scope.empty_allowed_origins",
        ),
        (
            lambda value: value["scope"].update(include_paths=[]),
            "scope.empty_include_paths",
        ),
        (
            lambda value: value["scope"].update(content_types=[]),
            "scope.empty_content_types",
        ),
        (
            lambda value: value["scope"].update(
                seeds=["https://user:secret@www.soa.org/"]
            ),
            "scope.url_userinfo",
        ),
        (
            lambda value: value["scope"].update(seeds=["https://www.soa.org/#section"]),
            "scope.url_fragment",
        ),
        (
            lambda value: value["scope"].update(
                seeds=["https://www.soa.org/%2e%2e/private"]
            ),
            "scope.path_escape",
        ),
        (
            lambda value: value["scope"].update(
                seeds=["https://example.org/safe/%2525252e%2525252e/private"],
                allowed_origins=["https://example.org"],
                include_paths=["/safe/**"],
            ),
            "scope.path_escape",
        ),
        (
            lambda value: value["scope"].update(
                seeds=["https://exa%mple.com/"],
                allowed_origins=["https://exa%mple.com"],
            ),
            "scope.url_invalid",
        ),
        (
            lambda value: value["scope"].update(
                seeds=["https://example.com\\evil.test/"],
                allowed_origins=["https://example.com\\evil.test"],
            ),
            "scope.url_invalid",
        ),
        (
            lambda value: value["scope"].update(seeds=["https://www.soa.org/?q=%ZZ"]),
            "scope.query_invalid",
        ),
        (
            lambda value: value["scope"].update(
                seeds=["https://www.soa.org/?q=bad\\value"]
            ),
            "scope.query_invalid",
        ),
        (
            lambda value: value["scope"].update(
                seeds=["https://www.soa.org/?q=bad|value"]
            ),
            "scope.query_invalid",
        ),
        (
            lambda value: value["scope"].update(
                seeds=["https://www.soa.org:0/"],
                allowed_origins=["https://www.soa.org:0"],
            ),
            "scope.url_invalid",
        ),
        (
            lambda value: value["scope"].update(seeds=["https://www.casact.org/"]),
            "scope.origin_not_allowed",
        ),
        (
            lambda value: value["scope"].update(
                seeds=["https://www.soa.org/private"],
                include_paths=["/research/**"],
            ),
            "scope.path_not_included",
        ),
        (
            lambda value: value["scope"].update(content_types=["video"]),
            "scope.content_type_invalid",
        ),
        (
            lambda value: value["budgets"].update(max_requests=True),
            "budget.invalid",
        ),
        (
            lambda value: value["budgets"].update(max_requests=0),
            "budget.invalid",
        ),
        (
            lambda value: value["budgets"].update(max_requests=-1),
            "budget.invalid",
        ),
    ],
)
def test_invalid_request_values_are_rejected_with_stable_codes(
    mutate: object, code: str
) -> None:
    """Validation fails closed without echoing the rejected value."""
    payload = minimal_payload()
    mutate(payload)  # type: ignore[operator]

    with pytest.raises(RequestValidationError) as caught:
        request_from_mapping(payload)

    assert caught.value.code == code
    assert str(caught.value) == code


@pytest.mark.parametrize(
    "field",
    ["seeds", "allowed_origins", "include_paths", "content_types"],
)
def test_duplicate_scope_values_are_rejected(field: str) -> None:
    """Duplicates are rejected after canonicalization, not silently dropped."""
    payload = minimal_payload()
    scope = payload["scope"]
    assert isinstance(scope, dict)
    values = scope[field]
    assert isinstance(values, list)
    values.append(values[0])

    with pytest.raises(RequestValidationError) as caught:
        request_from_mapping(payload)

    assert caught.value.code == "scope.duplicate"


def test_canonical_origin_duplicates_are_rejected() -> None:
    """Default ports cannot disguise a duplicate origin."""
    payload = minimal_payload()
    scope = payload["scope"]
    assert isinstance(scope, dict)
    scope["allowed_origins"] = [
        "https://www.soa.org",
        "https://www.soa.org:443",
    ]

    with pytest.raises(RequestValidationError) as caught:
        request_from_mapping(payload)

    assert caught.value.code == "scope.duplicate"


@pytest.mark.parametrize(
    "seeds",
    [
        ["https://www.soa.org/?q=%7e", "https://www.soa.org/?q=~"],
        ["https://www.soa.org/?next=%2f", "https://www.soa.org/?next=%2F"],
    ],
)
def test_canonical_query_duplicates_are_rejected(seeds: list[str]) -> None:
    """Unreserved decoding and percent case cannot disguise duplicate seeds."""
    payload = minimal_payload()
    scope = payload["scope"]
    assert isinstance(scope, dict)
    scope["seeds"] = seeds

    with pytest.raises(RequestValidationError) as caught:
        request_from_mapping(payload)

    assert caught.value.code == "scope.duplicate"


@pytest.mark.parametrize(
    "seeds",
    [
        ["https://www.soa.org/safe/{id}", "https://www.soa.org/safe/%7Bid%7D"],
        ["https://www.soa.org/safe/`id`", "https://www.soa.org/safe/%60id%60"],
    ],
)
def test_canonical_raw_path_duplicates_are_rejected(seeds: list[str]) -> None:
    """Unsafe raw path characters cannot disguise equivalent encoded seeds."""
    payload = minimal_payload()
    scope = payload["scope"]
    assert isinstance(scope, dict)
    scope.update(seeds=seeds, include_paths=["/safe/**"])

    with pytest.raises(RequestValidationError) as caught:
        request_from_mapping(payload)

    assert caught.value.code == "scope.duplicate"


def test_port_zero_is_rejected_in_allowed_origins() -> None:
    """The origin contract uses the same 1..65535 port boundary as URLs."""
    payload = minimal_payload()
    scope = payload["scope"]
    assert isinstance(scope, dict)
    scope["allowed_origins"] = ["https://www.soa.org:0"]

    with pytest.raises(RequestValidationError) as caught:
        request_from_mapping(payload)

    assert caught.value.code == "scope.origin_invalid"


def test_ordinary_encoded_path_segment_is_allowed() -> None:
    """Encoded punctuation inside a segment is not mistaken for traversal."""
    payload = minimal_payload()
    scope = payload["scope"]
    assert isinstance(scope, dict)
    scope.update(
        seeds=["https://www.soa.org/safe/report%2Ehtml"],
        include_paths=["/safe/**"],
    )

    request = request_from_mapping(payload)

    assert request.scope.seeds == ("https://www.soa.org/safe/report.html",)


@pytest.mark.parametrize(
    "payload",
    [
        '{"scope": {}, "scope": {}}',
        '{"scope": {"seeds": [], "seeds": []}}',
    ],
)
def test_duplicate_json_keys_are_rejected(payload: str) -> None:
    """JSON duplicate keys are caught before ordinary field validation."""
    with pytest.raises(RequestValidationError) as caught:
        request_from_json(payload)

    assert caught.value.code == "request.duplicate_key"


@pytest.mark.parametrize(
    ("container", "unknown"),
    [
        ("request", "authorized_tool_ids"),
        ("scope", "tool_name"),
        ("budgets", "max_depth"),
    ],
)
def test_unknown_fields_are_rejected(container: str, unknown: str) -> None:
    """Old tool authority and unrequested fields cannot enter the contract."""
    payload = minimal_payload()
    target = payload if container == "request" else payload[container]
    assert isinstance(target, dict)
    target[unknown] = "not-allowed"

    with pytest.raises(RequestValidationError) as caught:
        request_from_mapping(payload)

    assert caught.value.code == f"{container}.unknown_field"
