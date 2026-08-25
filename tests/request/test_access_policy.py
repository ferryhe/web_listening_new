"""Immutable, zero-I/O access-policy tests reused by the next phase."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from web_listening.request.budgets import Budgets
from web_listening.request.model import ContentType, RequestValidationError
from web_listening.request.scope import Scope
from web_listening.request.validate import compile_access_policy, request_from_mapping


def request_payload() -> dict[str, object]:
    """Return a legal two-origin Request for policy tests."""
    return {
        "scope": {
            "seeds": [
                "https://www.soa.org/research/annual/",
                "https://www.casact.org/publications/",
            ],
            "allowed_origins": [
                "https://www.soa.org",
                "https://www.casact.org",
            ],
            "include_paths": ["/research/**", "/publications/**"],
            "content_types": ["html", "file"],
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


def test_policy_decisions_allow_only_requested_access() -> None:
    """URL, path, content-type, and budget checks return stable reason codes."""
    policy = compile_access_policy(request_from_mapping(request_payload()))

    assert policy.decide_url("https://www.soa.org/research/report?year=2025").code == (
        "policy.allowed"
    )
    assert policy.decide_url("https://actuaries.org/research/").code == (
        "scope.origin_not_allowed"
    )
    assert policy.decide_url("https://www.soa.org/private/").code == (
        "scope.path_not_included"
    )
    assert policy.decide_url("https://www.soa.org/research/#part").code == (
        "scope.url_fragment"
    )
    assert policy.decide_path("/research/2025/").code == "policy.allowed"
    assert policy.decide_path("/private/").code == "scope.path_not_included"
    assert policy.decide_content_type(ContentType.HTML).code == "policy.allowed"
    assert policy.decide_content_type("video").code == "scope.content_type_invalid"
    assert policy.decide_budget("max_requests", 10).code == "policy.allowed"
    assert policy.decide_budget("max_requests", 11).code == "budget.exceeded"
    assert policy.decide_budget("unknown", 1).code == "budget.unknown"
    assert policy.decide_budget("max_requests", True).code == "budget.invalid_amount"


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("https://exa%mple.com/", "scope.url_invalid"),
        ("https://example.com\\evil.test/", "scope.url_invalid"),
        ("https://www.soa.org/research/?q=%ZZ", "scope.query_invalid"),
        ("https://www.soa.org/research/?q=bad\\value", "scope.query_invalid"),
        ("https://www.soa.org/research/?q=bad|value", "scope.query_invalid"),
        ("https://www.soa.org:0/research/", "scope.url_invalid"),
        (
            "https://example.org/safe/%2525252e%2525252e/private",
            "scope.path_escape",
        ),
    ],
)
def test_policy_rejects_malformed_urls_before_scope_decisions(
    url: str, code: str
) -> None:
    """Malformed authority, query, and nested traversal fail before origin checks."""
    policy = compile_access_policy(request_from_mapping(request_payload()))

    assert policy.decide_url(url).code == code


def test_policy_allows_an_ordinary_encoded_path_boundary() -> None:
    """Encoded punctuation within an allowed segment remains a legal path."""
    policy = compile_access_policy(request_from_mapping(request_payload()))

    decision = policy.decide_url("https://www.soa.org/research/report%2Ehtml")

    assert decision.code == "policy.allowed"


def test_policy_is_deeply_immutable_and_deterministic() -> None:
    """The policy contains only frozen primitive-backed authority."""
    request = request_from_mapping(request_payload())
    first = compile_access_policy(request)
    second = compile_access_policy(request)

    assert first == second
    assert first.scope_fingerprint == second.scope_fingerprint
    with pytest.raises(FrozenInstanceError):
        first.scope = replace(first.scope, seeds=())  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        first.budgets.max_requests = 999  # type: ignore[misc]

    reordered_scope = replace(
        request.scope,
        seeds=tuple(reversed(request.scope.seeds)),
        allowed_origins=tuple(reversed(request.scope.allowed_origins)),
        include_paths=tuple(reversed(request.scope.include_paths)),
        content_types=tuple(reversed(request.scope.content_types)),
    )
    reordered = compile_access_policy(replace(request, scope=reordered_scope))
    assert reordered.scope_fingerprint == first.scope_fingerprint


def test_policy_may_narrow_scope_and_budgets() -> None:
    """Explicit overrides can remove authority but cannot add any."""
    request = request_from_mapping(request_payload())
    narrowed_scope = Scope(
        seeds=("https://www.soa.org/research/annual/",),
        allowed_origins=("https://www.soa.org",),
        include_paths=("/research/annual/**",),
        content_types=(ContentType.HTML,),
    )
    narrowed_budgets = Budgets(
        max_requests=5,
        max_bytes=500_000,
        max_runtime_seconds=10,
        max_tool_attempts_per_target=1,
    )

    policy = compile_access_policy(
        request, scope=narrowed_scope, budgets=narrowed_budgets
    )

    assert policy.scope == narrowed_scope
    assert policy.budgets == narrowed_budgets
    assert policy.decide_url("https://www.casact.org/publications/").code == (
        "scope.origin_not_allowed"
    )


@pytest.mark.parametrize(
    ("scope", "budgets", "code"),
    [
        (
            Scope(
                seeds=("https://actuaries.org/research/",),
                allowed_origins=("https://actuaries.org",),
                include_paths=("/research/**",),
                content_types=(ContentType.HTML,),
            ),
            None,
            "policy.scope_expansion",
        ),
        (
            Scope(
                seeds=("https://www.soa.org/research/annual/",),
                allowed_origins=("https://www.soa.org",),
                include_paths=("/**",),
                content_types=(ContentType.HTML,),
            ),
            None,
            "policy.scope_expansion",
        ),
        (
            None,
            Budgets(
                max_requests=11,
                max_bytes=1_048_576,
                max_runtime_seconds=30,
                max_tool_attempts_per_target=2,
            ),
            "policy.budget_expansion",
        ),
    ],
)
def test_policy_rejects_authority_expansion(
    scope: Scope | None, budgets: Budgets | None, code: str
) -> None:
    """A compiled override cannot enlarge the validated Request."""
    request = request_from_mapping(request_payload())

    with pytest.raises(RequestValidationError) as caught:
        compile_access_policy(request, scope=scope, budgets=budgets)

    assert caught.value.code == code


def test_policy_compilation_performs_no_network_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Network entry points can be disabled without affecting policy compilation."""

    def fail_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network I/O is forbidden")

    monkeypatch.setattr("socket.create_connection", fail_network)
    monkeypatch.setattr("urllib.request.urlopen", fail_network)

    policy = compile_access_policy(request_from_mapping(request_payload()))

    assert policy.decide_url("https://www.soa.org/research/").allowed is True
