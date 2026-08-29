"""Strict SiteRefreshRequest authority and binding tests."""

# pylint: disable=duplicate-code,missing-function-docstring

from __future__ import annotations

import json
from dataclasses import replace
from urllib.parse import quote

import pytest

from web_listening.artifact.site_state import SiteState, SiteStatePage
from web_listening.request.model import (
    Budgets,
    ContentType,
    RequestValidationError,
    Scope,
)
from web_listening.request.site_refresh import (
    SITE_REFRESH_REQUEST_SCHEMA_VERSION,
    SiteRefreshRequest,
    site_refresh_request_from_json,
    site_refresh_request_from_mapping,
    validate_site_refresh_request,
)
from web_listening.site_skill.model import (
    DiscoveryRecipe,
    SuccessChecks,
    ToolReference,
)
from web_listening.site_skill.update import create_candidate
from web_listening.site_skill.validate import site_skill_to_mapping
from web_listening.tool_registry.manifest import ToolCategory

NOW = "2026-08-28T00:00:00Z"


def _encoded_absolute_path_url(*, multilayer: bool = False) -> str:
    encoded = quote("".join(chr(item) for item in (67, 58, 47, 112)), safe="")
    if multilayer:
        encoded = quote(encoded, safe="")
    return f"https://example.test/reports/a?next={encoded}"


def _scope(include_paths: tuple[str, ...] = ("/reports/**",)) -> Scope:
    return Scope(
        ("https://example.test/reports/",),
        ("https://example.test",),
        include_paths,
        (ContentType.HTML,),
    )


def _skill(
    *,
    scope: Scope | None = None,
    budgets: Budgets = Budgets(6, 8192, 30, 6),
    with_discovery: bool = True,
):
    effective_scope = scope or _scope()
    acquisition = ToolReference(
        "acquisition.web_http",
        "1.0.0",
        ToolCategory.ACQUISITION,
        frozenset({"http_get"}),
    )
    discovery = DiscoveryRecipe(
        ToolReference(
            "discovery.html_links",
            "1.0.0",
            ToolCategory.DISCOVERY,
            frozenset({"html_links"}),
        ),
        effective_scope.seeds[0],
    )
    return create_candidate(
        site_key="example.test",
        version=1,
        previous=None,
        scope=effective_scope,
        budgets=budgets,
        tool=acquisition,
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
        discovery=discovery if with_discovery else None,
    ).skill


def _page(url: str = "https://example.test/reports/a") -> SiteStatePage:
    return SiteStatePage(
        url,
        "observation-" + "a" * 32,
        "artifact-" + "b" * 64,
        "sha256:" + "c" * 64,
    )


def _state(skill, *, page: SiteStatePage | None = None) -> SiteState:
    selected = _page() if page is None else page
    return SiteState(
        "example.test",
        NOW,
        skill.digest,
        True,
        (selected,),
    )


def _payload() -> dict[str, object]:
    skill = _skill()
    return {
        "schema_version": SITE_REFRESH_REQUEST_SCHEMA_VERSION,
        "scope": {
            "seeds": list(skill.scope.seeds),
            "allowed_origins": list(skill.scope.allowed_origins),
            "include_paths": list(skill.scope.include_paths),
            "content_types": [item.value for item in skill.scope.content_types],
        },
        "site_skill": site_skill_to_mapping(skill),
        "previous_state": _state(skill).to_dict(),
        "explore_all_tools": True,
        "budgets": {
            "max_requests": 8,
            "max_bytes": 16384,
            "max_runtime_seconds": 60,
            "max_tool_attempts_per_target": 8,
        },
    }


def test_site_refresh_request_strictly_round_trips_and_snapshots_authority() -> None:
    payload = _payload()

    request = site_refresh_request_from_json(json.dumps(payload))
    rebuilt = site_refresh_request_from_mapping(request.to_dict())

    assert rebuilt == request
    assert request.schema_version == SITE_REFRESH_REQUEST_SCHEMA_VERSION
    assert request.site_skill.digest == request.previous_state.site_skill_digest
    assert request.to_dict() == payload


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("unknown", True, "site_refresh_request.unknown_field"),
        ("schema_version", "future", "site_refresh_request.version_invalid"),
        ("explore_all_tools", 1, "site_refresh_request.invalid"),
    ],
)
def test_site_refresh_request_rejects_schema_drift(field, value, code) -> None:
    payload = _payload()
    payload[field] = value

    with pytest.raises(RequestValidationError, match=code):
        site_refresh_request_from_mapping(payload)


def test_site_refresh_request_rejects_duplicate_json_keys() -> None:
    payload = json.dumps(_payload())
    hostile = payload[:-1] + ',"explore_all_tools":false}'

    with pytest.raises(
        RequestValidationError, match="site_refresh_request.duplicate_key"
    ):
        site_refresh_request_from_json(hostile)


@pytest.mark.parametrize(
    "changed",
    [
        lambda request: replace(
            request,
            scope=_scope(),
            site_skill=_skill(scope=_scope(("/**",))),
        ),
        lambda request: replace(
            request,
            budgets=Budgets(5, 8192, 30, 6),
        ),
    ],
)
def test_site_skill_can_only_narrow_request_authority(changed) -> None:
    parsed = site_refresh_request_from_mapping(_payload())

    with pytest.raises(RequestValidationError, match="policy.*expansion"):
        validate_site_refresh_request(changed(parsed))


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda payload: payload["previous_state"].__setitem__(
                "site_skill_digest", "sha256:" + "f" * 64
            ),
            "site_refresh_request.skill_state_mismatch",
        ),
        (
            lambda payload: payload["previous_state"].__setitem__(
                "site_key", "outside.test"
            ),
            "site_state.site_mismatch",
        ),
        (
            lambda payload: payload["previous_state"]["pages"][0].__setitem__(
                "canonical_url", "https://example.test/outside"
            ),
            "site_refresh_request.state_scope_mismatch",
        ),
    ],
)
def test_previous_state_is_untrusted_and_bound_to_skill_and_scope(mutate, code) -> None:
    payload = _payload()
    mutate(payload)

    with pytest.raises(RequestValidationError, match=code):
        site_refresh_request_from_mapping(payload)


@pytest.mark.parametrize(
    "query",
    (
        "token=placeholder-value",
        "api_key=placeholder-value",
        "password=placeholder-value",
        "ToKeN=placeholder-value",
        "token%3Dplaceholder-value",
        "%2574oken=placeholder-value",
        "filter=password%3Dplaceholder-value",
    ),
)
def test_previous_state_sensitive_query_is_rejected_without_echo(query: str) -> None:
    payload = _payload()
    payload["previous_state"]["pages"][0][
        "canonical_url"
    ] = f"https://example.test/reports/a?{query}"

    with pytest.raises(
        RequestValidationError, match="^site_state.sensitive_data$"
    ) as caught:
        site_refresh_request_from_mapping(payload)

    assert "placeholder-value" not in str(caught.value)


def test_previous_state_benign_query_strictly_round_trips() -> None:
    payload = _payload()
    payload["previous_state"]["pages"][0][
        "canonical_url"
    ] = "https://example.test/reports/a?page=2&sort=asc"

    request = site_refresh_request_from_mapping(payload)

    assert request.to_dict() == payload


def test_previous_state_public_natural_language_slug_strictly_round_trips() -> None:
    payload = _payload()
    public_url = (
        "https://example.test/reports/"
        "skilled-professionals-and-scientists-in-climate-assessment"
    )
    payload["previous_state"]["pages"][0]["canonical_url"] = public_url

    request = site_refresh_request_from_json(json.dumps(payload))

    assert request.to_dict() == payload
    assert validate_site_refresh_request(request) == request


@pytest.mark.parametrize("multilayer", (False, True))
def test_previous_state_absolute_path_query_is_rejected_without_echo(
    multilayer: bool,
) -> None:
    payload = _payload()
    payload["previous_state"]["pages"][0]["canonical_url"] = _encoded_absolute_path_url(
        multilayer=multilayer
    )

    with pytest.raises(
        RequestValidationError, match="^site_state.absolute_path$"
    ) as caught:
        site_refresh_request_from_mapping(payload)

    assert caught.value.args == ("site_state.absolute_path",)


def test_direct_request_revalidates_previous_state_absolute_path() -> None:
    request = site_refresh_request_from_mapping(_payload())
    object.__setattr__(
        request.previous_state.pages[0],
        "canonical_url",
        _encoded_absolute_path_url(),
    )

    with pytest.raises(
        RequestValidationError, match="^site_state.absolute_path$"
    ) as caught:
        validate_site_refresh_request(request)

    assert caught.value.args == ("site_state.absolute_path",)


def test_site_refresh_request_requires_a_replayable_discovery_recipe() -> None:
    parsed = site_refresh_request_from_mapping(_payload())

    with pytest.raises(
        RequestValidationError, match="site_refresh_request.discovery_required"
    ):
        validate_site_refresh_request(
            replace(parsed, site_skill=_skill(with_discovery=False))
        )


def test_direct_model_requires_the_exact_frozen_type() -> None:
    parsed = site_refresh_request_from_mapping(_payload())
    hostile = SiteRefreshRequest(
        parsed.scope,
        parsed.site_skill,
        parsed.previous_state,
        parsed.explore_all_tools,
        parsed.budgets,
    )

    assert validate_site_refresh_request(hostile) == parsed
