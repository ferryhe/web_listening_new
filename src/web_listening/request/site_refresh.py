"""Strict, versioned authority contract for one governed site refresh."""

# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from web_listening.artifact.model import ArtifactStoreError
from web_listening.artifact.site_state import SiteState, site_state_from_mapping
from web_listening.request.budgets import budgets_from_mapping
from web_listening.request.model import (
    Budgets,
    Request,
    RequestValidationError,
    Scope,
)
from web_listening.request.scope import scope_from_mapping
from web_listening.request.validate import compile_access_policy, validate_request
from web_listening.site_skill.model import SiteSkill, SiteSkillError
from web_listening.site_skill.validate import (
    site_skill_from_mapping,
    site_skill_to_mapping,
    validate_site_skill,
)

SITE_REFRESH_REQUEST_SCHEMA_VERSION = "web-listening-site-refresh-request.v1"
_FIELDS = frozenset(
    {
        "schema_version",
        "scope",
        "site_skill",
        "previous_state",
        "explore_all_tools",
        "budgets",
    }
)


@dataclass(frozen=True, slots=True)
class SiteRefreshRequest:
    """Request authority plus one validated recipe and untrusted prior state."""

    scope: Scope
    site_skill: SiteSkill
    previous_state: SiteState
    explore_all_tools: bool
    budgets: Budgets
    schema_version: str = SITE_REFRESH_REQUEST_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        """Return the exact JSON-compatible public request payload."""
        return {
            "schema_version": self.schema_version,
            "scope": _scope_mapping(self.scope),
            "site_skill": site_skill_to_mapping(self.site_skill),
            "previous_state": self.previous_state.to_dict(),
            "explore_all_tools": self.explore_all_tools,
            "budgets": _budgets_mapping(self.budgets),
        }


def _scope_mapping(scope: Scope) -> dict[str, object]:
    return {
        "seeds": list(scope.seeds),
        "allowed_origins": list(scope.allowed_origins),
        "include_paths": list(scope.include_paths),
        "content_types": [item.value for item in scope.content_types],
    }


def _budgets_mapping(budgets: Budgets) -> dict[str, int]:
    return {
        "max_requests": budgets.max_requests,
        "max_bytes": budgets.max_bytes,
        "max_runtime_seconds": budgets.max_runtime_seconds,
        "max_tool_attempts_per_target": budgets.max_tool_attempts_per_target,
    }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RequestValidationError("site_refresh_request.duplicate_key")
        result[key] = value
    return result


def _request_error(code: str) -> RequestValidationError:
    return RequestValidationError(code)


def _parse_embedded(value: Mapping[str, object]) -> tuple[SiteSkill, SiteState]:
    try:
        skill = site_skill_from_mapping(value["site_skill"])
        state = site_state_from_mapping(value["previous_state"])
    except (SiteSkillError, ArtifactStoreError) as exc:
        raise _request_error(exc.code) from exc
    return skill, state


def validate_site_refresh_request(value: SiteRefreshRequest) -> SiteRefreshRequest:
    """Validate all authority, recipe, site, and prior-state bindings."""
    if type(value) is not SiteRefreshRequest:
        raise _request_error("site_refresh_request.invalid")
    if value.schema_version != SITE_REFRESH_REQUEST_SCHEMA_VERSION:
        raise _request_error("site_refresh_request.version_invalid")
    if type(value.explore_all_tools) is not bool:
        raise _request_error("site_refresh_request.invalid")
    try:
        base_request = validate_request(
            Request(
                value.scope,
                None,
                value.explore_all_tools,
                value.budgets,
            )
        )
        skill = validate_site_skill(value.site_skill)
        state = site_state_from_mapping(value.previous_state.to_dict())
        effective_policy = compile_access_policy(
            base_request,
            scope=skill.scope,
            budgets=skill.budgets,
        )
    except (SiteSkillError, ArtifactStoreError) as exc:
        raise _request_error(exc.code) from exc
    if skill.discovery is None:
        raise _request_error("site_refresh_request.discovery_required")
    skill_hosts = {urlsplit(seed).hostname for seed in skill.scope.seeds}
    if skill_hosts != {skill.site_key} or state.site_key != skill.site_key:
        raise _request_error("site_refresh_request.site_mismatch")
    if state.site_skill_digest != skill.digest:
        raise _request_error("site_refresh_request.skill_state_mismatch")
    for page in state.pages:
        if not effective_policy.decide_url(page.canonical_url).allowed:
            raise _request_error("site_refresh_request.state_scope_mismatch")
    return SiteRefreshRequest(
        base_request.scope,
        skill,
        state,
        base_request.explore_all_tools,
        base_request.budgets,
    )


def site_refresh_request_from_mapping(value: object) -> SiteRefreshRequest:
    """Build one strict refresh request from a JSON-compatible mapping."""
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise _request_error("site_refresh_request.invalid")
    keys = set(value)
    if keys - _FIELDS:
        raise _request_error("site_refresh_request.unknown_field")
    if _FIELDS - keys:
        raise _request_error("site_refresh_request.missing")
    if value["schema_version"] != SITE_REFRESH_REQUEST_SCHEMA_VERSION:
        raise _request_error("site_refresh_request.version_invalid")
    if type(value["explore_all_tools"]) is not bool:
        raise _request_error("site_refresh_request.invalid")
    scope = scope_from_mapping(value["scope"])
    budgets = budgets_from_mapping(value["budgets"])
    skill, state = _parse_embedded(value)
    return validate_site_refresh_request(
        SiteRefreshRequest(
            scope,
            skill,
            state,
            value["explore_all_tools"],
            budgets,
            value["schema_version"],
        )
    )


def site_refresh_request_from_json(payload: str) -> SiteRefreshRequest:
    """Parse JSON while rejecting duplicate keys at every object depth."""
    try:
        value = json.loads(payload, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, TypeError) as exc:
        raise _request_error("site_refresh_request.invalid_json") from exc
    return site_refresh_request_from_mapping(value)


__all__ = [
    "SITE_REFRESH_REQUEST_SCHEMA_VERSION",
    "SiteRefreshRequest",
    "site_refresh_request_from_json",
    "site_refresh_request_from_mapping",
    "validate_site_refresh_request",
]
