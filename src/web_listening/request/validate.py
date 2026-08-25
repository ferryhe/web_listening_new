"""Strict Request parsing and immutable pure-policy compilation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from web_listening.request.budgets import (
    BUDGET_FIELDS,
    budgets_are_subset,
    budgets_from_mapping,
    validate_budgets,
)
from web_listening.request.model import (
    Budgets,
    ContentType,
    Request,
    RequestValidationError,
    Scope,
)
from web_listening.request.scope import (
    canonicalize_include_path,
    canonicalize_url,
    path_is_included,
    scope_fingerprint,
    scope_from_mapping,
    scope_is_subset,
    validate_scope,
)

REQUEST_FIELDS = frozenset({"scope", "site_skill", "explore_all_tools", "budgets"})


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """One non-sensitive allow or reject outcome."""

    allowed: bool
    code: str


_ALLOWED = PolicyDecision(True, "policy.allowed")


@dataclass(frozen=True, slots=True)
class CompiledAccessPolicy:
    """Frozen Request authority used for deterministic access decisions."""

    scope: Scope
    budgets: Budgets
    scope_fingerprint: str

    def decide_url(self, value: object) -> PolicyDecision:
        """Decide whether a URL stays within the compiled origin and path scope."""
        try:
            url = canonicalize_url(value)
        except RequestValidationError as exc:
            return PolicyDecision(False, exc.code)
        parsed = urlsplit(url)
        if f"{parsed.scheme}://{parsed.netloc}" not in self.scope.allowed_origins:
            return PolicyDecision(False, "scope.origin_not_allowed")
        return self.decide_path(parsed.path)

    def decide_path(self, value: object) -> PolicyDecision:
        """Decide whether a path stays within the compiled include patterns."""
        try:
            path = canonicalize_include_path(value)
        except RequestValidationError as exc:
            return PolicyDecision(False, exc.code)
        if "*" in path:
            return PolicyDecision(False, "scope.path_invalid")
        if not path_is_included(path, self.scope.include_paths):
            return PolicyDecision(False, "scope.path_not_included")
        return _ALLOWED

    def decide_content_type(self, value: object) -> PolicyDecision:
        """Decide whether a requested content category was authorized."""
        try:
            content_type = ContentType(value)
        except (TypeError, ValueError):
            return PolicyDecision(False, "scope.content_type_invalid")
        if content_type not in self.scope.content_types:
            return PolicyDecision(False, "scope.content_type_not_allowed")
        return _ALLOWED

    def decide_budget(self, name: str, amount: object) -> PolicyDecision:
        """Decide whether a non-negative amount remains within one limit."""
        if name not in BUDGET_FIELDS:
            return PolicyDecision(False, "budget.unknown")
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            return PolicyDecision(False, "budget.invalid_amount")
        if amount > getattr(self.budgets, name):
            return PolicyDecision(False, "budget.exceeded")
        return _ALLOWED


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RequestValidationError("request.duplicate_key")
        result[key] = value
    return result


def validate_request(value: Request) -> Request:
    """Return a canonical Request or reject invalid direct model construction."""
    if not isinstance(value, Request) or not isinstance(value.explore_all_tools, bool):
        raise RequestValidationError("request.invalid")
    return Request(
        scope=validate_scope(value.scope),
        site_skill=value.site_skill,
        explore_all_tools=value.explore_all_tools,
        budgets=validate_budgets(value.budgets),
    )


def request_from_mapping(value: object) -> Request:
    """Build the exact four-field public Request from a mapping."""
    if not isinstance(value, Mapping):
        raise RequestValidationError("request.invalid")
    keys = set(value)
    if not all(isinstance(key, str) for key in keys) or keys - REQUEST_FIELDS:
        raise RequestValidationError("request.unknown_field")
    if {"scope", "budgets"} - keys:
        raise RequestValidationError("request.missing")
    explore_all_tools = value.get("explore_all_tools", False)
    if not isinstance(explore_all_tools, bool):
        raise RequestValidationError("request.invalid")
    return Request(
        scope=scope_from_mapping(value["scope"]),
        site_skill=value.get("site_skill"),
        explore_all_tools=explore_all_tools,
        budgets=budgets_from_mapping(value["budgets"]),
    )


def request_from_json(payload: str) -> Request:
    """Parse JSON while rejecting duplicate keys before model validation."""
    try:
        value = json.loads(payload, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, TypeError) as exc:
        raise RequestValidationError("request.invalid_json") from exc
    return request_from_mapping(value)


def compile_access_policy(
    request: Request,
    *,
    scope: Scope | None = None,
    budgets: Budgets | None = None,
) -> CompiledAccessPolicy:
    """Freeze Request authority, optionally applying validated narrower limits."""
    canonical_request = validate_request(request)
    effective_scope = (
        canonical_request.scope if scope is None else validate_scope(scope)
    )
    effective_budgets = (
        canonical_request.budgets if budgets is None else validate_budgets(budgets)
    )
    if not scope_is_subset(effective_scope, canonical_request.scope):
        raise RequestValidationError("policy.scope_expansion")
    if not budgets_are_subset(effective_budgets, canonical_request.budgets):
        raise RequestValidationError("policy.budget_expansion")
    return CompiledAccessPolicy(
        scope=effective_scope,
        budgets=effective_budgets,
        scope_fingerprint=scope_fingerprint(effective_scope),
    )
