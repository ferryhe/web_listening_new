"""Pure Request narrowing and Registry metadata resolution for Site Skills."""

# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

from dataclasses import dataclass

from web_listening.request.model import (
    Budgets,
    ContentType,
    Request,
    RequestValidationError,
    Scope,
)
from web_listening.request.validate import compile_access_policy, validate_request
from web_listening.site_skill.model import SiteSkill, SiteSkillError
from web_listening.site_skill.validate import validate_site_skill
from web_listening.tool_registry.eligibility import (
    EligibilityDecision,
    EligibilityRequirements,
)
from web_listening.tool_registry.manifest import ToolManifest, ToolRegistryError
from web_listening.tool_registry.registry import Registry


@dataclass(frozen=True, slots=True)
class SiteSkillResolution:
    """The narrowed Request plus an observable metadata eligibility decision."""

    skill: SiteSkill
    request: Request
    manifest: ToolManifest | None
    eligible: bool
    reasons: tuple[str, ...]


def _snapshot_request(value: object) -> Request | None:
    if type(value) is not Request:
        return None
    scope = value.scope
    budgets = value.budgets
    if (
        type(scope) is not Scope
        or type(budgets) is not Budgets
        or type(value.explore_all_tools) is not bool
    ):
        return None
    string_sequences = (scope.seeds, scope.allowed_origins, scope.include_paths)
    if any(type(sequence) is not tuple for sequence in string_sequences) or any(
        type(item) is not str for sequence in string_sequences for item in sequence
    ):
        return None
    if type(scope.content_types) is not tuple or any(
        type(item) is not ContentType for item in scope.content_types
    ):
        return None
    limits = (
        budgets.max_requests,
        budgets.max_bytes,
        budgets.max_runtime_seconds,
        budgets.max_tool_attempts_per_target,
    )
    if any(type(limit) is not int for limit in limits):
        return None
    return Request(
        Scope(
            tuple(scope.seeds),
            tuple(scope.allowed_origins),
            tuple(scope.include_paths),
            tuple(scope.content_types),
        ),
        value.site_skill,
        value.explore_all_tools,
        Budgets(*limits),
    )


def _compile_narrowed_request(
    request: Request, skill: SiteSkill
) -> tuple[tuple[Request, Scope, Budgets] | None, str | None]:
    try:
        request = validate_request(request)
        policy = compile_access_policy(
            request, scope=skill.scope, budgets=skill.budgets
        )
        return (request, policy.scope, policy.budgets), None
    except RequestValidationError as exc:
        return None, exc.code


def _query_registry(
    registry: Registry,
) -> tuple[tuple[ToolManifest, ...] | None, str | None]:
    try:
        return registry.query(), None
    except ToolRegistryError as exc:
        return None, exc.code


def _check_eligibility(
    registry: Registry, requirements: EligibilityRequirements
) -> tuple[tuple[EligibilityDecision, ...] | None, str | None]:
    try:
        return registry.eligibility(requirements), None
    except ToolRegistryError as exc:
        return None, exc.code


def resolve_site_skill(
    request: Request, skill: SiteSkill, registry: Registry
) -> SiteSkillResolution:
    """Narrow Request authority and check exact registered tool metadata."""
    skill = validate_site_skill(skill)
    request = _snapshot_request(request)
    if request is None:
        raise SiteSkillError("request.invalid")
    narrowed, error = _compile_narrowed_request(request, skill)
    if error is not None:
        raise SiteSkillError(error)
    assert narrowed is not None
    request, scope, budgets = narrowed
    manifests, error = _query_registry(registry)
    if error is not None:
        raise SiteSkillError(error)
    assert manifests is not None
    effective_request = Request(
        scope,
        skill,
        request.explore_all_tools,
        budgets,
    )
    matching_id = tuple(
        manifest for manifest in manifests if manifest.tool_id == skill.tool.tool_id
    )
    if not matching_id:
        return SiteSkillResolution(
            skill,
            effective_request,
            None,
            False,
            ("site_skill.tool_unknown",),
        )
    manifest = matching_id[0]
    if manifest.version != skill.tool.version:
        return SiteSkillResolution(
            skill,
            effective_request,
            manifest,
            False,
            ("site_skill.tool_version_mismatch",),
        )
    decisions, error = _check_eligibility(
        registry,
        EligibilityRequirements(
            category=skill.tool.category,
            capabilities=skill.tool.capabilities,
        ),
    )
    if error is not None:
        raise SiteSkillError(error)
    assert decisions is not None
    decision = next(item for item in decisions if item.tool_id == manifest.tool_id)
    return SiteSkillResolution(
        skill,
        effective_request,
        manifest,
        decision.eligible,
        decision.reasons,
    )
