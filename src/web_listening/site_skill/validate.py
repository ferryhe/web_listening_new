"""Strict validation and deterministic identity for Site Skill data."""

# pylint: disable=duplicate-code,too-many-boolean-expressions,too-many-branches
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any
from urllib.parse import unquote

from web_listening.artifact.identity import validate_mime_type
from web_listening.artifact.model import ArtifactStoreError
from web_listening.artifact.observation import validate_observed_at
from web_listening.request.budgets import budgets_from_mapping, validate_budgets
from web_listening.request.model import (
    Budgets,
    ContentType,
    Request,
    RequestValidationError,
    Scope,
)
from web_listening.request.scope import (
    canonicalize_url,
    scope_from_mapping,
    validate_scope,
)
from web_listening.request.validate import compile_access_policy
from web_listening.site_skill.model import (
    DiscoveryRecipe,
    SiteSkill,
    SiteSkillError,
    SuccessChecks,
    ToolReference,
)
from web_listening.tool_registry.manifest import (
    ToolCategory,
    ToolRegistryError,
    capability_is_valid,
    validate_tool_id,
    validate_tool_version,
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:auth|authorization|cookie|credential|password|secret|token|"
    r"api[_-]?key)(?:$|[_-])",
    re.IGNORECASE,
)
_QUERY_SECRET = re.compile(
    r"(?:^|[?&])(?:auth|authorization|cookie|credential|password|secret|token|api[_-]?key)=",
    re.IGNORECASE,
)
_EXECUTABLE_FIELDS = frozenset(
    {
        "code",
        "command",
        "entrypoint",
        "executor",
        "path",
        "profile_ref",
        "runtime",
        "script",
        "script_path",
    }
)
_KNOWN_FIELDS = frozenset(
    {
        "site_key",
        "version",
        "previous_digest",
        "scope",
        "budgets",
        "tool",
        "success_checks",
        "verified_at",
        "digest",
        "discovery",
        "source_url",
        "seeds",
        "allowed_origins",
        "include_paths",
        "content_types",
        "max_requests",
        "max_bytes",
        "max_runtime_seconds",
        "max_tool_attempts_per_target",
        "tool_id",
        "category",
        "capabilities",
        "recipe_id",
        "allowed_mime_types",
        "minimum_words",
    }
)
_ROOT_FIELDS = frozenset(
    {
        "site_key",
        "version",
        "previous_digest",
        "scope",
        "budgets",
        "tool",
        "success_checks",
        "verified_at",
        "digest",
    }
)
_ROOT_OPTIONAL_FIELDS = frozenset({"discovery"})
_TOOL_FIELDS = frozenset({"tool_id", "version", "category", "capabilities"})
_TOOL_OPTIONAL_FIELDS = frozenset({"recipe_id"})
_CHECK_FIELDS = frozenset({"allowed_mime_types", "minimum_words"})
_DISCOVERY_FIELDS = frozenset({"tool", "source_url"})


def _decoded_forms(value: str) -> tuple[str, ...]:
    forms = [value]
    for _unused in range(3):
        decoded = unquote(forms[-1])
        if decoded == forms[-1]:
            break
        forms.append(decoded)
    return tuple(unicodedata.normalize("NFKC", item) for item in forms)


def _scan_safe_data(value: object) -> None:
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise SiteSkillError("site_skill.unknown_field")
            normalized = unicodedata.normalize("NFKC", key).casefold()
            if _SECRET_KEY.search(normalized):
                raise SiteSkillError("site_skill.sensitive_data")
            if normalized in _EXECUTABLE_FIELDS:
                raise SiteSkillError("site_skill.executable_surface")
            if normalized not in _KNOWN_FIELDS:
                raise SiteSkillError("site_skill.unknown_field")
            _scan_safe_data(child)
        return
    if type(value) is list:
        for child in value:
            _scan_safe_data(child)
        return
    if type(value) is str:
        for form in _decoded_forms(value):
            if _QUERY_SECRET.search(form):
                raise SiteSkillError("site_skill.sensitive_data")
            if any(
                unicodedata.category(character) in {"Cc", "Cf", "Cs"}
                for character in form
            ):
                raise SiteSkillError("site_skill.invalid")
        return
    if value is None or type(value) in {bool, int, float}:
        return
    raise SiteSkillError("site_skill.invalid")


def _require_fields(
    value: object,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if type(value) is not dict:
        raise SiteSkillError("site_skill.invalid")
    keys = set(value)
    if required - keys:
        raise SiteSkillError("site_skill.missing")
    if keys - required - optional:
        raise SiteSkillError("site_skill.unknown_field")
    return value


def _validate_digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise SiteSkillError("site_skill.digest_invalid")
    return value


def _parse_tool(value: object) -> ToolReference:
    mapping = _require_fields(value, _TOOL_FIELDS, _TOOL_OPTIONAL_FIELDS)
    capabilities = mapping["capabilities"]
    if (
        type(capabilities) is not list
        or not capabilities
        or any(type(item) is not str for item in capabilities)
        or len(capabilities) != len(set(capabilities))
        or any(not capability_is_valid(item) for item in capabilities)
    ):
        raise SiteSkillError("site_skill.tool_capabilities_invalid")
    recipe_id = mapping.get("recipe_id")
    if recipe_id is not None and type(recipe_id) is not str:
        raise SiteSkillError("site_skill.tool_invalid") from None
    validated = _validated_tool_scalars(
        mapping["tool_id"], mapping["version"], mapping["category"], recipe_id
    )
    if validated is None:
        raise SiteSkillError("site_skill.tool_invalid")
    tool_id, version, category, recipe_id = validated
    return ToolReference(tool_id, version, category, frozenset(capabilities), recipe_id)


def _validated_tool_scalars(
    tool_id: object,
    version: object,
    category: object,
    recipe_id: object,
) -> tuple[str, str, ToolCategory, str | None] | None:
    if (
        type(tool_id) is not str
        or type(version) is not str
        or type(category) is not str
        or (recipe_id is not None and type(recipe_id) is not str)
    ):
        return None
    try:
        validated_id = validate_tool_id(tool_id)
        validated_version = validate_tool_version(version)
        validated_category = ToolCategory(category)
        validated_recipe = None if recipe_id is None else validate_tool_id(recipe_id)
    except (ToolRegistryError, TypeError, ValueError):
        return None
    return validated_id, validated_version, validated_category, validated_recipe


def _identifier_is_valid(value: str) -> bool:
    try:
        validate_tool_id(value)
    except ToolRegistryError:
        return False
    return True


def _parse_checks(value: object) -> SuccessChecks:
    mapping = _require_fields(value, _CHECK_FIELDS)
    mime_types = mapping["allowed_mime_types"]
    minimum_words = mapping["minimum_words"]
    if (
        type(mime_types) is not list
        or not mime_types
        or any(type(item) is not str for item in mime_types)
        or len(mime_types) != len(set(mime_types))
        or type(minimum_words) is not int
        or minimum_words <= 0
    ):
        raise SiteSkillError("site_skill.checks_invalid")
    canonical_mime_types = _validated_mime_types(mime_types)
    if canonical_mime_types is None:
        raise SiteSkillError("site_skill.checks_invalid")
    return SuccessChecks(canonical_mime_types, minimum_words)


def _parse_discovery(value: object, scope: Scope, budgets: Budgets) -> DiscoveryRecipe:
    mapping = _require_fields(value, _DISCOVERY_FIELDS)
    tool = _parse_tool(mapping["tool"])
    if tool.category is not ToolCategory.DISCOVERY:
        raise SiteSkillError("site_skill.discovery_invalid")
    source_url = mapping["source_url"]
    if type(source_url) is not str:
        raise SiteSkillError("site_skill.discovery_invalid")
    try:
        policy = compile_access_policy(Request(scope, None, False, budgets))
        canonical_source = canonicalize_url(source_url)
    except RequestValidationError as exc:
        raise SiteSkillError(exc.code) from None
    decision = policy.decide_url(canonical_source)
    if not decision.allowed:
        raise SiteSkillError(decision.code)
    return DiscoveryRecipe(tool, canonical_source)


def _validated_mime_types(values: list[str]) -> tuple[str, ...] | None:
    try:
        return tuple(validate_mime_type(item) for item in values)
    except ArtifactStoreError:
        return None


def _site_skill_from_mapping(value: object, *, check_digest: bool) -> SiteSkill:
    _scan_safe_data(value)
    mapping = _require_fields(value, _ROOT_FIELDS, _ROOT_OPTIONAL_FIELDS)
    site_key = mapping["site_key"]
    version = mapping["version"]
    previous_digest = mapping["previous_digest"]
    if type(site_key) is not str:
        raise SiteSkillError("site_skill.site_key_invalid")
    if not _identifier_is_valid(site_key):
        raise SiteSkillError("site_skill.site_key_invalid")
    if type(version) is not int or version <= 0:
        raise SiteSkillError("site_skill.version_invalid")
    if version == 1 and previous_digest is not None:
        raise SiteSkillError("site_skill.previous_invalid")
    if version > 1:
        if previous_digest is None:
            raise SiteSkillError("site_skill.previous_required")
        _validate_digest(previous_digest)
    validated_request_values = _validated_request_values(
        mapping["scope"], mapping["budgets"], mapping["verified_at"]
    )
    if isinstance(validated_request_values, str):
        raise SiteSkillError(validated_request_values)
    scope, budgets, verified_at = validated_request_values
    discovery = (
        None
        if "discovery" not in mapping
        else _parse_discovery(mapping["discovery"], scope, budgets)
    )
    skill = SiteSkill(
        site_key,
        version,
        previous_digest,
        scope,
        budgets,
        _parse_tool(mapping["tool"]),
        _parse_checks(mapping["success_checks"]),
        verified_at,
        _validate_digest(mapping["digest"]),
        discovery,
    )
    if check_digest and skill.digest != _computed_digest(skill):
        raise SiteSkillError("site_skill.digest_mismatch")
    return skill


def _scope_mapping(scope: object) -> dict[str, object]:
    if (
        type(scope) is not Scope
        or type(scope.seeds) is not tuple
        or any(type(item) is not str for item in scope.seeds)
        or type(scope.allowed_origins) is not tuple
        or any(type(item) is not str for item in scope.allowed_origins)
        or type(scope.include_paths) is not tuple
        or any(type(item) is not str for item in scope.include_paths)
        or type(scope.content_types) is not tuple
        or any(type(item) is not ContentType for item in scope.content_types)
    ):
        raise SiteSkillError("site_skill.invalid")
    canonical, error = _validated_direct_scope(scope)
    if error is not None:
        raise SiteSkillError(error)
    assert canonical is not None
    return {
        "seeds": list(canonical.seeds),
        "allowed_origins": list(canonical.allowed_origins),
        "include_paths": list(canonical.include_paths),
        "content_types": [item.value for item in canonical.content_types],
    }


def _budgets_mapping(budgets: object) -> dict[str, int]:
    if type(budgets) is not Budgets or any(
        type(value) is not int
        for value in (
            budgets.max_requests,
            budgets.max_bytes,
            budgets.max_runtime_seconds,
            budgets.max_tool_attempts_per_target,
        )
    ):
        raise SiteSkillError("site_skill.invalid")
    canonical, error = _validated_direct_budgets(budgets)
    if error is not None:
        raise SiteSkillError(error)
    assert canonical is not None
    return {
        "max_requests": canonical.max_requests,
        "max_bytes": canonical.max_bytes,
        "max_runtime_seconds": canonical.max_runtime_seconds,
        "max_tool_attempts_per_target": canonical.max_tool_attempts_per_target,
    }


def _model_mapping(value: SiteSkill) -> dict[str, object]:
    if (
        type(value) is not SiteSkill
        or type(value.tool) is not ToolReference
        or type(value.success_checks) is not SuccessChecks
        or (
            value.discovery is not None and type(value.discovery) is not DiscoveryRecipe
        )
    ):
        raise SiteSkillError("site_skill.invalid")
    if (
        type(value.site_key) is not str
        or type(value.version) is not int
        or (
            value.previous_digest is not None and type(value.previous_digest) is not str
        )
        or type(value.verified_at) is not str
        or type(value.digest) is not str
    ):
        raise SiteSkillError("site_skill.invalid")
    tool = _direct_tool_mapping(value.tool)
    checks = _direct_checks_mapping(value.success_checks)
    mapping: dict[str, object] = {
        "site_key": value.site_key,
        "version": value.version,
        "previous_digest": value.previous_digest,
        "scope": _scope_mapping(value.scope),
        "budgets": _budgets_mapping(value.budgets),
        "tool": tool,
        "success_checks": checks,
        "verified_at": value.verified_at,
        "digest": value.digest,
    }
    if value.discovery is not None:
        mapping["discovery"] = _direct_discovery_mapping(
            value.discovery, value.scope, value.budgets
        )
    return mapping


def _direct_tool_mapping(value: ToolReference) -> dict[str, object]:
    if (
        type(value.tool_id) is not str
        or type(value.version) is not str
        or type(value.category) is not ToolCategory
        or type(value.capabilities) is not frozenset
        or not value.capabilities
        or any(type(item) is not str for item in value.capabilities)
    ):
        code = (
            "site_skill.tool_capabilities_invalid"
            if type(value.capabilities) is not frozenset
            or not value.capabilities
            or (
                type(value.capabilities) is frozenset
                and any(type(item) is not str for item in value.capabilities)
            )
            else "site_skill.tool_invalid"
        )
        raise SiteSkillError(code)
    if value.recipe_id is not None and type(value.recipe_id) is not str:
        raise SiteSkillError("site_skill.tool_invalid")
    mapping: dict[str, object] = {
        "tool_id": value.tool_id,
        "version": value.version,
        "category": value.category.value,
        "capabilities": sorted(value.capabilities),
    }
    if value.recipe_id is not None:
        mapping["recipe_id"] = value.recipe_id
    return mapping


def _direct_checks_mapping(value: SuccessChecks) -> dict[str, object]:
    if (
        type(value.allowed_mime_types) is not tuple
        or not value.allowed_mime_types
        or any(type(item) is not str for item in value.allowed_mime_types)
        or type(value.minimum_words) is not int
        or value.minimum_words <= 0
    ):
        raise SiteSkillError("site_skill.checks_invalid")
    return {
        "allowed_mime_types": list(value.allowed_mime_types),
        "minimum_words": value.minimum_words,
    }


def _direct_discovery_mapping(
    value: DiscoveryRecipe, scope: Scope, budgets: Budgets
) -> dict[str, object]:
    if type(value) is not DiscoveryRecipe or type(value.tool) is not ToolReference:
        raise SiteSkillError("site_skill.discovery_invalid")
    if value.tool.category is not ToolCategory.DISCOVERY:
        raise SiteSkillError("site_skill.discovery_invalid")
    mapping = {"tool": _direct_tool_mapping(value.tool), "source_url": value.source_url}
    if _parse_discovery(mapping, scope, budgets) != value:
        raise SiteSkillError("site_skill.discovery_invalid")
    return mapping


def _validated_request_values(
    scope: object, budgets: object, verified_at: object
) -> tuple[Scope, Budgets, str] | str:
    try:
        return (
            scope_from_mapping(scope),
            budgets_from_mapping(budgets),
            validate_observed_at(verified_at),  # type: ignore[arg-type]
        )
    except (RequestValidationError, ArtifactStoreError) as exc:
        return getattr(exc, "code", "site_skill.invalid")


def _validated_direct_scope(value: Scope) -> tuple[Scope | None, str | None]:
    try:
        return validate_scope(value), None
    except RequestValidationError as exc:
        return None, exc.code


def _validated_direct_budgets(value: Budgets) -> tuple[Budgets | None, str | None]:
    try:
        return validate_budgets(value), None
    except RequestValidationError as exc:
        return None, exc.code


def _payload_mapping(value: SiteSkill) -> dict[str, object]:
    mapping = _model_mapping(value)
    mapping.pop("digest")
    return mapping


def _encoded(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _computed_digest(value: SiteSkill) -> str:
    return f"sha256:{hashlib.sha256(_encoded(_payload_mapping(value))).hexdigest()}"


def compute_site_skill_digest(value: SiteSkill) -> str:
    """Compute the identity of validated content excluding its digest field."""
    mapping = _model_mapping(value)
    _site_skill_from_mapping(mapping, check_digest=False)
    return _computed_digest(value)


def validate_site_skill(value: SiteSkill) -> SiteSkill:
    """Rebuild and validate one direct immutable Site Skill value."""
    return _site_skill_from_mapping(_model_mapping(value), check_digest=True)


def site_skill_from_mapping(value: object) -> SiteSkill:
    """Parse one strict JSON-compatible Site Skill object."""
    return _site_skill_from_mapping(value, check_digest=True)


def site_skill_to_mapping(value: SiteSkill) -> dict[str, object]:
    """Return a detached JSON-compatible representation."""
    return _model_mapping(validate_site_skill(value))


def canonical_site_skill_bytes(value: SiteSkill) -> bytes:
    """Serialize one Site Skill to byte-stable canonical JSON."""
    return _encoded(site_skill_to_mapping(value))
