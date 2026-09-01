"""Strict Request contract for one serial multi-site batch."""

# pylint: disable=duplicate-code,unidiomatic-typecheck

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from web_listening.artifact.model import ArtifactStoreError
from web_listening.artifact.site_state import SiteState
from web_listening.request.model import Request, RequestValidationError, Scope
from web_listening.request.site_refresh import (
    SiteRefreshRequest,
    validate_site_refresh_request,
)
from web_listening.request.validate import request_from_mapping, validate_request
from web_listening.site_skill.model import SiteSkill, SiteSkillError
from web_listening.site_skill.validate import (
    site_skill_from_mapping,
    site_skill_to_mapping,
    validate_site_skill,
)

SITE_BATCH_REQUEST_SCHEMA_VERSION = "web-listening-site-batch-request.v1"
_FIELDS = frozenset({"schema_version", "phase", "request", "refresh_contexts"})
_REQUEST_FIELDS = frozenset({"scope", "site_skill", "explore_all_tools", "budgets"})
_CONTEXT_FIELDS = frozenset({"site_skill", "previous_state"})


class SiteBatchPhase(str, Enum):
    """The two independent batch Request phases."""

    FIRST = "first"
    REFRESH = "refresh"


def _error(code: str) -> RequestValidationError:
    return RequestValidationError(code)


def site_batch_child_scope(parent: Scope, seed: str) -> Scope:
    """Narrow one batch slot without discarding authorized non-sibling aliases."""
    current_host = urlsplit(seed).hostname
    sibling_hosts = {
        urlsplit(other).hostname
        for other in parent.seeds
        if urlsplit(other).hostname != current_host
    }
    return Scope(
        (seed,),
        tuple(
            origin
            for origin in parent.allowed_origins
            if urlsplit(origin).hostname not in sibling_hosts
        ),
        parent.include_paths,
        parent.content_types,
    )


@dataclass(frozen=True, slots=True)
class SiteRefreshContext:
    """One client-persisted Site Skill and its last usable Site State."""

    site_skill: SiteSkill
    previous_state: SiteState

    def __post_init__(self) -> None:
        try:
            skill = validate_site_skill(self.site_skill)
            state = SiteState.from_dict(self.previous_state.to_dict())
        except (SiteSkillError, ArtifactStoreError, AttributeError) as exc:
            raise _error(
                getattr(exc, "code", "site_batch_request.context_invalid")
            ) from exc
        if state.site_key != skill.site_key:
            raise _error("site_batch_request.site_mismatch")
        if state.site_skill_digest != skill.digest:
            raise _error("site_batch_request.skill_state_mismatch")
        object.__setattr__(self, "site_skill", skill)
        object.__setattr__(self, "previous_state", state)

    def to_dict(self) -> dict[str, object]:
        """Return the exact JSON-compatible continuation payload."""
        return {
            "site_skill": site_skill_to_mapping(self.site_skill),
            "previous_state": self.previous_state.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: object) -> SiteRefreshContext:
        """Parse one strict continuation payload."""
        if not isinstance(value, Mapping) or not all(
            isinstance(key, str) for key in value
        ):
            raise _error("site_batch_request.context_invalid")
        keys = set(value)
        if keys - _CONTEXT_FIELDS:
            raise _error("site_batch_request.context_unknown_field")
        if _CONTEXT_FIELDS - keys:
            raise _error("site_batch_request.context_missing")
        try:
            return cls(
                site_skill_from_mapping(value["site_skill"]),
                SiteState.from_dict(value["previous_state"]),
            )
        except (SiteSkillError, ArtifactStoreError) as exc:
            raise _error(exc.code) from exc


@dataclass(frozen=True, slots=True)
class SiteBatchRequest:
    """One parent Request and ordered refresh contexts for its site slots."""

    phase: SiteBatchPhase | str
    request: Request
    refresh_contexts: tuple[SiteRefreshContext, ...]
    schema_version: str = SITE_BATCH_REQUEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SITE_BATCH_REQUEST_SCHEMA_VERSION:
            raise _error("site_batch_request.version_invalid")
        try:
            phase = SiteBatchPhase(self.phase)
        except (TypeError, ValueError) as exc:
            raise _error("site_batch_request.phase_invalid") from exc
        request = validate_request(self.request)
        if request.site_skill is not None:
            raise _error("site_batch_request.parent_site_skill_forbidden")
        if type(self.refresh_contexts) is not tuple or not all(
            type(item) is SiteRefreshContext for item in self.refresh_contexts
        ):
            raise _error("site_batch_request.context_invalid")
        site_keys = tuple(
            urlsplit(seed).hostname or "invalid" for seed in request.scope.seeds
        )
        if len(site_keys) < 2:
            raise _error("site_batch_request.multiple_sites_required")
        if len(site_keys) != len(set(site_keys)):
            raise _error("site_batch_request.site_duplicate")
        if phase is SiteBatchPhase.FIRST:
            if self.refresh_contexts:
                raise _error("site_batch_request.refresh_context_forbidden")
        else:
            if len(self.refresh_contexts) != len(site_keys):
                raise _error("site_batch_request.refresh_context_missing")
            context_keys = tuple(
                context.site_skill.site_key for context in self.refresh_contexts
            )
            if context_keys != site_keys:
                raise _error("site_batch_request.site_order_mismatch")
            for seed, context in zip(
                request.scope.seeds,
                self.refresh_contexts,
                strict=True,
            ):
                validate_site_refresh_request(
                    SiteRefreshRequest(
                        site_batch_child_scope(request.scope, seed),
                        context.site_skill,
                        context.previous_state,
                        request.explore_all_tools,
                        request.budgets,
                    )
                )
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "request", request)

    @property
    def site_keys(self) -> tuple[str, ...]:
        """Return the stable caller-supplied site order."""
        return tuple(
            urlsplit(seed).hostname or "invalid" for seed in self.request.scope.seeds
        )

    @property
    def request_sha256(self) -> str:
        """Return the stable identity of this complete parent Request."""
        return hashlib.sha256(self.canonical_json_bytes()).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Return the exact JSON-compatible parent payload."""
        return {
            "schema_version": self.schema_version,
            "phase": self.phase.value,
            "request": _request_mapping(self.request),
            "refresh_contexts": [item.to_dict() for item in self.refresh_contexts],
        }

    def canonical_json_bytes(self) -> bytes:
        """Return byte-stable canonical UTF-8 JSON."""
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")


def _request_mapping(request: Request) -> dict[str, object]:
    return {
        "scope": {
            "seeds": list(request.scope.seeds),
            "allowed_origins": list(request.scope.allowed_origins),
            "include_paths": list(request.scope.include_paths),
            "content_types": [item.value for item in request.scope.content_types],
        },
        "site_skill": None,
        "explore_all_tools": request.explore_all_tools,
        "budgets": {
            "max_requests": request.budgets.max_requests,
            "max_bytes": request.budgets.max_bytes,
            "max_runtime_seconds": request.budgets.max_runtime_seconds,
            "max_tool_attempts_per_target": (
                request.budgets.max_tool_attempts_per_target
            ),
        },
    }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error("site_batch_request.duplicate_key")
        result[key] = value
    return result


def validate_site_batch_request(value: SiteBatchRequest) -> SiteBatchRequest:
    """Rebuild and validate one direct batch Request model."""
    if type(value) is not SiteBatchRequest:
        raise _error("site_batch_request.invalid")
    return SiteBatchRequest(
        value.phase,
        value.request,
        value.refresh_contexts,
        value.schema_version,
    )


def site_batch_request_from_mapping(value: object) -> SiteBatchRequest:
    """Parse one exact JSON-compatible batch Request mapping."""
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise _error("site_batch_request.invalid")
    keys = set(value)
    if keys - _FIELDS:
        raise _error("site_batch_request.unknown_field")
    if _FIELDS - keys:
        raise _error("site_batch_request.missing")
    request_payload = value["request"]
    if (
        not isinstance(request_payload, Mapping)
        or set(request_payload) != _REQUEST_FIELDS
    ):
        raise _error("site_batch_request.request_invalid")
    contexts = value["refresh_contexts"]
    if not isinstance(contexts, list):
        raise _error("site_batch_request.context_invalid")
    return SiteBatchRequest(
        value["phase"],
        request_from_mapping(request_payload),
        tuple(SiteRefreshContext.from_dict(item) for item in contexts),
        value["schema_version"],
    )


def site_batch_request_from_json(payload: str) -> SiteBatchRequest:
    """Parse JSON while rejecting duplicate keys at every object depth."""
    try:
        value = json.loads(payload, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, TypeError) as exc:
        raise _error("site_batch_request.invalid_json") from exc
    return site_batch_request_from_mapping(value)


__all__ = [
    "SITE_BATCH_REQUEST_SCHEMA_VERSION",
    "SiteBatchPhase",
    "SiteBatchRequest",
    "SiteRefreshContext",
    "site_batch_request_from_json",
    "site_batch_request_from_mapping",
    "site_batch_child_scope",
    "validate_site_batch_request",
]
