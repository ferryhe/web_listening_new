"""Immutable data-only Site Skill values."""

from __future__ import annotations

from dataclasses import dataclass

from web_listening.request.model import Budgets, Scope
from web_listening.tool_registry.manifest import ToolCategory


class SiteSkillError(ValueError):
    """Reject invalid Site Skill data with a stable, non-sensitive code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ToolReference:
    """Exact Registry metadata required by a Site Skill."""

    tool_id: str
    version: str
    category: ToolCategory
    capabilities: frozenset[str]
    recipe_id: str | None = None


@dataclass(frozen=True, slots=True)
class SuccessChecks:
    """Data-only evidence thresholds for a successful observation."""

    allowed_mime_types: tuple[str, ...]
    minimum_words: int


@dataclass(frozen=True, slots=True)
class SiteSkill:  # pylint: disable=too-many-instance-attributes
    """One immutable, versioned piece of verified site knowledge."""

    site_key: str
    version: int
    previous_digest: str | None
    scope: Scope
    budgets: Budgets
    tool: ToolReference
    success_checks: SuccessChecks
    verified_at: str
    digest: str
