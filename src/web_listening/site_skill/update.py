"""Pure Site Skill candidate construction."""

# pylint: disable=duplicate-code,unidiomatic-typecheck

from __future__ import annotations

from dataclasses import dataclass, replace

from web_listening.request.model import Budgets, Scope
from web_listening.site_skill.model import (
    DiscoveryRecipe,
    SiteSkill,
    SiteSkillError,
    SuccessChecks,
    ToolReference,
)
from web_listening.site_skill.validate import (
    compute_site_skill_digest,
    validate_site_skill,
)


@dataclass(frozen=True, slots=True)
class SiteSkillCandidate:
    """A verified value that remains inactive until explicitly activated."""

    skill: SiteSkill


def create_candidate(  # pylint: disable=too-many-arguments
    *,
    site_key: str,
    version: int,
    previous: SiteSkill | None,
    scope: Scope,
    budgets: Budgets,
    tool: ToolReference,
    success_checks: SuccessChecks,
    verified_at: str,
    discovery: DiscoveryRecipe | None = None,
) -> SiteSkillCandidate:
    """Create an immutable candidate with explicit predecessor lineage."""
    if type(site_key) is not str:
        raise SiteSkillError("site_skill.site_key_invalid")
    if type(version) is not int or version <= 0:
        raise SiteSkillError("site_skill.version_invalid")
    previous_digest: str | None = None
    if previous is not None:
        previous = validate_site_skill(previous)
        if previous.site_key != site_key or version != previous.version + 1:
            raise SiteSkillError("site_skill.previous_invalid")
        previous_digest = previous.digest
    elif version != 1:
        raise SiteSkillError("site_skill.previous_required")
    draft = SiteSkill(
        site_key,
        version,
        previous_digest,
        scope,
        budgets,
        tool,
        success_checks,
        verified_at,
        "sha256:" + "0" * 64,
        discovery,
    )
    skill = replace(draft, digest=compute_site_skill_digest(draft))
    return SiteSkillCandidate(validate_site_skill(skill))
