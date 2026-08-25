"""Minimal value-only Site Skill candidate and activation repository."""

# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import threading
from dataclasses import dataclass

from web_listening.site_skill.model import SiteSkill, SiteSkillError
from web_listening.site_skill.update import SiteSkillCandidate
from web_listening.site_skill.validate import (
    site_skill_from_mapping,
    site_skill_to_mapping,
    validate_site_skill,
)


@dataclass(frozen=True, slots=True)
class SiteSkillEvent:
    """One ordered provenance fact for an explicit lifecycle mutation."""

    sequence: int
    site_key: str
    action: str
    from_digest: str | None
    to_digest: str


class SiteSkillRepository:
    """Keep immutable values and explicit compare-and-set activation state."""

    def __init__(self) -> None:
        self._candidates: dict[tuple[str, str], SiteSkill] = {}
        self._active: dict[str, str] = {}
        self._events: list[SiteSkillEvent] = []
        self._lock = threading.RLock()

    @property
    def events(self) -> tuple[SiteSkillEvent, ...]:
        """Return detached immutable provenance in mutation order."""
        with self._lock:
            return tuple(_event_snapshot(event) for event in self._events)

    def submit(self, candidate: SiteSkillCandidate) -> SiteSkill:
        """Verify and retain a candidate without activating it."""
        with self._lock:
            if type(candidate) is not SiteSkillCandidate:
                raise SiteSkillError("repository.candidate_invalid")
            skill = _skill_snapshot(validate_site_skill(candidate.skill))
            key = (skill.site_key, skill.digest)
            existing = self._candidates.get(key)
            if existing is not None:
                return _skill_snapshot(existing)
            if skill.previous_digest is not None:
                previous = self._candidates.get((skill.site_key, skill.previous_digest))
                if previous is None:
                    raise SiteSkillError("repository.previous_missing")
                if skill.version != previous.version + 1:
                    raise SiteSkillError("repository.lineage_conflict")
            self._candidates[key] = skill
            self._record(
                skill.site_key, "candidate", skill.previous_digest, skill.digest
            )
            return _skill_snapshot(skill)

    def candidate(self, site_key: str, digest: str) -> SiteSkill | None:
        """Return one submitted immutable candidate, if present."""
        with self._lock:
            _validate_key(site_key)
            _validate_key(digest)
            skill = self._candidates.get((site_key, digest))
            return None if skill is None else _skill_snapshot(skill)

    def active(self, site_key: str) -> SiteSkill | None:
        """Return the explicitly active value, if one exists."""
        with self._lock:
            _validate_key(site_key)
            digest = self._active.get(site_key)
            return (
                None
                if digest is None
                else _skill_snapshot(self._candidates[(site_key, digest)])
            )

    def activate(
        self,
        site_key: str,
        digest: str,
        *,
        expected_active_digest: str | None,
    ) -> SiteSkill:
        """Activate one direct successor using compare-and-set semantics."""
        with self._lock:
            _validate_key(site_key)
            _validate_key(digest)
            _validate_optional_key(expected_active_digest)
            current = self._active.get(site_key)
            if current != expected_active_digest:
                raise SiteSkillError("repository.conflict")
            skill = self._candidates.get((site_key, digest))
            if skill is None:
                raise SiteSkillError("repository.candidate_missing")
            if skill.previous_digest != current:
                raise SiteSkillError("repository.lineage_conflict")
            self._active[site_key] = digest
            self._record(site_key, "activate", current, digest)
            return _skill_snapshot(skill)

    def rollback(
        self,
        site_key: str,
        digest: str,
        *,
        expected_active_digest: str,
    ) -> SiteSkill:
        """Explicitly restore an ancestor using compare-and-set semantics."""
        with self._lock:
            _validate_key(site_key)
            _validate_key(digest)
            _validate_key(expected_active_digest)
            current = self._active.get(site_key)
            if current != expected_active_digest:
                raise SiteSkillError("repository.conflict")
            target = self._candidates.get((site_key, digest))
            if target is None:
                raise SiteSkillError("repository.candidate_missing")
            ancestor = self._candidates.get((site_key, current)) if current else None
            while ancestor is not None and ancestor.previous_digest != digest:
                previous = ancestor.previous_digest
                ancestor = (
                    None
                    if previous is None
                    else self._candidates.get((site_key, previous))
                )
            if ancestor is None:
                raise SiteSkillError("repository.rollback_invalid")
            self._active[site_key] = digest
            self._record(site_key, "rollback", current, digest)
            return _skill_snapshot(target)

    def _record(
        self,
        site_key: str,
        action: str,
        from_digest: str | None,
        to_digest: str,
    ) -> None:
        self._events.append(
            SiteSkillEvent(
                len(self._events) + 1,
                site_key,
                action,
                from_digest,
                to_digest,
            )
        )


def _validate_key(value: object) -> None:
    if type(value) is not str:
        raise SiteSkillError("repository.key_invalid")


def _validate_optional_key(value: object) -> None:
    if value is not None:
        _validate_key(value)


def _skill_snapshot(value: SiteSkill) -> SiteSkill:
    return site_skill_from_mapping(site_skill_to_mapping(value))


def _event_snapshot(value: SiteSkillEvent) -> SiteSkillEvent:
    return SiteSkillEvent(
        value.sequence,
        value.site_key,
        value.action,
        value.from_digest,
        value.to_digest,
    )
