"""Strict deterministic SiteExploreResult v2 contract."""

# pylint: disable=duplicate-code,missing-function-docstring
# pylint: disable=too-many-boolean-expressions,unidiomatic-typecheck

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from web_listening.artifact.site_state import SiteState
from web_listening.result.attempts import Attempt, validate_attempts
from web_listening.result.errors import (
    ResultValidationError,
    SafeError,
    require_exact_fields,
    require_mapping,
    validate_url,
)
from web_listening.result.manifest import Usage
from web_listening.result.model import ResultStatus

SITE_EXPLORE_SCHEMA_VERSION = "web-listening-site-explore.v2"
_DISCOVERY_OUTCOMES = frozenset({"succeeded", "failed"})
_DISCOVERY_COVERAGES = frozenset({"complete", "truncated", "unknown"})
_STOP_REASONS = frozenset(
    {
        "source_exhausted",
        "budget_exhausted",
        "discovery_failed",
        "acquisition_failed",
        "rejected",
        "cancelled",
    }
)
_BUDGET_ERROR_CODES = frozenset(
    {
        "budget.exhausted",
        "budget.requests",
        "budget.bytes",
        "budget.runtime",
        "eligibility.request_budget_exhausted",
        "eligibility.byte_budget_exhausted",
        "eligibility.runtime_budget_exhausted",
        "eligibility.attempt_budget_exhausted",
    }
)
_TOOL_ID = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z")
_VERSION = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\Z")


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ResultValidationError("schema.invalid") from exc


@dataclass(frozen=True, slots=True)
class SiteSkillCandidateEvidence:
    """Immutable bytes and identity supplied by the authoritative Site Skill parser."""

    canonical_bytes: bytes
    digest: str
    discovery_key: tuple[str, str, str]

    def __post_init__(self) -> None:
        if type(self.canonical_bytes) is not bytes:
            raise ResultValidationError("site_explore.candidate_invalid")
        payload = require_mapping(self.to_dict())
        discovery = require_mapping(payload.get("discovery"))
        tool = require_mapping(discovery.get("tool"))
        observed_key = (
            tool.get("tool_id"),
            tool.get("version"),
            discovery.get("source_url"),
        )
        if payload.get("digest") != self.digest or observed_key != self.discovery_key:
            raise ResultValidationError("site_explore.candidate_invalid")

    @classmethod
    def from_validated_mapping(
        cls,
        value: object,
        *,
        digest: str,
        discovery_key: tuple[str, str, str],
    ) -> SiteSkillCandidateEvidence:
        """Snapshot a mapping only after its caller used the Site Skill validator."""
        return cls(_canonical_bytes(value), digest, discovery_key)

    def to_dict(self) -> dict[str, object]:
        try:
            value = json.loads(self.canonical_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ResultValidationError("site_explore.candidate_invalid") from exc
        if not isinstance(value, dict):
            raise ResultValidationError("site_explore.candidate_invalid")
        return value


@dataclass(frozen=True, slots=True)
class DiscoveryEvidence:  # pylint: disable=too-many-instance-attributes
    """One pure Discovery invocation and its inert output evidence."""

    tool_id: str
    tool_version: str
    source_url: str
    outcome: str
    candidates: tuple[str, ...]
    discovered_from: tuple[str, ...]
    coverage: str
    error: SafeError | None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.tool_id, str)
            or _TOOL_ID.fullmatch(self.tool_id) is None
            or not isinstance(self.tool_version, str)
            or _VERSION.fullmatch(self.tool_version) is None
        ):
            raise ResultValidationError("site_explore.discovery_invalid")
        validate_url(self.source_url)
        if (
            type(self.candidates) is not tuple
            or type(self.discovered_from) is not tuple
        ):
            raise ResultValidationError("site_explore.discovery_invalid")
        for url in self.candidates + self.discovered_from:
            validate_url(url)
        if (
            len(self.candidates) != len(self.discovered_from)
            or self.candidates != tuple(sorted(set(self.candidates)))
            or any(url != self.source_url for url in self.discovered_from)
            or self.outcome not in _DISCOVERY_OUTCOMES
            or type(self.coverage) is not str
            or self.coverage not in _DISCOVERY_COVERAGES
            or (self.error is not None and not isinstance(self.error, SafeError))
        ):
            raise ResultValidationError("site_explore.discovery_invalid")
        if self.outcome == "succeeded":
            if not self.candidates or self.error is not None:
                raise ResultValidationError("site_explore.discovery_invalid")
        elif (
            self.candidates
            or self.discovered_from
            or self.coverage != "unknown"
            or self.error is None
        ):
            raise ResultValidationError("site_explore.discovery_invalid")

    @classmethod
    def from_dict(cls, value: object) -> DiscoveryEvidence:
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {
                "tool_id",
                "tool_version",
                "source_url",
                "outcome",
                "candidates",
                "discovered_from",
                "coverage",
                "error",
            },
        )
        if not isinstance(payload["candidates"], list) or not isinstance(
            payload["discovered_from"], list
        ):
            raise ResultValidationError("site_explore.discovery_invalid")
        error = (
            None if payload["error"] is None else SafeError.from_dict(payload["error"])
        )
        return cls(
            tool_id=payload["tool_id"],
            tool_version=payload["tool_version"],
            source_url=payload["source_url"],
            outcome=payload["outcome"],
            candidates=tuple(payload["candidates"]),
            discovered_from=tuple(payload["discovered_from"]),
            coverage=payload["coverage"],
            error=error,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "source_url": self.source_url,
            "outcome": self.outcome,
            "candidates": list(self.candidates),
            "discovered_from": list(self.discovered_from),
            "coverage": self.coverage,
            "error": None if self.error is None else self.error.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class SiteExploreResult:  # pylint: disable=too-many-instance-attributes
    """One immutable exploration result assembled only from governed evidence."""

    status: ResultStatus | str
    exploration_complete: bool
    site_state: SiteState
    site_skill_candidate: SiteSkillCandidateEvidence | None
    site_skill_used: None
    discovery: tuple[DiscoveryEvidence, ...]
    attempts: tuple[Attempt, ...]
    usage: Usage
    stop_reason: str
    errors: tuple[SafeError, ...]
    schema_version: str = SITE_EXPLORE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SITE_EXPLORE_SCHEMA_VERSION:
            raise ResultValidationError("schema.version_invalid")
        try:
            status = ResultStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise ResultValidationError("site_explore.status_invalid") from exc
        object.__setattr__(self, "status", status)
        if type(self.exploration_complete) is not bool or not isinstance(
            self.site_state, SiteState
        ):
            raise ResultValidationError("site_explore.invalid")
        if self.site_skill_used is not None:
            raise ResultValidationError("site_explore.site_skill_forbidden")
        if self.site_skill_candidate is not None and not isinstance(
            self.site_skill_candidate, SiteSkillCandidateEvidence
        ):
            raise ResultValidationError("site_explore.candidate_invalid")
        if type(self.discovery) is not tuple or not all(
            type(item) is DiscoveryEvidence for item in self.discovery
        ):
            raise ResultValidationError("site_explore.discovery_invalid")
        observed_order = tuple(
            (item.tool_id, item.tool_version, item.source_url)
            for item in self.discovery
        )
        if observed_order != tuple(sorted(observed_order)):
            raise ResultValidationError("site_explore.discovery_order_invalid")
        if len(observed_order) != len(set(observed_order)):
            raise ResultValidationError("site_explore.discovery_duplicate")
        validate_attempts(self.attempts)
        if not isinstance(self.usage, Usage):
            raise ResultValidationError("usage.invalid")
        self.usage.validate_attempts(self.attempts)
        if self.stop_reason not in _STOP_REASONS:
            raise ResultValidationError("site_explore.stop_reason_invalid")
        if type(self.errors) is not tuple or not all(
            isinstance(error, SafeError) for error in self.errors
        ):
            raise ResultValidationError("site_explore.errors_invalid")
        self._validate_consistency()

    def _validate_consistency(self) -> None:
        candidate = self.site_skill_candidate
        if self.status is ResultStatus.COMPLETED and candidate is None:
            raise ResultValidationError("site_explore.completed_invalid")
        if self.status is not ResultStatus.COMPLETED and candidate is not None:
            raise ResultValidationError("site_explore.candidate_forbidden")
        if self.exploration_complete != self.site_state.complete:
            raise ResultValidationError("site_explore.state_mismatch")
        if (
            candidate is not None
            and self.site_state.site_skill_digest != candidate.digest
        ):
            raise ResultValidationError("site_explore.state_mismatch")
        if candidate is None and self.site_state.site_skill_digest is not None:
            raise ResultValidationError("site_explore.state_mismatch")
        successful_urls = {
            attempt.final_url
            for attempt in self.attempts
            if attempt.outcome == "succeeded" and attempt.final_url is not None
        }
        if any(
            page.canonical_url not in successful_urls for page in self.site_state.pages
        ):
            raise ResultValidationError("site_explore.state_evidence_mismatch")
        discovered_candidates = {
            url for evidence in self.discovery for url in evidence.candidates
        }
        successful_candidate_requests = {
            attempt.requested_url
            for attempt in self.attempts
            if attempt.outcome == "succeeded" and attempt.final_url is not None
        }
        candidate_success = bool(successful_candidate_requests & discovered_candidates)
        for evidence in self.discovery:
            matching_attempts = tuple(
                attempt
                for attempt in self.attempts
                if attempt.tool_id == evidence.tool_id
                and attempt.tool_version == evidence.tool_version
                and attempt.requested_url == evidence.source_url
                and attempt.final_url is None
                and attempt.requests == 0
                and attempt.bytes_received == 0
                and attempt.outcome == evidence.outcome
                and (
                    (attempt.error is None and evidence.error is None)
                    or (
                        attempt.error is not None
                        and evidence.error is not None
                        and attempt.error.code == evidence.error.code
                    )
                )
            )
            if len(matching_attempts) != 1:
                raise ResultValidationError("site_explore.discovery_evidence_mismatch")
        self._validate_stop_reason_consistency(candidate)
        if self.status is ResultStatus.COMPLETED:
            successful_discovery_keys = {
                (item.tool_id, item.tool_version, item.source_url)
                for item in self.discovery
                if item.outcome == "succeeded"
            }
            if (
                not self.exploration_complete
                or candidate is None
                or not candidate_success
                or candidate.discovery_key not in successful_discovery_keys
                or self.stop_reason != "source_exhausted"
                or any(item.outcome != "succeeded" for item in self.discovery)
            ):
                raise ResultValidationError("site_explore.completed_invalid")
        else:
            if not self.errors:
                raise ResultValidationError("site_explore.errors_required")

    def _validate_stop_reason_consistency(
        self, candidate: SiteSkillCandidateEvidence | None
    ) -> None:
        error_codes = (
            {error.code for error in self.errors}
            | {
                attempt.error.code
                for attempt in self.attempts
                if attempt.error is not None
            }
            | {
                evidence.error.code
                for evidence in self.discovery
                if evidence.error is not None
            }
        )
        if self.stop_reason != "budget_exhausted" and error_codes & _BUDGET_ERROR_CODES:
            raise ResultValidationError("site_explore.stop_reason_inconsistent")
        if (
            self.stop_reason == "budget_exhausted"
            and self.status is not ResultStatus.PARTIAL
        ):
            raise ResultValidationError("site_explore.stop_reason_inconsistent")
        if self.stop_reason == "source_exhausted":
            if (
                self.status is not ResultStatus.COMPLETED
                or not self.exploration_complete
                or candidate is None
            ):
                raise ResultValidationError("site_explore.stop_reason_inconsistent")
            return
        if self.stop_reason == "rejected" or self.status is ResultStatus.REJECTED:
            if not (
                self.stop_reason == "rejected" and self.status is ResultStatus.REJECTED
            ):
                raise ResultValidationError("site_explore.stop_reason_inconsistent")
            return
        incomplete_evidence = {
            "cancelled": "runtime.cancelled" in error_codes,
            "budget_exhausted": "budget.exhausted" in error_codes,
            "discovery_failed": (
                any(item.outcome == "failed" for item in self.discovery)
                or bool(
                    error_codes
                    & {"runtime.discovery_unavailable", "discovery.no_candidates"}
                )
            ),
        }
        if self.stop_reason in incomplete_evidence and (
            self.status is ResultStatus.COMPLETED
            or self.exploration_complete
            or not incomplete_evidence[self.stop_reason]
        ):
            raise ResultValidationError("site_explore.stop_reason_inconsistent")

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        site_skill_candidate: SiteSkillCandidateEvidence | None = None,
    ) -> SiteExploreResult:
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {
                "schema_version",
                "status",
                "exploration_complete",
                "site_state",
                "site_skill_candidate",
                "site_skill_used",
                "discovery",
                "attempts",
                "usage",
                "stop_reason",
                "errors",
            },
        )
        for field in ("discovery", "attempts", "errors"):
            if not isinstance(payload[field], list):
                raise ResultValidationError("schema.invalid")
        candidate_payload = payload["site_skill_candidate"]
        if candidate_payload is None:
            if site_skill_candidate is not None:
                raise ResultValidationError("site_explore.candidate_invalid")
            candidate = None
        else:
            if (
                site_skill_candidate is None
                or site_skill_candidate.to_dict() != candidate_payload
            ):
                raise ResultValidationError("site_explore.candidate_invalid")
            candidate = site_skill_candidate
        return cls(
            schema_version=payload["schema_version"],
            status=payload["status"],
            exploration_complete=payload["exploration_complete"],
            site_state=SiteState.from_dict(payload["site_state"]),
            site_skill_candidate=candidate,
            site_skill_used=payload["site_skill_used"],
            discovery=tuple(
                DiscoveryEvidence.from_dict(item) for item in payload["discovery"]
            ),
            attempts=tuple(Attempt.from_dict(item) for item in payload["attempts"]),
            usage=Usage.from_dict(payload["usage"]),
            stop_reason=payload["stop_reason"],
            errors=tuple(SafeError.from_dict(item) for item in payload["errors"]),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "exploration_complete": self.exploration_complete,
            "site_state": self.site_state.to_dict(),
            "site_skill_candidate": (
                None
                if self.site_skill_candidate is None
                else self.site_skill_candidate.to_dict()
            ),
            "site_skill_used": None,
            "discovery": [item.to_dict() for item in self.discovery],
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "usage": self.usage.to_dict(),
            "stop_reason": self.stop_reason,
            "errors": [error.to_dict() for error in self.errors],
        }

    def canonical_json_bytes(self) -> bytes:
        return _canonical_bytes(self.to_dict())


__all__ = [
    "SITE_EXPLORE_SCHEMA_VERSION",
    "DiscoveryEvidence",
    "SiteExploreResult",
    "SiteSkillCandidateEvidence",
]
