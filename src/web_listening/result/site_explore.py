"""Strict deterministic SiteExploreResult v3 contract."""

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
from web_listening.result.model import Result, ResultStatus

SITE_EXPLORE_SCHEMA_VERSION = "web-listening-site-explore.v3"
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
_PARENT_ONLY_ERROR_CODES = frozenset(
    {
        "budget.exhausted",
        "discovery.no_candidates",
        "runtime.discovery_unavailable",
        "runtime.discovery_url_unrepresentable",
        "runtime.quality_minimum_words",
        "runtime.site_explore_requires_no_site_skill",
        "runtime.site_explore_single_seed_required",
        "runtime.site_identity_mismatch",
        "runtime.site_skill_discovery_unverified",
        "runtime.site_skill_tool_unverified",
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
    target_results: tuple[Result, ...]
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
        self._validate_target_results()
        self._validate_consistency()

    def _validate_target_results(self) -> None:
        if type(self.target_results) is not tuple or not all(
            type(item) is Result for item in self.target_results
        ):
            raise ResultValidationError("site_explore.target_results_invalid")
        if not self.target_results:
            if (
                self.attempts
                or self.discovery
                or self.site_state.pages
                or self.status is not ResultStatus.REJECTED
                or self.stop_reason != "rejected"
                or {error.code for error in self.errors}
                not in (
                    {"runtime.site_explore_requires_no_site_skill"},
                    {"runtime.site_explore_single_seed_required"},
                )
            ):
                raise ResultValidationError("site_explore.target_results_mismatch")
            return
        run_ids = tuple(item.manifest.run_id for item in self.target_results)
        if len(run_ids) != len(set(run_ids)) or not run_ids[0].endswith("-seed"):
            raise ResultValidationError("site_explore.target_results_duplicate")
        if any(
            result.attempts and result.attempts[0].attempt_id != result.manifest.run_id
            for result in self.target_results
        ):
            raise ResultValidationError("site_explore.target_results_mismatch")
        prefix = run_ids[0][:-5]
        candidate_numbers: list[int] = []
        for run_id in run_ids[1:]:
            match = re.fullmatch(rf"{re.escape(prefix)}-candidate-([1-9]\d*)", run_id)
            if match is None:
                raise ResultValidationError("site_explore.target_results_mismatch")
            candidate_numbers.append(int(match.group(1)))
        if candidate_numbers != sorted(set(candidate_numbers)):
            raise ResultValidationError("site_explore.target_results_order_invalid")
        candidate_urls = tuple(
            item.manifest.requested_url for item in self.target_results[1:]
        )
        discovered_urls = {
            url for evidence in self.discovery for url in evidence.candidates
        }
        if (
            candidate_urls != tuple(sorted(set(candidate_urls)))
            or not set(candidate_urls).issubset(discovered_urls)
            or any(item.site_skill_used is not None for item in self.target_results)
        ):
            raise ResultValidationError("site_explore.target_results_order_invalid")

    def _validate_consistency(self) -> None:  # pylint: disable=too-many-branches
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
        discovery_attempt_ids = {
            attempt.attempt_id
            for evidence in self.discovery
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
        }
        _validate_target_attempts(
            self.target_results,
            self.attempts,
            discovery_attempt_ids=discovery_attempt_ids,
            code="site_explore.target_results_mismatch",
        )
        discovery_attempts = tuple(
            attempt
            for attempt in self.attempts
            if attempt.attempt_id in discovery_attempt_ids
        )
        expected_usage = Usage(
            sum(result.usage.requests for result in self.target_results)
            + sum(attempt.requests for attempt in discovery_attempts),
            sum(result.usage.bytes_received for result in self.target_results)
            + sum(attempt.bytes_received for attempt in discovery_attempts),
            sum(result.usage.runtime_ms for result in self.target_results)
            + sum(attempt.runtime_ms for attempt in discovery_attempts),
            sum(result.usage.tool_attempts for result in self.target_results)
            + sum(attempt.outcome != "skipped" for attempt in discovery_attempts),
        )
        if self.usage != expected_usage:
            raise ResultValidationError("site_explore.target_results_mismatch")
        source_evidence = {
            (
                artifact.source_url,
                artifact.observation_id,
                artifact.artifact_id,
                f"sha256:{artifact.sha256}",
            )
            for result in self.target_results
            for artifact in result.artifacts
            if artifact.role == "source"
        }
        if any(
            (
                page.canonical_url,
                page.observation_id,
                page.artifact_id,
                page.content_digest,
            )
            not in source_evidence
            for page in self.site_state.pages
        ):
            raise ResultValidationError("site_explore.target_results_mismatch")
        self._validate_stop_reason_consistency(candidate)
        _validate_target_errors(
            self.target_results,
            self.discovery,
            self.errors,
        )
        if self.status is ResultStatus.COMPLETED:
            adopted_discovery = (
                ()
                if candidate is None
                else tuple(
                    item
                    for item in self.discovery
                    if (item.tool_id, item.tool_version, item.source_url)
                    == candidate.discovery_key
                )
            )
            if (
                not self.exploration_complete
                or candidate is None
                or not candidate_success
                or len(adopted_discovery) != 1
                or adopted_discovery[0].outcome != "succeeded"
                or self.stop_reason != "source_exhausted"
                or (
                    any(item.outcome != "succeeded" for item in self.discovery)
                    and adopted_discovery[0].coverage != "complete"
                )
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
                "target_results",
                "attempts",
                "usage",
                "stop_reason",
                "errors",
            },
        )
        for field in ("discovery", "target_results", "attempts", "errors"):
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
            target_results=tuple(
                Result.from_dict(item) for item in payload["target_results"]
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
            "target_results": [item.to_dict() for item in self.target_results],
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "usage": self.usage.to_dict(),
            "stop_reason": self.stop_reason,
            "errors": [error.to_dict() for error in self.errors],
        }

    def canonical_json_bytes(self) -> bytes:
        return _canonical_bytes(self.to_dict())


def _validate_target_attempts(
    target_results: tuple[Result, ...],
    attempts: tuple[Attempt, ...],
    *,
    discovery_attempt_ids: set[str],
    code: str,
) -> None:
    child_attempts = tuple(
        attempt for result in target_results for attempt in result.attempts
    )
    child_ids = tuple(attempt.attempt_id for attempt in child_attempts)
    if len(child_ids) != len(set(child_ids)):
        raise ResultValidationError(code)
    aggregate_acquisition = tuple(
        attempt
        for attempt in attempts
        if attempt.attempt_id not in discovery_attempt_ids
    )
    if tuple(item.attempt_id for item in aggregate_acquisition) != child_ids:
        raise ResultValidationError(code)
    for child, aggregate in zip(child_attempts, aggregate_acquisition):
        child_payload = child.to_dict()
        aggregate_payload = aggregate.to_dict()
        child_payload.pop("order")
        aggregate_payload.pop("order")
        if child_payload != aggregate_payload:
            raise ResultValidationError(code)


def _validate_target_errors(
    target_results: tuple[Result, ...],
    discovery: tuple[DiscoveryEvidence, ...],
    errors: tuple[SafeError, ...],
) -> None:
    if any(
        not result.attempts
        and any(error.code in _PARENT_ONLY_ERROR_CODES for error in result.errors)
        for result in target_results[1:]
    ):
        raise ResultValidationError("site_explore.target_results_mismatch")
    remaining = list(errors)
    attributed = tuple(
        error for result in target_results for error in result.errors
    ) + tuple(item.error for item in discovery if item.error is not None)
    for error in attributed:
        try:
            remaining.remove(error)
        except ValueError as exc:
            raise ResultValidationError("site_explore.target_results_mismatch") from exc
    if any(error.code not in _PARENT_ONLY_ERROR_CODES for error in remaining):
        raise ResultValidationError("site_explore.target_results_mismatch")


__all__ = [
    "SITE_EXPLORE_SCHEMA_VERSION",
    "DiscoveryEvidence",
    "SiteExploreResult",
    "SiteSkillCandidateEvidence",
]
