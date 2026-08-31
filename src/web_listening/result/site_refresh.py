"""Strict deterministic SiteRefreshResult v2 and mutually exclusive changes."""

# pylint: disable=duplicate-code,missing-function-docstring
# pylint: disable=too-many-boolean-expressions,unidiomatic-typecheck

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from web_listening.artifact.lineage import validate_artifact_id
from web_listening.artifact.model import ArtifactStoreError
from web_listening.artifact.site_state import (
    SiteState,
    SiteStatePage,
    validate_site_state_url,
)
from web_listening.result.attempts import Attempt, validate_attempts
from web_listening.result.errors import (
    ResultValidationError,
    SafeError,
    ensure_safe_payload,
    require_exact_fields,
    require_mapping,
    validate_text,
    validate_url,
)
from web_listening.result.manifest import SiteSkillEvidence, Usage
from web_listening.result.model import Result, ResultStatus
from web_listening.result.site_explore import SiteSkillCandidateEvidence

SITE_REFRESH_SCHEMA_VERSION = "web-listening-site-refresh.v2"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CHANGE_TYPES = frozenset(
    {"added", "changed", "unchanged", "missing", "failed", "unresolved"}
)
_UPDATE_REASONS = frozenset({"discovery_recipe_changed", "preferred_tool_changed"})
_STOP_REASONS = frozenset(
    {
        "source_exhausted",
        "budget_exhausted",
        "discovery_failed",
        "acquisition_failed",
        "rejected",
        "cancelled",
        "recovery_incomplete",
    }
)
_PARENT_ONLY_ERROR_CODES = frozenset(
    {
        "budget.exhausted",
        "discovery.no_candidates",
        "runtime.discovery_coverage_incomplete",
        "runtime.discovery_unavailable",
        "runtime.discovery_url_unrepresentable",
        "runtime.quality_minimum_words",
        "runtime.recovery_coverage_incomplete",
        "runtime.site_identity_mismatch",
        "runtime.site_skill_discovery_unverified",
        "runtime.site_skill_tool_unverified",
    }
)


def _canonical_url(value: object) -> str:
    try:
        canonical = validate_site_state_url(value)
    except ArtifactStoreError as exc:
        if exc.code == "site_state.sensitive_data":
            raise ResultValidationError("result.sensitive_data") from exc
        if exc.code == "site_state.absolute_path":
            raise ResultValidationError("result.absolute_path") from exc
        raise ResultValidationError("site_refresh.url_invalid") from exc
    validate_url(canonical)
    return canonical


@dataclass(frozen=True, slots=True)
class ChangeEvidence:
    """Artifact identity and frozen content digest from one Site State page."""

    artifact_id: str
    digest: str

    def __post_init__(self) -> None:
        try:
            validate_artifact_id(self.artifact_id)
        except ArtifactStoreError as exc:
            raise ResultValidationError("site_refresh.evidence_invalid") from exc
        if type(self.digest) is not str or _DIGEST.fullmatch(self.digest) is None:
            raise ResultValidationError("site_refresh.evidence_invalid")

    @classmethod
    def from_dict(cls, value: object) -> ChangeEvidence:
        payload = require_mapping(value)
        require_exact_fields(payload, {"artifact_id", "digest"})
        return cls(payload["artifact_id"], payload["digest"])

    def to_dict(self) -> dict[str, str]:
        return {"artifact_id": self.artifact_id, "digest": self.digest}


@dataclass(frozen=True, slots=True)
class SiteChange:  # pylint: disable=too-many-instance-attributes
    """One page in exactly one refresh change collection."""

    url: str
    change_type: str
    previous: ChangeEvidence | None
    current: ChangeEvidence | None
    attempt_ids: tuple[str, ...] = ()
    error_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _canonical_url(self.url)
        if self.change_type not in _CHANGE_TYPES:
            raise ResultValidationError("site_refresh.change_type_invalid")
        if self.previous is not None and type(self.previous) is not ChangeEvidence:
            raise ResultValidationError("site_refresh.evidence_invalid")
        if self.current is not None and type(self.current) is not ChangeEvidence:
            raise ResultValidationError("site_refresh.evidence_invalid")
        if type(self.attempt_ids) is not tuple or type(self.error_codes) is not tuple:
            raise ResultValidationError("site_refresh.change_invalid")
        for attempt_id in self.attempt_ids:
            validate_text(attempt_id, code="site_refresh.failed_evidence", maximum=128)
        for code in self.error_codes:
            SafeError(code, "Acquisition failed.")
        if self.attempt_ids != tuple(
            sorted(set(self.attempt_ids))
        ) or self.error_codes != tuple(sorted(set(self.error_codes))):
            raise ResultValidationError("site_refresh.failed_evidence")
        self._validate_shape()

    def _validate_shape(self) -> None:
        if self.change_type == "added":
            valid = self.previous is None and self.current is not None
        elif self.change_type in {"changed", "unchanged"}:
            valid = self.previous is not None and self.current is not None
            if valid:
                same = self.previous.digest == self.current.digest
                valid = same == (self.change_type == "unchanged")
        elif self.change_type in {"missing", "unresolved"}:
            valid = self.previous is not None and self.current is None
        else:
            valid = (
                self.current is None
                and bool(self.attempt_ids)
                and bool(self.error_codes)
            )
        if self.change_type != "failed" and (self.attempt_ids or self.error_codes):
            valid = False
        if not valid:
            raise ResultValidationError("site_refresh.change_invalid")

    @classmethod
    def from_dict(cls, value: object) -> SiteChange:
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {
                "url",
                "change_type",
                "previous",
                "current",
                "attempt_ids",
                "error_codes",
            },
        )
        if not isinstance(payload["attempt_ids"], list) or not isinstance(
            payload["error_codes"], list
        ):
            raise ResultValidationError("site_refresh.change_invalid")
        return cls(
            payload["url"],
            payload["change_type"],
            (
                None
                if payload["previous"] is None
                else ChangeEvidence.from_dict(payload["previous"])
            ),
            (
                None
                if payload["current"] is None
                else ChangeEvidence.from_dict(payload["current"])
            ),
            tuple(payload["attempt_ids"]),
            tuple(payload["error_codes"]),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "change_type": self.change_type,
            "previous": None if self.previous is None else self.previous.to_dict(),
            "current": None if self.current is None else self.current.to_dict(),
            "attempt_ids": list(self.attempt_ids),
            "error_codes": list(self.error_codes),
        }


@dataclass(frozen=True, slots=True)
class SiteSkillUpdate:
    """One inactive, validated replacement candidate and its active predecessor."""

    reason: str
    previous: SiteSkillEvidence
    candidate: SiteSkillCandidateEvidence

    def __post_init__(self) -> None:
        if self.reason not in _UPDATE_REASONS:
            raise ResultValidationError("site_refresh.skill_update_invalid")
        if type(self.previous) is not SiteSkillEvidence or not isinstance(
            self.candidate, SiteSkillCandidateEvidence
        ):
            raise ResultValidationError("site_refresh.skill_update_invalid")
        mapping = self.candidate.to_dict()
        expected = f"sha256:{self.previous.sha256}"
        if mapping.get("previous_digest") != expected:
            raise ResultValidationError("site_refresh.skill_update_invalid")

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        candidate: SiteSkillCandidateEvidence | None = None,
    ) -> SiteSkillUpdate:
        payload = require_mapping(value)
        require_exact_fields(payload, {"reason", "previous", "candidate"})
        if candidate is None or candidate.to_dict() != payload["candidate"]:
            raise ResultValidationError("site_refresh.skill_update_invalid")
        return cls(
            payload["reason"],
            SiteSkillEvidence.from_dict(payload["previous"]),
            candidate,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "reason": self.reason,
            "previous": self.previous.to_dict(),
            "candidate": self.candidate.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class SiteRefreshResult:  # pylint: disable=too-many-instance-attributes
    """One strict refresh result built from two states and governed attempts."""

    status: ResultStatus | str
    refresh_complete: bool
    added: tuple[SiteChange, ...]
    changed: tuple[SiteChange, ...]
    unchanged: tuple[SiteChange, ...]
    missing: tuple[SiteChange, ...]
    failed: tuple[SiteChange, ...]
    unresolved: tuple[SiteChange, ...]
    previous_state: SiteState
    current_state: SiteState
    site_skill_used: SiteSkillEvidence
    site_skill_update: SiteSkillUpdate | None
    target_results: tuple[Result, ...]
    attempts: tuple[Attempt, ...]
    usage: Usage
    stop_reason: str
    errors: tuple[SafeError, ...]
    schema_version: str = SITE_REFRESH_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SITE_REFRESH_SCHEMA_VERSION:
            raise ResultValidationError("schema.version_invalid")
        try:
            status = ResultStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise ResultValidationError("site_refresh.status_invalid") from exc
        object.__setattr__(self, "status", status)
        if type(self.refresh_complete) is not bool:
            raise ResultValidationError("site_refresh.invalid")
        if (
            type(self.previous_state) is not SiteState
            or type(self.current_state) is not SiteState
        ):
            raise ResultValidationError("site_refresh.state_invalid")
        if type(self.site_skill_used) is not SiteSkillEvidence:
            raise ResultValidationError("site_refresh.skill_invalid")
        if (
            self.site_skill_update is not None
            and type(self.site_skill_update) is not SiteSkillUpdate
        ):
            raise ResultValidationError("site_refresh.skill_update_invalid")
        validate_attempts(self.attempts)
        if type(self.usage) is not Usage:
            raise ResultValidationError("usage.invalid")
        self.usage.validate_attempts(self.attempts)
        if self.stop_reason not in _STOP_REASONS:
            raise ResultValidationError("site_refresh.stop_reason_invalid")
        if type(self.errors) is not tuple or not all(
            type(error) is SafeError for error in self.errors
        ):
            raise ResultValidationError("site_refresh.errors_invalid")
        self._validate_target_results()
        self._validate_collections()
        self._validate_state_and_skill()
        self._validate_evidence()
        self._validate_completion()

    def _validate_target_results(self) -> None:
        if type(self.target_results) is not tuple or not all(
            type(item) is Result for item in self.target_results
        ):
            raise ResultValidationError("site_refresh.target_results_invalid")
        if not self.target_results:
            raise ResultValidationError("site_refresh.target_results_mismatch")
        run_ids = tuple(item.manifest.run_id for item in self.target_results)
        if len(run_ids) != len(set(run_ids)) or not run_ids[0].endswith("-source"):
            raise ResultValidationError("site_refresh.target_results_duplicate")
        if any(
            result.attempts and result.attempts[0].attempt_id != result.manifest.run_id
            for result in self.target_results
        ):
            raise ResultValidationError("site_refresh.target_results_mismatch")
        prefix = run_ids[0][:-7]
        remaining = self.target_results[1:]
        if remaining and remaining[0].manifest.run_id == f"{prefix}-recovery-seed":
            recovery = remaining[1:]
            self._validate_candidate_order(recovery, f"{prefix}-recovery")
            if any(item.site_skill_used is not None for item in remaining):
                raise ResultValidationError("site_refresh.target_results_mismatch")
        else:
            self._validate_candidate_order(remaining, prefix)
            if any(item.site_skill_used != self.site_skill_used for item in remaining):
                raise ResultValidationError("site_refresh.target_results_mismatch")
        if self.target_results[0].site_skill_used != self.site_skill_used:
            raise ResultValidationError("site_refresh.target_results_mismatch")

    @staticmethod
    def _validate_candidate_order(results: tuple[Result, ...], prefix: str) -> None:
        numbers: list[int] = []
        for result in results:
            match = re.fullmatch(
                rf"{re.escape(prefix)}-candidate-([1-9]\d*)",
                result.manifest.run_id,
            )
            if match is None:
                raise ResultValidationError("site_refresh.target_results_mismatch")
            numbers.append(int(match.group(1)))
        urls = tuple(item.manifest.requested_url for item in results)
        if numbers != sorted(set(numbers)) or urls != tuple(sorted(set(urls))):
            raise ResultValidationError("site_refresh.target_results_order_invalid")

    def _collections(self) -> tuple[tuple[str, tuple[SiteChange, ...]], ...]:
        return (
            ("added", self.added),
            ("changed", self.changed),
            ("unchanged", self.unchanged),
            ("missing", self.missing),
            ("failed", self.failed),
            ("unresolved", self.unresolved),
        )

    def _validate_collections(self) -> None:
        seen: set[str] = set()
        for expected_type, changes in self._collections():
            if type(changes) is not tuple or not all(
                type(change) is SiteChange for change in changes
            ):
                raise ResultValidationError("site_refresh.change_invalid")
            urls = tuple(change.url for change in changes)
            if urls != tuple(sorted(urls)):
                raise ResultValidationError("site_refresh.change_order_invalid")
            if any(change.change_type != expected_type for change in changes):
                raise ResultValidationError("site_refresh.change_type_invalid")
            if len(urls) != len(set(urls)) or seen.intersection(urls):
                raise ResultValidationError("site_refresh.change_overlap")
            seen.update(urls)

    def _validate_state_and_skill(self) -> None:
        if self.previous_state.site_key != self.current_state.site_key:
            raise ResultValidationError("site_refresh.state_mismatch")
        active_digest = f"sha256:{self.site_skill_used.sha256}"
        if self.previous_state.site_skill_digest != active_digest:
            raise ResultValidationError("site_refresh.state_mismatch")
        allowed_current_digests = {active_digest}
        update = self.site_skill_update
        if update is not None:
            if update.previous != self.site_skill_used:
                raise ResultValidationError("site_refresh.skill_update_invalid")
            candidate_mapping = update.candidate.to_dict()
            if candidate_mapping.get("site_key") != self.current_state.site_key:
                raise ResultValidationError("site_refresh.skill_update_invalid")
            allowed_current_digests.add(update.candidate.digest)
        if not self.refresh_complete and update is None:
            allowed_current_digests.add(None)
        if self.current_state.site_skill_digest not in allowed_current_digests:
            raise ResultValidationError("site_refresh.state_mismatch")

    def _validate_evidence(  # pylint: disable=too-many-locals,too-many-branches
        self,
    ) -> None:
        previous = {page.canonical_url: page for page in self.previous_state.pages}
        current = {page.canonical_url: page for page in self.current_state.pages}
        if {page.observation_id for page in self.previous_state.pages}.intersection(
            page.observation_id for page in self.current_state.pages
        ):
            raise ResultValidationError("site_refresh.observation_reused")
        current_types = self.added + self.changed + self.unchanged
        previous_types = (
            self.changed
            + self.unchanged
            + self.missing
            + tuple(change for change in self.failed if change.previous is not None)
            + self.unresolved
        )
        if {change.url for change in current_types} != set(current):
            raise ResultValidationError("site_refresh.evidence_mismatch")
        if {change.url for change in previous_types} != set(previous):
            raise ResultValidationError("site_refresh.evidence_mismatch")
        for change in tuple(item for _, items in self._collections() for item in items):
            if change.previous is not None:
                page = previous.get(change.url)
                if page is None or change.previous != _page_evidence(page):
                    raise ResultValidationError("site_refresh.evidence_mismatch")
            if change.current is not None:
                page = current.get(change.url)
                if page is None or change.current != _page_evidence(page):
                    raise ResultValidationError("site_refresh.evidence_mismatch")
        successful_urls = {
            attempt.final_url
            for attempt in self.attempts
            if attempt.outcome == "succeeded" and attempt.final_url is not None
        }
        if not set(current).issubset(successful_urls):
            raise ResultValidationError("site_refresh.current_state_evidence")
        attempts_by_id = {attempt.attempt_id: attempt for attempt in self.attempts}
        result_error_codes = {error.code for error in self.errors}
        for change in self.failed:
            referenced = tuple(attempts_by_id.get(item) for item in change.attempt_ids)
            if any(
                attempt is None
                or attempt.outcome != "failed"
                or attempt.requested_url != change.url
                or attempt.error is None
                for attempt in referenced
            ):
                raise ResultValidationError("site_refresh.failed_evidence")
            observed_codes = tuple(
                sorted({attempt.error.code for attempt in referenced if attempt})
            )
            if observed_codes != change.error_codes or not set(
                change.error_codes
            ).issubset(result_error_codes):
                raise ResultValidationError("site_refresh.failed_evidence")
        audited_count, discovery_attempts = _validate_target_attempts(
            self.target_results, self.attempts
        )
        _validate_target_errors(self.target_results, discovery_attempts, self.errors)
        expected_usage = Usage(
            sum(result.usage.requests for result in self.target_results)
            + sum(attempt.requests for attempt in discovery_attempts),
            sum(result.usage.bytes_received for result in self.target_results)
            + sum(attempt.bytes_received for attempt in discovery_attempts),
            sum(result.usage.runtime_ms for result in self.target_results)
            + sum(attempt.runtime_ms for attempt in discovery_attempts),
            sum(result.usage.tool_attempts for result in self.target_results)
            - audited_count
            + sum(attempt.outcome != "skipped" for attempt in discovery_attempts),
        )
        if self.usage != expected_usage:
            raise ResultValidationError("site_refresh.target_results_mismatch")
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
            for page in self.current_state.pages
        ):
            raise ResultValidationError("site_refresh.target_results_mismatch")

    def _validate_completion(self) -> None:
        if self.current_state.complete != self.refresh_complete:
            raise ResultValidationError("site_refresh.state_mismatch")
        if self.refresh_complete:
            if self.status is not ResultStatus.COMPLETED:
                raise ResultValidationError("site_refresh.status_invalid")
            if self.stop_reason != "source_exhausted":
                raise ResultValidationError("site_refresh.stop_reason_invalid")
            if self.unresolved:
                raise ResultValidationError("site_refresh.unresolved_forbidden")
        else:
            if self.status is ResultStatus.COMPLETED:
                raise ResultValidationError("site_refresh.status_invalid")
            if self.stop_reason == "source_exhausted":
                raise ResultValidationError("site_refresh.stop_reason_invalid")
            if self.missing:
                raise ResultValidationError("site_refresh.missing_forbidden")

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        site_skill_update: SiteSkillUpdate | None = None,
    ) -> SiteRefreshResult:
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {
                "schema_version",
                "status",
                "refresh_complete",
                "added",
                "changed",
                "unchanged",
                "missing",
                "failed",
                "unresolved",
                "previous_state",
                "current_state",
                "site_skill_used",
                "site_skill_update",
                "target_results",
                "attempts",
                "usage",
                "stop_reason",
                "errors",
            },
        )
        collection_names = (
            "added",
            "changed",
            "unchanged",
            "missing",
            "failed",
            "unresolved",
            "target_results",
            "attempts",
            "errors",
        )
        if any(not isinstance(payload[name], list) for name in collection_names):
            raise ResultValidationError("site_refresh.invalid")
        try:
            previous_state = SiteState.from_dict(payload["previous_state"])
            current_state = SiteState.from_dict(payload["current_state"])
        except ArtifactStoreError as exc:
            raise ResultValidationError("site_refresh.state_invalid") from exc
        update_payload = payload["site_skill_update"]
        if update_payload is None:
            if site_skill_update is not None:
                raise ResultValidationError("site_refresh.skill_update_invalid")
            update = None
        else:
            if (
                site_skill_update is None
                or site_skill_update.to_dict() != update_payload
            ):
                raise ResultValidationError("site_refresh.skill_update_invalid")
            update = site_skill_update
        return cls(
            schema_version=payload["schema_version"],
            status=payload["status"],
            refresh_complete=payload["refresh_complete"],
            added=tuple(SiteChange.from_dict(item) for item in payload["added"]),
            changed=tuple(SiteChange.from_dict(item) for item in payload["changed"]),
            unchanged=tuple(
                SiteChange.from_dict(item) for item in payload["unchanged"]
            ),
            missing=tuple(SiteChange.from_dict(item) for item in payload["missing"]),
            failed=tuple(SiteChange.from_dict(item) for item in payload["failed"]),
            unresolved=tuple(
                SiteChange.from_dict(item) for item in payload["unresolved"]
            ),
            previous_state=previous_state,
            current_state=current_state,
            site_skill_used=SiteSkillEvidence.from_dict(payload["site_skill_used"]),
            site_skill_update=update,
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
            "refresh_complete": self.refresh_complete,
            "added": [item.to_dict() for item in self.added],
            "changed": [item.to_dict() for item in self.changed],
            "unchanged": [item.to_dict() for item in self.unchanged],
            "missing": [item.to_dict() for item in self.missing],
            "failed": [item.to_dict() for item in self.failed],
            "unresolved": [item.to_dict() for item in self.unresolved],
            "previous_state": self.previous_state.to_dict(),
            "current_state": self.current_state.to_dict(),
            "site_skill_used": self.site_skill_used.to_dict(),
            "site_skill_update": (
                None
                if self.site_skill_update is None
                else self.site_skill_update.to_dict()
            ),
            "target_results": [item.to_dict() for item in self.target_results],
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "usage": self.usage.to_dict(),
            "stop_reason": self.stop_reason,
            "errors": [error.to_dict() for error in self.errors],
        }

    def canonical_json_bytes(self) -> bytes:
        payload = self.to_dict()
        safe_payload = dict(payload)
        if self.site_skill_update is not None:
            safe_update = dict(self.site_skill_update.to_dict())
            safe_update["candidate"] = None
            safe_payload["site_skill_update"] = safe_update
        ensure_safe_payload(safe_payload)
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")


def _page_evidence(page: SiteStatePage) -> ChangeEvidence:
    return ChangeEvidence(page.artifact_id, page.content_digest)


def _validate_target_attempts(
    target_results: tuple[Result, ...], attempts: tuple[Attempt, ...]
) -> tuple[int, tuple[Attempt, ...]]:
    child_attempts = tuple(
        attempt for result in target_results for attempt in result.attempts
    )
    child_ids = tuple(attempt.attempt_id for attempt in child_attempts)
    if len(child_ids) != len(set(child_ids)):
        raise ResultValidationError("site_refresh.target_results_mismatch")
    child_by_id = {attempt.attempt_id: attempt for attempt in child_attempts}
    aggregate_acquisition = tuple(
        attempt for attempt in attempts if attempt.attempt_id in child_by_id
    )
    discovery_attempts = tuple(
        attempt for attempt in attempts if attempt.attempt_id not in child_by_id
    )
    if tuple(item.attempt_id for item in aggregate_acquisition) != child_ids or any(
        "-discovery" not in attempt.attempt_id
        or attempt.final_url is not None
        or attempt.http_status is not None
        or attempt.requests != 0
        or attempt.bytes_received != 0
        for attempt in discovery_attempts
    ):
        raise ResultValidationError("site_refresh.target_results_mismatch")
    audited_count = 0
    for child, aggregate in zip(child_attempts, aggregate_acquisition):
        child_payload = child.to_dict()
        aggregate_payload = aggregate.to_dict()
        child_payload.pop("order")
        aggregate_payload.pop("order")
        if child_payload == aggregate_payload:
            continue
        child_error = child.error
        audited = dict(child_payload)
        if (
            child_error is not None
            and child_error.code == "eligibility.attempt_budget_exhausted"
        ):
            audited_count += 1
            audited.update(
                {
                    "outcome": "skipped",
                    "final_url": None,
                    "http_status": None,
                    "requests": 0,
                    "bytes_received": 0,
                    "runtime_ms": 0,
                }
            )
        if audited != aggregate_payload:
            raise ResultValidationError("site_refresh.target_results_mismatch")
    return audited_count, discovery_attempts


def _validate_target_errors(
    target_results: tuple[Result, ...],
    discovery_attempts: tuple[Attempt, ...],
    errors: tuple[SafeError, ...],
) -> None:
    candidate_results = target_results[1:]
    if candidate_results and candidate_results[0].manifest.run_id.endswith(
        "-recovery-seed"
    ):
        candidate_results = candidate_results[1:]
    if any(
        not result.attempts
        and any(error.code in _PARENT_ONLY_ERROR_CODES for error in result.errors)
        for result in candidate_results
    ):
        raise ResultValidationError("site_refresh.target_results_mismatch")
    remaining = list(errors)
    attributed = tuple(
        error for result in target_results for error in result.errors
    ) + tuple(
        attempt.error for attempt in discovery_attempts if attempt.error is not None
    )
    for error in attributed:
        try:
            remaining.remove(error)
        except ValueError as exc:
            raise ResultValidationError("site_refresh.target_results_mismatch") from exc

    attributed_codes = {error.code for error in attributed}
    failed_attempt_errors: dict[str, SafeError] = {}
    for result in target_results:
        for attempt in result.attempts:
            if attempt.error is not None and attempt.error.code not in attributed_codes:
                failed_attempt_errors.setdefault(attempt.error.code, attempt.error)
    for error in remaining:
        if error.code in _PARENT_ONLY_ERROR_CODES:
            continue
        if failed_attempt_errors.pop(error.code, None) == error:
            continue
        raise ResultValidationError("site_refresh.target_results_mismatch")


__all__ = [
    "SITE_REFRESH_SCHEMA_VERSION",
    "ChangeEvidence",
    "SiteChange",
    "SiteRefreshResult",
    "SiteSkillUpdate",
]
