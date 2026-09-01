"""Strict factual Result contract for one serial multi-site batch."""

# pylint: disable=duplicate-code,too-many-branches,unidiomatic-typecheck

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import TypeAlias

from web_listening.result.errors import (
    ResultValidationError,
    SafeError,
    require_exact_fields,
    require_mapping,
    validate_text,
)
from web_listening.result.manifest import Usage
from web_listening.result.model import ResultStatus
from web_listening.result.site_explore import (
    SiteExploreResult,
    SiteSkillCandidateEvidence,
)
from web_listening.result.site_refresh import SiteRefreshResult, SiteSkillUpdate

SITE_BATCH_RESULT_SCHEMA_VERSION = "web-listening-site-batch-result.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HTTP_URL_HOST = re.compile(
    r"https?://(?P<host>[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)"
    r"(?::[1-9][0-9]{0,4})?(?:/|\Z)"
)
_DIRECT_CHILD_RUN_ID_MAXIMUM = 96
_PHASES = frozenset({"first", "refresh"})
_STOP_REASONS = frozenset(
    {"source_exhausted", "partial", "rejected", "cancelled", "failed"}
)
SiteResult: TypeAlias = SiteExploreResult | SiteRefreshResult


class SiteBatchMode(str, Enum):
    """How a site produced its current-run availability evidence."""

    REPLAYED = "replayed"
    RECOVERED = "recovered"
    FAILED = "failed"


def validate_site_batch_run_id(value: object) -> str:
    """Return one parent identity before any child work is attempted."""
    return validate_text(value, code="site_batch.run_id_invalid", maximum=128)


def site_batch_child_run_id(parent_run_id: str, site_index: int) -> str:
    """Derive one bounded child identity that Result can recompute exactly."""
    parent_run_id = validate_site_batch_run_id(parent_run_id)
    if (
        isinstance(site_index, bool)
        or not isinstance(site_index, int)
        or site_index < 1
    ):
        raise ResultValidationError("site_batch.run_identity_mismatch")
    direct = f"{parent_run_id}-site-{site_index}"
    if len(direct) <= _DIRECT_CHILD_RUN_ID_MAXIMUM:
        return direct
    identity = f"{len(parent_run_id)}:{parent_run_id}:{site_index}".encode("utf-8")
    return f"batch-{hashlib.sha256(identity).hexdigest()}"


@dataclass(frozen=True, slots=True)
class SiteBatchResult:  # pylint: disable=too-many-instance-attributes
    """One immutable aggregate of existing per-site facts and continuations."""

    phase: str
    run_id: str
    request_sha256: str
    site_keys: tuple[str, ...]
    site_results: tuple[SiteResult, ...]
    site_modes: tuple[SiteBatchMode | str, ...]
    usable_site_keys: tuple[str, ...]
    next_refresh_contexts: tuple[object, ...]
    status: ResultStatus | str
    stop_reason: str
    usage: Usage
    errors: tuple[SafeError, ...]
    schema_version: str = SITE_BATCH_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SITE_BATCH_RESULT_SCHEMA_VERSION:
            raise ResultValidationError("schema.version_invalid")
        if not isinstance(self.phase, str) or self.phase not in _PHASES:
            raise ResultValidationError("site_batch.phase_invalid")
        phase = next(item for item in _PHASES if self.phase == item)
        try:
            status = ResultStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise ResultValidationError("site_batch.status_invalid") from exc
        validate_site_batch_run_id(self.run_id)
        if (
            type(self.request_sha256) is not str
            or _SHA256.fullmatch(self.request_sha256) is None
        ):
            raise ResultValidationError("site_batch.request_sha256_invalid")
        self._validate_sites(phase)
        modes = self._validate_modes(phase)
        self._validate_continuations(phase, modes)
        if not isinstance(self.usage, Usage) or self.usage != _usage(self.site_results):
            raise ResultValidationError("site_batch.usage_mismatch")
        if self.stop_reason not in _STOP_REASONS:
            raise ResultValidationError("site_batch.stop_reason_invalid")
        if type(self.errors) is not tuple or not all(
            isinstance(error, SafeError) for error in self.errors
        ):
            raise ResultValidationError("site_batch.errors_invalid")
        expected_errors = tuple(
            error for result in self.site_results for error in result.errors
        )
        if self.errors != expected_errors:
            raise ResultValidationError("site_batch.errors_mismatch")
        expected_status, expected_stop = _completion(self.site_keys, self.site_results)
        if status is not expected_status or self.stop_reason != expected_stop:
            raise ResultValidationError("site_batch.status_invalid")
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "site_modes", modes)
        object.__setattr__(self, "status", status)

    def _validate_sites(self, phase: str) -> None:
        if (
            type(self.site_keys) is not tuple
            or len(self.site_keys) < 2
            or any(type(item) is not str for item in self.site_keys)
            or len(self.site_keys) != len(set(self.site_keys))
        ):
            raise ResultValidationError("site_batch.site_order_invalid")
        for site_key in self.site_keys:
            validate_text(site_key, code="site_batch.site_order_invalid", maximum=253)
        expected_type = SiteExploreResult if phase == "first" else SiteRefreshResult
        if (
            type(self.site_results) is not tuple
            or not self.site_results
            or not all(type(item) is expected_type for item in self.site_results)
            or len(self.site_results) > len(self.site_keys)
        ):
            raise ResultValidationError("site_batch.site_results_invalid")
        observed_keys = tuple(_requested_site_key(item) for item in self.site_results)
        if observed_keys != self.site_keys[: len(observed_keys)]:
            raise ResultValidationError("site_batch.site_order_invalid")
        for index, result in enumerate(self.site_results, start=1):
            expected_root = site_batch_child_run_id(self.run_id, index)
            expected_prefix = f"{expected_root}-"
            if result.target_results:
                suffix = "seed" if phase == "first" else "source"
                if (
                    result.target_results[0].manifest.run_id
                    != f"{expected_root}-{suffix}"
                ):
                    raise ResultValidationError("site_batch.run_identity_mismatch")
            identities = tuple(
                item.manifest.run_id for item in result.target_results
            ) + tuple(item.attempt_id for item in result.attempts)
            if any(not identity.startswith(expected_prefix) for identity in identities):
                raise ResultValidationError("site_batch.run_identity_mismatch")

    def _validate_modes(self, phase: str) -> tuple[SiteBatchMode, ...]:
        if type(self.site_modes) is not tuple or len(self.site_modes) != len(
            self.site_results
        ):
            raise ResultValidationError("site_batch.mode_invalid")
        try:
            modes = tuple(SiteBatchMode(mode) for mode in self.site_modes)
        except (TypeError, ValueError) as exc:
            raise ResultValidationError("site_batch.mode_invalid") from exc
        expected = tuple(
            _mode_for_result(
                phase,
                result,
                site_batch_child_run_id(self.run_id, index),
            )
            for index, result in enumerate(self.site_results, start=1)
        )
        if modes != expected:
            raise ResultValidationError("site_batch.mode_mismatch")
        return modes

    def _validate_continuations(
        self, phase: str, modes: tuple[SiteBatchMode, ...]
    ) -> None:
        derived_usable = tuple(
            self.site_keys[index]
            for index, result in enumerate(self.site_results)
            if _state(result).pages
        )
        if self.usable_site_keys != derived_usable:
            raise ResultValidationError("site_batch.usable_sites_mismatch")
        if type(self.next_refresh_contexts) is not tuple:
            raise ResultValidationError("site_batch.next_context_invalid")
        context_keys = tuple(
            _context_site_key(context) for context in self.next_refresh_contexts
        )
        expected_context_keys: list[str] = []
        for index, (result, mode) in enumerate(
            zip(self.site_results, modes, strict=True)
        ):
            if _continuation_expected(phase, result, mode):
                expected_context_keys.append(self.site_keys[index])
        if context_keys != tuple(expected_context_keys):
            raise ResultValidationError("site_batch.next_context_mismatch")
        context_by_key = {
            _context_site_key(context): context
            for context in self.next_refresh_contexts
        }
        for index, (result, mode) in enumerate(
            zip(self.site_results, modes, strict=True)
        ):
            context = context_by_key.get(self.site_keys[index])
            if context is not None:
                _validate_context(phase, result, mode, context)

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        site_skill_evidence: (
            tuple[SiteSkillCandidateEvidence | SiteSkillUpdate | None, ...] | None
        ) = None,
        next_refresh_contexts: tuple[object, ...] | None = None,
    ) -> SiteBatchResult:
        """Parse one exact versioned batch Result without performing I/O."""
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {
                "schema_version",
                "phase",
                "run_id",
                "request_sha256",
                "site_keys",
                "site_results",
                "site_modes",
                "usable_site_keys",
                "next_refresh_contexts",
                "status",
                "stop_reason",
                "usage",
                "errors",
            },
        )
        for field in (
            "site_keys",
            "site_results",
            "site_modes",
            "usable_site_keys",
            "next_refresh_contexts",
            "errors",
        ):
            if not isinstance(payload[field], list):
                raise ResultValidationError("schema.invalid")
        phase = payload["phase"]
        if not isinstance(phase, str) or phase not in _PHASES:
            raise ResultValidationError("site_batch.phase_invalid")
        result_payloads = payload["site_results"]
        if site_skill_evidence is None:
            site_skill_evidence = (None,) * len(result_payloads)
        if type(site_skill_evidence) is not tuple or len(site_skill_evidence) != len(
            result_payloads
        ):
            raise ResultValidationError("site_batch.site_results_invalid")
        parser = _parse_explore if phase == "first" else _parse_refresh
        if next_refresh_contexts is None:
            if payload["next_refresh_contexts"]:
                raise ResultValidationError("site_batch.next_context_invalid")
            contexts: tuple[object, ...] = ()
        else:
            if type(next_refresh_contexts) is not tuple or tuple(
                _context_mapping(item) for item in next_refresh_contexts
            ) != tuple(payload["next_refresh_contexts"]):
                raise ResultValidationError("site_batch.next_context_invalid")
            contexts = next_refresh_contexts
        return cls(
            phase,
            payload["run_id"],
            payload["request_sha256"],
            tuple(payload["site_keys"]),
            tuple(
                parser(item, evidence)
                for item, evidence in zip(
                    result_payloads,
                    site_skill_evidence,
                    strict=True,
                )
            ),
            tuple(payload["site_modes"]),
            tuple(payload["usable_site_keys"]),
            contexts,
            payload["status"],
            payload["stop_reason"],
            Usage.from_dict(payload["usage"]),
            tuple(SafeError.from_dict(item) for item in payload["errors"]),
            payload["schema_version"],
        )

    def to_dict(self) -> dict[str, object]:
        """Return the exact JSON-compatible factual batch payload."""
        return {
            "schema_version": self.schema_version,
            "phase": self.phase,
            "run_id": self.run_id,
            "request_sha256": self.request_sha256,
            "site_keys": list(self.site_keys),
            "site_results": [item.to_dict() for item in self.site_results],
            "site_modes": [item.value for item in self.site_modes],
            "usable_site_keys": list(self.usable_site_keys),
            "next_refresh_contexts": [
                _context_mapping(item) for item in self.next_refresh_contexts
            ],
            "status": self.status.value,
            "stop_reason": self.stop_reason,
            "usage": self.usage.to_dict(),
            "errors": [item.to_dict() for item in self.errors],
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


def _state(result: SiteResult):
    if isinstance(result, SiteExploreResult):
        return result.site_state
    return result.current_state


def _requested_site_key(result: SiteResult) -> str:
    if not result.target_results:
        return _state(result).site_key
    matched = _HTTP_URL_HOST.match(result.target_results[0].manifest.requested_url)
    if matched is None:
        raise ResultValidationError("site_batch.site_order_invalid")
    return matched.group("host")


def _usage(results: tuple[SiteResult, ...]) -> Usage:
    return Usage(
        sum(item.usage.requests for item in results),
        sum(item.usage.bytes_received for item in results),
        sum(item.usage.runtime_ms for item in results),
        sum(item.usage.tool_attempts for item in results),
    )


def _cancelled(result: SiteResult) -> bool:
    return result.stop_reason == "cancelled" or any(
        error.code == "runtime.cancelled" for error in result.errors
    )


def _completion(
    site_keys: tuple[str, ...], results: tuple[SiteResult, ...]
) -> tuple[ResultStatus, str]:
    cancelled = tuple(
        index for index, result in enumerate(results) if _cancelled(result)
    )
    if cancelled:
        if cancelled != (len(results) - 1,):
            raise ResultValidationError("site_batch.cancellation_order_invalid")
        return ResultStatus.PARTIAL, "cancelled"
    if len(results) != len(site_keys):
        raise ResultValidationError("site_batch.site_results_missing")
    statuses = {result.status for result in results}
    if statuses == {ResultStatus.COMPLETED}:
        return ResultStatus.COMPLETED, "source_exhausted"
    if statuses == {ResultStatus.REJECTED}:
        return ResultStatus.REJECTED, "rejected"
    if statuses == {ResultStatus.FAILED}:
        return ResultStatus.FAILED, "failed"
    return ResultStatus.PARTIAL, "partial"


def _mode_for_result(
    phase: str, result: SiteResult, child_run_id: str
) -> SiteBatchMode:
    if not _state(result).pages:
        return SiteBatchMode.FAILED
    if phase == "first":
        return SiteBatchMode.RECOVERED
    if isinstance(result, SiteRefreshResult) and result.site_skill_update is not None:
        return SiteBatchMode.RECOVERED
    recovery_prefix = f"{child_run_id}-recovery-"
    identities = tuple(item.manifest.run_id for item in result.target_results) + tuple(
        item.attempt_id for item in result.attempts
    )
    if any(identity.startswith(recovery_prefix) for identity in identities):
        return SiteBatchMode.RECOVERED
    return SiteBatchMode.REPLAYED


def _continuation_expected(phase: str, result: SiteResult, mode: SiteBatchMode) -> bool:
    if not _state(result).pages or result.stop_reason in {"rejected", "cancelled"}:
        return False
    if phase == "first":
        assert isinstance(result, SiteExploreResult)
        return result.site_skill_candidate is not None
    assert isinstance(result, SiteRefreshResult)
    return result.site_skill_update is not None or mode is SiteBatchMode.REPLAYED


def _validate_context(
    phase: str,
    result: SiteResult,
    mode: SiteBatchMode,
    context: object,
) -> None:
    state = _state(result)
    actual_state = getattr(context, "previous_state", None)
    if actual_state is None:
        raise ResultValidationError("site_batch.next_context_invalid")
    if (
        actual_state.site_key != state.site_key
        or actual_state.generated_at != state.generated_at
        or actual_state.complete != state.complete
        or actual_state.pages != state.pages
    ):
        raise ResultValidationError("site_batch.next_context_mismatch")
    skill = getattr(context, "site_skill", None)
    skill_mapping = _context_mapping(context)["site_skill"]
    if phase == "first":
        assert isinstance(result, SiteExploreResult)
        candidate = result.site_skill_candidate
        if candidate is None or skill_mapping != candidate.to_dict():
            raise ResultValidationError("site_batch.next_context_mismatch")
        return
    assert isinstance(result, SiteRefreshResult)
    update = result.site_skill_update
    if update is not None:
        if skill_mapping != update.candidate.to_dict():
            raise ResultValidationError("site_batch.next_context_mismatch")
        return
    if mode is not SiteBatchMode.REPLAYED or (
        getattr(skill, "version", None) != int(result.site_skill_used.version)
        or getattr(skill, "digest", "").removeprefix("sha256:")
        != result.site_skill_used.sha256
    ):
        raise ResultValidationError("site_batch.next_context_mismatch")


def _context_mapping(context: object) -> dict[str, object]:
    to_dict = getattr(context, "to_dict", None)
    if not callable(to_dict):
        raise ResultValidationError("site_batch.next_context_invalid")
    value = to_dict()
    if not isinstance(value, dict) or set(value) != {"site_skill", "previous_state"}:
        raise ResultValidationError("site_batch.next_context_invalid")
    return value


def _context_site_key(context: object) -> str:
    skill = getattr(context, "site_skill", None)
    site_key = getattr(skill, "site_key", None)
    if not isinstance(site_key, str):
        raise ResultValidationError("site_batch.next_context_invalid")
    return site_key


def _parse_explore(
    value: object,
    evidence: SiteSkillCandidateEvidence | SiteSkillUpdate | None,
) -> SiteExploreResult:
    if evidence is not None and not isinstance(evidence, SiteSkillCandidateEvidence):
        raise ResultValidationError("site_batch.site_results_invalid")
    return SiteExploreResult.from_dict(value, site_skill_candidate=evidence)


def _parse_refresh(
    value: object,
    evidence: SiteSkillCandidateEvidence | SiteSkillUpdate | None,
) -> SiteRefreshResult:
    if evidence is not None and not isinstance(evidence, SiteSkillUpdate):
        raise ResultValidationError("site_batch.site_results_invalid")
    return SiteRefreshResult.from_dict(value, site_skill_update=evidence)


__all__ = [
    "SITE_BATCH_RESULT_SCHEMA_VERSION",
    "SiteBatchMode",
    "SiteBatchResult",
    "site_batch_child_run_id",
    "validate_site_batch_run_id",
]
