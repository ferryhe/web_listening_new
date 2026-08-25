"""The pure, immutable Result boundary shared by every interface."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from web_listening.result.attempts import Attempt, validate_attempts
from web_listening.result.errors import (
    ResultValidationError,
    SafeError,
    canonical_json_bytes,
    require_exact_fields,
    require_mapping,
)
from web_listening.result.manifest import (
    ArtifactEvidence,
    Manifest,
    SiteSkillEvidence,
    Usage,
)

RESULT_SCHEMA_VERSION = "web-listening-result.v1"


class ResultStatus(str, Enum):
    """The four stable Result outcomes."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Result:  # pylint: disable=too-many-instance-attributes
    """One immutable Result assembled from already-existing facts."""

    status: ResultStatus
    manifest: Manifest
    site_skill_used: SiteSkillEvidence | None
    site_skill_update: SiteSkillEvidence | None
    attempts: tuple[Attempt, ...]
    errors: tuple[SafeError, ...]
    usage: Usage
    schema_version: str = RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RESULT_SCHEMA_VERSION:
            raise ResultValidationError("schema.version_invalid")
        try:
            normalized_status = ResultStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise ResultValidationError("result.status_invalid") from exc
        object.__setattr__(self, "status", normalized_status)
        if not isinstance(self.manifest, Manifest):
            raise ResultValidationError("result.manifest_invalid")
        if self.site_skill_used is not None and not isinstance(
            self.site_skill_used, SiteSkillEvidence
        ):
            raise ResultValidationError("result.site_skill_invalid")
        if self.site_skill_update is not None and not isinstance(
            self.site_skill_update, SiteSkillEvidence
        ):
            raise ResultValidationError("result.site_skill_invalid")
        if not isinstance(self.usage, Usage):
            raise ResultValidationError("usage.invalid")
        validate_attempts(self.attempts)
        self.usage.validate_attempts(self.attempts)
        if self.attempts != self.manifest.attempts:
            raise ResultValidationError("result.attempts_mismatch")
        if self.usage != self.manifest.usage:
            raise ResultValidationError("result.usage_mismatch")
        if self.site_skill_used != self.manifest.site_skill:
            raise ResultValidationError("result.site_skill_mismatch")
        if not isinstance(self.errors, tuple) or not all(
            isinstance(error, SafeError) for error in self.errors
        ):
            raise ResultValidationError("result.errors_invalid")
        self._validate_status()

    @property
    def artifacts(self) -> tuple[ArtifactEvidence, ...]:
        """Expose the Manifest's immutable Artifact evidence without a copy."""
        return self.manifest.artifacts

    def _validate_status(self) -> None:
        has_artifact = bool(self.artifacts)
        has_success = any(attempt.outcome == "succeeded" for attempt in self.attempts)
        has_failure = bool(self.errors) or any(
            attempt.outcome != "succeeded" for attempt in self.attempts
        )
        if self.status is ResultStatus.COMPLETED:
            if not has_artifact or not has_success:
                raise ResultValidationError("result.completed_requires_artifact")
            if has_failure:
                raise ResultValidationError("result.completed_has_failure")
        elif self.status is ResultStatus.PARTIAL:
            if not has_artifact or not has_success:
                raise ResultValidationError("result.partial_requires_artifact")
            if not has_failure:
                raise ResultValidationError("result.partial_requires_failure")
        elif self.status is ResultStatus.REJECTED:
            if has_artifact or has_success:
                raise ResultValidationError("result.rejected_has_artifact")
            if not self.errors:
                raise ResultValidationError("result.rejected_requires_error")
        else:
            if has_artifact or has_success:
                raise ResultValidationError("result.failed_has_artifact")
            if not self.errors:
                raise ResultValidationError("result.failed_requires_error")

    @classmethod
    def from_dict(cls, value: object) -> Result:
        """Parse a strict Result object without acquiring or mutating data."""
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {
                "schema_version",
                "status",
                "artifacts",
                "manifest",
                "site_skill_used",
                "site_skill_update",
                "attempts",
                "errors",
                "usage",
            },
        )
        for key in ("artifacts", "attempts", "errors"):
            if not isinstance(payload[key], list):
                raise ResultValidationError("schema.invalid")
        manifest = Manifest.from_dict(payload["manifest"])
        artifacts = tuple(
            ArtifactEvidence.from_dict(item) for item in payload["artifacts"]
        )
        if artifacts != manifest.artifacts:
            raise ResultValidationError("result.artifacts_mismatch")
        site_skill_used = (
            None
            if payload["site_skill_used"] is None
            else SiteSkillEvidence.from_dict(payload["site_skill_used"])
        )
        site_skill_update = (
            None
            if payload["site_skill_update"] is None
            else SiteSkillEvidence.from_dict(payload["site_skill_update"])
        )
        return cls(
            schema_version=payload["schema_version"],
            status=payload["status"],
            manifest=manifest,
            site_skill_used=site_skill_used,
            site_skill_update=site_skill_update,
            attempts=tuple(Attempt.from_dict(item) for item in payload["attempts"]),
            errors=tuple(SafeError.from_dict(item) for item in payload["errors"]),
            usage=Usage.from_dict(payload["usage"]),
        )

    def to_dict(self) -> dict[str, object]:
        """Return the exact versioned Result payload."""
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "manifest": self.manifest.to_dict(),
            "site_skill_used": (
                None if self.site_skill_used is None else self.site_skill_used.to_dict()
            ),
            "site_skill_update": (
                None
                if self.site_skill_update is None
                else self.site_skill_update.to_dict()
            ),
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "errors": [error.to_dict() for error in self.errors],
            "usage": self.usage.to_dict(),
        }

    def canonical_json_bytes(self) -> bytes:
        """Return byte-stable canonical UTF-8 JSON."""
        return canonical_json_bytes(self.to_dict())


__all__ = ["Result", "ResultStatus", "Usage"]
