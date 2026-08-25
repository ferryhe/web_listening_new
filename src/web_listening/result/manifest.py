"""Pure, byte-stable acquisition Manifest construction."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from web_listening.artifact.identity import artifact_id, validate_mime_type
from web_listening.artifact.lineage import validate_lineage
from web_listening.artifact.model import (
    ArtifactRole,
    ArtifactStoreError,
    Lineage,
    StoredObservation,
)
from web_listening.artifact.observation import validate_observation_id
from web_listening.result.attempts import Attempt, validate_attempts
from web_listening.result.errors import (
    ResultValidationError,
    canonical_json_bytes,
    require_exact_fields,
    require_mapping,
    validate_nonnegative_int,
    validate_sha256,
    validate_text,
    validate_url,
    validate_utc_time,
)

MANIFEST_SCHEMA_VERSION = "web-listening-manifest.v1"


@dataclass(frozen=True, slots=True)
class Usage:
    """Actual request, byte, runtime, and attempted-tool consumption."""

    requests: int
    bytes_received: int
    runtime_ms: int
    tool_attempts: int

    def __post_init__(self) -> None:
        for value in (
            self.requests,
            self.bytes_received,
            self.runtime_ms,
            self.tool_attempts,
        ):
            validate_nonnegative_int(value, code="usage.invalid")

    @classmethod
    def from_dict(cls, value: object) -> Usage:
        """Parse one strict Usage object."""
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {"requests", "bytes_received", "runtime_ms", "tool_attempts"},
        )
        return cls(
            requests=payload["requests"],
            bytes_received=payload["bytes_received"],
            runtime_ms=payload["runtime_ms"],
            tool_attempts=payload["tool_attempts"],
        )

    def to_dict(self) -> dict[str, int]:
        """Return plain JSON usage evidence."""
        return {
            "requests": self.requests,
            "bytes_received": self.bytes_received,
            "runtime_ms": self.runtime_ms,
            "tool_attempts": self.tool_attempts,
        }

    def validate_attempts(self, attempts: tuple[Attempt, ...]) -> None:
        """Reject totals that contradict explicit per-attempt facts."""
        if self.requests != sum(attempt.requests for attempt in attempts):
            raise ResultValidationError("usage.requests_mismatch")
        if self.bytes_received != sum(attempt.bytes_received for attempt in attempts):
            raise ResultValidationError("usage.bytes_mismatch")
        if self.tool_attempts != sum(
            attempt.outcome != "skipped" for attempt in attempts
        ):
            raise ResultValidationError("usage.tool_attempts_mismatch")
        if self.runtime_ms < sum(attempt.runtime_ms for attempt in attempts):
            raise ResultValidationError("usage.runtime_mismatch")


@dataclass(frozen=True, slots=True)
class RedirectEvidence:
    """One sanitized redirect transition already decided by acquisition."""

    order: int
    from_url: str
    to_url: str
    http_status: int
    decision: str

    def __post_init__(self) -> None:
        validate_nonnegative_int(self.order, code="redirect.order_invalid")
        validate_url(self.from_url)
        validate_url(self.to_url)
        if (
            isinstance(self.http_status, bool)
            or not isinstance(self.http_status, int)
            or not 300 <= self.http_status <= 399
        ):
            raise ResultValidationError("redirect.status_invalid")
        if not isinstance(self.decision, str) or self.decision not in {
            "followed",
            "rejected",
        }:
            raise ResultValidationError("redirect.decision_invalid")

    @classmethod
    def from_dict(cls, value: object) -> RedirectEvidence:
        """Parse one strict redirect transition."""
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {"order", "from_url", "to_url", "http_status", "decision"},
        )
        return cls(**payload)

    def to_dict(self) -> dict[str, object]:
        """Return plain JSON redirect evidence."""
        return {
            "order": self.order,
            "from_url": self.from_url,
            "to_url": self.to_url,
            "http_status": self.http_status,
            "decision": self.decision,
        }


@dataclass(frozen=True, slots=True)
class SiteSkillEvidence:
    """Version and digest evidence only; never Site Skill authority."""

    version: str
    sha256: str

    def __post_init__(self) -> None:
        validate_text(self.version, code="site_skill.version_invalid", maximum=128)
        validate_sha256(self.sha256, code="site_skill.sha256_invalid")

    @classmethod
    def from_dict(cls, value: object) -> SiteSkillEvidence:
        """Parse strict Site Skill version and digest evidence."""
        payload = require_mapping(value)
        require_exact_fields(payload, {"version", "sha256"})
        return cls(version=payload["version"], sha256=payload["sha256"])

    def to_dict(self) -> dict[str, str]:
        """Return plain JSON Site Skill evidence."""
        return {"version": self.version, "sha256": self.sha256}


def _lineage_from_dict(value: object) -> Lineage:
    payload = require_mapping(value)
    require_exact_fields(
        payload,
        {
            "lineage_id",
            "observation_id",
            "artifact_id",
            "relation",
            "source_observation_id",
            "source_artifact_id",
        },
    )
    try:
        return validate_lineage(Lineage(**payload))
    except (ArtifactStoreError, TypeError) as exc:
        raise ResultValidationError("lineage.invalid") from exc


def _lineage_to_dict(value: Lineage) -> dict[str, str]:
    return {
        "lineage_id": value.lineage_id,
        "observation_id": value.observation_id,
        "artifact_id": value.artifact_id,
        "relation": value.relation,
        "source_observation_id": value.source_observation_id,
        "source_artifact_id": value.source_artifact_id,
    }


@dataclass(frozen=True, slots=True)
class ArtifactEvidence:  # pylint: disable=too-many-instance-attributes
    """Safe immutable Artifact and Observation facts for a Manifest."""

    artifact_id: str
    observation_id: str
    role: str
    source_url: str
    observed_at: str
    mime_type: str
    size_bytes: int
    sha256: str
    lineage: tuple[Lineage, ...]

    def __post_init__(self) -> None:
        try:
            role = ArtifactRole(self.role)
            validate_observation_id(self.observation_id)
            mime = validate_mime_type(self.mime_type)
            expected_id = artifact_id(self.sha256, mime, role)
        except (ArtifactStoreError, TypeError, ValueError) as exc:
            raise ResultValidationError("artifact.invalid") from exc
        if self.artifact_id != expected_id:
            raise ResultValidationError("artifact.identity_mismatch")
        validate_url(self.source_url, allow_urn=True)
        validate_utc_time(self.observed_at)
        validate_nonnegative_int(self.size_bytes, code="artifact.size_invalid")
        validate_sha256(self.sha256)
        if not isinstance(self.lineage, tuple):
            raise ResultValidationError("lineage.invalid")
        try:
            for edge in self.lineage:
                validate_lineage(edge)
        except ArtifactStoreError as exc:
            raise ResultValidationError("lineage.invalid") from exc
        if role is ArtifactRole.SOURCE and self.lineage:
            raise ResultValidationError("lineage.forbidden")
        if role is ArtifactRole.DERIVED and len(self.lineage) != 1:
            raise ResultValidationError("lineage.required")
        if any(
            edge.observation_id != self.observation_id
            or edge.artifact_id != self.artifact_id
            for edge in self.lineage
        ):
            raise ResultValidationError("lineage.invalid")

    @classmethod
    def from_dict(cls, value: object) -> ArtifactEvidence:
        """Parse strict Artifact and Observation evidence."""
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {
                "artifact_id",
                "observation_id",
                "role",
                "source_url",
                "observed_at",
                "mime_type",
                "size_bytes",
                "sha256",
                "lineage",
            },
        )
        raw_lineage = payload["lineage"]
        if not isinstance(raw_lineage, list):
            raise ResultValidationError("lineage.invalid")
        return cls(
            artifact_id=payload["artifact_id"],
            observation_id=payload["observation_id"],
            role=payload["role"],
            source_url=payload["source_url"],
            observed_at=payload["observed_at"],
            mime_type=payload["mime_type"],
            size_bytes=payload["size_bytes"],
            sha256=payload["sha256"],
            lineage=tuple(_lineage_from_dict(edge) for edge in raw_lineage),
        )

    def to_dict(self) -> dict[str, object]:
        """Return plain JSON Artifact and Observation evidence."""
        return {
            "artifact_id": self.artifact_id,
            "observation_id": self.observation_id,
            "role": self.role,
            "source_url": self.source_url,
            "observed_at": self.observed_at,
            "mime_type": self.mime_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "lineage": [_lineage_to_dict(edge) for edge in self.lineage],
        }


def _validate_collection_lineage(artifacts: tuple[ArtifactEvidence, ...]) -> None:
    artifact_ids = {artifact.artifact_id for artifact in artifacts}
    observation_ids = {artifact.observation_id for artifact in artifacts}
    if len(artifact_ids) != len(artifacts) or len(observation_ids) != len(artifacts):
        raise ResultValidationError("artifact.duplicate")
    identity_roles = {
        (artifact.observation_id, artifact.artifact_id): artifact.role
        for artifact in artifacts
    }
    for artifact in artifacts:
        for edge in artifact.lineage:
            source_pair = (
                edge.source_observation_id,
                edge.source_artifact_id,
            )
            if source_pair not in identity_roles:
                raise ResultValidationError("lineage.dangling")
            if identity_roles[source_pair] != "source":
                raise ResultValidationError("lineage.source_role_invalid")


def _validate_redirect_chain(
    *,
    requested_url: str,
    current_url: str,
    final_url: str | None,
    redirects: tuple[RedirectEvidence, ...],
    succeeded: bool,
) -> None:
    """Bind ordered redirect evidence to the visited and final endpoints."""
    expected_from = requested_url
    for index, redirect in enumerate(redirects):
        if redirect.from_url != expected_from:
            raise ResultValidationError("redirect.chain_invalid")
        if redirect.decision == "rejected":
            if succeeded or index != len(redirects) - 1:
                raise ResultValidationError("redirect.chain_invalid")
            expected_current = redirect.from_url
            break
        expected_from = redirect.to_url
    else:
        expected_current = expected_from

    if current_url != expected_current:
        raise ResultValidationError("redirect.chain_invalid")
    if succeeded and final_url != current_url:
        raise ResultValidationError("redirect.chain_invalid")


@dataclass(frozen=True, slots=True)
class Manifest:  # pylint: disable=too-many-instance-attributes
    """Complete immutable facts explaining one acquisition outcome."""

    run_id: str
    generated_at: str
    requested_url: str
    current_url: str
    final_url: str | None
    http_status: int | None
    mime_type: str | None
    size_bytes: int | None
    sha256: str | None
    tool_id: str | None
    tool_version: str | None
    redirects: tuple[RedirectEvidence, ...]
    site_skill: SiteSkillEvidence | None
    attempts: tuple[Attempt, ...]
    artifacts: tuple[ArtifactEvidence, ...]
    usage: Usage
    schema_version: str = MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:  # pylint: disable=too-many-branches
        if self.schema_version != MANIFEST_SCHEMA_VERSION:
            raise ResultValidationError("schema.version_invalid")
        validate_text(self.run_id, code="manifest.run_id_invalid", maximum=128)
        validate_utc_time(self.generated_at)
        validate_url(self.requested_url)
        validate_url(self.current_url)
        if self.final_url is not None:
            validate_url(self.final_url)
        if (
            not isinstance(self.redirects, tuple)
            or not all(
                isinstance(redirect, RedirectEvidence) for redirect in self.redirects
            )
            or [redirect.order for redirect in self.redirects]
            != list(range(len(self.redirects)))
        ):
            raise ResultValidationError("redirect.order_invalid")
        if self.site_skill is not None and not isinstance(
            self.site_skill, SiteSkillEvidence
        ):
            raise ResultValidationError("site_skill.invalid")
        if not isinstance(self.usage, Usage):
            raise ResultValidationError("usage.invalid")
        if not isinstance(self.artifacts, tuple) or not all(
            isinstance(artifact, ArtifactEvidence) for artifact in self.artifacts
        ):
            raise ResultValidationError("artifact.invalid")
        validate_attempts(self.attempts)
        self.usage.validate_attempts(self.attempts)
        _validate_collection_lineage(self.artifacts)

        paired_tool = (self.tool_id is None) == (self.tool_version is None)
        if not paired_tool:
            raise ResultValidationError("manifest.tool_invalid")
        if self.tool_id is not None:
            validate_text(self.tool_id, code="manifest.tool_invalid", maximum=128)
            validate_text(self.tool_version, code="manifest.tool_invalid", maximum=128)
        if self.http_status is not None and (
            isinstance(self.http_status, bool)
            or not isinstance(self.http_status, int)
            or not 100 <= self.http_status <= 599
        ):
            raise ResultValidationError("manifest.http_status_invalid")

        successful_attempts = tuple(
            attempt for attempt in self.attempts if attempt.outcome == "succeeded"
        )
        if self.artifacts:
            sources = tuple(
                artifact for artifact in self.artifacts if artifact.role == "source"
            )
            if len(sources) != 1:
                raise ResultValidationError("manifest.source_cardinality_invalid")
            if len(successful_attempts) != 1:
                raise ResultValidationError("manifest.success_cardinality_invalid")
            source = sources[0]
            successful_attempt = successful_attempts[0]
            if (
                self.final_url is None
                or self.http_status is None
                or self.tool_id is None
            ):
                raise ResultValidationError("manifest.success_facts_invalid")
            if source.source_url != self.final_url or (
                self.mime_type,
                self.size_bytes,
                self.sha256,
            ) != (source.mime_type, source.size_bytes, source.sha256):
                raise ResultValidationError("manifest.success_facts_invalid")
            result_facts = (
                self.requested_url,
                self.final_url,
                self.http_status,
                self.tool_id,
                self.tool_version,
            )
            attempt_facts = (
                successful_attempt.requested_url,
                successful_attempt.final_url,
                successful_attempt.http_status,
                successful_attempt.tool_id,
                successful_attempt.tool_version,
            )
            if result_facts != attempt_facts:
                raise ResultValidationError("manifest.success_facts_invalid")
            _validate_redirect_chain(
                requested_url=self.requested_url,
                current_url=self.current_url,
                final_url=self.final_url,
                redirects=self.redirects,
                succeeded=True,
            )
        else:
            _validate_redirect_chain(
                requested_url=self.requested_url,
                current_url=self.current_url,
                final_url=self.final_url,
                redirects=self.redirects,
                succeeded=False,
            )
            if successful_attempts or any(
                value is not None
                for value in (
                    self.final_url,
                    self.http_status,
                    self.mime_type,
                    self.size_bytes,
                    self.sha256,
                )
            ):
                raise ResultValidationError("manifest.artifact_required")

    @classmethod
    def from_dict(cls, value: object) -> Manifest:
        """Parse a strict Manifest object without executing acquisition logic."""
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {
                "schema_version",
                "run_id",
                "generated_at",
                "requested_url",
                "current_url",
                "final_url",
                "http_status",
                "mime_type",
                "size_bytes",
                "sha256",
                "tool_id",
                "tool_version",
                "redirects",
                "site_skill",
                "attempts",
                "artifacts",
                "usage",
            },
        )
        for key in ("redirects", "attempts", "artifacts"):
            if not isinstance(payload[key], list):
                raise ResultValidationError("schema.invalid")
        return cls(
            schema_version=payload["schema_version"],
            run_id=payload["run_id"],
            generated_at=payload["generated_at"],
            requested_url=payload["requested_url"],
            current_url=payload["current_url"],
            final_url=payload["final_url"],
            http_status=payload["http_status"],
            mime_type=payload["mime_type"],
            size_bytes=payload["size_bytes"],
            sha256=payload["sha256"],
            tool_id=payload["tool_id"],
            tool_version=payload["tool_version"],
            redirects=tuple(
                RedirectEvidence.from_dict(item) for item in payload["redirects"]
            ),
            site_skill=(
                None
                if payload["site_skill"] is None
                else SiteSkillEvidence.from_dict(payload["site_skill"])
            ),
            attempts=tuple(Attempt.from_dict(item) for item in payload["attempts"]),
            artifacts=tuple(
                ArtifactEvidence.from_dict(item) for item in payload["artifacts"]
            ),
            usage=Usage.from_dict(payload["usage"]),
        )

    def to_dict(self) -> dict[str, object]:
        """Return the exact versioned Manifest payload."""
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "requested_url": self.requested_url,
            "current_url": self.current_url,
            "final_url": self.final_url,
            "http_status": self.http_status,
            "mime_type": self.mime_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "redirects": [redirect.to_dict() for redirect in self.redirects],
            "site_skill": (
                None if self.site_skill is None else self.site_skill.to_dict()
            ),
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "usage": self.usage.to_dict(),
        }

    def canonical_json_bytes(self) -> bytes:
        """Return byte-stable canonical UTF-8 JSON."""
        return canonical_json_bytes(self.to_dict())


def _artifact_evidence(value: StoredObservation) -> ArtifactEvidence:
    if not isinstance(value, StoredObservation):
        raise ResultValidationError("artifact.invalid")
    content_sha = hashlib.sha256(value.content).hexdigest()
    if content_sha != value.blob.sha256 or len(value.content) != value.blob.size_bytes:
        raise ResultValidationError("artifact.content_mismatch")
    if (
        value.artifact.blob_sha256 != value.blob.sha256
        or value.observation.artifact_id != value.artifact.artifact_id
    ):
        raise ResultValidationError("artifact.identity_mismatch")
    return ArtifactEvidence(
        artifact_id=value.artifact.artifact_id,
        observation_id=value.observation.observation_id,
        role=value.artifact.role.value,
        source_url=value.observation.source_url,
        observed_at=value.observation.observed_at,
        mime_type=value.artifact.mime_type,
        size_bytes=value.blob.size_bytes,
        sha256=value.blob.sha256,
        lineage=value.lineage,
    )


def manifest_from_observations(  # pylint: disable=too-many-arguments
    *,
    run_id: str,
    generated_at: str,
    requested_url: str,
    current_url: str,
    final_url: str,
    http_status: int,
    tool_id: str,
    tool_version: str,
    redirects: tuple[RedirectEvidence, ...],
    site_skill: SiteSkillEvidence | None,
    attempts: tuple[Attempt, ...],
    observations: tuple[StoredObservation, ...],
    usage: Usage,
) -> Manifest:
    """Build a Manifest solely from already verified public Artifact values."""
    artifacts = tuple(_artifact_evidence(item) for item in observations)
    source = next((item for item in artifacts if item.role == "source"), None)
    if source is None:
        raise ResultValidationError("manifest.source_required")
    return Manifest(
        run_id=run_id,
        generated_at=generated_at,
        requested_url=requested_url,
        current_url=current_url,
        final_url=final_url,
        http_status=http_status,
        mime_type=source.mime_type,
        size_bytes=source.size_bytes,
        sha256=source.sha256,
        tool_id=tool_id,
        tool_version=tool_version,
        redirects=redirects,
        site_skill=site_skill,
        attempts=attempts,
        artifacts=artifacts,
        usage=usage,
    )
