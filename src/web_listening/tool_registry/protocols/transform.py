"""Pure contract for transforms over already stored source content."""

# pylint: disable=duplicate-code,unidiomatic-typecheck

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from web_listening.artifact.identity import (
    artifact_id,
    blob_relative_path,
    validate_blob_declaration,
)
from web_listening.artifact.identity import validate_mime_type as validate_artifact_mime
from web_listening.artifact.identity import (
    validate_relative_path,
    validate_sha256,
)
from web_listening.artifact.lineage import validate_artifact_id, validate_lineage
from web_listening.artifact.model import (
    Artifact,
    ArtifactRole,
    ArtifactStoreError,
    Blob,
    Lineage,
    Observation,
    StoredObservation,
)
from web_listening.artifact.observation import (
    validate_observation_id,
    validate_observed_at,
    validate_source_url,
)
from web_listening.tool_registry.manifest import (
    ToolManifest,
    ToolRegistryError,
    validate_safe_code,
    validate_tool_id,
    validate_tool_version,
)
from web_listening.tool_registry.protocols.acquisition import (
    validate_body_hash,
    validate_mime_type,
    validate_runtime,
)


@dataclass(frozen=True, slots=True)
class TransformInput:
    """Verified stored source content presented to a transform tool."""

    source: StoredObservation

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", _rebuild_stored_observation(self.source))


@dataclass(frozen=True, slots=True)
class TransformOutput:
    """Derived bytes bound to the source Artifact identity."""

    tool_id: str
    tool_version: str
    source_artifact_id: str
    mime_type: str
    body: bytes
    sha256: str
    runtime_ms: int

    def __post_init__(self) -> None:
        validate_tool_id(self.tool_id)
        validate_tool_version(self.tool_version)
        if type(self.source_artifact_id) is not str:
            raise ToolRegistryError("protocol.source_invalid")
        try:
            validate_artifact_id(self.source_artifact_id)
        except ArtifactStoreError:
            raise ToolRegistryError("protocol.source_invalid") from None
        validate_mime_type(self.mime_type)
        validate_body_hash(self.body, self.sha256)
        validate_runtime(self.runtime_ms)


@dataclass(frozen=True, slots=True)
class TransformFailure:
    """A safe transform failure returned instead of derived bytes."""

    tool_id: str
    tool_version: str
    code: str

    def __post_init__(self) -> None:
        validate_tool_id(self.tool_id)
        validate_tool_version(self.tool_version)
        validate_safe_code(self.code)


@runtime_checkable
class TransformTool(Protocol):  # pylint: disable=too-few-public-methods
    """Structural interface implemented by a transform tool."""

    manifest: ToolManifest

    def transform(
        self, tool_input: TransformInput
    ) -> TransformOutput | TransformFailure:
        """Return derived bytes or a safe failure."""


def _rebuild_stored_observation(value: StoredObservation) -> StoredObservation:
    rebuilt, error = _contained_stored_observation(value)
    if error is not None:
        raise ToolRegistryError(error)
    return rebuilt  # type: ignore[return-value]


def _contained_stored_observation(
    value: object,
) -> tuple[StoredObservation | None, str | None]:
    try:
        if type(value) is not StoredObservation:
            return None, "protocol.input_invalid"
        return _validated_stored_observation(value), None
    except ArtifactStoreError as exc:
        return None, exc.code
    except Exception:  # pylint: disable=broad-exception-caught
        return None, "protocol.input_invalid"


def _validated_stored_observation(  # pylint: disable=too-many-branches,too-many-statements
    value: StoredObservation,
) -> StoredObservation:
    if type(value.blob) is not Blob:
        raise ArtifactStoreError("blob.invalid")
    if type(value.content) is not bytes:
        raise ArtifactStoreError("blob.content_invalid")
    if type(value.blob.sha256) is not str:
        raise ArtifactStoreError("blob.sha256_invalid")
    if type(value.blob.size_bytes) is not int:
        raise ArtifactStoreError("blob.size_invalid")
    if type(value.blob.relative_path) is not str:
        raise ArtifactStoreError("path.invalid")
    digest, size = validate_blob_declaration(
        value.content, value.blob.sha256, value.blob.size_bytes
    )
    relative_path = validate_relative_path(value.blob.relative_path)
    if relative_path != blob_relative_path(digest):
        raise ArtifactStoreError("blob.path_invalid")
    blob = Blob(digest, size, relative_path)

    if type(value.artifact) is not Artifact:
        raise ArtifactStoreError("artifact.invalid")
    if type(value.artifact.artifact_id) is not str:
        raise ArtifactStoreError("artifact.id_invalid")
    if type(value.artifact.blob_sha256) is not str:
        raise ArtifactStoreError("blob.sha256_invalid")
    if type(value.artifact.mime_type) is not str:
        raise ArtifactStoreError("mime.invalid")
    if type(value.artifact.role) is not ArtifactRole:
        raise ArtifactStoreError("artifact.role_invalid")
    identifier = validate_artifact_id(value.artifact.artifact_id)
    artifact_digest = validate_sha256(value.artifact.blob_sha256)
    mime_type = validate_artifact_mime(value.artifact.mime_type)
    try:
        role = ArtifactRole(value.artifact.role)
    except (TypeError, ValueError) as exc:
        raise ArtifactStoreError("artifact.role_invalid") from exc
    if artifact_digest != digest or identifier != artifact_id(digest, mime_type, role):
        raise ArtifactStoreError("artifact.invalid")
    artifact = Artifact(identifier, digest, mime_type, role)

    if type(value.observation) is not Observation:
        raise ArtifactStoreError("observation.invalid")
    if type(value.observation.observation_id) is not str:
        raise ArtifactStoreError("observation.id_invalid")
    if type(value.observation.artifact_id) is not str:
        raise ArtifactStoreError("artifact.id_invalid")
    if type(value.observation.source_url) is not str:
        raise ArtifactStoreError("observation.source_invalid")
    if type(value.observation.observed_at) is not str:
        raise ArtifactStoreError("observation.time_invalid")
    observation = Observation(
        validate_observation_id(value.observation.observation_id),
        validate_artifact_id(value.observation.artifact_id),
        validate_source_url(value.observation.source_url),
        validate_observed_at(value.observation.observed_at),
    )
    if observation.artifact_id != identifier:
        raise ArtifactStoreError("observation.invalid")

    if type(value.lineage) is not tuple:
        raise ArtifactStoreError("lineage.invalid")
    edges = []
    for edge in value.lineage:
        if type(edge) is not Lineage or any(
            type(item) is not str
            for item in (
                edge.lineage_id,
                edge.observation_id,
                edge.artifact_id,
                edge.relation,
                edge.source_observation_id,
                edge.source_artifact_id,
            )
        ):
            raise ArtifactStoreError("lineage.invalid")
        edges.append(
            validate_lineage(
                Lineage(
                    edge.lineage_id,
                    edge.observation_id,
                    edge.artifact_id,
                    edge.relation,
                    edge.source_observation_id,
                    edge.source_artifact_id,
                )
            )
        )
    rebuilt_edges = tuple(edges)
    if role is ArtifactRole.SOURCE and rebuilt_edges:
        raise ArtifactStoreError("lineage.forbidden")
    if role is ArtifactRole.DERIVED and len(rebuilt_edges) != 1:
        raise ArtifactStoreError("lineage.required")
    if any(
        edge.observation_id != observation.observation_id
        or edge.artifact_id != artifact.artifact_id
        for edge in rebuilt_edges
    ):
        raise ArtifactStoreError("lineage.invalid")
    return StoredObservation(blob, artifact, observation, rebuilt_edges, value.content)
