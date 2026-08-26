"""Immutable values returned by the local Artifact repository."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ArtifactStoreError(ValueError):
    """A stable, non-sensitive Artifact repository failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ArtifactRole(str, Enum):
    """The minimal role distinction required by lineage."""

    SOURCE = "source"
    DERIVED = "derived"


@dataclass(frozen=True, slots=True)
class Blob:
    """One content-addressed byte sequence."""

    sha256: str
    size_bytes: int
    relative_path: str


@dataclass(frozen=True, slots=True)
class Artifact:
    """An immutable interpretation of one Blob."""

    artifact_id: str
    blob_sha256: str
    mime_type: str
    role: ArtifactRole


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    """Verified Artifact content and delivery metadata."""

    artifact_id: str
    blob_sha256: str
    size_bytes: int
    mime_type: str
    content: bytes


@dataclass(frozen=True, slots=True)
class Observation:
    """One successful acquisition event."""

    observation_id: str
    artifact_id: str
    source_url: str
    observed_at: str


@dataclass(frozen=True, slots=True)
class Lineage:
    """A validated derived-to-source relationship."""

    lineage_id: str
    observation_id: str
    artifact_id: str
    relation: str
    source_observation_id: str
    source_artifact_id: str


@dataclass(frozen=True, slots=True)
class StoredObservation:
    """A complete verified repository read."""

    blob: Blob
    artifact: Artifact
    observation: Observation
    lineage: tuple[Lineage, ...]
    content: bytes
