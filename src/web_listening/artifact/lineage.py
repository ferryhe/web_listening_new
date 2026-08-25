"""Deterministic validation for minimal derived Artifact lineage."""

from __future__ import annotations

import hashlib
import json
import re

from web_listening.artifact.model import ArtifactRole, ArtifactStoreError, Lineage
from web_listening.artifact.observation import validate_observation_id

DERIVED_FROM = "derived_from"
_ARTIFACT_ID = re.compile(r"artifact-[0-9a-f]{64}\Z")
_LINEAGE_ID = re.compile(r"lineage-[0-9a-f]{64}\Z")


def validate_artifact_id(value: str) -> str:
    """Validate a canonical Artifact identity."""
    if not isinstance(value, str) or _ARTIFACT_ID.fullmatch(value) is None:
        raise ArtifactStoreError("artifact.id_invalid")
    return value


def lineage_id(
    *,
    observation_id: str,
    artifact_id: str,
    source_observation_id: str,
    source_artifact_id: str,
) -> str:
    """Return the deterministic identity of one immutable lineage edge."""
    payload = {
        "artifact_id": validate_artifact_id(artifact_id),
        "observation_id": validate_observation_id(observation_id),
        "relation": DERIVED_FROM,
        "source_artifact_id": validate_artifact_id(source_artifact_id),
        "source_observation_id": validate_observation_id(source_observation_id),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"lineage-{hashlib.sha256(encoded).hexdigest()}"


def validate_role_lineage(
    role: ArtifactRole, derived_from_observation_id: str | None
) -> str | None:
    """Enforce the sole source/derived relationship rule."""
    try:
        normalized_role = ArtifactRole(role)
    except (TypeError, ValueError) as exc:
        raise ArtifactStoreError("artifact.role_invalid") from exc
    if normalized_role is ArtifactRole.SOURCE:
        if derived_from_observation_id is not None:
            raise ArtifactStoreError("lineage.forbidden")
        return None
    if derived_from_observation_id is None:
        raise ArtifactStoreError("lineage.required")
    return validate_observation_id(derived_from_observation_id)


def validate_lineage(value: Lineage) -> Lineage:
    """Recompute a loaded edge and reject self-reference or identity drift."""
    if not isinstance(value, Lineage) or value.relation != DERIVED_FROM:
        raise ArtifactStoreError("lineage.invalid")
    if value.observation_id == value.source_observation_id:
        raise ArtifactStoreError("lineage.self_reference")
    expected = lineage_id(
        observation_id=value.observation_id,
        artifact_id=value.artifact_id,
        source_observation_id=value.source_observation_id,
        source_artifact_id=value.source_artifact_id,
    )
    if _LINEAGE_ID.fullmatch(value.lineage_id) is None or value.lineage_id != expected:
        raise ArtifactStoreError("lineage.invalid")
    return value
