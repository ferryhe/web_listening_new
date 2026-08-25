"""Validation and construction of successful acquisition observations."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from web_listening.artifact.model import ArtifactRole, ArtifactStoreError

_OBSERVATION_ID = re.compile(r"observation-[0-9a-f]{32}\Z")
_UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


@dataclass(frozen=True, slots=True)
class ObservationProposal:  # pylint: disable=too-many-instance-attributes
    """Complete caller input for one successful observation commit."""

    content: bytes
    sha256: str
    size_bytes: int
    mime_type: str
    source_url: str
    observed_at: str
    role: ArtifactRole
    derived_from_observation_id: str | None = None


def validate_source_url(value: str) -> str:
    """Validate an inert source locator without interpreting or opening it."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ArtifactStoreError("observation.source_invalid")
    return value


def validate_observed_at(value: str) -> str:
    """Accept canonical whole-second UTC timestamps."""
    if not isinstance(value, str) or _UTC_TIME.fullmatch(value) is None:
        raise ArtifactStoreError("observation.time_invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ArtifactStoreError("observation.time_invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ArtifactStoreError("observation.time_invalid")
    return value


def new_observation_id() -> str:
    """Create an always-new event identity."""
    return f"observation-{uuid.uuid4().hex}"


def validate_observation_id(value: str) -> str:
    """Validate an Observation identity loaded from a caller or repository."""
    if not isinstance(value, str) or _OBSERVATION_ID.fullmatch(value) is None:
        raise ArtifactStoreError("observation.id_invalid")
    return value
