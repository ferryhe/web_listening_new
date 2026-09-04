"""Strict, deterministic cross-service acquisition handoff contract."""

# pylint: disable=duplicate-code,too-many-branches,too-many-locals,too-many-statements

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from web_listening.result.attempts import Attempt, validate_attempts
from web_listening.result.errors import (
    ResultValidationError,
    SafeError,
    ensure_safe_payload,
    parse_utc_time,
    require_exact_fields,
    require_mapping,
    validate_sha256,
    validate_text,
    validate_url,
    validate_utc_time,
)
from web_listening.result.manifest import (
    ArtifactEvidence,
    RedirectEvidence,
    Usage,
)
from web_listening.result.model import ResultStatus

HANDOFF_SCHEMA_VERSION = "acquisition-handoff.v1"
PRODUCER_NAME = "web_listening_new"
PRODUCER_VERSION = "acquisition-handoff-producer.v1"
_TRANSFORM_URL = re.compile(
    r"urn:web-listening:transform:[A-Za-z0-9._~-]+:[A-Za-z0-9._+~-]+\Z"
)


class HandoffValidationError(ResultValidationError):
    """A stable fail-closed handoff validation failure."""


def _exact(value: object, fields: set[str]) -> dict[str, Any]:
    payload = dict(require_mapping(value))
    require_exact_fields(payload, fields)
    return payload


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise HandoffValidationError("handoff.duplicate_key")
        payload[key] = value
    return payload


def _safe_payload(payload: dict[str, Any]) -> None:
    """Apply shared safety validation while preserving fixed API-relative refs."""
    scrubbed = json.loads(json.dumps(payload))
    for artifact in scrubbed.get("artifacts", []):
        if isinstance(artifact, dict) and "content_ref" in artifact:
            artifact["content_ref"] = "artifact-content-reference"
    ensure_safe_payload(scrubbed)


def _canonical(payload: dict[str, Any]) -> bytes:
    _safe_payload(payload)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _validate_producer(value: object) -> None:
    payload = _exact(value, {"name", "version"})
    if payload != {"name": PRODUCER_NAME, "version": PRODUCER_VERSION}:
        raise HandoffValidationError("handoff.producer_invalid")


def _validate_source(value: object) -> dict[str, Any]:
    payload = _exact(
        value,
        {"source_id", "requested_url", "current_url", "final_url", "redirects"},
    )
    requested = validate_url(payload["requested_url"])
    if validate_url(payload["source_id"]) != requested:
        raise HandoffValidationError("handoff.source_id_mismatch")
    validate_url(payload["current_url"])
    if payload["final_url"] is not None:
        validate_url(payload["final_url"])
    if not isinstance(payload["redirects"], list):
        raise HandoffValidationError("schema.invalid")
    redirects = tuple(RedirectEvidence.from_dict(item) for item in payload["redirects"])
    if [item.order for item in redirects] != list(range(len(redirects))):
        raise HandoffValidationError("redirect.order_invalid")
    expected = requested
    for index, redirect in enumerate(redirects):
        if redirect.from_url != expected:
            raise HandoffValidationError("redirect.chain_invalid")
        if redirect.decision == "rejected":
            if index != len(redirects) - 1:
                raise HandoffValidationError("redirect.chain_invalid")
            expected = redirect.from_url
            break
        expected = redirect.to_url
    if payload["current_url"] != expected:
        raise HandoffValidationError("redirect.chain_invalid")
    if payload["final_url"] is not None and payload["final_url"] != expected:
        raise HandoffValidationError("redirect.chain_invalid")
    return payload


def _validate_artifact(value: object) -> ArtifactEvidence:
    payload = _exact(
        value,
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
            "tool_id",
            "tool_version",
            "content_ref",
        },
    )
    evidence = ArtifactEvidence.from_dict(
        {
            key: payload[key]
            for key in (
                "artifact_id",
                "observation_id",
                "role",
                "source_url",
                "observed_at",
                "mime_type",
                "size_bytes",
                "sha256",
                "lineage",
            )
        }
    )
    if evidence.role == "source":
        validate_url(evidence.source_url)
    elif _TRANSFORM_URL.fullmatch(evidence.source_url) is None:
        raise HandoffValidationError("url.invalid")
    validate_text(payload["tool_id"], code="handoff.tool_invalid", maximum=128)
    validate_text(payload["tool_version"], code="handoff.tool_invalid", maximum=128)
    if payload["content_ref"] != f"/v1/artifacts/{evidence.artifact_id}":
        raise HandoffValidationError("handoff.content_ref_invalid")
    return evidence


def _validate_payload(payload: dict[str, Any], *, verify_id: bool) -> None:
    require_exact_fields(
        payload,
        {
            "schema_version",
            "handoff_id",
            "producer",
            "job_id",
            "run_id",
            "status",
            "generated_at",
            "source",
            "artifacts",
            "attempts",
            "errors",
            "usage",
        },
    )
    _safe_payload(payload)
    if payload["schema_version"] != HANDOFF_SCHEMA_VERSION:
        raise HandoffValidationError("schema.version_invalid")
    validate_sha256(payload["handoff_id"], code="handoff.id_invalid")
    _validate_producer(payload["producer"])
    job_id = validate_text(payload["job_id"], code="job.id_invalid", maximum=128)
    if (
        validate_text(payload["run_id"], code="manifest.run_id_invalid", maximum=128)
        != job_id
    ):
        raise HandoffValidationError("handoff.run_id_mismatch")
    try:
        ResultStatus(payload["status"])
    except (TypeError, ValueError) as exc:
        raise HandoffValidationError("result.status_invalid") from exc
    validate_utc_time(payload["generated_at"])
    generated_at = parse_utc_time(payload["generated_at"])
    source = _validate_source(payload["source"])
    if not all(
        isinstance(payload[key], list) for key in ("artifacts", "attempts", "errors")
    ):
        raise HandoffValidationError("schema.invalid")
    artifacts = tuple(_validate_artifact(item) for item in payload["artifacts"])
    # Reuse Manifest's collection-level lineage checks by requiring every edge target.
    identities = {
        (item.observation_id, item.artifact_id): item.role for item in artifacts
    }
    for artifact in artifacts:
        for edge in artifact.lineage:
            if (
                identities.get((edge.source_observation_id, edge.source_artifact_id))
                != "source"
            ):
                raise HandoffValidationError("lineage.dangling")
    artifact_ids = [item.artifact_id for item in artifacts]
    observation_ids = [item.observation_id for item in artifacts]
    if len(set(artifact_ids)) != len(artifact_ids) or len(set(observation_ids)) != len(
        observation_ids
    ):
        raise HandoffValidationError("artifact.duplicate")
    attempts = tuple(Attempt.from_dict(item) for item in payload["attempts"])
    validate_attempts(attempts)
    if any(
        parse_utc_time(value) > generated_at
        for attempt in attempts
        for value in (attempt.started_at, attempt.finished_at)
    ):
        raise HandoffValidationError("job.time_invalid")
    if any(
        parse_utc_time(artifact.observed_at) > generated_at for artifact in artifacts
    ):
        raise HandoffValidationError("job.time_invalid")
    errors = tuple(SafeError.from_dict(item) for item in payload["errors"])
    if len(errors) != len(payload["errors"]):
        raise HandoffValidationError("schema.invalid")
    usage = Usage.from_dict(payload["usage"])
    usage.validate_attempts(attempts)
    status = ResultStatus(payload["status"])
    has_artifact = bool(artifacts)
    has_success = any(attempt.outcome == "succeeded" for attempt in attempts)
    has_failure = bool(errors) or any(
        attempt.outcome != "succeeded" for attempt in attempts
    )
    if status is ResultStatus.COMPLETED:
        if not has_artifact or not has_success:
            raise HandoffValidationError("result.completed_requires_artifact")
        if has_failure:
            raise HandoffValidationError("result.completed_has_failure")
    elif status is ResultStatus.PARTIAL:
        if not has_artifact or not has_success:
            raise HandoffValidationError("result.partial_requires_artifact")
        if not has_failure:
            raise HandoffValidationError("result.partial_requires_failure")
    elif status is ResultStatus.REJECTED:
        if has_artifact or has_success:
            raise HandoffValidationError("result.rejected_has_artifact")
        if not errors:
            raise HandoffValidationError("result.rejected_requires_error")
    else:
        if has_artifact or has_success:
            raise HandoffValidationError("result.failed_has_artifact")
        if not errors:
            raise HandoffValidationError("result.failed_requires_error")
    if not has_artifact and source["final_url"] is not None:
        raise HandoffValidationError("manifest.artifact_required")
    if artifacts:
        if any(redirect["decision"] == "rejected" for redirect in source["redirects"]):
            raise HandoffValidationError("redirect.chain_invalid")
        sources = tuple(item for item in artifacts if item.role == "source")
        acquisition = tuple(
            item
            for item in attempts
            if item.outcome == "succeeded" and item.final_url is not None
        )
        if len(sources) != 1 or len(acquisition) != 1:
            raise HandoffValidationError("handoff.source_invalid")
        source_artifact = sources[0]
        source_payload = payload["artifacts"][
            artifact_ids.index(source_artifact.artifact_id)
        ]
        succeeded = acquisition[0]
        if (
            source_artifact.source_url != source["final_url"]
            or source_payload["tool_id"] != succeeded.tool_id
            or source_payload["tool_version"] != succeeded.tool_version
            or succeeded.requested_url != source["requested_url"]
            or succeeded.final_url != source["final_url"]
        ):
            raise HandoffValidationError("handoff.source_mismatch")
        transforms = tuple(
            item
            for item in attempts
            if item.outcome == "succeeded" and item.final_url is None
        )
        if len(transforms) > 1:
            raise HandoffValidationError("manifest.success_cardinality_invalid")
        tagged = tuple(
            (artifact, payload["artifacts"][index])
            for index, artifact in enumerate(artifacts)
            if artifact.role == "derived"
            and artifact.source_url.startswith("urn:web-listening:transform:")
        )
        matched: set[str] = set()
        for attempt in transforms:
            expected_source = (
                f"urn:web-listening:transform:{attempt.tool_id}:{attempt.tool_version}"
            )
            matches = tuple(
                (artifact, raw)
                for artifact, raw in tagged
                if artifact.source_url == expected_source
                and raw["tool_id"] == attempt.tool_id
                and raw["tool_version"] == attempt.tool_version
            )
            if attempt.requested_url != source_artifact.source_url or len(matches) != 1:
                raise HandoffValidationError("manifest.transform_lineage_invalid")
            matched.add(matches[0][0].artifact_id)
        if len(matched) != len(tagged):
            raise HandoffValidationError("manifest.transform_lineage_invalid")
    if verify_id:
        unsigned = dict(payload)
        unsigned.pop("handoff_id")
        expected = hashlib.sha256(_canonical(unsigned)).hexdigest()
        if payload["handoff_id"] != expected:
            raise HandoffValidationError("handoff.id_mismatch")


@dataclass(frozen=True, slots=True)
class AcquisitionHandoff:
    """An immutable validated handoff represented by its exact JSON payload."""

    _payload: dict[str, Any]

    def __post_init__(self) -> None:
        payload = deepcopy(dict(self._payload))
        try:
            _validate_payload(payload, verify_id=True)
        except HandoffValidationError:
            raise
        except ResultValidationError as exc:
            raise HandoffValidationError(exc.code) from exc
        object.__setattr__(self, "_payload", payload)

    @classmethod
    def from_dict(cls, value: object) -> "AcquisitionHandoff":
        """Parse a strict already-decoded handoff mapping."""
        return cls(deepcopy(dict(require_mapping(value))))

    @classmethod
    def from_json(cls, value: str | bytes) -> "AcquisitionHandoff":
        """Parse JSON while rejecting duplicate keys at every nesting level."""
        try:
            payload = json.loads(value, object_pairs_hook=_pairs)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HandoffValidationError("handoff.invalid_json") from exc
        return cls.from_dict(payload)

    def to_dict(self) -> dict[str, Any]:
        """Return an independent JSON-compatible payload."""
        return json.loads(self.canonical_json_bytes())

    def canonical_json_bytes(self) -> bytes:
        """Return canonical byte-stable UTF-8 JSON."""
        return _canonical(self._payload)


def make_handoff(payload: dict[str, Any]) -> AcquisitionHandoff:
    """Add the content-derived handoff identity to one unsigned payload."""
    unsigned = dict(payload)
    unsigned.pop("handoff_id", None)
    handoff_id = hashlib.sha256(_canonical(unsigned)).hexdigest()
    return AcquisitionHandoff({**unsigned, "handoff_id": handoff_id})


__all__ = [
    "AcquisitionHandoff",
    "HANDOFF_SCHEMA_VERSION",
    "HandoffValidationError",
    "PRODUCER_NAME",
    "PRODUCER_VERSION",
    "make_handoff",
]
