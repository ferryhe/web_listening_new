"""Read-only Runtime projection of persisted acquisition facts."""

from __future__ import annotations

from web_listening.artifact.model import ArtifactStoreError, StoredObservation
from web_listening.artifact.store import ArtifactStore
from web_listening.result.errors import ResultValidationError
from web_listening.result.handoff import (
    HANDOFF_SCHEMA_VERSION,
    PRODUCER_NAME,
    PRODUCER_VERSION,
    AcquisitionHandoff,
    make_handoff,
)
from web_listening.runtime.jobs import Job, JobStatus


class HandoffError(ValueError):
    """A stable Runtime handoff export error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _tool_for_artifact(job: Job, role: str, source_url: str) -> tuple[str, str]:
    assert job.result is not None
    attempts = job.result.attempts
    if role == "source":
        matches = [
            item
            for item in attempts
            if item.outcome == "succeeded" and item.final_url is not None
        ]
    else:
        prefix = "urn:web-listening:transform:"
        matches = [
            item
            for item in attempts
            if item.outcome == "succeeded" and item.final_url is None
        ]
        if source_url.startswith(prefix):
            identity = source_url[len(prefix) :]
            matches = [
                item
                for item in matches
                if f"{item.tool_id}:{item.tool_version}" == identity
            ]
    if len(matches) != 1:
        raise HandoffError("handoff.tool_mismatch")
    return matches[0].tool_id, matches[0].tool_version


def _reconcile(expected: object, stored: StoredObservation) -> dict[str, object]:
    facts = expected.to_dict()  # type: ignore[attr-defined]
    observed = {
        "artifact_id": stored.artifact.artifact_id,
        "observation_id": stored.observation.observation_id,
        "role": stored.artifact.role.value,
        "source_url": stored.observation.source_url,
        "observed_at": stored.observation.observed_at,
        "mime_type": stored.artifact.mime_type,
        "size_bytes": stored.blob.size_bytes,
        "sha256": stored.blob.sha256,
        "lineage": facts["lineage"],
    }
    stored_lineage = [
        {
            "lineage_id": edge.lineage_id,
            "observation_id": edge.observation_id,
            "artifact_id": edge.artifact_id,
            "relation": edge.relation,
            "source_observation_id": edge.source_observation_id,
            "source_artifact_id": edge.source_artifact_id,
        }
        for edge in stored.lineage
    ]
    observed["lineage"] = stored_lineage
    if observed != facts:
        raise HandoffError("handoff.artifact_mismatch")
    return facts


def project_handoff(job: Job, store: ArtifactStore) -> AcquisitionHandoff:
    """Project a terminal Job after reopening every Artifact Observation."""
    if job.status not in {
        JobStatus.COMPLETED,
        JobStatus.PARTIAL,
        JobStatus.REJECTED,
        JobStatus.FAILED,
    }:
        raise HandoffError("handoff.not_terminal")
    if job.result is None:
        raise HandoffError("handoff.result_unavailable")
    if job.finished_at is None:
        raise HandoffError("handoff.job_mismatch")
    result = job.result
    if result.status.value != job.status.value or result.manifest.run_id != job.job_id:
        raise HandoffError("handoff.job_mismatch")
    try:
        artifacts = []
        for expected in result.artifacts:
            facts = _reconcile(expected, store.get_observation(expected.observation_id))
            tool_id, tool_version = _tool_for_artifact(
                job, expected.role, expected.source_url
            )
            artifacts.append(
                {
                    **facts,
                    "tool_id": tool_id,
                    "tool_version": tool_version,
                    "content_ref": f"/v1/artifacts/{expected.artifact_id}",
                }
            )
        manifest = result.manifest
        payload = {
            "schema_version": HANDOFF_SCHEMA_VERSION,
            "producer": {"name": PRODUCER_NAME, "version": PRODUCER_VERSION},
            "job_id": job.job_id,
            "run_id": job.job_id,
            "status": result.status.value,
            "generated_at": job.finished_at,
            "source": {
                "source_id": manifest.requested_url,
                "requested_url": manifest.requested_url,
                "current_url": manifest.current_url,
                "final_url": manifest.final_url,
                "redirects": [item.to_dict() for item in manifest.redirects],
            },
            "artifacts": artifacts,
            "attempts": [item.to_dict() for item in result.attempts],
            "errors": [item.to_dict() for item in result.errors],
            "usage": result.usage.to_dict(),
        }
        return make_handoff(payload)
    except (ArtifactStoreError, ResultValidationError) as exc:
        raise HandoffError("handoff.fact_invalid") from exc


__all__ = ["HandoffError", "project_handoff"]
