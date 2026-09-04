"""Read-only Runtime handoff projection tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import hashlib

import pytest

from web_listening.artifact.model import ArtifactRole
from web_listening.artifact.observation import ObservationProposal
from web_listening.artifact.store import ArtifactStore
from web_listening.result.attempts import Attempt
from web_listening.result.manifest import (
    RedirectEvidence,
    Usage,
    manifest_from_observations,
)
from web_listening.result.model import Result, ResultStatus
from web_listening.runtime.handoff import HandoffError, project_handoff
from web_listening.runtime.jobs import Job, JobStatus


def _terminal(
    store: ArtifactStore, *, observed_at: str = "2026-09-04T12:00:00Z"
) -> Job:
    content = b"handoff source"
    stored = store.commit_observation(
        ObservationProposal(
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            mime_type="text/html",
            source_url="https://example.test/final",
            observed_at=observed_at,
            role=ArtifactRole.SOURCE,
        )
    )
    attempt = Attempt(
        order=0,
        attempt_id="attempt-one",
        outcome="succeeded",
        tool_id="web_http",
        tool_version="1.0.0",
        started_at="2026-09-04T11:59:59Z",
        finished_at=observed_at,
        requested_url="https://example.test/start",
        final_url="https://example.test/final",
        http_status=200,
        error=None,
        requests=1,
        bytes_received=len(content),
        runtime_ms=10,
    )
    usage = Usage(1, len(content), 12, 1)
    manifest = manifest_from_observations(
        run_id="job-one",
        generated_at="2026-09-04T12:00:01Z",
        requested_url="https://example.test/start",
        current_url="https://example.test/final",
        final_url="https://example.test/final",
        http_status=200,
        tool_id="web_http",
        tool_version="1.0.0",
        redirects=(
            RedirectEvidence(
                0,
                "https://example.test/start",
                "https://example.test/final",
                301,
                "followed",
            ),
        ),
        site_skill=None,
        attempts=(attempt,),
        observations=(stored,),
        usage=usage,
    )
    result = Result(ResultStatus.COMPLETED, manifest, None, None, (attempt,), (), usage)
    return Job(
        "job-one",
        JobStatus.COMPLETED,
        "2026-09-04T11:59:58Z",
        "2026-09-04T11:59:59Z",
        observed_at,
        result,
    )


def test_projection_is_repeatable_and_does_not_mutate_persisted_facts(
    tmp_path: object,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")  # type: ignore[operator]
    job = _terminal(store)
    observation_id = job.result.artifacts[0].observation_id  # type: ignore[union-attr]
    before = store.get_observation(observation_id)
    first = project_handoff(job, store).canonical_json_bytes()
    second = project_handoff(job, store).canonical_json_bytes()
    after = store.get_observation(observation_id)
    assert first == second
    assert before == after
    assert b"handoff source" not in first
    assert bstr(store.root) not in first


def bstr(value: object) -> bytes:
    return str(value).encode()


@pytest.mark.parametrize("status", (JobStatus.SUBMITTED, JobStatus.RUNNING))
def test_non_terminal_job_is_rejected(tmp_path: object, status: JobStatus) -> None:
    store = ArtifactStore(tmp_path / "artifacts")  # type: ignore[operator]
    job = Job("job-one", status, "2026-09-04T12:00:00Z")
    with pytest.raises(HandoffError, match="handoff.not_terminal"):
        project_handoff(job, store)


@pytest.mark.parametrize("status", tuple({JobStatus.REJECTED, JobStatus.FAILED}))
def test_terminal_job_without_result_is_unavailable(
    tmp_path: object, status: JobStatus
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")  # type: ignore[operator]
    job = Job(
        "job-one", status, "2026-09-04T12:00:00Z", finished_at="2026-09-04T12:00:01Z"
    )
    with pytest.raises(HandoffError, match="handoff.result_unavailable"):
        project_handoff(job, store)


def test_projection_fails_closed_against_a_different_store(tmp_path: object) -> None:
    first = ArtifactStore(tmp_path / "first")  # type: ignore[operator]
    second = ArtifactStore(tmp_path / "second")  # type: ignore[operator]
    job = _terminal(first)
    with pytest.raises(HandoffError, match="handoff.fact_invalid"):
        project_handoff(job, second)


def test_same_bytes_across_visits_keep_distinct_observations(tmp_path: object) -> None:
    first = ArtifactStore(tmp_path / "first")  # type: ignore[operator]
    second = ArtifactStore(tmp_path / "second")  # type: ignore[operator]
    job_one = _terminal(first, observed_at="2026-09-04T12:00:00Z")
    job_two = _terminal(second, observed_at="2026-09-04T13:00:00Z")
    artifact_one = project_handoff(job_one, first).to_dict()["artifacts"][0]
    artifact_two = project_handoff(job_two, second).to_dict()["artifacts"][0]
    assert artifact_one["sha256"] == artifact_two["sha256"]
    assert artifact_one["artifact_id"] == artifact_two["artifact_id"]
    assert artifact_one["observation_id"] != artifact_two["observation_id"]
