"""Offline end-to-end tests for the minimal Runtime supporting layer."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

import web_listening.runtime.service as service_module
import web_listening.runtime.workflow as workflow_module
from web_listening.artifact.model import ArtifactStoreError, Observation
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.result.errors import ResultValidationError
from web_listening.runtime.jobs import JobRepository, JobStatus
from web_listening.runtime.service import RuntimeService
from web_listening.site_skill.model import SuccessChecks, ToolReference
from web_listening.site_skill.update import create_candidate
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.manifest import ToolCategory, ToolManifest
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
    AcquisitionRedirect,
)
from web_listening.tool_registry.registry import Registry

URL = "https://example.test/report"
ORIGIN = "https://example.test"
PUBLIC_IP = "93.184.216.34"
NOW = "2026-08-25T20:00:00Z"
BODY = b"<html><body>governed runtime</body></html>"


class _Response:
    def __init__(self, status: int, body: bytes = b"", **headers: str) -> None:
        self.status = status
        self.body = body
        self.headers = {
            name.replace("_", "-"): value for name, value in headers.items()
        }
        self.peer_ip = PUBLIC_IP
        self.closed = 0

    def read(self, max_bytes: int) -> bytes:
        return self.body[:max_bytes]

    def close(self) -> None:
        self.closed += 1


class _Transport:
    def __init__(
        self,
        target: _Response | BaseException,
        *,
        cleanup_error: bool = False,
    ) -> None:
        self.robots = _Response(404)
        self.target = target
        self.cleanup_error = cleanup_error
        self.requests: list[str] = []
        self.closed = 0

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> _Response:
        del timeout, addresses
        self.requests.append(url)
        if url.endswith("/robots.txt"):
            return self.robots
        if isinstance(self.target, BaseException):
            raise self.target
        return self.target

    def close(self) -> None:
        self.closed += 1
        if self.cleanup_error:
            raise RuntimeError("private cleanup failure")


def _resolver(_host: str, _port: int) -> tuple[str, ...]:
    return (PUBLIC_IP,)


def _skill(*, scope: Scope | None = None):
    return create_candidate(
        site_key="example",
        version=1,
        previous=None,
        scope=scope
        or Scope(
            seeds=(URL,),
            allowed_origins=(ORIGIN,),
            include_paths=("/**",),
            content_types=(ContentType.HTML,),
        ),
        budgets=Budgets(6, 2 * 1024 * 1024, 30, 1),
        tool=ToolReference(
            WEB_HTTP_MANIFEST.tool_id,
            WEB_HTTP_MANIFEST.version,
            ToolCategory.ACQUISITION,
            frozenset({"http_get"}),
        ),
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
    ).skill


def _request(skill, *, explore_all_tools: bool = False) -> Request:
    return Request(
        Scope(
            seeds=(URL,),
            allowed_origins=(ORIGIN,),
            include_paths=("/**",),
            content_types=(ContentType.HTML,),
        ),
        skill,
        explore_all_tools,
        Budgets(6, 2 * 1024 * 1024, 30, 1),
    )


def _service(
    tmp_path: Path,
    tool: object,
) -> tuple[RuntimeService, ArtifactStore, JobRepository]:
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, tool)
    store = ArtifactStore(tmp_path / "artifacts")
    jobs = JobRepository()
    identifiers = iter((f"job-{index}" for index in range(1, 20)))
    service = RuntimeService(
        registry,
        store,
        jobs,
        clock=lambda: NOW,
        job_id_factory=lambda: next(identifiers),
    )
    return service, store, jobs


@pytest.mark.parametrize("explore_all_tools", [False, True])
def test_no_ai_fake_transport_completes_one_exact_acquisition(
    tmp_path: Path, explore_all_tools: bool
) -> None:
    transports: list[_Transport] = []

    def factory() -> _Transport:
        transport = _Transport(
            _Response(
                200,
                BODY,
                Content_Type="text/html",
                Content_Length=str(len(BODY)),
            )
        )
        transports.append(transport)
        return transport

    tool = WebHttpAcquisitionTool(factory, resolver=_resolver)
    service, store, jobs = _service(tmp_path, tool)

    job = service.run(_request(_skill(), explore_all_tools=explore_all_tools))

    assert job.status is JobStatus.COMPLETED
    assert job.result is not None
    assert job.result.status.value == "completed"
    assert len(job.result.attempts) == 1
    attempt = job.result.attempts[0]
    assert attempt.outcome == "succeeded"
    assert attempt.requests == 1
    assert attempt.bytes_received == len(BODY)
    assert job.result.usage.to_dict() == {
        "requests": 1,
        "bytes_received": len(BODY),
        "runtime_ms": attempt.runtime_ms,
        "tool_attempts": 1,
    }
    assert len(job.result.artifacts) == 1
    evidence = job.result.artifacts[0]
    stored = store.get_observation(evidence.observation_id)
    assert stored.content == BODY
    assert stored.blob.sha256 == hashlib.sha256(BODY).hexdigest()
    assert transports[0].requests == [f"{ORIGIN}/robots.txt", URL]
    assert transports[0].closed == 1
    assert [event.status for event in jobs.events(job.job_id)] == [
        JobStatus.SUBMITTED,
        JobStatus.RUNNING,
        JobStatus.COMPLETED,
    ]
    store.close()


def test_identical_content_deduplicates_blob_but_not_observation(
    tmp_path: Path,
) -> None:
    transports: list[_Transport] = []

    def factory() -> _Transport:
        transport = _Transport(
            _Response(
                200, BODY, Content_Type="text/html", Content_Length=str(len(BODY))
            )
        )
        transports.append(transport)
        return transport

    service, store, _jobs = _service(
        tmp_path, WebHttpAcquisitionTool(factory, resolver=_resolver)
    )

    first = service.run(_request(_skill()))
    second = service.run(_request(_skill()))

    assert first.result is not None and second.result is not None
    first_artifact = first.result.artifacts[0]
    second_artifact = second.result.artifacts[0]
    assert first.job_id != second.job_id
    assert first_artifact.observation_id != second_artifact.observation_id
    assert first_artifact.artifact_id == second_artifact.artifact_id
    assert first_artifact.sha256 == second_artifact.sha256
    assert store.get_observation(first_artifact.observation_id).content == BODY
    assert store.get_observation(second_artifact.observation_id).content == BODY
    assert len(transports) == 2
    assert all(transport.closed == 1 for transport in transports)
    store.close()


@dataclass(slots=True)
class _CountingTool:
    output: AcquisitionOutput | AcquisitionFailure
    manifest: ToolManifest = WEB_HTTP_MANIFEST
    calls: int = 0

    def acquire(
        self, _tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        self.calls += 1
        return self.output


def _successful_output() -> AcquisitionOutput:
    return AcquisitionOutput(
        WEB_HTTP_MANIFEST.tool_id,
        WEB_HTTP_MANIFEST.version,
        URL,
        URL,
        200,
        "text/html",
        BODY,
        hashlib.sha256(BODY).hexdigest(),
        (),
        7,
    )


def test_multiple_seeds_are_rejected_without_silent_partial_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    skill = _skill()
    request = _request(skill)
    request = replace(
        request,
        scope=replace(
            request.scope,
            seeds=(URL, "https://example.test/second"),
        ),
    )
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)
    commits = 0
    commit_observation = store.commit_observation

    def count_commit(proposal: object):
        nonlocal commits
        commits += 1
        return commit_observation(proposal)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "commit_observation", count_commit)

    job = service.run(request)

    assert job.status is JobStatus.REJECTED
    assert job.result is not None
    assert [error.code for error in job.result.errors] == [
        "runtime.single_target_required"
    ]
    assert not job.result.attempts
    assert job.result.usage.to_dict() == {
        "requests": 0,
        "bytes_received": 0,
        "runtime_ms": 0,
        "tool_attempts": 0,
    }
    assert tool.calls == commits == 0
    assert [event.status for event in jobs.events(job.job_id)] == [
        JobStatus.SUBMITTED,
        JobStatus.RUNNING,
        JobStatus.REJECTED,
    ]
    with pytest.raises(ArtifactStoreError) as missing:
        store.read_blob(hashlib.sha256(BODY).hexdigest())
    assert missing.value.code == "blob.not_found"
    store.close()


def test_maximum_length_job_id_remains_a_valid_attempt_identity(
    tmp_path: Path,
) -> None:
    job_id = "j" * 128
    tool = _CountingTool(_successful_output())
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, tool)
    store = ArtifactStore(tmp_path / "artifacts")
    jobs = JobRepository()
    service = RuntimeService(
        registry,
        store,
        jobs,
        clock=lambda: NOW,
        job_id_factory=lambda: job_id,
    )

    job = service.run(_request(_skill()))

    assert job.status is JobStatus.COMPLETED
    assert job.result is not None
    assert len(job.result.attempts) == 1
    assert job.result.attempts[0].attempt_id == job_id
    assert tool.calls == 1
    assert len(job.result.artifacts) == 1
    observation = store.get_observation(job.result.artifacts[0].observation_id)
    assert observation.content == BODY
    assert [event.status for event in jobs.events(job_id)] == [
        JobStatus.SUBMITTED,
        JobStatus.RUNNING,
        JobStatus.COMPLETED,
    ]
    store.close()


def test_policy_rejection_precedes_tool_and_artifact_mutation(tmp_path: Path) -> None:
    expanded = Scope(
        seeds=("https://outside.test/",),
        allowed_origins=("https://outside.test",),
        include_paths=("/**",),
        content_types=(ContentType.HTML,),
    )
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)

    job = service.run(_request(_skill(scope=expanded)))

    assert job.status is JobStatus.REJECTED
    assert job.result is not None
    assert job.result.status.value == "rejected"
    assert [error.code for error in job.result.errors] == ["policy.scope_expansion"]
    assert not job.result.attempts
    assert job.result.usage.to_dict() == {
        "requests": 0,
        "bytes_received": 0,
        "runtime_ms": 0,
        "tool_attempts": 0,
    }
    assert tool.calls == 0
    assert [event.status for event in jobs.events(job.job_id)][-1] is JobStatus.REJECTED
    with pytest.raises(ArtifactStoreError) as missing:
        store.read_blob(hashlib.sha256(BODY).hexdigest())
    assert missing.value.code == "blob.not_found"
    store.close()


def test_transport_failure_is_safe_and_cleanup_cannot_mask_it(tmp_path: Path) -> None:
    transport = _Transport(TimeoutError("private transport"), cleanup_error=True)
    service, store, _jobs = _service(
        tmp_path,
        WebHttpAcquisitionTool(lambda: transport, resolver=_resolver),
    )

    job = service.run(_request(_skill()))

    assert job.status is JobStatus.FAILED
    assert job.result is not None
    assert [error.code for error in job.result.errors] == ["gateway.timeout"]
    assert len(job.result.attempts) == 1
    assert job.result.attempts[0].outcome == "failed"
    assert job.result.attempts[0].error == job.result.errors[0]
    assert job.result.usage.tool_attempts == 1
    assert not job.result.artifacts
    assert transport.closed == 1
    store.close()


def test_explore_all_tools_never_switches_to_another_eligible_tool(
    tmp_path: Path,
) -> None:
    primary = _CountingTool(
        AcquisitionFailure(
            WEB_HTTP_MANIFEST.tool_id,
            WEB_HTTP_MANIFEST.version,
            "gateway.timeout",
        )
    )
    alternate_manifest = replace(WEB_HTTP_MANIFEST, tool_id="acquisition.alternate")
    alternate = _CountingTool(
        replace(
            _successful_output(),
            tool_id=alternate_manifest.tool_id,
        ),
        manifest=alternate_manifest,
    )
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, primary)
    registry.register(alternate_manifest, alternate)
    store = ArtifactStore(tmp_path / "artifacts")
    service = RuntimeService(
        registry,
        store,
        JobRepository(),
        clock=lambda: NOW,
        job_id_factory=lambda: "job-one",
    )

    job = service.run(_request(_skill(), explore_all_tools=True))

    assert job.status is JobStatus.FAILED
    assert job.result is not None
    assert len(job.result.attempts) == 1
    assert job.result.usage.tool_attempts == 1
    assert primary.calls == 1
    assert alternate.calls == 0
    store.close()


def test_redirect_attempt_and_usage_are_preserved_exactly(tmp_path: Path) -> None:
    final_url = "https://example.test/final"
    tool = _CountingTool(
        replace(
            _successful_output(),
            final_url=final_url,
            redirects=(AcquisitionRedirect(URL, final_url, 302),),
        )
    )
    service, store, _jobs = _service(tmp_path, tool)

    job = service.run(_request(_skill()))

    assert job.result is not None
    assert job.result.status.value == "completed"
    assert job.result.attempts[0].requests == 2
    assert job.result.usage.requests == 2
    assert job.result.manifest.current_url == final_url
    assert [redirect.to_url for redirect in job.result.manifest.redirects] == [
        final_url
    ]
    store.close()


def test_artifact_failure_rolls_back_and_retains_attempt_usage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _CountingTool(_successful_output())
    service, store, _jobs = _service(tmp_path, tool)

    def fail_after_rows(stage: str, _observation: object) -> None:
        if stage == "after_rows":
            raise ArtifactStoreError("artifact.injected")

    monkeypatch.setattr(
        ArtifactStore, "_commit_checkpoint", staticmethod(fail_after_rows)
    )

    job = service.run(_request(_skill()))

    assert job.status is JobStatus.FAILED
    assert job.result is not None
    assert [error.code for error in job.result.errors] == ["artifact.injected"]
    assert len(job.result.attempts) == 1
    assert job.result.attempts[0].outcome == "failed"
    assert job.result.attempts[0].requests == 1
    assert job.result.attempts[0].bytes_received == len(BODY)
    assert job.result.usage.to_dict() == {
        "requests": 1,
        "bytes_received": len(BODY),
        "runtime_ms": 7,
        "tool_attempts": 1,
    }
    assert not job.result.artifacts
    assert tool.calls == 1
    with pytest.raises(ArtifactStoreError) as missing:
        store.read_blob(hashlib.sha256(BODY).hexdigest())
    assert missing.value.code == "blob.not_found"
    assert not tuple((store.root / "blobs").rglob("*.blob"))
    store.close()


def test_ordinary_artifact_exception_rolls_back_to_one_safe_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)
    rolled_back_observation_id: str | None = None

    def fail_after_rows(stage: str, _observation: object) -> None:
        nonlocal rolled_back_observation_id
        if stage == "after_rows":
            assert isinstance(_observation, Observation)
            rolled_back_observation_id = _observation.observation_id
            raise RuntimeError("private store implementation failure")

    monkeypatch.setattr(
        ArtifactStore, "_commit_checkpoint", staticmethod(fail_after_rows)
    )

    job = service.run(_request(_skill()))

    assert job.status is JobStatus.FAILED
    assert job.result is not None
    assert [error.code for error in job.result.errors] == [
        "runtime.artifact_commit_failed"
    ]
    assert "private store implementation failure" not in str(job.result.to_dict())
    assert len(job.result.attempts) == 1
    assert job.result.attempts[0].outcome == "failed"
    assert job.result.attempts[0].error == job.result.errors[0]
    assert job.result.usage.to_dict() == {
        "requests": 1,
        "bytes_received": len(BODY),
        "runtime_ms": 7,
        "tool_attempts": 1,
    }
    assert not job.result.artifacts
    assert [event.status for event in jobs.events(job.job_id)] == [
        JobStatus.SUBMITTED,
        JobStatus.RUNNING,
        JobStatus.FAILED,
    ]
    with pytest.raises(ArtifactStoreError) as missing:
        store.read_blob(hashlib.sha256(BODY).hexdigest())
    assert missing.value.code == "blob.not_found"
    assert rolled_back_observation_id is not None
    with pytest.raises(ArtifactStoreError) as missing_observation:
        store.get_observation(rolled_back_observation_id)
    assert missing_observation.value.code == "observation.not_found"
    assert not tuple((store.root / "blobs").rglob("*.blob"))
    store.close()


def test_invalid_attempt_time_is_rejected_before_artifact_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = Registry()
    tool = _CountingTool(_successful_output())
    registry.register(WEB_HTTP_MANIFEST, tool)
    store = ArtifactStore(tmp_path / "artifacts")
    jobs = JobRepository()
    times = iter(
        (
            NOW,
            NOW,
            "2026-08-25T20:00:02Z",
            "2026-08-25T20:00:01Z",
        )
    )
    service = RuntimeService(
        registry,
        store,
        jobs,
        clock=lambda: next(times),
        job_id_factory=lambda: "job-one",
    )
    commits = 0
    commit_observation = store.commit_observation

    def count_commit(proposal: object):
        nonlocal commits
        commits += 1
        return commit_observation(proposal)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "commit_observation", count_commit)

    with pytest.raises(ResultValidationError) as error:
        service.run(_request(_skill()))

    assert error.value.code == "attempt.time_invalid"
    assert commits == 0
    assert [event.status for event in jobs.events("job-one")] == [
        JobStatus.SUBMITTED,
        JobStatus.RUNNING,
    ]
    with pytest.raises(ArtifactStoreError) as missing:
        store.read_blob(hashlib.sha256(BODY).hexdigest())
    assert missing.value.code == "blob.not_found"
    assert not tuple((store.root / "blobs").rglob("*.blob"))
    store.close()


def test_runtime_source_is_one_ordered_orchestrator_without_new_authority() -> None:
    workflow = inspect.getsource(workflow_module.run_single_target)
    source = (
        inspect.getsource(service_module) + inspect.getsource(workflow_module)
    ).lower()

    assert workflow.index("validate_request(") < workflow.index("resolve_site_skill(")
    assert workflow.index("len(request.scope.seeds)") < workflow.index(
        "resolve_site_skill("
    )
    assert workflow.index("resolve_site_skill(") < workflow.index("registry.invoke(")
    assert workflow.index("registry.invoke(") < workflow.index("commit_observation(")
    assert workflow.index("commit_observation(") < workflow.index(
        "manifest_from_observations("
    )
    assert workflow.count("registry.invoke(") == 1
    assert workflow.count("commit_observation(") == 1
    forbidden = (
        "import requests",
        "import httpx",
        "import socket",
        "playwright",
        "subprocess",
        "discoveryinput",
        "transforminput",
        "fallback",
        "._connection",
        "._commit_checkpoint",
    )
    assert all(token not in source for token in forbidden)
