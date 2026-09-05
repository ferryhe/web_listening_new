"""Offline end-to-end tests for the minimal Runtime supporting layer."""

# pylint: disable=missing-class-docstring,missing-function-docstring
# pylint: disable=too-few-public-methods
# pylint: disable=duplicate-code,too-many-lines

from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import quote

import pytest

import web_listening.runtime.service as service_module
import web_listening.runtime.workflow as workflow_module
from web_listening.artifact.model import (
    ArtifactStoreError,
    Observation,
    StoredArtifact,
)
from web_listening.artifact.site_state import SiteState, SiteStatePage
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import (
    Budgets,
    ContentType,
    Request,
    RequestValidationError,
    Scope,
)
from web_listening.request.site_refresh import SiteRefreshRequest
from web_listening.result.errors import ResultValidationError
from web_listening.runtime.jobs import JobRepository, JobStateError, JobStatus
from web_listening.runtime.service import RuntimeService
from web_listening.site_skill.model import (
    DiscoveryRecipe,
    SuccessChecks,
    ToolReference,
)
from web_listening.site_skill.update import create_candidate
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.lifecycle import ToolLifecycle, ToolLifecycleError
from web_listening.tool_registry.manifest import ToolCategory, ToolManifest
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
    AcquisitionRedirect,
)
from web_listening.tool_registry.protocols.transform import (
    TransformFailure,
    TransformOutput,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)

EXTERNAL_TRANSFORM_SOURCE = (
    Path(__file__).parents[1] / "fixtures/tools/external_transform/1.0.0"
)
EXTERNAL_TRANSFORM_ID = "external.basic_html_markdown"

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


def _skill(*, scope: Scope | None = None, max_tool_attempts: int = 1):
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
        budgets=Budgets(6, 2 * 1024 * 1024, 30, max_tool_attempts),
        tool=ToolReference(
            WEB_HTTP_MANIFEST.tool_id,
            WEB_HTTP_MANIFEST.version,
            ToolCategory.ACQUISITION,
            frozenset({"http_get"}),
        ),
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
    ).skill


def _request(
    skill, *, explore_all_tools: bool = False, max_tool_attempts: int = 1
) -> Request:
    return Request(
        Scope(
            seeds=(URL,),
            allowed_origins=(ORIGIN,),
            include_paths=("/**",),
            content_types=(ContentType.HTML,),
        ),
        skill,
        explore_all_tools,
        Budgets(6, 2 * 1024 * 1024, 30, max_tool_attempts),
    )


def _refresh_request() -> SiteRefreshRequest:
    scope = Scope(
        (URL,),
        (ORIGIN,),
        ("/**",),
        (ContentType.HTML,),
    )
    budgets = Budgets(4, 2 * 1024 * 1024, 30, 4)
    tool = ToolReference(
        WEB_HTTP_MANIFEST.tool_id,
        WEB_HTTP_MANIFEST.version,
        ToolCategory.ACQUISITION,
        frozenset({"http_get"}),
    )
    skill = create_candidate(
        site_key="example.test",
        version=1,
        previous=None,
        scope=scope,
        budgets=budgets,
        tool=tool,
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
        discovery=DiscoveryRecipe(
            ToolReference(
                "discovery.html_links",
                "1.0.0",
                ToolCategory.DISCOVERY,
                frozenset({"html_links"}),
            ),
            URL,
        ),
    ).skill
    previous = SiteState(
        "example.test",
        NOW,
        skill.digest,
        True,
        (
            SiteStatePage(
                URL,
                "observation-" + "a" * 32,
                "artifact-" + "b" * 64,
                "sha256:" + "c" * 64,
            ),
        ),
    )
    return SiteRefreshRequest(scope, skill, previous, False, budgets)


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


def test_service_get_handoff_projects_persisted_job(tmp_path: Path) -> None:
    response = _Response(200, BODY, content_type="text/html")
    service, _store, _jobs = _service(
        tmp_path,
        WebHttpAcquisitionTool(lambda: _Transport(response), resolver=_resolver),
    )
    job = service.run(_request(_skill()))

    handoff = service.get_handoff(job.job_id)

    assert handoff.to_dict()["job_id"] == job.job_id
    assert handoff.to_dict()["generated_at"] == job.finished_at


def _file_request(url: str, max_bytes: int) -> Request:
    return Request(
        Scope(
            seeds=(url,),
            allowed_origins=(ORIGIN,),
            include_paths=("/**",),
            content_types=(ContentType.FILE,),
        ),
        None,
        False,
        Budgets(6, max_bytes, 30, 1),
    )


def test_open_registers_active_external_transform_before_builtin(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "runtime-data"
    lifecycle = ToolLifecycle(data_dir)
    lifecycle.install(EXTERNAL_TRANSFORM_SOURCE)
    lifecycle.qualify(ToolCategory.TRANSFORM, EXTERNAL_TRANSFORM_ID, "1.0.0")
    lifecycle.activate(ToolCategory.TRANSFORM, EXTERNAL_TRANSFORM_ID, "1.0.0")

    service = RuntimeService.open(data_dir)
    try:
        transforms = service._registry.query(  # pylint: disable=protected-access
            category=ToolCategory.TRANSFORM
        )
    finally:
        service.close()

    assert tuple(item.tool_id for item in transforms) == (
        EXTERNAL_TRANSFORM_ID,
        "transform.simple_html_markdown",
    )


def test_open_default_workflow_executes_active_external_transform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "runtime-data"
    lifecycle = ToolLifecycle(data_dir)
    lifecycle.install(EXTERNAL_TRANSFORM_SOURCE)
    lifecycle.qualify(ToolCategory.TRANSFORM, EXTERNAL_TRANSFORM_ID, "1.0.0")
    lifecycle.activate(ToolCategory.TRANSFORM, EXTERNAL_TRANSFORM_ID, "1.0.0")
    transport = _Transport(
        _Response(
            200,
            b"<html><body><h1>External</h1></body></html>",
            Content_Type="text/html",
        )
    )
    monkeypatch.setattr(service_module, "PinnedHttpTransport", lambda: transport)
    monkeypatch.setattr(
        service_module,
        "WebHttpAcquisitionTool",
        lambda factory: WebHttpAcquisitionTool(factory, resolver=_resolver),
    )

    service = RuntimeService.open(data_dir)
    try:
        job = service.run(
            _request(
                None,
                max_tool_attempts=2,
            )
        )
    finally:
        service.close()

    assert job.result is not None
    assert job.result.attempts[-1].tool_id == EXTERNAL_TRANSFORM_ID
    assert job.result.attempts[-1].tool_version == "1.0.0"
    assert tuple(item.role for item in job.result.artifacts) == ("source", "derived")


def test_open_does_not_load_external_discovery_or_acquisition(tmp_path: Path) -> None:
    data_dir = tmp_path / "runtime-data"
    (data_dir / "tools/discovery/external.untrusted").mkdir(parents=True)
    (data_dir / "tools/acquisition/external.untrusted").mkdir(parents=True)

    service = RuntimeService.open(data_dir)
    try:
        identities = tuple(
            item.tool_id
            for item in service._registry.query()  # pylint: disable=protected-access
        )
    finally:
        service.close()

    assert "external.untrusted" not in identities


@pytest.mark.parametrize("link", ("tools", "tools/transform"))
def test_open_rejects_dangling_external_transform_tree(
    tmp_path: Path, link: str
) -> None:
    data_dir = tmp_path / "runtime-data"
    data_dir.mkdir()
    path = data_dir / link
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.symlink_to(tmp_path / "missing", target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ToolLifecycleError) as caught:
        RuntimeService.open(data_dir)

    assert caught.value.code == "lifecycle.path_invalid"


def test_large_pdf_within_request_budget_is_persisted_with_complete_evidence(
    tmp_path: Path,
) -> None:
    url = f"{ORIGIN}/report.pdf"
    body = b"%PDF-1.7\n" + b"x" * (3 * 1024 * 1024)
    transport = _Transport(
        _Response(
            200,
            body,
            Content_Type="application/pdf",
            Content_Length=str(len(body)),
        )
    )
    service, store, jobs = _service(
        tmp_path,
        WebHttpAcquisitionTool(lambda: transport, resolver=_resolver),
    )

    job = service.run(_file_request(url, 8 * 1024 * 1024))

    assert job.status is JobStatus.COMPLETED
    assert job.result is not None
    assert job.result.status.value == "completed"
    assert not job.result.errors
    assert len(job.result.artifacts) == 1
    evidence = job.result.artifacts[0]
    digest = hashlib.sha256(body).hexdigest()
    assert (
        evidence.mime_type,
        evidence.size_bytes,
        evidence.sha256,
        evidence.source_url,
    ) == ("application/pdf", len(body), digest, url)
    stored = store.get_observation(evidence.observation_id)
    assert stored.content == body
    assert stored.blob.sha256 == digest
    assert stored.blob.size_bytes == len(body)
    attempt = job.result.attempts[0]
    assert (
        attempt.outcome,
        attempt.tool_id,
        attempt.tool_version,
        attempt.requested_url,
        attempt.final_url,
        attempt.http_status,
        attempt.requests,
        attempt.bytes_received,
    ) == (
        "succeeded",
        WEB_HTTP_MANIFEST.tool_id,
        WEB_HTTP_MANIFEST.version,
        url,
        url,
        200,
        2,
        len(body),
    )
    assert job.result.usage.to_dict() == {
        "requests": 2,
        "bytes_received": len(body),
        "runtime_ms": attempt.runtime_ms,
        "tool_attempts": 1,
    }
    assert job.result.manifest.artifacts == job.result.artifacts
    assert (
        job.result.manifest.mime_type,
        job.result.manifest.size_bytes,
        job.result.manifest.sha256,
    ) == ("application/pdf", len(body), digest)
    assert transport.requests == [f"{ORIGIN}/robots.txt", url]
    assert transport.closed == 1
    assert [event.status for event in jobs.events(job.job_id)] == [
        JobStatus.SUBMITTED,
        JobStatus.RUNNING,
        JobStatus.COMPLETED,
    ]
    store.close()


def test_pdf_over_request_byte_budget_creates_no_artifact_or_observation(
    tmp_path: Path,
) -> None:
    url = f"{ORIGIN}/report.pdf"
    body = b"%PDF-1.7\n" + b"x" * (3 * 1024 * 1024)
    transport = _Transport(
        _Response(
            200,
            body,
            Content_Type="application/pdf",
            Content_Length=str(len(body)),
        )
    )
    service, store, _jobs = _service(
        tmp_path,
        WebHttpAcquisitionTool(lambda: transport, resolver=_resolver),
    )

    job = service.run(_file_request(url, 2 * 1024 * 1024))

    assert job.status is JobStatus.FAILED
    assert job.result is not None
    assert [error.code for error in job.result.errors] == ["budget.bytes"]
    assert not job.result.artifacts
    assert len(job.result.attempts) == 1
    attempt = job.result.attempts[0]
    assert attempt.outcome == "failed"
    assert attempt.error == job.result.errors[0]
    assert (attempt.requests, attempt.bytes_received) == (2, 0)
    assert job.result.usage.to_dict() == {
        "requests": 2,
        "bytes_received": 0,
        "runtime_ms": attempt.runtime_ms,
        "tool_attempts": 1,
    }
    with pytest.raises(ArtifactStoreError) as missing:
        store.read_blob(hashlib.sha256(body).hexdigest())
    assert missing.value.code == "blob.not_found"
    assert not tuple((store.root / "blobs").rglob("*.blob"))
    assert transport.requests == [f"{ORIGIN}/robots.txt", url]
    assert transport.closed == 1
    store.close()


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
    assert attempt.requests == 2
    assert attempt.bytes_received == len(BODY)
    assert job.result.usage.to_dict() == {
        "requests": 2,
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


def test_invalid_attempt_time_is_failed_before_artifact_commit(
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
            "2026-08-25T20:00:03Z",
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
        JobStatus.FAILED,
    ]
    failed = jobs.get("job-one")
    assert failed.failure_code == "runtime.workflow_failed"
    assert failed.result is not None
    assert [error.code for error in failed.result.errors] == ["runtime.workflow_failed"]
    with pytest.raises(ArtifactStoreError) as missing:
        store.read_blob(hashlib.sha256(BODY).hexdigest())
    assert missing.value.code == "blob.not_found"
    assert not tuple((store.root / "blobs").rglob("*.blob"))
    store.close()


def test_failed_terminalization_cannot_mask_primary_workflow_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, _CountingTool(_successful_output()))
    store = ArtifactStore(tmp_path / "artifacts")
    jobs = JobRepository()
    times = iter(
        (
            NOW,
            NOW,
            "2026-08-25T20:00:02Z",
            "2026-08-25T20:00:01Z",
            "2026-08-25T20:00:03Z",
        )
    )
    service = RuntimeService(
        registry,
        store,
        jobs,
        clock=lambda: next(times),
        job_id_factory=lambda: "job-one",
    )
    transition = jobs.transition

    def fail_terminal(
        job_id: str,
        status: JobStatus,
        *,
        at: str,
        result=None,
        failure_code: str | None = None,
    ):
        if status is JobStatus.FAILED:
            raise RuntimeError("private terminalization failure")
        return transition(
            job_id,
            status,
            at=at,
            result=result,
            failure_code=failure_code,
        )

    monkeypatch.setattr(jobs, "transition", fail_terminal)

    with pytest.raises(ResultValidationError) as error:
        service.run(_request(_skill()))

    assert error.value.code == "attempt.time_invalid"
    assert "private terminalization failure" not in str(error.value)
    assert [event.status for event in jobs.events("job-one")] == [
        JobStatus.SUBMITTED,
        JobStatus.RUNNING,
    ]
    with pytest.raises(ArtifactStoreError) as missing:
        store.read_blob(hashlib.sha256(BODY).hexdigest())
    assert missing.value.code == "blob.not_found"
    store.close()


def test_runtime_source_is_one_ordered_orchestrator_without_new_authority() -> None:
    workflow = inspect.getsource(workflow_module.run_single_target)
    transform = inspect.getsource(
        workflow_module._transform_stored_source  # pylint: disable=protected-access
    )
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
        "_transform_stored_source("
    )
    assert workflow.index("_transform_stored_source(") < workflow.index(
        "manifest_from_observations("
    )
    assert workflow.count("registry.invoke(") == 1
    assert workflow.count("commit_observation(") == 1
    assert transform.index("TransformInput(") < transform.index("registry.invoke(")
    assert transform.index("registry.invoke(") < transform.index("commit_observation(")
    assert transform.count("registry.invoke(") == 1
    assert transform.count("commit_observation(") == 1
    forbidden = (
        "import requests",
        "import httpx",
        "import socket",
        "playwright",
        "fallback",
        "._connection",
        "._commit_checkpoint",
    )
    assert all(token not in source for token in forbidden)
    assert "simple_html_markdown" not in inspect.getsource(workflow_module).lower()
    assert "discoveryinput" not in workflow.lower()


def test_open_run_close_reopen_reads_job_and_artifact_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transports: list[_Transport] = []

    def transport_factory() -> _Transport:
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

    monkeypatch.setattr(service_module, "PinnedHttpTransport", transport_factory)
    monkeypatch.setattr(
        service_module,
        "WebHttpAcquisitionTool",
        lambda factory: WebHttpAcquisitionTool(factory, resolver=_resolver),
    )
    data_dir = tmp_path / "runtime-data"
    first = RuntimeService.open(data_dir)
    job = first.run(_request(_skill()))
    assert job.result is not None
    artifact_id = job.result.artifacts[0].artifact_id
    first.close()
    requests_after_run = tuple(transports[0].requests)

    reopened = RuntimeService.open(data_dir)
    restored_job = reopened.get_job(job.job_id)
    restored_artifact = reopened.read_artifact(artifact_id)
    reopened.close()

    assert restored_job == job
    assert restored_artifact == StoredArtifact(
        artifact_id=artifact_id,
        blob_sha256=hashlib.sha256(BODY).hexdigest(),
        size_bytes=len(BODY),
        mime_type="text/html",
        content=BODY,
    )
    assert len(transports) == 1
    assert tuple(transports[0].requests) == requests_after_run
    files = {
        path.relative_to(data_dir).as_posix()
        for path in data_dir.rglob("*")
        if path.is_file()
    }
    assert "jobs.sqlite3" in files
    assert "artifacts/artifact.sqlite3" in files
    assert len(files) == 3
    assert len(files - {"jobs.sqlite3", "artifacts/artifact.sqlite3"}) == 1
    assert next(
        iter(files - {"jobs.sqlite3", "artifacts/artifact.sqlite3"})
    ).startswith("artifacts/blobs/")


def test_get_job_and_read_artifact_are_identity_preserving_delegations() -> None:
    expected_job = object()
    expected_artifact = object()

    class Jobs:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def get(self, job_id: str) -> object:
            self.calls.append(job_id)
            return expected_job

    class Store:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def read_artifact(self, artifact_id: str) -> object:
            self.calls.append(artifact_id)
            return expected_artifact

    jobs = Jobs()
    store = Store()
    service = RuntimeService(object(), store, jobs)  # type: ignore[arg-type]

    assert service.get_job("job-one") is expected_job
    assert service.read_artifact("artifact-one") is expected_artifact
    assert jobs.calls == ["job-one"]
    assert store.calls == ["artifact-one"]


def test_explore_site_is_one_public_delegation_with_fresh_run_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = object()
    calls: list[tuple[object, object, object, str, object]] = []
    registry = object()
    store = object()
    jobs = JobRepository()
    service = RuntimeService(
        registry,  # type: ignore[arg-type]
        store,  # type: ignore[arg-type]
        jobs,
        clock=lambda: NOW,
        job_id_factory=lambda: "job-site-explore",
    )
    request = _request(None)

    def fake_run(request_arg, registry_arg, store_arg, *, run_id, clock):
        calls.append((request_arg, registry_arg, store_arg, run_id, clock))
        return expected

    monkeypatch.setattr(service_module, "run_site_explore", fake_run)

    assert service.explore_site(request) is expected
    assert len(calls) == 1
    assert calls[0][:4] == (request, registry, store, "job-site-explore")
    assert calls[0][4]() == NOW


def test_refresh_site_is_one_public_delegation_with_fresh_run_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = object()
    calls: list[tuple[object, object, object, str, object]] = []
    registry = object()
    store = object()
    service = RuntimeService(
        registry,  # type: ignore[arg-type]
        store,  # type: ignore[arg-type]
        JobRepository(),
        clock=lambda: NOW,
        job_id_factory=lambda: "job-site-refresh",
    )
    request = object()

    def fake_run(request_arg, registry_arg, store_arg, *, run_id, clock):
        calls.append((request_arg, registry_arg, store_arg, run_id, clock))
        return expected

    monkeypatch.setattr(service_module, "run_site_refresh", fake_run)

    assert service.refresh_site(request) is expected  # type: ignore[arg-type]
    assert len(calls) == 1
    assert calls[0][:4] == (request, registry, store, "job-site-refresh")
    assert calls[0][4]() == NOW


def test_refresh_service_rejects_sensitive_previous_state_before_tool_io(
    tmp_path: Path,
) -> None:
    request = _refresh_request()
    object.__setattr__(
        request.previous_state.pages[0],
        "canonical_url",
        "https://example.test/report?token=placeholder-value",
    )
    tool = _CountingTool(_successful_output())
    service, store, _jobs = _service(tmp_path, tool)

    with pytest.raises(
        RequestValidationError, match="^site_state.sensitive_data$"
    ) as caught:
        service.refresh_site(request)

    assert tool.calls == 0
    assert "placeholder-value" not in str(caught.value)
    service.close()
    store.close()


def test_refresh_service_rejects_absolute_path_previous_state_before_tool_io(
    tmp_path: Path,
) -> None:
    request = _refresh_request()
    encoded = quote("".join(chr(item) for item in (67, 58, 47, 112)), safe="")
    object.__setattr__(
        request.previous_state.pages[0],
        "canonical_url",
        f"https://example.test/report?next={encoded}",
    )
    tool = _CountingTool(_successful_output())
    service, store, _jobs = _service(tmp_path, tool)

    with pytest.raises(
        RequestValidationError, match="^site_state.absolute_path$"
    ) as caught:
        service.refresh_site(request)

    assert caught.value.args == ("site_state.absolute_path",)
    assert tool.calls == 0
    service.close()
    store.close()


def test_refresh_service_accepts_public_natural_language_slug(
    tmp_path: Path,
) -> None:
    request = _refresh_request()
    public_url = (
        "https://example.test/"
        "skilled-professionals-and-scientists-in-climate-assessment"
    )
    object.__setattr__(
        request.previous_state.pages[0],
        "canonical_url",
        public_url,
    )
    tool = _CountingTool(_successful_output())
    service, store, _jobs = _service(tmp_path, tool)

    result = service.refresh_site(request)

    assert result.previous_state.pages[0].canonical_url == public_url
    assert tool.calls > 0
    service.close()
    store.close()


def test_open_registers_builtin_discovery_for_site_workflows(tmp_path: Path) -> None:
    service = RuntimeService.open(tmp_path / "runtime-data")

    discovery = service._registry.query(  # pylint: disable=protected-access
        category=ToolCategory.DISCOVERY
    )

    assert [(item.tool_id, item.version) for item in discovery] == [
        ("discovery.html_file_links", "1.0.0"),
        ("discovery.html_links", "1.0.0"),
        ("discovery.rss", "1.0.0"),
        ("discovery.sitemap", "1.0.0"),
    ]
    service.close()


def test_close_is_idempotent_guards_operations_and_does_not_close_injections(
    tmp_path: Path,
) -> None:
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)

    service.close()
    service.close()

    for operation in (
        lambda: service.run(_request(_skill())),
        lambda: service.explore_site(_request(None)),
        lambda: service.refresh_site(object()),  # type: ignore[arg-type]
        lambda: service.get_job("job-one"),
        lambda: service.read_artifact("artifact-one"),
    ):
        with pytest.raises(RuntimeError, match="^runtime.closed$"):
            operation()
    assert jobs.submit("job-after-close", at=NOW).status is JobStatus.SUBMITTED
    with pytest.raises(ArtifactStoreError) as missing:
        store.read_artifact("artifact-" + "0" * 64)
    assert missing.value.code == "artifact.not_found"
    store.close()


def test_open_failure_closes_every_partially_created_resource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    closed: list[str] = []

    class Tool:
        manifest = WEB_HTTP_MANIFEST

        def acquire(self, _tool_input: AcquisitionInput) -> AcquisitionFailure:
            return AcquisitionFailure(
                WEB_HTTP_MANIFEST.tool_id,
                WEB_HTTP_MANIFEST.version,
                "test.unused",
            )

        def close(self) -> None:
            closed.append("tool")

    class Store:
        def __init__(self, _root: Path) -> None:
            pass

        def close(self) -> None:
            closed.append("store")

    def fail_jobs(_path: Path) -> JobRepository:
        raise OSError("injected open failure")

    monkeypatch.setattr(service_module, "WebHttpAcquisitionTool", lambda *_: Tool())
    monkeypatch.setattr(service_module, "ArtifactStore", Store)
    monkeypatch.setattr(service_module, "JobRepository", fail_jobs)

    with pytest.raises(OSError, match="injected open failure"):
        RuntimeService.open(tmp_path / "runtime-data")

    assert closed == ["store", "tool"]


def test_open_owned_resources_are_closed_once(tmp_path: Path) -> None:
    service = RuntimeService.open(tmp_path / "runtime-data")
    store = service._artifact_store  # pylint: disable=protected-access
    jobs = service._jobs  # pylint: disable=protected-access

    service.close()
    service.close()

    with pytest.raises(ArtifactStoreError) as store_error:
        store.read_artifact("artifact-" + "0" * 64)
    with pytest.raises(JobStateError) as jobs_error:
        jobs.get("job-one")
    assert store_error.value.code == "repository.closed"
    assert jobs_error.value.code == "repository.closed"


def test_submit_claim_execute_and_idempotent_replay_use_persisted_request(
    tmp_path: Path,
) -> None:
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)
    request = _request(_skill())
    submitted = service.submit(request, caller_id="caller-one", idempotency_key="key-1")
    replay = service.submit(request, caller_id="caller-one", idempotency_key="key-1")
    claim = jobs.claim_next("worker-one", at=NOW, lease_deadline="2026-08-25T20:01:00Z")

    assert replay.job_id == submitted.job_id
    assert claim is not None and claim.request == request
    finished = service.execute_submitted(claim.job.job_id, claim.request, lambda: False)
    assert finished.status is JobStatus.COMPLETED
    assert tool.calls == 1
    assert len(finished.result.artifacts) == 1  # type: ignore[union-attr]
    store.close()


def test_submission_identity_precedes_admission_narrowing(tmp_path: Path) -> None:
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)
    request_101 = replace(
        _request(_skill()),
        budgets=Budgets(101, 2 * 1024 * 1024, 30, 1),
    )
    request_100 = replace(
        request_101, budgets=replace(request_101.budgets, max_requests=100)
    )

    submitted = service.submit(
        request_101, caller_id="caller-one", idempotency_key="budget-key"
    )
    with pytest.raises(JobStateError, match="^idempotency.conflict$"):
        service.submit(
            request_100, caller_id="caller-one", idempotency_key="budget-key"
        )
    claim = jobs.claim_next("worker-one", at=NOW, lease_deadline="2026-08-25T20:01:00Z")

    assert (
        submitted.request_json is not None
        and '"max_requests":101' in submitted.request_json
    )
    assert claim is not None and claim.request.budgets.max_requests == 100
    store.close()


def test_canonical_equivalent_request_replays_before_admission(tmp_path: Path) -> None:
    tool = _CountingTool(_successful_output())
    service, store, _jobs = _service(tmp_path, tool)
    request = _request(_skill())
    equivalent = replace(
        request,
        scope=replace(
            request.scope,
            seeds=("HTTPS://EXAMPLE.TEST:443/report",),
            allowed_origins=("HTTPS://EXAMPLE.TEST:443",),
        ),
    )

    first = service.submit(request, caller_id="caller-one", idempotency_key="same")
    replay = service.submit(equivalent, caller_id="caller-one", idempotency_key="same")

    assert replay == first
    store.close()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("tokenizer", "wordpiece"),
        ("authorization_date", "2026-09-05"),
        ("sessionidentifier", "public-record"),
    ],
)
def test_safe_nearby_query_keys_execute_after_restart(
    tmp_path: Path, key: str, value: str
) -> None:
    target = f"{URL}?{key}={value}"
    output = replace(_successful_output(), requested_url=target, final_url=target)
    tool = _CountingTool(output)
    service, store, jobs = _service(tmp_path, tool)
    request = replace(
        _request(None),
        scope=replace(_request(None).scope, seeds=(target,)),
    )
    service.submit(request, caller_id="caller", idempotency_key=key)
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")

    assert claim is not None
    finished = service.execute_submitted(claim.job.job_id, claim.request, lambda: False)
    assert finished.status is JobStatus.COMPLETED
    assert tool.calls == 1
    store.close()


def test_cancel_before_execution_has_zero_tool_calls_and_strict_failed_result(
    tmp_path: Path,
) -> None:
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)
    submitted = service.submit(
        _request(_skill()), caller_id="caller-one", idempotency_key="key-1"
    )
    service.cancel(submitted.job_id)
    claim = jobs.claim_next("worker-one", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    assert claim is not None

    finished = service.execute_submitted(claim.job.job_id, claim.request, lambda: False)

    assert finished.status is JobStatus.FAILED
    assert finished.failure_code == "runtime.cancelled"
    assert finished.result is not None
    assert finished.result.usage.requests == 0
    assert not finished.result.artifacts
    assert tool.calls == 0
    store.close()


@pytest.mark.parametrize(
    ("acquisition", "fault", "expected_top_error", "expected_attempt_error"),
    [
        (
            AcquisitionFailure(
                WEB_HTTP_MANIFEST.tool_id,
                WEB_HTTP_MANIFEST.version,
                "gateway.timeout",
                requests=1,
                runtime_ms=7,
            ),
            "durable-cancel",
            "runtime.cancelled",
            "gateway.timeout",
        ),
        (
            AcquisitionFailure(
                WEB_HTTP_MANIFEST.tool_id,
                WEB_HTTP_MANIFEST.version,
                "gateway.timeout",
                requests=1,
                runtime_ms=7,
            ),
            "callback-error",
            "runtime.workflow_failed",
            "gateway.timeout",
        ),
        (
            _successful_output(),
            "callback-error",
            "runtime.workflow_failed",
            "runtime.workflow_failed",
        ),
    ],
    ids=("failed-durable-cancel", "failed-callback-error", "success-control"),
)
# pylint: disable-next=too-many-locals
def test_post_invocation_fault_preserves_genuine_attempt_error_and_usage(
    tmp_path: Path,
    acquisition: AcquisitionOutput | AcquisitionFailure,
    fault: str,
    expected_top_error: str,
    expected_attempt_error: str,
) -> None:
    primary = _CountingTool(acquisition)
    alternate_manifest = replace(WEB_HTTP_MANIFEST, tool_id="acquisition.alternate")
    alternate = _CountingTool(
        replace(_successful_output(), tool_id=alternate_manifest.tool_id),
        manifest=alternate_manifest,
    )
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, primary)
    registry.register(alternate_manifest, alternate)
    store = ArtifactStore(tmp_path / "artifacts")
    jobs = JobRepository(tmp_path / "jobs.sqlite3")
    service = RuntimeService(
        registry,
        store,
        jobs,
        clock=lambda: NOW,
        job_id_factory=lambda: "job-one",
    )
    submitted = service.submit(
        _request(
            _skill(max_tool_attempts=2),
            explore_all_tools=True,
            max_tool_attempts=2,
        ),
        caller_id="caller",
        idempotency_key=fault,
    )
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    callback_error = RuntimeError("deterministic post-invocation callback failure")
    checks = 0

    def should_cancel() -> bool:
        nonlocal checks
        checks += 1
        if checks != 2:
            return False
        if fault == "durable-cancel":
            service.cancel(submitted.job_id)
            return True
        raise callback_error

    assert claim is not None
    if fault == "callback-error":
        with pytest.raises(RuntimeError) as raised:
            service.execute_submitted(claim.job.job_id, claim.request, should_cancel)
        assert raised.value is callback_error
        finished = jobs.get(claim.job.job_id)
        assert checks == 2
    else:
        finished = service.execute_submitted(
            claim.job.job_id, claim.request, should_cancel
        )
        assert checks == 3

    assert finished.status is JobStatus.FAILED
    assert finished.failure_code == expected_top_error
    assert finished.result is not None
    assert [error.code for error in finished.result.errors] == [expected_top_error]
    assert len(finished.result.attempts) == 1
    assert finished.result.attempts[0].error is not None
    assert finished.result.attempts[0].error.code == expected_attempt_error
    assert finished.result.usage.to_dict() == {
        "requests": 1,
        "bytes_received": (
            0 if isinstance(acquisition, AcquisitionFailure) else len(BODY)
        ),
        "runtime_ms": 7,
        "tool_attempts": 1,
    }
    assert finished.result.manifest.attempts == finished.result.attempts
    assert finished.result.manifest.usage == finished.result.usage
    assert primary.calls == 1
    assert alternate.calls == 0
    store.close()
    jobs.close()


@pytest.mark.parametrize(
    ("fault", "expected_top_error"),
    [
        ("durable-cancel", "runtime.cancelled"),
        ("callback-error", "runtime.workflow_failed"),
    ],
)
# pylint: disable-next=too-many-locals,too-many-statements
def test_redirected_success_post_invocation_fault_preserves_terminal_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
    expected_top_error: str,
) -> None:
    intermediate_url = "https://example.test/intermediate"
    final_url = "https://example.test/final"
    acquisition = replace(
        _successful_output(),
        final_url=final_url,
        redirects=(
            AcquisitionRedirect(URL, intermediate_url, 301),
            AcquisitionRedirect(intermediate_url, final_url, 302),
        ),
    )
    primary = _CountingTool(acquisition)
    alternate_manifest = replace(WEB_HTTP_MANIFEST, tool_id="acquisition.alternate")
    alternate = _CountingTool(
        replace(_successful_output(), tool_id=alternate_manifest.tool_id),
        manifest=alternate_manifest,
    )
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, primary)
    registry.register(alternate_manifest, alternate)
    store = ArtifactStore(tmp_path / "artifacts")
    jobs = JobRepository(tmp_path / "jobs.sqlite3")
    service = RuntimeService(
        registry,
        store,
        jobs,
        clock=lambda: NOW,
        job_id_factory=lambda: "job-one",
    )
    submitted = service.submit(
        _request(
            _skill(max_tool_attempts=2),
            explore_all_tools=True,
            max_tool_attempts=2,
        ),
        caller_id="caller",
        idempotency_key=f"redirect-{fault}",
    )
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    callback_error = RuntimeError("deterministic redirected callback failure")
    checks = 0
    commits = 0
    commit_observation = store.commit_observation

    def count_commit(proposal: object):
        nonlocal commits
        commits += 1
        return commit_observation(proposal)  # type: ignore[arg-type]

    def should_cancel() -> bool:
        nonlocal checks
        checks += 1
        if checks != 2:
            return False
        if fault == "durable-cancel":
            service.cancel(submitted.job_id)
            return True
        raise callback_error

    monkeypatch.setattr(store, "commit_observation", count_commit)
    assert claim is not None
    if fault == "callback-error":
        with pytest.raises(RuntimeError) as raised:
            service.execute_submitted(claim.job.job_id, claim.request, should_cancel)
        assert raised.value is callback_error
        finished = jobs.get(claim.job.job_id)
        assert checks == 2
    else:
        finished = service.execute_submitted(
            claim.job.job_id, claim.request, should_cancel
        )
        assert checks == 3

    assert finished.status is JobStatus.FAILED
    assert finished.failure_code == expected_top_error
    assert finished.result is not None
    assert [error.code for error in finished.result.errors] == [expected_top_error]
    manifest = finished.result.manifest
    assert manifest.requested_url == URL
    assert manifest.current_url == final_url
    assert manifest.final_url is None
    assert tuple(
        (redirect.order, redirect.from_url, redirect.to_url, redirect.http_status)
        for redirect in manifest.redirects
    ) == (
        (0, URL, intermediate_url, 301),
        (1, intermediate_url, final_url, 302),
    )
    assert len(finished.result.attempts) == 1
    attempt = finished.result.attempts[0]
    assert attempt.requested_url == URL
    assert attempt.final_url == final_url
    assert attempt.http_status == 200
    assert attempt.error is not None
    assert attempt.error.code == expected_top_error
    assert finished.result.usage.to_dict() == {
        "requests": 3,
        "bytes_received": len(BODY),
        "runtime_ms": 7,
        "tool_attempts": 1,
    }
    assert manifest.attempts == finished.result.attempts
    assert manifest.usage == finished.result.usage
    assert not finished.result.artifacts
    assert primary.calls == 1
    assert alternate.calls == 0
    assert commits == 0
    store.close()
    jobs.close()


def test_persistent_cancellation_callback_exception_terminalizes_claim(
    tmp_path: Path,
) -> None:
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)
    service.submit(_request(_skill()), caller_id="caller", idempotency_key="callback")
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    callback_error = RuntimeError("deterministic cancellation callback exception")
    checks = 0

    def should_cancel() -> bool:
        nonlocal checks
        checks += 1
        raise callback_error

    assert claim is not None
    with pytest.raises(RuntimeError) as raised:
        service.execute_submitted(claim.job.job_id, claim.request, should_cancel)

    assert raised.value is callback_error
    assert checks == 1
    finished = jobs.get(claim.job.job_id)
    assert finished.status is JobStatus.FAILED
    assert finished.failure_code == "runtime.workflow_failed"
    assert finished.result is not None
    assert [error.code for error in finished.result.errors] == [
        "runtime.workflow_failed"
    ]
    assert not finished.result.artifacts
    assert finished.result.usage.requests == 0
    assert tool.calls == 0
    store.close()


def test_run_workflow_exception_with_sensitive_seed_still_terminalizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, store, jobs = _service(tmp_path, _CountingTool(_successful_output()))
    sensitive_url = f"{URL}?access_token=private-value"
    request = replace(
        _request(None),
        scope=replace(_request(None).scope, seeds=(sensitive_url,)),
    )
    workflow_error = RuntimeError("deterministic workflow exception")

    def fail_workflow(*_args, **_kwargs):
        raise workflow_error

    monkeypatch.setattr(service_module, "run_single_target", fail_workflow)

    with pytest.raises(RuntimeError) as raised:
        service.run(request)

    assert raised.value is workflow_error
    finished = jobs.get("job-1")
    assert finished.status is JobStatus.FAILED
    assert finished.failure_code == "runtime.workflow_failed"
    assert finished.result is not None
    assert finished.result.manifest.requested_url == "https://invalid.invalid/"
    assert sensitive_url not in str(finished.result.to_dict())
    store.close()


def test_async_workflow_exception_with_path_like_seed_still_terminalizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, store, jobs = _service(tmp_path, _CountingTool(_successful_output()))
    path_like_url = f"{URL}?next=/root/private"
    request = replace(
        _request(None),
        scope=replace(_request(None).scope, seeds=(path_like_url,)),
    )
    service.submit(request, caller_id="caller", idempotency_key="path-like")
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    workflow_error = RuntimeError("deterministic async workflow exception")

    def fail_workflow(*_args, **_kwargs):
        raise workflow_error

    monkeypatch.setattr(service_module, "run_single_target", fail_workflow)
    assert claim is not None

    with pytest.raises(RuntimeError) as raised:
        service.execute_submitted(claim.job.job_id, claim.request, lambda: False)

    assert raised.value is workflow_error
    finished = jobs.get(claim.job.job_id)
    assert finished.status is JobStatus.FAILED
    assert finished.failure_code == "runtime.workflow_failed"
    assert finished.result is not None
    assert finished.result.manifest.requested_url == "https://invalid.invalid/"
    assert path_like_url not in str(finished.result.to_dict())
    store.close()


def test_async_exception_result_uses_terminalization_timestamp(tmp_path: Path) -> None:
    tool = _CountingTool(
        AcquisitionFailure(
            WEB_HTTP_MANIFEST.tool_id,
            WEB_HTTP_MANIFEST.version,
            "gateway.timeout",
            requests=1,
            runtime_ms=7,
        )
    )
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, tool)
    store = ArtifactStore(tmp_path / "artifacts")
    jobs = JobRepository()
    times = iter(f"2026-08-25T20:00:{second:02d}Z" for second in range(60))
    service = RuntimeService(
        registry,
        store,
        jobs,
        clock=lambda: next(times),
        job_id_factory=lambda: "job-one",
    )
    service.submit(_request(_skill()), caller_id="caller", idempotency_key="timestamp")
    claim = jobs.claim_next(
        "worker", at="2026-08-25T20:00:01Z", lease_deadline="2026-08-25T20:01:00Z"
    )
    callback_error = RuntimeError("deterministic post-invocation callback failure")
    checks = 0

    def should_cancel() -> bool:
        nonlocal checks
        checks += 1
        if checks == 2:
            raise callback_error
        return False

    assert claim is not None
    with pytest.raises(RuntimeError) as raised:
        service.execute_submitted(claim.job.job_id, claim.request, should_cancel)

    assert raised.value is callback_error
    finished = jobs.get(claim.job.job_id)
    assert finished.status is JobStatus.FAILED
    assert finished.result is not None
    assert finished.result.manifest.generated_at == finished.finished_at
    assert finished.failure_code == "runtime.workflow_failed"
    store.close()


def test_run_empty_seed_request_preserves_rejection_and_terminalizes(
    tmp_path: Path,
) -> None:
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)
    request = replace(_request(None), scope=replace(_request(None).scope, seeds=()))

    finished = service.run(request)

    assert finished.status is JobStatus.REJECTED
    assert finished.failure_code == "scope.empty_seeds"
    assert finished.result is not None
    assert [error.code for error in finished.result.errors] == ["scope.empty_seeds"]
    assert finished.result.manifest.requested_url == "https://invalid.invalid/"
    assert tool.calls == 0
    assert jobs.get(finished.job_id) == finished
    store.close()


@pytest.mark.parametrize(
    (
        "checkpoint",
        "expected_status",
        "expected_roles",
        "expected_attempts",
        "expected_usage",
        "expected_tool_calls",
        "expected_transform_calls",
    ),
    [
        (1, JobStatus.FAILED, (), (), (0, 0, 0, 0), 0, 0),
        (
            2,
            JobStatus.FAILED,
            (),
            (("failed", "runtime.workflow_failed"),),
            (1, 49, 7, 1),
            1,
            0,
        ),
        (
            3,
            JobStatus.FAILED,
            (),
            (("failed", "runtime.workflow_failed"),),
            (1, 49, 7, 1),
            1,
            0,
        ),
        (
            4,
            JobStatus.PARTIAL,
            ("source",),
            (("succeeded", None),),
            (1, 49, 7, 1),
            1,
            0,
        ),
        (
            5,
            JobStatus.PARTIAL,
            ("source",),
            (("succeeded", None),),
            (1, 49, 7, 1),
            1,
            0,
        ),
        (
            6,
            JobStatus.PARTIAL,
            ("source",),
            (("succeeded", None), ("failed", "runtime.workflow_failed")),
            (1, 49, 18, 2),
            1,
            1,
        ),
        (
            7,
            JobStatus.PARTIAL,
            ("source", "derived"),
            (("succeeded", None), ("succeeded", None)),
            (1, 49, 18, 2),
            1,
            1,
        ),
        (
            8,
            JobStatus.PARTIAL,
            ("source", "derived"),
            (("succeeded", None), ("succeeded", None)),
            (1, 49, 18, 2),
            1,
            1,
        ),
    ],
    ids=(
        "before-acquisition",
        "after-acquisition",
        "before-source-commit",
        "after-source-commit",
        "before-transform",
        "after-transform",
        "after-derived-commit",
        "after-workflow",
    ),
)
# pylint: disable-next=too-many-locals,too-many-arguments,too-many-positional-arguments
def test_callback_exception_preserves_exact_committed_evidence_without_cancel(
    tmp_path: Path,
    checkpoint: int,
    expected_status: JobStatus,
    expected_roles: tuple[str, ...],
    expected_attempts: tuple[tuple[str, str | None], ...],
    expected_usage: tuple[int, int, int, int],
    expected_tool_calls: int,
    expected_transform_calls: int,
) -> None:
    transform_body = b"<html><body>one two three four five</body></html>"
    markdown_body = b"one two three four five\n"
    tool = _CountingTool(
        replace(
            _successful_output(),
            body=transform_body,
            sha256=hashlib.sha256(transform_body).hexdigest(),
            bytes_received=len(transform_body),
        )
    )
    service, store, jobs = _service(tmp_path, tool)

    class CountingTransform(SimpleHtmlMarkdownTransform):
        calls = 0

        def transform(self, tool_input) -> TransformOutput:
            self.calls += 1
            transformed = super().transform(tool_input)
            assert isinstance(transformed, TransformOutput)
            return replace(transformed, runtime_ms=11)

    transform = CountingTransform()
    service._registry.register(  # pylint: disable=protected-access
        SIMPLE_HTML_MARKDOWN_MANIFEST, transform
    )
    service.submit(
        _request(_skill(max_tool_attempts=2), max_tool_attempts=2),
        caller_id="caller",
        idempotency_key=f"late-{checkpoint}",
    )
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    callback_error = RuntimeError(f"callback failed at checkpoint {checkpoint}")
    checks = 0

    def should_cancel() -> bool:
        nonlocal checks
        checks += 1
        if checks == checkpoint:
            raise callback_error
        return False

    assert claim is not None
    with pytest.raises(RuntimeError) as raised:
        service.execute_submitted(claim.job.job_id, claim.request, should_cancel)

    assert raised.value is callback_error
    assert checks == checkpoint
    finished = jobs.get(claim.job.job_id)
    assert finished.status is expected_status
    assert finished.failure_code == "runtime.workflow_failed"
    assert finished.result is not None
    assert (
        tuple(artifact.role for artifact in finished.result.artifacts) == expected_roles
    )
    assert [error.code for error in finished.result.errors] == [
        "runtime.workflow_failed"
    ]
    assert (
        tuple(
            (
                attempt.outcome,
                None if attempt.error is None else attempt.error.code,
            )
            for attempt in finished.result.attempts
        )
        == expected_attempts
    )
    assert (
        finished.result.usage.requests,
        finished.result.usage.bytes_received,
        finished.result.usage.runtime_ms,
        finished.result.usage.tool_attempts,
    ) == expected_usage
    assert finished.result.manifest.attempts == finished.result.attempts
    assert finished.result.manifest.usage == finished.result.usage
    observations = tuple(
        store.get_observation(artifact.observation_id)
        for artifact in finished.result.artifacts
    )
    expected_contents = {
        (): (),
        ("source",): (transform_body,),
        ("source", "derived"): (transform_body, markdown_body),
    }
    assert tuple(observation.content for observation in observations) == (
        expected_contents[expected_roles]
    )
    assert tuple(observation.artifact.role.value for observation in observations) == (
        expected_roles
    )
    assert tuple(len(observation.lineage) for observation in observations) == (
        {
            (): (),
            ("source",): (0,),
            ("source", "derived"): (
                0,
                1,
            ),
        }[expected_roles]
    )
    if len(observations) == 2:
        assert observations[1].lineage[0].source_observation_id == (
            observations[0].observation.observation_id
        )
        assert observations[1].lineage[0].source_artifact_id == (
            observations[0].artifact.artifact_id
        )
    assert (tool.calls, transform.calls) == (
        expected_tool_calls,
        expected_transform_calls,
    )
    assert jobs.get(claim.job.job_id) == finished
    store.close()


@pytest.mark.parametrize(
    ("malformed_request", "expected_code", "rejected_values"),
    [
        (object(), "request.invalid", ()),
        (replace(_request(None), scope=None), "scope.invalid", ()),
        (replace(_request(None), scope=object()), "scope.invalid", ()),
        (
            replace(
                _request(None),
                scope=replace(_request(None).scope, seeds=(object(),)),
            ),
            "scope.url_invalid",
            (),
        ),
        (
            replace(_request(None), scope=replace(_request(None).scope, seeds=("",))),
            "scope.url_invalid",
            (),
        ),
        (
            replace(
                _request(None),
                scope=replace(_request(None).scope, seeds=("not-a-url",)),
            ),
            "scope.url_invalid",
            ("not-a-url",),
        ),
        (
            replace(
                _request(None),
                scope=replace(
                    _request(None).scope,
                    seeds=("https://example.test/report?next=/root/private",),
                ),
                budgets=None,
            ),
            "budget.invalid",
            ("/root/private",),
        ),
        (
            replace(
                _request(None),
                scope=replace(
                    _request(None).scope,
                    seeds=("https://example.test/report?token=private-value",),
                ),
                budgets=None,
            ),
            "budget.invalid",
            ("token", "private-value"),
        ),
        (
            replace(
                _request(None),
                scope=replace(
                    _request(None).scope,
                    seeds=(
                        "https://example.test/report?refresh%5Ftoken=private-value",
                    ),
                ),
                budgets=None,
            ),
            "budget.invalid",
            ("refresh%5Ftoken", "refresh_token", "private-value"),
        ),
    ],
    ids=(
        "non-request",
        "scope-none",
        "scope-object",
        "seed-object",
        "seed-empty",
        "seed-invalid-url",
        "absolute-path-query",
        "sensitive-query",
        "encoded-sensitive-query",
    ),
)
def test_run_malformed_request_returns_strict_terminal_rejection(
    tmp_path: Path,
    malformed_request: object,
    expected_code: str,
    rejected_values: tuple[str, ...],
) -> None:
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)

    finished = service.run(malformed_request)  # type: ignore[arg-type]

    assert finished.status is JobStatus.REJECTED
    assert finished.failure_code == expected_code
    assert finished.result is not None
    assert finished.result.status.value == "rejected"
    assert [error.code for error in finished.result.errors] == [expected_code]
    assert finished.result.manifest.requested_url == "https://invalid.invalid/"
    assert finished.result.manifest.current_url == "https://invalid.invalid/"
    assert not finished.result.artifacts
    assert finished.result.usage.to_dict() == {
        "requests": 0,
        "bytes_received": 0,
        "runtime_ms": 0,
        "tool_attempts": 0,
    }
    persisted_result = str(finished.result.to_dict())
    assert all(value not in persisted_result for value in rejected_values)
    assert tool.calls == 0
    assert jobs.get(finished.job_id) == finished
    store.close()


@pytest.mark.parametrize(
    ("checkpoint", "expected_artifacts"),
    [(4, 1), (6, 1), (7, 2), (8, 2)],
    ids=("source-commit", "post-transform", "derived-commit", "post-workflow"),
)
def test_persisting_callback_exception_preserves_committed_cancellation_evidence(
    tmp_path: Path, checkpoint: int, expected_artifacts: int
) -> None:
    transform_body = b"<html><body>one two three four five</body></html>"
    tool = _CountingTool(
        replace(
            _successful_output(),
            body=transform_body,
            sha256=hashlib.sha256(transform_body).hexdigest(),
            bytes_received=len(transform_body),
        )
    )
    service, store, jobs = _service(tmp_path, tool)
    service._registry.register(  # pylint: disable=protected-access
        SIMPLE_HTML_MARKDOWN_MANIFEST, SimpleHtmlMarkdownTransform()
    )
    submitted = service.submit(
        _request(_skill(max_tool_attempts=2), max_tool_attempts=2),
        caller_id="caller",
        idempotency_key=f"callback-{checkpoint}",
    )
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    callback_error = RuntimeError(f"callback failed at checkpoint {checkpoint}")
    checks = 0

    def should_cancel() -> bool:
        nonlocal checks
        checks += 1
        if checks == checkpoint:
            service.cancel(submitted.job_id)
            raise callback_error
        return False

    assert claim is not None
    with pytest.raises(RuntimeError) as raised:
        service.execute_submitted(claim.job.job_id, claim.request, should_cancel)

    assert raised.value is callback_error
    assert checks == checkpoint
    finished = jobs.get(claim.job.job_id)
    assert finished.status is JobStatus.PARTIAL
    assert finished.failure_code == "runtime.cancelled"
    assert finished.result is not None
    assert len(finished.result.artifacts) == expected_artifacts
    assert [error.code for error in finished.result.errors] == ["runtime.cancelled"]
    assert tool.calls == 1
    store.close()


def test_late_callback_exception_cancel_race_preserves_committed_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)
    service.submit(_request(_skill()), caller_id="caller", idempotency_key="late-race")
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    callback_error = RuntimeError("deterministic late callback exception")
    checks = 0
    transition = jobs.transition
    injected = False

    def should_cancel() -> bool:
        nonlocal checks
        checks += 1
        if checks >= 5:
            raise callback_error
        return False

    def cancel_before_partial(job_id, status, **kwargs):
        nonlocal injected
        if status is JobStatus.PARTIAL and not injected:
            injected = True
            jobs.cancel(job_id, at=NOW)
        return transition(job_id, status, **kwargs)

    monkeypatch.setattr(jobs, "transition", cancel_before_partial)
    assert claim is not None
    with pytest.raises(RuntimeError) as raised:
        service.execute_submitted(claim.job.job_id, claim.request, should_cancel)

    assert raised.value is callback_error
    assert checks == 5
    assert injected
    finished = jobs.get(claim.job.job_id)
    assert finished.status is JobStatus.PARTIAL
    assert finished.failure_code == "runtime.cancelled"
    assert finished.result is not None and len(finished.result.artifacts) == 1
    assert [error.code for error in finished.result.errors] == ["runtime.cancelled"]
    assert tool.calls == 1
    store.close()


def test_cancel_before_workflow_exception_persists_strict_cancelled_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _CountingTool(_successful_output())
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, tool)
    store = ArtifactStore(tmp_path / "artifacts")
    database = tmp_path / "jobs.sqlite3"
    jobs = JobRepository(database)
    cancellation_repository = JobRepository(database)
    service = RuntimeService(
        registry,
        store,
        jobs,
        clock=lambda: NOW,
        job_id_factory=lambda: "job-one",
    )
    service.submit(_request(_skill()), caller_id="caller", idempotency_key="race")
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    workflow_error = RuntimeError("deterministic workflow exception")

    def cancel_then_raise(*_args, **_kwargs):
        assert claim is not None
        cancellation_repository.cancel(claim.job.job_id, at=NOW)
        raise workflow_error

    monkeypatch.setattr(service_module, "run_single_target", cancel_then_raise)
    assert claim is not None
    with pytest.raises(RuntimeError) as raised:
        service.execute_submitted(claim.job.job_id, claim.request, lambda: False)

    assert raised.value is workflow_error
    finished = jobs.get(claim.job.job_id)
    assert finished.status is JobStatus.FAILED
    assert finished.failure_code == "runtime.cancelled"
    assert finished.result is not None
    assert [error.code for error in finished.result.errors] == ["runtime.cancelled"]
    assert not finished.result.artifacts
    assert finished.result.usage.to_dict() == {
        "requests": 0,
        "bytes_received": 0,
        "runtime_ms": 0,
        "tool_attempts": 0,
    }
    assert tool.calls == 0
    cancellation_repository.close()
    jobs.close()
    store.close()


@pytest.mark.parametrize(
    ("checkpoint", "expected_status", "expected_artifacts"),
    [
        (1, JobStatus.FAILED, 0),
        (2, JobStatus.FAILED, 0),
        (3, JobStatus.FAILED, 0),
        (4, JobStatus.PARTIAL, 1),
    ],
)
def test_cooperative_cancellation_preserves_only_committed_source_evidence(
    tmp_path: Path,
    checkpoint: int,
    expected_status: JobStatus,
    expected_artifacts: int,
) -> None:
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)
    service.submit(
        _request(_skill()),
        caller_id="caller-one",
        idempotency_key=f"key-{checkpoint}",
    )
    claim = jobs.claim_next("worker-one", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    checks = 0

    def should_cancel() -> bool:
        nonlocal checks
        checks += 1
        return checks >= checkpoint

    assert claim is not None
    finished = service.execute_submitted(claim.job.job_id, claim.request, should_cancel)

    assert finished.status is expected_status
    assert finished.failure_code == "runtime.cancelled"
    assert finished.result is not None
    assert len(finished.result.artifacts) == expected_artifacts
    assert tool.calls == (0 if checkpoint == 1 else 1)
    store.close()


@pytest.mark.parametrize(
    ("checkpoint", "artifact_count", "transform_calls"),
    [(5, 1, 0), (7, 2, 1)],
)
def test_transform_boundary_cancellation_is_partial_and_preserves_evidence(
    tmp_path: Path,
    checkpoint: int,
    artifact_count: int,
    transform_calls: int,
) -> None:
    transform_body = b"<html><body>one two three four five</body></html>"
    tool = _CountingTool(
        replace(
            _successful_output(),
            body=transform_body,
            sha256=hashlib.sha256(transform_body).hexdigest(),
            bytes_received=len(transform_body),
        )
    )
    service, store, jobs = _service(tmp_path, tool)

    class CountingTransform(SimpleHtmlMarkdownTransform):
        calls = 0

        def transform(self, tool_input):
            self.calls += 1
            return super().transform(tool_input)

    transform = CountingTransform()
    service._registry.register(  # pylint: disable=protected-access
        SIMPLE_HTML_MARKDOWN_MANIFEST, transform
    )
    service.submit(
        _request(_skill(max_tool_attempts=2), max_tool_attempts=2),
        caller_id="caller",
        idempotency_key=f"transform-{checkpoint}",
    )
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    checks = 0

    def should_cancel() -> bool:
        nonlocal checks
        checks += 1
        return checks >= checkpoint

    assert claim is not None
    finished = service.execute_submitted(claim.job.job_id, claim.request, should_cancel)

    assert finished.status is JobStatus.PARTIAL
    assert finished.failure_code == "runtime.cancelled"
    assert finished.result is not None
    assert len(finished.result.artifacts) == artifact_count
    assert transform.calls == transform_calls
    if transform_calls:
        assert finished.result.attempts[-1].outcome == "succeeded"
    store.close()


def test_cancel_committing_before_completed_transition_forces_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)
    service.submit(_request(_skill()), caller_id="caller", idempotency_key="race")
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    transition = jobs.transition
    injected = False

    def cancel_before_completed(job_id, status, **kwargs):
        nonlocal injected
        if status is JobStatus.COMPLETED and not injected:
            injected = True
            jobs.cancel(job_id, at=NOW)
        return transition(job_id, status, **kwargs)

    monkeypatch.setattr(jobs, "transition", cancel_before_completed)
    assert claim is not None
    finished = service.execute_submitted(claim.job.job_id, claim.request, lambda: False)

    assert injected
    assert finished.status is JobStatus.PARTIAL
    assert finished.failure_code == "runtime.cancelled"
    assert finished.result is not None and len(finished.result.artifacts) == 1
    store.close()


def test_cancel_committing_before_failed_transition_forces_cancelled_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _CountingTool(
        AcquisitionFailure(
            WEB_HTTP_MANIFEST.tool_id,
            WEB_HTTP_MANIFEST.version,
            "gateway.timeout",
        )
    )
    service, store, jobs = _service(tmp_path, tool)
    service.submit(_request(_skill()), caller_id="caller", idempotency_key="race")
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    transition = jobs.transition
    injected = False

    def cancel_before_failed(job_id, status, **kwargs):
        nonlocal injected
        if status is JobStatus.FAILED and not injected:
            injected = True
            jobs.cancel(job_id, at=NOW)
        return transition(job_id, status, **kwargs)

    monkeypatch.setattr(jobs, "transition", cancel_before_failed)
    assert claim is not None
    finished = service.execute_submitted(claim.job.job_id, claim.request, lambda: False)

    assert injected
    assert finished.status is JobStatus.FAILED
    assert finished.failure_code == "runtime.cancelled"
    assert finished.result is not None and not finished.result.artifacts
    assert [error.code for error in finished.result.errors] == ["runtime.cancelled"]
    store.close()


def test_cancel_committing_before_partial_transition_preserves_source_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FailingTransform(SimpleHtmlMarkdownTransform):
        def transform(self, tool_input):
            del tool_input
            return TransformFailure(
                SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id,
                SIMPLE_HTML_MARKDOWN_MANIFEST.version,
                "transform.failed",
            )

    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)
    service._registry.register(  # pylint: disable=protected-access
        SIMPLE_HTML_MARKDOWN_MANIFEST, FailingTransform()
    )
    service.submit(
        _request(_skill(max_tool_attempts=2), max_tool_attempts=2),
        caller_id="caller",
        idempotency_key="race",
    )
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    transition = jobs.transition
    injected = False

    def cancel_before_partial(job_id, status, **kwargs):
        nonlocal injected
        if status is JobStatus.PARTIAL and not injected:
            injected = True
            jobs.cancel(job_id, at=NOW)
        return transition(job_id, status, **kwargs)

    monkeypatch.setattr(jobs, "transition", cancel_before_partial)
    assert claim is not None
    finished = service.execute_submitted(claim.job.job_id, claim.request, lambda: False)

    assert injected
    assert finished.status is JobStatus.PARTIAL
    assert finished.failure_code == "runtime.cancelled"
    assert finished.result is not None and len(finished.result.artifacts) == 1
    assert [error.code for error in finished.result.errors] == ["runtime.cancelled"]
    store.close()


def test_cancel_committing_before_rejected_transition_forces_cancelled_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _CountingTool(_successful_output())
    service, store, jobs = _service(tmp_path, tool)
    request = replace(
        _request(None),
        scope=replace(_request(None).scope, seeds=(URL, f"{URL}/other")),
    )
    service.submit(request, caller_id="caller", idempotency_key="race")
    claim = jobs.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
    transition = jobs.transition
    injected = False

    def cancel_before_rejected(job_id, status, **kwargs):
        nonlocal injected
        if status is JobStatus.REJECTED and not injected:
            injected = True
            jobs.cancel(job_id, at=NOW)
        return transition(job_id, status, **kwargs)

    monkeypatch.setattr(jobs, "transition", cancel_before_rejected)
    assert claim is not None
    finished = service.execute_submitted(claim.job.job_id, claim.request, lambda: False)

    assert injected
    assert finished.status is JobStatus.FAILED
    assert finished.failure_code == "runtime.cancelled"
    assert finished.result is not None and not finished.result.artifacts
    assert [error.code for error in finished.result.errors] == ["runtime.cancelled"]
    assert tool.calls == 0
    store.close()
