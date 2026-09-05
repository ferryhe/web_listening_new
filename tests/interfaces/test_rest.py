"""Focused contract tests for the Phase 10 thin REST adapter."""

# pylint: disable=missing-function-docstring,protected-access
# pylint: disable=too-few-public-methods
# pylint: disable=consider-using-from-import,duplicate-code
# pylint: disable=redefined-outer-name,too-many-instance-attributes
# pylint: disable=wrong-import-position

from __future__ import annotations

import base64
import hashlib
import json
import tomllib
from contextlib import contextmanager
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from threading import get_ident
from urllib.parse import quote

import pytest

pytest.importorskip("fastapi", reason="install the optional web-listening[rest] extra")

from fastapi.testclient import TestClient  # pylint: disable=import-error

import web_listening.interfaces.cli as cli
import web_listening.interfaces.rest as rest
from web_listening.artifact.model import (
    ArtifactStoreError,
    StoredArtifact,
    VerifiedArtifactStream,
)
from web_listening.artifact.site_state import SiteState
from web_listening.request.model import (
    Budgets,
    ContentType,
    Request,
    RequestValidationError,
    Scope,
)
from web_listening.request.site_refresh import (
    SITE_REFRESH_REQUEST_SCHEMA_VERSION,
    SiteRefreshRequest,
)
from web_listening.result.errors import SafeError
from web_listening.result.handoff import AcquisitionHandoff
from web_listening.result.manifest import SiteSkillEvidence, Usage
from web_listening.result.model import Result
from web_listening.result.site_explore import SiteExploreResult
from web_listening.result.site_refresh import (
    ChangeEvidence,
    SiteChange,
    SiteRefreshResult,
)
from web_listening.runtime.jobs import Job, JobStateError, JobStatus
from web_listening.site_skill.model import (
    DiscoveryRecipe,
    SiteSkill,
    SiteSkillError,
    SuccessChecks,
    ToolReference,
)
from web_listening.site_skill.update import create_candidate
from web_listening.site_skill.validate import site_skill_to_mapping
from web_listening.tool_registry.manifest import ToolCategory

ROOT = Path(__file__).parents[2]
RESULT_FIXTURES = ROOT / "tests" / "result" / "fixtures"
SITE_SKILL_CATALOG = ROOT / "tests" / "live" / "catalog" / "site_skill_cases.json"


def _result(name: str = "completed.v1.json") -> Result:
    return Result.from_dict(
        json.loads((RESULT_FIXTURES / name).read_text(encoding="utf-8"))
    )


def _job(name: str = "completed.v1.json") -> Job:
    result = _result(name)
    failure_code = result.errors[0].code if result.errors else None
    return Job(
        job_id=result.manifest.run_id,
        status=JobStatus(result.status.value),
        submitted_at="2026-08-25T11:59:58Z",
        started_at="2026-08-25T11:59:59Z",
        finished_at="2026-08-25T12:00:01Z",
        result=result,
        failure_code=failure_code,
        caller_id="caller-one",
    )


def _rest_job_payload(job: Job) -> dict[str, object]:
    payload = cli._job_payload(job)
    payload["cancel_requested_at"] = job.cancel_requested_at
    return payload


def _explore_result() -> SiteExploreResult:
    return SiteExploreResult(
        status="rejected",
        exploration_complete=False,
        site_state=SiteState("www.ipcc.ch", "2026-08-26T12:00:00Z", None, False, ()),
        site_skill_candidate=None,
        site_skill_used=None,
        discovery=(),
        target_results=(),
        attempts=(),
        usage=Usage(0, 0, 0, 0),
        stop_reason="rejected",
        errors=(
            SafeError(
                "runtime.site_explore_single_seed_required",
                "Exploration was rejected.",
            ),
        ),
    )


def _refresh_result() -> SiteRefreshResult:
    target = Result.from_dict(
        json.loads((RESULT_FIXTURES / "failed.v1.json").read_text(encoding="utf-8"))
    )
    skill = SiteSkillEvidence("1", "e" * 64)
    url = "https://example.test/"
    attempt = replace(
        target.attempts[0],
        attempt_id="refresh-source",
        requested_url=url,
    )
    target = replace(
        target,
        manifest=replace(
            target.manifest,
            run_id="refresh-source",
            requested_url=url,
            current_url=url,
            site_skill=skill,
            attempts=(attempt,),
        ),
        site_skill_used=skill,
        attempts=(attempt,),
    )
    previous_payload = json.loads(
        (RESULT_FIXTURES / "site-refresh-partial.v1.json").read_text(encoding="utf-8")
    )["previous_state"]
    previous = replace(
        SiteState.from_dict(previous_payload), site_skill_digest="sha256:" + "e" * 64
    )
    current = SiteState(
        previous.site_key,
        previous.generated_at,
        previous.site_skill_digest,
        False,
        (),
    )
    code = target.errors[0].code
    return SiteRefreshResult(
        status="partial",
        refresh_complete=False,
        added=(),
        changed=(),
        unchanged=(),
        missing=(),
        failed=(SiteChange(url, "failed", None, None, (attempt.attempt_id,), (code,)),),
        unresolved=tuple(
            SiteChange(
                page.canonical_url,
                "unresolved",
                ChangeEvidence(page.artifact_id, page.content_digest),
                None,
            )
            for page in previous.pages
        ),
        previous_state=previous,
        current_state=current,
        site_skill_used=skill,
        site_skill_update=None,
        target_results=(target,),
        attempts=(attempt,),
        usage=target.usage,
        stop_reason="acquisition_failed",
        errors=target.errors,
    )


def _refresh_request_payload() -> dict[str, object]:
    scope = Scope(
        ("https://example.test/",),
        ("https://example.test",),
        ("/**",),
        (ContentType.HTML,),
    )
    discovery_tool = ToolReference(
        "discovery.html_links",
        "1.0.0",
        ToolCategory.DISCOVERY,
        frozenset({"html_links"}),
    )
    skill = create_candidate(
        site_key="example.test",
        version=1,
        previous=None,
        scope=scope,
        budgets=Budgets(4, 4096, 30, 4),
        tool=ToolReference(
            "acquisition.web_http",
            "1.0.0",
            ToolCategory.ACQUISITION,
            frozenset({"http_get"}),
        ),
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at="2026-08-28T00:00:00Z",
        discovery=DiscoveryRecipe(discovery_tool, "https://example.test/"),
    ).skill
    previous = _refresh_result().previous_state
    previous = SiteState(
        previous.site_key,
        previous.generated_at,
        skill.digest,
        previous.complete,
        previous.pages,
    )
    return {
        "schema_version": SITE_REFRESH_REQUEST_SCHEMA_VERSION,
        "scope": {
            "seeds": list(scope.seeds),
            "allowed_origins": list(scope.allowed_origins),
            "include_paths": list(scope.include_paths),
            "content_types": ["html"],
        },
        "site_skill": site_skill_to_mapping(skill),
        "previous_state": previous.to_dict(),
        "explore_all_tools": False,
        "budgets": {
            "max_requests": 4,
            "max_bytes": 4096,
            "max_runtime_seconds": 30,
            "max_tool_attempts_per_target": 4,
        },
    }


def _request_payload(site_skill: object = None) -> dict[str, object]:
    return {
        "scope": {
            "seeds": ["https://www.ipcc.ch/"],
            "allowed_origins": ["https://www.ipcc.ch"],
            "include_paths": ["/**"],
            "content_types": ["html"],
        },
        "site_skill": site_skill,
        "explore_all_tools": False,
        "budgets": {
            "max_requests": 1,
            "max_bytes": 2 * 1024 * 1024,
            "max_runtime_seconds": 30,
            "max_tool_attempts_per_target": 1,
        },
    }


def _site_skill() -> dict[str, object]:
    payload = json.loads(SITE_SKILL_CATALOG.read_text(encoding="utf-8"))
    return next(
        item["site_skill"] for item in payload["cases"] if item["site_key"] == "ipcc"
    )


class FakeRuntime:
    """Programmable test double exposing only RuntimeService public methods."""

    def __init__(self) -> None:
        self.run_job = _job()
        self.get_job_result = _job()
        content = b"\x00phase-10\xff"
        self.artifact = StoredArtifact(
            artifact_id="artifact-one",
            blob_sha256="a" * 64,
            size_bytes=len(content),
            mime_type="application/octet-stream",
            content=content,
        )
        self.run_error: Exception | None = None
        self.explore_error: Exception | None = None
        self.refresh_error: Exception | None = None
        self.get_error: Exception | None = None
        self.handoff_error: Exception | None = None
        self.read_error: Exception | None = None
        self.requests: list[Request | SiteRefreshRequest] = []
        self.run_thread_ids: list[int] = []
        self.explore_thread_ids: list[int] = []
        self.refresh_thread_ids: list[int] = []
        self.job_ids: list[str] = []
        self.artifact_ids: list[str] = []
        self.last_stream: BytesIO | None = None

    def run(self, request: Request) -> Job:
        self.run_thread_ids.append(get_ident())
        self.requests.append(request)
        if self.run_error is not None:
            raise self.run_error
        return self.run_job

    def submit(self, request: Request, *, caller_id: str, idempotency_key: str) -> Job:
        del idempotency_key
        assert caller_id == "caller-one"
        return self.run(request)

    def get_job(self, job_id: str) -> Job:
        self.job_ids.append(job_id)
        if self.get_error is not None:
            raise self.get_error
        return self.get_job_result

    def get_owned_job(self, job_id: str, caller_id: str) -> Job:
        assert caller_id == "caller-one"
        return self.get_job(job_id)

    def get_handoff(self, job_id: str) -> AcquisitionHandoff:
        self.job_ids.append(job_id)
        if self.handoff_error is not None:
            raise self.handoff_error
        path = RESULT_FIXTURES / "acquisition-handoff-completed.v1.json"
        return AcquisitionHandoff.from_json(path.read_bytes())

    def get_owned_handoff(self, job_id: str, caller_id: str) -> AcquisitionHandoff:
        assert caller_id == "caller-one"
        return self.get_handoff(job_id)

    def explore_site(self, request: Request) -> SiteExploreResult:
        self.explore_thread_ids.append(get_ident())
        self.requests.append(request)
        if self.explore_error is not None:
            raise self.explore_error
        return _explore_result()

    def explore_site_owned(self, request: Request, caller_id: str) -> SiteExploreResult:
        assert caller_id == "caller-one"
        return self.explore_site(request)

    def refresh_site(self, request: SiteRefreshRequest) -> SiteRefreshResult:
        self.refresh_thread_ids.append(get_ident())
        self.requests.append(request)
        if self.refresh_error is not None:
            raise self.refresh_error
        return _refresh_result()

    def refresh_site_owned(
        self, request: SiteRefreshRequest, caller_id: str
    ) -> SiteRefreshResult:
        assert caller_id == "caller-one"
        return self.refresh_site(request)

    def read_artifact(self, artifact_id: str) -> StoredArtifact:
        self.artifact_ids.append(artifact_id)
        if self.read_error is not None:
            raise self.read_error
        return self.artifact

    def read_owned_artifact(self, artifact_id: str, caller_id: str) -> StoredArtifact:
        assert caller_id == "caller-one"
        return self.read_artifact(artifact_id)

    @contextmanager
    def open_owned_artifact(self, artifact_id: str, caller_id: str):
        stored = self.read_owned_artifact(artifact_id, caller_id)
        stream = BytesIO(stored.content)
        self.last_stream = stream
        try:
            yield VerifiedArtifactStream(
                stored.artifact_id,
                stored.blob_sha256,
                stored.size_bytes,
                stored.mime_type,
                stream,
            )
        finally:
            stream.close()


@pytest.fixture
def runtime() -> FakeRuntime:
    return FakeRuntime()


TOKEN = "opaque-test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
CONFIG = rest.RestConfig("caller-one", hashlib.sha256(TOKEN.encode()).hexdigest())


def _app(provider) -> object:
    return rest.create_app(provider, CONFIG)


def _client(runtime: FakeRuntime) -> TestClient:
    client = TestClient(_app(lambda: runtime))
    client.headers.update({**AUTH, "Idempotency-Key": "test-key"})
    return client


def test_app_exposes_exactly_the_six_readme_routes_and_disables_docs(
    runtime: FakeRuntime,
) -> None:
    app = _app(lambda: runtime)

    observed = {(route.path, tuple(sorted(route.methods))) for route in app.routes}
    assert observed == {
        ("/v1/acquisitions", ("POST",)),
        ("/health", ("GET",)),
        ("/ready", ("GET",)),
        ("/v1/jobs/{job_id}", ("GET",)),
        ("/v1/jobs/{job_id}/cancel", ("POST",)),
        ("/v1/jobs/{job_id}/handoff", ("GET",)),
        ("/v1/artifacts/{artifact_id}", ("GET",)),
        ("/v1/artifacts/{artifact_id}/content", ("GET",)),
        ("/v1/site-explorations", ("POST",)),
        ("/v1/site-refreshes", ("POST",)),
        ("/v1/site-batches", ("POST",)),
        ("/v1/site-batches/{batch_id}", ("GET",)),
        ("/v1/site-batches/{batch_id}/cancel", ("POST",)),
        ("/v1/url-fetches", ("POST",)),
        ("/v1/url-fetches/{job_id}", ("GET",)),
        ("/v1/url-fetches/{job_id}/cancel", ("POST",)),
    }
    client = TestClient(app, headers=AUTH)
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_get_handoff_calls_only_runtime_and_returns_contract(
    runtime: FakeRuntime,
) -> None:
    response = _client(runtime).get("/v1/jobs/run-completed-001/handoff")

    assert response.status_code == 200
    assert response.json()["schema_version"] == "acquisition-handoff.v1"
    assert runtime.job_ids == ["run-completed-001"]


def test_acquire_maps_a_strict_request_to_runtime_and_returns_exact_result_schema(
    runtime: FakeRuntime,
) -> None:
    response = _client(runtime).post("/v1/acquisitions", json=_request_payload())

    assert response.status_code == 202
    assert len(runtime.requests) == 1
    assert isinstance(runtime.requests[0], Request)
    assert response.json() == _rest_job_payload(runtime.run_job)
    assert Result.from_dict(response.json()["result"]) == runtime.run_job.result


def test_acquire_offloads_runtime_run_from_the_handler_thread(
    runtime: FakeRuntime,
) -> None:
    provider_thread_ids: list[int] = []

    def provider() -> FakeRuntime:
        provider_thread_ids.append(get_ident())
        return runtime

    response = TestClient(_app(provider), headers=AUTH).post(
        "/v1/acquisitions", headers={"Idempotency-Key": "key"}, json=_request_payload()
    )

    assert response.status_code == 202
    assert len(provider_thread_ids) == len(runtime.run_thread_ids) == 1


def test_durable_submit_stays_202_when_wake_fails_and_replay_is_idempotent(
    runtime: FakeRuntime,
) -> None:
    def fail_wake() -> None:
        raise RuntimeError("worker unhealthy")

    client = TestClient(
        rest.create_app(lambda: runtime, CONFIG, wake=fail_wake), headers=AUTH
    )
    headers = {"Idempotency-Key": "wake-failure-key"}
    first = client.post("/v1/acquisitions", headers=headers, json=_request_payload())
    replay = client.post("/v1/acquisitions", headers=headers, json=_request_payload())

    assert first.status_code == replay.status_code == 202
    assert first.json()["job_id"] == replay.json()["job_id"]
    assert first.json() == replay.json() == _rest_job_payload(runtime.run_job)


def test_site_explore_maps_request_to_one_runtime_call_with_contract_parity(
    runtime: FakeRuntime,
) -> None:
    provider_thread_ids: list[int] = []

    def provider() -> FakeRuntime:
        provider_thread_ids.append(get_ident())
        return runtime

    response = TestClient(_app(provider), headers=AUTH).post(
        "/v1/site-explorations", json=_request_payload()
    )

    assert response.status_code == 422
    assert len(runtime.requests) == 1
    assert runtime.requests[0].site_skill is None
    assert response.json() == _explore_result().to_dict()
    assert response.json()["target_results"] == []
    assert len(provider_thread_ids) == len(runtime.explore_thread_ids) == 1
    assert runtime.explore_thread_ids[0] != provider_thread_ids[0]


def test_site_refresh_maps_request_to_one_runtime_call_with_contract_parity(
    runtime: FakeRuntime,
) -> None:
    provider_thread_ids: list[int] = []

    def provider() -> FakeRuntime:
        provider_thread_ids.append(get_ident())
        return runtime

    response = TestClient(_app(provider), headers=AUTH).post(
        "/v1/site-refreshes", json=_refresh_request_payload()
    )

    assert response.status_code == 201
    assert len(runtime.requests) == 1
    request = runtime.requests[0]
    assert isinstance(request, SiteRefreshRequest)
    assert request.site_skill.digest == request.previous_state.site_skill_digest
    assert response.json() == _refresh_result().to_dict()
    assert response.json()["target_results"]
    assert SiteRefreshResult.from_dict(response.json()) == _refresh_result()
    assert len(provider_thread_ids) == len(runtime.refresh_thread_ids) == 1
    assert runtime.refresh_thread_ids[0] != provider_thread_ids[0]


def test_site_refresh_rejects_sensitive_previous_state_before_runtime_provider(
    runtime: FakeRuntime,
) -> None:
    payload = _refresh_request_payload()
    payload["previous_state"]["pages"][0][
        "canonical_url"
    ] = "https://example.test/a?token=placeholder-value"
    provider_calls = 0

    def provider() -> FakeRuntime:
        nonlocal provider_calls
        provider_calls += 1
        return runtime

    response = TestClient(_app(provider), headers=AUTH).post(
        "/v1/site-refreshes", json=payload
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "site_state.sensitive_data",
            "message": "Request is invalid.",
            "details": {},
        }
    }
    assert "placeholder-value" not in response.text
    assert provider_calls == 0
    assert runtime.requests == []


def test_site_refresh_rejects_absolute_path_before_runtime_provider(
    runtime: FakeRuntime,
) -> None:
    payload = _refresh_request_payload()
    encoded = quote("".join(chr(item) for item in (67, 58, 47, 112)), safe="")
    payload["previous_state"]["pages"][0][
        "canonical_url"
    ] = f"https://example.test/a?next={encoded}"
    provider_calls = 0

    def provider() -> FakeRuntime:
        nonlocal provider_calls
        provider_calls += 1
        return runtime

    response = TestClient(_app(provider), headers=AUTH).post(
        "/v1/site-refreshes", json=payload
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "site_state.absolute_path",
            "message": "Request is invalid.",
            "details": {},
        }
    }
    assert provider_calls == 0
    assert runtime.requests == []


def test_site_refresh_accepts_public_natural_language_slug(
    runtime: FakeRuntime,
) -> None:
    payload = _refresh_request_payload()
    public_url = (
        "https://example.test/"
        "skilled-professionals-and-scientists-in-climate-assessment"
    )
    payload["previous_state"]["pages"][0]["canonical_url"] = public_url
    payload["previous_state"]["pages"].sort(key=lambda page: page["canonical_url"])
    provider_calls = 0

    def provider() -> FakeRuntime:
        nonlocal provider_calls
        provider_calls += 1
        return runtime

    response = TestClient(_app(provider), headers=AUTH).post(
        "/v1/site-refreshes", json=payload
    )

    assert response.status_code == 201
    assert provider_calls == 1
    assert len(runtime.requests) == 1
    assert public_url in {
        page.canonical_url for page in runtime.requests[0].previous_state.pages
    }


def test_acquire_validates_embedded_site_skill_before_runtime(
    runtime: FakeRuntime,
) -> None:
    response = _client(runtime).post(
        "/v1/acquisitions", json=_request_payload(_site_skill())
    )

    assert response.status_code == 202
    assert len(runtime.requests) == 1
    parsed = runtime.requests[0]
    assert isinstance(parsed.site_skill, SiteSkill)
    assert parsed.site_skill.site_key == "ipcc"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b'{"scope":', "request.invalid_json"),
        (json.dumps({"scope": {}}).encode(), "request.missing"),
        (
            json.dumps({**_request_payload(), "private": "C:/private/canary"}).encode(),
            "request.unknown_field",
        ),
        (
            json.dumps(_request_payload({})).encode(),
            "site_skill.missing",
        ),
    ],
)
def test_invalid_acquisition_input_is_stable_safe_422_without_calling_runtime(
    runtime: FakeRuntime, body: bytes, code: str
) -> None:
    client = _client(runtime)

    first = client.post(
        "/v1/acquisitions",
        content=body,
        headers={"content-type": "application/json"},
    )
    second = client.post(
        "/v1/acquisitions",
        content=body,
        headers={"content-type": "application/json"},
    )

    assert first.status_code == second.status_code == 422
    assert first.content == second.content
    assert first.json() == {
        "error": {
            "code": code,
            "message": "Request is invalid.",
            "details": {},
        }
    }
    assert "private" not in first.text.lower()
    assert "canary" not in first.text.lower()
    assert runtime.requests == []


@pytest.mark.parametrize(
    ("failure_source", "error"),
    [
        ("provider", RequestValidationError("private.provider_request")),
        ("provider", SiteSkillError("private.provider_site_skill")),
        ("runtime", RequestValidationError("private.runtime_request")),
        ("runtime", SiteSkillError("private.runtime_site_skill")),
    ],
)
def test_acquire_redacts_provider_and_runtime_validation_errors(
    runtime: FakeRuntime, failure_source: str, error: Exception
) -> None:
    def failing_provider() -> FakeRuntime:
        raise error

    if failure_source == "provider":
        client = TestClient(
            _app(failing_provider), headers={**AUTH, "Idempotency-Key": "test-key"}
        )
    else:
        runtime.run_error = error
        client = _client(runtime)

    response = client.post("/v1/acquisitions", json=_request_payload())

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "runtime.failed",
            "message": "Runtime request failed.",
            "details": {},
        }
    }
    assert str(error) not in response.text


@pytest.mark.parametrize(
    ("fixture", "status"),
    [("rejected-boundary.v1.json", 202), ("failed.v1.json", 202)],
)
def test_acquire_maps_rejected_and_failed_jobs_without_changing_result_body(
    runtime: FakeRuntime, fixture: str, status: int
) -> None:
    runtime.run_job = _job(fixture)

    response = _client(runtime).post("/v1/acquisitions", json=_request_payload())

    assert response.status_code == status
    assert response.json() == _rest_job_payload(runtime.run_job)
    assert Result.from_dict(response.json()["result"]) == runtime.run_job.result


def test_get_job_calls_only_public_runtime_and_returns_cli_parity(
    runtime: FakeRuntime,
) -> None:
    response = _client(runtime).get("/v1/jobs/run-completed-001")

    assert response.status_code == 200
    assert runtime.job_ids == ["run-completed-001"]
    assert response.json() == _rest_job_payload(runtime.get_job_result)


@pytest.mark.parametrize(
    ("path", "error", "status", "code"),
    [
        ("/v1/jobs/missing", JobStateError("job.not_found"), 404, "job.not_found"),
        ("/v1/jobs/bad%20id", JobStateError("job.id_invalid"), 422, "job.id_invalid"),
    ],
)
def test_get_job_maps_safe_repository_errors(
    runtime: FakeRuntime, path: str, error: Exception, status: int, code: str
) -> None:
    runtime.get_error = error

    response = _client(runtime).get(path)

    assert response.status_code == status
    assert response.json() == {
        "error": {
            "code": code,
            "message": (
                "Resource was not found." if status == 404 else "Identifier is invalid."
            ),
            "details": {},
        }
    }


def test_read_artifact_returns_lossless_base64_with_cli_parity(
    runtime: FakeRuntime,
) -> None:
    response = _client(runtime).get("/v1/artifacts/artifact-one")

    assert response.status_code == 200
    assert runtime.artifact_ids == ["artifact-one"]
    assert response.json() == cli._artifact_payload(runtime.artifact)
    assert base64.b64decode(response.json()["content"], validate=True) == (
        runtime.artifact.content
    )
    assert runtime.last_stream is not None and runtime.last_stream.closed


def test_base64_cap_is_checked_before_stream_body_read(runtime: FakeRuntime) -> None:
    class Unreadable(BytesIO):
        """Fail if an over-cap response attempts to read stream content."""

        def read(self, *_args, **_kwargs):
            raise AssertionError("over-cap body was read")

    @contextmanager
    def open_over_cap(_artifact_id: str, _caller_id: str):
        stream = Unreadable(b"not-read")
        try:
            yield VerifiedArtifactStream(
                "artifact-one", "a" * 64, 2 * 1024 * 1024, "text/plain", stream
            )
        finally:
            stream.close()

    runtime.open_owned_artifact = open_over_cap  # type: ignore[method-assign]
    config = replace(CONFIG, base64_cap_bytes=1024 * 1024)
    client = TestClient(rest.create_app(lambda: runtime, config), headers=AUTH)
    response = client.get("/v1/artifacts/artifact-one")
    assert response.status_code == 413


def test_stream_uses_exact_authoritative_text_mime_without_charset(
    runtime: FakeRuntime,
) -> None:
    runtime.artifact = replace(runtime.artifact, mime_type="text/plain")
    response = _client(runtime).get("/v1/artifacts/artifact-one/content")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/plain"
    assert response.content == runtime.artifact.content


@pytest.mark.parametrize(
    ("path", "error", "status", "code"),
    [
        (
            "/v1/artifacts/missing",
            ArtifactStoreError("artifact.not_found"),
            404,
            "artifact.not_found",
        ),
        (
            "/v1/artifacts/bad",
            ArtifactStoreError("artifact.id_invalid"),
            422,
            "artifact.id_invalid",
        ),
    ],
)
def test_read_artifact_maps_safe_repository_errors(
    runtime: FakeRuntime, path: str, error: Exception, status: int, code: str
) -> None:
    runtime.read_error = error

    response = _client(runtime).get(path)

    assert response.status_code == status
    assert response.json()["error"] == {
        "code": code,
        "message": (
            "Resource was not found." if status == 404 else "Identifier is invalid."
        ),
        "details": {},
    }


@pytest.mark.parametrize(
    ("route", "error_attribute", "error"),
    [
        (
            "/v1/jobs/private",
            "get_error",
            JobStateError("private.job_state.not_found"),
        ),
        (
            "/v1/jobs/cross-type",
            "get_error",
            JobStateError("artifact.not_found"),
        ),
        (
            "/v1/artifacts/private",
            "read_error",
            ArtifactStoreError("blob.not_found"),
        ),
        (
            "/v1/artifacts/cross-type",
            "read_error",
            ArtifactStoreError("job.not_found"),
        ),
        (
            "/v1/artifacts/corrupt",
            "read_error",
            ArtifactStoreError("artifact.corrupt"),
        ),
    ],
)
def test_unallowlisted_typed_runtime_errors_are_redacted(
    runtime: FakeRuntime, route: str, error_attribute: str, error: Exception
) -> None:
    setattr(runtime, error_attribute, error)

    response = _client(runtime).get(route)

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "runtime.failed",
            "message": "Runtime request failed.",
            "details": {},
        }
    }
    assert str(error) not in response.text


def test_unexpected_runtime_failure_is_redacted_and_deterministic(
    runtime: FakeRuntime, tmp_path: Path
) -> None:
    private_error = RuntimeError(f"PRIVATE:{tmp_path}")
    private_error.code = "private.not_found"  # type: ignore[attr-defined]
    runtime.run_error = private_error
    client = _client(runtime)

    first = client.post("/v1/acquisitions", json=_request_payload())
    second = client.post("/v1/acquisitions", json=_request_payload())

    assert first.status_code == second.status_code == 500
    assert first.content == second.content
    assert first.json() == {
        "error": {
            "code": "runtime.failed",
            "message": "Runtime request failed.",
            "details": {},
        }
    }
    assert "PRIVATE" not in first.text
    assert str(tmp_path) not in first.text


def test_rest_source_has_only_interface_dto_and_public_runtime_authority() -> None:
    source = Path(rest.__file__).read_text(encoding="utf-8")
    forbidden = (
        "tool_registry",
        "Registry",
        "Gateway",
        "artifact.store",
        "ArtifactStore(",
        "runtime.workflow",
        "acquisition.builtins",
        "sqlite",
    )

    assert "RuntimeService" in source
    assert "runtime_provider" in source
    assert "runtime_provider().submit(" in source
    assert "runtime_provider().explore_site_owned" in source
    assert "runtime_provider().refresh_site_owned" in source
    assert "runtime_provider().get_owned_job(" in source
    assert "runtime_provider().open_owned_artifact(" in source
    assert "RuntimeService.open" not in source
    assert all(name not in source for name in forbidden)


def test_pyproject_keeps_rest_dependencies_in_one_optional_extra() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]

    assert project["dependencies"] == []
    rest_dependencies = project["optional-dependencies"]["rest"]
    assert len(rest_dependencies) == 2
    assert rest_dependencies[0].startswith("fastapi>=")
    assert rest_dependencies[1].startswith("uvicorn>=")
