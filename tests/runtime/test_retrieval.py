"""Retrieval preserves caller-owned Job authority and exact method execution."""

# Intentional cross-test fixtures: pytest resolves the repository namespace.
# pylint: disable=import-error
# pylint: disable=missing-function-docstring,protected-access,duplicate-code
# pylint: disable=import-outside-toplevel,redefined-outer-name,too-many-locals
import hashlib
from dataclasses import replace

import pytest

from tests.runtime.test_service import NOW, _request
from web_listening.runtime.jobs import JobRepository, JobStateError, JobStatus


@pytest.mark.parametrize("sqlite", [False, True])
def test_atomic_exact_claim_and_replay(tmp_path, sqlite):
    jobs = JobRepository(tmp_path / "jobs.sqlite3" if sqlite else None)
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    args = {
        "caller_id": "caller",
        "idempotency_key": "selected",
        "worker_id": "inline",
        "at": NOW,
        "lease_deadline": "2026-08-25T20:01:00Z",
    }
    try:
        jobs.submit_request(
            "older", request, caller_id="other", idempotency_key="older", at=NOW
        )
        claim = jobs.submit_and_claim("selected", request, **args)
        assert claim.job.job_id == "selected"
        assert claim.request == request
        assert claim.job.caller_id == "caller"
        assert claim.job.status is JobStatus.RUNNING
        assert [event.status for event in jobs.events("selected")] == [
            JobStatus.SUBMITTED,
            JobStatus.RUNNING,
        ]
        assert (
            jobs.claim_next(
                "background", at=NOW, lease_deadline=args["lease_deadline"]
            ).job.job_id
            == "older"
        )
        assert (
            jobs.claim_next("background", at=NOW, lease_deadline=args["lease_deadline"])
            is None
        )
        assert jobs.submit_and_claim("duplicate", request, **args) == claim.job
        with pytest.raises(JobStateError, match="idempotency.conflict"):
            jobs.submit_and_claim(
                "conflict", replace(request, explore_all_tools=False), **args
            )
        with pytest.raises(JobStateError):
            jobs.submit_and_claim("invalid", request, **(args | {"caller_id": ""}))
    finally:
        jobs.close()


def test_retrieval_contract_exists():
    from web_listening.runtime.retrieval import (
        RetrievalState,  # pylint: disable=import-outside-toplevel
    )

    assert callable(RetrievalState.from_dict)


@pytest.mark.parametrize(
    "status,headers,code",
    [
        (401, {}, "acquisition.auth_required"),
        (
            403,
            {
                "Server": "cloudflare",
                "CF_Ray": "edge",
                "Cache_Control": (
                    "private, max-age=0, no-store, no-cache, "
                    "must-revalidate, post-check=0, pre-check=0"
                ),
                "X_Frame_Options": "SAMEORIGIN",
                "Referrer_Policy": "same-origin",
            },
            "acquisition.cloudflare_blocked",
        ),
        (403, {}, "acquisition.permission_denied"),
        (
            403,
            {"Server": "cloudflare", "CF_Mitigated": "challenge"},
            "acquisition.cloudflare_blocked",
        ),
        (
            403,
            {"Server": "cloudflare", "CF_Ray": "edge"},
            "acquisition.permission_denied",
        ),
    ],
)
@pytest.mark.parametrize("reader_kind", ["http", "browser"])
def test_http_metadata_classification_never_reads_rejected_body(
    status, headers, code, reader_kind
):
    from tests.tool_registry.test_access_gateway import (
        FakeResponse,
        FakeTransport,
        Resolver,
    )
    from web_listening.request.model import Scope
    from web_listening.tool_registry.protocols.acquisition import AcquisitionInput
    from web_listening.tool_registry.runners.browser_acquisition import (
        GovernedHttpAcquisitionTool,
    )

    response = FakeResponse(status, b"never read", **headers)
    url = "https://example.com/public"
    request = replace(
        _request(None),
        scope=Scope(
            (url,),
            ("https://example.com",),
            ("/**",),
            _request(None).scope.content_types,
        ),
    )
    transport = FakeTransport(
        {url: [response], "https://example.com/robots.txt": [FakeResponse(404)]}
    )
    if reader_kind == "http":
        reader = GovernedHttpAcquisitionTool(lambda: transport, resolver=Resolver())
        output = reader.acquire(AcquisitionInput(request, url))
        assert output.code == code
        assert output.requests == 2
    else:
        from web_listening.tool_registry.runners.browser_network import (
            BrowserNetworkBridge,
        )

        bridge = BrowserNetworkBridge(request, url, transport, resolver=Resolver())
        try:
            assert bridge.read(url, "GET", navigation=True)["code"] == code
            assert bridge.requests == 2
        finally:
            bridge.close()
    assert not response.read_limits
    assert response.closed == 1


@pytest.fixture
def retrieval_runtime(tmp_path):
    from types import SimpleNamespace

    from tests.runtime.test_service import BODY, _service
    from web_listening.tool_registry.acquisition.builtins.web_http import (
        WEB_HTTP_MANIFEST,
    )
    from web_listening.tool_registry.protocols.acquisition import (
        AcquisitionFailure,
        AcquisitionOutput,
    )

    calls = []
    outcomes = {}

    def tool(name, version):
        manifest = replace(
            WEB_HTTP_MANIFEST,
            tool_id=name,
            version=version,
            capabilities=(
                frozenset({"browser_render"})
                if name != WEB_HTTP_MANIFEST.tool_id
                else WEB_HTTP_MANIFEST.capabilities
            ),
        )

        def acquire(value):
            calls.append((name, value))
            code = outcomes.get((name, value.target_url), outcomes.get(name))
            mime, content = code if isinstance(code, tuple) else ("text/html", BODY)
            if isinstance(code, str):
                return AcquisitionFailure(name, version, code, requests=1)
            return AcquisitionOutput(
                name,
                version,
                value.target_url,
                value.target_url,
                200,
                mime,
                content,
                hashlib.sha256(content).hexdigest(),
                (),
                0,
                requests=1,
            )

        return SimpleNamespace(manifest=manifest, acquire=acquire)

    http = tool("acquisition.web_http", "1.0.0")
    runtime, store, jobs = _service(tmp_path, http)
    for name, version in [
        ("acquisition.playwright", "1.0.0"),
        ("acquisition.cloakbrowser", "0.5.9"),
    ]:
        value = tool(name, version)
        runtime._registry.register(value.manifest, value)
    yield runtime, outcomes, calls
    runtime.close()
    store.close()
    jobs.close()


def test_exact_method_and_catalog_no_io(retrieval_runtime):
    runtime, _, calls = retrieval_runtime
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    catalog = runtime.retrieval_methods(request)
    assert not calls
    assert {m["method"] for m in catalog["methods"]} == {
        "HTTP",
        "BROWSER",
        "CLOAK",
        "FILE",
        "OFFICIAL_ALTERNATE",
    }
    response = runtime.retrieve_browser(request, caller_id="reader")
    assert [v[0] for v in calls] == ["acquisition.playwright"]
    assert response["retrieval"]["outcome"] == "FETCHED"
    assert runtime.get_owned_job(
        response["jobs"][0]["job_id"], "reader"
    ).result.artifacts
    from web_listening.runtime.retrieval import RetrievalState

    state = RetrievalState.from_dict(response["retrieval"])
    assert state.to_dict() == response["retrieval"]
    assert state.canonical_json_bytes()
    with pytest.raises(ValueError):
        RetrievalState.from_dict(dict(response["retrieval"], extra=True))
    with pytest.raises(ValueError):
        RetrievalState.from_dict(dict(response["retrieval"], fallback_used=1))


@pytest.mark.parametrize(
    "browser_failure",
    [None, "acquisition.cloudflare_blocked", "browser.navigation_failed"],
)
def test_cloudflare_only_ordinary_browser_once(retrieval_runtime, browser_failure):
    runtime, outcomes, calls = retrieval_runtime
    outcomes["acquisition.web_http"] = "acquisition.cloudflare_blocked"
    outcomes["acquisition.playwright"] = browser_failure
    response = runtime.retrieve(
        _request(None, explore_all_tools=True, max_tool_attempts=3)
    )
    assert [v[0] for v in calls] == ["acquisition.web_http", "acquisition.playwright"]
    assert response["retrieval"]["usage"]["requests"] == 2
    assert response["retrieval"]["fallback_used"]
    assert response["retrieval"]["outcome"] == (
        "UNRESOLVED" if browser_failure else "FETCHED"
    )
    if browser_failure == "acquisition.cloudflare_blocked":
        assert response["retrieval"]["reason"] == "CLOUDFLARE_BLOCKED"
        assert not response["retrieval"]["artifacts"]
        assert [a["action_id"] for a in response["retrieval"]["next_actions"]] == [
            "discover_official_alternates",
            "retrieve_alternate",
        ]


def test_false_and_exact_failure_never_fall_through(retrieval_runtime):
    runtime, outcomes, calls = retrieval_runtime
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    outcomes["acquisition.web_http"] = "acquisition.script_only"
    assert runtime.retrieve_http(request)["retrieval"]["outcome"] == "UNRESOLVED"
    assert len(calls) == 1
    runtime.retrieve_browser(replace(request, explore_all_tools=False))
    assert len(calls) == 1


@pytest.mark.parametrize(
    "code",
    [
        "acquisition.auth_required",
        "acquisition.permission_denied",
        "robots.disallowed",
        "runtime.cancelled",
        "gateway.request_budget_exhausted",
    ],
)
def test_terminal_never_starts_alternate(retrieval_runtime, code):
    runtime, outcomes, calls = retrieval_runtime
    outcomes["acquisition.web_http"] = code
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    if code.startswith("acquisition."):
        assert (
            runtime.retrieve(
                request,
                alternates=(
                    replace(
                        request,
                        scope=replace(
                            request.scope, seeds=("https://example.test/unused",)
                        ),
                    ),
                ),
            )["retrieval"]["outcome"]
            == "UNRESOLVED"
        )
    else:
        with pytest.raises(JobStateError):
            runtime.retrieve(
                request,
                alternates=(
                    replace(
                        request,
                        scope=replace(
                            request.scope, seeds=("https://example.test/unused",)
                        ),
                    ),
                ),
            )
    assert len(calls) == 1


def test_alternate_requires_full_request_and_records_real_provenance(retrieval_runtime):
    runtime, outcomes, calls = retrieval_runtime
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    outcomes["acquisition.web_http"] = "acquisition.cloudflare_blocked"
    first = runtime.retrieve_http(request, caller_id="owner")
    outcomes.clear()
    candidate = replace(
        request, scope=replace(request.scope, seeds=("https://example.test/alternate",))
    )
    response = runtime.retrieve_alternate(
        candidate, primary_job_id=first["jobs"][0]["job_id"], caller_id="owner"
    )
    assert response["retrieval"]["method"] == "OFFICIAL_ALTERNATE"
    assert response["retrieval"]["outcome"] == "FETCHED"
    assert response["provenance"][0]["candidate_url"] == candidate.scope.seeds[0]
    with pytest.raises(JobStateError):
        runtime.retrieve_alternate(
            candidate, primary_job_id=first["jobs"][0]["job_id"], caller_id="stranger"
        )
    with pytest.raises(ValueError):
        runtime.retrieve_alternate(
            "https://example.test/alternate",
            primary_job_id=first["jobs"][0]["job_id"],
            caller_id="owner",
        )
    assert len(calls) == 2


def test_one_shot_first_success_never_admits_later_work(retrieval_runtime):
    runtime, _, calls = retrieval_runtime
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    response = runtime.retrieve(
        request,
        alternates=(
            replace(
                request,
                scope=replace(request.scope, seeds=("https://example.test/unused",)),
            ),
        ),
    )
    assert response["retrieval"]["outcome"] == "FETCHED"
    assert len(response["jobs"]) == len(calls) == 1


def test_file_rejects_html_method_without_io(retrieval_runtime):
    from web_listening.request.model import ContentType

    runtime, _, calls = retrieval_runtime
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    with pytest.raises(ValueError):
        runtime.retrieve_file(request)
    request = replace(
        request, scope=replace(request.scope, content_types=(ContentType.FILE,))
    )
    with pytest.raises(ValueError):
        runtime.retrieve_browser(request)
    assert not calls


@pytest.mark.parametrize(
    "operation",
    [
        "retrieval-methods",
        "retrieve-http",
        "retrieve-browser",
        "retrieve-cloak",
        "retrieve-file",
        "retrieve",
        "retrieve-alternate",
    ],
)
def test_three_interface_parity_without_sockets(  # pylint: disable=too-many-statements
    retrieval_runtime, monkeypatch, tmp_path, capsys, operation
):
    import json
    from dataclasses import asdict
    from types import SimpleNamespace

    import jsonschema

    pytest.importorskip("mcp")
    pytest.importorskip("fastapi")
    from web_listening.interfaces import cli, mcp, rest
    from web_listening.runtime.retrieval import OPERATIONS

    runtime, outcomes, _ = retrieval_runtime
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    if operation == "retrieve-file":
        from web_listening.request.model import ContentType

        request = replace(
            request, scope=replace(request.scope, content_types=(ContentType.FILE,))
        )
    envelope = {"request": json.loads(json.dumps(asdict(request)))}
    if operation == "retrieve-alternate":
        outcomes["acquisition.web_http"] = "acquisition.cloudflare_blocked"
        primary = runtime.retrieve_http(request)
        envelope["primary_job_id"] = primary["jobs"][0]["job_id"]
        outcomes.clear()
    else:
        outcomes["acquisition.web_http"] = "acquisition.cloudflare_blocked"
        outcomes["acquisition.playwright"] = "acquisition.cloudflare_blocked"
        outcomes["acquisition.cloakbrowser"] = "acquisition.cloudflare_blocked"

    if operation == "retrieve-file":
        outcomes["acquisition.web_http"] = ("application/pdf", b"%PDF-1.7 fixture")

    async def immediate(function, *args, **kwargs):
        return function(*args, **kwargs)

    def finish(coroutine):
        with pytest.raises(StopIteration) as ended:
            coroutine.send(None)
        return ended.value.value

    monkeypatch.setattr(mcp.anyio.to_thread, "run_sync", immediate)
    monkeypatch.setattr(rest, "run_in_threadpool", immediate)
    monkeypatch.setattr(
        cli, "_run_with_runtime", lambda _path, operation: operation(runtime)
    )
    path = tmp_path / "request.json"
    path.write_text(json.dumps(envelope["request"]))
    args = [operation, "--request", str(path), "--output", str(tmp_path), "--json"]
    if "primary_job_id" in envelope:
        args += ["--primary-job-id", envelope["primary_job_id"]]
    assert cli.main(args) == 0
    cli_payload = json.loads(capsys.readouterr().out)
    app = rest.create_app(
        lambda: runtime, rest.RestConfig("local", hashlib.sha256(b"token").hexdigest())
    )
    endpoint = next(r.endpoint for r in app.routes if r.path == OPERATIONS[operation])

    async def body():
        return json.dumps(envelope).encode()

    response = finish(
        endpoint(SimpleNamespace(headers={"authorization": "Bearer token"}, body=body))
    )
    assert response.status_code == 200
    rest_payload = json.loads(response.body)
    name = "web_listening_" + operation.replace("-", "_")
    mcp_payload = finish(mcp._call_tool(lambda: runtime, name, envelope))
    tool = next(t for t in mcp._TOOLS if t.name == name)
    jsonschema.validate(envelope, tool.inputSchema)
    jsonschema.validate(mcp_payload, tool.outputSchema)
    if operation == "retrieval-methods":
        assert cli_payload == rest_payload == mcp_payload
    else:
        for field in ("outcome", "reason", "method", "fallback_used", "next_actions"):
            assert (
                cli_payload["retrieval"][field]
                == rest_payload["retrieval"][field]
                == mcp_payload["retrieval"][field]
            )


def test_one_shot_candidate_uses_remaining_budget(retrieval_runtime):
    runtime, outcomes, calls = retrieval_runtime
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    candidate = replace(
        request, scope=replace(request.scope, seeds=("https://example.test/candidate",))
    )
    outcomes["acquisition.web_http"] = "acquisition.cloudflare_blocked"
    outcomes["acquisition.playwright"] = "acquisition.cloudflare_blocked"
    outcomes[("acquisition.web_http", candidate.scope.seeds[0])] = None
    response = runtime.retrieve(request, alternates=(candidate,))
    assert response["retrieval"]["outcome"] == "FETCHED"
    assert response["retrieval"]["method"] == "OFFICIAL_ALTERNATE"
    assert response["retrieval"]["usage"]["requests"] == 3
    assert calls[-1][1].request.budgets.max_requests == request.budgets.max_requests - 2
    assert calls[-1][1].request.budgets.max_tool_attempts_per_target == 1
    assert response["provenance"][0]["candidate_url"] == candidate.scope.seeds[0]


def test_file_success_is_http_only_and_request_is_narrowed(retrieval_runtime):
    from web_listening.request.model import ContentType

    runtime, outcomes, calls = retrieval_runtime
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    request = replace(
        request,
        scope=replace(
            request.scope, content_types=(ContentType.HTML, ContentType.FILE)
        ),
    )
    outcomes["acquisition.web_http"] = ("application/pdf", b"%PDF-1.7\nfixture")
    response = runtime.retrieve_file(request)
    assert response["retrieval"]["method"] == "FILE"
    assert response["retrieval"]["outcome"] == "FETCHED"
    assert [name for name, _ in calls] == ["acquisition.web_http"]
    assert calls[0][1].request.scope.content_types == (ContentType.FILE,)
    assert request.scope.content_types == (ContentType.HTML, ContentType.FILE)


def test_sqlite_submission_is_never_visible_unclaimed(tmp_path, monkeypatch):
    jobs = JobRepository(tmp_path / "jobs.sqlite3")
    observer = JobRepository(tmp_path / "jobs.sqlite3")
    insert = jobs._insert_event
    seen = []

    def inspect_before_commit(event):
        with pytest.raises(JobStateError, match="job.not_found"):
            observer.get("selected")
        seen.append(event.status)
        insert(event)

    monkeypatch.setattr(jobs, "_insert_event", inspect_before_commit)
    try:
        jobs.submit_and_claim(
            "selected",
            _request(None),
            caller_id="owner",
            idempotency_key="atomic",
            worker_id="inline",
            at=NOW,
            lease_deadline="2026-08-25T20:01:00Z",
        )
        assert seen == [JobStatus.SUBMITTED, JobStatus.RUNNING]
        assert observer.get("selected").status is JobStatus.RUNNING
        assert (
            observer.claim_next("worker", at=NOW, lease_deadline="2026-08-25T20:01:00Z")
            is None
        )
    finally:
        observer.close()
        jobs.close()


@pytest.mark.parametrize("sqlite", [False, True])
def test_atomic_claim_fencing_terminal_replay_and_admission(tmp_path, sqlite):
    jobs = JobRepository(tmp_path / "jobs.sqlite3" if sqlite else None)
    request = _request(None)
    args = {
        "caller_id": "owner",
        "idempotency_key": "exact",
        "worker_id": "inline",
        "at": NOW,
        "lease_deadline": "2026-08-25T20:01:00Z",
    }
    try:
        with pytest.raises(JobStateError, match="request.execution_authority_invalid"):
            jobs.submit_and_claim(
                "expanded",
                request,
                execution_request=replace(
                    request, budgets=replace(request.budgets, max_requests=100)
                ),
                **args,
            )
        claim = jobs.submit_and_claim("exact", request, **args)
        with pytest.raises(JobStateError, match="job.claim_stale"):
            jobs.transition(
                "exact",
                JobStatus.FAILED,
                at=NOW,
                failure_code="runtime.failed",
                claim_token="stale",
            )
        from web_listening.result.model import ResultStatus
        from web_listening.runtime.workflow import terminal_failure_result

        result = terminal_failure_result(
            request,
            status=ResultStatus.FAILED,
            run_id="exact",
            generated_at=NOW,
            code="runtime.failed",
            message="Fixture failure",
        )
        terminal = jobs.transition(
            "exact",
            JobStatus.FAILED,
            at=NOW,
            result=result,
            failure_code="runtime.failed",
            claim_token=claim.token,
        )
        assert jobs.submit_and_claim("replayed", request, **args) == terminal
        assert len(jobs.events("exact")) == 3
    finally:
        jobs.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("caller_id", ""),
        ("idempotency_key", ""),
        ("worker_id", ""),
        ("lease_deadline", NOW),
    ],
)
@pytest.mark.parametrize("sqlite", [False, True])
def test_atomic_invalid_boundary_has_no_job(tmp_path, sqlite, field, value):
    jobs = JobRepository(tmp_path / "jobs.sqlite3" if sqlite else None)
    args = {
        "caller_id": "owner",
        "idempotency_key": "exact",
        "worker_id": "inline",
        "at": NOW,
        "lease_deadline": "2026-08-25T20:01:00Z",
    } | {field: value}
    try:
        with pytest.raises(JobStateError):
            jobs.submit_and_claim("invalid", _request(None), **args)
        with pytest.raises(JobStateError, match="job.not_found"):
            jobs.get("invalid")
    finally:
        jobs.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("reason", "FALLBACK_USED"),
        ("outcome", "PARTIAL"),
        ("method", "SEARCH"),
        ("job_ids", []),
        ("fallback_used", 1),
    ],
)
def test_state_rejects_noncanonical_fields(retrieval_runtime, field, value):
    from web_listening.runtime.retrieval import RetrievalState

    runtime, _, _ = retrieval_runtime
    state = runtime.retrieve_http(_request(None))["retrieval"]
    with pytest.raises(ValueError):
        RetrievalState.from_dict(state | {field: value})


def test_non_cloudflare_fallback_keeps_cloak(retrieval_runtime):
    runtime, outcomes, calls = retrieval_runtime
    outcomes["acquisition.web_http"] = "acquisition.script_only"
    outcomes["acquisition.playwright"] = "browser.navigation_failed"
    response = runtime.retrieve(
        _request(None, explore_all_tools=True, max_tool_attempts=3)
    )
    assert response["retrieval"]["outcome"] == "FETCHED"
    assert response["retrieval"]["method"] == "CLOAK"
    assert [name for name, _ in calls] == [
        "acquisition.web_http",
        "acquisition.playwright",
        "acquisition.cloakbrowser",
    ]


def test_open_catalog_reports_missing_engines_without_transport(tmp_path, monkeypatch):
    from web_listening.runtime import service

    def forbidden():
        raise AssertionError("catalog attempted target transport")

    monkeypatch.setattr(service, "PinnedHttpTransport", forbidden)
    runtime = service.RuntimeService.open(tmp_path)
    try:
        methods = runtime.retrieval_methods(
            _request(None, explore_all_tools=True, max_tool_attempts=3)
        )["methods"]
        browser = next(m for m in methods if m["method"] == "BROWSER")
        assert not browser["eligible"]
        assert not browser["active"]
        assert not browser["healthy"]
        assert not browser["qualified"]
        assert "eligibility.not_installed" in browser["reasons"]
        assert next(m for m in methods if m["method"] == "HTTP")["eligible"]
    finally:
        runtime.close()


def test_rejected_result_is_not_expected_unresolved():
    from web_listening.result.model import ResultStatus
    from web_listening.runtime.retrieval import retrieval_error_code
    from web_listening.runtime.workflow import terminal_failure_result

    result = terminal_failure_result(
        _request(None),
        status=ResultStatus.REJECTED,
        run_id="rejected",
        generated_at=NOW,
        code="site_skill.invalid",
        message="Invalid skill",
    )
    assert retrieval_error_code(result) == "site_skill.invalid"


def test_recognized_200_cloudflare_template_never_escalates_to_cloak(retrieval_runtime):
    runtime, outcomes, calls = retrieval_runtime
    blocked = ("text/html", b"<script src='/cf-chl-challenge.js'></script>")
    outcomes["acquisition.web_http"] = blocked
    outcomes["acquisition.playwright"] = blocked
    response = runtime.retrieve(
        _request(None, explore_all_tools=True, max_tool_attempts=3)
    )
    assert response["retrieval"]["outcome"] == "UNRESOLVED"
    assert response["retrieval"]["reason"] == "CLOUDFLARE_BLOCKED"
    assert [name for name, _ in calls] == [
        "acquisition.web_http",
        "acquisition.playwright",
    ]


@pytest.mark.parametrize("mutation", ["artifact_id", "unresolved_http_ok"])
def test_state_rejects_noncanonical_artifact_and_outcome(retrieval_runtime, mutation):
    from web_listening.runtime.retrieval import RetrievalState

    runtime, _, _ = retrieval_runtime
    value = runtime.retrieve_http(_request(None))["retrieval"]
    if mutation == "artifact_id":
        value["artifacts"][0][1] = "not-an-artifact-id"
    else:
        value["outcome"], value["artifacts"] = "UNRESOLVED", []
    with pytest.raises(ValueError):
        RetrievalState.from_dict(value)


OPERATIONAL_CODES = (
    "browser.runtime_missing",
    "browser.container_runtime_missing",
    "browser.runtime_mismatch",
    "browser.binary_digest_mismatch",
    "browser.sdk_version_mismatch",
    "browser.inactive",
    "browser.bridge_unavailable",
    "isolated_runtime.qualification_required",
    "isolated_runtime.health_failed",
    "isolated_runtime.probe_failed",
    "isolated_runtime.describe_failed",
    "isolated_runtime.broken",
    "lifecycle.install_failed",
    "lifecycle.qualification_failed",
    "lifecycle.not_activatable",
    "runner.startup_error",
    "runner.nonzero_exit",
    "registry.not_found",
    "registry.identity_mismatch",
    "runtime.workflow_failed",
)


@pytest.mark.parametrize("code", OPERATIONAL_CODES)
@pytest.mark.parametrize("exact", [True, False])
def test_review9_operational_failures_are_terminal(retrieval_runtime, code, exact):
    from web_listening.tool_registry.eligibility import (
        acquisition_failure_allows_switch,
    )

    runtime, outcomes, calls = retrieval_runtime
    request = _request(None, explore_all_tools=True, max_tool_attempts=4)
    outcomes["acquisition.web_http"] = "acquisition.script_only"
    outcomes["acquisition.playwright"] = code
    alternate = replace(
        request, scope=replace(request.scope, seeds=("https://example.test/alternate",))
    )
    with pytest.raises(JobStateError, match=code):
        if exact:
            runtime.retrieve_browser(request)
        else:
            runtime.retrieve(request, alternates=(alternate,))
    assert [name for name, _ in calls] == (
        ["acquisition.playwright"]
        if exact
        else ["acquisition.web_http", "acquisition.playwright"]
    )
    assert not acquisition_failure_allows_switch(code, "acquisition.playwright")


@pytest.mark.parametrize("sqlite", [False, True])
def test_review9_failed_file_persists_exact_execution(
    retrieval_runtime, tmp_path, sqlite
):
    import json

    from web_listening.request.model import ContentType
    from web_listening.runtime.retrieval import RetrievalState, project_retrieval

    runtime, outcomes, _ = retrieval_runtime
    original_jobs = runtime._jobs
    jobs = JobRepository(tmp_path / "file-jobs.sqlite3") if sqlite else original_jobs
    runtime._jobs = jobs
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    request = replace(
        request,
        scope=replace(
            request.scope, content_types=(ContentType.HTML, ContentType.FILE)
        ),
    )
    outcomes["acquisition.web_http"] = "gateway.server_error"
    try:
        response = runtime.retrieve_file(request)
        job = runtime.get_owned_job(response["jobs"][0]["job_id"], "local")
        assert set(json.loads(job.request_json)["scope"]["content_types"]) == {
            "html",
            "file",
        }
        assert json.loads(job.execution_request_json)["scope"]["content_types"] == [
            "file"
        ]
        assert response["retrieval"]["method"] == "FILE"
        assert response["retrieval"]["outcome"] == "UNRESOLVED"
        assert (
            runtime.get_owned_handoff(job.job_id, "local").to_dict()["job_id"]
            == job.job_id
        )
        if sqlite:
            jobs.close()
            jobs = JobRepository(tmp_path / "file-jobs.sqlite3")
            runtime._jobs = jobs
            job = runtime.get_owned_job(job.job_id, "local")
        state = project_retrieval([job], runtime.retrieval_methods(request)["methods"])
        assert RetrievalState.from_dict(state.to_dict()).method == "FILE"
        with pytest.raises(JobStateError, match="job.not_found"):
            runtime.get_owned_job(job.job_id, "other")
    finally:
        runtime._jobs = original_jobs
        if sqlite:
            jobs.close()


@pytest.mark.parametrize(
    "code",
    [
        "browser.runtime_missing",
        "isolated_runtime.health_failed",
        "runner.startup_error",
        "gateway.server_error",
    ],
)
def test_review9_interface_errors_and_failed_file(
    retrieval_runtime, monkeypatch, tmp_path, capsys, code
):
    import json
    from dataclasses import asdict
    from types import SimpleNamespace

    pytest.importorskip("mcp")
    pytest.importorskip("fastapi")
    from web_listening.interfaces import cli, mcp, rest
    from web_listening.request.model import ContentType
    from web_listening.runtime.retrieval import OPERATIONS

    runtime, outcomes, _ = retrieval_runtime
    file_failure = code == "gateway.server_error"
    operation = "retrieve-file" if file_failure else "retrieve-browser"
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    request = replace(
        request,
        scope=replace(
            request.scope, content_types=(ContentType.HTML, ContentType.FILE)
        ),
    )
    outcomes["acquisition.web_http" if file_failure else "acquisition.playwright"] = (
        code
    )
    envelope = {"request": json.loads(json.dumps(asdict(request)))}

    async def immediate(function, *args, **kwargs):
        return function(*args, **kwargs)

    def finish(coroutine):
        with pytest.raises(StopIteration) as ended:
            coroutine.send(None)
        return ended.value.value

    monkeypatch.setattr(mcp.anyio.to_thread, "run_sync", immediate)
    monkeypatch.setattr(rest, "run_in_threadpool", immediate)
    monkeypatch.setattr(
        cli, "_run_with_runtime", lambda _path, operation: operation(runtime)
    )
    path = tmp_path / "request.json"
    path.write_text(json.dumps(envelope["request"]))
    exit_code = cli.main(
        [operation, "--request", str(path), "--output", str(tmp_path), "--json"]
    )
    captured = capsys.readouterr()
    assert (exit_code == 0) is file_failure
    app = rest.create_app(
        lambda: runtime, rest.RestConfig("local", hashlib.sha256(b"token").hexdigest())
    )
    endpoint = next(r.endpoint for r in app.routes if r.path == OPERATIONS[operation])

    async def body():
        return json.dumps(envelope).encode()

    response = finish(
        endpoint(SimpleNamespace(headers={"authorization": "Bearer token"}, body=body))
    )
    mcp_response = finish(
        mcp._call_tool(
            lambda: runtime, "web_listening_" + operation.replace("-", "_"), envelope
        )
    )
    if file_failure:
        assert response.status_code == 200
        for payload in (
            json.loads(captured.out),
            json.loads(response.body),
            mcp_response,
        ):
            assert payload["retrieval"]["method"] == "FILE"
            assert payload["retrieval"]["outcome"] == "UNRESOLVED"
    else:
        assert response.status_code == 500
        assert mcp_response.isError


def test_review9_operational_error_is_not_hidden_by_committed_artifact(
    retrieval_runtime,
):
    from web_listening.result.errors import SafeError
    from web_listening.runtime.retrieval import retrieval_error_code

    runtime, _, _ = retrieval_runtime
    response = runtime.retrieve_http(_request(None))
    result = runtime.get_job(response["jobs"][0]["job_id"]).result
    assert result.artifacts
    from web_listening.result.model import ResultStatus

    result = replace(
        result,
        status=ResultStatus.PARTIAL,
        errors=(SafeError("runner.cleanup_error", "Cleanup failed."),),
    )
    assert retrieval_error_code(result) == "runner.cleanup_error"
