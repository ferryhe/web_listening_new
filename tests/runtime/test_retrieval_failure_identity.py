"""Regression coverage for targeted retrieval terminal failure identity."""

# Intentional Runtime fixture access mirrors the existing retrieval contract tests.
# pylint: disable=import-error,import-outside-toplevel,missing-function-docstring
# pylint: disable=missing-class-docstring,protected-access,too-few-public-methods
# pylint: disable=too-many-locals,unidiomatic-typecheck

import pytest

from tests.runtime.test_service import NOW, _request
from web_listening.runtime.jobs import JobRepository, JobStateError, JobStatus

pytest_plugins = ("tests.runtime.test_retrieval",)


def test_terminal_retrieval_failure_keeps_owned_job_identity(retrieval_runtime):
    """Terminal failures expose only their durable, caller-owned Job identity."""
    from web_listening.runtime.retrieval import RetrievalJobError

    runtime, outcomes, _ = retrieval_runtime
    request = _request(None, explore_all_tools=True, max_tool_attempts=3)
    runtime._jobs.submit_request(
        "older",
        request,
        caller_id="owner",
        idempotency_key="older",
        at=NOW,
    )
    outcomes["acquisition.web_http"] = "robots.disallowed"

    with pytest.raises(RetrievalJobError, match="robots.disallowed") as raised:
        runtime.retrieve(request, caller_id="owner")

    failure = raised.value
    assert isinstance(failure, JobStateError)
    assert failure.code == str(failure) == "robots.disallowed"
    assert failure.job_id
    assert "result" not in vars(failure)
    persisted = runtime.get_owned_job(failure.job_id, "owner")
    assert persisted.result is not None
    assert persisted.result.usage.requests == 1
    assert runtime.get_job("older").status is JobStatus.SUBMITTED
    with pytest.raises(JobStateError, match="job.not_found"):
        runtime.get_owned_job(failure.job_id, "other")


def test_rejected_terminal_result_keeps_owned_job_identity(retrieval_runtime):
    from web_listening.request.model import RequestValidationError
    from web_listening.result.model import ResultStatus
    from web_listening.runtime.retrieval import RetrievalRequestError
    from web_listening.runtime.workflow import terminal_failure_result

    runtime, _, _ = retrieval_runtime

    def rejected(job_id, request, _cancellation):
        result = terminal_failure_result(
            request,
            status=ResultStatus.REJECTED,
            run_id=job_id,
            generated_at=NOW,
            code="site_skill.invalid",
            message="Invalid skill.",
        )
        return runtime._jobs.transition(
            job_id,
            JobStatus.REJECTED,
            at=NOW,
            result=result,
            failure_code="site_skill.invalid",
            claim_token=runtime._jobs.get(job_id).claim_token,
        )

    runtime.execute_submitted = rejected
    with pytest.raises(RetrievalRequestError, match="site_skill.invalid") as raised:
        runtime.retrieve(_request(None), caller_id="owner")

    failure = raised.value
    assert isinstance(failure, RequestValidationError)
    assert failure.code == str(failure) == "site_skill.invalid"
    assert runtime.get_owned_job(failure.job_id, "owner").status is JobStatus.REJECTED


@pytest.mark.parametrize(
    "code",
    [
        "scope.path_not_included",
        "robots.disallowed",
        "gateway.request_budget_exhausted",
        "runner.startup_error",
    ],
)
def test_terminal_failure_identity_covers_governed_error_families(
    retrieval_runtime, code
):
    from web_listening.runtime.retrieval import RetrievalJobError

    runtime, outcomes, _ = retrieval_runtime
    outcomes["acquisition.web_http"] = code
    with pytest.raises(RetrievalJobError, match=code) as raised:
        runtime.retrieve(_request(None), caller_id="owner")
    assert runtime.get_owned_job(raised.value.job_id, "owner").result is not None


def test_pre_admission_error_has_no_retrieval_identity(retrieval_runtime):
    from web_listening.request.model import RequestValidationError

    runtime, _, _ = retrieval_runtime
    with pytest.raises(
        RequestValidationError, match="retrieval.method_invalid"
    ) as raised:
        runtime.retrieve(_request(None), method="INVALID")
    assert type(raised.value) is RequestValidationError
    assert not hasattr(raised.value, "job_id")


@pytest.mark.parametrize("outcome", ["robots.disallowed", None])
def test_retrieval_isolation_survives_sqlite_reopen_without_running_older_job(
    retrieval_runtime, tmp_path, outcome
):
    from web_listening.runtime.retrieval import RetrievalJobError

    runtime, outcomes, _ = retrieval_runtime
    original_jobs = runtime._jobs
    database = tmp_path / "retrieval-failures.sqlite3"
    runtime._jobs = JobRepository(database)
    request = _request(None)
    try:
        runtime._jobs.submit_request(
            "older",
            request,
            caller_id="owner",
            idempotency_key="older",
            at=NOW,
        )
        outcomes["acquisition.web_http"] = outcome
        if outcome:
            with pytest.raises(RetrievalJobError) as raised:
                runtime.retrieve(request, caller_id="owner")
            job_id = raised.value.job_id
        else:
            response = runtime.retrieve(request, caller_id="owner")
            assert set(response) == {"jobs", "retrieval", "provenance"}
            job_id = response["jobs"][0]["job_id"]

        runtime._jobs.close()
        runtime._jobs = JobRepository(database)
        assert runtime.get_job("older").status is JobStatus.SUBMITTED
        restored = runtime.get_owned_job(job_id, "owner")
        assert restored.status is (JobStatus.FAILED if outcome else JobStatus.COMPLETED)
        assert restored.result is not None
    finally:
        runtime._jobs.close()
        runtime._jobs = original_jobs


def test_success_envelope_remains_compatible(retrieval_runtime):
    runtime, _, _ = retrieval_runtime

    response = runtime.retrieve(_request(None), caller_id="owner")

    assert set(response) == {"jobs", "retrieval", "provenance"}
    assert runtime.get_owned_job(response["jobs"][0]["job_id"], "owner").result


def test_operational_failure_identity_persists_artifact_grant_in_sqlite(
    retrieval_runtime, tmp_path
):
    from web_listening.artifact.model import ArtifactStoreError
    from web_listening.request.validate import request_from_json
    from web_listening.runtime.retrieval import RetrievalJobError
    from web_listening.tool_registry.protocols.transform import TransformFailure
    from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
        SIMPLE_HTML_MARKDOWN_MANIFEST,
        SimpleHtmlMarkdownTransform,
    )

    class CleanupFailureTransform(SimpleHtmlMarkdownTransform):
        def transform(self, tool_input):
            del tool_input
            return TransformFailure(
                SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id,
                SIMPLE_HTML_MARKDOWN_MANIFEST.version,
                "runner.cleanup_error",
            )

    runtime, _, _ = retrieval_runtime
    original_jobs = runtime._jobs
    database = tmp_path / "retrieval-artifact-failure.sqlite3"
    runtime._jobs = JobRepository(database)
    request = _request(None, max_tool_attempts=2)
    runtime._registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, CleanupFailureTransform())
    try:
        with pytest.raises(RetrievalJobError, match="runner.cleanup_error") as raised:
            runtime.retrieve(request, caller_id="owner")

        job_id = raised.value.job_id
        runtime._jobs.close()
        runtime._jobs = JobRepository(database)
        persisted = runtime.get_owned_job(job_id, "owner")
        assert request_from_json(persisted.request_json) == request
        assert persisted.status is JobStatus.PARTIAL
        assert persisted.result is not None
        assert [attempt.outcome for attempt in persisted.result.attempts] == [
            "succeeded",
            "failed",
        ]
        assert persisted.result.usage.requests == 1
        artifact_id = persisted.result.artifacts[0].artifact_id
        assert runtime.read_owned_artifact(artifact_id, "owner").content
        with pytest.raises(ArtifactStoreError, match="artifact.not_found"):
            runtime.read_owned_artifact(artifact_id, "other")
    finally:
        runtime._jobs.close()
        runtime._jobs = original_jobs
