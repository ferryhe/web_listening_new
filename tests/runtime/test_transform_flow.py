"""Offline Runtime orchestration tests for stored HTML Transform flow."""

# pylint: disable=line-too-long,missing-function-docstring,too-few-public-methods
# pylint: disable=too-many-arguments

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

import web_listening.runtime.workflow as workflow_module
from web_listening.artifact.model import ArtifactRole
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.result.attempts import Attempt
from web_listening.result.errors import ResultValidationError
from web_listening.result.model import ResultStatus
from web_listening.runtime.service import RuntimeService
from web_listening.runtime.workflow import run_single_target
from web_listening.site_skill.model import SuccessChecks, ToolReference
from web_listening.site_skill.update import create_candidate
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.protocols.transform import (
    TransformFailure,
    TransformInput,
    TransformOutput,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)

URL = "https://example.test/report"
NOW = "2026-08-26T12:00:00Z"
HTML = b"<html><body><main><h1>Report</h1><p>Five visible words make quality sufficient.</p></main></body></html>"
MARKDOWN = b"# Report\n\nFive visible words make quality sufficient.\n"
ACQUISITION_MANIFEST = ToolManifest(
    tool_id="acquisition.test_http",
    version="1.0.0",
    category=ToolCategory.ACQUISITION,
    distribution=ToolDistribution.BUILTIN,
    capabilities=frozenset({"http_get"}),
    limits=ToolLimits(30, 2 * 1024 * 1024, 2 * 1024 * 1024),
    health=HealthStatus.HEALTHY,
    qualification=QualificationStatus.QUALIFIED,
)
FAKE_TRANSFORM_MANIFEST = replace(
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    tool_id="transform.test_markdown",
    version="2.3.4",
)
WRONG_CAPABILITY_MANIFEST = replace(
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    tool_id="transform.wrong_capability",
    capabilities=frozenset({"other_transform"}),
)


class _Acquisition:
    manifest = ACQUISITION_MANIFEST

    def __init__(self, body: bytes = HTML, runtime_ms: int = 7) -> None:
        self.body = body
        self.runtime_ms = runtime_ms
        self.calls = 0

    def acquire(self, tool_input: AcquisitionInput) -> AcquisitionOutput:
        self.calls += 1
        return AcquisitionOutput(
            self.manifest.tool_id,
            self.manifest.version,
            tool_input.target_url,
            tool_input.target_url,
            200,
            "text/html",
            self.body,
            hashlib.sha256(self.body).hexdigest(),
            (),
            self.runtime_ms,
        )


class _UnexpectedAcquisition:
    manifest = replace(ACQUISITION_MANIFEST, tool_id="acquisition.unexpected")

    def __init__(self) -> None:
        self.calls = 0

    def acquire(self, _tool_input: AcquisitionInput) -> AcquisitionOutput:
        self.calls += 1
        raise AssertionError("Transform failure triggered Acquisition fallback")


class _EligibilityCountingRegistry(Registry):
    def __init__(self) -> None:
        super().__init__()
        self.eligible_calls = 0

    def eligible(self, requirements):
        self.eligible_calls += 1
        return super().eligible(requirements)


class _TransformFailure:
    manifest = FAKE_TRANSFORM_MANIFEST

    def __init__(self, code: str = "transform.failed") -> None:
        self.code = code
        self.calls = 0
        self.sources = []

    def transform(self, tool_input: TransformInput) -> TransformFailure:
        self.calls += 1
        self.sources.append(tool_input.source)
        return TransformFailure(
            self.manifest.tool_id,
            self.manifest.version,
            self.code,
        )


class _WrongMimeTransform:
    manifest = FAKE_TRANSFORM_MANIFEST

    def __init__(self) -> None:
        self.calls = 0

    def transform(self, tool_input: TransformInput) -> TransformOutput:
        self.calls += 1
        body = b"plain output"
        return TransformOutput(
            self.manifest.tool_id,
            self.manifest.version,
            tool_input.source.artifact.artifact_id,
            "text/plain",
            body,
            hashlib.sha256(body).hexdigest(),
            3,
        )


class _ReportedRuntimeTransform:
    manifest = FAKE_TRANSFORM_MANIFEST

    def __init__(self, runtime_ms: int) -> None:
        self.runtime_ms = runtime_ms
        self.calls = 0

    def transform(self, tool_input: TransformInput) -> TransformOutput:
        self.calls += 1
        body = b"# Derived report\n"
        return TransformOutput(
            self.manifest.tool_id,
            self.manifest.version,
            tool_input.source.artifact.artifact_id,
            "text/markdown",
            body,
            hashlib.sha256(body).hexdigest(),
            self.runtime_ms,
        )


class _RaisingTransform:
    manifest = FAKE_TRANSFORM_MANIFEST

    def __init__(self) -> None:
        self.calls = 0

    def transform(self, _tool_input: TransformInput) -> TransformOutput:
        self.calls += 1
        raise RuntimeError("generic Transform crashed")


class _WrongCapabilityTransform:
    manifest = WRONG_CAPABILITY_MANIFEST

    def __init__(self) -> None:
        self.calls = 0

    def transform(self, _tool_input: TransformInput) -> TransformFailure:
        self.calls += 1
        raise AssertionError("wrong-capability Transform was invoked")


def _request(max_tool_attempts: int = 2, max_runtime_seconds: int = 30) -> Request:
    scope = Scope(
        seeds=(URL,),
        allowed_origins=("https://example.test",),
        include_paths=("/**",),
        content_types=(ContentType.HTML,),
    )
    budgets = Budgets(
        6,
        2 * 1024 * 1024,
        max_runtime_seconds,
        max_tool_attempts,
    )
    skill = create_candidate(
        site_key="example",
        version=1,
        previous=None,
        scope=scope,
        budgets=budgets,
        tool=ToolReference(
            ACQUISITION_MANIFEST.tool_id,
            ACQUISITION_MANIFEST.version,
            ToolCategory.ACQUISITION,
            ACQUISITION_MANIFEST.capabilities,
        ),
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
    ).skill
    return Request(scope, skill, False, budgets)


def _run(
    tmp_path: Path,
    transform: object,
    *,
    unexpected: _UnexpectedAcquisition | None = None,
    body: bytes = HTML,
    before_transforms: tuple[object, ...] = (),
    request: Request | None = None,
    clock=None,
    registry: Registry | None = None,
    acquisition_runtime_ms: int = 7,
):
    acquisition = _Acquisition(body, acquisition_runtime_ms)
    registry = registry or Registry()
    registry.register(acquisition.manifest, acquisition)
    if unexpected is not None:
        registry.register(unexpected.manifest, unexpected)
    for prior_transform in before_transforms:
        registry.register(prior_transform.manifest, prior_transform)
    registry.register(transform.manifest, transform)
    store = ArtifactStore(tmp_path / "artifacts")
    result = run_single_target(
        request or _request(),
        registry,
        store,
        run_id="run-transform",
        clock=clock or (lambda: NOW),
    )
    return result, store, acquisition


def test_attempt_accepts_truthful_zero_network_transform_success() -> None:
    attempt = Attempt(
        order=1,
        attempt_id="run-transform-transform",
        outcome="succeeded",
        tool_id=FAKE_TRANSFORM_MANIFEST.tool_id,
        tool_version=FAKE_TRANSFORM_MANIFEST.version,
        started_at=NOW,
        finished_at=NOW,
        requested_url=URL,
        final_url=None,
        http_status=None,
        error=None,
        requests=0,
        bytes_received=0,
        runtime_ms=3,
    )

    assert attempt.requests == 0
    assert attempt.final_url is None
    assert attempt.http_status is None


def test_success_stores_derived_markdown_lineage_and_tool_attempt(
    tmp_path: Path,
) -> None:
    result, store, acquisition = _run(tmp_path, SimpleHtmlMarkdownTransform())
    try:
        assert result.status is ResultStatus.COMPLETED
        assert acquisition.calls == 1
        assert [artifact.role for artifact in result.artifacts] == [
            "source",
            "derived",
        ]
        source_evidence, derived_evidence = result.artifacts
        source = store.get_observation(source_evidence.observation_id)
        derived = store.get_observation(derived_evidence.observation_id)
        assert source.content == HTML
        assert source.artifact.role is ArtifactRole.SOURCE
        assert derived.content == MARKDOWN
        assert derived.artifact.role is ArtifactRole.DERIVED
        assert (
            derived.lineage[0].source_observation_id
            == source.observation.observation_id
        )
        assert derived.lineage[0].source_artifact_id == source.artifact.artifact_id

        acquisition_attempt, transform_attempt = result.attempts
        assert acquisition_attempt.tool_id == ACQUISITION_MANIFEST.tool_id
        assert transform_attempt.outcome == "succeeded"
        assert transform_attempt.tool_id == SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id
        assert transform_attempt.tool_version == SIMPLE_HTML_MARKDOWN_MANIFEST.version
        assert transform_attempt.requests == 0
        assert transform_attempt.bytes_received == 0
        assert transform_attempt.final_url is None
        assert transform_attempt.http_status is None
        assert result.usage.requests == 1
        assert result.usage.bytes_received == len(HTML)
        assert result.usage.tool_attempts == 2
        assert derived_evidence.source_url == (
            "urn:web-listening:transform:"
            f"{transform_attempt.tool_id}:{transform_attempt.tool_version}"
        )
    finally:
        store.close()


def test_transform_is_not_invoked_beyond_caller_tool_attempt_budget(
    tmp_path: Path,
) -> None:
    transform = _TransformFailure()
    unexpected = _UnexpectedAcquisition()
    registry = _EligibilityCountingRegistry()
    times = iter(("2026-08-26T12:00:00Z", "2026-08-26T12:00:01Z"))
    result, store, acquisition = _run(
        tmp_path,
        transform,
        unexpected=unexpected,
        request=_request(max_tool_attempts=1),
        clock=lambda: next(times),
        registry=registry,
    )
    try:
        assert acquisition.calls == 1
        assert unexpected.calls == 0
        assert transform.calls == 0
        assert registry.eligible_calls == 0
        assert len(result.artifacts) == 1
        assert store.get_observation(result.artifacts[0].observation_id).content == HTML
        assert result.status is ResultStatus.COMPLETED
        assert len(result.attempts) == 1
        assert not result.errors
        assert result.usage.tool_attempts == 1
    finally:
        store.close()


def test_transform_is_not_selected_after_acquisition_exhausts_runtime_budget(
    tmp_path: Path,
) -> None:
    transform = _TransformFailure()
    unexpected = _UnexpectedAcquisition()
    registry = _EligibilityCountingRegistry()
    times = iter(("2026-08-26T12:00:00Z", "2026-08-26T12:00:01Z"))
    result, store, acquisition = _run(
        tmp_path,
        transform,
        unexpected=unexpected,
        request=_request(max_runtime_seconds=1),
        clock=lambda: next(times),
        registry=registry,
        acquisition_runtime_ms=1_000,
    )
    try:
        assert acquisition.calls == 1
        assert unexpected.calls == 0
        assert transform.calls == 0
        assert registry.eligible_calls == 0
        assert result.status is ResultStatus.COMPLETED
        assert len(result.artifacts) == 1
        assert len(result.attempts) == 1
        assert result.usage.runtime_ms == 1_000
    finally:
        store.close()


def test_transform_over_cumulative_runtime_budget_fails_before_derived_commit(
    tmp_path: Path,
) -> None:
    transform = _ReportedRuntimeTransform(30_000)
    unexpected = _UnexpectedAcquisition()
    result, store, acquisition = _run(
        tmp_path,
        transform,
        unexpected=unexpected,
        request=_request(max_runtime_seconds=1),
    )
    try:
        assert acquisition.calls == 1
        assert unexpected.calls == 0
        assert transform.calls == 1
        assert result.status is ResultStatus.PARTIAL
        assert len(result.artifacts) == 1
        assert store.get_observation(result.artifacts[0].observation_id).content == HTML
        assert result.attempts[1].outcome == "failed"
        assert result.attempts[1].runtime_ms == 30_000
        assert result.attempts[1].error is not None
        assert (
            result.attempts[1].error.code == "runtime.transform_runtime_budget_exceeded"
        )
        assert result.errors == (result.attempts[1].error,)
        assert result.usage.runtime_ms == 30_007
        assert result.usage.tool_attempts == 2
    finally:
        store.close()


def test_runtime_selects_html_to_markdown_capability_not_registration_order(
    tmp_path: Path,
) -> None:
    wrong = _WrongCapabilityTransform()
    result, store, _acquisition = _run(
        tmp_path,
        SimpleHtmlMarkdownTransform(),
        before_transforms=(wrong,),
    )
    try:
        assert wrong.calls == 0
        assert result.status is ResultStatus.COMPLETED
        assert result.attempts[1].tool_id == SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id
    finally:
        store.close()


def test_manifest_timestamp_follows_transform_and_derived_commit(
    tmp_path: Path,
) -> None:
    times = iter(
        (
            "2026-08-26T12:00:00Z",
            "2026-08-26T12:00:01Z",
            "2026-08-26T12:00:02Z",
            "2026-08-26T12:00:03Z",
            "2026-08-26T12:00:04Z",
        )
    )
    result, store, _acquisition = _run(
        tmp_path,
        SimpleHtmlMarkdownTransform(),
        clock=lambda: next(times),
    )
    try:
        derived = result.artifacts[1]
        assert result.attempts[0].finished_at == "2026-08-26T12:00:01Z"
        assert result.attempts[1].finished_at == "2026-08-26T12:00:03Z"
        assert derived.observed_at == "2026-08-26T12:00:03Z"
        assert result.manifest.generated_at == "2026-08-26T12:00:04Z"
    finally:
        store.close()


def test_non_markdown_output_is_failed_before_derived_commit(
    tmp_path: Path,
) -> None:
    transform = _WrongMimeTransform()
    unexpected = _UnexpectedAcquisition()
    result, store, acquisition = _run(
        tmp_path,
        transform,
        unexpected=unexpected,
    )
    try:
        assert acquisition.calls == 1
        assert unexpected.calls == 0
        assert transform.calls == 1
        assert len(result.artifacts) == 1
        assert store.get_observation(result.artifacts[0].observation_id).content == HTML
        assert result.attempts[1].outcome == "failed"
        assert result.attempts[1].error is not None
        assert result.attempts[1].error.code == "runtime.transform_output_mime_invalid"
        assert result.usage.tool_attempts == 2
        assert result.errors == (result.attempts[1].error,)
    finally:
        store.close()


def test_derived_commit_failure_uses_post_failure_timestamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_commit = ArtifactStore.commit_observation

    def fail_derived_commit(self, proposal):
        if proposal.role is ArtifactRole.DERIVED:
            raise RuntimeError("derived commit failed")
        return original_commit(self, proposal)

    monkeypatch.setattr(ArtifactStore, "commit_observation", fail_derived_commit)
    times = iter(
        (
            "2026-08-26T12:00:00Z",
            "2026-08-26T12:00:01Z",
            "2026-08-26T12:00:02Z",
            "2026-08-26T12:00:03Z",
            "2026-08-26T12:00:04Z",
        )
    )
    result, store, _acquisition = _run(
        tmp_path,
        SimpleHtmlMarkdownTransform(),
        clock=lambda: next(times),
    )
    try:
        assert len(result.artifacts) == 1
        assert result.attempts[1].outcome == "failed"
        assert result.attempts[1].finished_at == "2026-08-26T12:00:04Z"
        assert result.manifest.generated_at == "2026-08-26T12:00:04Z"
        assert result.errors[0].code == "runtime.derived_commit_failed"
    finally:
        store.close()


def test_manifest_rejects_transform_attempt_without_bound_derived_lineage(
    tmp_path: Path,
) -> None:
    result, store, _acquisition = _run(tmp_path, SimpleHtmlMarkdownTransform())
    try:
        source, derived = result.artifacts
        unbound = replace(derived, source_url="urn:web-listening:derived:markdown")
        with pytest.raises(ResultValidationError) as caught:
            replace(result.manifest, artifacts=(source, unbound))
    finally:
        store.close()

    assert caught.value.code == "manifest.transform_lineage_invalid"


def test_manifest_rejects_a_second_successful_transform_attempt(
    tmp_path: Path,
) -> None:
    result, store, _acquisition = _run(tmp_path, SimpleHtmlMarkdownTransform())
    try:
        acquisition_attempt, transform_attempt = result.attempts
        duplicate = replace(
            transform_attempt,
            order=2,
            attempt_id="run-transform-transform-duplicate",
        )
        with pytest.raises(ResultValidationError) as caught:
            replace(
                result.manifest,
                attempts=(acquisition_attempt, transform_attempt, duplicate),
                usage=replace(result.usage, tool_attempts=3),
            )
    finally:
        store.close()

    assert caught.value.code == "manifest.success_cardinality_invalid"


def test_invoked_ineligible_complex_html_records_failure_and_preserves_source(
    tmp_path: Path,
) -> None:
    complex_html = (
        b"<html><body>"
        + b"<div>" * 65
        + b"enough visible words for the explicit quality threshold"
        + b"</div>" * 65
        + b"</body></html>"
    )
    result, store, acquisition = _run(
        tmp_path,
        SimpleHtmlMarkdownTransform(),
        body=complex_html,
    )
    try:
        assert result.status is ResultStatus.PARTIAL
        assert acquisition.calls == 1
        assert len(result.artifacts) == 1
        assert (
            store.get_observation(result.artifacts[0].observation_id).content
            == complex_html
        )
        assert result.attempts[1].outcome == "failed"
        assert result.attempts[1].error is not None
        assert result.attempts[1].error.code == "transform.ineligible_complex"
        assert result.usage.tool_attempts == 2
        assert result.errors == (result.attempts[1].error,)
    finally:
        store.close()


def test_transform_failure_preserves_original_and_never_falls_back(
    tmp_path: Path,
) -> None:
    transform = _TransformFailure()
    unexpected = _UnexpectedAcquisition()
    result, store, acquisition = _run(
        tmp_path,
        transform,
        unexpected=unexpected,
    )
    try:
        assert result.status is ResultStatus.PARTIAL
        assert acquisition.calls == 1
        assert unexpected.calls == 0
        assert transform.calls == 1
        assert len(transform.sources) == 1
        assert transform.sources[0].content == HTML
        assert len(result.artifacts) == 1
        source = store.get_observation(result.artifacts[0].observation_id)
        assert source.content == HTML
        assert result.attempts[1].outcome == "failed"
        assert result.attempts[1].requests == 0
        assert result.attempts[1].error == result.errors[0]
        assert result.errors[0].code == "transform.failed"
    finally:
        store.close()


@pytest.mark.parametrize(
    ("raises", "expected_code"),
    [
        (False, "transform.failed"),
        (True, "registry.tool_exception"),
    ],
)
def test_generic_transform_failure_records_measured_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    raises: bool,
    expected_code: str,
) -> None:
    ticks = iter((1_000_000_000, 1_007_900_000))
    monkeypatch.setattr(workflow_module.time, "monotonic_ns", lambda: next(ticks))
    transform = _RaisingTransform() if raises else _TransformFailure()
    result, store, _acquisition = _run(tmp_path, transform)
    try:
        assert transform.calls == 1
        assert result.attempts[1].outcome == "failed"
        assert result.attempts[1].runtime_ms == 7
        assert result.attempts[1].error is not None
        assert result.attempts[1].error.code == expected_code
        assert result.usage.runtime_ms == 14
    finally:
        store.close()


def test_measured_transform_failure_obeys_remaining_runtime_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticks = iter((1_000_000_000, 3_000_000_000))
    monkeypatch.setattr(workflow_module.time, "monotonic_ns", lambda: next(ticks))
    transform = _TransformFailure()
    unexpected = _UnexpectedAcquisition()
    result, store, acquisition = _run(
        tmp_path,
        transform,
        unexpected=unexpected,
        request=_request(max_runtime_seconds=1),
    )
    try:
        assert acquisition.calls == 1
        assert unexpected.calls == 0
        assert transform.calls == 1
        assert len(result.artifacts) == 1
        assert result.attempts[1].runtime_ms == 2_000
        assert result.attempts[1].error is not None
        assert (
            result.attempts[1].error.code == "runtime.transform_runtime_budget_exceeded"
        )
        assert result.usage.runtime_ms == 2_007
    finally:
        store.close()


def test_runtime_service_open_registers_the_one_builtin_transform(
    tmp_path: Path,
) -> None:
    service = RuntimeService.open(tmp_path / "runtime")
    try:
        transforms = service._registry.query(  # pylint: disable=protected-access
            category=ToolCategory.TRANSFORM
        )
    finally:
        service.close()

    assert transforms == (SIMPLE_HTML_MARKDOWN_MANIFEST,)
