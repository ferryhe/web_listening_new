"""Focused offline tests for one bounded external exploration proposal."""

# pylint: disable=duplicate-code,missing-class-docstring,missing-function-docstring
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-locals
# pylint: disable=too-many-lines

from __future__ import annotations

import asyncio
import hashlib
import inspect
from dataclasses import FrozenInstanceError, dataclass, field
from pathlib import Path

import pytest

import web_listening.runtime.workflow as workflow_module
from web_listening.artifact.model import ArtifactStoreError
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.runtime.workflow import (
    BoundedActionProposal,
    ExplorationMetadata,
    run_agent_assisted_target,
    run_single_target,
)
from web_listening.site_skill.model import (
    SiteSkillError,
    SuccessChecks,
    ToolReference,
)
from web_listening.site_skill.update import create_candidate
from web_listening.site_skill.validate import (
    site_skill_from_mapping,
    site_skill_to_mapping,
)
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
)
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.registry import Registry

INITIAL_URL = "https://example.test/monitor"
CANDIDATE_URL = "https://example.test/news"
OUT_OF_SCOPE_URL = "https://outside.test/news"
NOW = "2026-08-27T12:00:00Z"
PRIVATE_BODY = b"PRIVATE-PAGE-CONTENT must not leave Runtime"


def _manifest(
    tool_id: str,
    *,
    qualification: QualificationStatus = QualificationStatus.QUALIFIED,
) -> ToolManifest:
    return ToolManifest(
        tool_id,
        "1.0.0",
        ToolCategory.ACQUISITION,
        ToolDistribution.INSTALLED,
        frozenset({"http_get"}),
        ToolLimits(30, 4 * 1024 * 1024, 4 * 1024 * 1024),
        HealthStatus.HEALTHY,
        qualification,
    )


INITIAL = WEB_HTTP_MANIFEST
ALLOWED = WEB_HTTP_MANIFEST


def _output(
    manifest: ToolManifest,
    url: str,
    body: bytes,
    *,
    mime_type: str = "text/html",
    runtime_ms: int = 10,
) -> AcquisitionOutput:
    return AcquisitionOutput(
        manifest.tool_id,
        manifest.version,
        url,
        url,
        200,
        mime_type,
        body,
        hashlib.sha256(body).hexdigest(),
        (),
        runtime_ms,
        requests=1,
        bytes_received=len(body),
    )


def _failure(
    manifest: ToolManifest,
    code: str = "gateway.timeout",
) -> AcquisitionFailure:
    return AcquisitionFailure(
        manifest.tool_id,
        manifest.version,
        code,
        requests=1,
        bytes_received=0,
        runtime_ms=10,
    )


@dataclass(slots=True)
class _Tool:
    manifest: ToolManifest
    responses: dict[str, AcquisitionOutput | AcquisitionFailure | BaseException]
    calls: list[str] = field(default_factory=list)
    cancellation_timer: _PerfCounter | None = None
    cancellation_advance_ns: int = 0

    def acquire(
        self, tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        self.calls.append(tool_input.target_url)
        response = self.responses[tool_input.target_url]
        if isinstance(response, BaseException):
            if self.cancellation_timer is not None:
                self.cancellation_timer.now_ns += self.cancellation_advance_ns
            raise response
        return response


@dataclass(slots=True)
class _Explorer:
    proposal: object
    seen: list[ExplorationMetadata] = field(default_factory=list)

    def propose(self, metadata: ExplorationMetadata) -> object:
        self.seen.append(metadata)
        return self.proposal


class _RaisingExplorer:
    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.calls = 0

    def propose(self, metadata: ExplorationMetadata) -> object:
        del metadata
        self.calls += 1
        raise self.error


@dataclass(slots=True)
class _PerfCounter:
    now_ns: int = 0

    def __call__(self) -> int:
        return self.now_ns


@dataclass(slots=True)
class _SlowExplorer:
    proposal: object
    timer: _PerfCounter
    advance_ns: int
    seen: list[ExplorationMetadata] = field(default_factory=list)

    def propose(self, metadata: ExplorationMetadata) -> object:
        self.seen.append(metadata)
        self.timer.now_ns += self.advance_ns
        return self.proposal


@dataclass(slots=True)
class _StoreSpy:
    store: ArtifactStore
    commits: int = 0
    reads: int = 0
    read_error: ArtifactStoreError | None = None

    def commit_observation(self, proposal):
        self.commits += 1
        return self.store.commit_observation(proposal)

    def read_artifact(self, artifact_id: str):
        self.reads += 1
        if self.read_error is not None:
            raise self.read_error
        return self.store.read_artifact(artifact_id)


def _request(
    *,
    explore_all_tools: bool = False,
    max_tool_attempts_per_target: int = 1,
    allowed_mime_types: tuple[str, ...] = ("text/html",),
    seeds: tuple[str, ...] = (INITIAL_URL, CANDIDATE_URL),
) -> Request:
    scope = Scope(
        seeds,
        ("https://example.test",),
        ("/**",),
        (ContentType.HTML,),
    )
    budgets = Budgets(4, 4096, 30, max_tool_attempts_per_target)
    skill = create_candidate(
        site_key="example.test",
        version=1,
        previous=None,
        scope=scope,
        budgets=budgets,
        tool=ToolReference(
            INITIAL.tool_id,
            INITIAL.version,
            ToolCategory.ACQUISITION,
            INITIAL.capabilities,
        ),
        success_checks=SuccessChecks(allowed_mime_types, 6),
        verified_at=NOW,
    ).skill
    return Request(scope, skill, explore_all_tools, budgets)


def _proposal(
    *,
    action: str = "acquire_url",
    target_url: str = CANDIDATE_URL,
    tool_id: str = ALLOWED.tool_id,
    budgets: Budgets | None = None,
) -> BoundedActionProposal:
    return BoundedActionProposal(
        action,
        target_url,
        tool_id,
        budgets or Budgets(3, 4000, 29, 1),
    )


def _setup(
    tmp_path: Path,
    proposal: object,
    *,
    allowed_manifest: ToolManifest = ALLOWED,
    allowed_output: (
        AcquisitionOutput | AcquisitionFailure | BaseException | None
    ) = None,
):
    initial = _Tool(
        INITIAL,
        {
            INITIAL_URL: _output(INITIAL, INITIAL_URL, PRIVATE_BODY),
            CANDIDATE_URL: (
                allowed_output
                or _output(
                    INITIAL,
                    CANDIDATE_URL,
                    b"one two three four five six",
                )
            ),
        },
    )
    allowed = _Tool(
        allowed_manifest,
        {
            CANDIDATE_URL: (
                allowed_output
                or _output(
                    allowed_manifest,
                    CANDIDATE_URL,
                    b"one two three four five six",
                )
            )
        },
    )
    registry = Registry()
    registry.register(initial.manifest, initial)
    if allowed.manifest.tool_id != initial.manifest.tool_id:
        registry.register(allowed.manifest, allowed)
    store = ArtifactStore(tmp_path / "artifacts")
    spy = _StoreSpy(store)
    explorer = _Explorer(proposal)
    return initial, allowed, registry, store, spy, explorer


def test_run_single_target_signature_and_no_explorer_path_are_unchanged(
    tmp_path: Path,
) -> None:
    assert tuple(inspect.signature(run_single_target).parameters) == (
        "request",
        "registry",
        "artifact_store",
        "run_id",
        "clock",
        "target_url",
    )
    initial, allowed, registry, store, spy, _explorer = _setup(tmp_path, _proposal())
    request = _request(seeds=(INITIAL_URL,))

    direct = run_single_target(
        request,
        registry,
        spy,
        run_id="standard-no-ai",
        clock=lambda: NOW,
    )
    assisted = run_agent_assisted_target(
        request,
        registry,
        spy,
        run_id="optional-port-absent",
        clock=lambda: NOW,
        explorer=None,
    )

    assert direct.status.value == assisted.result.status.value == "failed"
    assert assisted.code == "exploration.not_requested"
    assert assisted.proposal is None
    assert assisted.candidate is None
    assert initial.calls == [INITIAL_URL, INITIAL_URL]
    assert not allowed.calls
    assert spy.commits == 0
    store.close()


def test_no_explorer_multi_seed_matches_standard_single_target_rejection(
    tmp_path: Path,
) -> None:
    initial, allowed, registry, store, spy, _explorer = _setup(tmp_path, _proposal())
    request = _request()
    direct = run_single_target(
        request,
        registry,
        spy,
        run_id="multi-seed-no-explorer",
        clock=lambda: NOW,
    )

    assisted = run_agent_assisted_target(
        request,
        registry,
        spy,
        run_id="multi-seed-no-explorer",
        clock=lambda: NOW,
        explorer=None,
    )

    assert assisted.code == "exploration.not_requested"
    assert assisted.result == direct
    assert assisted.result.status.value == "rejected"
    assert assisted.result.errors[0].code == "runtime.single_target_required"
    assert not initial.calls
    assert not allowed.calls
    assert spy.commits == 0
    store.close()


def test_allowed_proposal_is_reauthorized_once_and_returns_inactive_candidate(
    tmp_path: Path,
) -> None:
    initial, allowed, registry, store, spy, explorer = _setup(tmp_path, _proposal())
    request = _request()
    active_digest = request.site_skill.digest

    decision = run_agent_assisted_target(
        request,
        registry,
        spy,
        run_id="agent-allowed",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.allowed is True
    assert decision.code == "exploration.succeeded"
    assert decision.proposal == _proposal()
    assert [attempt.outcome for attempt in decision.result.attempts] == [
        "failed",
        "succeeded",
    ]
    assert [attempt.requested_url for attempt in decision.result.attempts] == [
        INITIAL_URL,
        CANDIDATE_URL,
    ]
    assert decision.result.status.value == "partial"
    assert decision.result.manifest.run_id == "agent-allowed"
    assert [attempt.attempt_id for attempt in decision.result.attempts] == [
        "agent-allowed",
        "agent-allowed-explore",
    ]
    assert decision.result.usage.requests == 2
    assert decision.result.usage.tool_attempts == 2
    assert len(decision.result.artifacts) == 1
    assert decision.candidate is not None
    assert decision.candidate.skill.version == 2
    assert decision.candidate.skill.previous_digest == active_digest
    assert decision.candidate.skill.tool.tool_id == ALLOWED.tool_id
    assert decision.result.site_skill_update is not None
    assert decision.result.site_skill_update.sha256 == (
        decision.candidate.skill.digest.removeprefix("sha256:")
    )
    assert request.site_skill.digest == active_digest
    assert explorer.seen and len(explorer.seen) == 1
    metadata = explorer.seen[0]
    assert metadata.failure_code == "runtime.quality_minimum_words"
    assert metadata.requested_url == INITIAL_URL
    assert metadata.remaining_requests == 3
    assert metadata.remaining_bytes == 4096 - len(PRIVATE_BODY)
    assert metadata.remaining_tool_attempts_per_target == 1
    assert PRIVATE_BODY.decode() not in repr(metadata)
    assert not hasattr(metadata, "body")
    assert initial.calls == [INITIAL_URL, CANDIDATE_URL]
    assert not allowed.calls
    assert spy.commits == 1
    with pytest.raises(FrozenInstanceError):
        metadata.failure_code = "changed"  # type: ignore[misc]
    store.close()


@pytest.mark.parametrize(
    ("proposal", "expected_code", "expected_proposal"),
    [
        (
            BoundedActionProposal(
                "navigate_and_extract",
                "HTTPS://EXAMPLE.TEST/news",
                ALLOWED.tool_id,
                Budgets(3, 4000, 29, 1),
            ),
            "exploration.action_unknown",
            _proposal(action="navigate_and_extract"),
        ),
        (
            _proposal(target_url=OUT_OF_SCOPE_URL),
            "scope.origin_not_allowed",
            _proposal(target_url=OUT_OF_SCOPE_URL),
        ),
        (
            _proposal(budgets=Budgets(4, 4000, 29, 1)),
            "exploration.budget_exceeded",
            _proposal(budgets=Budgets(4, 4000, 29, 1)),
        ),
        (
            _proposal(tool_id="acquisition.missing"),
            "exploration.tool_unknown",
            _proposal(tool_id="acquisition.missing"),
        ),
        (object(), "exploration.proposal_invalid", None),
    ],
)
def test_invalid_or_unauthorized_proposal_stops_before_target_read_and_store(
    tmp_path: Path,
    proposal: object,
    expected_code: str,
    expected_proposal: BoundedActionProposal | None,
) -> None:
    initial, allowed, registry, store, spy, explorer = _setup(tmp_path, proposal)

    decision = run_agent_assisted_target(
        _request(),
        registry,
        spy,
        run_id="agent-rejected",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.allowed is False
    assert decision.code == expected_code
    assert decision.proposal == expected_proposal
    assert decision.candidate is None
    assert decision.result.status.value == "failed"
    assert len(decision.result.attempts) == 1
    assert initial.calls == [INITIAL_URL]
    assert not allowed.calls
    assert spy.commits == 0
    store.close()


def test_unqualified_tool_is_rejected_before_target_read(tmp_path: Path) -> None:
    unqualified = _manifest(
        "acquisition.unqualified",
        qualification=QualificationStatus.UNQUALIFIED,
    )
    initial, target, registry, store, spy, explorer = _setup(
        tmp_path,
        _proposal(tool_id=unqualified.tool_id),
        allowed_manifest=unqualified,
    )

    decision = run_agent_assisted_target(
        _request(),
        registry,
        spy,
        run_id="agent-ineligible",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.allowed is False
    assert decision.code == "eligibility.unqualified"
    assert decision.proposal == _proposal(tool_id=unqualified.tool_id)
    assert initial.calls == [INITIAL_URL]
    assert not target.calls
    assert spy.commits == 0
    store.close()


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (ValueError("private proposer detail"), "exploration.proposer_exception"),
        (asyncio.CancelledError(), "exploration.proposer_cancelled"),
    ],
)
def test_proposer_exception_or_cancellation_leaves_no_candidate_or_artifact(
    tmp_path: Path,
    error: BaseException,
    expected_code: str,
) -> None:
    initial, allowed, registry, store, spy, _explorer = _setup(tmp_path, _proposal())
    explorer = _RaisingExplorer(error)

    decision = run_agent_assisted_target(
        _request(),
        registry,
        spy,
        run_id="agent-proposer-failed",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.allowed is False
    assert decision.code == expected_code
    assert decision.proposal is None
    assert decision.candidate is None
    assert explorer.calls == 1
    assert initial.calls == [INITIAL_URL]
    assert not allowed.calls
    assert spy.commits == 0
    assert "private proposer detail" not in repr(decision)
    store.close()


def test_allowed_proposal_execution_failure_keeps_attempts_without_candidate(
    tmp_path: Path,
) -> None:
    initial, allowed, registry, store, spy, explorer = _setup(
        tmp_path,
        _proposal(),
        allowed_output=_failure(ALLOWED),
    )

    decision = run_agent_assisted_target(
        _request(),
        registry,
        spy,
        run_id="agent-execution-failed",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.allowed is True
    assert decision.code == "exploration.execution_failed"
    assert decision.candidate is None
    assert decision.result.status.value == "failed"
    assert decision.result.manifest.run_id == "agent-execution-failed"
    assert [attempt.error.code for attempt in decision.result.attempts] == [
        "runtime.quality_minimum_words",
        "gateway.timeout",
    ]
    assert decision.result.usage.requests == 2
    assert initial.calls == [INITIAL_URL, CANDIDATE_URL]
    assert not allowed.calls
    assert spy.commits == 0
    store.close()


def test_same_target_proposal_exhausts_per_target_attempts_before_second_io(
    tmp_path: Path,
) -> None:
    proposal = _proposal(target_url=INITIAL_URL)
    initial, allowed, registry, store, spy, explorer = _setup(tmp_path, proposal)

    decision = run_agent_assisted_target(
        _request(),
        registry,
        spy,
        run_id="agent-same-target",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.allowed is False
    assert decision.code == "eligibility.attempt_budget_exhausted"
    assert decision.proposal == proposal
    assert decision.candidate is None
    assert decision.result.status.value == "failed"
    assert len(decision.result.attempts) == 1
    assert decision.result.usage.tool_attempts == 1
    assert initial.calls == [INITIAL_URL]
    assert not allowed.calls
    assert spy.commits == 0
    store.close()


def test_empty_successful_body_keeps_evidence_without_unverified_candidate(
    tmp_path: Path,
) -> None:
    initial, allowed, registry, store, spy, explorer = _setup(
        tmp_path,
        _proposal(),
        allowed_output=_output(INITIAL, CANDIDATE_URL, b""),
    )
    request = _request()
    active_digest = request.site_skill.digest

    decision = run_agent_assisted_target(
        request,
        registry,
        spy,
        run_id="agent-empty-body",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.allowed is True
    assert decision.code == "exploration.candidate_quality_unverified"
    assert decision.candidate is None
    assert decision.result.site_skill_update is None
    assert decision.result.status.value == "partial"
    assert [attempt.outcome for attempt in decision.result.attempts] == [
        "failed",
        "succeeded",
    ]
    assert decision.result.usage.requests == 2
    assert decision.result.usage.tool_attempts == 2
    assert len(decision.result.artifacts) == 1
    assert initial.calls == [INITIAL_URL, CANDIDATE_URL]
    assert not allowed.calls
    assert spy.commits == 1
    assert request.site_skill.digest == active_digest
    store.close()


@pytest.mark.parametrize(
    ("body", "previous_mime_types"),
    [
        (b"one two three four five", ("text/html",)),
        (b"one two three four five six", ("application/json",)),
    ],
)
def test_candidate_must_satisfy_previous_success_checks(
    tmp_path: Path,
    body: bytes,
    previous_mime_types: tuple[str, ...],
) -> None:
    initial, allowed, registry, store, spy, explorer = _setup(
        tmp_path,
        _proposal(),
        allowed_output=_output(
            INITIAL,
            CANDIDATE_URL,
            body,
        ),
    )
    request = _request(allowed_mime_types=previous_mime_types)
    active_digest = request.site_skill.digest

    decision = run_agent_assisted_target(
        request,
        registry,
        spy,
        run_id="agent-previous-checks",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.allowed is True
    assert decision.code == "exploration.candidate_quality_unverified"
    assert decision.candidate is None
    assert decision.result.site_skill_update is None
    assert decision.result.status.value == "partial"
    assert len(decision.result.artifacts) == 1
    assert decision.result.manifest.mime_type == "text/html"
    assert initial.calls == [INITIAL_URL, CANDIDATE_URL]
    assert not allowed.calls
    assert spy.commits == 1
    assert request.site_skill.digest == active_digest
    store.close()


def test_proposer_receives_only_terminal_acquisition_failure_metadata(
    tmp_path: Path,
) -> None:
    alternate_manifest = _manifest("acquisition.alternate")
    initial = _Tool(
        INITIAL,
        {INITIAL_URL: _output(INITIAL, INITIAL_URL, PRIVATE_BODY)},
    )
    alternate = _Tool(
        alternate_manifest,
        {INITIAL_URL: _failure(alternate_manifest)},
    )
    registry = Registry()
    registry.register(initial.manifest, initial)
    registry.register(alternate.manifest, alternate)
    store = ArtifactStore(tmp_path / "artifacts")
    spy = _StoreSpy(store)
    explorer = _Explorer(_proposal(action="stop"))

    decision = run_agent_assisted_target(
        _request(explore_all_tools=True, max_tool_attempts_per_target=2),
        registry,
        spy,
        run_id="agent-terminal-metadata",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.code == "exploration.action_unknown"
    assert len(explorer.seen) == 1
    metadata = explorer.seen[0]
    assert (
        metadata.failure_code
        == decision.result.attempts[-1].error.code
        == "gateway.timeout"
    )
    assert (
        metadata.tool_id
        == decision.result.manifest.tool_id
        == alternate_manifest.tool_id
    )
    assert (
        metadata.tool_version
        == decision.result.manifest.tool_version
        == alternate_manifest.version
    )
    assert metadata.http_status is None
    assert decision.result.manifest.http_status is None
    assert metadata.requested_url == INITIAL_URL
    assert metadata.current_url == decision.result.manifest.current_url == INITIAL_URL
    assert metadata.requests_used == decision.result.usage.requests == 2
    assert metadata.tool_attempts_used == decision.result.usage.tool_attempts == 2
    assert PRIVATE_BODY.decode() not in repr(metadata)
    assert not hasattr(metadata, "body")
    assert initial.calls == [INITIAL_URL]
    assert alternate.calls == [INITIAL_URL]
    assert spy.commits == 0
    store.close()


def test_candidate_artifact_read_failure_returns_stable_evidence(
    tmp_path: Path,
) -> None:
    initial, allowed, registry, store, spy, explorer = _setup(tmp_path, _proposal())
    spy.read_error = ArtifactStoreError("blob.corrupt")

    decision = run_agent_assisted_target(
        _request(),
        registry,
        spy,
        run_id="agent-candidate-read-failed",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.allowed is True
    assert decision.code == "exploration.candidate_verification_failed"
    assert decision.candidate is None
    assert decision.result.site_skill_update is None
    assert decision.result.status.value == "partial"
    assert decision.result.manifest.run_id == "agent-candidate-read-failed"
    assert len(decision.result.artifacts) == 1
    assert [attempt.outcome for attempt in decision.result.attempts] == [
        "failed",
        "succeeded",
    ]
    assert decision.result.usage.requests == 2
    assert initial.calls == [INITIAL_URL, CANDIDATE_URL]
    assert not allowed.calls
    assert spy.commits == 1
    assert spy.reads == 1
    assert "blob.corrupt" not in repr(decision)
    store.close()


def test_candidate_round_trip_standard_run_uses_only_verified_seed(
    tmp_path: Path,
) -> None:
    initial, allowed, registry, store, spy, explorer = _setup(tmp_path, _proposal())
    request = _request()

    decision = run_agent_assisted_target(
        request,
        registry,
        spy,
        run_id="agent-round-trip",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.candidate is not None
    candidate = decision.candidate.skill
    assert candidate.scope.seeds == (CANDIDATE_URL,)
    assert candidate.scope.allowed_origins == request.scope.allowed_origins
    assert candidate.scope.include_paths == request.scope.include_paths
    assert candidate.scope.content_types == request.scope.content_types
    followup = run_single_target(
        Request(candidate.scope, candidate, False, candidate.budgets),
        registry,
        spy,
        run_id="candidate-round-trip",
        clock=lambda: NOW,
    )

    assert followup.status.value == "completed"
    assert followup.manifest.requested_url == CANDIDATE_URL
    assert initial.calls == [INITIAL_URL, CANDIDATE_URL, CANDIDATE_URL]
    assert not allowed.calls
    assert spy.commits == 2
    store.close()


def test_authorized_action_cancellation_returns_initial_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial, allowed, registry, store, spy, explorer = _setup(
        tmp_path,
        _proposal(),
        allowed_output=asyncio.CancelledError(),
    )
    timer = _PerfCounter()
    initial.cancellation_timer = timer
    initial.cancellation_advance_ns = 250_000_000
    monkeypatch.setattr(workflow_module.time, "perf_counter_ns", timer)

    decision = run_agent_assisted_target(
        _request(),
        registry,
        spy,
        run_id="agent-action-cancelled",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.allowed is True
    assert decision.code == "exploration.execution_cancelled"
    assert decision.proposal == _proposal()
    assert decision.candidate is None
    assert decision.result.site_skill_update is None
    assert decision.result.status.value == "failed"
    assert decision.result.manifest.run_id == "agent-action-cancelled"
    assert len(decision.result.attempts) == len(initial.calls) == 2
    cancelled = decision.result.attempts[-1]
    assert cancelled.outcome == "failed"
    assert cancelled.requested_url == CANDIDATE_URL
    assert cancelled.tool_id == INITIAL.tool_id
    assert cancelled.tool_version == INITIAL.version
    assert cancelled.error is not None
    assert cancelled.error.code == "exploration.execution_cancelled"
    assert cancelled.requests == 0
    assert cancelled.bytes_received == 0
    assert cancelled.runtime_ms == 250
    assert decision.result.usage.requests == 1
    assert decision.result.usage.bytes_received == len(PRIVATE_BODY)
    assert decision.result.usage.tool_attempts == 2
    assert decision.result.usage.runtime_ms == 260
    assert decision.result.usage.runtime_ms == sum(
        attempt.runtime_ms for attempt in decision.result.attempts
    )
    assert initial.calls == [INITIAL_URL, CANDIDATE_URL]
    assert not allowed.calls
    assert spy.commits == 0
    store.close()


def test_slow_proposer_exhausts_runtime_before_target_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timer = _PerfCounter()
    proposal = _proposal(budgets=Budgets(3, 4000, 1, 1))
    initial, allowed, registry, store, spy, _explorer = _setup(tmp_path, proposal)
    explorer = _SlowExplorer(proposal, timer, 29_500_000_000)
    monkeypatch.setattr(workflow_module.time, "perf_counter_ns", timer)

    decision = run_agent_assisted_target(
        _request(),
        registry,
        spy,
        run_id="agent-slow-proposer",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.allowed is False
    assert decision.code == "exploration.budget_exceeded"
    assert decision.proposal == proposal
    assert decision.candidate is None
    assert len(explorer.seen) == 1
    assert explorer.seen[0].remaining_runtime_ms == 29_990
    assert initial.calls == [INITIAL_URL]
    assert not allowed.calls
    assert spy.commits == 0
    store.close()


def test_explorer_metadata_strips_query_secrets_without_changing_result_url(
    tmp_path: Path,
) -> None:
    query_url = "https://example.test/monitor?session=abc123&sig=private-signature"
    initial = _Tool(
        INITIAL,
        {query_url: _output(INITIAL, query_url, PRIVATE_BODY)},
    )
    registry = Registry()
    registry.register(initial.manifest, initial)
    store = ArtifactStore(tmp_path / "artifacts")
    spy = _StoreSpy(store)
    explorer = _Explorer(_proposal(action="stop"))

    decision = run_agent_assisted_target(
        _request(seeds=(query_url, CANDIDATE_URL)),
        registry,
        spy,
        run_id="agent-query-metadata",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.code == "exploration.action_unknown"
    assert len(explorer.seen) == 1
    metadata = explorer.seen[0]
    assert metadata.requested_url == "https://example.test/monitor"
    assert metadata.current_url == "https://example.test/monitor"
    assert "?" not in repr(metadata)
    assert "abc123" not in repr(metadata)
    assert "private-signature" not in repr(metadata)
    assert PRIVATE_BODY.decode() not in repr(metadata)
    assert decision.result.manifest.requested_url == query_url
    assert decision.result.manifest.current_url == query_url
    assert initial.calls == [query_url]
    assert spy.commits == 0
    store.close()


@pytest.mark.parametrize(
    ("authority", "expected_site_key"),
    [
        ("example.test", "example.test"),
        ("3m.com", "site-3m.com"),
        ("192.0.2.1", "site-192.0.2.1"),
        ("[2001:db8::1]", "site-323030313a6462383a3a31"),
    ],
)
def test_first_candidate_maps_canonical_hostname_to_round_trip_site_key(
    tmp_path: Path,
    authority: str,
    expected_site_key: str,
) -> None:
    initial_url = f"https://{authority}/monitor"
    candidate_url = f"https://{authority}/news"
    scope = Scope(
        (initial_url, candidate_url),
        (f"https://{authority}",),
        ("/**",),
        (ContentType.HTML,),
    )
    request = Request(scope, None, False, Budgets(4, 4096, 30, 1))
    proposal = BoundedActionProposal(
        "acquire_url",
        candidate_url,
        INITIAL.tool_id,
        Budgets(3, 4000, 29, 1),
    )
    tool = _Tool(
        INITIAL,
        {
            initial_url: _failure(INITIAL),
            candidate_url: _output(
                INITIAL,
                candidate_url,
                b"one two three four five six",
            ),
        },
    )
    registry = Registry()
    registry.register(tool.manifest, tool)
    store = ArtifactStore(tmp_path / "artifacts")
    spy = _StoreSpy(store)

    decision = run_agent_assisted_target(
        request,
        registry,
        spy,
        run_id="agent-first-candidate",
        clock=lambda: NOW,
        explorer=_Explorer(proposal),
    )

    assert decision.code == "exploration.succeeded"
    assert decision.candidate is not None
    candidate = decision.candidate.skill
    assert candidate.site_key == expected_site_key
    assert candidate.previous_digest is None
    restored = site_skill_from_mapping(site_skill_to_mapping(candidate))
    assert restored == candidate
    followup = run_single_target(
        Request(restored.scope, restored, False, restored.budgets),
        registry,
        spy,
        run_id="first-candidate-round-trip",
        clock=lambda: NOW,
    )
    assert followup.status.value == "completed"
    assert tool.calls == [initial_url, candidate_url, candidate_url]
    assert spy.commits == 2
    store.close()


def test_candidate_site_skill_validation_error_returns_stable_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial, allowed, registry, store, spy, explorer = _setup(tmp_path, _proposal())

    def _reject_candidate(**_kwargs):
        raise SiteSkillError("site_skill.site_key_invalid")

    monkeypatch.setattr(workflow_module, "create_candidate", _reject_candidate)
    decision = run_agent_assisted_target(
        _request(),
        registry,
        spy,
        run_id="agent-candidate-validation-failed",
        clock=lambda: NOW,
        explorer=explorer,
    )

    assert decision.allowed is True
    assert decision.code == "exploration.candidate_verification_failed"
    assert decision.candidate is None
    assert decision.result.site_skill_update is None
    assert decision.result.status.value == "partial"
    assert len(decision.result.artifacts) == 1
    assert [attempt.outcome for attempt in decision.result.attempts] == [
        "failed",
        "succeeded",
    ]
    assert initial.calls == [INITIAL_URL, CANDIDATE_URL]
    assert not allowed.calls
    assert spy.commits == 1
    assert "site_skill.site_key_invalid" not in repr(decision)
    store.close()
