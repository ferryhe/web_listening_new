"""One governed single-target workflow connecting existing public modules."""

# pylint: disable=duplicate-code,too-few-public-methods,too-many-lines,too-many-locals
# pylint: disable=too-many-return-statements
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import Protocol
from urllib.parse import (
    urlsplit,
    urlunsplit,
)

from web_listening.artifact.model import (
    ArtifactRole,
    ArtifactStoreError,
    StoredObservation,
)
from web_listening.artifact.observation import ObservationProposal
from web_listening.artifact.store import ArtifactStore
from web_listening.request.budgets import validate_budgets
from web_listening.request.model import (
    Budgets,
    ContentType,
    Request,
    RequestValidationError,
    classify_mime_type,
)
from web_listening.request.scope import canonicalize_url
from web_listening.request.validate import compile_access_policy, validate_request
from web_listening.result.attempts import Attempt
from web_listening.result.errors import SafeError
from web_listening.result.manifest import (
    Manifest,
    RedirectEvidence,
    SiteSkillEvidence,
    Usage,
    manifest_from_observations,
)
from web_listening.result.model import Result, ResultStatus
from web_listening.site_skill.model import (
    SiteSkill,
    SiteSkillError,
    SuccessChecks,
    ToolReference,
)
from web_listening.site_skill.resolve import resolve_site_skill
from web_listening.site_skill.update import SiteSkillCandidate, create_candidate
from web_listening.tool_registry.eligibility import (
    EligibilityFacts,
    EligibilityRequirements,
    acquisition_failure_allows_switch,
    rank_eligible_tools,
)
from web_listening.tool_registry.manifest import (
    ToolCategory,
    ToolManifest,
    ToolRegistryError,
    validate_tool_id,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryFailure,
    DiscoveryInput,
    DiscoveryOutput,
)
from web_listening.tool_registry.protocols.transform import (
    TransformFailure,
    TransformInput,
    TransformOutput,
)
from web_listening.tool_registry.registry import AcquisitionOutputRejected, Registry

_MAX_DISCOVERY_CANDIDATES = 100
_DEFAULT_ACQUISITION_TOOL_ID = "acquisition.web_http"
_INVOCATION_BUDGET_LIMITS: ContextVar[Budgets | None] = ContextVar(
    "web_listening_invocation_budget_limits", default=None
)
_PRIOR_TARGET_ATTEMPTS: ContextVar[tuple[Attempt, ...]] = ContextVar(
    "web_listening_prior_target_attempts", default=()
)


@dataclass(frozen=True, slots=True)
class DiscoveredCandidateResult:
    """One deterministically paired candidate, provenance URL, and Result."""

    candidate_url: str
    discovered_from: str
    result: Result


@dataclass(frozen=True, slots=True)
class BoundedActionProposal:
    """One inert external proposal; it carries no execution capability."""

    action: str
    target_url: str
    tool_id: str
    budgets: Budgets


@dataclass(frozen=True, slots=True)
class ExplorationMetadata:  # pylint: disable=too-many-instance-attributes
    """Safe failure metadata exposed to an optional external explorer."""

    failure_code: str
    requested_url: str
    current_url: str
    tool_id: str | None
    tool_version: str | None
    http_status: int | None
    requests_used: int
    bytes_received: int
    runtime_ms: int
    tool_attempts_used: int
    remaining_requests: int
    remaining_bytes: int
    remaining_runtime_ms: int
    remaining_tool_attempts_per_target: int
    active_site_skill_digest: str | None


class ExplorerPort(Protocol):
    """Core-external proposer port with no Registry, Store, or network handle."""

    def propose(self, metadata: ExplorationMetadata) -> object:
        """Return at most one inert proposal from safe metadata."""


@dataclass(frozen=True, slots=True)
class ExplorationDecision:
    """One immutable authorization/execution outcome plus optional candidate."""

    proposal: BoundedActionProposal | None
    allowed: bool
    code: str
    result: Result
    candidate: SiteSkillCandidate | None


@dataclass(frozen=True, slots=True)
class _TransformResult:
    attempt: Attempt | None = None
    observation: StoredObservation | None = None
    errors: tuple[SafeError, ...] = ()
    completed_at: str | None = None


@dataclass(frozen=True, slots=True)
class _AuthorizedAction:
    proposal: BoundedActionProposal
    request: Request
    manifest: ToolManifest
    previous: SiteSkill | None
    scope_request: Request


def run_single_target(  # pylint: disable=too-many-arguments,too-many-branches
    # pylint: disable=too-many-statements
    request: Request,
    registry: Registry,
    artifact_store: ArtifactStore,
    *,
    run_id: str,
    clock: Callable[[], str],
    target_url: str | None = None,
) -> Result:
    """Validate, resolve, run the controlled acquisition, and assemble a Result."""
    request = validate_request(request)
    requested_url = target_url or request.scope.seeds[0]
    if target_url is None and len(request.scope.seeds) != 1:
        return _failure_result(
            status=ResultStatus.REJECTED,
            run_id=run_id,
            generated_at=clock(),
            requested_url=requested_url,
            current_url=requested_url,
            code="runtime.single_target_required",
            message="Runtime request requires exactly one target.",
        )
    if request.site_skill is None:
        effective_request = request
        site_skill = None
        preferred_tool_id = _DEFAULT_ACQUISITION_TOOL_ID
        preferred_tool_version = None
        allowed_mime_types = None
        minimum_words = 0
    else:
        try:
            resolution = resolve_site_skill(request, request.site_skill, registry)
        except SiteSkillError as exc:
            return _failure_result(
                status=ResultStatus.REJECTED,
                run_id=run_id,
                generated_at=clock(),
                requested_url=requested_url,
                current_url=requested_url,
                code=exc.code,
                message="Runtime request was rejected.",
            )
        site_skill = SiteSkillEvidence(
            str(resolution.skill.version),
            resolution.skill.digest.removeprefix("sha256:"),
        )
        preferred_tool_id = resolution.skill.tool.tool_id
        preferred_tool_version = resolution.skill.tool.version
        allowed_mime_types = resolution.skill.success_checks.allowed_mime_types
        minimum_words = resolution.skill.success_checks.minimum_words
        if not resolution.eligible:
            return _failure_result(
                status=ResultStatus.REJECTED,
                run_id=run_id,
                generated_at=clock(),
                requested_url=requested_url,
                current_url=requested_url,
                code=_ineligible_code(resolution.reasons),
                message="Runtime request was rejected.",
                tool_id=preferred_tool_id,
                tool_version=preferred_tool_version,
                site_skill=site_skill,
            )
        effective_request = resolution.request
    budget_limits = _INVOCATION_BUDGET_LIMITS.get()
    if budget_limits is not None:
        current = effective_request.budgets
        effective_request = replace(
            effective_request,
            budgets=Budgets(
                min(current.max_requests, budget_limits.max_requests),
                min(current.max_bytes, budget_limits.max_bytes),
                min(
                    current.max_runtime_seconds,
                    budget_limits.max_runtime_seconds,
                ),
                min(
                    current.max_tool_attempts_per_target,
                    budget_limits.max_tool_attempts_per_target,
                ),
            ),
        )
    if target_url is None:
        requested_url = effective_request.scope.seeds[0]
    try:
        tool_input = AcquisitionInput(effective_request, requested_url)
        acquisition_manifests = registry.query(category=ToolCategory.ACQUISITION)
    except ToolRegistryError as exc:
        return _failure_result(
            status=ResultStatus.REJECTED,
            run_id=run_id,
            generated_at=clock(),
            requested_url=requested_url,
            current_url=requested_url,
            code=exc.code,
            message="Runtime request was rejected.",
            tool_id=(preferred_tool_id if preferred_tool_version is not None else None),
            tool_version=preferred_tool_version,
            site_skill=site_skill,
        )

    requested_url = tool_input.target_url
    registered_tool_ids = frozenset(
        manifest.tool_id for manifest in acquisition_manifests
    )
    remaining_requests = effective_request.budgets.max_requests
    remaining_bytes = effective_request.budgets.max_bytes
    remaining_runtime_ms = effective_request.budgets.max_runtime_seconds * 1_000
    prior_attempts_used = sum(
        attempt.outcome != "skipped"
        and canonicalize_url(attempt.requested_url) == requested_url
        for attempt in _PRIOR_TARGET_ATTEMPTS.get()
    )
    remaining_tool_attempts = max(
        0,
        effective_request.budgets.max_tool_attempts_per_target - prior_attempts_used,
    )
    if remaining_tool_attempts == 0:
        return _failure_result(
            status=ResultStatus.FAILED,
            run_id=run_id,
            generated_at=clock(),
            requested_url=requested_url,
            current_url=requested_url,
            code="eligibility.attempt_budget_exhausted",
            message="Acquisition did not complete.",
            tool_id=(preferred_tool_id if preferred_tool_version is not None else None),
            tool_version=preferred_tool_version,
            site_skill=site_skill,
        )
    attempted_tool_ids: set[str] = set()
    recorded_skips: set[str] = set()
    acquisition_attempts: list[Attempt] = []
    acquisition_errors: list[SafeError] = []
    last_failure_code = "runtime.acquisition_unavailable"
    last_tool_id = preferred_tool_id
    last_tool_version = preferred_tool_version
    finished_at: str | None = None
    while True:
        selection = rank_eligible_tools(
            acquisition_manifests,
            EligibilityRequirements(category=ToolCategory.ACQUISITION),
            EligibilityFacts(
                # Registry registration is the current executable/installed seam.
                registered_tool_ids,
                # Every Acquisition registration executes under the same Request gate.
                registered_tool_ids,
                remaining_requests,
                remaining_bytes,
                remaining_runtime_ms,
                remaining_tool_attempts,
            ),
            preferred_tool_id=preferred_tool_id,
            include_alternates=effective_request.explore_all_tools,
            attempted_tool_ids=frozenset(attempted_tool_ids),
        )
        if (attempted_tool_ids or not selection.ranked) and not (
            selection.budget_exhausted
        ):
            for decision in selection.skipped:
                if decision.tool_id in recorded_skips:
                    continue
                skipped_at = clock()
                error = _eligibility_error(decision.reasons)
                acquisition_errors.append(error)
                acquisition_attempts.append(
                    _attempt(
                        run_id=run_id,
                        attempt_id=_ordered_attempt_id(
                            run_id, "acquisition", len(acquisition_attempts)
                        ),
                        order=len(acquisition_attempts),
                        outcome="skipped",
                        requested_url=requested_url,
                        started_at=skipped_at,
                        finished_at=skipped_at,
                        tool_id=decision.tool_id,
                        tool_version=decision.tool_version,
                        final_url=None,
                        http_status=None,
                        error=error,
                        requests=0,
                        bytes_received=0,
                        runtime_ms=0,
                    )
                )
                recorded_skips.add(decision.tool_id)
        if not selection.ranked:
            if not attempted_tool_ids:
                decision = next(
                    (
                        item
                        for item in selection.decisions
                        if item.tool_id == preferred_tool_id
                    ),
                    None,
                )
                code = (
                    "runtime.default_tool_missing"
                    if decision is None
                    else _ineligible_code(decision.reasons)
                )
                if decision is not None:
                    preferred_tool_version = decision.tool_version
                return _failure_result(
                    status=ResultStatus.REJECTED,
                    run_id=run_id,
                    generated_at=clock(),
                    requested_url=requested_url,
                    current_url=requested_url,
                    code=code,
                    message="Runtime request was rejected.",
                    tool_id=(
                        preferred_tool_id
                        if preferred_tool_version is not None
                        else None
                    ),
                    tool_version=preferred_tool_version,
                    site_skill=site_skill,
                    attempts=tuple(acquisition_attempts),
                )
            assert last_tool_version is not None
            budget_code = _acquisition_budget_exhaustion_code(
                remaining_requests,
                remaining_bytes,
                remaining_runtime_ms,
                remaining_tool_attempts,
            )
            return _acquisition_failure_result(
                run_id=run_id,
                generated_at=finished_at or clock(),
                requested_url=requested_url,
                tool_id=last_tool_id,
                tool_version=last_tool_version,
                code=budget_code or last_failure_code,
                site_skill=site_skill,
                attempts=tuple(acquisition_attempts),
            )
        manifest = selection.ranked[0]
        last_tool_id = manifest.tool_id
        last_tool_version = manifest.version
        attempt_request = Request(
            effective_request.scope,
            effective_request.site_skill,
            effective_request.explore_all_tools,
            Budgets(
                remaining_requests,
                remaining_bytes,
                remaining_runtime_ms // 1_000,
                remaining_tool_attempts,
            ),
        )
        tool_input = AcquisitionInput(attempt_request, requested_url)
        started_at = clock()
        invocation_started_ns = time.perf_counter_ns()
        try:
            acquisition = registry.invoke(manifest.tool_id, tool_input)
        except AcquisitionOutputRejected as exc:
            acquisition = exc.failure
        except ToolRegistryError as exc:
            acquisition = AcquisitionFailure(
                manifest.tool_id,
                manifest.version,
                exc.code,
                runtime_ms=0,
            )
        invocation_runtime_ms = _elapsed_runtime_ms(
            invocation_started_ns, time.perf_counter_ns()
        )
        finished_at = clock()
        attempt_runtime_ms = max(acquisition.runtime_ms, invocation_runtime_ms)
        reported_failure_code = (
            acquisition.code if isinstance(acquisition, AcquisitionFailure) else None
        )
        post_invoke_budget_code: str | None = None
        if acquisition.requests > remaining_requests:
            post_invoke_budget_code = (
                "budget.requests"
                if reported_failure_code == "budget.requests"
                else "eligibility.request_budget_exhausted"
            )
        elif acquisition.bytes_received > remaining_bytes:
            post_invoke_budget_code = (
                "budget.bytes"
                if reported_failure_code == "budget.bytes"
                else "eligibility.byte_budget_exhausted"
            )
        elif attempt_runtime_ms > remaining_runtime_ms:
            post_invoke_budget_code = (
                "budget.runtime"
                if reported_failure_code == "budget.runtime"
                else "eligibility.runtime_budget_exhausted"
            )
        failure_code = (
            post_invoke_budget_code
            if post_invoke_budget_code is not None
            else (
                acquisition.code
                if isinstance(acquisition, AcquisitionFailure)
                else (
                    None
                    if allowed_mime_types is None
                    else _quality_failure_code(
                        acquisition, allowed_mime_types, minimum_words
                    )
                )
            )
        )
        error = (
            None
            if failure_code is None
            else SafeError(
                failure_code,
                (
                    "Acquisition did not complete."
                    if isinstance(acquisition, AcquisitionFailure)
                    or post_invoke_budget_code is not None
                    else "Acquisition quality checks failed."
                ),
            )
        )
        output = acquisition if isinstance(acquisition, AcquisitionOutput) else None
        attempt = _attempt(
            run_id=run_id,
            attempt_id=_ordered_attempt_id(
                run_id, "acquisition", len(acquisition_attempts)
            ),
            order=len(acquisition_attempts),
            outcome="succeeded" if error is None else "failed",
            requested_url=requested_url,
            started_at=started_at,
            finished_at=finished_at,
            tool_id=acquisition.tool_id,
            tool_version=acquisition.tool_version,
            final_url=None if output is None else output.final_url,
            http_status=None if output is None else output.status_code,
            error=error,
            requests=(
                acquisition.requests
                if isinstance(acquisition, AcquisitionFailure)
                else acquisition.requests
            ),
            bytes_received=(
                acquisition.bytes_received
                if isinstance(acquisition, AcquisitionFailure)
                else acquisition.bytes_received
            ),
            runtime_ms=attempt_runtime_ms,
        )
        acquisition_attempts.append(attempt)
        attempted_tool_ids.add(manifest.tool_id)
        remaining_requests = max(0, remaining_requests - attempt.requests)
        remaining_bytes = max(0, remaining_bytes - attempt.bytes_received)
        remaining_runtime_ms = max(0, remaining_runtime_ms - attempt.runtime_ms)
        remaining_tool_attempts -= 1
        if attempt.outcome == "succeeded":
            break
        assert error is not None and failure_code is not None
        acquisition_errors.append(error)
        last_failure_code = failure_code
        if not effective_request.explore_all_tools or not (
            acquisition_failure_allows_switch(failure_code)
        ):
            return _acquisition_failure_result(
                run_id=run_id,
                generated_at=finished_at,
                requested_url=requested_url,
                tool_id=manifest.tool_id,
                tool_version=manifest.version,
                code=failure_code,
                site_skill=site_skill,
                attempts=tuple(acquisition_attempts),
            )
    assert isinstance(acquisition, AcquisitionOutput)
    assert finished_at is not None
    redirects = tuple(
        RedirectEvidence(
            order=index,
            from_url=redirect.from_url,
            to_url=redirect.to_url,
            http_status=redirect.status_code,
            decision="followed",
        )
        for index, redirect in enumerate(acquisition.redirects)
    )
    attempt = acquisition_attempts[-1]
    # The public Store boundary rolls back before propagating commit failures.
    try:
        observation = artifact_store.commit_observation(
            ObservationProposal(
                content=acquisition.body,
                sha256=acquisition.sha256,
                size_bytes=len(acquisition.body),
                mime_type=acquisition.mime_type,
                source_url=acquisition.final_url,
                observed_at=finished_at,
                role=ArtifactRole.SOURCE,
            )
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        code = (
            exc.code
            if isinstance(exc, ArtifactStoreError)
            else "runtime.artifact_commit_failed"
        )
        error = SafeError(code, "Artifact commit did not complete.")
        attempt = _attempt(
            run_id=run_id,
            attempt_id=attempt.attempt_id,
            order=attempt.order,
            outcome="failed",
            requested_url=requested_url,
            started_at=started_at,
            finished_at=finished_at,
            tool_id=acquisition.tool_id,
            tool_version=acquisition.tool_version,
            final_url=acquisition.final_url,
            http_status=acquisition.status_code,
            error=error,
            requests=attempt.requests,
            bytes_received=attempt.bytes_received,
            runtime_ms=attempt.runtime_ms,
        )
        return _failure_result(
            status=ResultStatus.FAILED,
            run_id=run_id,
            generated_at=finished_at,
            requested_url=requested_url,
            current_url=acquisition.final_url,
            code=code,
            message="Artifact commit did not complete.",
            tool_id=acquisition.tool_id,
            tool_version=acquisition.tool_version,
            site_skill=site_skill,
            redirects=redirects,
            attempts=tuple(acquisition_attempts[:-1]) + (attempt,),
        )
    transformed = _transform_stored_source(
        registry,
        artifact_store,
        observation,
        run_id=run_id,
        clock=clock,
        tool_attempts_remaining=(
            effective_request.budgets.max_tool_attempts_per_target
            - sum(item.outcome != "skipped" for item in acquisition_attempts)
        ),
        runtime_ms_remaining=(
            effective_request.budgets.max_runtime_seconds * 1_000
            - sum(item.runtime_ms for item in acquisition_attempts)
        ),
        attempt_order=len(acquisition_attempts),
    )
    attempts = tuple(acquisition_attempts) + (
        () if transformed.attempt is None else (transformed.attempt,)
    )
    observations = (observation,) + (
        () if transformed.observation is None else (transformed.observation,)
    )
    usage = _usage(attempts)
    manifest = manifest_from_observations(
        run_id=run_id,
        generated_at=transformed.completed_at or finished_at,
        requested_url=requested_url,
        current_url=acquisition.final_url,
        final_url=acquisition.final_url,
        http_status=acquisition.status_code,
        tool_id=acquisition.tool_id,
        tool_version=acquisition.tool_version,
        redirects=redirects,
        site_skill=site_skill,
        attempts=attempts,
        observations=observations,
        usage=usage,
    )
    return Result(
        status=(
            ResultStatus.PARTIAL
            if any(item.outcome != "succeeded" for item in attempts)
            else ResultStatus.COMPLETED
        ),
        manifest=manifest,
        site_skill_used=site_skill,
        site_skill_update=None,
        attempts=attempts,
        errors=tuple(acquisition_errors) + transformed.errors,
        usage=usage,
    )


def run_single_target_bounded(  # pylint: disable=too-many-arguments
    request: Request,
    registry: Registry,
    artifact_store: ArtifactStore,
    *,
    run_id: str,
    clock: Callable[[], str],
    target_url: str,
    budget_limits: Budgets,
) -> Result:
    """Run the existing governed path under narrower invocation-local limits."""
    limits = validate_budgets(budget_limits)
    token = _INVOCATION_BUDGET_LIMITS.set(limits)
    try:
        return run_single_target(
            request,
            registry,
            artifact_store,
            run_id=run_id,
            clock=clock,
            target_url=target_url,
        )
    finally:
        _INVOCATION_BUDGET_LIMITS.reset(token)


@contextmanager
def prior_target_attempts(attempts: tuple[Attempt, ...]) -> Iterator[None]:
    """Apply already-consumed target attempts to nested governed acquisitions."""
    token = _PRIOR_TARGET_ATTEMPTS.set(attempts)
    try:
        yield
    finally:
        _PRIOR_TARGET_ATTEMPTS.reset(token)


def run_agent_assisted_target(  # pylint: disable=too-many-arguments
    request: Request,
    registry: Registry,
    artifact_store: ArtifactStore,
    *,
    run_id: str,
    clock: Callable[[], str],
    explorer: ExplorerPort | None = None,
) -> ExplorationDecision:
    """Run once normally, then authorize at most one external proposal."""
    request = validate_request(request)
    if explorer is None:
        initial = run_single_target(
            request,
            registry,
            artifact_store,
            run_id=run_id,
            clock=clock,
        )
        return _exploration_decision("exploration.not_requested", initial)
    initial = run_single_target(
        request,
        registry,
        artifact_store,
        run_id=run_id,
        clock=clock,
        target_url=request.scope.seeds[0],
    )
    if not _is_acquisition_failure(initial):
        return _exploration_decision("exploration.not_needed", initial)

    try:
        scope_request, previous = _exploration_authority(request, registry)
    except (RequestValidationError, SiteSkillError, ToolRegistryError) as exc:
        return _exploration_decision(exc.code, initial)
    metadata = _exploration_metadata(initial, scope_request, previous)
    proposer_started_ns = time.perf_counter_ns()
    try:
        proposed = explorer.propose(metadata)
    except asyncio.CancelledError:
        return _exploration_decision("exploration.proposer_cancelled", initial)
    except Exception:  # pylint: disable=broad-exception-caught
        return _exploration_decision("exploration.proposer_exception", initial)
    proposer_runtime_ms = _elapsed_runtime_ms(
        proposer_started_ns, time.perf_counter_ns()
    )
    authorization_metadata = replace(
        metadata,
        runtime_ms=metadata.runtime_ms + proposer_runtime_ms,
        remaining_runtime_ms=max(
            0, metadata.remaining_runtime_ms - proposer_runtime_ms
        ),
    )

    proposal, rejection = _snapshot_proposal(proposed)
    if rejection is not None:
        return _exploration_decision(rejection, initial)
    assert proposal is not None
    authorized, rejection = _authorize_action(
        proposal,
        registry,
        scope_request=scope_request,
        previous=previous,
        metadata=authorization_metadata,
        prior_attempts=initial.attempts,
    )
    if rejection is not None:
        return _exploration_decision(rejection, initial, proposal=proposal)
    assert authorized is not None
    action_started_at = clock()
    action_started_ns = time.perf_counter_ns()
    try:
        execution = run_single_target(
            authorized.request,
            registry,
            artifact_store,
            run_id=_exploration_run_id(run_id),
            clock=clock,
            target_url=authorized.proposal.target_url,
        )
    except asyncio.CancelledError:
        action_finished_at = clock()
        cancelled = _cancelled_exploration_result(
            authorized,
            run_id=run_id,
            started_at=action_started_at,
            finished_at=action_finished_at,
            runtime_ms=_elapsed_runtime_ms(action_started_ns, time.perf_counter_ns()),
        )
        return ExplorationDecision(
            authorized.proposal,
            True,
            "exploration.execution_cancelled",
            _combine_exploration_results(initial, cancelled, None),
            None,
        )
    if not execution.artifacts:
        return ExplorationDecision(
            authorized.proposal,
            True,
            "exploration.execution_failed",
            _combine_exploration_results(initial, execution, None),
            None,
        )

    try:
        candidate = _create_exploration_candidate(authorized, execution, artifact_store)
    except (ArtifactStoreError, SiteSkillError):
        return ExplorationDecision(
            authorized.proposal,
            True,
            "exploration.candidate_verification_failed",
            _combine_exploration_results(initial, execution, None),
            None,
        )
    if candidate is None:
        return ExplorationDecision(
            authorized.proposal,
            True,
            "exploration.candidate_quality_unverified",
            _combine_exploration_results(initial, execution, None),
            None,
        )
    evidence = SiteSkillEvidence(
        str(candidate.skill.version),
        candidate.skill.digest.removeprefix("sha256:"),
    )
    return ExplorationDecision(
        authorized.proposal,
        True,
        "exploration.succeeded",
        _combine_exploration_results(initial, execution, evidence),
        candidate,
    )


def _exploration_authority(
    request: Request, registry: Registry
) -> tuple[Request, SiteSkill | None]:
    if request.site_skill is None:
        return request, None
    resolution = resolve_site_skill(request, request.site_skill, registry)
    if not resolution.eligible:
        raise SiteSkillError(_ineligible_code(resolution.reasons))
    return resolution.request, resolution.skill


def _is_acquisition_failure(result: Result) -> bool:
    return (
        result.status is ResultStatus.FAILED
        and not result.artifacts
        and bool(result.errors)
        and result.errors[-1].message == "Acquisition did not complete."
        and any(attempt.outcome == "failed" for attempt in result.attempts)
    )


def _exploration_metadata(
    result: Result,
    request: Request,
    previous: SiteSkill | None,
) -> ExplorationMetadata:
    failed = next(
        attempt for attempt in reversed(result.attempts) if attempt.outcome == "failed"
    )
    assert failed.error is not None
    runtime_limit_ms = request.budgets.max_runtime_seconds * 1_000
    return ExplorationMetadata(
        failure_code=failed.error.code,
        requested_url=_safe_exploration_url(failed.requested_url),
        current_url=_safe_exploration_url(
            failed.final_url or result.manifest.current_url
        ),
        tool_id=failed.tool_id,
        tool_version=failed.tool_version,
        http_status=failed.http_status,
        requests_used=result.usage.requests,
        bytes_received=result.usage.bytes_received,
        runtime_ms=result.usage.runtime_ms,
        tool_attempts_used=result.usage.tool_attempts,
        remaining_requests=max(0, request.budgets.max_requests - result.usage.requests),
        remaining_bytes=max(0, request.budgets.max_bytes - result.usage.bytes_received),
        remaining_runtime_ms=max(0, runtime_limit_ms - result.usage.runtime_ms),
        # This limit is per target; the proposal names a different target.
        remaining_tool_attempts_per_target=(
            request.budgets.max_tool_attempts_per_target
        ),
        active_site_skill_digest=(None if previous is None else previous.digest),
    )


def _safe_exploration_url(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _authorize_action(  # pylint: disable=too-many-arguments
    proposal: BoundedActionProposal,
    registry: Registry,
    *,
    scope_request: Request,
    previous: SiteSkill | None,
    metadata: ExplorationMetadata,
    prior_attempts: tuple[Attempt, ...],
) -> tuple[_AuthorizedAction | None, str | None]:
    if proposal.action != "acquire_url":
        return None, "exploration.action_unknown"
    decision = compile_access_policy(scope_request).decide_url(proposal.target_url)
    if not decision.allowed:
        return None, decision.code
    if proposal.budgets.max_tool_attempts_per_target != 1:
        return None, "exploration.action_contract_invalid"
    target_attempts_used = sum(
        attempt.outcome != "skipped"
        and canonicalize_url(attempt.requested_url) == proposal.target_url
        for attempt in prior_attempts
    )
    remaining_target_attempts = max(
        0,
        scope_request.budgets.max_tool_attempts_per_target - target_attempts_used,
    )
    if proposal.budgets.max_tool_attempts_per_target > remaining_target_attempts:
        return None, "eligibility.attempt_budget_exhausted"
    if (
        proposal.budgets.max_requests > metadata.remaining_requests
        or proposal.budgets.max_bytes > metadata.remaining_bytes
        or proposal.budgets.max_runtime_seconds * 1_000 > metadata.remaining_runtime_ms
        or proposal.budgets.max_tool_attempts_per_target
        > metadata.remaining_tool_attempts_per_target
    ):
        return None, "exploration.budget_exceeded"
    try:
        manifests = registry.query(category=ToolCategory.ACQUISITION)
    except ToolRegistryError as exc:
        return None, exc.code
    manifest = next(
        (item for item in manifests if item.tool_id == proposal.tool_id), None
    )
    if manifest is None:
        return None, "exploration.tool_unknown"
    tool_ids = frozenset(item.tool_id for item in manifests)
    selection = rank_eligible_tools(
        manifests,
        EligibilityRequirements(category=ToolCategory.ACQUISITION),
        EligibilityFacts(
            tool_ids,
            tool_ids,
            proposal.budgets.max_requests,
            proposal.budgets.max_bytes,
            proposal.budgets.max_runtime_seconds * 1_000,
            proposal.budgets.max_tool_attempts_per_target,
        ),
        preferred_tool_id=proposal.tool_id,
        include_alternates=False,
    )
    if not selection.ranked:
        tool_decision = next(
            item for item in selection.decisions if item.tool_id == proposal.tool_id
        )
        return None, (
            tool_decision.reasons[0]
            if tool_decision.reasons
            else "eligibility.ineligible"
        )
    if proposal.tool_id != _DEFAULT_ACQUISITION_TOOL_ID:
        return None, "exploration.tool_not_permitted"
    action_request = Request(
        scope_request.scope,
        None,
        False,
        proposal.budgets,
    )
    return (
        _AuthorizedAction(
            proposal,
            action_request,
            manifest,
            previous,
            scope_request,
        ),
        None,
    )


def _snapshot_proposal(
    value: object,
) -> tuple[BoundedActionProposal | None, str | None]:
    if (
        type(value) is not BoundedActionProposal
        or type(value.action) is not str
        or type(value.target_url) is not str
        or type(value.tool_id) is not str
        or type(value.budgets) is not Budgets
    ):
        return None, "exploration.proposal_invalid"
    try:
        target_url = canonicalize_url(value.target_url)
        validate_tool_id(value.tool_id)
        budgets = validate_budgets(value.budgets)
    except (RequestValidationError, ToolRegistryError) as exc:
        return None, exc.code
    return (
        BoundedActionProposal(value.action, target_url, value.tool_id, budgets),
        None,
    )


def _create_exploration_candidate(
    authorized: _AuthorizedAction,
    result: Result,
    artifact_store: ArtifactStore,
) -> SiteSkillCandidate | None:
    previous = authorized.previous
    mime_type = result.manifest.mime_type
    assert mime_type is not None
    source = next(
        artifact for artifact in result.artifacts if artifact.role == "source"
    )
    stored = artifact_store.read_artifact(source.artifact_id)
    observed_words = len(stored.content.decode("utf-8", errors="ignore").split())
    if observed_words == 0:
        return None
    if previous is not None and (
        mime_type not in previous.success_checks.allowed_mime_types
        or observed_words < previous.success_checks.minimum_words
    ):
        return None
    minimum_words = (
        observed_words if previous is None else previous.success_checks.minimum_words
    )
    checks = SuccessChecks((mime_type,), minimum_words)
    candidate_scope = replace(
        authorized.scope_request.scope,
        seeds=(authorized.proposal.target_url,),
    )
    hostname = urlsplit(authorized.proposal.target_url).hostname
    assert hostname is not None
    return create_candidate(
        site_key=(
            _site_key_from_hostname(hostname) if previous is None else previous.site_key
        ),
        version=1 if previous is None else previous.version + 1,
        previous=previous,
        scope=candidate_scope,
        budgets=authorized.proposal.budgets,
        tool=ToolReference(
            authorized.manifest.tool_id,
            authorized.manifest.version,
            authorized.manifest.category,
            authorized.manifest.capabilities,
        ),
        success_checks=checks,
        verified_at=result.manifest.generated_at,
    )


def _site_key_from_hostname(hostname: str) -> str:
    for candidate in (hostname, f"site-{hostname}"):
        try:
            return validate_tool_id(candidate)
        except ToolRegistryError:
            continue
    encoded = f"site-{hostname.encode('utf-8').hex()}"
    try:
        return validate_tool_id(encoded)
    except ToolRegistryError as exc:
        raise SiteSkillError("site_skill.site_key_invalid") from exc


def _combine_exploration_results(
    initial: Result,
    execution: Result,
    candidate: SiteSkillEvidence | None,
) -> Result:
    start = len(initial.attempts)
    action_attempts = tuple(
        replace(attempt, order=start + index)
        for index, attempt in enumerate(execution.attempts)
    )
    attempts = initial.attempts + action_attempts
    usage = _usage(attempts)
    manifest = replace(
        execution.manifest,
        run_id=initial.manifest.run_id,
        site_skill=initial.site_skill_used,
        attempts=attempts,
        usage=usage,
    )
    return Result(
        status=(ResultStatus.PARTIAL if execution.artifacts else ResultStatus.FAILED),
        manifest=manifest,
        site_skill_used=initial.site_skill_used,
        site_skill_update=candidate,
        attempts=attempts,
        errors=initial.errors + execution.errors,
        usage=usage,
    )


def _exploration_decision(
    code: str,
    result: Result,
    *,
    proposal: BoundedActionProposal | None = None,
) -> ExplorationDecision:
    return ExplorationDecision(proposal, False, code, result, None)


def _exploration_run_id(run_id: str) -> str:
    suffix = "-explore"
    return f"{run_id[: 128 - len(suffix)]}{suffix}"


def _cancelled_exploration_result(  # pylint: disable=too-many-arguments
    authorized: _AuthorizedAction,
    *,
    run_id: str,
    started_at: str,
    finished_at: str,
    runtime_ms: int,
) -> Result:
    action_run_id = _exploration_run_id(run_id)
    code = "exploration.execution_cancelled"
    error = SafeError(code, "Exploration action was cancelled.")
    attempt = _attempt(
        run_id=action_run_id,
        attempt_id=_ordered_attempt_id(action_run_id, "acquisition", 0),
        order=0,
        outcome="failed",
        requested_url=authorized.proposal.target_url,
        started_at=started_at,
        finished_at=finished_at,
        tool_id=authorized.manifest.tool_id,
        tool_version=authorized.manifest.version,
        final_url=None,
        http_status=None,
        error=error,
        requests=0,
        bytes_received=0,
        runtime_ms=runtime_ms,
    )
    return _failure_result(
        status=ResultStatus.FAILED,
        run_id=action_run_id,
        generated_at=finished_at,
        requested_url=authorized.proposal.target_url,
        current_url=authorized.proposal.target_url,
        code=code,
        message="Exploration action was cancelled.",
        tool_id=authorized.manifest.tool_id,
        tool_version=authorized.manifest.version,
        attempts=(attempt,),
    )


def _transform_stored_source(  # pylint: disable=too-many-arguments
    registry: Registry,
    artifact_store: ArtifactStore,
    source: StoredObservation,
    *,
    run_id: str,
    clock: Callable[[], str],
    tool_attempts_remaining: int,
    runtime_ms_remaining: int,
    attempt_order: int,
) -> _TransformResult:
    """Invoke at most one eligible generic Transform over stored HTML."""
    if tool_attempts_remaining <= 0 or runtime_ms_remaining <= 0:
        return _TransformResult()
    if classify_mime_type(source.artifact.mime_type) is not ContentType.HTML:
        return _TransformResult()
    manifests = registry.eligible(
        EligibilityRequirements(
            category=ToolCategory.TRANSFORM,
            capabilities=frozenset({"html_to_markdown"}),
            input_bytes=len(source.content),
        )
    )
    if not manifests:
        return _TransformResult()
    manifest = manifests[0]
    started_at = clock()
    invocation_started_ns = time.monotonic_ns()
    try:
        tool_input = TransformInput(source)
        transformed = registry.invoke(manifest.tool_id, tool_input)
    except ToolRegistryError as exc:
        invocation_runtime_ms = _elapsed_runtime_ms(invocation_started_ns)
        finished_at = clock()
        return _transform_failure_result(
            source,
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            tool_id=manifest.tool_id,
            tool_version=manifest.version,
            code=(
                "runtime.transform_runtime_budget_exceeded"
                if invocation_runtime_ms > runtime_ms_remaining
                else exc.code
            ),
            runtime_ms=invocation_runtime_ms,
            attempt_order=attempt_order,
        )
    invocation_runtime_ms = _elapsed_runtime_ms(invocation_started_ns)
    finished_at = clock()
    if isinstance(transformed, TransformFailure):
        return _transform_failure_result(
            source,
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            tool_id=transformed.tool_id,
            tool_version=transformed.tool_version,
            code=(
                "runtime.transform_runtime_budget_exceeded"
                if invocation_runtime_ms > runtime_ms_remaining
                else transformed.code
            ),
            runtime_ms=invocation_runtime_ms,
            attempt_order=attempt_order,
        )
    assert isinstance(transformed, TransformOutput)
    if transformed.runtime_ms > runtime_ms_remaining:
        return _transform_failure_result(
            source,
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            tool_id=transformed.tool_id,
            tool_version=transformed.tool_version,
            code="runtime.transform_runtime_budget_exceeded",
            runtime_ms=transformed.runtime_ms,
            attempt_order=attempt_order,
        )
    if transformed.mime_type != "text/markdown":
        return _transform_failure_result(
            source,
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            tool_id=transformed.tool_id,
            tool_version=transformed.tool_version,
            code="runtime.transform_output_mime_invalid",
            runtime_ms=transformed.runtime_ms,
            attempt_order=attempt_order,
        )
    try:
        derived = artifact_store.commit_observation(
            ObservationProposal(
                content=transformed.body,
                sha256=transformed.sha256,
                size_bytes=len(transformed.body),
                mime_type=transformed.mime_type,
                source_url=(
                    "urn:web-listening:transform:"
                    f"{transformed.tool_id}:{transformed.tool_version}"
                ),
                observed_at=finished_at,
                role=ArtifactRole.DERIVED,
                derived_from_observation_id=source.observation.observation_id,
            )
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        failed_at = clock()
        code = (
            exc.code
            if isinstance(exc, ArtifactStoreError)
            else "runtime.derived_commit_failed"
        )
        return _transform_failure_result(
            source,
            run_id=run_id,
            started_at=started_at,
            finished_at=failed_at,
            tool_id=transformed.tool_id,
            tool_version=transformed.tool_version,
            code=code,
            runtime_ms=transformed.runtime_ms,
            attempt_order=attempt_order,
        )
    return _TransformResult(
        attempt=_attempt(
            run_id=run_id,
            attempt_id=_ordered_attempt_id(run_id, "transform", attempt_order),
            order=attempt_order,
            outcome="succeeded",
            requested_url=source.observation.source_url,
            started_at=started_at,
            finished_at=finished_at,
            tool_id=transformed.tool_id,
            tool_version=transformed.tool_version,
            final_url=None,
            http_status=None,
            error=None,
            requests=0,
            bytes_received=0,
            runtime_ms=transformed.runtime_ms,
        ),
        observation=derived,
        completed_at=clock(),
    )


def _transform_failure_result(  # pylint: disable=too-many-arguments
    source: StoredObservation,
    *,
    run_id: str,
    started_at: str,
    finished_at: str,
    tool_id: str,
    tool_version: str,
    code: str,
    runtime_ms: int = 0,
    attempt_order: int = 1,
) -> _TransformResult:
    error = SafeError(code, "Transform did not complete.")
    return _TransformResult(
        attempt=_attempt(
            run_id=run_id,
            attempt_id=_ordered_attempt_id(run_id, "transform", attempt_order),
            order=attempt_order,
            outcome="failed",
            requested_url=source.observation.source_url,
            started_at=started_at,
            finished_at=finished_at,
            tool_id=tool_id,
            tool_version=tool_version,
            final_url=None,
            http_status=None,
            error=error,
            requests=0,
            bytes_received=0,
            runtime_ms=runtime_ms,
        ),
        errors=(error,),
        completed_at=finished_at,
    )


def discover_candidates(  # pylint: disable=too-many-arguments
    request: Request,
    registry: Registry,
    *,
    discovery_tool_id: str,
    source_url: str,
    source_body: bytes,
    source_mime_type: str,
) -> DiscoveryOutput | DiscoveryFailure:
    """Invoke one Discovery Protocol tool on an already-governed source."""
    request = validate_request(request)
    result = registry.invoke(
        discovery_tool_id,
        DiscoveryInput(
            request.scope,
            source_url,
            source_body,
            source_mime_type,
        ),
    )
    assert isinstance(result, (DiscoveryOutput, DiscoveryFailure))
    return result


def acquire_discovered_candidates(  # pylint: disable=too-many-arguments
    request: Request,
    registry: Registry,
    artifact_store: ArtifactStore,
    discovery: DiscoveryOutput,
    *,
    max_candidates: int,
    run_id: str,
    clock: Callable[[], str],
) -> tuple[DiscoveredCandidateResult, ...]:
    """Bound candidates and return each through the governed acquisition path."""
    request = validate_request(request)
    if (
        type(max_candidates) is not int
        or not 0 < max_candidates <= _MAX_DISCOVERY_CANDIDATES
    ):
        raise ToolRegistryError("runtime.discovery_limit_invalid")
    discovery = DiscoveryOutput(
        discovery.tool_id,
        discovery.tool_version,
        discovery.candidates,
        discovery.discovered_from,
        discovery.coverage,
    )
    assert discovery.discovered_from is not None
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    for candidate, source in sorted(
        zip(discovery.candidates, discovery.discovered_from)
    ):
        if candidate in seen:
            continue
        seen.add(candidate)
        candidates.append((candidate, source))
        if len(candidates) == max_candidates:
            break
    return tuple(
        DiscoveredCandidateResult(
            candidate,
            source,
            run_single_target(
                request,
                registry,
                artifact_store,
                run_id=f"{run_id}-{index + 1}",
                clock=clock,
                target_url=candidate,
            ),
        )
        for index, (candidate, source) in enumerate(candidates)
    )


def _acquisition_failure_result(  # pylint: disable=too-many-arguments
    *,
    run_id: str,
    generated_at: str,
    requested_url: str,
    tool_id: str,
    tool_version: str,
    code: str,
    site_skill: SiteSkillEvidence | None,
    attempts: tuple[Attempt, ...],
) -> Result:
    return _failure_result(
        status=ResultStatus.FAILED,
        run_id=run_id,
        generated_at=generated_at,
        requested_url=requested_url,
        current_url=requested_url,
        code=code,
        message="Acquisition did not complete.",
        tool_id=tool_id,
        tool_version=tool_version,
        site_skill=site_skill,
        attempts=attempts,
    )


def _failure_result(  # pylint: disable=too-many-arguments
    *,
    status: ResultStatus,
    run_id: str,
    generated_at: str,
    requested_url: str,
    current_url: str,
    code: str,
    message: str,
    tool_id: str | None = None,
    tool_version: str | None = None,
    site_skill: SiteSkillEvidence | None = None,
    redirects: tuple[RedirectEvidence, ...] = (),
    attempts: tuple[Attempt, ...] = (),
) -> Result:
    usage = _usage(attempts)
    error = SafeError(code, message)
    manifest = Manifest(
        run_id=run_id,
        generated_at=generated_at,
        requested_url=requested_url,
        current_url=current_url,
        final_url=None,
        http_status=None,
        mime_type=None,
        size_bytes=None,
        sha256=None,
        tool_id=tool_id,
        tool_version=tool_version,
        redirects=redirects,
        site_skill=site_skill,
        attempts=attempts,
        artifacts=(),
        usage=usage,
    )
    return Result(
        status=status,
        manifest=manifest,
        site_skill_used=site_skill,
        site_skill_update=None,
        attempts=attempts,
        errors=(error,),
        usage=usage,
    )


def _attempt(  # pylint: disable=too-many-arguments
    *,
    run_id: str,
    outcome: str,
    requested_url: str,
    started_at: str,
    finished_at: str,
    tool_id: str,
    tool_version: str,
    final_url: str | None,
    http_status: int | None,
    error: SafeError | None,
    requests: int,
    bytes_received: int,
    runtime_ms: int,
    order: int = 0,
    attempt_id: str | None = None,
) -> Attempt:
    return Attempt(
        order=order,
        attempt_id=run_id if attempt_id is None else attempt_id,
        outcome=outcome,
        tool_id=tool_id,
        tool_version=tool_version,
        started_at=started_at,
        finished_at=finished_at,
        requested_url=requested_url,
        final_url=final_url,
        http_status=http_status,
        error=error,
        requests=requests,
        bytes_received=bytes_received,
        runtime_ms=runtime_ms,
    )


def _ordered_attempt_id(run_id: str, kind: str, order: int) -> str:
    if order == 0 and kind == "acquisition":
        return run_id
    suffix = f"-{kind}-{order}"
    return f"{run_id[: 128 - len(suffix)]}{suffix}"


def _eligibility_error(reasons: tuple[str, ...]) -> SafeError:
    safe_reasons = reasons or ("eligibility.ineligible",)
    return SafeError(
        safe_reasons[0].partition(":")[0],
        "Acquisition tool was not eligible.",
        tuple((f"reason_{index}", reason) for index, reason in enumerate(safe_reasons)),
    )


def _quality_failure_code(
    acquisition: AcquisitionOutput,
    allowed_mime_types: tuple[str, ...],
    minimum_words: int,
) -> str | None:
    if acquisition.mime_type not in allowed_mime_types:
        return "runtime.quality_mime_mismatch"
    words = acquisition.body.decode("utf-8", errors="ignore").split()
    if len(words) < minimum_words:
        return "runtime.quality_minimum_words"
    return None


def _acquisition_budget_exhaustion_code(
    remaining_requests: int,
    remaining_bytes: int,
    remaining_runtime_ms: int,
    remaining_tool_attempts: int,
) -> str | None:
    if remaining_requests == 0:
        return "eligibility.request_budget_exhausted"
    if remaining_bytes == 0:
        return "eligibility.byte_budget_exhausted"
    if remaining_runtime_ms < 1_000:
        return "eligibility.runtime_budget_exhausted"
    if remaining_tool_attempts == 0:
        return "eligibility.attempt_budget_exhausted"
    return None


def _usage(attempts: tuple[Attempt, ...]) -> Usage:
    return Usage(
        requests=sum(attempt.requests for attempt in attempts),
        bytes_received=sum(attempt.bytes_received for attempt in attempts),
        runtime_ms=sum(attempt.runtime_ms for attempt in attempts),
        tool_attempts=sum(attempt.outcome != "skipped" for attempt in attempts),
    )


def _elapsed_runtime_ms(started_ns: int, finished_ns: int | None = None) -> int:
    if finished_ns is None:
        finished_ns = time.monotonic_ns()
    return max(0, (finished_ns - started_ns) // 1_000_000)


def _ineligible_code(reasons: tuple[str, ...]) -> str:
    if len(reasons) == 1 and ":" not in reasons[0]:
        return reasons[0]
    return "runtime.site_skill_ineligible"


__all__ = [
    "BoundedActionProposal",
    "DiscoveredCandidateResult",
    "ExplorationDecision",
    "ExplorationMetadata",
    "ExplorerPort",
    "acquire_discovered_candidates",
    "discover_candidates",
    "prior_target_attempts",
    "run_agent_assisted_target",
    "run_single_target",
]
