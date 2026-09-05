"""Availability-first serial composition for strict multi-site batches."""

# pylint: disable=duplicate-code,missing-function-docstring,too-many-locals
# pylint: disable=too-many-return-statements

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import nullcontext
from dataclasses import replace

from web_listening.artifact.site_state import SiteState
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Request, RequestValidationError
from web_listening.request.site_batch import (
    FileDiscoveryGoal,
    SiteBatchPhase,
    SiteBatchRequest,
    SiteRefreshContext,
    validate_site_batch_request,
)
from web_listening.request.site_refresh import SiteRefreshRequest
from web_listening.result.errors import ResultValidationError
from web_listening.result.manifest import Usage
from web_listening.result.site_batch import (
    FileDiscoveryStatus,
    SiteBatchMode,
    SiteBatchResult,
    derive_site_batch_completion,
    file_discovery_satisfied,
    site_batch_child_run_id,
    validate_site_batch_run_id,
)
from web_listening.result.site_explore import (
    SiteExploreResult,
    SiteSkillCandidateEvidence,
)
from web_listening.result.site_refresh import SiteRefreshResult, SiteSkillUpdate
from web_listening.runtime.site_explore import run_site_explore
from web_listening.runtime.site_refresh import run_site_refresh
from web_listening.runtime.workflow import cancellation_check
from web_listening.site_skill.validate import site_skill_from_mapping
from web_listening.tool_registry.registry import Registry

SiteResult = SiteExploreResult | SiteRefreshResult


def run_site_batch(  # pylint: disable=too-many-arguments
    request: SiteBatchRequest,
    registry: Registry,
    artifact_store: ArtifactStore,
    *,
    run_id: str,
    clock: Callable[[], str],
    completed_results: tuple[SiteResult, ...] = (),
    checkpoint: Callable[[int, SiteResult], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> SiteBatchResult:
    """Run every authorized site independently in stable serial order."""
    request = validate_site_batch_request(request)
    run_id = validate_site_batch_run_id(run_id)
    parent = request.request
    results: list[SiteResult] = list(completed_results)
    modes: list[SiteBatchMode] = []
    contexts: list[SiteRefreshContext] = []
    file_statuses: list[FileDiscoveryStatus] = []
    if len(results) > len(request.site_keys):
        raise ResultValidationError("site_batch.site_results_invalid")
    for index, prior in enumerate(results, start=1):
        input_context = (
            None
            if request.phase is SiteBatchPhase.FIRST
            else request.refresh_contexts[index - 1]
        )
        file_status = _file_status(prior, request.sites[index - 1].file_discovery_goal)
        file_statuses.append(file_status)
        mode = _mode(request.phase, prior, site_batch_child_run_id(run_id, index))
        modes.append(mode)
        context = _next_context(request.phase, prior, mode, input_context, file_status)
        if context is not None:
            contexts.append(context)
    for index, _seed in enumerate(
        parent.scope.seeds[len(results) :], start=len(results) + 1
    ):
        cancel_before_child = should_cancel is not None and should_cancel()
        child_run_id = site_batch_child_run_id(run_id, index)
        site = request.sites[index - 1]
        child_scope = site.scope
        require_file = site.file_discovery_goal is FileDiscoveryGoal.REQUIRED
        input_context = (
            None
            if request.phase is SiteBatchPhase.FIRST
            else request.refresh_contexts[index - 1]
        )
        context = (
            cancellation_check(lambda: True) if cancel_before_child else nullcontext()
        )
        with context:
            if request.phase is SiteBatchPhase.FIRST:
                child_request = Request(
                    child_scope,
                    None,
                    parent.explore_all_tools,
                    parent.budgets,
                )
                result: SiteResult = run_site_explore(
                    child_request,
                    registry,
                    artifact_store,
                    run_id=child_run_id,
                    clock=clock,
                    require_file=require_file,
                )
            else:
                assert input_context is not None
                result = run_site_refresh(
                    SiteRefreshRequest(
                        child_scope,
                        input_context.site_skill,
                        input_context.previous_state,
                        parent.explore_all_tools,
                        parent.budgets,
                    ),
                    registry,
                    artifact_store,
                    run_id=child_run_id,
                    clock=clock,
                    require_file=require_file,
                )
        results.append(result)
        file_status = _file_status(result, site.file_discovery_goal)
        file_statuses.append(file_status)
        mode = _mode(request.phase, result, child_run_id)
        modes.append(mode)
        context = _next_context(
            request.phase,
            result,
            mode,
            input_context,
            file_status,
        )
        if context is not None:
            contexts.append(context)
        if checkpoint is not None:
            checkpoint(index, result)
        if _cancelled(result):
            break
    return _batch_result(
        request,
        run_id,
        tuple(results),
        tuple(modes),
        tuple(contexts),
        tuple(file_statuses),
    )


def site_batch_result_from_mapping(value: object) -> SiteBatchResult:
    """Validate embedded Site Skills before rebuilding an inert batch Result."""
    evidence: list[SiteSkillCandidateEvidence | SiteSkillUpdate | None] = []
    if not isinstance(value, Mapping):
        return SiteBatchResult.from_dict(value)
    phase = value.get("phase")
    result_payloads = value.get("site_results")
    if not isinstance(result_payloads, list):
        return SiteBatchResult.from_dict(value)
    context_payloads = value.get("next_refresh_contexts")
    if not isinstance(context_payloads, list):
        return SiteBatchResult.from_dict(value)
    try:
        contexts = tuple(
            SiteRefreshContext.from_dict(item) for item in context_payloads
        )
    except RequestValidationError as exc:
        raise ResultValidationError("site_batch.next_context_invalid") from exc
    for result_payload in result_payloads:
        if not isinstance(result_payload, Mapping):
            evidence.append(None)
            continue
        if phase == "first":
            evidence.append(
                _candidate_evidence(result_payload.get("site_skill_candidate"))
            )
            continue
        update_payload = result_payload.get("site_skill_update")
        if update_payload is None:
            evidence.append(None)
            continue
        if not isinstance(update_payload, Mapping):
            evidence.append(None)
            continue
        candidate = _candidate_evidence(update_payload.get("candidate"))
        evidence.append(SiteSkillUpdate.from_dict(update_payload, candidate=candidate))
    return SiteBatchResult.from_dict(
        value,
        site_skill_evidence=tuple(evidence),
        next_refresh_contexts=contexts,
    )


def site_batch_child_result_from_mapping(
    phase: SiteBatchPhase, value: object
) -> SiteResult:
    """Rebuild one inert persisted child checkpoint without performing I/O."""
    if not isinstance(value, Mapping):
        raise ResultValidationError("site_batch.site_results_invalid")
    if phase is SiteBatchPhase.FIRST:
        evidence = _candidate_evidence(value.get("site_skill_candidate"))
        return SiteExploreResult.from_dict(value, site_skill_candidate=evidence)
    update_payload = value.get("site_skill_update")
    update = None
    if isinstance(update_payload, Mapping):
        update = SiteSkillUpdate.from_dict(
            update_payload,
            candidate=_candidate_evidence(update_payload.get("candidate")),
        )
    return SiteRefreshResult.from_dict(value, site_skill_update=update)


def _candidate_evidence(value: object) -> SiteSkillCandidateEvidence | None:
    if value is None:
        return None
    skill = site_skill_from_mapping(value)
    recipe = skill.discovery
    if recipe is None:
        return None
    return SiteSkillCandidateEvidence.from_validated_mapping(
        value,
        digest=skill.digest,
        discovery_key=(
            recipe.tool.tool_id,
            recipe.tool.version,
            recipe.source_url,
        ),
    )


def _state(result: SiteResult) -> SiteState:
    if isinstance(result, SiteExploreResult):
        return result.site_state
    return result.current_state


def _mode(
    phase: SiteBatchPhase, result: SiteResult, child_run_id: str
) -> SiteBatchMode:
    if not _state(result).pages:
        return SiteBatchMode.FAILED
    if phase is SiteBatchPhase.FIRST:
        return SiteBatchMode.RECOVERED
    if isinstance(result, SiteRefreshResult) and result.site_skill_update is not None:
        return SiteBatchMode.RECOVERED
    recovery_prefix = f"{child_run_id}-recovery-"
    identities = tuple(item.manifest.run_id for item in result.target_results) + tuple(
        item.attempt_id for item in result.attempts
    )
    if any(identity.startswith(recovery_prefix) for identity in identities):
        return SiteBatchMode.RECOVERED
    return SiteBatchMode.REPLAYED


def _next_context(
    phase: SiteBatchPhase,
    result: SiteResult,
    mode: SiteBatchMode,
    input_context: SiteRefreshContext | None,
    file_status: FileDiscoveryStatus,
) -> SiteRefreshContext | None:
    state = _state(result)
    if (
        not state.pages
        or result.stop_reason in {"rejected", "cancelled"}
        or file_status is FileDiscoveryStatus.NOT_FOUND
    ):
        return None
    if phase is SiteBatchPhase.FIRST:
        assert isinstance(result, SiteExploreResult)
        candidate = result.site_skill_candidate
        if candidate is None:
            return None
        skill = site_skill_from_mapping(candidate.to_dict())
        return SiteRefreshContext(
            skill,
            replace(state, site_skill_digest=skill.digest),
        )
    assert isinstance(result, SiteRefreshResult)
    assert input_context is not None
    update = result.site_skill_update
    if update is not None:
        skill = site_skill_from_mapping(update.candidate.to_dict())
        return SiteRefreshContext(
            skill,
            replace(state, site_skill_digest=skill.digest),
        )
    if mode is not SiteBatchMode.REPLAYED:
        return None
    if state.site_skill_digest != input_context.site_skill.digest:
        return None
    return SiteRefreshContext(input_context.site_skill, state)


def _cancelled(result: SiteResult) -> bool:
    return result.stop_reason == "cancelled" or any(
        error.code == "runtime.cancelled" for error in result.errors
    )


def _batch_result(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    request: SiteBatchRequest,
    run_id: str,
    results: tuple[SiteResult, ...],
    modes: tuple[SiteBatchMode, ...],
    contexts: tuple[SiteRefreshContext, ...],
    file_statuses: tuple[FileDiscoveryStatus, ...],
) -> SiteBatchResult:
    status, stop_reason = derive_site_batch_completion(
        request.site_keys,
        results,
        file_statuses,
    )
    return SiteBatchResult(
        request.phase.value,
        run_id,
        request.request_sha256,
        request.site_keys,
        results,
        modes,
        tuple(
            request.site_keys[index]
            for index, result in enumerate(results)
            if _state(result).pages
        ),
        contexts,
        status,
        stop_reason,
        _usage(results),
        tuple(error for result in results for error in result.errors),
        file_discovery_statuses=file_statuses,
    )


def _file_status(
    result: SiteResult,
    goal: FileDiscoveryGoal,
) -> FileDiscoveryStatus:
    if goal is FileDiscoveryGoal.NOT_REQUIRED:
        return FileDiscoveryStatus.NOT_REQUESTED
    return (
        FileDiscoveryStatus.SATISFIED
        if file_discovery_satisfied(result)
        else FileDiscoveryStatus.NOT_FOUND
    )


def _usage(results: tuple[SiteResult, ...]) -> Usage:
    return Usage(
        sum(result.usage.requests for result in results),
        sum(result.usage.bytes_received for result in results),
        sum(result.usage.runtime_ms for result in results),
        sum(result.usage.tool_attempts for result in results),
    )


__all__ = [
    "run_site_batch",
    "site_batch_child_result_from_mapping",
    "site_batch_result_from_mapping",
]
