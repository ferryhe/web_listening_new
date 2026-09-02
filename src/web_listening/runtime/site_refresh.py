"""Deterministic governed orchestration for one incremental site refresh."""

# pylint: disable=broad-exception-caught,duplicate-code,too-many-branches,too-many-lines
# pylint: disable=missing-function-docstring,too-many-locals
# pylint: disable=too-many-positional-arguments,too-many-return-statements
# pylint: disable=too-many-statements

from __future__ import annotations

from asyncio import CancelledError
from collections.abc import Callable, Mapping
from dataclasses import replace
from time import monotonic_ns
from urllib.parse import urlsplit

from web_listening.artifact.site_state import SiteState, SiteStatePage
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, Request
from web_listening.request.scope import canonicalize_url
from web_listening.request.site_refresh import (
    SiteRefreshRequest,
    validate_site_refresh_request,
)
from web_listening.request.validate import compile_access_policy
from web_listening.result.attempts import Attempt
from web_listening.result.errors import SafeError
from web_listening.result.manifest import ArtifactEvidence, SiteSkillEvidence, Usage
from web_listening.result.model import Result, ResultStatus
from web_listening.result.site_explore import (
    SiteExploreResult,
    SiteSkillCandidateEvidence,
)
from web_listening.result.site_refresh import (
    ChangeEvidence,
    SiteChange,
    SiteRefreshResult,
    SiteSkillUpdate,
)
from web_listening.runtime.site_explore import run_site_explore
from web_listening.runtime.workflow import (
    prior_target_attempts,
    run_single_target_bounded,
)
from web_listening.site_skill.model import SiteSkill
from web_listening.site_skill.update import create_candidate
from web_listening.site_skill.validate import (
    site_skill_from_mapping,
    site_skill_to_mapping,
)
from web_listening.tool_registry.eligibility import EligibilityRequirements
from web_listening.tool_registry.manifest import (
    ToolCategory,
    ToolManifest,
    ToolRegistryError,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryCoverage,
    DiscoveryFailure,
    DiscoveryInput,
    DiscoveryOutput,
)
from web_listening.tool_registry.protocols.transform import (
    TransformFailure,
    TransformInput,
)
from web_listening.tool_registry.registry import AcquisitionOutputRejected, Registry

_BUDGET_CODES = frozenset(
    {
        "budget.requests",
        "budget.bytes",
        "budget.runtime",
        "eligibility.request_budget_exhausted",
        "eligibility.byte_budget_exhausted",
        "eligibility.runtime_budget_exhausted",
        "eligibility.attempt_budget_exhausted",
    }
)
_REJECTION_CODES = frozenset(
    {
        "gateway.dns_not_public",
        "gateway.robots",
        "gateway.https_downgrade",
        "gateway.peer_not_public",
        "gateway.tls_certificate_invalid",
        "eligibility.unqualified",
        "eligibility.policy_noncompliant",
    }
)


def run_site_refresh(  # pylint: disable=too-many-arguments
    request: SiteRefreshRequest,
    registry: Registry,
    artifact_store: ArtifactStore,
    *,
    run_id: str,
    clock: Callable[[], str],
    require_file: bool = False,
) -> SiteRefreshResult:
    """Replay one validated recipe under a single shared budget ledger."""
    request = validate_site_refresh_request(request)
    generated_at = clock()
    skill = request.site_skill
    active_evidence = _skill_evidence(skill)
    limits = skill.budgets
    acquisition_registry = _AcquisitionOnlyRegistry(registry)
    governed_request = Request(
        request.scope,
        skill,
        request.explore_all_tools,
        request.budgets,
    )
    attempts: tuple[Attempt, ...] = ()
    errors: tuple[SafeError, ...] = ()
    successful_sources: list[ArtifactEvidence] = []
    failed_by_url: dict[str, tuple[Attempt, ...]] = {}
    site_skill_update: SiteSkillUpdate | None = None

    discovery_source_url = skill.discovery.source_url  # type: ignore[union-attr]
    remaining = _remaining_budgets(limits, attempts, discovery_source_url)
    assert remaining is not None
    source_result = run_single_target_bounded(
        governed_request,
        acquisition_registry,  # type: ignore[arg-type]
        artifact_store,
        run_id=f"{run_id}-source",
        clock=clock,
        target_url=discovery_source_url,
        budget_limits=remaining,
    )
    target_results: list[Result] = [source_result]
    attempts = _merge_attempts(attempts, source_result.attempts)
    errors += source_result.errors
    source = _source_artifact(source_result)
    if source is None:
        failed = _failed_target_attempts(source_result, discovery_source_url)
        if failed:
            failed_by_url[discovery_source_url] = failed
            errors = _merge_failed_attempt_errors(errors, failed)
        stop_reason = _terminal_stop_reason(source_result)
        return _result(
            request,
            generated_at=generated_at,
            active_evidence=active_evidence,
            target_results=tuple(target_results),
            attempts=attempts,
            errors=errors,
            sources=(),
            failed_by_url=failed_by_url,
            complete=False,
            stop_reason=stop_reason,
            site_skill_update=None,
            state_skill_digest=skill.digest,
        )
    identity_error = _site_identity_error(source, skill)
    if identity_error is not None:
        errors += (identity_error,)
        return _result(
            request,
            generated_at=generated_at,
            active_evidence=active_evidence,
            target_results=tuple(target_results),
            attempts=attempts,
            errors=errors,
            sources=(),
            failed_by_url=failed_by_url,
            complete=False,
            stop_reason="rejected",
            site_skill_update=None,
            state_skill_digest=skill.digest,
        )
    successful_sources.append(source)
    site_skill_update = _preferred_tool_update(
        skill,
        source_result,
        registry,
        generated_at=generated_at,
    )

    remaining = _remaining_budgets(limits, attempts, discovery_source_url)
    if remaining is None:
        errors += (SafeError("budget.exhausted", "Refresh budget was exhausted."),)
        return _result(
            request,
            generated_at=generated_at,
            active_evidence=active_evidence,
            target_results=tuple(target_results),
            attempts=attempts,
            errors=errors,
            sources=tuple(successful_sources),
            failed_by_url=failed_by_url,
            complete=False,
            stop_reason="budget_exhausted",
            site_skill_update=site_skill_update,
            state_skill_digest=skill.digest,
        )

    recipe = skill.discovery
    assert recipe is not None
    stored_source = artifact_store.read_artifact(source.artifact_id)
    manifest = _exact_discovery_manifest(
        registry,
        recipe.tool.tool_id,
        recipe.tool.version,
        recipe.tool.capabilities,
        len(stored_source.content),
    )
    if manifest is None:
        code = "runtime.discovery_recipe_unavailable"
        error = SafeError(code, "Stored discovery recipe was unavailable.")
        discovery_attempt = _discovery_attempt(
            run_id,
            recipe.tool.tool_id,
            recipe.tool.version,
            source.source_url,
            clock(),
            clock(),
            error=error,
            runtime_ms=0,
        )
        attempts = _merge_attempts(attempts, (discovery_attempt,))
        errors += (error,)
        return _recover(
            request,
            registry,
            artifact_store,
            generated_at=generated_at,
            run_id=run_id,
            clock=clock,
            active_evidence=active_evidence,
            target_results=tuple(target_results),
            attempts=attempts,
            errors=errors,
            sources=tuple(successful_sources),
            require_file=require_file,
        )

    started_at = clock()
    invocation_started_ns = monotonic_ns()
    discovery_error: SafeError | None = None
    cancelled = False
    try:
        discovery = registry.invoke(
            manifest.tool_id,
            DiscoveryInput(
                skill.scope,
                source.source_url,
                stored_source.content,
                source.mime_type,
            ),
        )
    except CancelledError:
        discovery = None
        cancelled = True
        discovery_error = SafeError("runtime.cancelled", "Refresh was cancelled.")
    except Exception as exc:
        discovery = None
        discovery_error = SafeError(
            getattr(exc, "code", "registry.tool_exception"),
            "Discovery did not complete.",
        )
    finished_at = clock()
    runtime_ms = max(0, (monotonic_ns() - invocation_started_ns) // 1_000_000)
    if isinstance(discovery, DiscoveryFailure):
        discovery_error = SafeError(discovery.code, "Discovery did not complete.")
    if discovery_error is not None:
        attempts = _merge_attempts(
            attempts,
            (
                _discovery_attempt(
                    run_id,
                    manifest.tool_id,
                    manifest.version,
                    source.source_url,
                    started_at,
                    finished_at,
                    error=discovery_error,
                    runtime_ms=runtime_ms,
                ),
            ),
        )
        errors += (discovery_error,)
        if cancelled:
            return _result(
                request,
                generated_at=generated_at,
                active_evidence=active_evidence,
                target_results=tuple(target_results),
                attempts=attempts,
                errors=errors,
                sources=tuple(successful_sources),
                failed_by_url=failed_by_url,
                complete=False,
                stop_reason="cancelled",
                site_skill_update=site_skill_update,
                state_skill_digest=skill.digest,
            )
        if discovery_error.code in _BUDGET_CODES:
            return _result(
                request,
                generated_at=generated_at,
                active_evidence=active_evidence,
                target_results=tuple(target_results),
                attempts=attempts,
                errors=errors,
                sources=tuple(successful_sources),
                failed_by_url=failed_by_url,
                complete=False,
                stop_reason="budget_exhausted",
                site_skill_update=site_skill_update,
                state_skill_digest=skill.digest,
            )
        return _recover(
            request,
            registry,
            artifact_store,
            generated_at=generated_at,
            run_id=run_id,
            clock=clock,
            active_evidence=active_evidence,
            target_results=tuple(target_results),
            attempts=attempts,
            errors=errors,
            sources=tuple(successful_sources),
            require_file=require_file,
        )

    assert isinstance(discovery, DiscoveryOutput)
    if any(value != source.source_url for value in discovery.discovered_from or ()):
        error = SafeError(
            "runtime.discovery_provenance_mismatch",
            "Discovery provenance did not match the stored recipe source.",
        )
        attempts = _merge_attempts(
            attempts,
            (
                _discovery_attempt(
                    run_id,
                    manifest.tool_id,
                    manifest.version,
                    source.source_url,
                    started_at,
                    finished_at,
                    error=error,
                    runtime_ms=runtime_ms,
                ),
            ),
        )
        errors += (error,)
        return _recover(
            request,
            registry,
            artifact_store,
            generated_at=generated_at,
            run_id=run_id,
            clock=clock,
            active_evidence=active_evidence,
            target_results=tuple(target_results),
            attempts=attempts,
            errors=errors,
            sources=tuple(successful_sources),
            require_file=require_file,
        )
    attempts = _merge_attempts(
        attempts,
        (
            _discovery_attempt(
                run_id,
                manifest.tool_id,
                manifest.version,
                source.source_url,
                started_at,
                finished_at,
                error=None,
                runtime_ms=runtime_ms,
            ),
        ),
    )
    policy = compile_access_policy(Request(skill.scope, None, False, skill.budgets))
    observed_urls = {source.source_url}
    discovered_candidates = (
        tuple(dict.fromkeys(discovery.candidates))
        if require_file and "html_file_links" in manifest.capabilities
        else tuple(sorted(set(discovery.candidates)))
    )
    candidates = tuple(
        candidate
        for candidate in discovered_candidates
        if candidate not in observed_urls
        and (
            require_file
            or policy.decide_url(candidate).allowed
            and (urlsplit(candidate).hostname or "invalid") == skill.site_key
        )
    )
    complete = discovery.coverage is DiscoveryCoverage.COMPLETE
    stop_reason = "source_exhausted" if complete else "discovery_failed"
    if not complete:
        errors += (
            SafeError(
                "runtime.discovery_coverage_incomplete",
                "Discovery coverage was incomplete.",
            ),
        )
    required_file_satisfied = False
    candidate_numbers = {
        url: index for index, url in enumerate(sorted(candidates), start=1)
    }
    for candidate_url in candidates:
        parsed_candidate = urlsplit(candidate_url)
        if (
            require_file
            and (parsed_candidate.hostname or "invalid") != skill.site_key
            and policy.decide_url(candidate_url).allowed
        ):
            errors += (
                SafeError(
                    "runtime.site_identity_mismatch",
                    "Candidate belongs to a different site identity.",
                ),
            )
            complete = False
            stop_reason = "rejected"
            site_skill_update = None
            break
        remaining = _remaining_budgets(limits, attempts, candidate_url)
        if remaining is None:
            complete = False
            stop_reason = "budget_exhausted"
            errors += (SafeError("budget.exhausted", "Refresh budget was exhausted."),)
            break
        target_result = run_single_target_bounded(
            governed_request,
            acquisition_registry,  # type: ignore[arg-type]
            artifact_store,
            run_id=f"{run_id}-candidate-{candidate_numbers[candidate_url]}",
            clock=clock,
            target_url=candidate_url,
            budget_limits=remaining,
        )
        target_results.append(target_result)
        attempts = _merge_attempts(attempts, target_result.attempts)
        errors += target_result.errors
        target_source = _source_artifact(target_result)
        if target_source is not None:
            identity_error = _site_identity_error(target_source, skill)
            if identity_error is not None:
                errors += (identity_error,)
                complete = False
                stop_reason = "rejected"
                site_skill_update = None
                break
            successful_sources.append(target_source)
            observed_urls.add(target_source.source_url)
            update = _preferred_tool_update(
                skill,
                target_result,
                registry,
                generated_at=generated_at,
            )
            if update is not None:
                site_skill_update = update
            if require_file and target_source.mime_type not in {
                "application/xhtml+xml",
                "text/html",
            }:
                required_file_satisfied = True
                break
            continue
        failed = _failed_target_attempts(target_result, candidate_url)
        if failed:
            failed_by_url[candidate_url] = failed
            errors = _merge_failed_attempt_errors(errors, failed)
        terminal = _terminal_stop_reason(target_result)
        if terminal in {"budget_exhausted", "cancelled", "rejected"}:
            complete = False
            stop_reason = terminal
            if terminal == "rejected":
                site_skill_update = None
            break
    if not required_file_satisfied and _shared_budget_exhausted(limits, attempts):
        complete = False
        stop_reason = "budget_exhausted"
        if "budget.exhausted" not in {error.code for error in errors}:
            errors += (SafeError("budget.exhausted", "Refresh budget was exhausted."),)
    target_results[1:] = sorted(
        target_results[1:],
        key=lambda result: result.manifest.requested_url,
    )
    return _result(
        request,
        generated_at=generated_at,
        active_evidence=active_evidence,
        target_results=tuple(target_results),
        attempts=attempts,
        errors=errors,
        sources=tuple(successful_sources),
        failed_by_url=failed_by_url,
        complete=complete,
        stop_reason=stop_reason,
        site_skill_update=site_skill_update,
        state_skill_digest=skill.digest,
    )


def site_refresh_result_from_mapping(value: object) -> SiteRefreshResult:
    """Parse a result after validating any candidate through Site Skill authority."""
    update = None
    if isinstance(value, Mapping):
        update_payload = value.get("site_skill_update")
        if isinstance(update_payload, Mapping):
            candidate = _candidate_evidence(
                site_skill_from_mapping(update_payload.get("candidate"))
            )
            update = SiteSkillUpdate.from_dict(
                update_payload,
                candidate=candidate,
            )
    return SiteRefreshResult.from_dict(value, site_skill_update=update)


def _recover(  # pylint: disable=too-many-arguments
    request: SiteRefreshRequest,
    registry: Registry,
    artifact_store: ArtifactStore,
    *,
    generated_at: str,
    run_id: str,
    clock: Callable[[], str],
    active_evidence: SiteSkillEvidence,
    target_results: tuple[Result, ...],
    attempts: tuple[Attempt, ...],
    errors: tuple[SafeError, ...],
    sources: tuple[ArtifactEvidence, ...],
    require_file: bool,
) -> SiteRefreshResult:
    recovery_seed_url = request.site_skill.scope.seeds[0]
    recovery_scope = replace(
        request.site_skill.scope,
        seeds=(recovery_seed_url,),
    )
    remaining = _remaining_budgets(
        request.site_skill.budgets,
        attempts,
        recovery_seed_url,
    )
    if remaining is None:
        errors += (SafeError("budget.exhausted", "Refresh budget was exhausted."),)
        return _result(
            request,
            generated_at=generated_at,
            active_evidence=active_evidence,
            target_results=target_results,
            attempts=attempts,
            errors=errors,
            sources=sources,
            failed_by_url={},
            complete=False,
            stop_reason="budget_exhausted",
            site_skill_update=None,
            state_skill_digest=request.site_skill.digest,
        )
    recovery_registry = _RecoveryRegistry(
        registry,
        attempts,
        recovery_seed_url,
        request.site_skill.budgets.max_tool_attempts_per_target,
    )
    recovery_limits = Budgets(
        remaining.max_requests,
        remaining.max_bytes,
        remaining.max_runtime_seconds,
        request.site_skill.budgets.max_tool_attempts_per_target,
    )
    with prior_target_attempts(attempts):
        recovery = run_site_explore(
            Request(
                recovery_scope,
                None,
                request.explore_all_tools,
                recovery_limits,
            ),
            recovery_registry,  # type: ignore[arg-type]
            artifact_store,
            run_id=f"{run_id}-recovery",
            clock=clock,
            require_file=require_file,
        )
    recovery_attempts = recovery_registry.audited_attempts(recovery.attempts)
    target_results += recovery.target_results
    failed_by_url = _recovery_failed_by_url(recovery_attempts, registry)
    attempts = _merge_attempts(attempts, recovery_attempts)
    if any(
        item.outcome == "succeeded"
        and item.coverage != DiscoveryCoverage.COMPLETE.value
        for item in recovery.discovery
    ) and "runtime.discovery_coverage_incomplete" not in {
        error.code for error in errors
    }:
        errors += (
            SafeError(
                "runtime.discovery_coverage_incomplete",
                "Discovery coverage was incomplete.",
            ),
        )
    errors += recovery.errors
    page_by_url = {
        page.canonical_url: page
        for page in _state_pages(sources, request.site_skill.site_key)
    }
    recovery_identity_mismatch = (
        recovery.site_state.site_key != request.site_skill.site_key
        or any(
            error.code == "runtime.site_identity_mismatch" for error in recovery.errors
        )
        or any(
            (urlsplit(page.canonical_url).hostname or "invalid")
            != request.site_skill.site_key
            for page in recovery.site_state.pages
        )
    )
    page_by_url.update(
        {
            page.canonical_url: page
            for page in recovery.site_state.pages
            if (urlsplit(page.canonical_url).hostname or "invalid")
            == request.site_skill.site_key
        }
    )
    current_pages = tuple(page_by_url[url] for url in sorted(page_by_url))
    error_codes = {error.code for error in errors}
    for url in sorted(failed_by_url):
        for attempt in failed_by_url[url]:
            if attempt.error is not None and attempt.error.code not in error_codes:
                errors += (attempt.error,)
                error_codes.add(attempt.error.code)
    if recovery_registry.attempt_budget_exhausted and "budget.exhausted" not in {
        error.code for error in errors
    }:
        errors += (SafeError("budget.exhausted", "Refresh budget was exhausted."),)
    shared_budget_exhausted = _shared_budget_exhausted(
        request.site_skill.budgets, attempts
    )
    if shared_budget_exhausted and "budget.exhausted" not in {
        error.code for error in errors
    }:
        errors += (SafeError("budget.exhausted", "Refresh budget was exhausted."),)
    if recovery_identity_mismatch:
        if "runtime.site_identity_mismatch" not in {error.code for error in errors}:
            errors += (
                SafeError(
                    "runtime.site_identity_mismatch",
                    "Acquired page did not match the active site identity.",
                ),
            )
        current_state = SiteState(
            request.site_skill.site_key,
            generated_at,
            None,
            False,
            current_pages,
        )
        return _result_from_state(
            request,
            current_state=current_state,
            active_evidence=active_evidence,
            target_results=target_results,
            attempts=attempts,
            errors=errors,
            failed_by_url=failed_by_url,
            complete=False,
            stop_reason="rejected",
            site_skill_update=None,
        )
    if recovery_registry.rejection_code is not None:
        if recovery_registry.rejection_code not in {error.code for error in errors}:
            errors += (
                SafeError(
                    recovery_registry.rejection_code,
                    "Acquisition did not complete.",
                ),
            )
        current_state = SiteState(
            request.site_skill.site_key,
            generated_at,
            None,
            False,
            current_pages,
        )
        return _result_from_state(
            request,
            current_state=current_state,
            active_evidence=active_evidence,
            target_results=target_results,
            attempts=attempts,
            errors=errors,
            failed_by_url=failed_by_url,
            complete=False,
            stop_reason=("budget_exhausted" if shared_budget_exhausted else "rejected"),
            site_skill_update=None,
        )
    if (
        recovery.exploration_complete
        and recovery.site_skill_candidate is not None
        and not recovery_registry.attempt_budget_exhausted
        and not shared_budget_exhausted
    ):
        recovered = site_skill_from_mapping(recovery.site_skill_candidate.to_dict())
        candidate = create_candidate(
            site_key=request.site_skill.site_key,
            version=request.site_skill.version + 1,
            previous=request.site_skill,
            scope=request.site_skill.scope,
            budgets=request.site_skill.budgets,
            tool=recovered.tool,
            success_checks=recovered.success_checks,
            verified_at=generated_at,
            discovery=recovered.discovery,
        ).skill
        update = SiteSkillUpdate(
            "discovery_recipe_changed",
            active_evidence,
            _candidate_evidence(candidate),
        )
        coverage_error = _recovery_coverage_error(
            recovery, registry, request, current_pages
        )
        if coverage_error is not None:
            if coverage_error.code not in {error.code for error in errors}:
                errors += (coverage_error,)
            current_state = SiteState(
                recovery.site_state.site_key,
                generated_at,
                candidate.digest,
                False,
                current_pages,
            )
            return _result_from_state(
                request,
                current_state=current_state,
                active_evidence=active_evidence,
                target_results=target_results,
                attempts=attempts,
                errors=errors,
                failed_by_url=failed_by_url,
                complete=False,
                stop_reason="recovery_incomplete",
                site_skill_update=update,
            )
        current_state = SiteState(
            recovery.site_state.site_key,
            generated_at,
            candidate.digest,
            True,
            current_pages,
        )
        return _result_from_state(
            request,
            current_state=current_state,
            active_evidence=active_evidence,
            target_results=target_results,
            attempts=attempts,
            errors=errors,
            failed_by_url=failed_by_url,
            complete=True,
            stop_reason="source_exhausted",
            site_skill_update=update,
        )
    stop_reason = (
        "budget_exhausted"
        if recovery_registry.attempt_budget_exhausted or shared_budget_exhausted
        else {
            "budget_exhausted": "budget_exhausted",
            "cancelled": "cancelled",
            "rejected": "rejected",
        }.get(recovery.stop_reason, "recovery_incomplete")
    )
    current_state = SiteState(
        request.site_skill.site_key,
        generated_at,
        None,
        False,
        current_pages,
    )
    return _result_from_state(
        request,
        current_state=current_state,
        active_evidence=active_evidence,
        target_results=target_results,
        attempts=attempts,
        errors=errors,
        failed_by_url=failed_by_url,
        complete=False,
        stop_reason=stop_reason,
        site_skill_update=None,
    )


def _result(  # pylint: disable=too-many-arguments
    request: SiteRefreshRequest,
    *,
    generated_at: str,
    active_evidence: SiteSkillEvidence,
    target_results: tuple[Result, ...],
    attempts: tuple[Attempt, ...],
    errors: tuple[SafeError, ...],
    sources: tuple[ArtifactEvidence, ...],
    failed_by_url: dict[str, tuple[Attempt, ...]],
    complete: bool,
    stop_reason: str,
    site_skill_update: SiteSkillUpdate | None,
    state_skill_digest: str | None,
) -> SiteRefreshResult:
    current_state = SiteState(
        request.site_skill.site_key,
        generated_at,
        state_skill_digest,
        complete,
        _state_pages(sources, request.site_skill.site_key),
    )
    return _result_from_state(
        request,
        current_state=current_state,
        active_evidence=active_evidence,
        target_results=target_results,
        attempts=attempts,
        errors=errors,
        failed_by_url=failed_by_url,
        complete=complete,
        stop_reason=stop_reason,
        site_skill_update=site_skill_update,
    )


def _result_from_state(  # pylint: disable=too-many-arguments
    request: SiteRefreshRequest,
    *,
    current_state: SiteState,
    active_evidence: SiteSkillEvidence,
    target_results: tuple[Result, ...],
    attempts: tuple[Attempt, ...],
    errors: tuple[SafeError, ...],
    failed_by_url: dict[str, tuple[Attempt, ...]],
    complete: bool,
    stop_reason: str,
    site_skill_update: SiteSkillUpdate | None,
) -> SiteRefreshResult:
    if _shared_budget_exhausted(
        request.site_skill.budgets, attempts
    ) or "budget.exhausted" in {error.code for error in errors}:
        complete = False
        stop_reason = "budget_exhausted"
        current_state = replace(current_state, complete=False)
        if "budget.exhausted" not in {error.code for error in errors}:
            errors += (SafeError("budget.exhausted", "Refresh budget was exhausted."),)
    changes = compare_site_states(
        request.previous_state,
        current_state,
        refresh_complete=complete,
        failed_by_url=failed_by_url,
    )
    usage = _usage(attempts)
    return SiteRefreshResult(
        status=ResultStatus.COMPLETED if complete else ResultStatus.PARTIAL,
        refresh_complete=complete,
        added=changes["added"],
        changed=changes["changed"],
        unchanged=changes["unchanged"],
        missing=changes["missing"],
        failed=changes["failed"],
        unresolved=changes["unresolved"],
        previous_state=request.previous_state,
        current_state=current_state,
        site_skill_used=active_evidence,
        site_skill_update=site_skill_update,
        target_results=target_results,
        attempts=attempts,
        usage=usage,
        stop_reason=stop_reason,
        errors=errors,
    )


def compare_site_states(
    previous: SiteState,
    current: SiteState,
    *,
    refresh_complete: bool,
    failed_by_url: dict[str, tuple[Attempt, ...]],
) -> dict[str, tuple[SiteChange, ...]]:
    """Compare canonical URLs and frozen digests into six stable collections."""
    previous_pages = {page.canonical_url: page for page in previous.pages}
    current_pages = {page.canonical_url: page for page in current.pages}
    changes: dict[str, list[SiteChange]] = {
        name: []
        for name in (
            "added",
            "changed",
            "unchanged",
            "missing",
            "failed",
            "unresolved",
        )
    }
    for url in sorted(current_pages):
        current_page = current_pages[url]
        previous_page = previous_pages.get(url)
        if previous_page is None:
            change_type = "added"
        elif previous_page.content_digest == current_page.content_digest:
            change_type = "unchanged"
        else:
            change_type = "changed"
        changes[change_type].append(
            SiteChange(
                url,
                change_type,
                None if previous_page is None else _page_evidence(previous_page),
                _page_evidence(current_page),
            )
        )
    for url in sorted(failed_by_url):
        if url in current_pages:
            continue
        failed_attempts = failed_by_url[url]
        if not failed_attempts:
            continue
        changes["failed"].append(
            SiteChange(
                url,
                "failed",
                (
                    None
                    if url not in previous_pages
                    else _page_evidence(previous_pages[url])
                ),
                None,
                tuple(sorted(attempt.attempt_id for attempt in failed_attempts)),
                tuple(
                    sorted(
                        {
                            attempt.error.code
                            for attempt in failed_attempts
                            if attempt.error is not None
                        }
                    )
                ),
            )
        )
    for url in sorted(set(previous_pages) - set(current_pages) - set(failed_by_url)):
        change_type = "missing" if refresh_complete else "unresolved"
        changes[change_type].append(
            SiteChange(
                url,
                change_type,
                _page_evidence(previous_pages[url]),
                None,
            )
        )
    return {name: tuple(items) for name, items in changes.items()}


def _exact_discovery_manifest(
    registry: Registry,
    tool_id: str,
    version: str,
    capabilities: frozenset[str],
    input_bytes: int,
) -> ToolManifest | None:
    manifest = next(
        (
            item
            for item in registry.query(category=ToolCategory.DISCOVERY)
            if item.tool_id == tool_id
        ),
        None,
    )
    if (
        manifest is None
        or manifest.version != version
        or not capabilities.issubset(manifest.capabilities)
    ):
        return None
    eligible = registry.eligible(
        EligibilityRequirements(
            category=ToolCategory.DISCOVERY,
            capabilities=capabilities,
            input_bytes=input_bytes,
        )
    )
    return manifest if manifest in eligible else None


def _discovery_attempt(  # pylint: disable=too-many-arguments
    run_id: str,
    tool_id: str,
    tool_version: str,
    source_url: str,
    started_at: str,
    finished_at: str,
    *,
    error: SafeError | None,
    runtime_ms: int,
) -> Attempt:
    suffix = "-discovery"
    return Attempt(
        0,
        f"{run_id[: 128 - len(suffix)]}{suffix}",
        "succeeded" if error is None else "failed",
        tool_id,
        tool_version,
        started_at,
        finished_at,
        source_url,
        None,
        None,
        error,
        0,
        0,
        runtime_ms,
    )


def _remaining_budgets(
    limits: Budgets,
    attempts: tuple[Attempt, ...],
    target_url: str,
) -> Budgets | None:
    usage = _usage(attempts)
    requests = limits.max_requests - usage.requests
    bytes_remaining = limits.max_bytes - usage.bytes_received
    runtime_seconds = (limits.max_runtime_seconds * 1_000 - usage.runtime_ms) // 1_000
    target_attempts = sum(
        attempt.outcome != "skipped" and attempt.requested_url == target_url
        for attempt in attempts
    )
    tool_attempts = limits.max_tool_attempts_per_target - target_attempts
    if (
        requests <= 0
        or bytes_remaining <= 0
        or runtime_seconds <= 0
        or tool_attempts <= 0
    ):
        return None
    return Budgets(requests, bytes_remaining, runtime_seconds, tool_attempts)


def _usage(attempts: tuple[Attempt, ...]) -> Usage:
    return Usage(
        sum(attempt.requests for attempt in attempts),
        sum(attempt.bytes_received for attempt in attempts),
        sum(attempt.runtime_ms for attempt in attempts),
        sum(attempt.outcome != "skipped" for attempt in attempts),
    )


def _shared_budget_exhausted(limits: Budgets, attempts: tuple[Attempt, ...]) -> bool:
    usage = _usage(attempts)
    return (
        usage.requests > limits.max_requests
        or usage.bytes_received > limits.max_bytes
        or usage.runtime_ms > limits.max_runtime_seconds * 1_000
    )


def _merge_attempts(
    current: tuple[Attempt, ...], additions: tuple[Attempt, ...]
) -> tuple[Attempt, ...]:
    combined = current + additions
    return tuple(
        replace(attempt, order=index) for index, attempt in enumerate(combined)
    )


def _source_artifact(result: Result) -> ArtifactEvidence | None:
    return next(
        (artifact for artifact in result.artifacts if artifact.role == "source"), None
    )


def _site_identity_error(
    source: ArtifactEvidence, skill: SiteSkill
) -> SafeError | None:
    if (urlsplit(source.source_url).hostname or "invalid") == skill.site_key:
        return None
    return SafeError(
        "runtime.site_identity_mismatch",
        "Acquired page did not match the active site identity.",
    )


def _failed_target_attempts(result: Result, url: str) -> tuple[Attempt, ...]:
    return tuple(
        attempt
        for attempt in result.attempts
        if attempt.requested_url == url
        and attempt.outcome == "failed"
        and attempt.error is not None
    )


def _merge_failed_attempt_errors(
    errors: tuple[SafeError, ...], attempts: tuple[Attempt, ...]
) -> tuple[SafeError, ...]:
    merged = list(errors)
    error_codes = {error.code for error in errors}
    for attempt in attempts:
        if attempt.error is not None and attempt.error.code not in error_codes:
            merged.append(attempt.error)
            error_codes.add(attempt.error.code)
    return tuple(merged)


def _recovery_coverage_error(
    recovery: SiteExploreResult,
    registry: Registry,
    request: SiteRefreshRequest,
    current_pages: tuple[SiteStatePage, ...],
) -> SafeError | None:
    candidate = recovery.site_skill_candidate
    assert candidate is not None
    evidence = next(
        (
            item
            for item in recovery.discovery
            if (item.tool_id, item.tool_version, item.source_url)
            == candidate.discovery_key
        ),
        None,
    )
    if evidence is None or evidence.coverage != DiscoveryCoverage.COMPLETE.value:
        return SafeError(
            "runtime.discovery_coverage_incomplete",
            "Discovery coverage was incomplete.",
        )
    policy = compile_access_policy(
        Request(request.site_skill.scope, None, False, request.site_skill.budgets)
    )
    expected = {
        canonicalize_url(candidate_url)
        for candidate_url in evidence.candidates
        if candidate_url != evidence.source_url
        and policy.decide_url(candidate_url).allowed
        and (urlsplit(candidate_url).hostname or "invalid")
        == request.site_skill.site_key
    }
    discovered = {
        canonicalize_url(candidate_url)
        for item in recovery.discovery
        if item.outcome == "succeeded"
        for candidate_url in item.candidates
        if candidate_url != item.source_url
        and policy.decide_url(candidate_url).allowed
        and (urlsplit(candidate_url).hostname or "invalid")
        == request.site_skill.site_key
    }
    if discovered - expected:
        return SafeError(
            "runtime.recovery_coverage_incomplete",
            "Recovery state was not replayable by the selected recipe.",
        )
    acquisition_tool_ids = {
        manifest.tool_id
        for manifest in registry.query(category=ToolCategory.ACQUISITION)
    }
    terminal = {
        canonicalize_url(attempt.requested_url)
        for attempt in recovery.attempts
        if attempt.tool_id in acquisition_tool_ids
        and attempt.outcome in {"succeeded", "failed"}
    }
    if expected - terminal:
        return SafeError(
            "runtime.recovery_coverage_incomplete",
            "Recovery did not process every discovered candidate.",
        )
    replayable_pages = {canonicalize_url(evidence.source_url)} | {
        canonicalize_url(attempt.final_url)
        for attempt in recovery.attempts
        if attempt.tool_id in acquisition_tool_ids
        and attempt.outcome == "succeeded"
        and attempt.final_url is not None
        and canonicalize_url(attempt.requested_url) in expected
    }
    current_urls = {page.canonical_url for page in current_pages}
    if current_urls - replayable_pages:
        return SafeError(
            "runtime.recovery_coverage_incomplete",
            "Recovery state was not replayable by the selected recipe.",
        )
    return None


def _recovery_failed_by_url(
    attempts: tuple[Attempt, ...], registry: Registry
) -> dict[str, tuple[Attempt, ...]]:
    acquisition_tool_ids = {
        manifest.tool_id
        for manifest in registry.query(category=ToolCategory.ACQUISITION)
    }
    succeeded = {
        attempt.requested_url
        for attempt in attempts
        if attempt.tool_id in acquisition_tool_ids and attempt.outcome == "succeeded"
    }
    failed: dict[str, list[Attempt]] = {}
    for attempt in attempts:
        if (
            attempt.tool_id in acquisition_tool_ids
            and attempt.outcome == "failed"
            and attempt.error is not None
            and attempt.requested_url not in succeeded
        ):
            failed.setdefault(attempt.requested_url, []).append(attempt)
    return {url: tuple(items) for url, items in failed.items()}


def _terminal_stop_reason(result: Result) -> str:
    codes = {error.code for error in result.errors} | {
        attempt.error.code for attempt in result.attempts if attempt.error is not None
    }
    if "runtime.cancelled" in codes:
        return "cancelled"
    if codes.intersection(_BUDGET_CODES):
        return "budget_exhausted"
    if result.status is ResultStatus.REJECTED or any(
        _is_rejection_code(code) for code in codes
    ):
        return "rejected"
    return "acquisition_failed"


def _is_rejection_code(code: str) -> bool:
    return code in _REJECTION_CODES or code.startswith(
        ("scope.", "robots.", "security.", "policy.")
    )


def _state_pages(
    sources: tuple[ArtifactEvidence, ...], site_key: str
) -> tuple[SiteStatePage, ...]:
    selected: dict[str, SiteStatePage] = {}
    for source in sources:
        if (urlsplit(source.source_url).hostname or "invalid") != site_key:
            continue
        selected.setdefault(
            source.source_url,
            SiteStatePage(
                source.source_url,
                source.observation_id,
                source.artifact_id,
                f"sha256:{source.sha256}",
            ),
        )
    return tuple(selected[url] for url in sorted(selected))


def _page_evidence(page: SiteStatePage) -> ChangeEvidence:
    return ChangeEvidence(page.artifact_id, page.content_digest)


def _skill_evidence(skill: SiteSkill) -> SiteSkillEvidence:
    return SiteSkillEvidence(str(skill.version), skill.digest.removeprefix("sha256:"))


def _candidate_evidence(skill: SiteSkill) -> SiteSkillCandidateEvidence:
    discovery = skill.discovery
    assert discovery is not None
    return SiteSkillCandidateEvidence.from_validated_mapping(
        site_skill_to_mapping(skill),
        digest=skill.digest,
        discovery_key=(
            discovery.tool.tool_id,
            discovery.tool.version,
            discovery.source_url,
        ),
    )


def _preferred_tool_update(
    active: SiteSkill,
    result: Result,
    registry: Registry,
    *,
    generated_at: str,
) -> SiteSkillUpdate | None:
    succeeded = next(
        (
            attempt
            for attempt in result.attempts
            if attempt.outcome == "succeeded" and attempt.final_url is not None
        ),
        None,
    )
    if succeeded is None or succeeded.tool_id == active.tool.tool_id:
        return None
    manifest = next(
        (
            item
            for item in registry.query(category=ToolCategory.ACQUISITION)
            if item.tool_id == succeeded.tool_id
            and item.version == succeeded.tool_version
        ),
        None,
    )
    if manifest is None:
        return None
    candidate = create_candidate(
        site_key=active.site_key,
        version=active.version + 1,
        previous=active,
        scope=active.scope,
        budgets=active.budgets,
        tool=replace(
            active.tool,
            tool_id=manifest.tool_id,
            version=manifest.version,
            category=manifest.category,
            capabilities=manifest.capabilities,
            recipe_id=None,
        ),
        success_checks=active.success_checks,
        verified_at=generated_at,
        discovery=active.discovery,
    ).skill
    return SiteSkillUpdate(
        "preferred_tool_changed",
        _skill_evidence(active),
        _candidate_evidence(candidate),
    )


class _AcquisitionOnlyRegistry:
    """Delegate target work while normalizing Acquisition/Transform cancellation."""

    def __init__(self, registry: Registry) -> None:
        self._registry = registry

    def query(self, **kwargs):
        return self._registry.query(**kwargs)

    def eligibility(self, requirements):
        return self._registry.eligibility(requirements)

    def eligible(self, requirements):
        return self._registry.eligible(requirements)

    def invoke(self, tool_id, tool_input):
        try:
            return self._registry.invoke(tool_id, tool_input)
        except CancelledError:
            category = (
                ToolCategory.TRANSFORM
                if isinstance(tool_input, TransformInput)
                else ToolCategory.ACQUISITION
            )
            manifest = next(
                (
                    item
                    for item in self._registry.query(category=category)
                    if item.tool_id == tool_id
                ),
                None,
            )
            if manifest is None:
                raise
            if category is ToolCategory.TRANSFORM:
                return TransformFailure(
                    manifest.tool_id,
                    manifest.version,
                    "runtime.cancelled",
                )
            return AcquisitionFailure(
                manifest.tool_id,
                manifest.version,
                "runtime.cancelled",
            )


class _RecoveryRegistry:  # pylint: disable=too-many-instance-attributes
    """Carry pre-recovery source attempts into deterministic Phase 18B recovery."""

    def __init__(
        self,
        registry: Registry,
        attempts: tuple[Attempt, ...],
        source_url: str,
        max_attempts: int,
    ) -> None:
        self._registry = registry
        self._source_url = canonicalize_url(source_url)
        used = sum(
            attempt.outcome != "skipped"
            and canonicalize_url(attempt.requested_url) == self._source_url
            for attempt in attempts
        )
        self._remaining_source_attempts = max(0, max_attempts - used)
        self._source_attempts = 0
        self._active_target_is_source = False
        self._blocked_invocations: list[tuple[str, str]] = []
        self.attempt_budget_exhausted = False
        self.rejection_code: str | None = None

    def query(self, **kwargs):
        if (
            self.rejection_code is not None
            and kwargs.get("category") is ToolCategory.ACQUISITION
        ):
            return ()
        return self._registry.query(**kwargs)

    def eligibility(self, requirements):
        return self._registry.eligibility(requirements)

    def eligible(self, requirements):
        manifests = self._registry.eligible(requirements)
        if (
            requirements.category is ToolCategory.TRANSFORM
            and self._active_target_is_source
            and self._source_attempts >= self._remaining_source_attempts
        ):
            self.attempt_budget_exhausted = True
            return ()
        if requirements.category is not ToolCategory.DISCOVERY:
            return manifests
        remaining = max(0, self._remaining_source_attempts - self._source_attempts)
        if len(manifests) > remaining:
            self.attempt_budget_exhausted = True
        return manifests[:remaining]

    def invoke(self, tool_id, tool_input):
        if self.rejection_code is not None and isinstance(tool_input, AcquisitionInput):
            raise ToolRegistryError(self.rejection_code)
        if isinstance(tool_input, AcquisitionInput):
            target_url = canonicalize_url(tool_input.target_url)
            self._active_target_is_source = target_url == self._source_url
        elif isinstance(tool_input, DiscoveryInput):
            target_url = canonicalize_url(tool_input.source_url)
        elif isinstance(tool_input, TransformInput) and self._active_target_is_source:
            target_url = self._source_url
        else:
            target_url = None
        if target_url == self._source_url:
            if self._source_attempts >= self._remaining_source_attempts:
                self.attempt_budget_exhausted = True
                self._blocked_invocations.append((tool_id, self._source_url))
                raise ToolRegistryError("eligibility.attempt_budget_exhausted")
            self._source_attempts += 1
        try:
            result = self._registry.invoke(tool_id, tool_input)
        except AcquisitionOutputRejected as exc:
            self._record_rejection(tool_input, exc.failure.code)
            raise
        if isinstance(result, AcquisitionFailure):
            self._record_rejection(tool_input, result.code)
        return result

    def audited_attempts(self, attempts: tuple[Attempt, ...]) -> tuple[Attempt, ...]:
        blocked = list(self._blocked_invocations)
        audited: list[Attempt] = []
        for attempt in attempts:
            key = (attempt.tool_id, canonicalize_url(attempt.requested_url))
            if (
                key in blocked
                and attempt.error is not None
                and attempt.error.code == "eligibility.attempt_budget_exhausted"
            ):
                blocked.remove(key)
                audited.append(
                    replace(
                        attempt,
                        outcome="skipped",
                        final_url=None,
                        http_status=None,
                        requests=0,
                        bytes_received=0,
                        runtime_ms=0,
                    )
                )
                continue
            audited.append(attempt)
        return tuple(audited)

    def _record_rejection(self, tool_input, code: str) -> None:
        if (
            isinstance(tool_input, AcquisitionInput)
            and _is_rejection_code(code)
            and self.rejection_code is None
        ):
            self.rejection_code = code


__all__ = [
    "compare_site_states",
    "run_site_refresh",
    "site_refresh_result_from_mapping",
]
