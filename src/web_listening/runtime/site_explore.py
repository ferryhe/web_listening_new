"""Deterministic governed orchestration for one bounded site exploration."""

# pylint: disable=broad-exception-caught,duplicate-code,missing-function-docstring
# pylint: disable=too-many-branches,too-many-lines,too-many-locals,too-many-statements

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
from web_listening.request.validate import validate_request
from web_listening.result.attempts import Attempt
from web_listening.result.errors import ResultValidationError, SafeError
from web_listening.result.manifest import ArtifactEvidence, Usage
from web_listening.result.model import Result, ResultStatus
from web_listening.result.site_explore import (
    DiscoveryEvidence,
    SiteExploreResult,
    SiteSkillCandidateEvidence,
)
from web_listening.runtime.workflow import run_single_target
from web_listening.site_skill.model import (
    DiscoveryRecipe,
    SiteSkill,
    SiteSkillError,
    SuccessChecks,
    ToolReference,
)
from web_listening.site_skill.update import create_candidate
from web_listening.site_skill.validate import (
    site_skill_from_mapping,
    site_skill_to_mapping,
)
from web_listening.tool_registry.eligibility import EligibilityRequirements
from web_listening.tool_registry.manifest import ToolCategory, ToolManifest
from web_listening.tool_registry.protocols.acquisition import AcquisitionFailure
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryCoverage,
    DiscoveryFailure,
    DiscoveryInput,
    DiscoveryOutput,
)
from web_listening.tool_registry.registry import Registry

_MAX_CANDIDATES = 2
_SITE_EXPLORE_V1 = "web-listening-site-explore.v1"
_BUDGET_TERMINAL_CODES = frozenset(
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
_SHARED_BUDGET_TERMINAL_CODES = _BUDGET_TERMINAL_CODES - frozenset(
    {"eligibility.attempt_budget_exhausted"}
)


def site_explore_result_from_mapping(value: object) -> SiteExploreResult:
    """Parse a result while delegating candidate semantics to Site Skill authority."""
    value = _migrate_site_explore_v1(value)
    candidate_evidence = None
    if isinstance(value, Mapping):
        candidate_mapping = value.get("site_skill_candidate")
        if candidate_mapping is not None:
            candidate_evidence = _candidate_evidence(
                site_skill_from_mapping(candidate_mapping)
            )
    return SiteExploreResult.from_dict(value, site_skill_candidate=candidate_evidence)


def _migrate_site_explore_v1(value: object) -> object:
    if (
        not isinstance(value, Mapping)
        or value.get("schema_version") != _SITE_EXPLORE_V1
    ):
        return value
    discovery = value.get("discovery")
    if not isinstance(discovery, list) or any(
        not isinstance(item, Mapping) or "coverage" in item for item in discovery
    ):
        return value
    migrated = dict(value)
    migrated["schema_version"] = "web-listening-site-explore.v2"
    migrated["discovery"] = [
        {**dict(item), "coverage": DiscoveryCoverage.UNKNOWN.value}
        for item in discovery
    ]
    return migrated


def run_site_explore(  # pylint: disable=too-many-arguments
    request: Request,
    registry: Registry,
    artifact_store: ArtifactStore,
    *,
    run_id: str,
    clock: Callable[[], str],
) -> SiteExploreResult:
    """Explore one seed under shared Request budgets and return strict evidence."""
    request = validate_request(request)
    generated_at = clock()
    if request.site_skill is not None or len(request.scope.seeds) != 1:
        return _empty_failure(
            request,
            generated_at=generated_at,
            status=ResultStatus.REJECTED,
            code=(
                "runtime.site_explore_requires_no_site_skill"
                if request.site_skill is not None
                else "runtime.site_explore_single_seed_required"
            ),
        )
    seed_url = request.scope.seeds[0]
    site_key = urlsplit(seed_url).hostname or "invalid"
    results: list[Result] = []
    acquisition_registry = _AcquisitionOnlyRegistry(registry)
    seed = run_single_target(
        request,
        acquisition_registry,  # type: ignore[arg-type]
        artifact_store,
        run_id=f"{run_id}-seed",
        clock=clock,
    )
    results.append(seed)
    if _was_cancelled(seed):
        return _result(
            site_key=site_key,
            generated_at=generated_at,
            status=ResultStatus.PARTIAL,
            complete=False,
            candidate=None,
            discovery=(),
            discovery_attempts=(),
            results=results,
            stop_reason="cancelled",
            extra_errors=(),
        )
    if _has_budget_terminal(seed):
        return _result(
            site_key=site_key,
            generated_at=generated_at,
            status=ResultStatus.PARTIAL,
            complete=False,
            candidate=None,
            discovery=(),
            discovery_attempts=(),
            results=results,
            stop_reason="budget_exhausted",
            extra_errors=(
                SafeError("budget.exhausted", "Exploration budget was exhausted."),
            ),
        )
    seed_source = _source_artifact(seed)
    if seed_source is None:
        return _result(
            site_key=site_key,
            generated_at=generated_at,
            status=(
                ResultStatus.REJECTED
                if seed.status is ResultStatus.REJECTED
                else ResultStatus.FAILED
            ),
            complete=False,
            candidate=None,
            discovery=(),
            discovery_attempts=(),
            results=results,
            stop_reason=(
                "rejected"
                if seed.status is ResultStatus.REJECTED
                else "acquisition_failed"
            ),
            extra_errors=(),
        )
    site_key = urlsplit(seed_source.source_url).hostname or "invalid"

    source = artifact_store.read_artifact(seed_source.artifact_id)
    manifests = tuple(
        sorted(
            {
                manifest.tool_id: manifest
                for capability in _discovery_capabilities(seed_source.mime_type)
                for manifest in registry.eligible(
                    EligibilityRequirements(
                        category=ToolCategory.DISCOVERY,
                        capabilities=frozenset({capability}),
                        input_bytes=len(source.content),
                    )
                )
            }.values(),
            key=_manifest_key,
        )
    )
    discovery_evidence: list[DiscoveryEvidence] = []
    discovery_attempts: list[Attempt] = []
    discovery_terminal_errors: list[SafeError] = []
    discovered: dict[str, tuple[str, ToolManifest]] = {}
    budget_exhausted = False
    target_attempt_budget_exhausted = False
    cancelled = False
    discovery_all_processed = True
    for index, manifest in enumerate(manifests):
        if not _discovery_budget_available(
            request.budgets,
            results,
            discovery_attempts,
            seed_source.source_url,
        ):
            discovery_all_processed = False
            if _shared_budget_exhausted(
                request.budgets,
                results,
                discovery_attempts,
            ):
                budget_exhausted = True
            else:
                target_attempt_budget_exhausted = True
            break
        started_at = clock()
        invocation_started_ns = monotonic_ns()
        error: SafeError | None = None
        try:
            output = registry.invoke(
                manifest.tool_id,
                DiscoveryInput(
                    request.scope,
                    seed_source.source_url,
                    source.content,
                    seed_source.mime_type,
                ),
            )
        except CancelledError:
            error = SafeError("runtime.cancelled", "Site exploration was cancelled.")
            output = None
            cancelled = True
        except Exception as exc:  # Registry contains the safe boundary.
            code = getattr(exc, "code", "registry.tool_exception")
            error = SafeError(code, "Discovery did not complete.")
            output = None
        finished_at = clock()
        runtime_ms = max(0, (monotonic_ns() - invocation_started_ns) // 1_000_000)
        if isinstance(output, DiscoveryFailure):
            error = SafeError(output.code, "Discovery did not complete.")
        if error is not None:
            discovery_evidence.append(
                DiscoveryEvidence(
                    manifest.tool_id,
                    manifest.version,
                    seed_source.source_url,
                    "failed",
                    (),
                    (),
                    DiscoveryCoverage.UNKNOWN.value,
                    error,
                )
            )
            discovery_attempts.append(
                _discovery_attempt(
                    run_id=run_id,
                    index=index,
                    manifest=manifest,
                    source_url=seed_source.source_url,
                    outcome="failed",
                    error=error,
                    started_at=started_at,
                    finished_at=finished_at,
                    runtime_ms=runtime_ms,
                )
            )
            if cancelled:
                discovery_all_processed = False
                break
            if error.code in _BUDGET_TERMINAL_CODES:
                discovery_all_processed = False
                if error.code in _SHARED_BUDGET_TERMINAL_CODES:
                    budget_exhausted = True
                else:
                    target_attempt_budget_exhausted = True
                break
            if _shared_budget_exhausted(request.budgets, results, discovery_attempts):
                budget_exhausted = True
                discovery_all_processed = False
                break
            continue
        assert isinstance(output, DiscoveryOutput)
        assert output.discovered_from is not None
        assert isinstance(output.coverage, DiscoveryCoverage)
        pairs = tuple(sorted(set(zip(output.candidates, output.discovered_from))))
        representable_pairs: list[tuple[str, str]] = []
        representation_error: SafeError | None = None
        for candidate_url, discovered_from in pairs:
            try:
                DiscoveryEvidence(
                    output.tool_id,
                    output.tool_version,
                    seed_source.source_url,
                    "succeeded",
                    (candidate_url,),
                    (discovered_from,),
                    output.coverage.value,
                    None,
                )
            except ResultValidationError:
                representation_error = SafeError(
                    "runtime.discovery_url_unrepresentable",
                    "Discovery candidate could not be represented safely.",
                )
                continue
            representable_pairs.append((candidate_url, discovered_from))
        pairs = tuple(representable_pairs)
        if not pairs:
            assert representation_error is not None
            discovery_evidence.append(
                DiscoveryEvidence(
                    output.tool_id,
                    output.tool_version,
                    seed_source.source_url,
                    "failed",
                    (),
                    (),
                    DiscoveryCoverage.UNKNOWN.value,
                    representation_error,
                )
            )
            discovery_attempts.append(
                _discovery_attempt(
                    run_id=run_id,
                    index=index,
                    manifest=manifest,
                    source_url=seed_source.source_url,
                    outcome="failed",
                    error=representation_error,
                    started_at=started_at,
                    finished_at=finished_at,
                    runtime_ms=runtime_ms,
                )
            )
            if _shared_budget_exhausted(request.budgets, results, discovery_attempts):
                budget_exhausted = True
                discovery_all_processed = False
                break
            continue
        if representation_error is not None:
            discovery_terminal_errors.append(representation_error)
        candidates = tuple(candidate_url for candidate_url, _source in pairs)
        sources = tuple(source_url for _candidate, source_url in pairs)
        discovery_evidence.append(
            DiscoveryEvidence(
                output.tool_id,
                output.tool_version,
                seed_source.source_url,
                "succeeded",
                candidates,
                sources,
                output.coverage.value,
                None,
            )
        )
        discovery_attempts.append(
            _discovery_attempt(
                run_id=run_id,
                index=index,
                manifest=manifest,
                source_url=seed_source.source_url,
                outcome="succeeded",
                error=None,
                started_at=started_at,
                finished_at=finished_at,
                runtime_ms=runtime_ms,
            )
        )
        if _shared_budget_exhausted(request.budgets, results, discovery_attempts):
            budget_exhausted = True
            discovery_all_processed = False
            break
        for candidate_url, discovered_from in pairs:
            if candidate_url == seed_source.source_url:
                continue
            current = discovered.get(candidate_url)
            proposed = (discovered_from, manifest)
            if current is None or _candidate_source_key(
                proposed
            ) < _candidate_source_key(current):
                discovered[candidate_url] = proposed

    discovery_evidence.sort(
        key=lambda item: (item.tool_id, item.tool_version, item.source_url)
    )
    discovery_failed = not manifests or any(
        item.outcome == "failed" for item in discovery_evidence
    )
    available_candidates = tuple(sorted(discovered.items()))
    extra_errors = list(discovery_terminal_errors)
    if budget_exhausted or target_attempt_budget_exhausted:
        extra_errors.append(
            SafeError("budget.exhausted", "Exploration budget was exhausted.")
        )
    if not manifests:
        extra_errors.append(
            SafeError("runtime.discovery_unavailable", "Discovery did not complete.")
        )
    if (
        not available_candidates
        and not budget_exhausted
        and not target_attempt_budget_exhausted
        and not cancelled
    ):
        extra_errors.append(
            SafeError("discovery.no_candidates", "Discovery did not find candidates.")
        )

    acquired_all = not budget_exhausted and not cancelled
    processed_candidates = 0
    acquired_candidates = 0
    selected_candidates: list[tuple[str, tuple[str, ToolManifest]]] = []
    for index, candidate in enumerate(available_candidates):
        if acquired_candidates >= _MAX_CANDIDATES:
            break
        if budget_exhausted or cancelled:
            break
        candidate_url, _source_recipe = candidate
        selected_candidates.append(candidate)
        parsed_candidate = urlsplit(candidate_url)
        candidate_origin = f"{parsed_candidate.scheme}://{parsed_candidate.netloc}"
        if (
            parsed_candidate.hostname or "invalid"
        ) != site_key and candidate_origin in request.scope.allowed_origins:
            extra_errors.append(
                SafeError(
                    "runtime.site_identity_mismatch",
                    "Candidate belongs to a different site identity.",
                )
            )
            processed_candidates += 1
            continue
        remaining = _remaining_budgets(
            request.budgets,
            results,
            discovery_attempts,
            candidate_url,
        )
        if remaining is None:
            acquired_all = False
            extra_errors.append(
                SafeError("budget.exhausted", "Exploration budget was exhausted.")
            )
            if _shared_budget_exhausted(
                request.budgets,
                results,
                discovery_attempts,
            ):
                budget_exhausted = True
                break
            target_attempt_budget_exhausted = True
            processed_candidates += 1
            continue
        candidate_request = Request(
            request.scope,
            None,
            request.explore_all_tools,
            remaining,
        )
        candidate_result = run_single_target(
            candidate_request,
            acquisition_registry,  # type: ignore[arg-type]
            artifact_store,
            run_id=f"{run_id}-candidate-{index + 1}",
            clock=clock,
            target_url=candidate_url,
        )
        results.append(candidate_result)
        processed_candidates += 1
        if _entered_acquisition(candidate_result, candidate_url):
            acquired_candidates += 1
        if _has_budget_terminal(candidate_result):
            acquired_all = False
            extra_errors.append(
                SafeError("budget.exhausted", "Exploration budget was exhausted.")
            )
            if _has_shared_budget_terminal(candidate_result):
                budget_exhausted = True
                break
            target_attempt_budget_exhausted = True
        if _was_cancelled(candidate_result):
            cancelled = True
            acquired_all = False
            break

    selected = tuple(selected_candidates)
    candidate_results = results[1:]
    successful_candidate_results: list[Result] = []
    for result in candidate_results:
        candidate_source = _source_artifact(result)
        if candidate_source is None:
            continue
        if (urlsplit(candidate_source.source_url).hostname or "invalid") != site_key:
            extra_errors.append(_site_identity_error(candidate_source))
            continue
        successful_candidate_results.append(result)
    quality_verified = bool(successful_candidate_results) and _passes_success_checks(
        [seed, *successful_candidate_results], artifact_store
    )
    complete = (
        not discovery_failed
        and discovery_all_processed
        and bool(selected)
        and acquired_all
        and processed_candidates == len(selected)
    )
    candidate: SiteSkill | None = None
    if complete and quality_verified:
        try:
            candidate = _candidate(
                request,
                site_key=site_key,
                verified_at=generated_at,
                registry=registry,
                selected=selected,
                discovery=tuple(discovery_evidence),
                seed=seed,
                results=successful_candidate_results,
            )
        except SiteSkillError as exc:
            extra_errors.append(
                SafeError(exc.code, "Site Skill candidate was not created.")
            )
    elif complete and successful_candidate_results and not quality_verified:
        extra_errors.append(
            SafeError(
                "runtime.quality_minimum_words",
                "Acquisition quality checks failed.",
            )
        )

    if candidate is not None:
        status = ResultStatus.COMPLETED
        stop_reason = "source_exhausted"
    elif cancelled:
        status = ResultStatus.PARTIAL
        stop_reason = "cancelled"
    elif budget_exhausted or target_attempt_budget_exhausted:
        status = ResultStatus.PARTIAL
        stop_reason = "budget_exhausted"
    elif discovery_failed or not selected:
        status = ResultStatus.PARTIAL
        stop_reason = "discovery_failed"
    else:
        status = ResultStatus.PARTIAL
        stop_reason = "acquisition_failed"
    return _result(
        site_key=site_key,
        generated_at=generated_at,
        status=status,
        complete=complete,
        candidate=candidate,
        discovery=tuple(discovery_evidence),
        discovery_attempts=tuple(discovery_attempts),
        results=results,
        stop_reason=stop_reason,
        extra_errors=tuple(extra_errors),
    )


def _candidate(  # pylint: disable=too-many-arguments
    request: Request,
    *,
    site_key: str,
    verified_at: str,
    registry: Registry,
    selected: tuple[tuple[str, tuple[str, ToolManifest]], ...],
    discovery: tuple[DiscoveryEvidence, ...],
    seed: Result,
    results: list[Result],
) -> SiteSkill:
    seed_tool_keys = {
        (attempt.tool_id, attempt.tool_version)
        for attempt in seed.attempts
        if attempt.outcome == "succeeded" and attempt.final_url is not None
    }
    selected_by_url = dict(selected)
    common_proofs: list[tuple[tuple[str, str], str, str, ToolManifest, Result]] = []
    for result in results:
        for attempt in result.attempts:
            tool_key = (attempt.tool_id, attempt.tool_version)
            provenance = selected_by_url.get(attempt.requested_url)
            if (
                attempt.outcome != "succeeded"
                or attempt.final_url is None
                or tool_key not in seed_tool_keys
                or provenance is None
            ):
                continue
            discovery_source, discovery_manifest = provenance
            common_proofs.append(
                (
                    tool_key,
                    attempt.requested_url,
                    discovery_source,
                    discovery_manifest,
                    result,
                )
            )
    if not common_proofs:
        raise SiteSkillError("runtime.site_skill_tool_unverified")
    successful_discovery_keys = {
        (item.tool_id, item.tool_version, item.source_url)
        for item in discovery
        if item.outcome == "succeeded"
    }
    replayable_proofs = [
        proof
        for proof in common_proofs
        if (
            proof[3].tool_id,
            proof[3].version,
            proof[2],
        )
        in successful_discovery_keys
    ]
    if not replayable_proofs:
        raise SiteSkillError("runtime.site_skill_discovery_unverified")
    chosen = min(
        replayable_proofs,
        key=lambda proof: (
            proof[0],
            proof[1],
            _manifest_key(proof[3]),
            proof[2],
        ),
    )
    acquisition_tool_key, _candidate_url, discovery_source, discovery_manifest, _ = (
        chosen
    )
    acquisition_manifest = next(
        (
            manifest
            for manifest in registry.query(category=ToolCategory.ACQUISITION)
            if (manifest.tool_id, manifest.version) == acquisition_tool_key
        ),
        None,
    )
    if acquisition_manifest is None:
        raise SiteSkillError("runtime.site_skill_tool_unverified")
    seed_source = _source_artifact(seed)
    if seed_source is None:
        raise SiteSkillError("runtime.site_skill_tool_unverified")
    mime_types = tuple(
        sorted(
            {
                seed_source.mime_type,
                *(
                    source.mime_type
                    for tool_key, _, _, _, result in replayable_proofs
                    if tool_key == acquisition_tool_key
                    and (source := _source_artifact(result)) is not None
                ),
            }
        )
    )
    return create_candidate(
        site_key=site_key,
        version=1,
        previous=None,
        scope=request.scope,
        budgets=request.budgets,
        tool=ToolReference(
            acquisition_manifest.tool_id,
            acquisition_manifest.version,
            acquisition_manifest.category,
            acquisition_manifest.capabilities,
        ),
        success_checks=SuccessChecks(mime_types, 1),
        verified_at=verified_at,
        discovery=DiscoveryRecipe(
            ToolReference(
                discovery_manifest.tool_id,
                discovery_manifest.version,
                discovery_manifest.category,
                discovery_manifest.capabilities,
            ),
            discovery_source,
        ),
    ).skill


def _remaining_budgets(
    limits: Budgets,
    results: list[Result],
    discovery_attempts: list[Attempt],
    target_url: str,
) -> Budgets | None:
    usage = _usage_from_results(results, discovery_attempts)
    requests = limits.max_requests - usage.requests
    bytes_remaining = limits.max_bytes - usage.bytes_received
    runtime_seconds = (limits.max_runtime_seconds * 1_000 - usage.runtime_ms) // 1_000
    attempts = limits.max_tool_attempts_per_target - _tool_attempts_for_target(
        results,
        discovery_attempts,
        target_url,
    )
    if requests <= 0 or bytes_remaining <= 0 or runtime_seconds <= 0 or attempts <= 0:
        return None
    return Budgets(
        requests,
        bytes_remaining,
        runtime_seconds,
        attempts,
    )


def _discovery_budget_available(
    limits: Budgets,
    results: list[Result],
    discovery_attempts: list[Attempt],
    source_url: str,
) -> bool:
    usage = _usage_from_results(results, discovery_attempts)
    return (
        usage.requests < limits.max_requests
        and usage.bytes_received < limits.max_bytes
        and usage.runtime_ms < limits.max_runtime_seconds * 1_000
        and _tool_attempts_for_target(results, discovery_attempts, source_url)
        < limits.max_tool_attempts_per_target
    )


def _shared_budget_exhausted(
    limits: Budgets,
    results: list[Result],
    discovery_attempts: list[Attempt],
) -> bool:
    usage = _usage_from_results(results, discovery_attempts)
    return (
        usage.requests >= limits.max_requests
        or usage.bytes_received >= limits.max_bytes
        or usage.runtime_ms >= limits.max_runtime_seconds * 1_000
    )


def _discovery_attempt(  # pylint: disable=too-many-arguments
    *,
    run_id: str,
    index: int,
    manifest: ToolManifest,
    source_url: str,
    outcome: str,
    error: SafeError | None,
    started_at: str,
    finished_at: str,
    runtime_ms: int,
) -> Attempt:
    suffix = f"-discovery-{index + 1}"
    return Attempt(
        order=0,
        attempt_id=f"{run_id[: 128 - len(suffix)]}{suffix}",
        outcome=outcome,
        tool_id=manifest.tool_id,
        tool_version=manifest.version,
        started_at=started_at,
        finished_at=finished_at,
        requested_url=source_url,
        final_url=None,
        http_status=None,
        error=error,
        requests=0,
        bytes_received=0,
        runtime_ms=runtime_ms,
    )


def _result(  # pylint: disable=too-many-arguments
    *,
    site_key: str,
    generated_at: str,
    status: ResultStatus,
    complete: bool,
    candidate: SiteSkill | None,
    discovery: tuple[DiscoveryEvidence, ...],
    discovery_attempts: tuple[Attempt, ...],
    results: list[Result],
    stop_reason: str,
    extra_errors: tuple[SafeError, ...],
) -> SiteExploreResult:
    attempts = _ordered_attempts(results, discovery_attempts)
    usage = Usage(
        sum(attempt.requests for attempt in attempts),
        sum(attempt.bytes_received for attempt in attempts),
        sum(attempt.runtime_ms for attempt in attempts),
        sum(attempt.outcome != "skipped" for attempt in attempts),
    )
    pages = _state_pages(results, site_key)
    errors = (
        tuple(error for result in results for error in result.errors)
        + tuple(item.error for item in discovery if item.error is not None)
        + extra_errors
    )
    candidate_evidence = None if candidate is None else _candidate_evidence(candidate)
    return SiteExploreResult(
        status=status,
        exploration_complete=complete,
        site_state=SiteState(
            site_key,
            generated_at,
            None if candidate is None else candidate.digest,
            complete,
            pages,
        ),
        site_skill_candidate=candidate_evidence,
        site_skill_used=None,
        discovery=discovery,
        attempts=attempts,
        usage=usage,
        stop_reason=stop_reason,
        errors=errors,
    )


def _empty_failure(
    request: Request,
    *,
    generated_at: str,
    status: ResultStatus,
    code: str,
) -> SiteExploreResult:
    site_key = urlsplit(request.scope.seeds[0]).hostname or "invalid"
    error = SafeError(code, "Site exploration request was rejected.")
    return SiteExploreResult(
        status=status,
        exploration_complete=False,
        site_state=SiteState(site_key, generated_at, None, False, ()),
        site_skill_candidate=None,
        site_skill_used=None,
        discovery=(),
        attempts=(),
        usage=Usage(0, 0, 0, 0),
        stop_reason="rejected",
        errors=(error,),
    )


def _candidate_evidence(candidate: SiteSkill) -> SiteSkillCandidateEvidence:
    discovery = candidate.discovery
    if discovery is None:  # Candidate creation requires a replayable recipe.
        raise SiteSkillError("site_skill.discovery_required")
    return SiteSkillCandidateEvidence.from_validated_mapping(
        site_skill_to_mapping(candidate),
        digest=candidate.digest,
        discovery_key=(
            discovery.tool.tool_id,
            discovery.tool.version,
            discovery.source_url,
        ),
    )


def _ordered_attempts(
    results: list[Result], discovery_attempts: tuple[Attempt, ...]
) -> tuple[Attempt, ...]:
    flattened = (
        results[0].attempts
        + discovery_attempts
        + tuple(attempt for result in results[1:] for attempt in result.attempts)
    )
    return tuple(
        replace(attempt, order=index) for index, attempt in enumerate(flattened)
    )


def _usage_from_results(
    results: list[Result], discovery_attempts: list[Attempt]
) -> Usage:
    attempts = tuple(
        attempt for result in results for attempt in result.attempts
    ) + tuple(discovery_attempts)
    return Usage(
        sum(attempt.requests for attempt in attempts),
        sum(attempt.bytes_received for attempt in attempts),
        sum(attempt.runtime_ms for attempt in attempts),
        sum(attempt.outcome != "skipped" for attempt in attempts),
    )


def _tool_attempts_for_target(
    results: list[Result],
    discovery_attempts: list[Attempt],
    target_url: str,
) -> int:
    canonical_target = canonicalize_url(target_url)
    attempts = tuple(
        attempt for result in results for attempt in result.attempts
    ) + tuple(discovery_attempts)
    return sum(
        attempt.outcome != "skipped"
        and canonicalize_url(attempt.requested_url) == canonical_target
        for attempt in attempts
    )


def _source_artifact(result: Result) -> ArtifactEvidence | None:
    return next(
        (artifact for artifact in result.artifacts if artifact.role == "source"), None
    )


def _was_cancelled(result: Result) -> bool:
    return any(error.code == "runtime.cancelled" for error in result.errors)


def _has_budget_terminal(result: Result) -> bool:
    return any(error.code in _BUDGET_TERMINAL_CODES for error in result.errors)


def _has_shared_budget_terminal(result: Result) -> bool:
    return any(error.code in _SHARED_BUDGET_TERMINAL_CODES for error in result.errors)


def _entered_acquisition(result: Result, candidate_url: str) -> bool:
    return any(
        attempt.requested_url == candidate_url and attempt.outcome != "skipped"
        for attempt in result.attempts
    )


def _site_identity_error(source: ArtifactEvidence) -> SafeError:
    return SafeError(
        "runtime.site_identity_mismatch",
        "Candidate final URL belongs to a different site identity.",
        (
            ("artifact_id", source.artifact_id),
            ("content_digest", f"sha256:{source.sha256}"),
            ("final_url", source.source_url),
            ("observation_id", source.observation_id),
        ),
    )


def _state_pages(results: list[Result], site_key: str) -> tuple[SiteStatePage, ...]:
    candidates = sorted(
        (
            SiteStatePage(
                source.source_url,
                source.observation_id,
                source.artifact_id,
                f"sha256:{source.sha256}",
            )
            for result in results
            if (source := _source_artifact(result)) is not None
            and (urlsplit(source.source_url).hostname or "invalid") == site_key
        ),
        key=lambda page: (
            page.canonical_url,
            page.observation_id,
            page.artifact_id,
            page.content_digest,
        ),
    )
    selected: dict[str, SiteStatePage] = {}
    for page in candidates:
        selected.setdefault(page.canonical_url, page)
    return tuple(selected[url] for url in sorted(selected))


def _passes_success_checks(
    results: list[Result], artifact_store: ArtifactStore
) -> bool:
    for result in results:
        source = _source_artifact(result)
        if source is None or source.mime_type not in {
            "application/xhtml+xml",
            "text/html",
        }:
            return False
        stored = artifact_store.read_artifact(source.artifact_id)
        if len(stored.content.decode("utf-8", errors="ignore").split()) < 1:
            return False
    return True


def _manifest_key(manifest: ToolManifest) -> tuple[object, ...]:
    return (manifest.tool_id, manifest.version, tuple(sorted(manifest.capabilities)))


def _candidate_source_key(value: tuple[str, ToolManifest]) -> tuple[object, ...]:
    return (_manifest_key(value[1]), value[0])


def _discovery_capabilities(mime_type: str) -> tuple[str, ...]:
    if mime_type in {"application/xhtml+xml", "text/html"}:
        return ("html_links",)
    if mime_type in {"application/atom+xml", "application/rss+xml"}:
        return ("rss",)
    if mime_type in {"application/sitemap+xml", "text/xml", "application/xml"}:
        return ("rss", "sitemap")
    return ()


class _AcquisitionOnlyRegistry:
    """Delegate Registry authority while excluding out-of-scope Transform work."""

    def __init__(self, registry: Registry) -> None:
        self._registry = registry

    def query(self, **kwargs):
        return self._registry.query(**kwargs)

    def eligibility(self, requirements):
        return self._registry.eligibility(requirements)

    def eligible(self, requirements):
        if requirements.category is ToolCategory.TRANSFORM:
            return ()
        return self._registry.eligible(requirements)

    def invoke(self, tool_id, tool_input):
        try:
            return self._registry.invoke(tool_id, tool_input)
        except CancelledError:
            manifest = next(
                (
                    item
                    for item in self._registry.query(category=ToolCategory.ACQUISITION)
                    if item.tool_id == tool_id
                ),
                None,
            )
            if manifest is None:
                raise
            return AcquisitionFailure(
                manifest.tool_id,
                manifest.version,
                "runtime.cancelled",
            )


__all__ = ["run_site_explore"]
