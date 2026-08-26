"""One governed single-target workflow connecting existing public modules."""

# pylint: disable=duplicate-code,too-many-locals,too-many-return-statements
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from web_listening.artifact.model import ArtifactRole, ArtifactStoreError
from web_listening.artifact.observation import ObservationProposal
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Request
from web_listening.request.validate import validate_request
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
from web_listening.site_skill.model import SiteSkillError
from web_listening.site_skill.resolve import resolve_site_skill
from web_listening.tool_registry.manifest import ToolRegistryError
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
from web_listening.tool_registry.registry import Registry

_MAX_DISCOVERY_CANDIDATES = 100


@dataclass(frozen=True, slots=True)
class DiscoveredCandidateResult:
    """One deterministically paired candidate, provenance URL, and Result."""

    candidate_url: str
    discovered_from: str
    result: Result


def run_single_target(  # pylint: disable=too-many-arguments
    request: Request,
    registry: Registry,
    artifact_store: ArtifactStore,
    *,
    run_id: str,
    clock: Callable[[], str],
    target_url: str | None = None,
) -> Result:
    """Validate, resolve, invoke once, commit once, and assemble one Result."""
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
    if not resolution.eligible:
        return _failure_result(
            status=ResultStatus.REJECTED,
            run_id=run_id,
            generated_at=clock(),
            requested_url=requested_url,
            current_url=requested_url,
            code=_ineligible_code(resolution.reasons),
            message="Runtime request was rejected.",
            tool_id=resolution.skill.tool.tool_id,
            tool_version=resolution.skill.tool.version,
            site_skill=site_skill,
        )
    effective_request = resolution.request
    if target_url is None:
        requested_url = effective_request.scope.seeds[0]
    try:
        tool_input = AcquisitionInput(effective_request, requested_url)
    except ToolRegistryError as exc:
        return _failure_result(
            status=ResultStatus.REJECTED,
            run_id=run_id,
            generated_at=clock(),
            requested_url=requested_url,
            current_url=requested_url,
            code=exc.code,
            message="Runtime request was rejected.",
            tool_id=resolution.skill.tool.tool_id,
            tool_version=resolution.skill.tool.version,
            site_skill=site_skill,
        )

    requested_url = tool_input.target_url
    started_at = clock()
    try:
        acquisition = registry.invoke(resolution.skill.tool.tool_id, tool_input)
    except ToolRegistryError as exc:
        finished_at = clock()
        return _acquisition_failure_result(
            run_id=run_id,
            generated_at=finished_at,
            requested_url=requested_url,
            started_at=started_at,
            finished_at=finished_at,
            tool_id=resolution.skill.tool.tool_id,
            tool_version=resolution.skill.tool.version,
            code=exc.code,
            site_skill=site_skill,
        )
    finished_at = clock()
    if isinstance(acquisition, AcquisitionFailure):
        return _acquisition_failure_result(
            run_id=run_id,
            generated_at=finished_at,
            requested_url=requested_url,
            started_at=started_at,
            finished_at=finished_at,
            tool_id=acquisition.tool_id,
            tool_version=acquisition.tool_version,
            code=acquisition.code,
            site_skill=site_skill,
        )
    assert isinstance(acquisition, AcquisitionOutput)
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
    requests = len(redirects) + 1
    attempt = _attempt(
        run_id=run_id,
        outcome="succeeded",
        requested_url=requested_url,
        started_at=started_at,
        finished_at=finished_at,
        tool_id=acquisition.tool_id,
        tool_version=acquisition.tool_version,
        final_url=acquisition.final_url,
        http_status=acquisition.status_code,
        error=None,
        requests=requests,
        bytes_received=len(acquisition.body),
        runtime_ms=acquisition.runtime_ms,
    )
    attempts = (attempt,)
    usage = _usage(attempts)
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
            outcome="failed",
            requested_url=requested_url,
            started_at=started_at,
            finished_at=finished_at,
            tool_id=acquisition.tool_id,
            tool_version=acquisition.tool_version,
            final_url=acquisition.final_url,
            http_status=acquisition.status_code,
            error=error,
            requests=requests,
            bytes_received=len(acquisition.body),
            runtime_ms=acquisition.runtime_ms,
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
            attempts=(attempt,),
        )
    manifest = manifest_from_observations(
        run_id=run_id,
        generated_at=finished_at,
        requested_url=requested_url,
        current_url=acquisition.final_url,
        final_url=acquisition.final_url,
        http_status=acquisition.status_code,
        tool_id=acquisition.tool_id,
        tool_version=acquisition.tool_version,
        redirects=redirects,
        site_skill=site_skill,
        attempts=attempts,
        observations=(observation,),
        usage=usage,
    )
    return Result(
        status=ResultStatus.COMPLETED,
        manifest=manifest,
        site_skill_used=site_skill,
        site_skill_update=None,
        attempts=attempts,
        errors=(),
        usage=usage,
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
    started_at: str,
    finished_at: str,
    tool_id: str,
    tool_version: str,
    code: str,
    site_skill: SiteSkillEvidence,
) -> Result:
    error = SafeError(code, "Acquisition did not complete.")
    attempt = _attempt(
        run_id=run_id,
        outcome="failed",
        requested_url=requested_url,
        started_at=started_at,
        finished_at=finished_at,
        tool_id=tool_id,
        tool_version=tool_version,
        final_url=None,
        http_status=None,
        error=error,
        requests=0,
        bytes_received=0,
        runtime_ms=0,
    )
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
        attempts=(attempt,),
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
) -> Attempt:
    return Attempt(
        order=0,
        attempt_id=run_id,
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


def _usage(attempts: tuple[Attempt, ...]) -> Usage:
    return Usage(
        requests=sum(attempt.requests for attempt in attempts),
        bytes_received=sum(attempt.bytes_received for attempt in attempts),
        runtime_ms=sum(attempt.runtime_ms for attempt in attempts),
        tool_attempts=len(attempts),
    )


def _ineligible_code(reasons: tuple[str, ...]) -> str:
    if len(reasons) == 1 and ":" not in reasons[0]:
        return reasons[0]
    return "runtime.site_skill_ineligible"


__all__ = [
    "DiscoveredCandidateResult",
    "acquire_discovered_candidates",
    "discover_candidates",
    "run_single_target",
]
