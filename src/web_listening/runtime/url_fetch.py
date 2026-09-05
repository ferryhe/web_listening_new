"""Bounded serial Smart URL Fetch orchestration over existing seams."""

# pylint: disable=too-many-arguments,too-many-locals,too-many-branches
# pylint: disable=too-many-statements,duplicate-code

from __future__ import annotations

import time
from collections.abc import Callable

from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, classify_mime_type
from web_listening.request.url_fetch import UrlFetchRequest
from web_listening.result.errors import SafeError
from web_listening.result.manifest import Usage
from web_listening.result.model import Result, ResultStatus
from web_listening.result.url_fetch import (
    NavigationDiscovery,
    ResolutionKind,
    UrlFetchResult,
)
from web_listening.runtime.workflow import (
    prior_target_attempts,
    run_single_target_bounded,
)
from web_listening.tool_registry.discovery.builtins.html_navigation import (
    HTML_NAVIGATION_MANIFEST,
)
from web_listening.tool_registry.manifest import ToolRegistryError
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryFailure,
    DiscoveryInput,
)
from web_listening.tool_registry.registry import Registry


def run_url_fetch(
    request: UrlFetchRequest,
    registry: Registry,
    artifact_store: ArtifactStore,
    *,
    run_id: str,
    clock: Callable[[], str],
    completed_results: tuple[Result, ...] = (),
    completed_discovery: tuple[NavigationDiscovery, ...] = (),
    checkpoint: Callable[[int, Result], None] | None = None,
    checkpoint_discovery: Callable[[int, NavigationDiscovery], None] | None = None,
    should_cancel: Callable[[], bool] = lambda: False,
) -> UrlFetchResult:
    """Resolve one URL without repeating a durably checkpointed hop."""
    authority = request.compile()
    results = list(completed_results)
    discovery = list(completed_discovery)
    current = (
        request.url
        if not results
        else results[-1].manifest.final_url or results[-1].manifest.current_url
    )
    visited = {
        url
        for item in results
        for url in (
            item.manifest.requested_url,
            item.manifest.final_url or item.manifest.current_url,
        )
    }
    stop_reason = ""
    if results and discovery:
        latest = results[-1]
        latest_source = _source(latest)
        latest_url = latest.manifest.final_url or latest.manifest.current_url
        latest_discovery = discovery[-1]
        if (
            latest_source is not None
            and classify_mime_type(latest_source.mime_type) is ContentType.HTML
            and latest_discovery.source_url == latest_url
        ):
            if (
                latest_discovery.failure_code is not None
                or not latest_discovery.candidates
            ):
                stop_reason = "terminal_html"
            elif len(latest_discovery.candidates) > 1:
                stop_reason = "multiple_navigation_targets"
            else:
                candidate = latest_discovery.candidates[0]
                if candidate in visited:
                    stop_reason = "navigation_loop"
                elif len(results) - 1 >= request.max_navigation_hops:
                    stop_reason = "navigation_hop_limit"
                else:
                    current = candidate
    while True:
        if stop_reason:
            break
        if should_cancel():
            stop_reason = "cancelled"
            break
        if not results or current not in visited:
            used = _usage(results, discovery)
            remaining_runtime_ms = (
                authority.budgets.max_runtime_seconds * 1000 - used.runtime_ms
            )
            remaining = Budgets(
                max(1, authority.budgets.max_requests - used.requests),
                max(1, authority.budgets.max_bytes - used.bytes_received),
                max(1, remaining_runtime_ms // 1000),
                authority.budgets.max_tool_attempts_per_target,
            )
            if (
                used.requests >= authority.budgets.max_requests
                or used.bytes_received >= authority.budgets.max_bytes
                or remaining_runtime_ms < 1000
            ):
                stop_reason = "budget_exhausted"
                break
            with prior_target_attempts(
                tuple(attempt for result in results for attempt in result.attempts)
            ):
                result = run_single_target_bounded(
                    authority,
                    registry,
                    artifact_store,
                    run_id=f"{run_id}-hop-{len(results) + 1}",
                    clock=clock,
                    target_url=current,
                    budget_limits=remaining,
                )
            results.append(result)
            if checkpoint is not None:
                checkpoint(len(results), result)
        result = results[-1]
        source = _source(result)
        if source is None:
            stop_reason = "acquisition_failed"
            break
        current = result.manifest.final_url or result.manifest.current_url
        if classify_mime_type(source.mime_type) is ContentType.FILE:
            stop_reason = "terminal_file"
            break
        if not request.follow_html_navigation:
            stop_reason = "terminal_html"
            break
        stored = artifact_store.read_artifact(source.artifact_id)
        used = _usage(results, discovery)
        remaining_runtime_ms = (
            authority.budgets.max_runtime_seconds * 1000 - used.runtime_ms
        )
        target_tool_attempts = result.usage.tool_attempts + sum(
            item.usage.tool_attempts for item in discovery if item.source_url == current
        )
        if (
            remaining_runtime_ms <= 0
            or target_tool_attempts >= authority.budgets.max_tool_attempts_per_target
        ):
            stop_reason = "budget_exhausted"
            break
        started_ns = time.monotonic_ns()
        try:
            discovered = registry.invoke(
                HTML_NAVIGATION_MANIFEST.tool_id,
                DiscoveryInput(
                    authority.scope, current, stored.content, source.mime_type
                ),
            )
        except ToolRegistryError:
            discovered = DiscoveryFailure(
                HTML_NAVIGATION_MANIFEST.tool_id,
                HTML_NAVIGATION_MANIFEST.version,
                "registry.tool_exception",
            )
        runtime_ms = max(1, (time.monotonic_ns() - started_ns + 999_999) // 1_000_000)
        failure_code = (
            discovered.code if isinstance(discovered, DiscoveryFailure) else None
        )
        evidence = NavigationDiscovery(
            discovered.tool_id,
            discovered.tool_version,
            current,
            () if isinstance(discovered, DiscoveryFailure) else discovered.candidates,
            (
                ()
                if isinstance(discovered, DiscoveryFailure)
                else discovered.discovered_from
            ),
            (
                "complete"
                if isinstance(discovered, DiscoveryFailure)
                else discovered.coverage
            ),
            Usage(0, 0, runtime_ms, 1),
            failure_code,
        )
        if not discovery or discovery[-1] != evidence:
            discovery.append(evidence)
            if checkpoint_discovery is not None:
                checkpoint_discovery(len(discovery), evidence)
        if isinstance(discovered, DiscoveryFailure):
            stop_reason = "terminal_html"
            break
        if len(discovered.candidates) > 1:
            stop_reason = "multiple_navigation_targets"
            break
        target = discovered.candidates[0]
        if target in visited or target == current:
            stop_reason = "navigation_loop"
            break
        if len(results) - 1 >= request.max_navigation_hops:
            stop_reason = "navigation_hop_limit"
            break
        visited.update((result.manifest.requested_url, current))
        current = target
    terminal = results[-1] if results else None
    source = None if terminal is None else _source(terminal)
    content = None if source is None else classify_mime_type(source.mime_type)
    followed = len(results) > 1
    redirected = bool(terminal and terminal.manifest.redirects)
    if content is ContentType.FILE:
        kind = (
            ResolutionKind.HTML_NAVIGATION_FILE
            if followed
            else (
                ResolutionKind.REDIRECT_FILE
                if redirected
                else ResolutionKind.DIRECT_FILE
            )
        )
    elif content is ContentType.HTML:
        kind = (
            ResolutionKind.HTML_NAVIGATION_HTML
            if followed
            else (
                ResolutionKind.REDIRECT_HTML
                if redirected
                else ResolutionKind.DIRECT_HTML
            )
        )
    else:
        kind = ResolutionKind.UNRESOLVED
    aggregate_errors = tuple(error for item in results for error in item.errors)
    if stop_reason == "cancelled":
        aggregate_errors += (
            SafeError("runtime.cancelled", "Runtime execution was cancelled."),
        )
    degraded = aggregate_errors or any(
        item.status is not ResultStatus.COMPLETED for item in results
    )
    status = (
        ResultStatus.PARTIAL
        if source is not None
        and (
            degraded
            or stop_reason in {"cancelled", "budget_exhausted", "navigation_hop_limit"}
        )
        else (terminal.status if terminal else ResultStatus.FAILED)
    )
    return UrlFetchResult(
        status,
        request.url,
        (
            None
            if terminal is None
            else terminal.manifest.final_url or terminal.manifest.current_url
        ),
        content,
        kind,
        source,
        tuple(results[:-1]),
        terminal,
        tuple(discovery),
        _usage(results, discovery),
        stop_reason,
        aggregate_errors,
    )


def _source(result: Result):
    return next(
        (artifact for artifact in result.artifacts if artifact.role == "source"), None
    )


def _usage(results, discovery=()):
    return Usage(
        sum(item.usage.requests for item in results),
        sum(item.usage.bytes_received for item in results),
        sum(item.usage.runtime_ms for item in results)
        + sum(item.usage.runtime_ms for item in discovery),
        sum(item.usage.tool_attempts for item in results)
        + sum(item.usage.tool_attempts for item in discovery),
    )


__all__ = ["run_url_fetch"]
