"""Authorized Phase 18C incremental site-refresh evidence; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring,protected-access
# pylint: disable=too-few-public-methods,too-many-locals

from __future__ import annotations

import ast
import hashlib
import json
import os
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.request.site_refresh import SiteRefreshRequest
from web_listening.runtime.site_explore import run_site_explore
from web_listening.runtime.site_refresh import (
    run_site_refresh,
    site_refresh_result_from_mapping,
)
from web_listening.site_skill.validate import site_skill_from_mapping
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.discovery.builtins.html_links import (
    HTML_LINKS_MANIFEST,
    HtmlLinksDiscoveryTool,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryCoverage,
    DiscoveryInput,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners import in_process as in_process_runner
from web_listening.tool_registry.runners.in_process import (
    PinnedHttpTransport,
    TransportResponse,
)

TARGETS = Path(__file__).with_name("phase_18c_site_targets.json")
SMOKE_CATALOG = Path(__file__).parent / "catalog" / "smoke_site_catalog.json"
SMOKE_SHA256 = "CE378F743C6363F1DC22A25758B958E3ADA695F8996B3F619AFA4CF0CD5D5322"


def _catalog_sha256(content: bytes) -> str:
    canonical = content.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    return hashlib.sha256(canonical).hexdigest().upper()


def _load_snapshot() -> tuple[dict[str, object], dict[str, object]]:
    payload = json.loads(TARGETS.read_bytes())
    target = payload.get("target")
    if not isinstance(target, dict) or target.get("site_key") != "ipcc":
        pytest.fail("Phase 18C must retain exactly the audited IPCC row")
    if payload.get("source_catalog_sha256") != SMOKE_SHA256:
        pytest.fail("Phase 18C smoke catalog digest drifted")
    if _catalog_sha256(SMOKE_CATALOG.read_bytes()) != SMOKE_SHA256:
        pytest.fail("Phase 18C smoke source bytes drifted")
    smoke_rows = json.loads(SMOKE_CATALOG.read_bytes()).get("sites")
    if not isinstance(smoke_rows, list):
        pytest.fail("Phase 18C smoke source catalog is invalid")
    if target != next(item for item in smoke_rows if item.get("site_key") == "ipcc"):
        pytest.fail("Phase 18C target drifted from the audited catalog")
    expected_limits = {
        "max_sites": 1,
        "max_total_requests": 20,
        "max_total_response_bytes": 8 * 1024 * 1024,
        "timeout_seconds": 60,
        "concurrency": 1,
        "retry": 0,
    }
    if payload.get("network_limits") != expected_limits:
        pytest.fail("Phase 18C network limits drifted")
    return payload, target


def _authorized_target() -> tuple[dict[str, object], dict[str, object]]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 18C site-refresh live test is offline by default")
    if not os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip():
        pytest.fail("a non-empty Phase 18C authorized live window is required")
    return _load_snapshot()


class _NetworkBudget:
    def __init__(
        self,
        requests: int,
        response_bytes: int,
        timeout: int,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_requests = requests
        self.max_response_bytes = response_bytes
        self.requests = 0
        self.response_bytes = 0
        self._clock = clock
        self.deadline = clock() + timeout

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline - self._clock())


class _CappedResponse:
    def __init__(self, response: TransportResponse, budget: _NetworkBudget) -> None:
        self.status = response.status
        self.headers = response.headers
        self.peer_ip = response.peer_ip
        self._response = response
        self._budget = budget

    def read(self, max_bytes: int) -> bytes:
        remaining = self._budget.max_response_bytes - self._budget.response_bytes
        if self._budget.remaining_seconds <= 0 or remaining <= 0:
            raise TimeoutError
        try:
            content = self._response.read(min(max_bytes, remaining))
        except in_process_runner._PartialBodyRead as exc:
            self._budget.response_bytes += len(exc.partial)
            raise
        self._budget.response_bytes += len(content)
        return content

    def set_timeout(self, timeout: float) -> None:
        remaining = self._budget.remaining_seconds
        if remaining <= 0:
            raise TimeoutError
        setter = getattr(self._response, "set_timeout", None)
        if callable(setter):
            setter(min(timeout, remaining))

    def close(self) -> None:
        self._response.close()


class _CappedTransport:
    def __init__(self, budget: _NetworkBudget) -> None:
        self._budget = budget
        self._transport = PinnedHttpTransport()

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> _CappedResponse:
        if (
            self._budget.remaining_seconds <= 0
            or self._budget.requests >= self._budget.max_requests
        ):
            raise TimeoutError
        self._budget.requests += 1
        response = self._transport.send(
            url,
            timeout=min(timeout, self._budget.remaining_seconds),
            addresses=addresses,
        )
        return _CappedResponse(response, self._budget)

    def close(self) -> None:
        self._transport.close()


def _request(target: dict[str, object]) -> Request:
    url = str(target["urls"]["monitor"])
    return Request(
        Scope(
            (url,),
            tuple(target["allowed_origins"]),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(20, 8 * 1024 * 1024, 60, 8),
    )


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _url_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _error_code(error) -> str | None:
    return None if error is None else error.code


def _baseline_exploration_packet(result) -> dict[str, object]:
    return {
        "status": getattr(result.status, "value", result.status),
        "exploration_complete": result.exploration_complete,
        "candidate_present": result.site_skill_candidate is not None,
        "discovery": [
            {
                "tool_id": item.tool_id,
                "tool_version": item.tool_version,
                "source_url_sha256": _url_sha256(item.source_url),
                "outcome": item.outcome,
                "coverage": getattr(item.coverage, "value", item.coverage),
                "candidate_count": len(item.candidates),
                "candidate_url_sha256": [
                    _url_sha256(candidate) for candidate in item.candidates
                ],
                "error_code": _error_code(item.error),
            }
            for item in result.discovery
        ],
        "attempts": [
            {
                "order": attempt.order,
                "attempt_id": attempt.attempt_id,
                "outcome": attempt.outcome,
                "tool_id": attempt.tool_id,
                "tool_version": attempt.tool_version,
                "requested_url_sha256": _url_sha256(attempt.requested_url),
                "final_url_sha256": _url_sha256(attempt.final_url),
                "http_status": attempt.http_status,
                "requests": attempt.requests,
                "bytes_received": attempt.bytes_received,
                "runtime_ms": attempt.runtime_ms,
                "error_code": _error_code(attempt.error),
            }
            for attempt in result.attempts
        ],
        "usage": result.usage.to_dict(),
        "stop_reason": result.stop_reason,
        "errors": [_error_code(error) for error in result.errors],
    }


def _assert_current_page_evidence(result) -> None:
    assert result.current_state.pages, "live refresh produced no current page"
    current_changes = (*result.added, *result.changed, *result.unchanged)
    by_url = {change.url: change for change in current_changes}
    assert len(by_url) == len(current_changes)
    assert set(by_url) == {page.canonical_url for page in result.current_state.pages}
    for page in result.current_state.pages:
        current = by_url[page.canonical_url].current
        assert current is not None
        assert current.artifact_id == page.artifact_id
        assert current.digest == page.content_digest


def _current_acquisition_packet(
    result, store: ArtifactStore
) -> list[dict[str, object]]:
    packet: list[dict[str, object]] = []
    for page in result.current_state.pages:
        stored = store.get_observation(page.observation_id)
        attempts = [
            attempt
            for attempt in result.attempts
            if attempt.outcome == "succeeded"
            and attempt.http_status is not None
            and attempt.final_url == page.canonical_url
        ]
        assert attempts
        attempt = attempts[-1]
        assert stored.observation.source_url == page.canonical_url
        assert stored.artifact.artifact_id == page.artifact_id
        assert f"sha256:{stored.artifact.blob_sha256}" == page.content_digest
        assert not stored.lineage
        packet.append(
            {
                "attempt_id": attempt.attempt_id,
                "observation_id": page.observation_id,
                "artifact_id": page.artifact_id,
                "content_digest": page.content_digest,
                "requested_url": attempt.requested_url,
                "final_url": attempt.final_url,
                "redirected": attempt.requested_url != attempt.final_url,
                "http_status": attempt.http_status,
                "mime_type": stored.artifact.mime_type,
                "lineage": {
                    "status": "not_applicable",
                    "reason": "source_artifact",
                    "edges": [],
                },
            }
        )
    return packet


def test_phase_18c_snapshot_is_exact_and_bounded() -> None:
    payload, target = _load_snapshot()

    assert payload["phase"] == "18C"
    assert target["urls"]["monitor"] == "https://www.ipcc.ch/"
    assert target["historical_classification"]["expectation"] == "pass_http"
    assert target["provenance"] == {
        "old_commit": "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5",
        "old_path": "config/smoke_site_catalog.json",
        "old_blob": "e50b2c0d29e1b3c5df6473409c1a33ad4ffee4c4",
        "old_site_key": "ipcc",
    }
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden_token = "WEB_LISTENING_" + "LIVE_URL"
    assert forbidden_token not in source
    assert source.count("run_site_" + "explore(") == 1
    assert source.count("run_site_" + "refresh(") == 1
    assert source.count("@pytest.mark." + "live") == 1
    assert 'os.environ.get("WEB_LISTENING_' + 'RUN_LIVE")' in source
    assert "WEB_LISTENING_" + "LIVE_AUTHORIZED_WINDOW" in source


def test_phase_18c_live_registry_uses_default_discovery_bound() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    live_function = next(
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef)
        and item.name == "test_phase_18c_site_refresh_live"
    )
    discovery_calls = [
        item
        for item in ast.walk(live_function)
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id == "HtmlLinksDiscoveryTool"
    ]

    assert len(discovery_calls) == 1
    assert not discovery_calls[0].args
    assert not discovery_calls[0].keywords
    assert "max_" + "candidates=2" not in source


def test_phase_18c_pre_scope_bound_counterexample_keeps_later_candidate() -> None:
    inside = "https://example.test/inside"
    scope = Scope(
        ("https://example.test/",),
        ("https://example.test",),
        ("/**",),
        (ContentType.HTML,),
    )
    source_body = (
        b"<a href='https://aaa.test/a'>a</a>"
        b"<a href='https://bbb.test/b'>b</a>"
        b"<a href='/inside'>inside</a>"
    )
    tool_input = DiscoveryInput(
        scope,
        source_url="https://example.test/",
        source_body=source_body,
        source_mime_type="text/html",
    )
    prebound = HtmlLinksDiscoveryTool(**{"max_" + "candidates": 2}).discover(tool_input)
    runtime_bounded = HtmlLinksDiscoveryTool().discover(tool_input)

    assert inside not in prebound.candidates
    assert prebound.coverage is DiscoveryCoverage.TRUNCATED
    assert inside in runtime_bounded.candidates
    assert runtime_bounded.coverage is DiscoveryCoverage.COMPLETE


def test_phase_18c_baseline_failure_packet_is_prepared_and_redacted() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    live_function = next(
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef)
        and item.name == "test_phase_18c_site_refresh_live"
    )
    baseline_assignment = next(
        item
        for item in ast.walk(live_function)
        if isinstance(item, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "baseline_evidence"
            for target in item.targets
        )
    )
    candidate_assertion = next(
        item
        for item in ast.walk(live_function)
        if isinstance(item, ast.Assert)
        and "site_skill_candidate" in ast.unparse(item.test)
    )
    error = SimpleNamespace(code="gateway.timeout")
    placeholder = "placeholder-url-detail"
    explored = SimpleNamespace(
        status=SimpleNamespace(value="partial"),
        exploration_complete=False,
        site_skill_candidate=None,
        discovery=(
            SimpleNamespace(
                tool_id="discovery.html_links",
                tool_version="1.0.0",
                source_url=placeholder,
                outcome="succeeded",
                candidates=(placeholder,),
                coverage="complete",
                error=None,
            ),
        ),
        attempts=(
            SimpleNamespace(
                order=0,
                attempt_id="baseline-0",
                outcome="failed",
                tool_id="acquisition.web_http",
                tool_version="1.0.0",
                requested_url=placeholder,
                final_url=None,
                http_status=503,
                requests=1,
                bytes_received=0,
                runtime_ms=1,
                error=error,
            ),
        ),
        usage=SimpleNamespace(
            to_dict=lambda: {
                "tool_attempts": 1,
                "requests": 1,
                "bytes_received": 0,
                "runtime_ms": 1,
            }
        ),
        stop_reason="acquisition_failed",
        errors=(error,),
    )

    packet = _baseline_exploration_packet(explored)
    serialized = json.dumps(packet, sort_keys=True)

    assert baseline_assignment.lineno < candidate_assertion.lineno
    assert isinstance(candidate_assertion.msg, ast.Name)
    assert candidate_assertion.msg.id == "baseline_failure"
    assert set(packet) == {
        "status",
        "exploration_complete",
        "candidate_present",
        "discovery",
        "attempts",
        "usage",
        "stop_reason",
        "errors",
    }
    assert set(packet["attempts"][0]) >= {
        "outcome",
        "requested_url_sha256",
        "final_url_sha256",
        "http_status",
        "error_code",
    }
    assert set(packet["discovery"][0]) >= {
        "outcome",
        "coverage",
        "source_url_sha256",
        "candidate_count",
        "candidate_url_sha256",
        "error_code",
    }
    assert placeholder not in serialized


def test_phase_18c_catalog_hash_is_checkout_line_ending_stable() -> None:
    lf_bytes = SMOKE_CATALOG.read_bytes().replace(b"\r\n", b"\n")
    crlf_bytes = lf_bytes.replace(b"\n", b"\r\n")

    assert _catalog_sha256(lf_bytes) == SMOKE_SHA256
    assert _catalog_sha256(crlf_bytes) == SMOKE_SHA256


def test_phase_18c_live_requires_current_page_change_evidence() -> None:
    source = Path(__file__).read_text(encoding="utf-8")

    assert "_assert_current_page_" + "evidence(result)" in source
    assert "assert result.current_" + "state.pages" in source
    assert "current_" + "changes" in source


def test_phase_18c_zero_current_page_cannot_satisfy_live_contract() -> None:
    empty = SimpleNamespace(
        current_state=SimpleNamespace(pages=()),
        added=(),
        changed=(),
        unchanged=(),
    )

    with pytest.raises(AssertionError, match="no current page"):
        _assert_current_page_evidence(empty)


def test_phase_18c_live_packet_keeps_full_audit_contract() -> None:
    source = Path(__file__).read_text(encoding="utf-8")

    for required in (
        '"baseline": baseline_' + "evidence",
        '"request": refresh_' + "request.to_dict()",
        '"result": result.' + "to_dict()",
        '"redirect_status_mime": current_' + "acquisition_evidence",
        '"lineage"' + ": {",
        '"status": "not_' + 'applicable"',
        '"reason": "source_' + 'artifact"',
    ):
        assert required in source


@pytest.mark.live
def test_phase_18c_site_refresh_live(tmp_path: Path) -> None:
    payload, target = _authorized_target()
    limits = payload["network_limits"]
    network = _NetworkBudget(
        limits["max_total_requests"],
        limits["max_total_response_bytes"],
        limits["timeout_seconds"],
    )
    exploration_request = _request(target)
    acquisition = WebHttpAcquisitionTool(
        lambda: _CappedTransport(network), runtime_deadline=network.deadline
    )
    registry = Registry()
    registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    store = ArtifactStore(tmp_path / "phase-18c-artifacts")

    try:
        explored = run_site_explore(
            exploration_request,
            registry,
            store,
            run_id="phase-18c-ipcc-baseline",
            clock=_now,
        )
        baseline_evidence = _baseline_exploration_packet(explored)
        baseline_failure = json.dumps(baseline_evidence, sort_keys=True)
        assert explored.exploration_complete is True, baseline_failure
        assert explored.site_skill_candidate is not None, baseline_failure
        active_skill = site_skill_from_mapping(explored.site_skill_candidate.to_dict())
        active_digest_before = active_skill.digest
        refresh_request = SiteRefreshRequest(
            active_skill.scope,
            active_skill,
            explored.site_state,
            False,
            active_skill.budgets,
        )
        result = run_site_refresh(
            refresh_request,
            registry,
            store,
            run_id="phase-18c-ipcc-refresh",
            clock=_now,
        )
        _assert_current_page_evidence(result)
        current_acquisition_evidence = _current_acquisition_packet(result, store)
    finally:
        acquisition.close()
        store.close()

    collections = {
        name: getattr(result, name)
        for name in (
            "added",
            "changed",
            "unchanged",
            "missing",
            "failed",
            "unresolved",
        )
    }
    evidence = {
        "phase_18c_live_evidence": {
            "authorized_window": os.environ["WEB_LISTENING_LIVE_AUTHORIZED_WINDOW"],
            "site_key": target["site_key"],
            "baseline": baseline_evidence,
            "request": refresh_request.to_dict(),
            "result": result.to_dict(),
            "site_skill_digest": active_digest_before,
            "previous_state_digest": result.previous_state.digest,
            "current_state_digest": result.current_state.digest,
            "refresh_complete": result.refresh_complete,
            "changes": {
                name: [item.to_dict() for item in changes]
                for name, changes in collections.items()
            },
            "previous_pages": [page.to_dict() for page in result.previous_state.pages],
            "current_pages": [page.to_dict() for page in result.current_state.pages],
            "attempts": [attempt.to_dict() for attempt in result.attempts],
            "usage": result.usage.to_dict(),
            "stop_reason": result.stop_reason,
            "errors": [error.to_dict() for error in result.errors],
            "site_skill_update": (
                None
                if result.site_skill_update is None
                else result.site_skill_update.to_dict()
            ),
            "candidate_inactive": result.site_skill_update is not None,
            "active_digest_after": active_digest_before,
            "redirect_status_mime": current_acquisition_evidence,
            "physical_network": {
                "requests": network.requests,
                "response_bytes": network.response_bytes,
                "timeout_seconds": limits["timeout_seconds"],
                "concurrency": limits["concurrency"],
                "retry": limits["retry"],
            },
        }
    }
    print(json.dumps(evidence, sort_keys=True))

    assert (
        site_refresh_result_from_mapping(json.loads(result.canonical_json_bytes()))
        == result
    )
    assert result.previous_state == explored.site_state
    assert result.site_skill_used.sha256 == active_digest_before.removeprefix("sha256:")
    assert result.current_state.complete is result.refresh_complete
    assert not result.missing if not result.refresh_complete else True
    all_urls = [change.url for changes in collections.values() for change in changes]
    assert len(all_urls) == len(set(all_urls))
    previous_observations = {
        page.observation_id for page in result.previous_state.pages
    }
    current_observations = {page.observation_id for page in result.current_state.pages}
    assert previous_observations.isdisjoint(current_observations)
    assert result.usage.tool_attempts == sum(
        attempt.outcome != "skipped" for attempt in result.attempts
    )
    assert result.usage.requests == sum(attempt.requests for attempt in result.attempts)
    assert network.requests <= 20
    assert network.response_bytes <= 8 * 1024 * 1024
    assert limits["concurrency"] == 1
    assert limits["retry"] == 0
    assert active_digest_before == active_skill.digest
