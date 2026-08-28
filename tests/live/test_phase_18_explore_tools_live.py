"""Authorized Phase 18 exploration evidence; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring,protected-access
# pylint: disable=too-few-public-methods
# pylint: disable=too-many-locals

from __future__ import annotations

import hashlib
import inspect
import json
import os
import ssl
import time
from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock

import pytest

from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.runtime.workflow import run_single_target
from web_listening.site_skill.model import SuccessChecks, ToolReference
from web_listening.site_skill.update import create_candidate
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.eligibility import (
    EligibilityFacts,
    EligibilityRequirements,
    rank_eligible_tools,
)
from web_listening.tool_registry.manifest import ToolCategory
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners import in_process as in_process_runner
from web_listening.tool_registry.runners.in_process import (
    PinnedHttpTransport,
    TransportResponse,
)

pytestmark = pytest.mark.live

TARGETS = Path(__file__).with_name("phase_18_site_targets.json")
SOURCE_CATALOG = Path(__file__).parent / "catalog" / "smoke_site_catalog.json"
EXPECTED_CATALOG_SHA256 = (
    "CE378F743C6363F1DC22A25758B958E3ADA695F8996B3F619AFA4CF0CD5D5322"
)
EXPECTED_KEYS = ("ipcc", "tnfd")
NOW = "2026-08-27T12:00:00Z"


def _load_snapshot() -> tuple[dict[str, object], list[dict[str, object]]]:
    payload = json.loads(TARGETS.read_bytes())
    targets = payload.get("targets")
    if not isinstance(targets, list):
        pytest.fail("Phase 18 targets must be a list")
    if tuple(target.get("site_key") for target in targets) != EXPECTED_KEYS:
        pytest.fail("Phase 18 must retain only the audited ipcc/tnfd rows")
    if payload.get("source_catalog_sha256") != EXPECTED_CATALOG_SHA256:
        pytest.fail("Phase 18 catalog digest drifted")
    if hashlib.sha256(SOURCE_CATALOG.read_bytes()).hexdigest().upper() != (
        EXPECTED_CATALOG_SHA256
    ):
        pytest.fail("Phase 18 source catalog bytes drifted")
    catalog_sites = json.loads(SOURCE_CATALOG.read_bytes()).get("sites")
    if not isinstance(catalog_sites, list):
        pytest.fail("Phase 18 source catalog is invalid")
    catalog_by_key = {site.get("site_key"): site for site in catalog_sites}
    if targets != [catalog_by_key[key] for key in EXPECTED_KEYS]:
        pytest.fail("Phase 18 targets drifted from the audited catalog rows")
    expected_limits = {
        "max_targets": 2,
        "max_total_requests": 12,
        "max_total_response_bytes": 8 * 1024 * 1024,
        "timeout_seconds": 60,
        "concurrency": 1,
        "retry": 0,
    }
    if payload.get("network_limits") != expected_limits:
        pytest.fail("Phase 18 network limits drifted")
    return payload, targets


def _authorized_targets() -> tuple[dict[str, object], list[dict[str, object]]]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 18 explore-tools live test is offline by default")
    authorized_window = os.environ.get(
        "WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", ""
    ).strip()
    if not authorized_window:
        pytest.fail("a non-empty Phase 18 authorized live window is required")
    payload, targets = _load_snapshot()
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE")
    if selector is not None:
        selector = selector.strip()
        if selector not in EXPECTED_KEYS:
            pytest.fail("WEB_LISTENING_LIVE_SITE must be ipcc or tnfd")
        targets = [target for target in targets if target["site_key"] == selector]
    return payload, targets


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
        self.max_timeout = timeout
        self.requests = 0
        self.response_bytes = 0
        self._clock = clock
        self._deadline = clock() + timeout

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self._deadline - self._clock())

    @property
    def deadline(self) -> float:
        return self._deadline


def _coarse_transport_exception(exc: Exception) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "tls-certificate"
    if isinstance(exc, ssl.SSLError):
        return "tls-generic"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, in_process_runner._PartialBodyRead):
        if exc.code == "gateway.body_incomplete":
            return "body-incomplete"
        if exc.code == "gateway.timeout":
            return "timeout"
    return "connect-transport"


class _CappedResponse:
    def __init__(
        self,
        response: TransportResponse,
        budget: _NetworkBudget,
        trace: list[dict[str, object]] | None = None,
    ) -> None:
        self.status = response.status
        self.headers = response.headers
        self.peer_ip = response.peer_ip
        self._response = response
        self._budget = budget
        self._trace = [] if trace is None else trace

    def read(self, max_bytes: int) -> bytes:
        self._trace.append({"stage": "body-read"})
        try:
            if self._budget.remaining_seconds <= 0:
                raise TimeoutError
            remaining = self._budget.max_response_bytes - self._budget.response_bytes
            if remaining <= 0:
                raise TimeoutError
            content = self._response.read(min(max_bytes, remaining))
        except in_process_runner._PartialBodyRead as exc:
            self._budget.response_bytes += len(exc.partial)
            if self._budget.response_bytes > self._budget.max_response_bytes:
                capped_failure = in_process_runner._PartialBodyRead(
                    exc.partial, "gateway.timeout"
                )
                self._trace.append(
                    {
                        "stage": "exception-category",
                        "category": _coarse_transport_exception(capped_failure),
                    }
                )
                raise capped_failure from exc
            self._trace.append(
                {
                    "stage": "exception-category",
                    "category": _coarse_transport_exception(exc),
                }
            )
            raise
        except Exception as exc:
            self._trace.append(
                {
                    "stage": "exception-category",
                    "category": _coarse_transport_exception(exc),
                }
            )
            raise
        self._budget.response_bytes += len(content)
        return content

    def set_timeout(self, timeout: float) -> None:
        remaining = self._budget.remaining_seconds
        if remaining <= 0:
            raise TimeoutError
        setter = getattr(self._response, "set_timeout", None)
        if callable(setter):
            try:
                setter(min(timeout, remaining))
            except Exception as exc:
                self._trace.append(
                    {
                        "stage": "exception-category",
                        "category": _coarse_transport_exception(exc),
                    }
                )
                raise

    def close(self) -> None:
        self._response.close()


class _CappedTransport:
    def __init__(
        self,
        budget: _NetworkBudget,
        *,
        transport_factory: Callable[[], PinnedHttpTransport] = PinnedHttpTransport,
        trace: list[dict[str, object]] | None = None,
    ) -> None:
        self._budget = budget
        self._transport = transport_factory()
        self._trace = [] if trace is None else trace

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> _CappedResponse:
        remaining_seconds = self._budget.remaining_seconds
        if remaining_seconds <= 0:
            raise TimeoutError
        if self._budget.requests >= self._budget.max_requests:
            raise TimeoutError
        self._trace.append({"stage": "send-start"})
        self._budget.requests += 1
        try:
            response = self._transport.send(
                url,
                timeout=min(timeout, remaining_seconds),
                addresses=addresses,
            )
        except Exception as exc:
            self._trace.append(
                {
                    "stage": "exception-category",
                    "category": _coarse_transport_exception(exc),
                }
            )
            raise
        self._trace.append({"stage": "response-received"})
        self._trace.append({"stage": "status-only", "status": response.status})
        return _CappedResponse(response, self._budget, self._trace)

    def close(self) -> None:
        self._transport.close()


def _request(target: dict[str, object]) -> Request:
    url = str(target["urls"]["monitor"])
    scope = Scope(
        (url,),
        tuple(target["allowed_origins"]),
        ("/**",),
        (ContentType.HTML,),
    )
    budgets = Budgets(12, 8 * 1024 * 1024, 60, 4)
    tool_facts = target["tool_facts"]
    skill = create_candidate(
        site_key=str(target["site_key"]),
        version=1,
        previous=None,
        scope=scope,
        budgets=budgets,
        tool=ToolReference(
            str(tool_facts["tool_id"]),
            str(tool_facts["version"]),
            ToolCategory(str(tool_facts["category"])),
            frozenset(tool_facts["capabilities"]),
            tool_facts.get("recipe_id"),
        ),
        success_checks=SuccessChecks(
            ("text/html",),
            int(target["evidence_thresholds"]["monitor_min_words"]),
        ),
        verified_at=NOW,
    ).skill
    return Request(scope, skill, True, budgets)


def _live_outcome_evidence(
    attempts: list[dict[str, object]], *, artifact_count: int
) -> dict[str, object]:
    succeeded = artifact_count > 0 and any(
        attempt.get("outcome") == "succeeded" and attempt.get("final_url")
        for attempt in attempts
    )
    return {
        "quality": {
            "state": "checked" if succeeded else "not_checked",
            "checked": succeeded,
            "passed": succeeded,
        },
        "first_valid_success_stopped": succeeded,
        "observed": "valid_success" if succeeded else "no_valid_success",
    }


def _require_ipcc_success(evidence: list[dict[str, object]]) -> None:
    ipcc = next(
        (item for item in evidence if item.get("site_key") == "ipcc"),
        None,
    )
    if ipcc is None:
        pytest.fail("Phase 18 acceptance requires IPCC evidence")
    if ipcc.get("observed") != "valid_success":
        pytest.fail("Phase 18 acceptance requires successful IPCC evidence")


def test_phase_18_snapshot_and_live_source_are_bounded() -> None:
    payload, targets = _load_snapshot()
    source = inspect.getsource(test_phase_18_explore_all_tools_live)

    assert payload["phase"] == "18"
    assert len(targets) == 2
    assert "WEB_LISTENING_RUN_LIVE" in inspect.getsource(_authorized_targets)
    assert "WEB_LISTENING_LIVE_AUTHORIZED_WINDOW" in inspect.getsource(
        _authorized_targets
    )
    assert "WEB_LISTENING_LIVE_URL" not in inspect.getsource(_authorized_targets)
    assert source.count("run_single_target(") == 1
    evidence_print = source.index('"phase_18_live_evidence"')
    for acceptance_check in (
        "assert len(evidence) <= 2",
        "assert budget.requests <= 12",
        "assert budget.response_bytes <= 8 * 1024 * 1024",
        'assert evidence[0]["eligibility"]["ranked"]',
        'assert len(evidence[0]["attempts"]["tried"])',
        "_require_ipcc_success(evidence)",
    ):
        assert evidence_print < source.index(acceptance_check)


def test_live_outcome_evidence_requires_actual_success_and_artifact() -> None:
    failure = _live_outcome_evidence(
        [{"outcome": "failed", "final_url": None}],
        artifact_count=0,
    )
    success = _live_outcome_evidence(
        [
            {"outcome": "failed", "final_url": None},
            {"outcome": "succeeded", "final_url": "https://example.test/"},
        ],
        artifact_count=1,
    )

    assert failure == {
        "quality": {"state": "not_checked", "checked": False, "passed": False},
        "first_valid_success_stopped": False,
        "observed": "no_valid_success",
    }
    assert success == {
        "quality": {"state": "checked", "checked": True, "passed": True},
        "first_valid_success_stopped": True,
        "observed": "valid_success",
    }


@pytest.mark.parametrize("selector", EXPECTED_KEYS)
def test_live_selector_strictly_selects_one_site_key(
    monkeypatch: pytest.MonkeyPatch, selector: str
) -> None:
    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    monkeypatch.setenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "review-window")
    monkeypatch.setenv("WEB_LISTENING_LIVE_SITE", selector)

    _payload, targets = _authorized_targets()

    assert [target["site_key"] for target in targets] == [selector]


def test_phase_18_acceptance_requires_ipcc_evidence() -> None:
    with pytest.raises(pytest.fail.Exception, match="requires IPCC evidence"):
        _require_ipcc_success([{"site_key": "tnfd", "observed": "valid_success"}])


def test_shared_live_deadline_reduces_timeout_and_stops_before_expired_send() -> None:
    now = [0.0]
    transport = Mock()
    response = Mock(status=200, headers={}, peer_ip="93.184.216.34")
    transport.send.return_value = response
    budget = _NetworkBudget(3, 100, 60, clock=lambda: now[0])
    capped = _CappedTransport(budget, transport_factory=lambda: transport)
    url = "https://example.test/"

    capped.send(url, timeout=60, addresses=("93.184.216.34",))
    now[0] = 25.0
    capped.send(url, timeout=60, addresses=("93.184.216.34",))
    now[0] = 60.0
    with pytest.raises(TimeoutError):
        capped.send(url, timeout=60, addresses=("93.184.216.34",))

    assert transport.send.call_args_list[0].kwargs["timeout"] == 60
    assert transport.send.call_args_list[1].kwargs["timeout"] == 35
    assert transport.send.call_count == 2
    assert budget.requests == 2


def test_shared_live_deadline_also_bounds_body_read() -> None:
    now = [0.0]
    response = Mock(status=200, headers={}, peer_ip="93.184.216.34")

    def slow_read(_max_bytes: int) -> bytes:
        now[0] = 61.0
        return b"body"

    response.read.side_effect = slow_read
    budget = _NetworkBudget(3, 100, 60, clock=lambda: now[0])
    capped = _CappedResponse(response, budget)

    capped.set_timeout(100)
    assert capped.read(100) == b"body"

    response.set_timeout.assert_called_once_with(60)
    assert budget.response_bytes == 4


def test_shared_live_budget_counts_partial_failure_once_and_stops_at_cap() -> None:
    response = Mock(status=200, headers={}, peer_ip="93.184.216.34")
    response.read.side_effect = (
        in_process_runner._PartialBodyRead(b"abc"),
        in_process_runner._PartialBodyRead(b"def"),
    )
    budget = _NetworkBudget(3, 5, 60)
    capped = _CappedResponse(response, budget)

    with pytest.raises(in_process_runner._PartialBodyRead) as first:
        capped.read(5)
    with pytest.raises(in_process_runner._PartialBodyRead) as second:
        capped.read(5)
    with pytest.raises(TimeoutError):
        capped.read(5)

    assert first.value.partial == b"abc"
    assert second.value.partial == b"def"
    assert first.value.code == "gateway.transport"
    assert second.value.code == "gateway.timeout"
    assert budget.response_bytes == 6
    assert response.read.call_count == 2


def test_live_transport_trace_records_success_without_an_extra_send() -> None:
    transport = Mock()
    response = Mock(status=200, headers={}, peer_ip="93.184.216.34")
    response.read.return_value = b"body"
    transport.send.return_value = response
    trace: list[dict[str, object]] = []
    budget = _NetworkBudget(3, 100, 60)
    capped = _CappedTransport(
        budget,
        transport_factory=lambda: transport,
        trace=trace,
    )

    capped_response = capped.send(
        "https://example.test/",
        timeout=60,
        addresses=("93.184.216.34",),
    )
    assert capped_response.read(100) == b"body"

    assert trace == [
        {"stage": "send-start"},
        {"stage": "response-received"},
        {"stage": "status-only", "status": 200},
        {"stage": "body-read"},
    ]
    assert transport.send.call_count == 1
    assert response.read.call_count == 1
    assert budget.requests == 1
    assert budget.response_bytes == 4


@pytest.mark.parametrize(
    ("failure", "category"),
    [
        (ssl.SSLCertVerificationError(1, "private detail"), "tls-certificate"),
        (ssl.SSLError(1, "private detail"), "tls-generic"),
        (TimeoutError("private detail"), "timeout"),
        (ConnectionError("private detail"), "connect-transport"),
    ],
)
def test_live_transport_trace_classifies_send_failure_without_retry(
    failure: Exception,
    category: str,
) -> None:
    transport = Mock()
    transport.send.side_effect = failure
    trace: list[dict[str, object]] = []
    budget = _NetworkBudget(3, 100, 60)
    capped = _CappedTransport(
        budget,
        transport_factory=lambda: transport,
        trace=trace,
    )

    with pytest.raises(type(failure)):
        capped.send(
            "https://example.test/",
            timeout=60,
            addresses=("93.184.216.34",),
        )

    assert trace == [
        {"stage": "send-start"},
        {"stage": "exception-category", "category": category},
    ]
    assert transport.send.call_count == 1
    assert budget.requests == 1
    assert budget.response_bytes == 0


def test_live_transport_trace_classifies_incomplete_body_without_retry() -> None:
    transport = Mock()
    response = Mock(status=200, headers={}, peer_ip="93.184.216.34")
    response.read.side_effect = in_process_runner._PartialBodyRead(
        b"abc", "gateway.body_incomplete"
    )
    transport.send.return_value = response
    trace: list[dict[str, object]] = []
    budget = _NetworkBudget(3, 100, 60)
    capped = _CappedTransport(
        budget,
        transport_factory=lambda: transport,
        trace=trace,
    )

    capped_response = capped.send(
        "https://example.test/",
        timeout=60,
        addresses=("93.184.216.34",),
    )
    with pytest.raises(in_process_runner._PartialBodyRead):
        capped_response.read(100)

    assert trace == [
        {"stage": "send-start"},
        {"stage": "response-received"},
        {"stage": "status-only", "status": 200},
        {"stage": "body-read"},
        {"stage": "exception-category", "category": "body-incomplete"},
    ]
    assert transport.send.call_count == 1
    assert response.read.call_count == 1
    assert budget.requests == 1
    assert budget.response_bytes == 3


def test_phase_18_explore_all_tools_live(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    payload, targets = _authorized_targets()
    limits = payload["network_limits"]
    budget = _NetworkBudget(
        int(limits["max_total_requests"]),
        int(limits["max_total_response_bytes"]),
        int(limits["timeout_seconds"]),
    )
    evidence: list[dict[str, object]] = []

    for index, target in enumerate(targets[: int(limits["max_targets"])]):
        request = _request(target)
        transport_trace: list[dict[str, object]] = []
        acquisition = WebHttpAcquisitionTool(
            lambda trace=transport_trace: _CappedTransport(budget, trace=trace),
            runtime_deadline=budget.deadline,
        )
        registry = Registry()
        registry.register(WEB_HTTP_MANIFEST, acquisition)
        manifests = registry.query(category=ToolCategory.ACQUISITION)
        tool_ids = frozenset(manifest.tool_id for manifest in manifests)
        selection = rank_eligible_tools(
            manifests,
            EligibilityRequirements(ToolCategory.ACQUISITION),
            EligibilityFacts(
                tool_ids,
                tool_ids,
                request.budgets.max_requests,
                request.budgets.max_bytes,
                request.budgets.max_runtime_seconds * 1_000,
                request.budgets.max_tool_attempts_per_target,
            ),
            preferred_tool_id=request.site_skill.tool.tool_id,
            include_alternates=request.explore_all_tools,
        )
        store = ArtifactStore(tmp_path / str(target["site_key"]))
        try:
            result = run_single_target(
                request,
                registry,
                store,
                run_id=f"live-phase-18-{index}",
                clock=lambda: NOW,
            )
            tried = [
                attempt.to_dict()
                for attempt in result.attempts
                if attempt.outcome != "skipped"
            ]
            skipped = [
                attempt.to_dict()
                for attempt in result.attempts
                if attempt.outcome == "skipped"
            ]
            error_codes = tuple(error.code for error in result.errors)
            outcome = _live_outcome_evidence(
                tried,
                artifact_count=len(result.artifacts),
            )
            expected = "valid_success"
            evidence.append(
                {
                    "site_key": target["site_key"],
                    "historical_expectation": target["historical_classification"][
                        "expectation"
                    ],
                    "request": {
                        "explore_all_tools": request.explore_all_tools,
                        "budgets": {
                            "max_requests": request.budgets.max_requests,
                            "max_bytes": request.budgets.max_bytes,
                            "max_runtime_seconds": (
                                request.budgets.max_runtime_seconds
                            ),
                            "max_tool_attempts_per_target": (
                                request.budgets.max_tool_attempts_per_target
                            ),
                        },
                    },
                    "eligibility": {
                        "ranked": [manifest.tool_id for manifest in selection.ranked],
                        "decisions": [
                            {
                                "tool_id": decision.tool_id,
                                "tool_version": decision.tool_version,
                                "eligible": decision.eligible,
                                "checks": list(decision.checks),
                                "reasons": list(decision.reasons),
                            }
                            for decision in selection.decisions
                        ],
                    },
                    "attempts": {"tried": tried, "skipped": skipped},
                    "quality": {
                        "minimum_words": target["evidence_thresholds"][
                            "monitor_min_words"
                        ],
                        **outcome["quality"],
                    },
                    "first_valid_success_stopped": outcome[
                        "first_valid_success_stopped"
                    ],
                    "expected": expected,
                    "observed": outcome["observed"],
                    "drift": outcome["observed"] != expected,
                    "policy": {
                        "terminal_rejection": any(
                            code.startswith(("robots.", "scope.", "policy.", "budget."))
                            or code == "gateway.https_downgrade"
                            for code in error_codes
                        ),
                        "error_codes": list(error_codes),
                    },
                    "usage": result.usage.to_dict(),
                    "network_usage": {
                        "requests": budget.requests,
                        "response_bytes": budget.response_bytes,
                    },
                    "transport_trace": transport_trace,
                    "result": result.to_dict(),
                }
            )
        finally:
            store.close()
            acquisition.close()

    with capfd.disabled():
        print(json.dumps({"phase_18_live_evidence": evidence}, sort_keys=True))
    assert len(evidence) <= 2
    assert budget.requests <= 12
    assert budget.response_bytes <= 8 * 1024 * 1024
    assert evidence[0]["eligibility"]["ranked"] == [WEB_HTTP_MANIFEST.tool_id]
    assert len(evidence[0]["attempts"]["tried"]) == 1
    _require_ipcc_success(evidence)
