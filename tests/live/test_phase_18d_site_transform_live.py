"""Authorized Phase 18D aggregate Transform canary; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring,protected-access
# pylint: disable=too-few-public-methods,too-many-locals,too-many-statements

from __future__ import annotations

import hashlib
import inspect
import json
import os
import socket
from pathlib import Path

import pytest

from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.runtime.site_explore import (
    run_site_explore,
    site_explore_result_from_mapping,
)
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.protocols.transform import (
    TransformFailure,
    TransformInput,
    TransformOutput,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners.in_process import (
    PinnedHttpTransport,
    TransportResponse,
)
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)

pytestmark = pytest.mark.live

TARGETS = Path(__file__).with_name("phase_18d_site_targets.json")
AUTHORIZED_WINDOW = "issue-75-2026-08-31-user-authorized-ipcc-wri"
EXPECTED_CATALOG_SHA256 = (
    "CE378F743C6363F1DC22A25758B958E3ADA695F8996B3F619AFA4CF0CD5D5322"
)
EXPECTED_KEYS = ("ipcc", "wri")
NOW = "2026-08-31T00:00:00Z"


def _expected_targets() -> list[dict[str, object]]:
    return [
        {
            "site_key": "ipcc",
            "display_name": "Intergovernmental Panel on Climate Change",
            "url": "https://www.ipcc.ch/",
            "allowed_origins": ["https://www.ipcc.ch"],
            "historical_expectation": "pass_http",
            "minimum_words": 300,
            "site_skill_digest": (
                "sha256:65886846062d93ebe8e4d9edef63c1c65fc37774749d731db086ed3a408b97be"
            ),
            "recipe_id": "catalog-http",
            "provenance": {
                "old_commit": "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5",
                "old_path": "config/smoke_site_catalog.json",
                "old_blob": "e50b2c0d29e1b3c5df6473409c1a33ad4ffee4c4",
                "old_site_key": "ipcc",
            },
        },
        {
            "site_key": "wri",
            "display_name": "World Resources Institute",
            "url": "https://www.wri.org/",
            "allowed_origins": ["https://www.wri.org"],
            "historical_expectation": "pass_http",
            "minimum_words": 250,
            "site_skill_digest": (
                "sha256:20e88cbe540f6651e88e179eb06f02ee45300a1ea21ac23e1525eb7f80feede2"
            ),
            "recipe_id": None,
            "provenance": {
                "old_commit": "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5",
                "old_path": "config/smoke_site_catalog.json",
                "old_blob": "e50b2c0d29e1b3c5df6473409c1a33ad4ffee4c4",
                "old_site_key": "wri",
            },
        },
    ]


def _load_snapshot() -> tuple[dict[str, object], list[dict[str, object]]]:
    payload = json.loads(TARGETS.read_bytes())
    if payload.get("source_catalog_sha256") != EXPECTED_CATALOG_SHA256:
        pytest.fail("Phase 18D catalog digest drifted")
    targets = payload.get("targets")
    if targets != _expected_targets():
        pytest.fail("Phase 18D must retain the exact audited ipcc/wri projection")
    limits = {
        "max_targets": 2,
        "max_total_requests": 12,
        "max_total_bytes": 4 * 1024 * 1024,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
        "acquisition_fallback": 0,
        "transform_network_calls": 0,
    }
    if payload.get("network_limits") != limits:
        pytest.fail("Phase 18D network limits drifted")
    return payload, targets  # type: ignore[return-value]


def _authorized_targets() -> tuple[dict[str, object], list[dict[str, object]]]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 18D aggregate Transform live test is offline by default")
    if os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW") != AUTHORIZED_WINDOW:
        pytest.fail("the exact Phase 18D authorized live window is required")
    payload, targets = _load_snapshot()
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE")
    if selector is not None:
        selector = selector.strip()
        if selector not in EXPECTED_KEYS:
            pytest.fail("WEB_LISTENING_LIVE_SITE must be ipcc or wri")
        targets = [target for target in targets if target["site_key"] == selector]
    return payload, targets


class _NetworkBudget:
    def __init__(self, max_requests: int, max_bytes: int) -> None:
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.requests = 0
        self.bytes = 0


class _CappedResponse:
    def __init__(self, response: TransportResponse, budget: _NetworkBudget) -> None:
        self.status = response.status
        self.headers = response.headers
        self.peer_ip = response.peer_ip
        self._response = response
        self._budget = budget

    def read(self, max_bytes: int) -> bytes:
        remaining = self._budget.max_bytes - self._budget.bytes
        if remaining <= 0:
            raise TimeoutError
        content = self._response.read(min(max_bytes, remaining))
        self._budget.bytes += len(content)
        return content

    def close(self) -> None:
        self._response.close()


class _CappedTransport:
    def __init__(self, budget: _NetworkBudget) -> None:
        self._budget = budget
        self._transport = PinnedHttpTransport()

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> _CappedResponse:
        if self._budget.requests >= self._budget.max_requests:
            raise TimeoutError
        self._budget.requests += 1
        return _CappedResponse(
            self._transport.send(url, timeout=timeout, addresses=addresses),
            self._budget,
        )

    def close(self) -> None:
        self._transport.close()


class _NoNetworkProbeTransform:
    manifest = SIMPLE_HTML_MARKDOWN_MANIFEST

    def __init__(self) -> None:
        self.calls = 0
        self.socket_calls = 0
        self._tool = SimpleHtmlMarkdownTransform()

    def transform(
        self, tool_input: TransformInput
    ) -> TransformOutput | TransformFailure:
        self.calls += 1
        original_socket = socket.socket

        def reject_socket(*_args: object, **_kwargs: object) -> None:
            self.socket_calls += 1
            raise AssertionError("Transform attempted network access")

        socket.socket = reject_socket  # type: ignore[assignment]
        try:
            return self._tool.transform(tool_input)
        finally:
            socket.socket = original_socket


def _request(target: dict[str, object]) -> Request:
    return Request(
        Scope(
            seeds=(str(target["url"]),),
            allowed_origins=tuple(target["allowed_origins"]),
            include_paths=("/**",),
            content_types=(ContentType.HTML,),
        ),
        None,
        False,
        Budgets(12, 2 * 1024 * 1024, 30, 2),
    )


def test_snapshot_is_exact_and_self_contained() -> None:
    payload, targets = _load_snapshot()

    assert payload["phase"] == "18d"
    assert tuple(target["site_key"] for target in targets) == EXPECTED_KEYS
    assert tuple(target["url"] for target in targets) == (
        "https://www.ipcc.ch/",
        "https://www.wri.org/",
    )
    assert all(target["historical_expectation"] == "pass_http" for target in targets)
    live_source = inspect.getsource(
        test_real_site_explore_target_result_contains_transform_evidence
    )
    assert live_source.index("print(") < live_source.index("assert eligible")


def test_real_site_explore_target_result_contains_transform_evidence(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    payload, targets = _authorized_targets()
    limits = payload["network_limits"]
    budget = _NetworkBudget(
        int(limits["max_total_requests"]),
        int(limits["max_total_bytes"]),
    )
    evidence: list[dict[str, object]] = []
    eligible = False

    for index, target in enumerate(targets[: int(limits["max_targets"])]):
        transform = _NoNetworkProbeTransform()
        acquisition = WebHttpAcquisitionTool(lambda: _CappedTransport(budget))
        registry = Registry()
        registry.register(WEB_HTTP_MANIFEST, acquisition)
        registry.register(SIMPLE_HTML_MARKDOWN_MANIFEST, transform)
        store = ArtifactStore(tmp_path / str(target["site_key"]))
        try:
            result = run_site_explore(
                _request(target),
                registry,
                store,
                run_id=f"live-phase-18d-{index}",
                clock=lambda: NOW,
            )
            assert site_explore_result_from_mapping(result.to_dict()) == result
            assert len(result.target_results) == 1
            target_result = result.target_results[0]
            source = next(
                (
                    artifact
                    for artifact in target_result.artifacts
                    if artifact.role == "source"
                ),
                None,
            )
            derived = next(
                (
                    artifact
                    for artifact in target_result.artifacts
                    if artifact.role == "derived"
                ),
                None,
            )
            transform_attempt = next(
                (
                    attempt
                    for attempt in target_result.attempts
                    if attempt.tool_id == SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id
                ),
                None,
            )
            if source is not None:
                stored_source = store.get_observation(source.observation_id)
                assert stored_source.content
                assert (
                    hashlib.sha256(stored_source.content).hexdigest() == source.sha256
                )
                assert stored_source.artifact.mime_type == source.mime_type
            if derived is not None:
                stored_derived = store.get_observation(derived.observation_id)
                assert source is not None
                assert derived.mime_type == "text/markdown"
                assert stored_derived.lineage == derived.lineage
                assert derived.lineage[0].source_artifact_id == source.artifact_id
                assert derived.lineage[0].source_observation_id == source.observation_id
                assert stored_derived.content
                assert transform_attempt is not None
                assert transform_attempt.outcome == "succeeded"
                assert transform_attempt.requests == 0
                assert transform_attempt.bytes_received == 0
                assert target_result.manifest.artifacts == target_result.artifacts
                assert target_result.manifest.attempts == target_result.attempts
                assert target_result.manifest.usage == target_result.usage
                assert result.attempts == target_result.attempts
                assert result.usage == target_result.usage
                eligible = True
            evidence.append(
                {
                    "site_key": target["site_key"],
                    "historical_expectation": target["historical_expectation"],
                    "aggregate_status": result.status.value,
                    "aggregate_stop_reason": result.stop_reason,
                    "target_run_id": target_result.manifest.run_id,
                    "requested_url": target_result.manifest.requested_url,
                    "final_url": target_result.manifest.final_url,
                    "http_status": target_result.manifest.http_status,
                    "mime_type": target_result.manifest.mime_type,
                    "redirects": [
                        item.to_dict() for item in target_result.manifest.redirects
                    ],
                    "source": None if source is None else source.to_dict(),
                    "derived": None if derived is None else derived.to_dict(),
                    "attempts": [
                        attempt.to_dict() for attempt in target_result.attempts
                    ],
                    "errors": [error.to_dict() for error in result.errors],
                    "target_usage": target_result.usage.to_dict(),
                    "aggregate_usage": result.usage.to_dict(),
                    "no_network_probe": {
                        "transform_calls": transform.calls,
                        "socket_calls": transform.socket_calls,
                    },
                }
            )
        finally:
            store.close()
            acquisition.close()
        if eligible:
            break

    assert budget.requests <= 12
    assert budget.bytes <= 4 * 1024 * 1024
    assert len(evidence) <= 2
    assert all(
        item["no_network_probe"]["socket_calls"] == 0  # type: ignore[index]
        for item in evidence
        if item["no_network_probe"]["transform_calls"]  # type: ignore[index]
    )
    with capfd.disabled():
        print(json.dumps({"phase_18d_live_evidence": evidence}, sort_keys=True))
    assert eligible, "both frozen real HTML targets lacked derived Markdown evidence"
