"""Authorized SOA canary for the one Phase 16 external Transform."""

# pylint: disable=duplicate-code,missing-function-docstring,protected-access
# pylint: disable=too-few-public-methods
# pylint: disable=too-many-locals,too-many-statements

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from web_listening.artifact.model import Lineage
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.runtime.workflow import run_single_target
from web_listening.site_skill.model import SuccessChecks, ToolReference
from web_listening.site_skill.update import create_candidate
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.lifecycle import ToolLifecycle
from web_listening.tool_registry.manifest import ToolCategory, ToolManifest
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
from web_listening.tool_registry.runners.subprocess import SubprocessRunner

pytestmark = pytest.mark.live

ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "tests/fixtures/tools/external_transform/1.0.0"
TARGETS = Path(__file__).with_name("phase_16_site_targets.json")
AUTHORIZED_WINDOW = "issue-17-2026-08-27-user-authorized-soa"
EXPECTED_CATALOG_SHA256 = (
    "3074C31AC5370D0D6E1C1025D28E08CCCAAD042F976547540F420FAEF81CAED3"
)
TOOL_ID = "external.basic_html_markdown"
VERSION = "1.0.0"
NOW = "2026-08-27T00:00:00Z"


def _expected_target() -> dict[str, object]:
    return {
        "site_key": "soa",
        "display_name": "SOA",
        "urls": {
            "homepage": "https://www.soa.org/",
            "monitor": "https://www.soa.org/",
            "document": "https://www.soa.org/publications/publications-landing/",
            "tree_seed": None,
        },
        "allowed_origins": ["https://www.soa.org"],
        "historical_classification": {"expectation": "dev_fixture"},
        "evidence_thresholds": {
            "monitor_min_words": 150,
            "document_min_words": 150,
            "document_min_links": 1,
        },
        "site_skill_case": "soa",
        "site_skill_digest": (
            "sha256:889175f428f227000aeacfae1ebfda14704a9d469088c02b4a8745bfb732caf2"
        ),
        "provenance": {
            "old_commit": "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5",
            "old_path": "config/dev_test_sites.json",
            "old_blob": "922ddc452e6f8cb1e8e1eee78832ba178f915fe1",
            "old_site_key": "soa",
        },
        "tree_include_paths": [],
        "tool_facts": {
            "tool_id": "acquisition.web_http",
            "version": "1.0.0",
            "category": "acquisition",
            "capabilities": ["http_get"],
        },
    }


def _load_snapshot() -> tuple[dict[str, object], dict[str, object]]:
    payload = json.loads(TARGETS.read_bytes())
    assert payload["phase"] == "16"
    assert payload["source_catalog_sha256"] == EXPECTED_CATALOG_SHA256
    assert payload["targets"] == [_expected_target()]
    assert payload["external_transform"] == {
        "tool_id": TOOL_ID,
        "version": VERSION,
        "category": "transform",
        "distribution": "installed",
        "capabilities": ["html_to_markdown"],
        "input_mime_type": "text/html",
        "output_mime_type": "text/markdown",
    }
    assert payload["network_limits"] == {
        "max_targets": 1,
        "max_total_requests": 6,
        "max_total_bytes": 4 * 1024 * 1024,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
        "acquisition_fallback": 0,
        "transform_network_requests": 0,
    }
    return payload, payload["targets"][0]


def _authorized_target() -> tuple[dict[str, object], dict[str, object]]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 16 external Transform live test is offline by default")
    if os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW") != AUTHORIZED_WINDOW:
        pytest.fail("the exact Phase 16 authorized live window is required")
    selector = os.environ.get("WEB_LISTENING_LIVE_SITE")
    if selector is not None and selector.strip() != "soa":
        pytest.fail("WEB_LISTENING_LIVE_SITE must be soa")
    return _load_snapshot()


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


class _EvidenceRunner(SubprocessRunner):
    def __init__(self, manifest: ToolManifest, command: tuple[str, ...]) -> None:
        super().__init__(manifest, command)
        self.stdin_envelope: dict[str, object] | None = None
        self.stdout_envelope: dict[str, object] | None = None
        self.exit_code: int | str | None = None

    def _execute(self, wire, attempt_directory, started, runtime_seconds):
        self.stdin_envelope = json.loads(wire)
        code, stdout = super()._execute(
            wire, attempt_directory, started, runtime_seconds
        )
        self.exit_code = 0 if code is None else code
        self.stdout_envelope = json.loads(stdout) if stdout else None
        return code, stdout


class _ExternalTransform:
    def __init__(self, manifest: ToolManifest, runner: _EvidenceRunner) -> None:
        self.manifest = manifest
        self.runner = runner

    def transform(
        self, tool_input: TransformInput
    ) -> TransformOutput | TransformFailure:
        result = self.runner.invoke(tool_input)
        assert isinstance(result, (TransformOutput, TransformFailure))
        return result


def _request(target: dict[str, object]) -> Request:
    url = str(target["urls"]["homepage"])
    scope = Scope(
        seeds=(url,),
        allowed_origins=tuple(target["allowed_origins"]),
        include_paths=("/**",),
        content_types=(ContentType.HTML,),
    )
    budgets = Budgets(6, 4 * 1024 * 1024, 30, 2)
    skill = create_candidate(
        site_key="soa",
        version=1,
        previous=None,
        scope=scope,
        budgets=budgets,
        tool=ToolReference(
            WEB_HTTP_MANIFEST.tool_id,
            WEB_HTTP_MANIFEST.version,
            ToolCategory.ACQUISITION,
            WEB_HTTP_MANIFEST.capabilities,
        ),
        success_checks=SuccessChecks(("text/html",), 150),
        verified_at=NOW,
    ).skill
    return Request(scope, skill, False, budgets)


def _external_imports() -> set[str]:
    tree = ast.parse((SOURCE / "tool.py").read_text(encoding="utf-8"))
    return {
        node.names[0].name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }


def _project_stdin_evidence(envelope: dict[str, object]) -> dict[str, object]:
    """Keep protocol metadata while replacing the HTML body with digest evidence."""
    tool_input = envelope["input"]
    assert isinstance(tool_input, dict)
    projected_input = dict(tool_input)
    encoded = projected_input.pop("source_body_base64")
    assert isinstance(encoded, str)
    body = base64.b64decode(encoded, validate=True)
    projected_input.update(
        content_redacted=True,
        size_bytes=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
    )
    projected = dict(envelope)
    projected["input"] = projected_input
    return projected


def _lineage_evidence(lineage: Lineage) -> dict[str, str]:
    return {
        "lineage_id": lineage.lineage_id,
        "observation_id": lineage.observation_id,
        "artifact_id": lineage.artifact_id,
        "relation": lineage.relation,
        "source_observation_id": lineage.source_observation_id,
        "source_artifact_id": lineage.source_artifact_id,
    }


def test_snapshot_is_exact_single_soa_projection() -> None:
    payload, target = _load_snapshot()
    assert payload["network_limits"]["max_targets"] == 1
    assert target["urls"]["homepage"] == "https://www.soa.org/"
    assert target["provenance"]["old_commit"] == (
        "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5"
    )


def test_printed_stdin_evidence_redacts_body_but_keeps_size_and_hash() -> None:
    body = b"<html><body>private live content</body></html>"
    encoded = base64.b64encode(body).decode("ascii")
    envelope = {
        "protocol_version": "web-listening-external-tool.v1",
        "category": "transform",
        "input": {
            "source_artifact_id": "artifact-example",
            "source_mime_type": "text/html",
            "source_body_base64": encoded,
        },
    }

    projected = _project_stdin_evidence(envelope)

    assert envelope["input"]["source_body_base64"] == encoded
    assert "source_body_base64" not in projected["input"]
    assert projected["input"]["content_redacted"] is True
    assert projected["input"]["size_bytes"] == len(body)
    assert projected["input"]["sha256"] == hashlib.sha256(body).hexdigest()
    rendered = json.dumps(projected, sort_keys=True)
    assert body.decode("utf-8") not in rendered
    assert encoded not in rendered


def test_lineage_evidence_projects_the_six_existing_fields() -> None:
    lineage = Lineage(
        lineage_id="lineage-1",
        observation_id="derived-observation",
        artifact_id="derived-artifact",
        relation="derived_from",
        source_observation_id="source-observation",
        source_artifact_id="source-artifact",
    )

    assert _lineage_evidence(lineage) == {
        "lineage_id": "lineage-1",
        "observation_id": "derived-observation",
        "artifact_id": "derived-artifact",
        "relation": "derived_from",
        "source_observation_id": "source-observation",
        "source_artifact_id": "source-artifact",
    }


def test_real_soa_html_runs_through_qualified_external_transform(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    payload, target = _authorized_target()
    limits = payload["network_limits"]
    budget = _NetworkBudget(
        int(limits["max_total_requests"]), int(limits["max_total_bytes"])
    )
    lifecycle = ToolLifecycle(tmp_path / "lifecycle")
    lifecycle.install(SOURCE)
    qualified = lifecycle.qualify(ToolCategory.TRANSFORM, TOOL_ID, VERSION)
    active = lifecycle.activate(ToolCategory.TRANSFORM, TOOL_ID, VERSION)
    command = (
        sys.executable,
        str(
            lifecycle.data_root / "tools" / "transform" / TOOL_ID / VERSION / "tool.py"
        ),
    )
    runner = _EvidenceRunner(active.manifest, command)
    transform = _ExternalTransform(active.manifest, runner)
    acquisition = WebHttpAcquisitionTool(lambda: _CappedTransport(budget))
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    registry.register(active.manifest, transform)
    store = ArtifactStore(tmp_path / "artifacts")
    try:
        result = run_single_target(
            _request(target), registry, store, run_id="live-phase-16", clock=lambda: NOW
        )
        source = next(
            (item for item in result.artifacts if item.role == "source"), None
        )
        derived = next(
            (item for item in result.artifacts if item.role == "derived"), None
        )
        transform_attempt = next(
            (item for item in result.attempts if item.tool_id == TOOL_ID), None
        )
        stored_source = (
            None if source is None else store.get_observation(source.observation_id)
        )
        stored_derived = (
            None if derived is None else store.get_observation(derived.observation_id)
        )
        imports = _external_imports()
        network_imports = sorted(imports & {"http", "requests", "socket", "urllib"})
        stdin_evidence = (
            None
            if runner.stdin_envelope is None
            else _project_stdin_evidence(runner.stdin_envelope)
        )
        evidence = {
            "site_key": target["site_key"],
            "source": (
                None
                if source is None
                else {
                    "artifact_id": source.artifact_id,
                    "observation_id": source.observation_id,
                    "sha256": source.sha256,
                    "mime_type": source.mime_type,
                }
            ),
            "external_protocol": {
                "stdin": stdin_evidence,
                "stdout": runner.stdout_envelope,
                "exit_code": runner.exit_code,
            },
            "tool": {
                "tool_id": active.manifest.tool_id,
                "version": active.manifest.version,
                "qualified": qualified.qualified,
                "active": active.active,
            },
            "derived": (
                None
                if derived is None
                else {
                    "artifact_id": derived.artifact_id,
                    "observation_id": derived.observation_id,
                    "sha256": derived.sha256,
                    "mime_type": derived.mime_type,
                    "lineage": [_lineage_evidence(edge) for edge in derived.lineage],
                }
            ),
            "transform_attempt": (
                None if transform_attempt is None else transform_attempt.to_dict()
            ),
            "errors": [item.to_dict() for item in result.errors],
            "network": {
                "acquisition_requests": budget.requests,
                "acquisition_bytes": budget.bytes,
                "transform_requests": 0,
                "external_network_imports": network_imports,
                "concurrency": 1,
                "retry": 0,
            },
        }
        with capfd.disabled():
            print(json.dumps({"phase_16_live_evidence": evidence}, sort_keys=True))

        assert source is not None and stored_source is not None
        assert source.mime_type == "text/html"
        assert source.sha256 == stored_source.blob.sha256
        assert derived is not None and stored_derived is not None
        assert derived.mime_type == "text/markdown"
        assert derived.sha256 == stored_derived.blob.sha256
        assert stored_derived.lineage[0].source_observation_id == source.observation_id
        assert stored_derived.lineage[0].source_artifact_id == source.artifact_id
        assert transform_attempt is not None
        assert transform_attempt.outcome == "succeeded"
        assert transform_attempt.requests == 0
        assert runner.exit_code == 0
        assert runner.stdin_envelope is not None
        assert runner.stdout_envelope is not None
        assert stdin_evidence is not None
        assert "source_body_base64" not in stdin_evidence["input"]
        assert network_imports == []
        assert budget.requests <= 6
        assert budget.bytes <= 4 * 1024 * 1024
        assert not list(lifecycle.data_root.rglob("derived.md"))
    finally:
        store.close()
        acquisition.close()
