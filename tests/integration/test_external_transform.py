"""Phase 16 integration for one installed no-network external Transform.

README 1-2 Alignment:
- Purpose: acquired HTML remains the immutable source while the optional
  external Transform produces one Markdown derivative and a recorded attempt.
- Product model: Lifecycle and Registry select/execute the tool, Runtime alone
  commits Artifacts, and no Request, Site Skill, Result, or interface gains new
  authority.
- Sections 8/12/18: this is exactly one installed Transform, it has no network
  behavior, and failure retains the source without another acquisition.
"""

# pylint: disable=duplicate-code,missing-function-docstring,too-few-public-methods

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path

from web_listening.artifact.identity import artifact_id, blob_relative_path
from web_listening.artifact.model import (
    Artifact,
    ArtifactRole,
    Blob,
    Observation,
    StoredObservation,
)
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.result.model import ResultStatus
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
from web_listening.tool_registry.runners.subprocess import SubprocessRunner

ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "tests/fixtures/tools/external_transform/1.0.0"
TOOL_ID = "external.basic_html_markdown"
VERSION = "1.0.0"
URL = "https://example.test/"
NOW = "2026-08-27T00:00:00Z"
PUBLIC_IP = "93.184.216.34"
HTML = b"<html><body><h1>Example</h1><p>Hello external transform.</p></body></html>"
FAIL_HTML = b"<html><body data-external-transform-fail>keep source</body></html>"
LIFECYCLE_TEST_SHA256 = (
    "27066394b79cf4ea89a34a9f7114dd2e25dc82e8060ed8c9afec52e69673ce20"
)
OLD_COMMIT = "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5"

# Fixed-SHA migration table required by Issue #17. The old project had a
# subprocess acquisition boundary and preserved original documents, but no
# equivalent external Transform. Phase 14/15 public APIs are therefore reused;
# only the one new fixture and its integration evidence are added here.
MIGRATION = (
    (
        "web_listening/executors/subprocess_runner.py and "
        "tests/test_executor_gateway.py @ " + OLD_COMMIT,
        "test_lifecycle_qualifies_activates_and_registers_external_transform",
        "tests/fixtures/tools/external_transform/1.0.0/tool.py",
        "rewrite: reuse the current external protocol and runner, not the old executor",
    ),
    (
        "web_listening/executors/wrapper_protocol.py and "
        "web_listening/contracts/tool_result.py @ " + OLD_COMMIT,
        "test_runtime_commits_external_markdown_with_source_lineage",
        "tests/fixtures/tools/external_transform/1.0.0/tool.py + reused read-only "
        "src/web_listening/tool_registry/runners/subprocess.py + reused read-only "
        "src/web_listening/runtime/workflow.py",
        "rewrite: emit the current TransformOutput envelope and Result evidence",
    ),
    (
        "web_listening/blocks/document.py and tests/test_document.py @ " + OLD_COMMIT,
        "test_external_failure_preserves_source_without_acquisition_fallback",
        "tests/fixtures/tools/external_transform/1.0.0/tool.py + reused read-only "
        "src/web_listening/tool_registry/runners/subprocess.py + reused read-only "
        "src/web_listening/runtime/workflow.py",
        "preserve: original content survives conversion failure; discard Document framework",
    ),
)


def _phase15_evidence_sha256(contents: bytes) -> str:
    lf_contents = contents.replace(b"\r\n", b"\n")
    crlf_contents = lf_contents.replace(b"\n", b"\r\n")
    return hashlib.sha256(crlf_contents).hexdigest()


class _Response:
    def __init__(self, status: int, body: bytes = b"", mime: str = "text/plain"):
        self.status = status
        self.headers = {
            "content-type": mime,
            "content-length": str(len(body)),
        }
        self.peer_ip = PUBLIC_IP
        self._body = body

    def read(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]

    def close(self) -> None:
        return None


class _Transport:
    """Deterministic web_http transport; it never opens a network connection."""

    def __init__(self, body: bytes):
        self.body = body
        self.requests: list[str] = []

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> _Response:
        del timeout, addresses
        self.requests.append(url)
        if url == "https://example.test/robots.txt":
            return _Response(404)
        return _Response(200, self.body, "text/html")

    def close(self) -> None:
        return None


class _ExternalTransform:
    """Thin Registry protocol view over the existing subprocess runner."""

    def __init__(self, manifest: ToolManifest, command: tuple[str, ...]):
        self.manifest = manifest
        self._runner = SubprocessRunner(manifest, command)

    def transform(
        self, tool_input: TransformInput
    ) -> TransformOutput | TransformFailure:
        result = self._runner.invoke(tool_input)
        assert isinstance(result, (TransformOutput, TransformFailure))
        return result


def _resolver(_host: str, _port: int) -> tuple[str, ...]:
    return (PUBLIC_IP,)


def _request() -> Request:
    scope = Scope(
        seeds=(URL,),
        allowed_origins=("https://example.test",),
        include_paths=("/**",),
        content_types=(ContentType.HTML,),
    )
    budgets = Budgets(6, 4 * 1024 * 1024, 30, 2)
    skill = create_candidate(
        site_key="example",
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
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
    ).skill
    return Request(scope, skill, False, budgets)


def _stored_html() -> StoredObservation:
    digest = hashlib.sha256(HTML).hexdigest()
    identifier = artifact_id(digest, "text/html", ArtifactRole.SOURCE)
    return StoredObservation(
        Blob(digest, len(HTML), blob_relative_path(digest)),
        Artifact(identifier, digest, "text/html", ArtifactRole.SOURCE),
        Observation("observation-" + "1" * 32, identifier, URL, NOW),
        (),
        HTML,
    )


def _install(tmp_path: Path) -> tuple[ToolLifecycle, ToolManifest, tuple[str, ...]]:
    lifecycle = ToolLifecycle(tmp_path / "lifecycle")
    installed = lifecycle.install(SOURCE)
    assert installed.qualified is False
    qualified = lifecycle.qualify(ToolCategory.TRANSFORM, TOOL_ID, VERSION)
    assert qualified.qualified is True
    active = lifecycle.activate(ToolCategory.TRANSFORM, TOOL_ID, VERSION)
    command = (
        sys.executable,
        str(
            lifecycle.data_root / "tools" / "transform" / TOOL_ID / VERSION / "tool.py"
        ),
    )
    return lifecycle, active.manifest, command


def _run(tmp_path: Path, body: bytes):
    lifecycle, manifest, command = _install(tmp_path)
    transport = _Transport(body)
    acquisition = WebHttpAcquisitionTool(lambda: transport, resolver=_resolver)
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, acquisition)
    registry.register(manifest, _ExternalTransform(manifest, command))
    store = ArtifactStore(tmp_path / "artifacts")
    result = run_single_target(
        _request(), registry, store, run_id="phase-16", clock=lambda: NOW
    )
    return result, store, lifecycle, transport, registry


def test_lifecycle_qualifies_activates_and_registers_external_transform(
    tmp_path: Path,
) -> None:
    lifecycle, manifest, command = _install(tmp_path)
    current = lifecycle.active(ToolCategory.TRANSFORM, TOOL_ID)

    assert current is not None
    assert current.active is True
    assert current.manifest == manifest
    assert manifest.tool_id == TOOL_ID
    assert manifest.version == VERSION
    assert manifest.category is ToolCategory.TRANSFORM
    assert manifest.distribution.value == "installed"
    assert manifest.capabilities == frozenset({"html_to_markdown"})

    registry = Registry()
    registry.register(manifest, _ExternalTransform(manifest, command))
    output = registry.invoke(TOOL_ID, TransformInput(_stored_html()))
    assert isinstance(output, TransformOutput)
    assert output.mime_type == "text/markdown"
    assert output.source_artifact_id == _stored_html().artifact.artifact_id
    assert b"# Example" in output.body
    assert b"Hello external transform." in output.body


def test_runtime_commits_external_markdown_with_source_lineage(tmp_path: Path) -> None:
    result, store, lifecycle, transport, registry = _run(tmp_path, HTML)
    try:
        assert result.status is ResultStatus.COMPLETED
        assert tuple(item.role for item in result.artifacts) == ("source", "derived")
        source_evidence, derived_evidence = result.artifacts
        source = store.get_observation(source_evidence.observation_id)
        derived = store.get_observation(derived_evidence.observation_id)
        assert source.content == HTML
        assert source.artifact.mime_type == "text/html"
        assert derived.artifact.mime_type == "text/markdown"
        assert derived.content
        assert derived.blob.sha256 == hashlib.sha256(derived.content).hexdigest()
        assert (
            derived.lineage[0].source_observation_id
            == source.observation.observation_id
        )
        assert derived.lineage[0].source_artifact_id == source.artifact.artifact_id
        assert result.attempts[1].tool_id == TOOL_ID
        assert result.attempts[1].tool_version == VERSION
        assert result.attempts[1].outcome == "succeeded"
        assert result.attempts[1].requests == 0
        assert result.attempts[1].bytes_received == 0
        assert registry.query(category=ToolCategory.TRANSFORM) == (
            lifecycle.active(ToolCategory.TRANSFORM, TOOL_ID).manifest,
        )
        assert transport.requests == [
            "https://example.test/robots.txt",
            URL,
        ]
        assert not list(lifecycle.data_root.rglob("derived.md"))
    finally:
        store.close()


def test_external_failure_preserves_source_without_acquisition_fallback(
    tmp_path: Path,
) -> None:
    result, store, lifecycle, transport, _registry = _run(tmp_path, FAIL_HTML)
    try:
        assert result.status is ResultStatus.PARTIAL
        assert len(result.artifacts) == 1
        source = store.get_observation(result.artifacts[0].observation_id)
        assert source.content == FAIL_HTML
        assert source.artifact.role is ArtifactRole.SOURCE
        assert result.attempts[1].tool_id == TOOL_ID
        assert result.attempts[1].outcome == "failed"
        assert result.attempts[1].error is not None
        assert result.attempts[1].error.code == "external.transform_failed"
        assert result.errors == (result.attempts[1].error,)
        assert transport.requests == [
            "https://example.test/robots.txt",
            URL,
        ]
        assert not list(lifecycle.data_root.rglob("derived.md"))
    finally:
        store.close()


def test_disabled_external_transform_is_not_active_or_selectable(
    tmp_path: Path,
) -> None:
    lifecycle, _manifest, _command = _install(tmp_path)

    disabled = lifecycle.disable(ToolCategory.TRANSFORM, TOOL_ID, VERSION)

    assert disabled.disabled is True
    assert disabled.active is False
    assert lifecycle.active(ToolCategory.TRANSFORM, TOOL_ID) is None


def test_phase15_evidence_hash_is_stable_for_lf_and_crlf() -> None:
    local_bytes = (ROOT / "tests/tool_registry/test_tool_lifecycle.py").read_bytes()
    lf_bytes = local_bytes.replace(b"\r\n", b"\n")
    crlf_bytes = lf_bytes.replace(b"\n", b"\r\n")

    assert hashlib.sha256(lf_bytes).hexdigest() != LIFECYCLE_TEST_SHA256
    assert _phase15_evidence_sha256(lf_bytes) == LIFECYCLE_TEST_SHA256
    assert _phase15_evidence_sha256(crlf_bytes) == LIFECYCLE_TEST_SHA256


def test_fixture_has_no_network_or_cross_module_authority_and_records_migration() -> (
    None
):
    tree = ast.parse((SOURCE / "tool.py").read_text(encoding="utf-8"))
    import_roots = {
        node.names[0].name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }

    assert import_roots <= {
        "__future__",
        "base64",
        "hashlib",
        "html",
        "json",
        "pathlib",
        "sys",
    }
    assert all(OLD_COMMIT in row[0] for row in MIGRATION)
    assert len(MIGRATION) == 3
    assert "src/web_listening/runtime/workflow.py" in MIGRATION[1][2]
    assert "src/web_listening/tool_registry/runners/subprocess.py" in MIGRATION[1][2]
    assert "src/web_listening/runtime/workflow.py" in MIGRATION[2][2]
    assert "tests/integration/test_external_transform.py" not in MIGRATION[2][2]
    assert (
        _phase15_evidence_sha256(
            (ROOT / "tests/tool_registry/test_tool_lifecycle.py").read_bytes()
        )
        == LIFECYCLE_TEST_SHA256
    )
