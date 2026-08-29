"""Focused contract tests for the isolated external subprocess runner."""

# pylint: disable=consider-using-with,missing-function-docstring,protected-access
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from web_listening.artifact.identity import artifact_id, blob_relative_path
from web_listening.artifact.model import (
    Artifact,
    ArtifactRole,
    Blob,
    Observation,
    StoredObservation,
)
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
)
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
from web_listening.tool_registry.protocols.transform import (
    TransformFailure,
    TransformInput,
    TransformOutput,
)
from web_listening.tool_registry.runners import subprocess as subprocess_runner
from web_listening.tool_registry.runners.subprocess import (
    SubprocessLimits,
    SubprocessRunner,
)

ROOT = Path(__file__).parents[2]
FAKE_TOOL = ROOT / "tests/fixtures/tools/fake_external_tool/v1.py"


def _scope(
    content_types: tuple[ContentType, ...] = (ContentType.HTML, ContentType.FILE),
) -> Scope:
    return Scope(
        seeds=("https://example.test/",),
        allowed_origins=("https://example.test",),
        include_paths=("/**",),
        content_types=content_types,
    )


def _request(
    *,
    max_bytes: int = 4096,
    runtime_seconds: int = 2,
    content_types: tuple[ContentType, ...] = (ContentType.HTML, ContentType.FILE),
) -> Request:
    return Request(
        scope=_scope(content_types),
        site_skill={"must_not_cross_runner": True},
        explore_all_tools=False,
        budgets=Budgets(3, max_bytes, runtime_seconds, 1),
    )


def _stored_source() -> StoredObservation:
    body = b"<html><body>source</body></html>"
    digest = hashlib.sha256(body).hexdigest()
    identity = artifact_id(digest, "text/html", ArtifactRole.SOURCE)
    return StoredObservation(
        blob=Blob(digest, len(body), blob_relative_path(digest)),
        artifact=Artifact(identity, digest, "text/html", ArtifactRole.SOURCE),
        observation=Observation(
            "observation-" + "1" * 32,
            identity,
            "https://example.test/source",
            "2026-08-27T00:00:00Z",
        ),
        lineage=(),
        content=body,
    )


def _manifest(
    category: ToolCategory,
    *,
    output_bytes: int = 4096,
    runtime_seconds: int = 2,
) -> ToolManifest:
    return ToolManifest(
        tool_id="external.fake",
        version="1.0.0",
        category=category,
        distribution=ToolDistribution.INSTALLED,
        capabilities=frozenset({"fixture"}),
        limits=ToolLimits(runtime_seconds, 4096, output_bytes),
        health=HealthStatus.HEALTHY,
        qualification=QualificationStatus.QUALIFIED,
    )


def _runner(
    category: ToolCategory,
    behavior: str,
    *,
    stdout_bytes: int = 4096,
    stderr_bytes: int = 4096,
    timeout_seconds: float = 1.0,
) -> SubprocessRunner:
    return SubprocessRunner(
        _manifest(category),
        (sys.executable, str(FAKE_TOOL), behavior),
        limits=SubprocessLimits(
            timeout_seconds=timeout_seconds,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            terminate_grace_seconds=0.2,
        ),
    )


@pytest.mark.parametrize(
    ("category", "behavior", "tool_input", "output_type"),
    [
        (
            ToolCategory.DISCOVERY,
            "discovery_success",
            DiscoveryInput(
                _scope(),
                "https://example.test/feed.xml",
                b"<feed/>",
                "application/xml",
            ),
            DiscoveryOutput,
        ),
        (
            ToolCategory.ACQUISITION,
            "content_success",
            AcquisitionInput(_request(), "https://example.test/report"),
            AcquisitionOutput,
        ),
        (
            ToolCategory.TRANSFORM,
            "content_success",
            TransformInput(_stored_source()),
            TransformOutput,
        ),
    ],
)
def test_versioned_round_trip_rebuilds_all_three_protocol_results(
    category: ToolCategory, behavior: str, tool_input: object, output_type: type
) -> None:
    result = _runner(category, behavior).invoke(tool_input)

    assert type(result) is output_type
    assert result.tool_id == "external.fake"
    assert result.tool_version == "1.0.0"
    if isinstance(result, DiscoveryOutput):
        assert result.coverage == "unknown"
    if isinstance(result, (AcquisitionOutput, TransformOutput)):
        assert result.sha256 == hashlib.sha256(result.body).hexdigest()
        assert 0 <= result.runtime_ms <= 2000


def test_external_discovery_v1_cannot_claim_a_coverage_field(monkeypatch) -> None:
    runner = _runner(ToolCategory.DISCOVERY, "discovery_success")
    payload = {
        "protocol_version": "web-listening-external-tool.v1",
        "category": "discovery",
        "status": "success",
        "tool_id": "external.fake",
        "tool_version": "1.0.0",
        "result": {
            "candidates": ["https://example.test/report"],
            "discovered_from": ["https://example.test/feed.xml"],
            "coverage": "complete",
        },
    }
    monkeypatch.setattr(
        runner,
        "_execute",
        lambda *_args: (None, json.dumps(payload).encode("utf-8")),
    )

    result = runner.invoke(
        DiscoveryInput(
            _scope(),
            "https://example.test/feed.xml",
            b"<feed/>",
            "application/xml",
        )
    )

    assert result == DiscoveryFailure("external.fake", "1.0.0", "runner.protocol_error")


@pytest.mark.parametrize(
    ("category", "tool_input", "failure_type"),
    [
        (ToolCategory.DISCOVERY, DiscoveryInput(_scope()), DiscoveryFailure),
        (
            ToolCategory.ACQUISITION,
            AcquisitionInput(_request(), "https://example.test/report"),
            AcquisitionFailure,
        ),
        (ToolCategory.TRANSFORM, TransformInput(_stored_source()), TransformFailure),
    ],
)
def test_external_safe_failure_reuses_category_protocol(
    category: ToolCategory, tool_input: object, failure_type: type
) -> None:
    result = _runner(category, "failed").invoke(tool_input)

    assert type(result) is failure_type
    assert result.code == "external.unavailable"


@pytest.mark.parametrize(
    ("category", "tool_input", "failure_type"),
    [
        (ToolCategory.DISCOVERY, DiscoveryInput(_scope()), DiscoveryFailure),
        (
            ToolCategory.ACQUISITION,
            AcquisitionInput(_request(), "https://example.test/report"),
            AcquisitionFailure,
        ),
        (ToolCategory.TRANSFORM, TransformInput(_stored_source()), TransformFailure),
    ],
)
def test_external_rejection_reuses_category_failure_and_safe_code(
    category: ToolCategory, tool_input: object, failure_type: type
) -> None:
    result = _runner(category, "rejected").invoke(tool_input)

    assert type(result) is failure_type
    assert result.code == "external.unsupported"


def test_request_envelope_is_versioned_and_carries_only_attempt_input() -> None:
    acquisition = json.loads(
        subprocess_runner._encode_request(
            _manifest(ToolCategory.ACQUISITION),
            AcquisitionInput(_request(), "https://example.test/report"),
        )
    )
    transform = json.loads(
        subprocess_runner._encode_request(
            _manifest(ToolCategory.TRANSFORM), TransformInput(_stored_source())
        )
    )
    rendered = json.dumps((acquisition, transform), sort_keys=True).lower()

    assert acquisition["protocol_version"] == "web-listening-external-tool.v1"
    assert acquisition["attempt_directory"] == "."
    assert set(acquisition) == {
        "protocol_version",
        "category",
        "tool_id",
        "tool_version",
        "attempt_directory",
        "input",
    }
    assert acquisition["input"]["target_url"] == "https://example.test/report"
    assert transform["input"]["source_body_base64"]
    for forbidden in (
        "must_not_cross_runner",
        "site_skill",
        "manifest",
        "database",
        "artifact_store",
        "relative_path",
        "observation_id",
    ):
        assert forbidden not in rendered


def test_acquisition_wire_uses_effective_manifest_and_local_limits(
    monkeypatch,
) -> None:
    observed: list[dict[str, object]] = []
    runner = SubprocessRunner(
        _manifest(
            ToolCategory.ACQUISITION,
            output_bytes=4096,
            runtime_seconds=2,
        ),
        (sys.executable, str(FAKE_TOOL), "content_success"),
        limits=SubprocessLimits(timeout_seconds=0.75),
    )

    def capture_wire(wire: bytes, *_args) -> tuple[str, bytes]:
        observed.append(json.loads(wire)["input"]["limits"])
        return "runner.timeout", b""

    monkeypatch.setattr(runner, "_execute", capture_wire)
    runner.invoke(
        AcquisitionInput(
            _request(max_bytes=1_000_000, runtime_seconds=60),
            "https://example.test/report",
        )
    )

    assert observed == [
        {
            "max_requests": 3,
            "max_bytes": 4096,
            "max_runtime_seconds": 0.75,
        }
    ]


def test_timeout_terminates_process_and_returns_stable_failure(monkeypatch) -> None:
    terminated: list[int] = []
    original = subprocess.Popen.terminate

    def observed_terminate(process: subprocess.Popen[bytes]) -> None:
        terminated.append(process.pid)
        original(process)

    monkeypatch.setattr(subprocess.Popen, "terminate", observed_terminate)
    started = time.monotonic()
    result = _runner(ToolCategory.ACQUISITION, "timeout", timeout_seconds=0.2).invoke(
        AcquisitionInput(_request(), "https://example.test/report")
    )

    assert result == AcquisitionFailure("external.fake", "1.0.0", "runner.timeout")
    assert terminated
    assert time.monotonic() - started < 2


def test_request_runtime_budget_sets_parent_deadline() -> None:
    started = time.monotonic()
    result = _runner(ToolCategory.ACQUISITION, "timeout", timeout_seconds=5).invoke(
        AcquisitionInput(_request(runtime_seconds=1), "https://example.test/report")
    )

    assert result == AcquisitionFailure("external.fake", "1.0.0", "runner.timeout")
    assert time.monotonic() - started < 1.7


@pytest.mark.parametrize(
    ("behavior", "stdout_bytes", "stderr_bytes", "code"),
    [
        ("nonzero", 4096, 4096, "runner.nonzero_exit"),
        ("stdout_large", 256, 4096, "runner.stdout_limit"),
        ("stderr_large", 4096, 256, "runner.stderr_limit"),
        ("malformed_json", 4096, 4096, "runner.protocol_error"),
    ],
)
def test_process_and_framing_failures_are_bounded_and_secret_free(
    behavior: str, stdout_bytes: int, stderr_bytes: int, code: str
) -> None:
    result = _runner(
        ToolCategory.ACQUISITION,
        behavior,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
        timeout_seconds=0.5,
    ).invoke(AcquisitionInput(_request(), "https://example.test/report"))

    assert result == AcquisitionFailure("external.fake", "1.0.0", code)
    assert "fixture-secret" not in str(result)


@pytest.mark.parametrize(
    "behavior",
    ["path_traversal", "absolute_path", "windows_absolute_path", "symlink"],
)
def test_output_path_must_be_portable_regular_content_inside_attempt(
    behavior: str,
) -> None:
    result = _runner(ToolCategory.ACQUISITION, behavior).invoke(
        AcquisitionInput(_request(), "https://example.test/report")
    )

    assert result == AcquisitionFailure(
        "external.fake", "1.0.0", "runner.output_path_invalid"
    )


@pytest.mark.parametrize(
    "behavior",
    [
        "hash_mismatch",
        "size_mismatch",
        "mime_mismatch",
        "url_mismatch",
        "identity_mismatch",
    ],
)
def test_parent_rejects_untrusted_content_and_identity_claims(behavior: str) -> None:
    result = _runner(ToolCategory.ACQUISITION, behavior).invoke(
        AcquisitionInput(_request(), "https://example.test/report")
    )

    assert result == AcquisitionFailure(
        "external.fake", "1.0.0", "runner.output_mismatch"
    )


def test_output_file_limit_is_applied_while_parent_reads() -> None:
    result = SubprocessRunner(
        _manifest(ToolCategory.ACQUISITION, output_bytes=16),
        (sys.executable, str(FAKE_TOOL), "content_success"),
        limits=SubprocessLimits(timeout_seconds=1),
    ).invoke(AcquisitionInput(_request(), "https://example.test/report"))

    assert result == AcquisitionFailure("external.fake", "1.0.0", "runner.output_limit")


def test_request_byte_budget_is_the_parent_read_cap(monkeypatch) -> None:
    observed_caps: list[int] = []
    original = subprocess_runner._read_output

    def observed_read(root: Path, value: object, limit: int) -> bytes:
        observed_caps.append(limit)
        return original(root, value, limit)

    monkeypatch.setattr(subprocess_runner, "_read_output", observed_read)
    result = _runner(ToolCategory.ACQUISITION, "content_success").invoke(
        AcquisitionInput(_request(max_bytes=16), "https://example.test/report")
    )

    assert result == AcquisitionFailure("external.fake", "1.0.0", "runner.output_limit")
    assert observed_caps == [16]


def test_parent_rejects_pdf_bytes_claimed_as_html_for_html_only_request() -> None:
    result = _runner(ToolCategory.ACQUISITION, "pdf_mime_mismatch").invoke(
        AcquisitionInput(
            _request(content_types=(ContentType.HTML,)),
            "https://example.test/report",
        )
    )

    assert result == AcquisitionFailure(
        "external.fake", "1.0.0", "runner.output_mismatch"
    )


def test_parent_rejects_non_pdf_bytes_claimed_as_pdf() -> None:
    result = _runner(ToolCategory.ACQUISITION, "non_pdf_claimed_pdf").invoke(
        AcquisitionInput(_request(), "https://example.test/report")
    )

    assert result == AcquisitionFailure(
        "external.fake", "1.0.0", "runner.output_mismatch"
    )


@pytest.mark.parametrize("behavior", ["content_success", "malformed_json", "timeout"])
def test_attempt_directory_is_cleaned_after_every_outcome(
    behavior: str, monkeypatch
) -> None:
    created: list[Path] = []
    original = subprocess_runner.tempfile.TemporaryDirectory

    def recording_directory(*args, **kwargs):
        directory = original(*args, **kwargs)
        created.append(Path(directory.name))
        return directory

    monkeypatch.setattr(
        subprocess_runner.tempfile, "TemporaryDirectory", recording_directory
    )
    result = _runner(ToolCategory.ACQUISITION, behavior, timeout_seconds=0.2).invoke(
        AcquisitionInput(_request(), "https://example.test/report")
    )

    assert isinstance(result, (AcquisitionOutput, AcquisitionFailure))
    assert len(created) == 1
    assert not created[0].exists()


def test_attempt_directory_oserror_returns_stable_failure(monkeypatch) -> None:
    def unavailable_directory(*_args, **_kwargs):
        raise OSError("private host path")

    monkeypatch.setattr(
        subprocess_runner.tempfile, "TemporaryDirectory", unavailable_directory
    )

    result = _runner(ToolCategory.ACQUISITION, "content_success").invoke(
        AcquisitionInput(_request(), "https://example.test/report")
    )

    assert result == AcquisitionFailure(
        "external.fake", "1.0.0", "runner.startup_error"
    )
    assert "private host path" not in str(result)


def test_runner_preserves_host_executable_search_path(monkeypatch) -> None:
    monkeypatch.setenv("PATH", "fixture-tool-search-path")

    assert subprocess_runner._minimal_environment()["PATH"] == (
        "fixture-tool-search-path"
    )


def test_attempt_directory_cleanup_oserror_is_not_a_startup_error(
    monkeypatch, tmp_path: Path
) -> None:
    class CleanupFailure:
        """Temporary-directory context whose cleanup fails."""

        def __enter__(self) -> str:
            return str(tmp_path)

        def __exit__(self, *_args) -> None:
            raise OSError("private cleanup path")

    monkeypatch.setattr(
        subprocess_runner.tempfile,
        "TemporaryDirectory",
        lambda **_kwargs: CleanupFailure(),
    )

    result = _runner(ToolCategory.ACQUISITION, "content_success").invoke(
        AcquisitionInput(_request(), "https://example.test/report")
    )

    assert result == AcquisitionFailure(
        "external.fake", "1.0.0", "runner.cleanup_error"
    )
    assert "private cleanup path" not in str(result)


def test_fake_fixture_is_versioned_and_has_no_network_code() -> None:
    source = FAKE_TOOL.read_text(encoding="utf-8")

    assert 'PROTOCOL_VERSION = "web-listening-external-tool.v1"' in source
    assert '"status": "success"' in source
    assert '"status": "succeeded"' not in source
    for token in ("socket", "requests", "httpx", "urlopen"):
        assert token not in source


def test_runner_does_not_import_final_storage_or_orchestration_authority() -> None:
    path = ROOT / "src/web_listening/tool_registry/runners/subprocess.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }

    assert imports.isdisjoint(
        {
            "web_listening.artifact.store",
            "web_listening.result",
            "web_listening.runtime",
            "web_listening.site_skill",
            "web_listening.tool_registry.registry",
        }
    )
