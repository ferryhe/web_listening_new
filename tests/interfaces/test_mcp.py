"""Focused contract tests for the Phase 11 thin MCP adapter."""

# pylint: disable=consider-using-from-import,duplicate-code,import-error
# pylint: disable=missing-function-docstring
# pylint: disable=too-many-locals,wrong-import-position

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="install the optional web-listening[mcp] extra")

import anyio
from mcp import ClientSession, McpError, StdioServerParameters
from mcp.client.stdio import stdio_client

import web_listening.interfaces.mcp as mcp_interface
from web_listening.artifact.model import ArtifactRole
from web_listening.artifact.observation import ObservationProposal
from web_listening.artifact.store import ArtifactStore
from web_listening.result.model import Result

ROOT = Path(__file__).parents[2]
SITE_SKILL_CATALOG = ROOT / "tests" / "live" / "catalog" / "site_skill_cases.json"
TOOL_NAMES = {
    "web_listening_acquire",
    "web_listening_get_job",
    "web_listening_read_artifact",
    "web_listening_validate_site_skill",
}

EXPECTED_STRING_ARRAY = {
    "type": "array",
    "items": {"type": "string"},
    "minItems": 1,
}
EXPECTED_SCOPE_SCHEMA = {
    "type": "object",
    "properties": {
        "seeds": EXPECTED_STRING_ARRAY,
        "allowed_origins": EXPECTED_STRING_ARRAY,
        "include_paths": EXPECTED_STRING_ARRAY,
        "content_types": {
            "type": "array",
            "items": {"enum": ["html", "file"]},
            "minItems": 1,
        },
    },
    "required": ["seeds", "allowed_origins", "include_paths", "content_types"],
    "additionalProperties": False,
}
EXPECTED_BUDGET_SCHEMA = {
    "type": "object",
    "properties": {
        "max_requests": {"type": "integer", "minimum": 1},
        "max_bytes": {"type": "integer", "minimum": 1},
        "max_runtime_seconds": {"type": "integer", "minimum": 1},
        "max_tool_attempts_per_target": {"type": "integer", "minimum": 1},
    },
    "required": [
        "max_requests",
        "max_bytes",
        "max_runtime_seconds",
        "max_tool_attempts_per_target",
    ],
    "additionalProperties": False,
}
EXPECTED_SITE_SKILL_SCHEMA = {
    "type": "object",
    "properties": {
        "site_key": {"type": "string"},
        "version": {"type": "integer", "minimum": 1},
        "previous_digest": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "scope": EXPECTED_SCOPE_SCHEMA,
        "budgets": EXPECTED_BUDGET_SCHEMA,
        "tool": {
            "type": "object",
            "properties": {
                "tool_id": {"type": "string"},
                "version": {"type": "string"},
                "category": {"enum": ["discovery", "acquisition", "transform"]},
                "capabilities": EXPECTED_STRING_ARRAY,
                "recipe_id": {"type": "string"},
            },
            "required": ["tool_id", "version", "category", "capabilities"],
            "additionalProperties": False,
        },
        "success_checks": {
            "type": "object",
            "properties": {
                "allowed_mime_types": EXPECTED_STRING_ARRAY,
                "minimum_words": {"type": "integer", "minimum": 1},
            },
            "required": ["allowed_mime_types", "minimum_words"],
            "additionalProperties": False,
        },
        "verified_at": {"type": "string"},
        "digest": {"type": "string"},
    },
    "required": [
        "site_key",
        "version",
        "previous_digest",
        "scope",
        "budgets",
        "tool",
        "success_checks",
        "verified_at",
        "digest",
    ],
    "additionalProperties": False,
}
EXPECTED_SAFE_ERROR_SCHEMA = {
    "type": "object",
    "properties": {
        "code": {"type": "string"},
        "message": {"type": "string"},
        "details": {
            "type": "object",
            "additionalProperties": {"type": "string"},
        },
    },
    "required": ["code", "message", "details"],
    "additionalProperties": False,
}
EXPECTED_ERROR_ENVELOPE_SCHEMA = {
    "type": "object",
    "properties": {"error": EXPECTED_SAFE_ERROR_SCHEMA},
    "required": ["error"],
    "additionalProperties": False,
}
EXPECTED_USAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "requests": {"type": "integer", "minimum": 0},
        "bytes_received": {"type": "integer", "minimum": 0},
        "runtime_ms": {"type": "integer", "minimum": 0},
        "tool_attempts": {"type": "integer", "minimum": 0},
    },
    "required": ["requests", "bytes_received", "runtime_ms", "tool_attempts"],
    "additionalProperties": False,
}
EXPECTED_SITE_SKILL_EVIDENCE_SCHEMA = {
    "type": "object",
    "properties": {
        "version": {"type": "string"},
        "sha256": {"type": "string"},
    },
    "required": ["version", "sha256"],
    "additionalProperties": False,
}
EXPECTED_LINEAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "lineage_id": {"type": "string"},
        "observation_id": {"type": "string"},
        "artifact_id": {"type": "string"},
        "relation": {"const": "derived_from"},
        "source_observation_id": {"type": "string"},
        "source_artifact_id": {"type": "string"},
    },
    "required": [
        "lineage_id",
        "observation_id",
        "artifact_id",
        "relation",
        "source_observation_id",
        "source_artifact_id",
    ],
    "additionalProperties": False,
}
EXPECTED_ARTIFACT_EVIDENCE_SCHEMA = {
    "type": "object",
    "properties": {
        "artifact_id": {"type": "string"},
        "observation_id": {"type": "string"},
        "role": {"enum": ["source", "derived"]},
        "source_url": {"type": "string"},
        "observed_at": {"type": "string"},
        "mime_type": {"type": "string"},
        "size_bytes": {"type": "integer", "minimum": 0},
        "sha256": {"type": "string"},
        "lineage": {"type": "array", "items": EXPECTED_LINEAGE_SCHEMA},
    },
    "required": [
        "artifact_id",
        "observation_id",
        "role",
        "source_url",
        "observed_at",
        "mime_type",
        "size_bytes",
        "sha256",
        "lineage",
    ],
    "additionalProperties": False,
}
EXPECTED_ATTEMPT_SCHEMA = {
    "type": "object",
    "properties": {
        "schema_version": {"const": "web-listening-attempt.v1"},
        "order": {"type": "integer", "minimum": 0},
        "attempt_id": {"type": "string"},
        "outcome": {"enum": ["succeeded", "failed", "skipped"]},
        "tool_id": {"type": "string"},
        "tool_version": {"type": "string"},
        "started_at": {"type": "string"},
        "finished_at": {"type": "string"},
        "requested_url": {"type": "string"},
        "final_url": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "http_status": {
            "anyOf": [
                {"type": "integer", "minimum": 100, "maximum": 599},
                {"type": "null"},
            ]
        },
        "error": {"anyOf": [EXPECTED_SAFE_ERROR_SCHEMA, {"type": "null"}]},
        "requests": {"type": "integer", "minimum": 0},
        "bytes_received": {"type": "integer", "minimum": 0},
        "runtime_ms": {"type": "integer", "minimum": 0},
    },
    "required": [
        "schema_version",
        "order",
        "attempt_id",
        "outcome",
        "tool_id",
        "tool_version",
        "started_at",
        "finished_at",
        "requested_url",
        "final_url",
        "http_status",
        "error",
        "requests",
        "bytes_received",
        "runtime_ms",
    ],
    "additionalProperties": False,
}
EXPECTED_REDIRECT_SCHEMA = {
    "type": "object",
    "properties": {
        "order": {"type": "integer", "minimum": 0},
        "from_url": {"type": "string"},
        "to_url": {"type": "string"},
        "http_status": {"type": "integer", "minimum": 300, "maximum": 399},
        "decision": {"enum": ["followed", "rejected"]},
    },
    "required": ["order", "from_url", "to_url", "http_status", "decision"],
    "additionalProperties": False,
}
EXPECTED_MANIFEST_SCHEMA = {
    "type": "object",
    "properties": {
        "schema_version": {"const": "web-listening-manifest.v1"},
        "run_id": {"type": "string"},
        "generated_at": {"type": "string"},
        "requested_url": {"type": "string"},
        "current_url": {"type": "string"},
        "final_url": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "http_status": {
            "anyOf": [
                {"type": "integer", "minimum": 100, "maximum": 599},
                {"type": "null"},
            ]
        },
        "mime_type": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "size_bytes": {
            "anyOf": [
                {"type": "integer", "minimum": 0},
                {"type": "null"},
            ]
        },
        "sha256": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "tool_id": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "tool_version": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "redirects": {"type": "array", "items": EXPECTED_REDIRECT_SCHEMA},
        "site_skill": {
            "anyOf": [EXPECTED_SITE_SKILL_EVIDENCE_SCHEMA, {"type": "null"}]
        },
        "attempts": {"type": "array", "items": EXPECTED_ATTEMPT_SCHEMA},
        "artifacts": {
            "type": "array",
            "items": EXPECTED_ARTIFACT_EVIDENCE_SCHEMA,
        },
        "usage": EXPECTED_USAGE_SCHEMA,
    },
    "required": [
        "schema_version",
        "run_id",
        "generated_at",
        "requested_url",
        "current_url",
        "final_url",
        "http_status",
        "mime_type",
        "size_bytes",
        "sha256",
        "tool_id",
        "tool_version",
        "redirects",
        "site_skill",
        "attempts",
        "artifacts",
        "usage",
    ],
    "additionalProperties": False,
}
EXPECTED_RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "schema_version": {"const": "web-listening-result.v1"},
        "status": {"enum": ["completed", "partial", "rejected", "failed"]},
        "artifacts": {
            "type": "array",
            "items": EXPECTED_ARTIFACT_EVIDENCE_SCHEMA,
        },
        "manifest": EXPECTED_MANIFEST_SCHEMA,
        "site_skill_used": {
            "anyOf": [EXPECTED_SITE_SKILL_EVIDENCE_SCHEMA, {"type": "null"}]
        },
        "site_skill_update": {
            "anyOf": [EXPECTED_SITE_SKILL_EVIDENCE_SCHEMA, {"type": "null"}]
        },
        "attempts": {"type": "array", "items": EXPECTED_ATTEMPT_SCHEMA},
        "errors": {"type": "array", "items": EXPECTED_SAFE_ERROR_SCHEMA},
        "usage": EXPECTED_USAGE_SCHEMA,
    },
    "required": [
        "schema_version",
        "status",
        "artifacts",
        "manifest",
        "site_skill_used",
        "site_skill_update",
        "attempts",
        "errors",
        "usage",
    ],
    "additionalProperties": False,
}
EXPECTED_JOB_SCHEMA = {
    "type": "object",
    "properties": {
        "job_id": {"type": "string"},
        "status": {
            "enum": [
                "submitted",
                "running",
                "completed",
                "partial",
                "rejected",
                "failed",
            ]
        },
        "submitted_at": {"type": "string"},
        "started_at": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "finished_at": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "result": {"anyOf": [EXPECTED_RESULT_SCHEMA, {"type": "null"}]},
        "failure_code": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
    "required": [
        "job_id",
        "status",
        "submitted_at",
        "started_at",
        "finished_at",
        "result",
        "failure_code",
    ],
    "additionalProperties": False,
}
EXPECTED_ARTIFACT_SCHEMA = {
    "type": "object",
    "properties": {
        "artifact_id": {"type": "string"},
        "blob_sha256": {"type": "string"},
        "size_bytes": {"type": "integer", "minimum": 0},
        "mime_type": {"type": "string"},
        "content_encoding": {"const": "base64"},
        "content": {"type": "string"},
    },
    "required": [
        "artifact_id",
        "blob_sha256",
        "size_bytes",
        "mime_type",
        "content_encoding",
        "content",
    ],
    "additionalProperties": False,
}


def _expected_output_schema(success: dict[str, object]) -> dict[str, object]:
    return {"oneOf": [success, EXPECTED_ERROR_ENVELOPE_SCHEMA]}


def _site_skill() -> dict[str, object]:
    payload = json.loads(SITE_SKILL_CATALOG.read_text(encoding="utf-8"))
    return next(
        item["site_skill"] for item in payload["cases"] if item["site_key"] == "ipcc"
    )


def _request() -> dict[str, object]:
    return {
        "scope": {
            "seeds": ["https://www.ipcc.ch/"],
            "allowed_origins": ["https://www.ipcc.ch"],
            "include_paths": ["/**"],
            "content_types": ["html"],
        },
        "site_skill": _site_skill(),
        "explore_all_tools": False,
        # The valid Site Skill has a wider request budget. Runtime rejects this
        # before transport, giving the offline stdio test a unified Result.
        "budgets": {
            "max_requests": 1,
            "max_bytes": 2 * 1024 * 1024,
            "max_runtime_seconds": 30,
            "max_tool_attempts_per_target": 1,
        },
    }


def _seed_artifact(data_dir: Path) -> tuple[str, bytes, str]:
    content = b"\x00phase-11\xff"
    digest = hashlib.sha256(content).hexdigest()
    data_dir.mkdir(parents=True)
    store = ArtifactStore(data_dir / "artifacts")
    try:
        stored = store.commit_observation(
            ObservationProposal(
                content=content,
                sha256=digest,
                size_bytes=len(content),
                mime_type="application/octet-stream",
                source_url="https://www.ipcc.ch/",
                observed_at="2026-08-26T12:00:00Z",
                role=ArtifactRole.SOURCE,
            )
        )
    finally:
        store.close()
    return stored.artifact.artifact_id, content, digest


def _payload(result: object) -> dict[str, object]:
    structured = getattr(result, "structuredContent")
    assert isinstance(structured, dict)
    return structured


async def _stdio_scenario(data_dir: Path) -> dict[str, object]:
    artifact_id, artifact_content, artifact_sha256 = _seed_artifact(data_dir)
    environment = {
        "PYTHONPATH": str(ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")
    }
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "web_listening.interfaces.mcp",
            "--data-dir",
            str(data_dir),
        ],
        cwd=ROOT,
        env=environment,
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            initialized = await session.initialize()
            listed = await session.list_tools()
            by_name = {tool.name: tool for tool in listed.tools}

            acquire = await session.call_tool(
                "web_listening_acquire", arguments=_request()
            )
            acquire_payload = _payload(acquire)
            result = Result.from_dict(acquire_payload["result"])
            assert acquire.isError is False
            assert acquire_payload["status"] == "rejected"
            assert result.status.value == "rejected"
            assert result.errors[0].code == "policy.budget_expansion"

            get_job = await session.call_tool(
                "web_listening_get_job",
                arguments={"job_id": acquire_payload["job_id"]},
            )
            assert get_job.isError is False
            assert _payload(get_job) == acquire_payload

            read_artifact = await session.call_tool(
                "web_listening_read_artifact",
                arguments={"artifact_id": artifact_id},
            )
            artifact_payload = _payload(read_artifact)
            assert read_artifact.isError is False
            assert artifact_payload == {
                "artifact_id": artifact_id,
                "blob_sha256": artifact_sha256,
                "size_bytes": len(artifact_content),
                "mime_type": "application/octet-stream",
                "content_encoding": "base64",
                "content": base64.b64encode(artifact_content).decode("ascii"),
            }

            validate = await session.call_tool(
                "web_listening_validate_site_skill",
                arguments={"site_skill": _site_skill()},
            )
            assert validate.isError is False
            assert _payload(validate) == _site_skill()

            invalid = _request()
            invalid["private_token"] = "Bearer SECRET123"
            invalid_call = await session.call_tool(
                "web_listening_acquire", arguments=invalid
            )
            invalid_payload = _payload(invalid_call)
            assert invalid_call.isError is True
            assert invalid_payload["error"]["code"] == "request.unknown_field"
            assert "SECRET123" not in str(invalid_call)

            missing = await session.call_tool(
                "web_listening_get_job", arguments={"job_id": "job-missing"}
            )
            assert missing.isError is True
            assert _payload(missing) == {
                "error": {
                    "code": "job.not_found",
                    "message": "Resource was not found.",
                    "details": {},
                }
            }
            assert str(data_dir) not in str(missing)

            unknown = await session.call_tool(
                "web_listening_discover", arguments={"url": "https://example.com"}
            )
            assert unknown.isError is True
            assert _payload(unknown)["error"]["code"] == "mcp.tool_not_found"

            resource_error = prompt_error = None
            try:
                await session.list_resources()
            except McpError as exc:
                resource_error = exc
            try:
                await session.list_prompts()
            except McpError as exc:
                prompt_error = exc

    return {
        "initialized": initialized,
        "by_name": by_name,
        "resource_error": resource_error,
        "prompt_error": prompt_error,
    }


def test_complete_client_stdio_server_boundary(tmp_path: Path) -> None:
    evidence = anyio.run(_stdio_scenario, tmp_path / "runtime-data")
    initialized = evidence["initialized"]
    by_name = evidence["by_name"]

    assert set(by_name) == TOOL_NAMES
    assert initialized.capabilities.tools is not None
    assert initialized.capabilities.resources is None
    assert initialized.capabilities.prompts is None
    assert evidence["resource_error"] is not None
    assert evidence["prompt_error"] is not None

    assert by_name["web_listening_acquire"].inputSchema == {
        "type": "object",
        "properties": {
            "scope": EXPECTED_SCOPE_SCHEMA,
            "site_skill": {"anyOf": [EXPECTED_SITE_SKILL_SCHEMA, {"type": "null"}]},
            "explore_all_tools": {"type": "boolean", "default": False},
            "budgets": EXPECTED_BUDGET_SCHEMA,
        },
        "required": ["scope", "budgets"],
        "additionalProperties": False,
    }
    assert by_name["web_listening_get_job"].inputSchema == {
        "type": "object",
        "properties": {"job_id": {"type": "string"}},
        "required": ["job_id"],
        "additionalProperties": False,
    }
    assert by_name["web_listening_read_artifact"].inputSchema == {
        "type": "object",
        "properties": {"artifact_id": {"type": "string"}},
        "required": ["artifact_id"],
        "additionalProperties": False,
    }
    assert by_name["web_listening_validate_site_skill"].inputSchema == {
        "type": "object",
        "properties": {"site_skill": EXPECTED_SITE_SKILL_SCHEMA},
        "required": ["site_skill"],
        "additionalProperties": False,
    }

    assert by_name["web_listening_acquire"].outputSchema == _expected_output_schema(
        EXPECTED_JOB_SCHEMA
    )
    assert by_name["web_listening_get_job"].outputSchema == _expected_output_schema(
        EXPECTED_JOB_SCHEMA
    )
    assert by_name[
        "web_listening_read_artifact"
    ].outputSchema == _expected_output_schema(EXPECTED_ARTIFACT_SCHEMA)
    assert by_name[
        "web_listening_validate_site_skill"
    ].outputSchema == _expected_output_schema(EXPECTED_SITE_SKILL_SCHEMA)


def test_source_calls_only_public_runtime_and_site_skill_boundaries() -> None:
    source = Path(mcp_interface.__file__).read_text(encoding="utf-8")
    forbidden = (
        "from web_listening.tool_registry",
        "GovernedAccessGateway",
        "from web_listening.artifact.store",
        "JobRepository",
        "Registry",
        "runtime.workflow",
        "acquisition.builtins",
        "http.client",
        "playwright",
        "CloakBrowser",
    )

    assert "runtime.run(" in source
    assert "runtime.get_job(" in source
    assert "runtime.read_artifact(" in source
    assert "site_skill_from_mapping(" in source
    assert "site_skill_to_mapping(" in source
    assert all(value not in source for value in forbidden)


def test_pyproject_adds_only_the_dedicated_mcp_extra() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]

    assert project["dependencies"] == []
    assert project["optional-dependencies"]["mcp"] == ["mcp>=1.27.2,<2"]
    assert {
        item.split(">=", maxsplit=1)[0]
        for item in project["optional-dependencies"]["dev"]
    } == {
        "black",
        "isort",
        "pylint",
        "pytest",
    }
    assert project["scripts"] == {
        "web-listening": "web_listening.interfaces.cli:main",
    }


def test_core_import_succeeds_when_mcp_dependency_is_blocked() -> None:
    script = """
import importlib.abc
import sys

class BlockMcp(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'mcp' or fullname.startswith('mcp.'):
            raise ModuleNotFoundError('mcp blocked')
        return None

sys.meta_path.insert(0, BlockMcp())
import web_listening
import web_listening.request
import web_listening.runtime
assert 'mcp' not in sys.modules
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = (
        str(ROOT / "src") + os.pathsep + environment.get("PYTHONPATH", "")
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
