"""Thin MCP adapter over the public Runtime and Site Skill services."""

# pylint: disable=duplicate-code,too-many-return-statements

from __future__ import annotations

import argparse
import base64
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path

import anyio  # pylint: disable=import-error
from mcp import types  # pylint: disable=import-error
from mcp.server import Server  # pylint: disable=import-error
from mcp.server.stdio import stdio_server  # pylint: disable=import-error

from web_listening.artifact.model import StoredArtifact
from web_listening.request.model import RequestValidationError
from web_listening.request.validate import request_from_mapping
from web_listening.result.errors import SafeError
from web_listening.runtime.jobs import Job
from web_listening.runtime.service import RuntimeService
from web_listening.site_skill.model import SiteSkillError
from web_listening.site_skill.validate import (
    site_skill_from_mapping,
    site_skill_to_mapping,
)

RuntimeProvider = Callable[[], RuntimeService]

_STRING_ARRAY = {"type": "array", "items": {"type": "string"}, "minItems": 1}
_SCOPE_SCHEMA = {
    "type": "object",
    "properties": {
        "seeds": _STRING_ARRAY,
        "allowed_origins": _STRING_ARRAY,
        "include_paths": _STRING_ARRAY,
        "content_types": {
            "type": "array",
            "items": {"enum": ["html", "file"]},
            "minItems": 1,
        },
    },
    "required": ["seeds", "allowed_origins", "include_paths", "content_types"],
    "additionalProperties": False,
}
_BUDGET_SCHEMA = {
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
_SITE_SKILL_SCHEMA = {
    "type": "object",
    "properties": {
        "site_key": {"type": "string"},
        "version": {"type": "integer", "minimum": 1},
        "previous_digest": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "scope": _SCOPE_SCHEMA,
        "budgets": _BUDGET_SCHEMA,
        "tool": {
            "type": "object",
            "properties": {
                "tool_id": {"type": "string"},
                "version": {"type": "string"},
                "category": {"enum": ["discovery", "acquisition", "transform"]},
                "capabilities": _STRING_ARRAY,
                "recipe_id": {"type": "string"},
            },
            "required": ["tool_id", "version", "category", "capabilities"],
            "additionalProperties": False,
        },
        "success_checks": {
            "type": "object",
            "properties": {
                "allowed_mime_types": _STRING_ARRAY,
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
_SAFE_ERROR_SCHEMA = {
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
_USAGE_SCHEMA = {
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
_SITE_SKILL_EVIDENCE_SCHEMA = {
    "type": "object",
    "properties": {
        "version": {"type": "string"},
        "sha256": {"type": "string"},
    },
    "required": ["version", "sha256"],
    "additionalProperties": False,
}
_LINEAGE_SCHEMA = {
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
_ARTIFACT_EVIDENCE_SCHEMA = {
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
        "lineage": {"type": "array", "items": _LINEAGE_SCHEMA},
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
_ATTEMPT_SCHEMA = {
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
        "error": {"anyOf": [_SAFE_ERROR_SCHEMA, {"type": "null"}]},
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
_REDIRECT_SCHEMA = {
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
_MANIFEST_SCHEMA = {
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
        "redirects": {"type": "array", "items": _REDIRECT_SCHEMA},
        "site_skill": {"anyOf": [_SITE_SKILL_EVIDENCE_SCHEMA, {"type": "null"}]},
        "attempts": {"type": "array", "items": _ATTEMPT_SCHEMA},
        "artifacts": {"type": "array", "items": _ARTIFACT_EVIDENCE_SCHEMA},
        "usage": _USAGE_SCHEMA,
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
_RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "schema_version": {"const": "web-listening-result.v1"},
        "status": {"enum": ["completed", "partial", "rejected", "failed"]},
        "artifacts": {"type": "array", "items": _ARTIFACT_EVIDENCE_SCHEMA},
        "manifest": _MANIFEST_SCHEMA,
        "site_skill_used": {"anyOf": [_SITE_SKILL_EVIDENCE_SCHEMA, {"type": "null"}]},
        "site_skill_update": {"anyOf": [_SITE_SKILL_EVIDENCE_SCHEMA, {"type": "null"}]},
        "attempts": {"type": "array", "items": _ATTEMPT_SCHEMA},
        "errors": {"type": "array", "items": _SAFE_ERROR_SCHEMA},
        "usage": _USAGE_SCHEMA,
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
_ERROR_SCHEMA = {
    "type": "object",
    "properties": {"error": _SAFE_ERROR_SCHEMA},
    "required": ["error"],
    "additionalProperties": False,
}
_JOB_SCHEMA = {
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
        "result": {"anyOf": [_RESULT_SCHEMA, {"type": "null"}]},
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
_ARTIFACT_SCHEMA = {
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


def _output_schema(success: dict[str, object]) -> dict[str, object]:
    return {"oneOf": [success, _ERROR_SCHEMA]}


_TOOLS = (
    types.Tool(
        name="web_listening_acquire",
        description="Run one governed Request through the public Runtime service.",
        inputSchema={
            "type": "object",
            "properties": {
                "scope": _SCOPE_SCHEMA,
                "site_skill": {"anyOf": [_SITE_SKILL_SCHEMA, {"type": "null"}]},
                "explore_all_tools": {"type": "boolean", "default": False},
                "budgets": _BUDGET_SCHEMA,
            },
            "required": ["scope", "budgets"],
            "additionalProperties": False,
        },
        outputSchema=_output_schema(_JOB_SCHEMA),
    ),
    types.Tool(
        name="web_listening_get_job",
        description="Read one Job through the public Runtime service.",
        inputSchema={
            "type": "object",
            "properties": {"job_id": {"type": "string"}},
            "required": ["job_id"],
            "additionalProperties": False,
        },
        outputSchema=_output_schema(_JOB_SCHEMA),
    ),
    types.Tool(
        name="web_listening_read_artifact",
        description="Read one lossless Artifact through the public Runtime service.",
        inputSchema={
            "type": "object",
            "properties": {"artifact_id": {"type": "string"}},
            "required": ["artifact_id"],
            "additionalProperties": False,
        },
        outputSchema=_output_schema(_ARTIFACT_SCHEMA),
    ),
    types.Tool(
        name="web_listening_validate_site_skill",
        description="Validate and serialize one data-only Site Skill.",
        inputSchema={
            "type": "object",
            "properties": {"site_skill": _SITE_SKILL_SCHEMA},
            "required": ["site_skill"],
            "additionalProperties": False,
        },
        outputSchema=_output_schema(_SITE_SKILL_SCHEMA),
    ),
)
_TOOL_NAMES = frozenset(tool.name for tool in _TOOLS)


def _job_payload(job: Job) -> dict[str, object]:
    result = None if job.result is None else job.result.to_dict()
    return {
        "job_id": job.job_id,
        "status": job.status.value,
        "submitted_at": job.submitted_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "result": result,
        "failure_code": job.failure_code,
    }


def _artifact_payload(artifact: StoredArtifact) -> dict[str, object]:
    return {
        "artifact_id": artifact.artifact_id,
        "blob_sha256": artifact.blob_sha256,
        "size_bytes": artifact.size_bytes,
        "mime_type": artifact.mime_type,
        "content_encoding": "base64",
        "content": base64.b64encode(artifact.content).decode("ascii"),
    }


def _error_result(code: str, message: str) -> types.CallToolResult:
    payload = {"error": SafeError(code, message).to_dict()}
    return types.CallToolResult(
        content=[
            types.TextContent(
                type="text",
                text=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            )
        ],
        structuredContent=payload,
        isError=True,
    )


def _runtime_error(exc: Exception) -> types.CallToolResult:
    code = getattr(exc, "code", "")
    if code in {"job.not_found", "artifact.not_found"}:
        return _error_result(code, "Resource was not found.")
    if code in {"job.id_invalid", "artifact.id_invalid"}:
        return _error_result(code, "Identifier is invalid.")
    return _error_result("runtime.failed", "Runtime request failed.")


def _single_string_argument(
    arguments: Mapping[str, object], name: str, code: str
) -> str:
    if set(arguments) != {name} or not isinstance(arguments.get(name), str):
        raise RequestValidationError(code)
    return arguments[name]  # type: ignore[return-value]


async def _call_tool(
    runtime_provider: RuntimeProvider,
    name: str,
    arguments: Mapping[str, object],
) -> dict[str, object] | types.CallToolResult:
    if name not in _TOOL_NAMES:
        return _error_result("mcp.tool_not_found", "Tool was not found.")
    try:
        if name == "web_listening_validate_site_skill":
            if set(arguments) != {"site_skill"}:
                raise SiteSkillError("site_skill.invalid")
            skill = site_skill_from_mapping(arguments["site_skill"])
            return site_skill_to_mapping(skill)

        if name == "web_listening_acquire":
            request = request_from_mapping(arguments)
            if request.site_skill is not None:
                request = replace(
                    request,
                    site_skill=site_skill_from_mapping(request.site_skill),
                )
            runtime = runtime_provider()
            job = await anyio.to_thread.run_sync(lambda: runtime.run(request))
            return _job_payload(job)

        if name == "web_listening_get_job":
            job_id = _single_string_argument(arguments, "job_id", "job.id_invalid")
            runtime = runtime_provider()
            job = await anyio.to_thread.run_sync(lambda: runtime.get_job(job_id))
            return _job_payload(job)

        artifact_id = _single_string_argument(
            arguments, "artifact_id", "artifact.id_invalid"
        )
        runtime = runtime_provider()
        artifact = await anyio.to_thread.run_sync(
            lambda: runtime.read_artifact(artifact_id)
        )
        return _artifact_payload(artifact)
    except (RequestValidationError, SiteSkillError) as exc:
        message = (
            "Site Skill is invalid."
            if isinstance(exc, SiteSkillError)
            else "Request is invalid."
        )
        return _error_result(exc.code, message)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return _runtime_error(exc)


def create_server(runtime_provider: RuntimeProvider) -> Server:
    """Create a server exposing exactly the four governed high-level tools."""
    server = Server("web-listening", version="0.1.0")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return list(_TOOLS)

    @server.call_tool(validate_input=False)
    async def call_tool(
        name: str, arguments: dict[str, object]
    ) -> dict[str, object] | types.CallToolResult:
        return await _call_tool(runtime_provider, name, arguments)

    return server


async def _run_stdio(server: Server) -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m web_listening.interfaces.mcp",
        description="Serve the governed Web Listening interface over stdio.",
    )
    parser.add_argument("--data-dir", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Open one Runtime data directory and serve MCP over stdio."""
    args = _parser().parse_args(argv)
    runtime = RuntimeService.open(args.data_dir)
    try:
        anyio.run(_run_stdio, create_server(lambda: runtime))
    finally:
        runtime.close()


__all__ = ["RuntimeProvider", "create_server", "main"]


if __name__ == "__main__":
    main()
