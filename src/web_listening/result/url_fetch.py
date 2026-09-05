"""Strict evidence-only result for Smart URL Fetch."""

# pylint: disable=missing-class-docstring,missing-function-docstring
# pylint: disable=too-many-instance-attributes,unidiomatic-typecheck
# pylint: disable=duplicate-code

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from web_listening.mime import is_html_mime_type
from web_listening.result.errors import (
    ResultValidationError,
    SafeError,
    require_exact_fields,
    require_mapping,
    validate_url,
)
from web_listening.result.manifest import ArtifactEvidence, Usage
from web_listening.result.model import Result, ResultStatus

URL_FETCH_RESULT_SCHEMA_VERSION = "web-listening-url-fetch.v1"


class ResolutionKind(str, Enum):
    DIRECT_HTML = "direct_html"
    DIRECT_FILE = "direct_file"
    REDIRECT_HTML = "redirect_html"
    REDIRECT_FILE = "redirect_file"
    HTML_NAVIGATION_HTML = "html_navigation_html"
    HTML_NAVIGATION_FILE = "html_navigation_file"
    UNRESOLVED = "unresolved"


class ResolvedContentType(str, Enum):
    HTML = "html"
    FILE = "file"


class DiscoveryCoverage(str, Enum):
    COMPLETE = "complete"
    TRUNCATED = "truncated"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class NavigationDiscovery:
    tool_id: str
    tool_version: str
    source_url: str
    candidates: tuple[str, ...]
    discovered_from: tuple[str, ...]
    coverage: DiscoveryCoverage | str
    usage: Usage
    failure_code: str | None = None

    def __post_init__(self):
        validate_url(self.source_url)
        if (
            type(self.candidates) is not tuple
            or type(self.discovered_from) is not tuple
            or len(self.candidates) != len(self.discovered_from)
        ):
            raise ResultValidationError("url_fetch.discovery_invalid")
        for value in self.candidates + self.discovered_from:
            validate_url(value)
        try:
            object.__setattr__(self, "coverage", DiscoveryCoverage(self.coverage))
        except (TypeError, ValueError) as exc:
            raise ResultValidationError("url_fetch.discovery_invalid") from exc
        if not isinstance(self.usage, Usage):
            raise ResultValidationError("url_fetch.discovery_invalid")
        if (
            self.usage.requests
            or self.usage.bytes_received
            or self.usage.tool_attempts != 1
        ):
            raise ResultValidationError("url_fetch.discovery_invalid")
        if self.failure_code is not None and not isinstance(self.failure_code, str):
            raise ResultValidationError("url_fetch.discovery_invalid")

    def to_dict(self):
        return {
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "source_url": self.source_url,
            "candidates": list(self.candidates),
            "discovered_from": list(self.discovered_from),
            "coverage": self.coverage.value,
            "usage": self.usage.to_dict(),
            "failure_code": self.failure_code,
        }

    @classmethod
    def from_dict(cls, value):
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {
                "tool_id",
                "tool_version",
                "source_url",
                "candidates",
                "discovered_from",
                "coverage",
                "usage",
                "failure_code",
            },
        )
        if not isinstance(payload["candidates"], list) or not isinstance(
            payload["discovered_from"], list
        ):
            raise ResultValidationError("url_fetch.discovery_invalid")
        return cls(
            payload["tool_id"],
            payload["tool_version"],
            payload["source_url"],
            tuple(payload["candidates"]),
            tuple(payload["discovered_from"]),
            payload["coverage"],
            Usage.from_dict(payload["usage"]),
            payload["failure_code"],
        )


@dataclass(frozen=True, slots=True)
class UrlFetchResult:
    status: ResultStatus | str
    requested_url: str
    final_url: str | None
    resolved_content_type: ResolvedContentType | str | None
    resolution_kind: ResolutionKind | str
    terminal_artifact: ArtifactEvidence | None
    intermediate_results: tuple[Result, ...]
    terminal_result: Result | None
    discovery: tuple[NavigationDiscovery, ...]
    usage: Usage
    stop_reason: str
    errors: tuple[SafeError, ...]
    schema_version: str = URL_FETCH_RESULT_SCHEMA_VERSION

    def __post_init__(self):
        if self.schema_version != URL_FETCH_RESULT_SCHEMA_VERSION:
            raise ResultValidationError("schema.version_invalid")
        try:
            status = ResultStatus(self.status)
            kind = ResolutionKind(self.resolution_kind)
            content = (
                None
                if self.resolved_content_type is None
                else ResolvedContentType(self.resolved_content_type)
            )
        except (TypeError, ValueError) as exc:
            raise ResultValidationError("url_fetch.result_invalid") from exc
        validate_url(self.requested_url)
        if self.final_url is not None:
            validate_url(self.final_url)
        results = (
            *self.intermediate_results,
            *((self.terminal_result,) if self.terminal_result else ()),
        )
        if not isinstance(self.usage, Usage) or self.usage != _usage(
            results, self.discovery
        ):
            raise ResultValidationError("url_fetch.usage_mismatch")
        expected_errors = tuple(error for result in results for error in result.errors)
        if self.stop_reason == "cancelled":
            expected_errors += (
                SafeError("runtime.cancelled", "Runtime execution was cancelled."),
            )
        if self.errors != expected_errors:
            raise ResultValidationError("url_fetch.errors_mismatch")
        if self.terminal_artifact is not None:
            if (
                self.terminal_artifact.role != "source"
                or self.terminal_result is None
                or self.terminal_artifact not in self.terminal_result.artifacts
            ):
                raise ResultValidationError("url_fetch.terminal_artifact_invalid")
            expected = (
                ResolvedContentType.HTML
                if is_html_mime_type(self.terminal_artifact.mime_type)
                else ResolvedContentType.FILE
            )
            if content is not expected:
                raise ResultValidationError("url_fetch.content_type_mismatch")
        elif content is not None:
            raise ResultValidationError("url_fetch.content_type_mismatch")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "resolution_kind", kind)
        object.__setattr__(self, "resolved_content_type", content)

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "resolved_content_type": (
                None
                if self.resolved_content_type is None
                else self.resolved_content_type.value
            ),
            "resolution_kind": self.resolution_kind.value,
            "terminal_artifact": (
                None
                if self.terminal_artifact is None
                else self.terminal_artifact.to_dict()
            ),
            "intermediate_results": [
                item.to_dict() for item in self.intermediate_results
            ],
            "terminal_result": (
                None if self.terminal_result is None else self.terminal_result.to_dict()
            ),
            "discovery": [item.to_dict() for item in self.discovery],
            "usage": self.usage.to_dict(),
            "stop_reason": self.stop_reason,
            "errors": [item.to_dict() for item in self.errors],
        }

    @classmethod
    def from_dict(cls, value):
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {
                "schema_version",
                "status",
                "requested_url",
                "final_url",
                "resolved_content_type",
                "resolution_kind",
                "terminal_artifact",
                "intermediate_results",
                "terminal_result",
                "discovery",
                "usage",
                "stop_reason",
                "errors",
            },
        )
        if not all(
            isinstance(payload[key], list)
            for key in ("intermediate_results", "discovery", "errors")
        ):
            raise ResultValidationError("url_fetch.result_invalid")
        return cls(
            payload["status"],
            payload["requested_url"],
            payload["final_url"],
            payload["resolved_content_type"],
            payload["resolution_kind"],
            (
                None
                if payload["terminal_artifact"] is None
                else ArtifactEvidence.from_dict(payload["terminal_artifact"])
            ),
            tuple(Result.from_dict(item) for item in payload["intermediate_results"]),
            (
                None
                if payload["terminal_result"] is None
                else Result.from_dict(payload["terminal_result"])
            ),
            tuple(NavigationDiscovery.from_dict(item) for item in payload["discovery"]),
            Usage.from_dict(payload["usage"]),
            payload["stop_reason"],
            tuple(SafeError.from_dict(item) for item in payload["errors"]),
            payload["schema_version"],
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


__all__ = [
    "NavigationDiscovery",
    "ResolutionKind",
    "URL_FETCH_RESULT_SCHEMA_VERSION",
    "UrlFetchResult",
]
