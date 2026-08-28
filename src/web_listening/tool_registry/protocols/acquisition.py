"""Pure contract for governed content acquisition tools."""

# pylint: disable=duplicate-code,unidiomatic-typecheck

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from web_listening.artifact.identity import validate_mime_type as validate_artifact_mime
from web_listening.artifact.model import ArtifactStoreError
from web_listening.request.model import Budgets, Request, RequestValidationError
from web_listening.request.validate import compile_access_policy, validate_request
from web_listening.tool_registry.manifest import (
    ToolManifest,
    ToolRegistryError,
    validate_safe_code,
    validate_tool_id,
    validate_tool_version,
)
from web_listening.tool_registry.protocols.discovery import validate_url

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def validate_mime_type(value: str) -> str:
    """Validate a strict lower-case MIME token without parameters."""
    mime_type = _contained_mime_type(value)
    if mime_type is None:
        raise ToolRegistryError("protocol.mime_invalid")
    return mime_type


def _contained_mime_type(value: object) -> str | None:
    try:
        if type(value) is not str:
            return None
        return validate_artifact_mime(value)  # type: ignore[arg-type]
    except ArtifactStoreError:
        return None
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def validate_body_hash(body: bytes, digest: str) -> None:
    """Reject an output whose claimed digest does not bind its bytes."""
    if (
        type(body) is not bytes
        or type(digest) is not str
        or _SHA256.fullmatch(digest) is None
        or hashlib.sha256(body).hexdigest() != digest
    ):
        raise ToolRegistryError("protocol.hash_mismatch")


def validate_runtime(value: int) -> int:
    """Validate a measured non-negative millisecond count."""
    if type(value) is not int or value < 0:
        raise ToolRegistryError("protocol.runtime_invalid")
    return value


@dataclass(frozen=True, slots=True)
class AcquisitionInput:
    """One Request-bound target presented to an acquisition tool."""

    request: Request
    target_url: str

    def __post_init__(self) -> None:
        canonical_request, error = _contained_request(self.request)
        if error is not None:
            raise ToolRegistryError(error)
        target = validate_url(self.target_url)
        decision = compile_access_policy(canonical_request).decide_url(target)
        if not decision.allowed:
            raise ToolRegistryError(decision.code)
        object.__setattr__(self, "request", canonical_request)
        object.__setattr__(self, "target_url", target)


@dataclass(frozen=True, slots=True)
class AcquisitionRedirect:
    """One followed redirect transition reported as inert evidence."""

    from_url: str
    to_url: str
    status_code: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "from_url", validate_url(self.from_url))
        object.__setattr__(self, "to_url", validate_url(self.to_url))
        if type(self.status_code) is not int or not 300 <= self.status_code < 400:
            raise ToolRegistryError("protocol.status_invalid")


@dataclass(frozen=True, slots=True)
class AcquisitionOutput:  # pylint: disable=too-many-instance-attributes
    """Original bytes and evidence returned by a successful acquisition."""

    tool_id: str
    tool_version: str
    requested_url: str
    final_url: str
    status_code: int
    mime_type: str
    body: bytes
    sha256: str
    redirects: tuple[AcquisitionRedirect, ...]
    runtime_ms: int
    requests: int | None = None
    bytes_received: int | None = None
    _usage_explicit: bool | None = field(default=None, repr=False, compare=False)
    _inferred_requests: int | None = field(default=None, repr=False, compare=False)
    _inferred_bytes: int | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        validate_tool_id(self.tool_id)
        validate_tool_version(self.tool_version)
        object.__setattr__(self, "requested_url", validate_url(self.requested_url))
        object.__setattr__(self, "final_url", validate_url(self.final_url))
        if type(self.status_code) is not int or not 200 <= self.status_code < 300:
            raise ToolRegistryError("protocol.status_invalid")
        validate_mime_type(self.mime_type)
        validate_body_hash(self.body, self.sha256)
        if type(self.redirects) is not tuple or any(
            type(value) is not AcquisitionRedirect for value in self.redirects
        ):
            raise ToolRegistryError("protocol.redirects_invalid")
        current_url = self.requested_url
        for redirect in self.redirects:
            if redirect.from_url != current_url:
                raise ToolRegistryError("protocol.redirects_invalid")
            current_url = redirect.to_url
        if current_url != self.final_url:
            raise ToolRegistryError("protocol.redirects_invalid")
        validate_runtime(self.runtime_ms)
        minimum_requests = len(self.redirects) + 1
        minimum_bytes = len(self.body)
        if self._usage_explicit is None:
            usage_explicit = (
                self.requests is not None or self.bytes_received is not None
            )
        elif type(self._usage_explicit) is bool:
            usage_explicit = self._usage_explicit
        else:
            raise ToolRegistryError("protocol.usage_invalid")
        inferred_values = (self._inferred_requests, self._inferred_bytes)
        if any(
            value is not None and (type(value) is not int or value < 0)
            for value in inferred_values
        ):
            raise ToolRegistryError("protocol.usage_invalid")
        if not usage_explicit and all(value is not None for value in inferred_values):
            usage_explicit = (
                self.requests != self._inferred_requests
                or self.bytes_received != self._inferred_bytes
            )
        requests = (
            self.requests
            if usage_explicit and self.requests is not None
            else minimum_requests
        )
        bytes_received = (
            self.bytes_received
            if usage_explicit and self.bytes_received is not None
            else minimum_bytes
        )
        if (
            type(requests) is not int
            or requests < minimum_requests
            or type(bytes_received) is not int
            or bytes_received < minimum_bytes
        ):
            raise ToolRegistryError("protocol.usage_invalid")
        object.__setattr__(self, "requests", requests)
        object.__setattr__(self, "bytes_received", bytes_received)
        object.__setattr__(self, "_usage_explicit", usage_explicit)
        object.__setattr__(
            self,
            "_inferred_requests",
            None if usage_explicit else requests,
        )
        object.__setattr__(
            self,
            "_inferred_bytes",
            None if usage_explicit else bytes_received,
        )


@dataclass(frozen=True, slots=True)
class AcquisitionFailure:
    """A safe acquisition failure returned instead of original bytes."""

    tool_id: str
    tool_version: str
    code: str
    requests: int = field(default=0, compare=False)
    bytes_received: int = field(default=0, compare=False)
    runtime_ms: int = field(default=0, compare=False)

    def __post_init__(self) -> None:
        validate_tool_id(self.tool_id)
        validate_tool_version(self.tool_version)
        validate_safe_code(self.code)
        if any(
            type(value) is not int or value < 0
            for value in (self.requests, self.bytes_received, self.runtime_ms)
        ):
            raise ToolRegistryError("protocol.usage_invalid")


@runtime_checkable
class AcquisitionTool(Protocol):  # pylint: disable=too-few-public-methods
    """Structural interface implemented by an acquisition tool."""

    manifest: ToolManifest

    def acquire(
        self, tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        """Return original bytes/evidence or a safe failure."""


def _contained_request(value: object) -> tuple[Request | None, str | None]:
    try:
        request = validate_request(value)  # type: ignore[arg-type]
        budgets = request.budgets
        budget_values = (
            budgets.max_requests,
            budgets.max_bytes,
            budgets.max_runtime_seconds,
            budgets.max_tool_attempts_per_target,
        )
        if type(budgets) is not Budgets or any(
            type(limit) is not int for limit in budget_values
        ):
            return None, "protocol.input_invalid"
        return (
            Request(
                request.scope,
                request.site_skill,
                request.explore_all_tools,
                Budgets(*budget_values),
            ),
            None,
        )
    except RequestValidationError as exc:
        return None, exc.code
    except Exception:  # pylint: disable=broad-exception-caught
        return None, "protocol.input_invalid"
