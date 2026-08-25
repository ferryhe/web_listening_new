"""Pure contract for URL discovery tools."""

# pylint: disable=duplicate-code

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

from web_listening.request.model import RequestValidationError, Scope
from web_listening.request.scope import canonicalize_url, validate_scope
from web_listening.tool_registry.manifest import (
    ToolManifest,
    ToolRegistryError,
    validate_safe_code,
    validate_tool_id,
    validate_tool_version,
)


def validate_url(value: str) -> str:
    """Validate an inert absolute HTTP URL without opening it."""
    canonical = _contained_canonical_url(value)
    if canonical is None:
        raise ToolRegistryError("protocol.url_invalid")
    hostname = urlsplit(canonical).hostname
    if (
        hostname
        and "." in hostname
        and all(character.isdigit() or character == "." for character in hostname)
    ):
        address = _contained_ip_address(hostname)
        if address is None or address.version != 4:
            raise ToolRegistryError("protocol.url_invalid")
    return canonical


def _contained_canonical_url(value: object) -> str | None:
    try:
        return canonicalize_url(value)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def _contained_ip_address(value: str):
    try:
        return ip_address(value)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


@dataclass(frozen=True, slots=True)
class DiscoveryInput:
    """The governed scope presented to one discovery tool."""

    scope: Scope

    def __post_init__(self) -> None:
        canonical, error = _contained_scope(self.scope)
        if error is not None:
            raise ToolRegistryError(error)
        object.__setattr__(self, "scope", canonical)


@dataclass(frozen=True, slots=True)
class DiscoveryOutput:
    """Ordered candidate URLs returned by a successful discovery tool."""

    tool_id: str
    tool_version: str
    candidates: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_tool_id(self.tool_id)
        validate_tool_version(self.tool_version)
        # pylint: disable-next=unidiomatic-typecheck
        if type(self.candidates) is not tuple or not self.candidates:
            raise ToolRegistryError("protocol.output_invalid")
        object.__setattr__(
            self,
            "candidates",
            tuple(validate_url(value) for value in self.candidates),
        )


@dataclass(frozen=True, slots=True)
class DiscoveryFailure:
    """A safe discovery failure returned instead of candidate URLs."""

    tool_id: str
    tool_version: str
    code: str

    def __post_init__(self) -> None:
        validate_tool_id(self.tool_id)
        validate_tool_version(self.tool_version)
        validate_safe_code(self.code)


@runtime_checkable
class DiscoveryTool(Protocol):  # pylint: disable=too-few-public-methods
    """Structural interface implemented by a discovery tool."""

    manifest: ToolManifest

    def discover(
        self, tool_input: DiscoveryInput
    ) -> DiscoveryOutput | DiscoveryFailure:
        """Return candidate URLs or a safe failure."""


def _contained_scope(value: object) -> tuple[Scope | None, str | None]:
    try:
        return validate_scope(value), None  # type: ignore[arg-type]
    except RequestValidationError as exc:
        return None, exc.code
    except Exception:  # pylint: disable=broad-exception-caught
        return None, "protocol.input_invalid"
