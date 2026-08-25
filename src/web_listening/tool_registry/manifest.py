"""Immutable metadata for explicitly registered tools."""

# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

_TOOL_ID = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z")
_VERSION = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\Z")
_CAPABILITY = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z")
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)*\Z")
_MAX_RUNTIME_SECONDS = 3600
_MAX_BYTES = 1 << 30


class ToolRegistryError(ValueError):
    """A stable, non-sensitive Tool Registry failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ToolCategory(str, Enum):
    """The three non-interchangeable tool contracts."""

    DISCOVERY = "discovery"
    ACQUISITION = "acquisition"
    TRANSFORM = "transform"


class ToolDistribution(str, Enum):
    """Where a tool is distributed, independent of its category."""

    BUILTIN = "builtin"
    INSTALLED = "installed"


class HealthStatus(str, Enum):
    """Whether the registered tool is currently usable."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


class QualificationStatus(str, Enum):
    """Whether the tool passed its external qualification process."""

    QUALIFIED = "qualified"
    UNQUALIFIED = "unqualified"


def validate_tool_id(value: str) -> str:
    """Return a valid stable tool identifier."""
    if type(value) is not str or _TOOL_ID.fullmatch(value) is None:
        raise ToolRegistryError("manifest.id_invalid")
    return value


def validate_tool_version(value: str) -> str:
    """Return a strict three-part semantic version."""
    if type(value) is not str or _VERSION.fullmatch(value) is None:
        raise ToolRegistryError("manifest.version_invalid")
    return value


def validate_safe_code(value: str) -> str:
    """Return a bounded machine-readable failure code."""
    if (
        type(value) is not str
        or len(value) > 128
        or _SAFE_CODE.fullmatch(value) is None
    ):
        raise ToolRegistryError("protocol.error_code_invalid")
    return value


def capability_is_valid(value: object) -> bool:
    """Return whether a value is a safe bounded capability token."""
    return (
        type(value) is str
        and len(value) <= 64
        and _CAPABILITY.fullmatch(value) is not None
    )


def _positive_int(value: int, maximum: int) -> bool:
    return type(value) is int and 0 < value <= maximum


@dataclass(frozen=True, slots=True)
class ToolLimits:
    """Hard resource claims used for basic eligibility checks."""

    max_runtime_seconds: int
    max_input_bytes: int
    max_output_bytes: int

    def __post_init__(self) -> None:
        if not (
            _positive_int(self.max_runtime_seconds, _MAX_RUNTIME_SECONDS)
            and _positive_int(self.max_input_bytes, _MAX_BYTES)
            and _positive_int(self.max_output_bytes, _MAX_BYTES)
        ):
            raise ToolRegistryError("manifest.limits_invalid")


@dataclass(frozen=True, slots=True)
class ToolManifest:  # pylint: disable=too-many-instance-attributes
    """The complete immutable identity and eligibility metadata for one tool."""

    tool_id: str
    version: str
    category: ToolCategory
    distribution: ToolDistribution
    capabilities: frozenset[str]
    limits: ToolLimits
    health: HealthStatus
    qualification: QualificationStatus

    def __post_init__(self) -> None:
        validate_tool_id(self.tool_id)
        validate_tool_version(self.version)
        if type(self.category) is not ToolCategory:
            raise ToolRegistryError("manifest.category_invalid")
        if type(self.distribution) is not ToolDistribution:
            raise ToolRegistryError("manifest.distribution_invalid")
        if (
            type(self.capabilities) is not frozenset
            or not self.capabilities
            or len(self.capabilities) > 64
            or any(not capability_is_valid(value) for value in self.capabilities)
        ):
            raise ToolRegistryError("manifest.capabilities_invalid")
        if type(self.limits) is not ToolLimits:
            raise ToolRegistryError("manifest.limits_invalid")
        if type(self.health) is not HealthStatus:
            raise ToolRegistryError("manifest.health_invalid")
        if type(self.qualification) is not QualificationStatus:
            raise ToolRegistryError("manifest.qualification_invalid")
