"""Immutable data models for the public Request contract."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class RequestValidationError(ValueError):
    """Reject an invalid Request using a stable, non-sensitive reason code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ContentType(str, Enum):
    """Content categories a caller may request."""

    HTML = "html"
    FILE = "file"


@dataclass(frozen=True, slots=True)
class Scope:
    """The immutable websites, paths, and content categories in scope."""

    seeds: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    include_paths: tuple[str, ...]
    content_types: tuple[ContentType, ...]


@dataclass(frozen=True, slots=True)
class Budgets:
    """The immutable work limits for one Request."""

    max_requests: int
    max_bytes: int
    max_runtime_seconds: int
    max_tool_attempts_per_target: int


@dataclass(frozen=True, slots=True)
class Request:
    """The four-field public Request described by the product charter."""

    scope: Scope
    site_skill: Any | None
    explore_all_tools: bool
    budgets: Budgets
