"""Strict Smart URL Fetch request and compilation boundary."""

# pylint: disable=unidiomatic-typecheck,missing-function-docstring

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from web_listening.request.budgets import budgets_from_mapping, validate_budgets
from web_listening.request.model import (
    Budgets,
    ContentType,
    Request,
    RequestValidationError,
    Scope,
)
from web_listening.request.scope import canonicalize_url
from web_listening.request.validate import validate_request

URL_FETCH_REQUEST_SCHEMA_VERSION = "web-listening-url-fetch-request.v1"
_FIELDS = frozenset(
    {
        "url",
        "explore_all_tools",
        "follow_html_navigation",
        "max_navigation_hops",
        "budgets",
    }
)


@dataclass(frozen=True, slots=True)
class UrlFetchRequest:
    """Caller intent for one bounded URL resolution."""

    url: str
    explore_all_tools: bool
    follow_html_navigation: bool
    max_navigation_hops: int
    budgets: Budgets

    def __post_init__(self) -> None:
        try:
            url = canonicalize_url(self.url)
        except (TypeError, ValueError, RequestValidationError) as exc:
            raise RequestValidationError("url_fetch.url_invalid") from exc
        if type(self.explore_all_tools) is not bool:
            raise RequestValidationError("url_fetch.explore_all_tools_invalid")
        if type(self.follow_html_navigation) is not bool:
            raise RequestValidationError("url_fetch.follow_html_navigation_invalid")
        if (
            type(self.max_navigation_hops) is not int
            or not 1 <= self.max_navigation_hops <= 16
        ):
            raise RequestValidationError("url_fetch.max_navigation_hops_invalid")
        object.__setattr__(self, "url", url)
        object.__setattr__(self, "budgets", validate_budgets(self.budgets))

    def compile(self) -> Request:
        """Compile intent into the unchanged public four-field Request."""
        parsed = urlsplit(self.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return validate_request(
            Request(
                Scope(
                    (self.url,),
                    (origin,),
                    ("/**",),
                    (ContentType.HTML, ContentType.FILE),
                ),
                None,
                self.explore_all_tools,
                self.budgets,
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "explore_all_tools": self.explore_all_tools,
            "follow_html_navigation": self.follow_html_navigation,
            "max_navigation_hops": self.max_navigation_hops,
            "budgets": {
                name: getattr(self.budgets, name)
                for name in (
                    "max_requests",
                    "max_bytes",
                    "max_runtime_seconds",
                    "max_tool_attempts_per_target",
                )
            },
        }

    def canonical_json_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode()

    @property
    def request_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, value: object) -> "UrlFetchRequest":
        if not isinstance(value, Mapping) or not all(type(key) is str for key in value):
            raise RequestValidationError("url_fetch.invalid")
        if set(value) - _FIELDS:
            raise RequestValidationError("url_fetch.unknown_field")
        if _FIELDS - set(value):
            raise RequestValidationError("url_fetch.missing")
        return cls(
            value["url"],
            value["explore_all_tools"],
            value["follow_html_navigation"],
            value["max_navigation_hops"],
            budgets_from_mapping(value["budgets"]),
        )


def url_fetch_request_from_json(value: str) -> UrlFetchRequest:
    try:
        payload = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RequestValidationError("url_fetch.invalid_json") from exc
    return UrlFetchRequest.from_dict(payload)


__all__ = [
    "URL_FETCH_REQUEST_SCHEMA_VERSION",
    "UrlFetchRequest",
    "url_fetch_request_from_json",
]
