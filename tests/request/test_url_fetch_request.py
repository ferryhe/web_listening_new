"""Strict Smart URL Fetch request tests."""

# pylint: disable=missing-function-docstring

import pytest

from web_listening.request.model import ContentType, RequestValidationError
from web_listening.request.url_fetch import UrlFetchRequest


def test_request_round_trip_and_compilation() -> None:
    request = UrlFetchRequest.from_dict(
        {
            "url": "HTTPS://Example.COM:443/a",
            "explore_all_tools": False,
            "follow_html_navigation": True,
            "max_navigation_hops": 3,
            "budgets": {
                "max_requests": 4,
                "max_bytes": 1000,
                "max_runtime_seconds": 10,
                "max_tool_attempts_per_target": 2,
            },
        }
    )
    assert request.url == "https://example.com/a"
    assert UrlFetchRequest.from_dict(request.to_dict()) == request
    compiled = request.compile()
    assert compiled.scope.seeds == ("https://example.com/a",)
    assert compiled.scope.allowed_origins == ("https://example.com",)
    assert compiled.scope.include_paths == ("/**",)
    assert compiled.scope.content_types == (ContentType.HTML, ContentType.FILE)
    assert compiled.site_skill is None


@pytest.mark.parametrize(
    "change", ({"extra": 1}, {"url": None}, {"max_navigation_hops": 0}, {"budgets": {}})
)
def test_request_rejects_unknown_missing_and_invalid(change) -> None:
    payload = {
        "url": "https://example.com/",
        "explore_all_tools": False,
        "follow_html_navigation": True,
        "max_navigation_hops": 3,
        "budgets": {
            "max_requests": 4,
            "max_bytes": 1000,
            "max_runtime_seconds": 10,
            "max_tool_attempts_per_target": 2,
        },
    }
    payload.update(change)
    with pytest.raises(RequestValidationError):
        UrlFetchRequest.from_dict(payload)
