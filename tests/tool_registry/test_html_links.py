"""Pure HTML link Discovery contract tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

from web_listening.request.model import ContentType, Scope
from web_listening.tool_registry.discovery.builtins.html_links import (
    HtmlLinksDiscoveryTool,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryFailure,
    DiscoveryInput,
    DiscoveryOutput,
)


def _input(body: bytes, mime_type: str = "text/html") -> DiscoveryInput:
    return DiscoveryInput(
        Scope(
            ("https://example.test/reports/",),
            ("https://example.test",),
            ("/**",),
            (ContentType.HTML,),
        ),
        "https://example.test/reports/",
        body,
        mime_type,
    )


def test_html_links_are_inert_canonical_deduplicated_sorted_and_bounded() -> None:
    body = b"""
    <html><head><base href='/reports/'></head><body>
      <a href='z#section'>z</a><a href='./a'>a</a><a href='a'>dup</a>
      <area href='/map'><link href='/style.css'><a href='mailto:x@y'>mail</a>
    </body></html>
    """

    result = HtmlLinksDiscoveryTool(max_candidates=3).discover(_input(body))

    assert isinstance(result, DiscoveryOutput)
    assert result.candidates == (
        "https://example.test/map",
        "https://example.test/reports/a",
        "https://example.test/reports/z",
    )
    assert result.discovered_from == ("https://example.test/reports/",) * 3


def test_html_links_reject_non_html_without_network_or_store_surface() -> None:
    tool = HtmlLinksDiscoveryTool()

    result = tool.discover(_input(b"plain", "text/plain"))

    assert isinstance(result, DiscoveryFailure)
    assert result.code == "discovery.mime_unsupported"
    assert not hasattr(tool, "request")
    assert not hasattr(tool, "store")
