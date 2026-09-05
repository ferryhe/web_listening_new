"""Pure HTML navigation discovery tests."""

# pylint: disable=missing-function-docstring

from web_listening.request.model import ContentType, Scope
from web_listening.tool_registry.discovery.builtins.html_navigation import (
    HtmlNavigationDiscoveryTool,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryFailure,
    DiscoveryInput,
)

SCOPE = Scope(
    ("https://example.test/",),
    ("https://example.test",),
    ("/**",),
    (ContentType.HTML, ContentType.FILE),
)


def _discover(body: bytes):
    return HtmlNavigationDiscoveryTool().discover(
        DiscoveryInput(SCOPE, "https://example.test/page", body, "text/html")
    )


def test_meta_precedes_download_and_deduplicates() -> None:
    result = _discover(
        b'<meta http-equiv="refresh" content="0; url=/next">'
        b'<a download href="/file">x</a>'
    )
    assert result.candidates == ("https://example.test/next",)
    assert result.discovered_from == ("https://example.test/page",)


def test_download_candidates_are_sorted_and_cross_origin_removed() -> None:
    result = _discover(
        b'<a download href="/z">z</a><a download href="/a">a</a>'
        b'<a download href="https://other.test/x">x</a>'
    )
    assert result.candidates == ("https://example.test/a", "https://example.test/z")


def test_single_complete_ordinary_link_only_and_no_candidate() -> None:
    assert _discover(b'<a href="/only">only</a>').candidates == (
        "https://example.test/only",
    )
    assert isinstance(
        _discover(b'<a href="/one">1</a><a href="/two">2</a>'), DiscoveryFailure
    )
