"""Pure HTML link Discovery contract tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

from web_listening.request.model import ContentType, Scope
from web_listening.tool_registry.discovery.builtins.html_links import (
    HtmlFileLinksDiscoveryTool,
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
    assert result.coverage == "truncated"


def test_html_links_coverage_uses_unique_candidates_before_slicing() -> None:
    exact = HtmlLinksDiscoveryTool(max_candidates=3).discover(
        _input(
            b"<a href='/a'>a</a><a href='/b'>b</a>"
            b"<a href='/c'>c</a><a href='/c#duplicate'>duplicate</a>"
        )
    )
    over = HtmlLinksDiscoveryTool(max_candidates=3).discover(
        _input(
            b"<a href='/a'>a</a><a href='/b'>b</a>"
            b"<a href='/c'>c</a><a href='/d'>d</a>"
        )
    )

    assert isinstance(exact, DiscoveryOutput)
    assert exact.coverage == "complete"
    assert len(exact.candidates) == 3
    assert isinstance(over, DiscoveryOutput)
    assert over.coverage == "truncated"
    assert len(over.candidates) == 3


def test_html_links_reject_non_html_without_network_or_store_surface() -> None:
    tool = HtmlLinksDiscoveryTool()

    result = tool.discover(_input(b"plain", "text/plain"))

    assert isinstance(result, DiscoveryFailure)
    assert result.code == "discovery.mime_unsupported"
    assert not hasattr(tool, "request")
    assert not hasattr(tool, "store")


def test_file_links_prioritize_in_scope_pdf_beyond_ordinary_bound() -> None:
    ordinary_urls = tuple(
        f"https://example.test/reports/page-{index:03}.html" for index in range(249)
    )
    pdf_url = "https://example.test/reports/z-report.pdf"
    body = "".join(
        f"<a href='{url}'>item</a>" for url in (*ordinary_urls, pdf_url)
    ).encode()

    ordinary = HtmlLinksDiscoveryTool().discover(_input(body))
    goal_aware = HtmlFileLinksDiscoveryTool().discover(_input(body))

    assert isinstance(ordinary, DiscoveryOutput)
    assert len(ordinary.candidates) == 100
    assert pdf_url not in ordinary.candidates
    assert ordinary.coverage == "truncated"
    assert isinstance(goal_aware, DiscoveryOutput)
    assert goal_aware.candidates == (pdf_url, *ordinary_urls[:99])
    assert goal_aware.coverage == "truncated"


def test_file_links_accept_download_hint_and_prioritize_child_scope() -> None:
    child_input = DiscoveryInput(
        Scope(
            ("https://example.test/reports/",),
            ("https://example.test", "https://other.test"),
            ("/reports/**",),
            (ContentType.HTML, ContentType.FILE),
        ),
        "https://example.test/reports/",
        b"<a href='notes' download>notes</a>"
        b"<a href='https://other.test/reports/other.pdf'>other</a>"
        b"<a href='/outside/report.pdf'>outside</a>",
        "text/html",
    )

    result = HtmlFileLinksDiscoveryTool().discover(child_input)

    assert isinstance(result, DiscoveryOutput)
    assert result.candidates == (
        "https://example.test/reports/notes",
        "https://example.test/outside/report.pdf",
        "https://other.test/reports/other.pdf",
    )
    assert result.coverage == "complete"


def test_file_links_without_file_hint_falls_back_to_ordinary_links() -> None:
    result = HtmlFileLinksDiscoveryTool().discover(
        _input(b"<a href='/a'>a</a><a href='/b'>b</a>")
    )

    assert isinstance(result, DiscoveryOutput)
    assert result.candidates == (
        "https://example.test/a",
        "https://example.test/b",
    )
    assert result.coverage == "complete"


def test_file_links_keep_the_existing_hundred_candidate_cap() -> None:
    result = HtmlFileLinksDiscoveryTool().discover(
        _input(
            "".join(
                f"<a href='/report-{index:03}.pdf'>report</a>" for index in range(101)
            ).encode()
        )
    )

    assert isinstance(result, DiscoveryOutput)
    assert len(result.candidates) == 100
    assert result.coverage == "truncated"
