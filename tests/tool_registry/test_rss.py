"""Focused tests for the pure built-in RSS/Atom Discovery tool."""

# pylint: disable=duplicate-code,missing-function-docstring

from __future__ import annotations

import pytest

from web_listening.request.model import ContentType, Scope
from web_listening.tool_registry.discovery.builtins.rss import (
    RSS_MANIFEST,
    RssDiscoveryTool,
)
from web_listening.tool_registry.manifest import ToolCategory, ToolDistribution
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryFailure,
    DiscoveryInput,
    DiscoveryOutput,
)

SOURCE_URL = "https://example.test/feed/updates.xml"


def _input(body: bytes, mime_type: str) -> DiscoveryInput:
    return DiscoveryInput(
        scope=Scope(
            seeds=("https://example.test/",),
            allowed_origins=("https://example.test",),
            include_paths=("/**",),
            content_types=(ContentType.HTML,),
        ),
        source_url=SOURCE_URL,
        source_body=body,
        source_mime_type=mime_type,
    )


@pytest.mark.parametrize(
    ("body", "mime_type"),
    [
        (
            b"""<rss><channel>
            <item><link>/news/b</link></item>
            <item><link>HTTPS://EXAMPLE.TEST:443/news/a</link></item>
            <item><link>https://example.test/news/a</link></item>
            </channel></rss>""",
            "application/rss+xml",
        ),
        (
            b"""<feed xmlns='http://www.w3.org/2005/Atom'>
            <entry><link rel='alternate' href='/news/b'/></entry>
            <entry><link href='https://example.test/news/a'/></entry>
            </feed>""",
            "application/atom+xml",
        ),
    ],
)
def test_rss_and_atom_return_stable_candidates_with_provenance(
    body: bytes, mime_type: str
) -> None:
    output = RssDiscoveryTool().discover(_input(body, mime_type))

    assert isinstance(output, DiscoveryOutput)
    assert output.candidates == (
        "https://example.test/news/a",
        "https://example.test/news/b",
    )
    assert output.discovered_from == (SOURCE_URL, SOURCE_URL)
    assert output.coverage == "complete"


@pytest.mark.parametrize(
    ("unique_count", "expected_coverage"),
    ((100, "complete"), (101, "truncated")),
)
def test_rss_coverage_is_computed_before_the_stable_output_bound(
    unique_count: int, expected_coverage: str
) -> None:
    entries = "".join(
        f"<item><link>/news/{index:03d}</link></item>"
        for index in reversed(range(unique_count))
    )
    output = RssDiscoveryTool().discover(
        _input(f"<rss><channel>{entries}</channel></rss>".encode(), "text/xml")
    )

    assert isinstance(output, DiscoveryOutput)
    assert len(output.candidates) == min(unique_count, 100)
    assert output.candidates == tuple(sorted(output.candidates))
    assert output.coverage == expected_coverage


def test_rss_returns_safe_failures_for_damaged_or_empty_feeds() -> None:
    tool = RssDiscoveryTool()

    malformed = tool.discover(_input(b"<rss><channel>", "application/rss+xml"))
    empty = tool.discover(_input(b"<rss><channel/></rss>", "application/rss+xml"))

    assert malformed == DiscoveryFailure(
        RSS_MANIFEST.tool_id,
        RSS_MANIFEST.version,
        "discovery.feed_malformed",
    )
    assert empty == DiscoveryFailure(
        RSS_MANIFEST.tool_id,
        RSS_MANIFEST.version,
        "discovery.no_candidates",
    )


def test_rss_rejects_utf16_internal_entity_declarations() -> None:
    body = """<?xml version='1.0' encoding='utf-16'?>
    <!DOCTYPE rss [<!ENTITY private 'https://example.test/private'>]>
    <rss><channel><item><link>&private;</link></item></channel></rss>
    """.encode("utf-16")

    output = RssDiscoveryTool().discover(_input(body, "application/rss+xml"))

    assert output == DiscoveryFailure(
        RSS_MANIFEST.tool_id,
        RSS_MANIFEST.version,
        "discovery.feed_malformed",
    )


def test_rss_manifest_is_one_builtin_discovery_tool() -> None:
    assert RSS_MANIFEST.category is ToolCategory.DISCOVERY
    assert RSS_MANIFEST.distribution is ToolDistribution.BUILTIN
    assert RSS_MANIFEST.capabilities == frozenset({"rss"})
