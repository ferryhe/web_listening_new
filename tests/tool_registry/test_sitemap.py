"""Focused tests for the pure built-in Sitemap Discovery tool."""

# pylint: disable=duplicate-code,missing-function-docstring

from __future__ import annotations

from web_listening.request.model import ContentType, Scope
from web_listening.tool_registry.discovery.builtins.sitemap import (
    SITEMAP_MANIFEST,
    SitemapDiscoveryTool,
)
from web_listening.tool_registry.manifest import ToolCategory, ToolDistribution
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryFailure,
    DiscoveryInput,
    DiscoveryOutput,
)

SOURCE_URL = "https://example.test/feed/sitemap.xml"


def _input(body: bytes, mime_type: str = "application/xml") -> DiscoveryInput:
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


def test_sitemap_returns_canonical_bounded_deduplicated_candidates() -> None:
    rows = "".join(
        f"<url><loc>https://example.test/page-{index:03d}</loc></url>"
        for index in reversed(range(101))
    )
    body = (
        "<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
        "<url><loc>HTTPS://EXAMPLE.TEST:443/a/%7e</loc></url>"
        "<url><loc>https://example.test/a/~</loc></url>"
        f"{rows}"
        "</urlset>"
    ).encode()

    output = SitemapDiscoveryTool().discover(_input(body))

    assert isinstance(output, DiscoveryOutput)
    assert output.tool_id == SITEMAP_MANIFEST.tool_id
    assert len(output.candidates) == 100
    assert output.candidates == tuple(sorted(set(output.candidates)))
    assert output.candidates[0] == "https://example.test/a/~"
    assert output.discovered_from == (SOURCE_URL,) * len(output.candidates)


def test_sitemap_index_emits_child_sitemaps_without_reading_them() -> None:
    body = b"""<?xml version='1.0'?>
    <sitemapindex xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>
      <sitemap><loc>/feed/child-b.xml</loc></sitemap>
      <sitemap><loc>https://outside.test/child-a.xml</loc></sitemap>
    </sitemapindex>
    """

    output = SitemapDiscoveryTool().discover(_input(body))

    assert isinstance(output, DiscoveryOutput)
    assert output.candidates == (
        "https://example.test/feed/child-b.xml",
        "https://outside.test/child-a.xml",
    )
    assert output.discovered_from == (SOURCE_URL, SOURCE_URL)


def test_sitemap_returns_safe_failures_for_damaged_or_unsupported_sources() -> None:
    tool = SitemapDiscoveryTool()

    malformed = tool.discover(_input(b"<urlset><url>"))
    unsupported = tool.discover(_input(b"<html/>", "text/html"))

    assert malformed == DiscoveryFailure(
        SITEMAP_MANIFEST.tool_id,
        SITEMAP_MANIFEST.version,
        "discovery.feed_malformed",
    )
    assert unsupported == DiscoveryFailure(
        SITEMAP_MANIFEST.tool_id,
        SITEMAP_MANIFEST.version,
        "discovery.mime_unsupported",
    )


def test_sitemap_rejects_utf16_internal_entity_declarations() -> None:
    body = """<?xml version='1.0' encoding='utf-16'?>
    <!DOCTYPE urlset [<!ENTITY private 'https://example.test/private'>]>
    <urlset><url><loc>&private;</loc></url></urlset>
    """.encode("utf-16")

    output = SitemapDiscoveryTool().discover(_input(body))

    assert output == DiscoveryFailure(
        SITEMAP_MANIFEST.tool_id,
        SITEMAP_MANIFEST.version,
        "discovery.feed_malformed",
    )


def test_sitemap_manifest_is_one_builtin_discovery_tool() -> None:
    assert SITEMAP_MANIFEST.category is ToolCategory.DISCOVERY
    assert SITEMAP_MANIFEST.distribution is ToolDistribution.BUILTIN
    assert SITEMAP_MANIFEST.capabilities == frozenset({"sitemap"})
