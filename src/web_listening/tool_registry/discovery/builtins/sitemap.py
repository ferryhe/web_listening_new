"""Pure built-in parser for one already-governed Sitemap response."""

# pylint: disable=duplicate-code

from __future__ import annotations

from urllib.parse import urljoin
from xml.etree import ElementTree
from xml.parsers import expat

from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
    ToolRegistryError,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryFailure,
    DiscoveryInput,
    DiscoveryOutput,
    validate_url,
)

_MAX_CANDIDATES = 100
_XML_MIME_TYPES = frozenset({"application/xml", "application/sitemap+xml", "text/xml"})

SITEMAP_MANIFEST = ToolManifest(
    tool_id="discovery.sitemap",
    version="1.0.0",
    category=ToolCategory.DISCOVERY,
    distribution=ToolDistribution.BUILTIN,
    capabilities=frozenset({"sitemap"}),
    limits=ToolLimits(
        max_runtime_seconds=30,
        max_input_bytes=2 * 1024 * 1024,
        max_output_bytes=256 * 1024,
    ),
    health=HealthStatus.HEALTHY,
    qualification=QualificationStatus.QUALIFIED,
)


class SitemapDiscoveryTool:  # pylint: disable=too-few-public-methods
    """Extract inert URL candidates without performing network or Store I/O."""

    manifest = SITEMAP_MANIFEST

    def discover(
        self, tool_input: DiscoveryInput
    ) -> DiscoveryOutput | DiscoveryFailure:
        """Parse one Sitemap URL set or index into bounded candidates."""
        if tool_input.source_mime_type not in _XML_MIME_TYPES:
            return self._failure("discovery.mime_unsupported")
        try:
            root = _parse_xml(tool_input.source_body)
        except (ElementTree.ParseError, ValueError):
            return self._failure("discovery.feed_malformed")
        root_name = _local_name(root.tag)
        if root_name == "urlset":
            row_name = "url"
        elif root_name == "sitemapindex":
            row_name = "sitemap"
        else:
            return self._failure("discovery.feed_malformed")

        candidates = _candidate_urls(root, row_name, tool_input.source_url)
        if not candidates:
            return self._failure("discovery.no_candidates")
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            candidates,
            (tool_input.source_url,) * len(candidates),
        )

    def _failure(self, code: str) -> DiscoveryFailure:
        return DiscoveryFailure(self.manifest.tool_id, self.manifest.version, code)


def _parse_xml(body: bytes) -> ElementTree.Element:
    parser = expat.ParserCreate()
    parser.StartDoctypeDeclHandler = _reject_declaration
    parser.EntityDeclHandler = _reject_declaration
    try:
        parser.Parse(body, True)
    except expat.ExpatError as exc:
        raise ElementTree.ParseError from exc
    return ElementTree.fromstring(body)


def _reject_declaration(*_args: object) -> None:
    raise ValueError("declarations are not feed data")


def _candidate_urls(
    root: ElementTree.Element, row_name: str, source_url: str
) -> tuple[str, ...]:
    found: set[str] = set()
    for row in root:
        if _local_name(row.tag) != row_name:
            continue
        raw_url = next(
            (
                child.text.strip()
                for child in row
                if _local_name(child.tag) == "loc" and child.text and child.text.strip()
            ),
            None,
        )
        if raw_url is None:
            continue
        try:
            found.add(validate_url(urljoin(source_url, raw_url)))
        except ToolRegistryError:
            continue
    return tuple(sorted(found)[:_MAX_CANDIDATES])


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].casefold()


__all__ = ["SITEMAP_MANIFEST", "SitemapDiscoveryTool"]
