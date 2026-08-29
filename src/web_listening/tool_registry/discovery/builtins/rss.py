"""Pure built-in parser for one already-governed RSS or Atom response."""

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
    DiscoveryCoverage,
    DiscoveryFailure,
    DiscoveryInput,
    DiscoveryOutput,
    validate_url,
)

_MAX_CANDIDATES = 100
_FEED_MIME_TYPES = frozenset(
    {"application/atom+xml", "application/rss+xml", "application/xml", "text/xml"}
)

RSS_MANIFEST = ToolManifest(
    tool_id="discovery.rss",
    version="1.0.0",
    category=ToolCategory.DISCOVERY,
    distribution=ToolDistribution.BUILTIN,
    capabilities=frozenset({"rss"}),
    limits=ToolLimits(
        max_runtime_seconds=30,
        max_input_bytes=2 * 1024 * 1024,
        max_output_bytes=256 * 1024,
    ),
    health=HealthStatus.HEALTHY,
    qualification=QualificationStatus.QUALIFIED,
)


class RssDiscoveryTool:  # pylint: disable=too-few-public-methods
    """Extract inert entry URLs without performing network or Store I/O."""

    manifest = RSS_MANIFEST

    def discover(
        self, tool_input: DiscoveryInput
    ) -> DiscoveryOutput | DiscoveryFailure:
        """Parse one RSS or Atom document into bounded candidates."""
        if tool_input.source_mime_type not in _FEED_MIME_TYPES:
            return self._failure("discovery.mime_unsupported")
        try:
            root = _parse_xml(tool_input.source_body)
        except (ElementTree.ParseError, ValueError):
            return self._failure("discovery.feed_malformed")
        root_name = _local_name(root.tag)
        if root_name not in {"feed", "rss", "rdf"}:
            return self._failure("discovery.feed_malformed")

        all_candidates = _candidate_urls(root, tool_input.source_url)
        if not all_candidates:
            return self._failure("discovery.no_candidates")
        coverage = (
            DiscoveryCoverage.TRUNCATED
            if len(all_candidates) > _MAX_CANDIDATES
            else DiscoveryCoverage.COMPLETE
        )
        candidates = all_candidates[:_MAX_CANDIDATES]
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            candidates,
            (tool_input.source_url,) * len(candidates),
            coverage,
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


def _candidate_urls(root: ElementTree.Element, source_url: str) -> tuple[str, ...]:
    found: set[str] = set()
    for entry in root.iter():
        entry_name = _local_name(entry.tag)
        if entry_name not in {"entry", "item"}:
            continue
        for link in entry:
            if _local_name(link.tag) != "link":
                continue
            if entry_name == "entry" and link.attrib.get("rel", "alternate") not in {
                "",
                "alternate",
            }:
                continue
            raw_url = link.attrib.get("href") if entry_name == "entry" else link.text
            if not raw_url or not raw_url.strip():
                continue
            try:
                found.add(validate_url(urljoin(source_url, raw_url.strip())))
            except ToolRegistryError:
                continue
    return tuple(sorted(found))


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].casefold()


__all__ = ["RSS_MANIFEST", "RssDiscoveryTool"]
