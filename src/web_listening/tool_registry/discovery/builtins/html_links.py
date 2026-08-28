"""Pure built-in parser for links in one already-governed HTML response."""

# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

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
_HTML_MIME_TYPES = frozenset({"application/xhtml+xml", "text/html"})
_LINK_TAGS = frozenset({"a", "area", "link"})

HTML_LINKS_MANIFEST = ToolManifest(
    tool_id="discovery.html_links",
    version="1.0.0",
    category=ToolCategory.DISCOVERY,
    distribution=ToolDistribution.BUILTIN,
    capabilities=frozenset({"html_links"}),
    limits=ToolLimits(30, 8 * 1024 * 1024, 256 * 1024),
    health=HealthStatus.HEALTHY,
    qualification=QualificationStatus.QUALIFIED,
)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_href: str | None = None
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        href = values.get("href")
        if not href:
            return
        normalized = tag.casefold()
        if normalized == "base" and self.base_href is None:
            self.base_href = href
        elif normalized in _LINK_TAGS:
            self.hrefs.append(href)


class HtmlLinksDiscoveryTool:  # pylint: disable=too-few-public-methods
    """Extract bounded inert links without network or Store authority."""

    manifest = HTML_LINKS_MANIFEST

    def __init__(self, *, max_candidates: int = _MAX_CANDIDATES) -> None:
        if type(max_candidates) is not int or not 0 < max_candidates <= _MAX_CANDIDATES:
            raise ToolRegistryError("discovery.limit_invalid")
        self._max_candidates = max_candidates

    def discover(
        self, tool_input: DiscoveryInput
    ) -> DiscoveryOutput | DiscoveryFailure:
        """Parse standard HTML link declarations into stable canonical URLs."""
        if tool_input.source_mime_type not in _HTML_MIME_TYPES:
            return self._failure("discovery.mime_unsupported")
        parser = _LinkParser()
        try:
            parser.feed(tool_input.source_body.decode("utf-8", errors="replace"))
            parser.close()
        except (UnicodeError, ValueError):
            return self._failure("discovery.html_malformed")
        base_url = tool_input.source_url
        if parser.base_href is not None:
            base_url = urljoin(base_url, parser.base_href)
        candidates: set[str] = set()
        for href in parser.hrefs:
            try:
                joined = urljoin(base_url, href.strip())
                parsed = urlsplit(joined)
                joined = urlunsplit(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.query, "")
                )
                candidates.add(validate_url(joined))
            except (ToolRegistryError, ValueError):
                continue
        ordered = tuple(sorted(candidates)[: self._max_candidates])
        if not ordered:
            return self._failure("discovery.no_candidates")
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            ordered,
            (tool_input.source_url,) * len(ordered),
        )

    def _failure(self, code: str) -> DiscoveryFailure:
        return DiscoveryFailure(self.manifest.tool_id, self.manifest.version, code)


__all__ = ["HTML_LINKS_MANIFEST", "HtmlLinksDiscoveryTool"]
