"""Pure built-in parser for links in one already-governed HTML response."""

# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from web_listening.request.scope import path_is_included
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

HTML_FILE_LINKS_MANIFEST = ToolManifest(
    tool_id="discovery.html_file_links",
    version="1.0.0",
    category=ToolCategory.DISCOVERY,
    distribution=ToolDistribution.BUILTIN,
    capabilities=frozenset({"html_file_links"}),
    limits=ToolLimits(30, 8 * 1024 * 1024, 256 * 1024),
    health=HealthStatus.HEALTHY,
    qualification=QualificationStatus.QUALIFIED,
)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_href: str | None = None
        self.links: list[tuple[str, bool]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        href = values.get("href")
        if not href:
            return
        normalized = tag.casefold()
        if normalized == "base" and self.base_href is None:
            self.base_href = href
        elif normalized in _LINK_TAGS:
            self.links.append(
                (
                    href,
                    normalized == "a"
                    and any(name.casefold() == "download" for name, _ in attrs),
                )
            )


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
        all_candidates = tuple(sorted(_canonical_links(parser, base_url)))
        ordered = all_candidates[: self._max_candidates]
        if not ordered:
            return self._failure("discovery.no_candidates")
        coverage = (
            DiscoveryCoverage.TRUNCATED
            if len(all_candidates) > self._max_candidates
            else DiscoveryCoverage.COMPLETE
        )
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            ordered,
            (tool_input.source_url,) * len(ordered),
            coverage,
        )

    def _failure(self, code: str) -> DiscoveryFailure:
        return DiscoveryFailure(self.manifest.tool_id, self.manifest.version, code)


class HtmlFileLinksDiscoveryTool:  # pylint: disable=too-few-public-methods
    """Prioritize inert file-hinted links without granting acquisition authority."""

    manifest = HTML_FILE_LINKS_MANIFEST

    def __init__(self, *, max_candidates: int = _MAX_CANDIDATES) -> None:
        if type(max_candidates) is not int or not 0 < max_candidates <= _MAX_CANDIDATES:
            raise ToolRegistryError("discovery.limit_invalid")
        self._max_candidates = max_candidates

    def discover(
        self, tool_input: DiscoveryInput
    ) -> DiscoveryOutput | DiscoveryFailure:
        """Return stable file-hinted candidates, with child-scope matches first."""
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
        links = _canonical_links(parser, base_url)
        fallback = tuple(sorted(links))
        preferred = tuple(
            candidate
            for candidate in fallback
            if (
                links[candidate] or urlsplit(candidate).path.casefold().endswith(".pdf")
            )
            and _is_same_site_scope_candidate(candidate, tool_input)
        )
        preferred_set = frozenset(preferred)
        selected = (
            preferred
            + tuple(
                candidate for candidate in fallback if candidate not in preferred_set
            )
            if preferred
            else fallback
        )
        ordered = selected[: self._max_candidates]
        if not ordered:
            return self._failure("discovery.no_candidates")
        coverage = (
            DiscoveryCoverage.TRUNCATED
            if len(selected) > self._max_candidates
            else DiscoveryCoverage.COMPLETE
        )
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            ordered,
            (tool_input.source_url,) * len(ordered),
            coverage,
        )

    def _failure(self, code: str) -> DiscoveryFailure:
        return DiscoveryFailure(self.manifest.tool_id, self.manifest.version, code)


def _canonical_links(parser: _LinkParser, base_url: str) -> dict[str, bool]:
    candidates: dict[str, bool] = {}
    for href, download in parser.links:
        try:
            joined = urljoin(base_url, href.strip())
            parsed = urlsplit(joined)
            joined = urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.query, "")
            )
            candidate = validate_url(joined)
        except (ToolRegistryError, ValueError):
            continue
        candidates[candidate] = candidates.get(candidate, False) or download
    return candidates


def _is_same_site_scope_candidate(candidate: str, tool_input: DiscoveryInput) -> bool:
    parsed = urlsplit(candidate)
    source = urlsplit(tool_input.source_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return (
        parsed.hostname == source.hostname
        and origin in tool_input.scope.allowed_origins
        and path_is_included(parsed.path, tool_input.scope.include_paths)
    )


__all__ = [
    "HTML_FILE_LINKS_MANIFEST",
    "HTML_LINKS_MANIFEST",
    "HtmlFileLinksDiscoveryTool",
    "HtmlLinksDiscoveryTool",
]
