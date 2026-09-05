"""Pure deterministic navigation declarations from governed HTML bytes."""

# pylint: disable=too-few-public-methods,missing-function-docstring

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from web_listening.request.model import ContentType, classify_mime_type
from web_listening.request.scope import path_is_included
from web_listening.tool_registry.discovery.builtins.html_links import (
    HtmlLinksDiscoveryTool,
)
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

HTML_NAVIGATION_MANIFEST = ToolManifest(
    tool_id="discovery.html_navigation",
    version="1.0.0",
    category=ToolCategory.DISCOVERY,
    distribution=ToolDistribution.BUILTIN,
    capabilities=frozenset({"html_navigation"}),
    limits=ToolLimits(30, 8 * 1024 * 1024, 256 * 1024),
    health=HealthStatus.HEALTHY,
    qualification=QualificationStatus.QUALIFIED,
)
_REFRESH_URL = re.compile(r"(?:^|;)\s*url\s*=\s*(['\"]?)(.*?)\1\s*$", re.I)


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base: str | None = None
        self.meta: list[str] = []
        self.downloads: list[str] = []

    def handle_starttag(self, tag, attrs):
        values = {key.casefold(): value for key, value in attrs}
        tag = tag.casefold()
        if tag == "base" and self.base is None and values.get("href"):
            self.base = values["href"]
        elif tag == "meta" and (values.get("http-equiv") or "").casefold() == "refresh":
            match = _REFRESH_URL.search(values.get("content") or "")
            if match and match.group(2):
                self.meta.append(match.group(2))
        elif tag == "a" and "download" in values and values.get("href"):
            self.downloads.append(values["href"])


class HtmlNavigationDiscoveryTool:
    """Extract explicit navigation, falling back to one complete ordinary link."""

    manifest = HTML_NAVIGATION_MANIFEST

    def discover(
        self, tool_input: DiscoveryInput
    ) -> DiscoveryOutput | DiscoveryFailure:
        if classify_mime_type(tool_input.source_mime_type) is not ContentType.HTML:
            return DiscoveryFailure(
                self.manifest.tool_id,
                self.manifest.version,
                "discovery.mime_unsupported",
            )
        parser = _Parser()
        try:
            parser.feed(tool_input.source_body.decode("utf-8", errors="replace"))
            parser.close()
        except (UnicodeError, ValueError):
            return DiscoveryFailure(
                self.manifest.tool_id, self.manifest.version, "discovery.html_malformed"
            )
        base = (
            urljoin(tool_input.source_url, parser.base)
            if parser.base
            else tool_input.source_url
        )
        explicit = parser.meta if parser.meta else parser.downloads
        candidates = self._eligible(explicit, base, tool_input)
        if not candidates and not parser.meta and not parser.downloads:
            ordinary = HtmlLinksDiscoveryTool().discover(tool_input)
            if (
                isinstance(ordinary, DiscoveryOutput)
                and ordinary.coverage is DiscoveryCoverage.COMPLETE
            ):
                scoped = tuple(
                    candidate
                    for candidate in ordinary.candidates
                    if self._in_scope(candidate, tool_input)
                )
                if len(scoped) == 1:
                    candidates = scoped
        if not candidates:
            return DiscoveryFailure(
                self.manifest.tool_id, self.manifest.version, "discovery.no_candidates"
            )
        return DiscoveryOutput(
            self.manifest.tool_id,
            self.manifest.version,
            candidates,
            (tool_input.source_url,) * len(candidates),
            DiscoveryCoverage.COMPLETE,
        )

    def _eligible(self, hrefs, base, tool_input):
        candidates = set()
        for href in hrefs:
            try:
                candidate = validate_url(urljoin(base, href.strip()))
            except (ToolRegistryError, ValueError):
                continue
            if self._in_scope(candidate, tool_input):
                candidates.add(candidate)
        return tuple(sorted(candidates))

    @staticmethod
    def _in_scope(candidate, tool_input):
        parsed = urlsplit(candidate)
        return (
            f"{parsed.scheme}://{parsed.netloc}" in tool_input.scope.allowed_origins
            and path_is_included(parsed.path, tool_input.scope.include_paths)
        )


__all__ = ["HTML_NAVIGATION_MANIFEST", "HtmlNavigationDiscoveryTool"]
