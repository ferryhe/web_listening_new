"""Pure built-in Transform for explicitly simple stored HTML."""

# pylint: disable=duplicate-code

from __future__ import annotations

import hashlib
import re
import time
from html.parser import HTMLParser
from urllib.parse import urljoin

from web_listening.artifact.model import ArtifactRole
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
)
from web_listening.tool_registry.protocols.transform import (
    TransformFailure,
    TransformInput,
    TransformOutput,
)

_MIN_VISIBLE_WORDS = 5
_MAX_ELEMENTS = 10_000
_MAX_DEPTH = 64
_HEADING_LEVELS = {f"h{level}": level for level in range(1, 7)}
_PAIRED_MARKUP_TAGS = frozenset({"a", "b", "code", "em", "i", "pre", "strong"})
_NOISE_TAGS = frozenset(
    {
        "aside",
        "canvas",
        "footer",
        "head",
        "header",
        "iframe",
        "nav",
        "noscript",
        "script",
        "style",
        "svg",
        "template",
    }
)
_VOID_TAGS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)

SIMPLE_HTML_MARKDOWN_MANIFEST = ToolManifest(
    tool_id="transform.simple_html_markdown",
    version="1.0.0",
    category=ToolCategory.TRANSFORM,
    distribution=ToolDistribution.BUILTIN,
    capabilities=frozenset({"html_to_markdown"}),
    limits=ToolLimits(
        max_runtime_seconds=30,
        max_input_bytes=2 * 1024 * 1024,
        max_output_bytes=2 * 1024 * 1024,
    ),
    health=HealthStatus.HEALTHY,
    qualification=QualificationStatus.QUALIFIED,
)


class SimpleHtmlMarkdownTransform:  # pylint: disable=too-few-public-methods
    """Convert bounded visible HTML text without network or Store authority."""

    manifest = SIMPLE_HTML_MARKDOWN_MANIFEST

    def transform(
        self, tool_input: TransformInput
    ) -> (
        TransformOutput | TransformFailure
    ):  # pylint: disable=too-many-return-statements
        """Return deterministic Markdown or one explicit eligibility failure."""
        started_ns = time.monotonic_ns()
        source = tool_input.source
        if source.artifact.role is not ArtifactRole.SOURCE:
            return self._failure("transform.source_required")
        if source.artifact.mime_type != "text/html":
            return self._failure("transform.ineligible_mime")
        try:
            html = source.content.decode("utf-8")
            parser = _MarkdownParser(source.observation.source_url)
            parser.feed(html)
            parser.close()
        except (UnicodeError, ValueError):
            return self._failure("transform.html_invalid")
        if not parser.markup_balanced:
            return self._failure("transform.html_invalid")
        if parser.element_count > _MAX_ELEMENTS or parser.max_depth > _MAX_DEPTH:
            return self._failure("transform.ineligible_complex")
        markdown = _normalize_markdown("".join(parser.fragments))
        if parser.visible_word_count < _MIN_VISIBLE_WORDS or not markdown.strip():
            return self._failure("transform.ineligible_quality")
        body = markdown.encode("utf-8")
        if len(body) > self.manifest.limits.max_output_bytes:
            return self._failure("transform.output_limit")
        runtime_ms = max(0, (time.monotonic_ns() - started_ns) // 1_000_000)
        return TransformOutput(
            self.manifest.tool_id,
            self.manifest.version,
            source.artifact.artifact_id,
            "text/markdown",
            body,
            hashlib.sha256(body).hexdigest(),
            runtime_ms,
        )

    def _failure(self, code: str) -> TransformFailure:
        return TransformFailure(self.manifest.tool_id, self.manifest.version, code)


class _MarkdownParser(HTMLParser):  # pylint: disable=too-many-instance-attributes
    """Small streaming renderer with explicit size/depth quality facts."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.fragments: list[str] = []
        self.element_count = 0
        self.max_depth = 0
        self._depth = 0
        self._ignored: list[str] = []
        self._links: list[str | None] = []
        self._visible_text: list[str] = []
        self._pre_depth = 0
        self._open_markup: list[str] = []
        self._invalid_markup = False
        self._in_blockquote = False
        self._in_list_item = False

    @property
    def visible_word_count(self) -> int:
        """Return the small quality rule's visible word count."""
        return len(re.findall(r"\b[\w'-]+\b", " ".join(self._visible_text)))

    @property
    def markup_balanced(self) -> bool:
        """Return whether supported delimiter-producing tags closed in order."""
        return not self._invalid_markup and not self._open_markup

    def handle_starttag(  # pylint: disable=missing-function-docstring,too-many-branches,too-many-statements
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        tag = tag.casefold()
        self.element_count += 1
        if tag not in _VOID_TAGS:
            self._depth += 1
            self.max_depth = max(self.max_depth, self._depth)
        if self._ignored:
            if tag not in _VOID_TAGS:
                self._ignored.append(tag)
            return
        attributes = {name.casefold(): value or "" for name, value in attrs}
        if tag in _NOISE_TAGS or _is_hidden(attributes):
            if tag not in _VOID_TAGS:
                self._ignored.append(tag)
            return
        if tag in _PAIRED_MARKUP_TAGS:
            self._open_markup.append(tag)
        if tag in _HEADING_LEVELS:
            self._block_break()
            self.fragments.append("#" * _HEADING_LEVELS[tag] + " ")
        elif tag in {"article", "div", "main", "p", "section"}:
            if tag != "p" or not self._in_list_item:
                self._block_break()
            if tag == "p" and self._in_blockquote:
                self.fragments.append("> ")
        elif tag in {"ol", "ul"}:
            self._block_break()
        elif tag == "li":
            self._line_break()
            self.fragments.append("- ")
            self._in_list_item = True
        elif tag == "blockquote":
            self._block_break()
            self._in_blockquote = True
        elif tag == "br":
            self._line_break()
        elif tag == "a":
            href = attributes.get("href", "").strip()
            self._links.append(urljoin(self.base_url, href) if href else None)
            if href:
                self._ensure_blockquote_prefix()
                self.fragments.append("[")
        elif tag in {"b", "strong"}:
            self._ensure_blockquote_prefix()
            self.fragments.append("**")
        elif tag in {"em", "i"}:
            self._ensure_blockquote_prefix()
            self.fragments.append("*")
        elif tag == "pre":
            self._block_break()
            self.fragments.append("```\n")
            self._pre_depth += 1
        elif tag == "code" and not self._pre_depth:
            self._ensure_blockquote_prefix()
            self.fragments.append("`")
        elif tag == "img":
            source = attributes.get("src", "").strip()
            if source:
                alt = attributes.get("alt", "").strip()
                self._ensure_blockquote_prefix()
                self.fragments.append(f"![{alt}]({urljoin(self.base_url, source)})")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.casefold() not in _VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(  # pylint: disable=missing-function-docstring,too-many-branches
        self, tag: str
    ) -> None:
        tag = tag.casefold()
        if self._ignored:
            if tag in self._ignored:
                while self._ignored:
                    ignored = self._ignored.pop()
                    if ignored == tag:
                        break
            if tag not in _VOID_TAGS:
                self._depth = max(0, self._depth - 1)
            return
        if tag in _PAIRED_MARKUP_TAGS:
            if not self._open_markup or self._open_markup[-1] != tag:
                self._invalid_markup = True
                if tag not in _VOID_TAGS:
                    self._depth = max(0, self._depth - 1)
                return
            self._open_markup.pop()
        if tag in _HEADING_LEVELS or tag in {
            "article",
            "blockquote",
            "div",
            "main",
            "ol",
            "p",
            "section",
            "ul",
        }:
            if tag != "p" or not self._in_list_item:
                self._block_break()
            if tag == "blockquote":
                self._in_blockquote = False
        elif tag == "li":
            self._line_break()
            self._in_list_item = False
        elif tag == "a":
            target = self._links.pop() if self._links else None
            if target:
                self.fragments.append(f"]({target})")
        elif tag in {"b", "strong"}:
            self.fragments.append("**")
        elif tag in {"em", "i"}:
            self.fragments.append("*")
        elif tag == "pre":
            self.fragments.append("\n```")
            self._block_break()
            self._pre_depth = max(0, self._pre_depth - 1)
        elif tag == "code" and not self._pre_depth:
            self.fragments.append("`")
        if tag not in _VOID_TAGS:
            self._depth = max(0, self._depth - 1)

    def handle_data(self, data: str) -> None:
        if self._ignored or not data.strip():
            return
        self._ensure_blockquote_prefix()
        self.fragments.append(data)
        self._visible_text.append(data)

    def _ensure_blockquote_prefix(self) -> None:
        if self._in_blockquote and (
            not self.fragments or self.fragments[-1].endswith("\n")
        ):
            self.fragments.append("> ")

    def _block_break(self) -> None:
        if self.fragments and not "".join(self.fragments[-2:]).endswith("\n\n"):
            self.fragments.append("\n\n")

    def _line_break(self) -> None:
        if self.fragments and not self.fragments[-1].endswith("\n"):
            self.fragments.append("\n")


def _is_hidden(attributes: dict[str, str]) -> bool:
    if "hidden" in attributes or attributes.get("aria-hidden", "").casefold() == "true":
        return True
    style = re.sub(r"\s+", "", attributes.get("style", "").casefold())
    return "display:none" in style or "visibility:hidden" in style


def _normalize_markdown(value: str) -> str:
    normalized: list[str] = []
    blank_pending = False
    in_fence = False
    for raw_line in value.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if in_fence:
            if raw_line.strip() == "```":
                normalized.append("```")
                in_fence = False
            else:
                normalized.append(raw_line)
            continue
        line = re.sub(r"[ \t\f\v]+", " ", raw_line.replace("\xa0", " ")).strip()
        if not line:
            blank_pending = bool(normalized)
            continue
        if blank_pending:
            normalized.append("")
        normalized.append(line)
        blank_pending = False
        if line == "```":
            in_fence = True
    return "\n".join(normalized).strip() + "\n"


__all__ = ["SIMPLE_HTML_MARKDOWN_MANIFEST", "SimpleHtmlMarkdownTransform"]
