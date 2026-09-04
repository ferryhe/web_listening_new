"""Offline behavior tests for the built-in simple HTML Transform."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import ast
import hashlib
import inspect
import socket
from pathlib import Path

import pytest

import web_listening.tool_registry.transform.builtins.simple_html_markdown as transform_module
from web_listening.artifact.model import ArtifactRole
from web_listening.artifact.observation import ObservationProposal
from web_listening.artifact.store import ArtifactStore
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
)
from web_listening.tool_registry.protocols.transform import (
    TransformFailure,
    TransformInput,
    TransformOutput,
)
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)

SOURCE_URL = "https://example.test/reports/annual/"
OBSERVED_AT = "2026-08-26T12:00:00Z"
SIMPLE_HTML = b"""<!doctype html>
<html>
  <head><script>private script words</script><style>.x { display: none; }</style></head>
  <body>
    <nav>Navigation must disappear</nav>
    <main>
      <h1>Annual Report</h1>
      <p>Visible <strong>results</strong> and <a href="../details">full details</a>.</p>
      <p hidden>Hidden words must disappear.</p>
      <ul><li>First finding</li><li>Second finding</li></ul>
    </main>
  </body>
</html>"""
EXPECTED_MARKDOWN = b"""# Annual Report

Visible **results** and [full details](https://example.test/reports/details).

- First finding
- Second finding
"""


def _stored_source(
    tmp_path: Path,
    body: bytes = SIMPLE_HTML,
    *,
    mime_type: str = "text/html",
    role: ArtifactRole = ArtifactRole.SOURCE,
):
    store = ArtifactStore(tmp_path / "artifacts")
    source = store.commit_observation(
        ObservationProposal(
            content=body,
            sha256=hashlib.sha256(body).hexdigest(),
            size_bytes=len(body),
            mime_type=mime_type,
            source_url=SOURCE_URL,
            observed_at=OBSERVED_AT,
            role=role,
        )
    )
    return store, source


def test_manifest_is_one_small_qualified_builtin_transform() -> None:
    manifest = SIMPLE_HTML_MARKDOWN_MANIFEST

    assert manifest.tool_id == "transform.simple_html_markdown"
    assert manifest.version == "1.0.0"
    assert manifest.category is ToolCategory.TRANSFORM
    assert manifest.distribution is ToolDistribution.BUILTIN
    assert manifest.capabilities == frozenset({"html_to_markdown"})
    assert manifest.health is HealthStatus.HEALTHY
    assert manifest.qualification is QualificationStatus.QUALIFIED
    assert manifest.limits.max_input_bytes == 2 * 1024 * 1024
    assert manifest.limits.max_output_bytes == 2 * 1024 * 1024


def test_simple_html_is_deterministic_and_removes_non_visible_text(
    tmp_path: Path,
) -> None:
    store, source = _stored_source(tmp_path)
    tool = SimpleHtmlMarkdownTransform()
    try:
        first = tool.transform(TransformInput(source))
        second = tool.transform(
            TransformInput(store.get_observation(source.observation.observation_id))
        )
    finally:
        store.close()

    assert isinstance(first, TransformOutput)
    assert isinstance(second, TransformOutput)
    assert second.body == first.body
    assert second.sha256 == first.sha256
    assert second.source_artifact_id == first.source_artifact_id
    assert second.mime_type == first.mime_type
    assert first.source_artifact_id == source.artifact.artifact_id
    assert first.mime_type == "text/markdown"
    assert first.body == EXPECTED_MARKDOWN
    assert first.sha256 == hashlib.sha256(EXPECTED_MARKDOWN).hexdigest()
    assert b"private" not in first.body
    assert b"Navigation" not in first.body
    assert b"Hidden" not in first.body


@pytest.mark.parametrize("mime_type", ["text/html", "application/xhtml+xml"])
def test_simple_html_accepts_both_html_media_types(
    tmp_path: Path, mime_type: str
) -> None:
    store, source = _stored_source(tmp_path, mime_type=mime_type)
    try:
        result = SimpleHtmlMarkdownTransform().transform(TransformInput(source))
    finally:
        store.close()

    assert isinstance(result, TransformOutput)
    assert result.source_artifact_id == source.artifact.artifact_id


def test_runtime_ms_uses_controlled_monotonic_elapsed_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticks = iter((1_000_000_000, 1_007_900_000))
    monkeypatch.setattr(transform_module.time, "monotonic_ns", lambda: next(ticks))
    store, source = _stored_source(tmp_path)
    try:
        result = SimpleHtmlMarkdownTransform().transform(TransformInput(source))
    finally:
        store.close()

    assert isinstance(result, TransformOutput)
    assert result.runtime_ms == 7
    assert result.body == EXPECTED_MARKDOWN
    assert result.sha256 == hashlib.sha256(EXPECTED_MARKDOWN).hexdigest()


def test_preformatted_code_preserves_leading_line_whitespace(tmp_path: Path) -> None:
    body = (
        b"<pre>if ready:\n    publish()</pre>"
        b"<p>Five visible words keep this eligible.</p>"
    )
    store, source = _stored_source(tmp_path, body)
    try:
        result = SimpleHtmlMarkdownTransform().transform(TransformInput(source))
    finally:
        store.close()

    assert isinstance(result, TransformOutput)
    assert result.body == (
        b"```\nif ready:\n    publish()\n```\n\n"
        b"Five visible words keep this eligible.\n"
    )


def test_blockquote_paragraph_content_remains_quoted(tmp_path: Path) -> None:
    body = (
        b"<blockquote><p>These five quoted words should stay quoted.</p></blockquote>"
    )
    store, source = _stored_source(tmp_path, body)
    try:
        result = SimpleHtmlMarkdownTransform().transform(TransformInput(source))
    finally:
        store.close()

    assert isinstance(result, TransformOutput)
    assert result.body == b"> These five quoted words should stay quoted.\n"


def test_paragraph_inside_list_item_keeps_bullet_context(tmp_path: Path) -> None:
    body = b"<ul><li><p>First list item has enough visible words.</p></li></ul>"
    store, source = _stored_source(tmp_path, body)
    try:
        result = SimpleHtmlMarkdownTransform().transform(TransformInput(source))
    finally:
        store.close()

    assert isinstance(result, TransformOutput)
    assert result.body == b"- First list item has enough visible words.\n"


def test_blockquote_explicit_line_break_keeps_each_line_quoted(
    tmp_path: Path,
) -> None:
    body = (
        b"<blockquote><p>First quoted line<br>"
        b"Second quoted line has enough words.</p></blockquote>"
    )
    store, source = _stored_source(tmp_path, body)
    try:
        result = SimpleHtmlMarkdownTransform().transform(TransformInput(source))
    finally:
        store.close()

    assert isinstance(result, TransformOutput)
    assert result.body == (
        b"> First quoted line\n> Second quoted line has enough words.\n"
    )


def test_blockquote_prefix_precedes_inline_delimiter_after_line_break(
    tmp_path: Path,
) -> None:
    body = (
        b"<blockquote><p>First quoted line<br><strong>"
        b"Second line has enough visible words.</strong></p></blockquote>"
    )
    store, source = _stored_source(tmp_path, body)
    try:
        result = SimpleHtmlMarkdownTransform().transform(TransformInput(source))
    finally:
        store.close()

    assert isinstance(result, TransformOutput)
    assert result.body == (
        b"> First quoted line\n> **Second line has enough visible words.**\n"
    )


@pytest.mark.parametrize(
    ("body", "mime_type", "expected_code"),
    [
        (b"plain file words only", "text/plain", "transform.ineligible_mime"),
        (
            b"<html><body>too short</body></html>",
            "text/html",
            "transform.ineligible_quality",
        ),
        (
            (
                b"<html><body>"
                + (b"<div>" * 65)
                + b"enough visible words for the explicit quality threshold"
                + (b"</div>" * 65)
                + b"</body></html>"
            ),
            "text/html",
            "transform.ineligible_complex",
        ),
    ],
)
def test_non_html_low_quality_and_complex_inputs_are_explicitly_skipped(
    tmp_path: Path, body: bytes, mime_type: str, expected_code: str
) -> None:
    store, source = _stored_source(tmp_path, body, mime_type=mime_type)
    try:
        result = SimpleHtmlMarkdownTransform().transform(TransformInput(source))
    finally:
        store.close()

    assert result == TransformFailure(
        SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id,
        SIMPLE_HTML_MARKDOWN_MANIFEST.version,
        expected_code,
    )


@pytest.mark.parametrize(
    "body",
    [
        b"<p>Enough visible words remain <strong>unclosed here</p>",
        b'<p>Enough visible words remain <a href="/details">unclosed here</p>',
    ],
)
def test_unclosed_supported_inline_markup_is_invalid(
    tmp_path: Path, body: bytes
) -> None:
    store, source = _stored_source(tmp_path, body)
    try:
        result = SimpleHtmlMarkdownTransform().transform(TransformInput(source))
    finally:
        store.close()

    assert result == TransformFailure(
        SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id,
        SIMPLE_HTML_MARKDOWN_MANIFEST.version,
        "transform.html_invalid",
    )


def test_transform_has_no_network_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, source = _stored_source(tmp_path)
    source_text = inspect.getsource(transform_module)
    imported_roots: set[str] = set()
    for node in ast.walk(ast.parse(source_text)):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
    assert imported_roots.isdisjoint({"http", "httpx", "requests", "socket", "urllib3"})

    def reject_socket(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Transform attempted network access")

    monkeypatch.setattr(socket, "socket", reject_socket)
    try:
        result = SimpleHtmlMarkdownTransform().transform(TransformInput(source))
    finally:
        store.close()

    assert isinstance(result, TransformOutput)
    assert result.body == EXPECTED_MARKDOWN
