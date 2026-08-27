"""Deterministic stdlib-only external basic HTML-to-Markdown fixture."""

# pylint: disable=duplicate-code,missing-function-docstring

from __future__ import annotations

import base64
import hashlib
import json
import sys
from html.parser import HTMLParser
from pathlib import Path

TOOL_ID = "external.basic_html_markdown"
VERSION = "1.0.0"
EXTERNAL_PROTOCOL = "web-listening-external-tool.v1"
QUALIFICATION_PROTOCOL = "web-listening-tool-qualification.v1"
FAILURE_MARKER = b"data-external-transform-fail"


class _MarkdownParser(HTMLParser):
    """Render basic block structure without acquisition or storage authority."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.ignored_depth = 0

    def handle_starttag(self, tag: str, _attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        if tag in {"script", "style"}:
            self.ignored_depth += 1
        elif self.ignored_depth == 0:
            if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
                self.parts.append("\n" + "#" * int(tag[1]) + " ")
            elif tag == "li":
                self.parts.append("\n- ")
            elif tag in {"article", "br", "div", "main", "p", "section"}:
                self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag in {"script", "style"}:
            self.ignored_depth = max(0, self.ignored_depth - 1)
        elif self.ignored_depth == 0 and tag in {
            "article",
            "div",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "li",
            "main",
            "p",
            "section",
        }:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self.ignored_depth == 0:
            text = " ".join(data.split())
            if text:
                self.parts.append(text + " ")

    def render(self) -> bytes:
        lines = [" ".join(line.split()) for line in "".join(self.parts).splitlines()]
        markdown = "\n\n".join(line for line in lines if line)
        return (markdown + "\n").encode("utf-8") if markdown else b""


def _failure(code: str) -> dict[str, object]:
    return {
        "protocol_version": EXTERNAL_PROTOCOL,
        "category": "transform",
        "status": "failed",
        "tool_id": TOOL_ID,
        "tool_version": VERSION,
        "result": {"code": code},
    }


def _transform(request: dict[str, object]) -> dict[str, object]:
    tool_input = request["input"]
    if not isinstance(tool_input, dict):
        return _failure("external.input_invalid")
    mime_type = tool_input.get("source_mime_type")
    try:
        body = base64.b64decode(str(tool_input["source_body_base64"]), validate=True)
    except (KeyError, ValueError):
        return _failure("external.input_invalid")
    if FAILURE_MARKER in body:
        return _failure("external.transform_failed")
    if mime_type == "text/html":
        parser = _MarkdownParser()
        parser.feed(body.decode("utf-8", errors="replace"))
        output = parser.render()
    elif mime_type == "text/plain":
        text = "\n".join(
            line.strip()
            for line in body.decode("utf-8", errors="replace").splitlines()
            if line.strip()
        )
        output = (text + "\n").encode("utf-8") if text else b""
    else:
        return _failure("external.unsupported_mime")
    if not output:
        return _failure("external.empty_output")
    output_path = Path("derived.md")
    output_path.write_bytes(output)
    return {
        "protocol_version": EXTERNAL_PROTOCOL,
        "category": "transform",
        "status": "success",
        "tool_id": TOOL_ID,
        "tool_version": VERSION,
        "result": {
            "source_artifact_id": tool_input["source_artifact_id"],
            "mime_type": "text/markdown",
            "output_path": output_path.name,
            "size_bytes": len(output),
            "sha256": hashlib.sha256(output).hexdigest(),
            "runtime_ms": 0,
        },
    }


def _qualification(request: dict[str, object]) -> dict[str, object]:
    operation = request.get("operation")
    expected = {
        "protocol_version": QUALIFICATION_PROTOCOL,
        "operation": operation,
        "tool_id": TOOL_ID,
        "version": VERSION,
        "category": "transform",
    }
    if operation == "probe":
        expected["checks"] = ["stored_source", "derived_output"]
    if request != expected:
        raise SystemExit("invalid qualification request")
    response: dict[str, object] = {
        "protocol_version": QUALIFICATION_PROTOCOL,
        "operation": operation,
        "status": "ok",
    }
    if operation == "describe":
        response.update(tool_id=TOOL_ID, version=VERSION, category="transform")
    elif operation == "health":
        response["health"] = "healthy"
    elif operation == "probe":
        response.update(
            result="qualified",
            category="transform",
            checks=["stored_source", "derived_output"],
        )
    else:
        raise SystemExit("unsupported qualification operation")
    return response


REQUEST = json.load(sys.stdin)
RESPONSE = (
    _transform(REQUEST)
    if REQUEST.get("protocol_version") == EXTERNAL_PROTOCOL
    else _qualification(REQUEST)
)
json.dump(RESPONSE, sys.stdout, sort_keys=True)
