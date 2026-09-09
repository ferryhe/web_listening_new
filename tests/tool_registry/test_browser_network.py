"""Parent bridge reads use the unchanged Gateway (no public traffic)."""

# Intentional cross-test fixtures: pytest resolves the repository namespace.
# pylint: disable=import-error
# pylint: disable=missing-function-docstring,duplicate-code

from dataclasses import replace
from hashlib import sha256

import pytest

from tests.tool_registry.test_access_gateway import (
    FakeResponse,
    FakeTransport,
    Resolver,
)
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.tool_registry.protocols.acquisition import AcquisitionOutput
from web_listening.tool_registry.runners.browser_network import BrowserNetworkBridge

ORIGIN = "https://example.com"
ROBOTS = b"User-agent: *\nAllow: /\n"


def request(max_requests=6, content_types=(ContentType.HTML, ContentType.FILE)):
    return Request(
        Scope((ORIGIN + "/",), (ORIGIN,), ("/**",), content_types),
        None,
        True,
        Budgets(max_requests, 65536, 5, 3),
    )


def bridge(req=None, robots=ROBOTS):
    transport = FakeTransport(
        {
            ORIGIN
            + "/robots.txt": [FakeResponse(200, robots, content_type="text/plain")],
            ORIGIN
            + "/": [
                FakeResponse(
                    200, b"<script src='/app.js'></script>", content_type="text/html"
                )
            ],
            ORIGIN
            + "/app.js": [
                FakeResponse(
                    200, b"fetch('/data.json')", content_type="application/javascript"
                )
            ],
            ORIGIN
            + "/data.json": [
                FakeResponse(
                    200, b'{"value":"public content"}', content_type="application/json"
                )
            ],
        }
    )
    return (
        BrowserNetworkBridge(
            req or request(), ORIGIN + "/", transport, resolver=Resolver()
        ),
        transport,
    )


def test_navigation_script_xhr_use_one_ledger_and_parent_robots():
    reader, transport = bridge()
    try:
        results = [
            reader.read(url, "GET", navigation=index == 0)
            for index, url in enumerate(
                (ORIGIN + "/", ORIGIN + "/app.js", ORIGIN + "/data.json")
            )
        ]
        assert all(item["ok"] for item in results)
        assert reader.requests == 4
        assert reader.bytes_received == len(ROBOTS) + sum(
            len(item["body"]) for item in results
        )
        assert len(reader.robots_decisions) == 3
        assert len(transport.requests) == 4
    finally:
        reader.close()
    assert transport.closed == 1


@pytest.mark.parametrize(
    "case,code",
    [
        ("robots", "robots.disallowed"),
        ("origin", "scope.origin_not_allowed"),
        ("method", "browser.read_only"),
        ("budget", "budget.requests"),
        ("cancel", "runtime.cancelled"),
    ],
)
def test_boundary_failures_stop_without_extra_egress(case, code):
    req = request(2 if case == "budget" else 6)
    reader, transport = bridge(
        req, b"User-agent: *\nDisallow: /\n" if case == "robots" else ROBOTS
    )
    if case == "cancel":
        reader.should_cancel = lambda: True
    url = "https://other.example/" if case == "origin" else ORIGIN + "/"
    try:
        result = reader.read(
            url, "POST" if case == "method" else "GET", navigation=True
        )
        if case == "budget":
            assert result["ok"]
            result = reader.read(ORIGIN + "/app.js", "GET")
        assert result["code"] == code
        before = len(transport.requests)
        assert not reader.read(ORIGIN + "/data.json", "GET")["ok"]
        assert len(transport.requests) == before
    finally:
        reader.close()


def test_html_only_request_does_not_gain_resource_permission():
    reader, _ = bridge(
        replace(
            request(), scope=replace(request().scope, content_types=(ContentType.HTML,))
        )
    )
    try:
        assert reader.read(ORIGIN + "/", "GET", navigation=True)["ok"]
        assert not reader.read(ORIGIN + "/app.js", "GET")["ok"]
    finally:
        reader.close()


def test_subframe_navigation_keeps_main_document_parent_evidence():
    reader, transport = bridge()
    transport.scripts[ORIGIN + "/frame"] = [
        FakeResponse(200, b"<p>frame</p>", content_type="text/html")
    ]
    try:
        assert reader.read(ORIGIN + "/", "GET", navigation=True)["ok"]
        assert reader.read(
            ORIGIN + "/frame", "GET", navigation=True, main_document=False
        )["ok"]
        body = b"<p>Main rendered content</p>"
        output = AcquisitionOutput(
            "acquisition.playwright",
            "1.0.0",
            ORIGIN + "/",
            ORIGIN + "/",
            200,
            "text/html",
            body,
            sha256(body).hexdigest(),
            (),
            1,
        )
        result = reader.normalize(output)
        assert isinstance(result, AcquisitionOutput)
        assert result.requests == 3
    finally:
        reader.close()
