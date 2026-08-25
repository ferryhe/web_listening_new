"""Focused contract tests for the built-in governed HTTP acquisition tool."""

# pylint: disable=duplicate-code

from __future__ import annotations

import hashlib
import inspect
from urllib.parse import urlsplit

import pytest

import web_listening.tool_registry.acquisition.builtins.web_http as web_http_module
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
    AcquisitionRedirect,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners.in_process import (
    GatewayEvidence,
    GatewayFailure,
    GovernedAccessGateway,
    UsageEvidence,
)

PUBLIC_IP = "93.184.216.34"


class _ScriptedResponse:
    """Minimal response owned and closed by the real Gateway."""

    def __init__(self, status: int, body: bytes = b"", **headers: str) -> None:
        self.status = status
        self.body = body
        self.headers = {
            name.replace("_", "-"): value for name, value in headers.items()
        }
        self.peer_ip = PUBLIC_IP
        self.read_limits: list[int] = []
        self.closed = 0

    def read(self, max_bytes: int) -> bytes:
        """Return the bounded scripted body."""
        self.read_limits.append(max_bytes)
        return self.body[:max_bytes]

    def close(self) -> None:
        """Record response ownership cleanup."""
        self.closed += 1


class _ScriptedTransport:
    """Return fixed responses without DNS, sockets, or network access."""

    def __init__(
        self, scripts: dict[str, list[_ScriptedResponse | BaseException]]
    ) -> None:
        self.scripts = scripts
        self.requests: list[str] = []
        self.closed = 0

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> _ScriptedResponse:
        """Return the next response for an approved Gateway send."""
        del timeout, addresses
        self.requests.append(url)
        outcome = self.scripts[url].pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def close(self) -> None:
        """Record transport ownership cleanup."""
        self.closed += 1


class _HostileGateway:
    """Test-only replacement for malformed Gateway failures."""

    def __init__(self, failure: GatewayFailure) -> None:
        self.failure = failure
        self.closed = 0

    def read(self, _url: str) -> None:
        """Raise the scripted malformed failure."""
        raise self.failure

    def close(self) -> None:
        """Record per-attempt cleanup."""
        self.closed += 1


def _resolver(_host: str, _port: int) -> tuple[str, ...]:
    return (PUBLIC_IP,)


def _request(
    url: str = "https://example.test/report",
    *,
    allowed_origins: tuple[str, ...] | None = None,
    content_types: tuple[ContentType, ...] = (ContentType.HTML, ContentType.FILE),
) -> Request:
    parsed = urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return Request(
        Scope(
            seeds=(url,),
            allowed_origins=allowed_origins or (origin,),
            include_paths=("/**",),
            content_types=content_types,
        ),
        None,
        False,
        Budgets(6, 2 * 1024 * 1024, 30, 1),
    )


def _tool(transport: _ScriptedTransport) -> WebHttpAcquisitionTool:
    return WebHttpAcquisitionTool(lambda: transport, resolver=_resolver)


def _direct_transport(
    body: bytes, mime_type: str, url: str = "https://example.test/report"
) -> tuple[_ScriptedTransport, _ScriptedResponse, _ScriptedResponse]:
    robots = _ScriptedResponse(404)
    target = _ScriptedResponse(
        200,
        body,
        Content_Type=mime_type,
        Content_Length=str(len(body)),
    )
    return (
        _ScriptedTransport(
            {
                f"{urlsplit(url).scheme}://{urlsplit(url).netloc}/robots.txt": [robots],
                url: [target],
            }
        ),
        robots,
        target,
    )


def _gateway_failure(code: str) -> GatewayFailure:
    url = "https://example.test/report"
    return GatewayFailure(
        code,
        GatewayEvidence(
            requested_url=url,
            current_url=url,
            final_url=url,
            decisions=(),
            redirects=(),
            robots=(),
            usage=UsageEvidence(0, 0, 0.01),
            response_status=None,
            response_mime_type=None,
            content_bytes=0,
            content_sha256=None,
        ),
    )


def test_manifest_is_the_stable_minimal_builtin_acquisition_identity() -> None:
    """The built-in identity and eligibility claims remain explicit."""
    assert WEB_HTTP_MANIFEST.tool_id == "acquisition.web_http"
    assert WEB_HTTP_MANIFEST.version == "1.0.0"
    assert WEB_HTTP_MANIFEST.category is ToolCategory.ACQUISITION
    assert WEB_HTTP_MANIFEST.distribution is ToolDistribution.BUILTIN
    assert WEB_HTTP_MANIFEST.capabilities == frozenset({"http_get"})
    assert WEB_HTTP_MANIFEST.health is HealthStatus.HEALTHY
    assert WEB_HTTP_MANIFEST.qualification is QualificationStatus.QUALIFIED


@pytest.mark.parametrize(
    ("body", "mime_type"),
    [
        (b"<html><body>governed</body></html>", "text/html"),
        (b"%PDF-1.7\noriginal bytes", "application/pdf"),
    ],
)
def test_html_and_file_success_preserve_gateway_content_evidence(
    body: bytes, mime_type: str
) -> None:
    """Original HTML and file bytes map without transformation."""
    url = "https://example.test/report"
    transport, robots, target = _direct_transport(body, mime_type, url)

    output = _tool(transport).acquire(AcquisitionInput(_request(url), url))

    assert isinstance(output, AcquisitionOutput)
    assert output.tool_id == "acquisition.web_http"
    assert output.tool_version == "1.0.0"
    assert output.requested_url == output.final_url == url
    assert output.status_code == 200
    assert output.mime_type == mime_type
    assert output.body == body
    assert output.sha256 == hashlib.sha256(body).hexdigest()
    assert not output.redirects
    assert output.runtime_ms >= 0
    assert transport.requests == ["https://example.test/robots.txt", url]
    assert robots.closed == target.closed == transport.closed == 1
    assert target.read_limits == [len(body)]


def test_manual_target_redirects_map_without_robots_redirects() -> None:
    """Only target transitions belong in Acquisition redirect evidence."""
    requested = "https://example.test/report"
    final = "https://example.test/final"
    transport = _ScriptedTransport(
        {
            "https://example.test/robots.txt": [
                _ScriptedResponse(301, Location="/robots-v2.txt")
            ],
            "https://example.test/robots-v2.txt": [_ScriptedResponse(404)],
            requested: [_ScriptedResponse(302, Location=final)],
            final: [_ScriptedResponse(200, b"redirected", Content_Type="text/html")],
        }
    )

    output = _tool(transport).acquire(AcquisitionInput(_request(requested), requested))

    assert isinstance(output, AcquisitionOutput)
    assert output.redirects == (AcquisitionRedirect(requested, final, 302),)
    assert output.final_url == final
    assert transport.requests == [
        "https://example.test/robots.txt",
        "https://example.test/robots-v2.txt",
        requested,
        final,
    ]
    assert transport.closed == 1


def test_invocation_request_blocks_redirect_before_disallowed_origin_read() -> None:
    """The invocation Request governs the real Gateway before every send."""
    start = "https://example.com/start"
    outside = "https://other.example/final"
    allowed_robots = _ScriptedResponse(404)
    initial = _ScriptedResponse(302, Location=outside)
    outside_robots = _ScriptedResponse(404)
    forbidden_content = _ScriptedResponse(200, b"forbidden", Content_Type="text/html")
    transport = _ScriptedTransport(
        {
            "https://example.com/robots.txt": [allowed_robots],
            start: [initial],
            "https://other.example/robots.txt": [outside_robots],
            outside: [forbidden_content],
        }
    )
    narrow_request = _request(
        start,
        allowed_origins=("https://example.com",),
        content_types=(ContentType.HTML,),
    )

    failure = _tool(transport).acquire(AcquisitionInput(narrow_request, start))

    assert failure == AcquisitionFailure(
        "acquisition.web_http", "1.0.0", "scope.origin_not_allowed"
    )
    assert transport.requests == ["https://example.com/robots.txt", start]
    assert allowed_robots.closed == initial.closed == transport.closed == 1
    assert outside_robots.closed == forbidden_content.closed == 0


def test_prebuilt_broad_gateway_cannot_be_reused_as_transport_factory() -> None:
    """The removed prebuilt-Gateway seam cannot perform any read."""
    start = "https://example.com/start"
    transport = _ScriptedTransport({})
    broad_gateway = GovernedAccessGateway(
        _request(
            start,
            allowed_origins=("https://example.com", "https://other.example"),
        ),
        transport,
        resolver=_resolver,
    )
    tool = WebHttpAcquisitionTool(broad_gateway)  # type: ignore[arg-type]

    failure = tool.acquire(AcquisitionInput(_request(start), start))
    broad_gateway.close()

    assert failure == AcquisitionFailure(
        "acquisition.web_http", "1.0.0", "web_http.failure"
    )
    assert not transport.requests
    assert transport.closed == 1


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (TimeoutError("private timeout"), "gateway.timeout"),
        (OSError("private transport"), "gateway.transport"),
    ],
)
def test_gateway_timeout_and_transport_failures_keep_safe_codes(
    error: BaseException, code: str
) -> None:
    """Target transport failures cross the adapter unchanged and safely."""
    url = "https://example.test/report"
    robots = _ScriptedResponse(404)
    transport = _ScriptedTransport(
        {"https://example.test/robots.txt": [robots], url: [error]}
    )

    failure = _tool(transport).acquire(AcquisitionInput(_request(url), url))

    assert failure == AcquisitionFailure("acquisition.web_http", "1.0.0", code)
    assert "private" not in str(failure)
    assert transport.requests == ["https://example.test/robots.txt", url]
    assert robots.closed == transport.closed == 1


def test_ordinary_transport_factory_exception_is_safely_contained() -> None:
    """Unexpected factory diagnostics collapse to one safe stable code."""
    secret = "private-factory-diagnostic"
    tool = WebHttpAcquisitionTool(lambda: (_ for _ in ()).throw(RuntimeError(secret)))

    failure = tool.acquire(AcquisitionInput(_request(), "https://example.test/report"))

    assert failure == AcquisitionFailure(
        "acquisition.web_http", "1.0.0", "web_http.failure"
    )
    assert secret not in str(failure)


def test_invalid_gateway_failure_code_is_contained_without_private_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even malformed Gateway failure metadata cannot escape the adapter."""
    private_code = "private=diagnostic"
    hostile = _HostileGateway(_gateway_failure(private_code))
    monkeypatch.setattr(
        web_http_module,
        "GovernedAccessGateway",
        lambda _request, _transport, resolver=None: hostile,
    )
    transport = _ScriptedTransport({})

    failure = _tool(transport).acquire(
        AcquisitionInput(_request(), "https://example.test/report")
    )

    assert failure == AcquisitionFailure(
        "acquisition.web_http", "1.0.0", "web_http.failure"
    )
    assert private_code not in str(failure)
    assert hostile.closed == 1


def test_registry_requires_explicit_registration_and_invokes_the_adapter() -> None:
    """No import-time discovery or implicit registration is introduced."""
    url = "https://example.test/report"
    transport, _robots, _target = _direct_transport(b"registry", "text/html", url)
    tool = _tool(transport)
    registry = Registry()

    assert not registry.query()
    registry.register(WEB_HTTP_MANIFEST, tool)
    output = registry.invoke(
        WEB_HTTP_MANIFEST.tool_id,
        AcquisitionInput(_request(url), url),
    )

    assert isinstance(output, AcquisitionOutput)
    assert output.body == b"registry"
    assert registry.query(category=ToolCategory.ACQUISITION) == (WEB_HTTP_MANIFEST,)
    assert transport.closed == 1


def test_registry_query_url_returns_safe_failure_instead_of_invalid_output() -> None:
    """Gateway URL redaction cannot escape as a Registry contract error."""
    url = "https://example.test/report?access=private-token"
    transport, _robots, _target = _direct_transport(b"query", "text/html", url)
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, _tool(transport))

    output = registry.invoke(
        WEB_HTTP_MANIFEST.tool_id,
        AcquisitionInput(_request(url), url),
    )

    assert output == AcquisitionFailure(
        "acquisition.web_http", "1.0.0", "web_http.url_redacted"
    )
    assert transport.requests == ["https://example.test/robots.txt", url]
    assert transport.closed == 1


def test_repeat_acquisitions_use_and_close_fresh_request_bound_gateways() -> None:
    """Every invocation owns fresh resources and closes them before returning."""
    url = "https://example.test/report"
    transports: list[_ScriptedTransport] = []

    def transport_factory() -> _ScriptedTransport:
        transport, _robots, _target = _direct_transport(b"repeat", "text/html", url)
        transports.append(transport)
        return transport

    tool = WebHttpAcquisitionTool(transport_factory, resolver=_resolver)
    tool_input = AcquisitionInput(_request(url), url)

    assert isinstance(tool.acquire(tool_input), AcquisitionOutput)
    assert isinstance(tool.acquire(tool_input), AcquisitionOutput)

    assert len(transports) == 2
    assert all(transport.closed == 1 for transport in transports)


def test_close_is_idempotent_and_rejects_before_resource_creation() -> None:
    """A closed adapter cannot allocate a transport or begin access."""
    factory_calls = 0

    def transport_factory() -> _ScriptedTransport:
        nonlocal factory_calls
        factory_calls += 1
        return _ScriptedTransport({})

    tool = WebHttpAcquisitionTool(transport_factory, resolver=_resolver)

    tool.close()
    tool.close()
    failure = tool.acquire(AcquisitionInput(_request(), "https://example.test/report"))

    assert factory_calls == 0
    assert failure == AcquisitionFailure(
        "acquisition.web_http", "1.0.0", "gateway.closed"
    )


def test_adapter_has_no_store_runtime_fallback_or_second_network_path() -> None:
    """The source remains a thin Gateway-to-protocol mapping layer."""
    source = inspect.getsource(inspect.getmodule(WebHttpAcquisitionTool)).casefold()
    forbidden = (
        "import requests",
        "import httpx",
        "import urllib",
        "import http.client",
        "import socket",
        "web_listening.artifact",
        "web_listening.runtime",
        "fallback",
        "playwright",
    )

    assert all(token not in source for token in forbidden)
