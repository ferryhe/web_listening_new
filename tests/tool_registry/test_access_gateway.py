"""Focused offline tests for the one governed in-process access gateway."""

# pylint: disable=protected-access,too-few-public-methods,too-many-arguments,too-many-lines

from __future__ import annotations

import hashlib
import http.client
import inspect
import io
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Callable

import pytest

from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.tool_registry.runners import in_process as in_process_runner
from web_listening.tool_registry.runners.in_process import (
    GatewayFailure,
    GovernedAccessGateway,
    PinnedHttpTransport,
    TransportResponse,
)

PUBLIC_IP = "93.184.216.34"
OTHER_PUBLIC_IP = "93.184.216.35"
ROBOTS_ALLOW = b"User-agent: *\nAllow: /\n"
ROBOTS_DENY_PRIVATE = b"User-agent: *\nDisallow: /private\n"
TARGETS = Path(__file__).parents[1] / "live" / "phase_02_site_targets.json"


class FakeResponse:
    """One response whose read and close ownership is observable."""

    def __init__(
        self,
        status: int,
        body: bytes = b"",
        *,
        peer_ip: str = PUBLIC_IP,
        close_raises: bool = False,
        **headers: str,
    ) -> None:
        self.status = status
        self.headers = {
            key.replace("_", "-").lower(): value for key, value in headers.items()
        }
        self.peer_ip = peer_ip
        self.body = body
        self.close_raises = close_raises
        self.read_limits: list[int] = []
        self.closed = 0

    def read(self, max_bytes: int) -> bytes:
        """Record the bound and emulate a transport that honors it."""
        self.read_limits.append(max_bytes)
        return self.body[:max_bytes]

    def close(self) -> None:
        """Record ownership and optionally simulate a cleanup error."""
        self.closed += 1
        if self.close_raises:
            raise LookupError("private-close-secret")


class FakeTransport:
    """Scripted transport that records gateway-owned safety inputs."""

    def __init__(
        self, scripts: dict[str, list[TransportResponse | BaseException]]
    ) -> None:
        self.scripts = scripts
        self.requests: list[tuple[str, float, tuple[str, ...]]] = []
        self.closed = 0

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> TransportResponse:
        """Return the next scripted response without implicit redirects."""
        self.requests.append((url, timeout, addresses))
        scripted = self.scripts[url].pop(0)
        if isinstance(scripted, BaseException):
            raise scripted
        return scripted

    def close(self) -> None:
        """Record gateway-owned transport cleanup."""
        self.closed += 1


class FailingCloseTransport(FakeTransport):
    """A transport whose ordinary cleanup failure contains private detail."""

    def close(self) -> None:
        """Record cleanup before raising a non-listed ordinary exception."""
        super().close()
        raise LookupError("private-close-secret")


class Resolver:
    """Deterministic DNS source for offline policy tests."""

    def __init__(self, values: dict[str, tuple[str, ...]] | None = None) -> None:
        self.values = values or {
            "example.com": (PUBLIC_IP,),
            "other.example": (OTHER_PUBLIC_IP,),
        }
        self.calls: list[tuple[str, int]] = []

    def __call__(self, host: str, port: int) -> tuple[str, ...]:
        self.calls.append((host, port))
        return self.values[host]


class ManualClock:
    """A monotonic clock whose runtime can be advanced without sleeping."""

    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class AdvancingTransport(FakeTransport):
    """Advance the clock after a response exists but before gateway handoff."""

    def __init__(
        self,
        scripts: dict[str, list[TransportResponse | BaseException]],
        clock: ManualClock,
    ) -> None:
        super().__init__(scripts)
        self.clock = clock

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> TransportResponse:
        """Return a response after consuming the remaining runtime."""
        response = super().send(url, timeout=timeout, addresses=addresses)
        self.clock.value = 2.0
        return response


class PrivatePeerSocket:
    """A connected private peer used to prove the pre-HTTP safety order."""

    def __init__(self) -> None:
        self.closed = 0

    def settimeout(self, _timeout: float) -> None:
        """Accept the bounded timeout without changing the scripted peer."""

    def getpeername(self) -> tuple[str, int]:
        """Return a private peer that is outside the approved DNS set."""
        return ("127.0.0.1", 80)

    def close(self) -> None:
        """Record cleanup after the safety rejection."""
        self.closed += 1
        raise LookupError("private-close-secret")


class RecordingHttpResponse:
    """Minimal standard-library response double for the concrete wrapper."""

    status = 200

    def __init__(
        self, body: bytes, headers: list[tuple[str, str]] | None = None
    ) -> None:
        self.body = body
        self.headers = headers or [("Content-Length", str(len(body)))]
        self.read_limits: list[int] = []
        self.closed = 0

    def getheaders(self) -> list[tuple[str, str]]:
        """Return one bounded framing header."""
        return self.headers

    def read(self, amount: int) -> bytes:
        """Record the exact amount requested by the concrete wrapper."""
        self.read_limits.append(amount)
        return self.body[:amount]

    def close(self) -> None:
        """Record wrapper-owned response cleanup."""
        self.closed += 1


class RecordingConnection:
    """Minimal close-only connection double."""

    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        """Record wrapper-owned connection cleanup."""
        self.closed += 1


class MemorySocket:
    """Give HTTPResponse one complete in-memory HTTP/1.1 exchange."""

    def __init__(self, wire: bytes) -> None:
        self.stream = io.BytesIO(wire)

    def makefile(self, *_args: object, **_kwargs: object) -> io.BytesIO:
        """Return the response byte stream expected by HTTPResponse."""
        return self.stream


def concrete_http_response(
    headers: bytes, encoded_body: bytes
) -> tuple[TransportResponse, RecordingConnection]:
    """Wrap a real stdlib HTTPResponse for offline framing tests."""
    wire = b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n" + encoded_body
    raw = http.client.HTTPResponse(MemorySocket(wire))
    raw.begin()
    connection = RecordingConnection()
    return in_process_runner._HttpResponse(raw, connection, PUBLIC_IP), connection


def request_for(
    url: str = "https://example.com/public",
    *,
    origins: tuple[str, ...] = ("https://example.com",),
    paths: tuple[str, ...] = ("/**",),
    max_requests: int = 6,
    max_bytes: int = 2 * 1024 * 1024,
    max_runtime_seconds: int = 30,
    content_types: tuple[ContentType, ...] = (ContentType.HTML,),
) -> Request:
    """Build one direct Phase 1 Request without adding gateway authority."""
    return Request(
        scope=Scope(
            seeds=(url,),
            allowed_origins=origins,
            include_paths=paths,
            content_types=content_types,
        ),
        site_skill=None,
        explore_all_tools=False,
        budgets=Budgets(
            max_requests=max_requests,
            max_bytes=max_bytes,
            max_runtime_seconds=max_runtime_seconds,
            max_tool_attempts_per_target=1,
        ),
    )


def gateway(
    transport: FakeTransport,
    request: Request | None = None,
    resolver: Callable[[str, int], tuple[str, ...]] | None = None,
) -> GovernedAccessGateway:
    """Create a gateway with no real DNS or network access."""
    return GovernedAccessGateway(
        request or request_for(), transport, resolver=resolver or Resolver()
    )


def failure_code(call: Callable[[], object]) -> GatewayFailure:
    """Return the stable failure raised by one governed read."""
    with pytest.raises(GatewayFailure) as caught:
        call()
    assert str(caught.value) == caught.value.code
    return caught.value


def test_robots_denial_precedes_target_content_and_has_no_store_authority() -> None:
    """A denied target is never opened and the gateway cannot receive a store."""
    robots = FakeResponse(200, ROBOTS_DENY_PRIVATE, Content_Type="text/plain")
    transport = FakeTransport({"https://example.com/robots.txt": [robots]})
    access = gateway(
        transport,
        request_for("https://example.com/private/report", paths=("/private/**",)),
    )

    failure = failure_code(lambda: access.read("https://example.com/private/report"))

    assert failure.code == "robots.disallowed"
    assert [item[0] for item in transport.requests] == [
        "https://example.com/robots.txt"
    ]
    assert robots.read_limits and robots.closed == 1
    assert failure.evidence.robots[-1].code == "robots.disallowed"
    assert "artifact" not in inspect.signature(GovernedAccessGateway).parameters
    assert "store" not in inspect.signature(access.read).parameters


def test_cached_robots_denial_precedes_later_target_dns_failure() -> None:
    """A cached denial stops target DNS and network work on every read."""
    resolver_calls: list[tuple[str, int]] = []
    fail_dns = False

    def controlled_resolver(host: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((host, port))
        if fail_dns:
            raise LookupError("private-dns-secret")
        return (PUBLIC_IP,)

    robots = FakeResponse(200, ROBOTS_DENY_PRIVATE, Content_Type="text/plain")
    transport = FakeTransport({"https://example.com/robots.txt": [robots]})
    access = gateway(
        transport,
        request_for("https://example.com/private/report", paths=("/private/**",)),
        resolver=controlled_resolver,
    )

    first = failure_code(lambda: access.read("https://example.com/private/report"))
    fail_dns = True
    first_dns_count = len(resolver_calls)
    first_request_count = len(transport.requests)
    second = failure_code(lambda: access.read("https://example.com/private/report"))

    assert first.code == second.code == "robots.disallowed"
    assert first.evidence.robots[-1].code == "robots.disallowed"
    assert second.evidence.robots[-1].code == "robots.disallowed"
    assert resolver_calls == [("example.com", 443)]
    assert len(resolver_calls) == first_dns_count
    assert len(transport.requests) == first_request_count == 1


def test_redirect_hop_rechecks_scope_robots_dns_peer_and_budget() -> None:
    """Each redirected origin obtains its own robots decision before content."""
    first_robots = FakeResponse(404)
    redirect = FakeResponse(
        302, Location="https://other.example/final", peer_ip=PUBLIC_IP
    )
    second_robots = FakeResponse(404, peer_ip=OTHER_PUBLIC_IP)
    final = FakeResponse(
        200,
        b"done",
        peer_ip=OTHER_PUBLIC_IP,
        Content_Type="text/html; charset=utf-8",
    )
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [first_robots],
            "https://example.com/start": [redirect],
            "https://other.example/robots.txt": [second_robots],
            "https://other.example/final": [final],
        }
    )
    resolver = Resolver()
    access = gateway(
        transport,
        request_for(
            "https://example.com/start",
            origins=("https://example.com", "https://other.example"),
            max_requests=4,
        ),
        resolver,
    )

    result = access.read("https://example.com/start")

    assert result.body == b"done"
    assert result.requested_url == "https://example.com/start"
    assert result.current_url == result.final_url == "https://other.example/final"
    assert result.sha256 == hashlib.sha256(b"done").hexdigest()
    assert result.mime_type == "text/html"
    assert result.evidence.response_status == 200
    assert result.evidence.response_mime_type == "text/html"
    assert result.evidence.content_bytes == 4
    assert result.evidence.content_sha256 == result.sha256
    assert [item[0] for item in transport.requests] == [
        "https://example.com/robots.txt",
        "https://example.com/start",
        "https://other.example/robots.txt",
        "https://other.example/final",
    ]
    assert all(
        response.closed == 1
        for response in (first_robots, redirect, second_robots, final)
    )
    assert result.evidence.usage.requests == 4
    assert len(result.evidence.redirects) == 1
    assert result.evidence.redirects[0].decision_code == "policy.allowed"
    assert {item.origin for item in result.evidence.robots} == {
        "https://example.com",
        "https://other.example",
    }
    assert ("other.example", 443) in resolver.calls


def test_new_redirect_hop_clears_prior_response_fields_before_robots() -> None:
    """A next-hop robots failure cannot inherit the redirect response fields."""
    first_robots = FakeResponse(404)
    redirect = FakeResponse(
        302,
        Location="https://other.example/final",
        Content_Type="text/html; charset=utf-8",
    )
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [first_robots],
            "https://example.com/start": [redirect],
        }
    )

    def resolver(host: str, _port: int) -> tuple[str, ...]:
        if host == "other.example":
            raise LookupError("private-next-hop-dns")
        return (PUBLIC_IP,)

    access = gateway(
        transport,
        request_for(
            "https://example.com/start",
            origins=("https://example.com", "https://other.example"),
        ),
        resolver=resolver,
    )

    failure = failure_code(lambda: access.read("https://example.com/start"))

    assert failure.code == "robots.dns_error"
    assert failure.evidence.current_url == "https://other.example/final"
    assert failure.evidence.final_url == "https://other.example/final"
    assert failure.evidence.response_status is None
    assert failure.evidence.response_mime_type is None
    assert failure.evidence.content_bytes == 0
    assert failure.evidence.content_sha256 is None
    assert failure.evidence.redirects[0].status_code == 302
    assert failure.evidence.redirects[0].target_url == ("https://other.example/final")
    assert any(
        item.stage == "target.redirect" and item.code == "policy.allowed"
        for item in failure.evidence.decisions
    )
    assert [item[0] for item in transport.requests] == [
        "https://example.com/robots.txt",
        "https://example.com/start",
    ]


@pytest.mark.parametrize(
    ("target", "origins", "code"),
    [
        (
            "https://outside.example/final",
            ("https://example.com",),
            "scope.origin_not_allowed",
        ),
        (
            "http://example.com/final",
            ("https://example.com", "http://example.com"),
            "gateway.https_downgrade",
        ),
    ],
)
def test_redirect_policy_rejection_precedes_close_or_target_transport_failure(
    target: str, origins: tuple[str, ...], code: str
) -> None:
    """Redirect policy wins even when cleanup itself reports a private failure."""
    redirect = FakeResponse(302, Location=target, close_raises=True)
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [FakeResponse(404)],
            "https://example.com/start": [redirect],
        }
    )
    access = gateway(
        transport,
        request_for("https://example.com/start", origins=origins),
    )

    failure = failure_code(lambda: access.read("https://example.com/start"))

    assert failure.code == code
    assert [item[0] for item in transport.requests] == [
        "https://example.com/robots.txt",
        "https://example.com/start",
    ]
    assert redirect.closed == 1
    assert "private-close-secret" not in str(failure)
    assert "private-close-secret" not in json.dumps(asdict(failure.evidence))


def test_same_origin_robots_redirect_is_manual_and_cross_origin_is_rejected() -> None:
    """Robots redirects never follow implicitly or acquire a new origin."""
    same_origin = FakeTransport(
        {
            "https://example.com/robots.txt": [
                FakeResponse(301, Location="/robots-policy.txt")
            ],
            "https://example.com/robots-policy.txt": [
                FakeResponse(200, ROBOTS_ALLOW, Content_Type="text/plain")
            ],
            "https://example.com/public": [FakeResponse(302, Location="/final")],
            "https://example.com/final": [
                FakeResponse(200, b"ok", Content_Type="text/html")
            ],
        }
    )
    result = gateway(same_origin).read("https://example.com/public")
    assert result.body == b"ok"
    assert [item[0] for item in same_origin.requests] == [
        "https://example.com/robots.txt",
        "https://example.com/robots-policy.txt",
        "https://example.com/public",
        "https://example.com/final",
    ]
    assert any(item.stage == "robots.redirect" for item in result.evidence.decisions)

    cross_origin = FakeTransport(
        {
            "https://example.com/robots.txt": [
                FakeResponse(302, Location="https://other.example/robots.txt")
            ]
        }
    )
    failure = failure_code(
        lambda: gateway(
            cross_origin,
            request_for(origins=("https://example.com", "https://other.example")),
        ).read("https://example.com/public")
    )
    assert failure.code == "robots.redirect_origin"
    assert len(cross_origin.requests) == 1


@pytest.mark.parametrize(
    ("redirect_kind", "expected_requests"),
    [
        ("robots", ("https://example.com/robots.txt",)),
        (
            "target",
            (
                "https://example.com/robots.txt",
                "https://example.com/public",
            ),
        ),
    ],
)
def test_malformed_redirect_location_is_stable_and_redacted(
    redirect_kind: str, expected_requests: tuple[str, ...]
) -> None:
    """Malformed target and robots redirects never escape or start a next hop."""
    marker = "PRIVATE-REDIRECT-MARKER"
    redirect = FakeResponse(302, Location=f"https://[{marker}")
    scripts: dict[str, list[TransportResponse | BaseException]] = {
        "https://example.com/robots.txt": [
            redirect if redirect_kind == "robots" else FakeResponse(404)
        ]
    }
    if redirect_kind == "target":
        scripts["https://example.com/public"] = [redirect]
    transport = FakeTransport(scripts)
    resolver = Resolver()

    failure = failure_code(
        lambda: gateway(transport, resolver=resolver).read("https://example.com/public")
    )

    assert failure.code == "gateway.redirect_invalid"
    assert redirect.closed == 1
    assert tuple(item[0] for item in transport.requests) == expected_requests
    assert resolver.calls == [("example.com", 443)] * len(expected_requests)
    encoded = json.dumps(asdict(failure.evidence), sort_keys=True)
    assert marker not in encoded
    assert "https://[" not in encoded
    assert len(failure.evidence.redirects) == 1
    transition = failure.evidence.redirects[0]
    assert transition.kind == redirect_kind
    assert transition.status_code == 302
    assert transition.target_url == "[invalid-url]"
    assert transition.decision_code == "gateway.redirect_invalid"
    assert any(
        item.stage == f"{redirect_kind}.redirect"
        and item.code == "gateway.redirect_invalid"
        and not item.allowed
        for item in failure.evidence.decisions
    )


@pytest.mark.parametrize(
    ("redirect_kind", "expected_code"),
    [
        ("robots", "robots.redirect_missing"),
        ("target", "gateway.redirect"),
    ],
)
def test_missing_redirect_location_retains_rejection_evidence(
    redirect_kind: str, expected_code: str
) -> None:
    """A redirect without Location still records one sanitized transition."""
    redirect = FakeResponse(302)
    scripts: dict[str, list[TransportResponse | BaseException]] = {
        "https://example.com/robots.txt": [
            redirect if redirect_kind == "robots" else FakeResponse(404)
        ]
    }
    if redirect_kind == "target":
        scripts["https://example.com/public"] = [redirect]
    transport = FakeTransport(scripts)

    failure = failure_code(
        lambda: gateway(transport).read("https://example.com/public")
    )

    assert failure.code == expected_code
    assert redirect.closed == 1
    assert len(failure.evidence.redirects) == 1
    transition = failure.evidence.redirects[0]
    assert transition.kind == redirect_kind
    assert transition.status_code == 302
    assert transition.target_url == "[invalid-url]"
    assert transition.decision_code == expected_code
    assert any(
        item.stage == f"{redirect_kind}.redirect"
        and item.code == expected_code
        and not item.allowed
        for item in failure.evidence.decisions
    )


def test_dns_and_peer_safety_fail_closed() -> None:
    """Mixed/private DNS and an unexpected connected peer are stable failures."""
    no_transport = FakeTransport({})
    mixed_dns = Resolver({"example.com": (PUBLIC_IP, "127.0.0.1")})
    failure = failure_code(
        lambda: gateway(no_transport, resolver=mixed_dns).read(
            "https://example.com/public"
        )
    )
    assert failure.code == "gateway.dns_not_public"
    assert not no_transport.requests

    private_peer = FakeResponse(404, peer_ip="127.0.0.1")
    peer_transport = FakeTransport({"https://example.com/robots.txt": [private_peer]})
    failure = failure_code(
        lambda: gateway(peer_transport).read("https://example.com/public")
    )
    assert failure.code == "gateway.peer_not_public"
    assert private_peer.closed == 1


@pytest.mark.parametrize("address", ["224.0.0.1", "ff02::1"])
def test_multicast_dns_is_not_public(address: str) -> None:
    """IPv4 and IPv6 multicast addresses never reach the transport."""
    transport = FakeTransport({})
    resolver = Resolver({"example.com": (address,)})

    failure = failure_code(
        lambda: gateway(transport, resolver=resolver).read("https://example.com/public")
    )

    assert failure.code == "gateway.dns_not_public"
    assert not transport.requests


def test_resolver_ordinary_failure_is_stable_and_redacted() -> None:
    """A resolver implementation cannot leak an ordinary private failure."""
    resolver_calls = 0

    def failing_resolver(_host: str, _port: int) -> tuple[str, ...]:
        nonlocal resolver_calls
        resolver_calls += 1
        if resolver_calls == 1:
            return (PUBLIC_IP,)
        raise LookupError("private-dns-secret")

    transport = FakeTransport({"https://example.com/robots.txt": [FakeResponse(404)]})
    failure = failure_code(
        lambda: gateway(transport, resolver=failing_resolver).read(
            "https://example.com/public"
        )
    )

    assert failure.code == "gateway.dns"
    assert [item[0] for item in transport.requests] == [
        "https://example.com/robots.txt"
    ]
    assert "private-dns-secret" not in str(failure)
    assert "private-dns-secret" not in json.dumps(asdict(failure.evidence))


def test_resolver_does_not_swallow_base_exception() -> None:
    """Process-control exceptions remain outside the DNS failure boundary."""

    class ResolverAbort(BaseException):
        """A process-control signal used only by this boundary test."""

    def aborting_resolver(_host: str, _port: int) -> tuple[str, ...]:
        raise ResolverAbort

    with pytest.raises(ResolverAbort):
        gateway(FakeTransport({}), resolver=aborting_resolver).read(
            "https://example.com/public"
        )


def test_resolver_is_bounded_by_the_remaining_runtime() -> None:
    """A slow DNS resolver cannot hold the gateway past its remaining deadline."""
    clock = ManualClock()

    def slow_resolver(_host: str, _port: int) -> tuple[str, ...]:
        time.sleep(0.2)
        return (PUBLIC_IP,)

    access = GovernedAccessGateway(
        request_for(max_runtime_seconds=1),
        FakeTransport({}),
        resolver=slow_resolver,
        clock=clock,
    )
    clock.value = 0.99
    started = time.monotonic()

    failure = failure_code(lambda: access.read("https://example.com/public"))

    assert failure.code == "robots.timeout"
    assert time.monotonic() - started < 0.15
    assert any(
        item.stage == "robots.dns"
        and item.code == "gateway.timeout"
        and not item.allowed
        for item in failure.evidence.decisions
    )


def test_pinned_transport_checks_peer_before_http_application_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rebound private peer is closed before an HTTP connection can send."""
    peer = PrivatePeerSocket()
    monkeypatch.setattr("socket.create_connection", lambda *_args, **_kwargs: peer)
    http_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def forbidden_http(*_args: object, **_kwargs: object) -> object:
        http_calls.append((_args, _kwargs))
        raise AssertionError("HTTP construction must follow the peer gate")

    monkeypatch.setattr("http.client.HTTPConnection", forbidden_http)
    access = GovernedAccessGateway(
        request_for("http://example.com/public", origins=("http://example.com",)),
        PinnedHttpTransport(),
        resolver=Resolver(),
    )

    failure = failure_code(lambda: access.read("http://example.com/public"))

    assert failure.code == "gateway.peer_not_public"
    assert failure.evidence.decisions[-1].stage == "transport.peer"
    assert failure.evidence.decisions[-1].code == "gateway.peer_not_public"
    assert not failure.evidence.decisions[-1].allowed
    assert "private-close-secret" not in str(failure)
    assert "private-close-secret" not in json.dumps(asdict(failure.evidence))
    assert peer.closed == 1
    assert not http_calls


def test_https_tcp_peer_is_approved_before_tls_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A private TCP peer is rejected before any TLS ClientHello setup."""
    peer = PrivatePeerSocket()
    monkeypatch.setattr("socket.create_connection", lambda *_args, **_kwargs: peer)
    tls_calls: list[str] = []

    def forbidden_tls_context() -> object:
        tls_calls.append("context")
        raise AssertionError("TLS must follow the TCP peer gate")

    monkeypatch.setattr("ssl.create_default_context", forbidden_tls_context)
    access = GovernedAccessGateway(
        request_for(),
        PinnedHttpTransport(),
        resolver=Resolver(),
    )

    failure = failure_code(lambda: access.read("https://example.com/public"))

    assert failure.code == "gateway.peer_not_public"
    assert failure.evidence.decisions[-1].stage == "transport.peer"
    assert not failure.evidence.decisions[-1].allowed
    assert "private-close-secret" not in str(failure)
    assert "private-close-secret" not in json.dumps(asdict(failure.evidence))
    assert peer.closed == 1
    assert not tls_calls


def test_concrete_response_never_reads_past_the_governed_amount() -> None:
    """The stdlib wrapper passes the exact remaining limit to HTTPResponse."""
    raw = RecordingHttpResponse(b"0123456789")
    connection = RecordingConnection()
    response = in_process_runner._HttpResponse(raw, connection, PUBLIC_IP)

    assert response.read(5) == b"01234"
    assert raw.read_limits == [5]

    response.close()
    assert raw.closed == connection.closed == 1


@pytest.mark.parametrize("body_owner", ["robots", "target"])
def test_conflicting_framing_rejects_before_any_body_read(body_owner: str) -> None:
    """Content-Length plus Transfer-Encoding is never consumed."""
    framed = FakeResponse(
        200,
        ROBOTS_ALLOW if body_owner == "robots" else b"target",
        Content_Type="text/plain" if body_owner == "robots" else "text/html",
        Content_Length="1",
        Transfer_Encoding="chunked",
    )
    scripts: dict[str, list[TransportResponse | BaseException]] = {
        "https://example.com/robots.txt": [
            framed if body_owner == "robots" else FakeResponse(404)
        ]
    }
    if body_owner == "target":
        scripts["https://example.com/public"] = [framed]

    failure = failure_code(
        lambda: gateway(FakeTransport(scripts)).read("https://example.com/public")
    )

    assert failure.code == "gateway.framing_invalid"
    assert not framed.read_limits
    assert framed.closed == 1
    assert failure.evidence.usage.bytes == 0
    assert failure.evidence.content_bytes == 0
    assert failure.evidence.content_sha256 is None
    assert failure.evidence.decisions[-1].stage == "response.framing"


@pytest.mark.parametrize(
    "transfer_encoding",
    ["", "gzip", "chunked, gzip", "chunked;level=1", "chunked\x00"],
)
def test_invalid_transfer_encoding_rejects_before_body_read(
    transfer_encoding: str,
) -> None:
    """Only one exact chunked coding with surrounding OWS is accepted."""
    target = FakeResponse(
        200,
        b"must-not-be-read",
        Content_Type="text/html",
        Transfer_Encoding=transfer_encoding,
    )
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [FakeResponse(404)],
            "https://example.com/public": [target],
        }
    )

    failure = failure_code(
        lambda: gateway(transport).read("https://example.com/public")
    )

    assert failure.code == "gateway.framing_invalid"
    assert not target.read_limits
    assert failure.evidence.usage.bytes == 0


def test_chunked_with_safe_ows_is_accepted_as_unknown_length() -> None:
    """A legal case-insensitive chunked field follows the strict unknown path."""
    target = FakeResponse(
        200,
        b"target",
        Content_Type="text/html",
        Transfer_Encoding=" \tChUnKeD\t ",
    )
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [FakeResponse(404)],
            "https://example.com/public": [target],
        }
    )

    result = gateway(transport).read("https://example.com/public")

    assert result.body == b"target"
    assert target.read_limits == [2 * 1024 * 1024]


def test_concrete_http_response_dechunks_a_legal_body_under_budget() -> None:
    """The stdlib transport returns the complete legal chunked entity body."""
    target, connection = concrete_http_response(
        b"Content-Type: text/html\r\nTransfer-Encoding: chunked\r\n",
        b"A\r\n0123456789\r\n0\r\n\r\n",
    )
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [FakeResponse(404)],
            "https://example.com/public": [target],
        }
    )

    result = gateway(transport, request_for(max_bytes=100)).read(
        "https://example.com/public"
    )

    assert result.body == b"0123456789"
    assert result.sha256 == hashlib.sha256(result.body).hexdigest()
    assert result.evidence.usage.bytes == 10
    assert connection.closed == 1


def test_concrete_conflicting_framing_cannot_return_truncated_success() -> None:
    """A real CL plus chunked response fails before content or hash evidence."""
    target, connection = concrete_http_response(
        (
            b"Content-Type: text/html\r\n"
            b"Content-Length: 1\r\n"
            b"Transfer-Encoding: chunked\r\n"
        ),
        b"A\r\n0123456789\r\n0\r\n\r\n",
    )
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [FakeResponse(404)],
            "https://example.com/public": [target],
        }
    )

    failure = failure_code(
        lambda: gateway(transport, request_for(max_bytes=100)).read(
            "https://example.com/public"
        )
    )

    assert failure.code == "gateway.framing_invalid"
    assert failure.evidence.usage.bytes == 0
    assert failure.evidence.content_bytes == 0
    assert failure.evidence.content_sha256 is None
    assert connection.closed == 1


@pytest.mark.parametrize(
    ("content_types", "headers", "code", "normalized_mime"),
    [
        (
            (ContentType.HTML,),
            {"Content_Type": "application/pdf; version=1.7"},
            "scope.content_type_not_allowed",
            "application/pdf",
        ),
        (
            (ContentType.FILE,),
            {"Content_Type": " TeXt/HtMl ; Charset=UTF-8 "},
            "scope.content_type_not_allowed",
            "text/html",
        ),
        ((ContentType.HTML,), {}, "gateway.mime_missing", None),
        (
            (ContentType.HTML,),
            {"Content_Type": "not a media type"},
            "gateway.mime_invalid",
            None,
        ),
    ],
)
def test_content_scope_and_mime_reject_before_target_body_read(
    content_types: tuple[ContentType, ...],
    headers: dict[str, str],
    code: str,
    normalized_mime: str | None,
) -> None:
    """Target media type is normalized and checked against Request scope."""
    target = FakeResponse(200, b"must-not-be-read", **headers)
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [FakeResponse(404)],
            "https://example.com/public": [target],
        }
    )
    access = gateway(
        transport,
        request_for(content_types=content_types),
    )

    failure = failure_code(lambda: access.read("https://example.com/public"))

    assert failure.code == code
    assert not target.read_limits
    assert target.closed == 1
    assert failure.evidence.response_status == 200
    assert failure.evidence.response_mime_type == normalized_mime
    assert failure.evidence.content_bytes == 0
    assert failure.evidence.content_sha256 is None
    assert failure.evidence.decisions[-1].code == code


@pytest.mark.parametrize("status", [401, 403, 404, 500, 503])
def test_non_success_status_rejects_without_body_and_preserves_evidence(
    status: int,
) -> None:
    """A target non-2xx response is auditable but never consumed as success."""
    target = FakeResponse(
        status,
        b"must-not-be-read",
        close_raises=True,
        Content_Type=" Text/HTML ; charset=UTF-8 ",
    )
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [FakeResponse(404)],
            "https://example.com/public": [target],
        }
    )

    failure = failure_code(
        lambda: gateway(transport).read("https://example.com/public")
    )

    assert failure.code == "gateway.http_status"
    assert not target.read_limits
    assert target.closed == 1
    assert failure.evidence.response_status == status
    assert failure.evidence.response_mime_type == "text/html"
    assert failure.evidence.content_bytes == 0
    assert failure.evidence.content_sha256 is None


def test_request_and_byte_budgets_stop_before_unapproved_work() -> (
    None
):  # pylint: disable=too-many-locals
    """Request and aggregate byte limits are hard, run-level boundaries."""
    resolver = Resolver()
    request_limited = FakeTransport(
        {"https://example.com/robots.txt": [FakeResponse(404)]}
    )
    failure = failure_code(
        lambda: gateway(
            request_limited, request_for(max_requests=1), resolver=resolver
        ).read("https://example.com/public")
    )
    assert failure.code == "budget.requests"
    assert len(request_limited.requests) == 1
    assert resolver.calls == [("example.com", 443)]

    robots = FakeResponse(
        200,
        ROBOTS_ALLOW,
        Content_Type="text/plain",
        Content_Length=str(len(ROBOTS_ALLOW)),
    )
    resolver = Resolver()
    byte_preflight = FakeTransport({"https://example.com/robots.txt": [robots]})
    failure = failure_code(
        lambda: gateway(
            byte_preflight,
            request_for(max_bytes=len(ROBOTS_ALLOW)),
            resolver=resolver,
        ).read("https://example.com/public")
    )
    assert failure.code == "budget.bytes"
    assert resolver.calls == [("example.com", 443)]

    raw_target = RecordingHttpResponse(b"0123456789", [("Content-Type", "text/html")])
    target_connection = RecordingConnection()
    target = in_process_runner._HttpResponse(raw_target, target_connection, PUBLIC_IP)
    byte_limited = FakeTransport(
        {
            "https://example.com/robots.txt": [FakeResponse(404)],
            "https://example.com/public": [target],
        }
    )
    failure = failure_code(
        lambda: gateway(byte_limited, request_for(max_bytes=5)).read(
            "https://example.com/public"
        )
    )
    assert failure.code == "budget.bytes"
    assert raw_target.read_limits == [5]
    assert raw_target.closed == target_connection.closed == 1
    assert failure.evidence.usage.bytes == 5
    assert failure.evidence.content_bytes == 5
    assert failure.evidence.content_sha256 == hashlib.sha256(b"01234").hexdigest()

    declared_too_large = FakeResponse(
        200,
        b"0123456789",
        Content_Type="text/html",
        Content_Length="10",
    )
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [FakeResponse(404)],
            "https://example.com/public": [declared_too_large],
        }
    )
    failure = failure_code(
        lambda: gateway(transport, request_for(max_bytes=5)).read(
            "https://example.com/public"
        )
    )
    assert failure.code == "budget.bytes"
    assert not declared_too_large.read_limits
    assert failure.evidence.usage.bytes == 0

    malformed_length = FakeResponse(
        200,
        b"x",
        Content_Type="text/html",
        Content_Length="-1",
    )
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [FakeResponse(404)],
            "https://example.com/public": [malformed_length],
        }
    )
    failure = failure_code(
        lambda: gateway(transport).read("https://example.com/public")
    )
    assert failure.code == "gateway.content_length_invalid"
    assert not malformed_length.read_limits

    clock = ManualClock()
    runtime_transport = FakeTransport({})
    access = GovernedAccessGateway(
        request_for(max_runtime_seconds=1),
        runtime_transport,
        resolver=Resolver(),
        clock=clock,
    )
    clock.value = 2.0
    failure = failure_code(lambda: access.read("https://example.com/public"))
    assert failure.code == "budget.runtime"
    assert not runtime_transport.requests

    clock = ManualClock()
    late_response = FakeResponse(404)
    late_transport = AdvancingTransport(
        {"https://example.com/robots.txt": [late_response]}, clock
    )
    access = GovernedAccessGateway(
        request_for(max_runtime_seconds=1),
        late_transport,
        resolver=Resolver(),
        clock=clock,
    )
    failure = failure_code(lambda: access.read("https://example.com/public"))
    assert failure.code == "budget.runtime"
    assert late_response.closed == 1


@pytest.mark.parametrize(
    "requested",
    [
        "https://example.com/public/\x00PRIVATE-CONTROL-MARKER",
        " https://example.com/public/PRIVATE-CONTROL-MARKER ",
        "https://example.com:PRIVATE-CONTROL-MARKER/public",
    ],
)
def test_unsafe_url_characters_never_enter_evidence(requested: str) -> None:
    """Controls, outer whitespace, and adjacent private text fail redacted."""
    failure = failure_code(lambda: gateway(FakeTransport({})).read(requested))
    evidence = failure.evidence
    urls = [
        evidence.requested_url,
        evidence.current_url,
        evidence.final_url,
        *(item.url for item in evidence.decisions),
    ]
    encoded = json.dumps(asdict(evidence), sort_keys=True)

    assert evidence.requested_url == "[invalid-url]"
    assert evidence.current_url == "[invalid-url]"
    assert evidence.final_url == "[invalid-url]"
    assert all("PRIVATE-CONTROL-MARKER" not in item for item in urls)
    assert all(
        all(ord(character) > 32 and ord(character) != 127 for character in item)
        for item in urls
    )
    assert "PRIVATE-CONTROL-MARKER" not in encoded
    assert "\\u0000" not in encoded


def test_timeout_and_transport_failures_are_typed_and_redacted() -> None:
    """Private exception and query values never enter stable evidence."""
    secret = "do-not-emit"
    requested = f"https://example.com/public?access_token={secret}"
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [FakeResponse(404)],
            requested: [OSError(f"private transport {secret}")],
        }
    )
    failure = failure_code(
        lambda: gateway(transport, request_for(requested)).read(requested)
    )

    assert failure.code == "gateway.transport"
    encoded = json.dumps(asdict(failure.evidence), sort_keys=True)
    assert secret not in encoded
    assert "query-sha256=" in failure.evidence.requested_url

    timed_out = FakeTransport(
        {"https://example.com/robots.txt": [TimeoutError("private timeout")]}
    )
    failure = failure_code(
        lambda: gateway(timed_out).read("https://example.com/public")
    )
    assert failure.code == "robots.timeout"
    assert failure.evidence.robots[-1].code == "robots.timeout"
    assert timed_out.requests[0][1] <= 30


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (TimeoutError("private robots timeout"), "robots.timeout"),
        (OSError("private robots transport"), "robots.network_error"),
    ],
)
def test_robots_body_io_failures_keep_robots_specific_codes(
    error: BaseException, expected_code: str
) -> None:
    """Robots body I/O failures stay distinguishable from target failures."""

    class FailingRobotsBody(FakeResponse):
        """Raise the scripted failure while preserving read evidence."""

        def read(self, max_bytes: int) -> bytes:
            self.read_limits.append(max_bytes)
            raise error

    robots = FailingRobotsBody(200, Content_Type="text/plain")
    transport = FakeTransport({"https://example.com/robots.txt": [robots]})

    failure = failure_code(
        lambda: gateway(transport).read("https://example.com/public")
    )

    assert failure.code == expected_code
    assert failure.evidence.robots[-1].code == expected_code
    assert robots.closed == 1
    assert len(transport.requests) == 1
    encoded = json.dumps(asdict(failure.evidence), sort_keys=True)
    assert "private robots" not in encoded


def test_success_closes_responses_and_gateway_close_is_idempotent() -> None:
    """Every response and the transport have explicit owner-driven cleanup."""
    robots = FakeResponse(404)
    target = FakeResponse(200, b"ok", Content_Type="text/html", Content_Length="2")
    transport = FakeTransport(
        {
            "https://example.com/robots.txt": [robots],
            "https://example.com/public": [target],
        }
    )
    access = gateway(transport)

    assert access.read("https://example.com/public").body == b"ok"
    access.close()
    access.close()

    assert robots.closed == target.closed == 1
    assert transport.closed == 1
    failure = failure_code(lambda: access.read("https://example.com/public"))
    assert failure.code == "gateway.closed"


def test_gateway_close_suppresses_ordinary_private_cleanup_failure() -> None:
    """Transport cleanup cannot leak detail and remains idempotent."""
    transport = FailingCloseTransport({})
    access = gateway(transport)

    access.close()
    access.close()

    assert transport.closed == 1
    failure = failure_code(lambda: access.read("https://example.com/public"))
    assert failure.code == "gateway.closed"
    assert "private-close-secret" not in str(failure)
    assert "private-close-secret" not in json.dumps(asdict(failure.evidence))


def test_phase_02_live_catalog_is_one_pinned_ipcc_target() -> None:
    """The live URL is copied only from the pinned catalog and matching profile."""
    payload = json.loads(TARGETS.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "phase-live-targets.v1"
    assert payload["phase"] == 2
    assert payload["source_repo_commit"] == ("9fe9ea53104dd008086dfa0e86c35c50b75f4ce5")
    assert payload["network_limits"] == {
        "concurrency": 1,
        "max_bytes_per_response": 2 * 1024 * 1024,
        "max_content_reads_per_target": 1,
        "max_total_requests": 6,
        "retry": 0,
        "timeout_seconds": 30,
    }
    assert payload["targets"] == [
        {
            "allowed_origins": ["https://www.ipcc.ch"],
            "historical_expectation": "pass_http",
            "profile_allowed_domains": ["www.ipcc.ch"],
            "profile_source_path": (
                "web_listening/skills/sites/ipcc/1.0.0/profiles/default.yaml"
            ),
            "site_key": "ipcc",
            "source_path": "config/smoke_site_catalog.json",
            "url": "https://www.ipcc.ch/",
        }
    ]
    live_source = TARGETS.with_name("test_phase_02_gateway_live.py").read_text(
        encoding="utf-8"
    )
    assert "WEB_LISTENING_RUN_LIVE" in live_source
    assert "WEB_LISTENING_LIVE_AUTHORIZED_WINDOW" in live_source
    assert "WEB_LISTENING_LIVE_SITE" in live_source
    assert "WEB_LISTENING_LIVE_URL" not in live_source
    assert "pytest.skip" in live_source
    for field in (
        "response_status",
        "response_mime_type",
        "content_bytes",
        "content_sha256",
    ):
        assert f"exc.evidence.{field}" in live_source


def test_gateway_source_has_no_artifact_runtime_fallback_or_parser_authority() -> None:
    """The runner remains the narrow Tool Registry execution boundary."""
    source = inspect.getsource(inspect.getmodule(GovernedAccessGateway))
    forbidden = (
        "web_listening.artifact",
        "web_listening.runtime",
        "fallback",
        "playwright",
        "rag",
    )
    assert all(token not in source.casefold() for token in forbidden)
