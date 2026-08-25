"""The governed in-process HTTP execution boundary."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping, NoReturn, Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from web_listening.request.model import ContentType, Request, RequestValidationError
from web_listening.request.scope import canonicalize_url
from web_listening.request.validate import CompiledAccessPolicy, compile_access_policy

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_USER_AGENT = "web-listening/0.1"
_MEDIA_TYPE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_MAX_CONTENT_LENGTH = (1 << 63) - 1


class TransportResponse(Protocol):
    """A response whose body and lifetime remain owned by the gateway."""

    status: int
    headers: Mapping[str, str]
    peer_ip: str

    def read(self, max_bytes: int) -> bytes:
        """Read at most the supplied governed byte boundary."""

    def close(self) -> None:
        """Release the response and its connection."""


class Transport(Protocol):
    """A transport that connects only to gateway-approved addresses."""

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> TransportResponse:
        """Send one GET without following redirects."""

    def close(self) -> None:
        """Release transport resources."""


@dataclass(frozen=True, slots=True)
class DecisionEvidence:
    """One sanitized allow or reject decision."""

    stage: str
    url: str
    allowed: bool
    code: str


@dataclass(frozen=True, slots=True)
class RedirectEvidence:
    """One manually evaluated redirect transition."""

    kind: str
    ordinal: int
    source_url: str
    target_url: str
    status_code: int
    decision_code: str


@dataclass(frozen=True, slots=True)
class RobotsEvidence:
    """The robots outcome applied before one target read."""

    origin: str
    robots_url: str
    target_url: str
    status_code: int | None
    code: str
    allowed: bool


@dataclass(frozen=True, slots=True)
class UsageEvidence:
    """Cumulative Request budget usage at the evidence boundary."""

    requests: int
    bytes: int
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class GatewayEvidence:  # pylint: disable=too-many-instance-attributes
    """Sanitized evidence for one completed or rejected target read."""

    requested_url: str
    current_url: str
    final_url: str
    decisions: tuple[DecisionEvidence, ...]
    redirects: tuple[RedirectEvidence, ...]
    robots: tuple[RobotsEvidence, ...]
    usage: UsageEvidence
    response_status: int | None
    response_mime_type: str | None
    content_bytes: int
    content_sha256: str | None


@dataclass(frozen=True, slots=True)
class GatewayResult:
    """Original response bytes plus governed acquisition evidence."""

    body: bytes
    status_code: int
    mime_type: str
    sha256: str
    evidence: GatewayEvidence

    @property
    def requested_url(self) -> str:
        """Return the sanitized originally requested URL."""
        return self.evidence.requested_url

    @property
    def current_url(self) -> str:
        """Return the sanitized URL used for the final request."""
        return self.evidence.current_url

    @property
    def final_url(self) -> str:
        """Return the sanitized final URL."""
        return self.evidence.final_url


class GatewayFailure(RuntimeError):
    """A stable failure that never includes transport or URL secrets."""

    def __init__(self, code: str, evidence: GatewayEvidence) -> None:
        self.code = code
        self.evidence = evidence
        super().__init__(code)


@dataclass(slots=True)
class _ReadState:  # pylint: disable=too-many-instance-attributes
    requested_url: str
    current_url: str
    final_url: str
    response_status: int | None = None
    response_mime_type: str | None = None
    content_bytes: int = 0
    content_sha256: str | None = None
    decisions: list[DecisionEvidence] = field(default_factory=list)
    redirects: list[RedirectEvidence] = field(default_factory=list)
    robots: list[RobotsEvidence] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _RobotsPolicy:
    robots_url: str
    status_code: int | None
    code: str
    parser: RobotFileParser | None


@dataclass(slots=True)
class _Usage:
    """Mutable cumulative usage owned by one gateway."""

    started_at: float
    requests: int = 0
    bytes: int = 0


class _TransportSafetyError(RuntimeError):
    """A transport safety failure with a non-sensitive stable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _HttpResponse:
    """Own a standard-library response and its pinned connection."""

    def __init__(
        self,
        response: http.client.HTTPResponse,
        connection: http.client.HTTPConnection,
        peer_ip: str,
    ) -> None:
        self.status = response.status
        self.headers: dict[str, str] = {}
        for key, value in response.getheaders():
            normalized = key.casefold()
            self.headers[normalized] = (
                f"{self.headers[normalized]}, {value}"
                if normalized in self.headers
                else value
            )
        self.peer_ip = peer_ip
        self._response = response
        self._connection = connection
        self._closed = False

    def read(self, max_bytes: int) -> bytes:
        """Read through exactly the governed upper bound."""
        return self._response.read(max_bytes)

    def close(self) -> None:
        """Close both the response and its pinned connection exactly once."""
        if self._closed:
            return
        self._closed = True
        try:
            self._response.close()
        finally:
            self._connection.close()


class PinnedHttpTransport:
    """Minimal no-proxy HTTP transport with a pre-request pinned-peer check."""

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> TransportResponse:
        """Perform one GET through the first already-approved DNS address."""
        parsed = urlsplit(url)
        host = parsed.hostname
        if host is None or not addresses:
            raise _TransportSafetyError("gateway.transport_contract")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        raw: socket.socket | ssl.SSLSocket | None = None
        connection: http.client.HTTPConnection | None = None
        response: http.client.HTTPResponse | None = None
        try:
            raw = socket.create_connection((addresses[0], port), timeout=timeout)
            raw.settimeout(timeout)
            peer = str(ipaddress.ip_address(raw.getpeername()[0]))
            if peer not in addresses or not _is_public_address(peer):
                raise _TransportSafetyError("gateway.peer_not_public")
            if parsed.scheme == "https":
                raw = ssl.create_default_context().wrap_socket(
                    raw, server_hostname=host
                )

            connection_type = (
                http.client.HTTPSConnection
                if parsed.scheme == "https"
                else http.client.HTTPConnection
            )
            connection = connection_type(host, port, timeout=timeout)
            connection.sock = raw
            target = parsed.path or "/"
            if parsed.query:
                target += f"?{parsed.query}"
            connection.putrequest(
                "GET", target, skip_host=True, skip_accept_encoding=True
            )
            connection.putheader("Host", _host_header(host, port, parsed.scheme))
            connection.putheader("User-Agent", _USER_AGENT)
            connection.putheader("Accept-Encoding", "identity")
            connection.putheader("Connection", "close")
            connection.endheaders()
            response = connection.getresponse()
            result = _HttpResponse(response, connection, peer)
            response = None
            connection = None
            raw = None
            return result
        finally:
            # Cleanup cannot replace an already selected transport safety failure.
            if response is not None:
                try:
                    response.close()
                except Exception:  # pylint: disable=broad-exception-caught
                    pass
            if connection is not None:
                try:
                    connection.close()
                except Exception:  # pylint: disable=broad-exception-caught
                    pass
            elif raw is not None:
                try:
                    raw.close()
                except Exception:  # pylint: disable=broad-exception-caught
                    pass

    def close(self) -> None:
        """The transport keeps no resources between responses."""


class GovernedAccessGateway:
    """Apply Request policy, robots, safety, and budgets before every target."""

    def __init__(
        self,
        request: Request,
        transport: Transport,
        *,
        resolver: Callable[[str, int], tuple[str, ...]] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._policy: CompiledAccessPolicy = compile_access_policy(request)
        self._transport = transport
        self._resolver = resolver or _resolve_public_addresses
        self._clock = clock
        self._usage = _Usage(started_at=clock())
        self._robots: dict[str, _RobotsPolicy] = {}
        self._closed = False

    def read(self, url: str) -> GatewayResult:
        """Return bounded original bytes after every governed check succeeds."""
        safe_requested = _safe_url(url)
        state = _ReadState(safe_requested, safe_requested, safe_requested)
        if self._closed:
            self._raise("gateway.closed", state)

        current = self._authorize_target(url, state, "target.initial")
        while True:
            state.response_status = None
            state.response_mime_type = None
            state.content_bytes = 0
            state.content_sha256 = None
            state.current_url = _safe_url(current)
            state.final_url = state.current_url
            origin = _origin(current)
            self._apply_robots(origin, current, state)
            addresses = self._resolve(current, state, "target.dns")
            response = self._send(current, addresses, state)
            try:
                self._check_peer(response.peer_ip, addresses, current, state)
                self._record_target_headers(response, state)
                if response.status in _REDIRECT_STATUSES:
                    current = self._target_redirect(response, current, state)
                    continue
                self._authorize_target_response(response, current, state)
                body = self._read_body(response, current, state, target_content=True)
                self._ensure_runtime(state)
                state.final_url = _safe_url(current)
                evidence = self._evidence(state)
                assert state.response_mime_type is not None
                assert state.content_sha256 is not None
                return GatewayResult(
                    body=body,
                    status_code=response.status,
                    mime_type=state.response_mime_type,
                    sha256=state.content_sha256,
                    evidence=evidence,
                )
            finally:
                _close_response(response)

    def close(self) -> None:
        """Close the transport exactly once and reject later reads."""
        if self._closed:
            return
        self._closed = True
        try:
            self._transport.close()
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    def _authorize_target(self, url: str, state: _ReadState, stage: str) -> str:
        decision = self._policy.decide_url(url)
        state.decisions.append(
            DecisionEvidence(stage, _safe_url(url), decision.allowed, decision.code)
        )
        if not decision.allowed:
            self._raise(decision.code, state)
        try:
            return canonicalize_url(url)
        except RequestValidationError:
            self._raise("scope.url_invalid", state)

    def _apply_robots(self, origin: str, target_url: str, state: _ReadState) -> None:
        policy = self._robots.get(origin)
        if policy is None:
            policy = self._load_robots(origin, state)
            self._robots[origin] = policy
        allowed = policy.code == "robots.absent" or (
            policy.parser is not None
            and policy.parser.can_fetch(_USER_AGENT, target_url)
        )
        code = "robots.allowed" if allowed else policy.code
        if policy.parser is not None and not allowed:
            code = "robots.disallowed"
        state.robots.append(
            RobotsEvidence(
                origin=origin,
                robots_url=_safe_url(policy.robots_url),
                target_url=_safe_url(target_url),
                status_code=policy.status_code,
                code=code,
                allowed=allowed,
            )
        )
        state.decisions.append(
            DecisionEvidence("target.robots", _safe_url(target_url), allowed, code)
        )
        if not allowed:
            self._raise(code, state)

    def _load_robots(self, origin: str, state: _ReadState) -> _RobotsPolicy:
        current = f"{origin}/robots.txt"
        seen: set[str] = set()
        while True:
            if current in seen:
                self._raise("robots.redirect_loop", state)
            seen.add(current)
            self._authorize_robots_url(origin, current, state)
            try:
                addresses = self._resolve(current, state, "robots.dns")
                response = self._send(current, addresses, state)
            except GatewayFailure as exc:
                mapped_code = {
                    "gateway.dns": "robots.dns_error",
                    "gateway.timeout": "robots.timeout",
                    "gateway.transport": "robots.network_error",
                }.get(exc.code)
                if mapped_code is None:
                    raise
                return _RobotsPolicy(current, None, mapped_code, None)
            try:
                self._check_peer(response.peer_ip, addresses, current, state)
                if response.status in _REDIRECT_STATUSES:
                    current = self._robots_redirect(response, current, origin, state)
                    continue
                if response.status in {401, 403, 404, 410}:
                    code = {
                        401: "robots.auth_required",
                        403: "robots.forbidden",
                        404: "robots.absent",
                        410: "robots.absent",
                    }[response.status]
                    return _RobotsPolicy(current, response.status, code, None)
                if response.status != 200:
                    return _RobotsPolicy(
                        current, response.status, "robots.http_status", None
                    )
                body = self._read_body(response, current, state)
                try:
                    text = body.decode("utf-8-sig")
                except UnicodeDecodeError:
                    return _RobotsPolicy(
                        current, response.status, "robots.parse_error", None
                    )
                parser = RobotFileParser(current)
                parser.parse(text.splitlines())
                return _RobotsPolicy(current, response.status, "robots.allowed", parser)
            finally:
                _close_response(response)

    def _authorize_robots_url(self, origin: str, url: str, state: _ReadState) -> None:
        try:
            canonical = canonicalize_url(url)
        except RequestValidationError:
            state.decisions.append(
                DecisionEvidence(
                    "robots.request", _safe_url(url), False, "robots.url_invalid"
                )
            )
            self._raise("robots.url_invalid", state)
        allowed = (
            _origin(canonical) == origin
            and origin in self._policy.scope.allowed_origins
        )
        code = "policy.allowed" if allowed else "robots.redirect_origin"
        state.decisions.append(
            DecisionEvidence("robots.request", _safe_url(canonical), allowed, code)
        )
        if not allowed:
            self._raise(code, state)

    def _record_target_headers(
        self, response: TransportResponse, state: _ReadState
    ) -> None:
        state.response_status = response.status
        state.response_mime_type, _unused = _normalized_media_type(response.headers)

    def _authorize_target_response(
        self,
        response: TransportResponse,
        current: str,
        state: _ReadState,
    ) -> None:
        status_allowed = 200 <= response.status < 300
        status_code = "policy.allowed" if status_allowed else "gateway.http_status"
        state.decisions.append(
            DecisionEvidence(
                "target.status", _safe_url(current), status_allowed, status_code
            )
        )
        if not status_allowed:
            self._raise(status_code, state)

        mime_type, mime_error = _normalized_media_type(response.headers)
        state.response_mime_type = mime_type
        if mime_error is not None:
            state.decisions.append(
                DecisionEvidence("target.mime", _safe_url(current), False, mime_error)
            )
            self._raise(mime_error, state)
        assert mime_type is not None
        content_type = (
            ContentType.HTML if mime_type == "text/html" else ContentType.FILE
        )
        decision = self._policy.decide_content_type(content_type)
        state.decisions.append(
            DecisionEvidence(
                "target.content_type",
                _safe_url(current),
                decision.allowed,
                decision.code,
            )
        )
        if not decision.allowed:
            self._raise(decision.code, state)

    def _target_redirect(
        self,
        response: TransportResponse,
        current: str,
        state: _ReadState,
    ) -> str:
        target = self._redirect_target(response, current, "gateway.redirect", state)
        code = "policy.allowed"
        if urlsplit(current).scheme == "https" and urlsplit(target).scheme == "http":
            code = "gateway.https_downgrade"
            allowed = False
        else:
            decision = self._policy.decide_url(target)
            code = decision.code
            allowed = decision.allowed
        state.decisions.append(
            DecisionEvidence("target.redirect", _safe_url(target), allowed, code)
        )
        state.redirects.append(
            RedirectEvidence(
                kind="target",
                ordinal=len(state.redirects) + 1,
                source_url=_safe_url(current),
                target_url=_safe_url(target),
                status_code=response.status,
                decision_code=code,
            )
        )
        if not allowed:
            state.final_url = _safe_url(target)
            self._raise(code, state)
        return target

    def _robots_redirect(
        self,
        response: TransportResponse,
        current: str,
        origin: str,
        state: _ReadState,
    ) -> str:
        target = self._redirect_target(
            response, current, "robots.redirect_missing", state
        )
        if urlsplit(current).scheme == "https" and urlsplit(target).scheme == "http":
            code = "gateway.https_downgrade"
            allowed = False
        else:
            allowed = _origin(target) == origin
            code = "policy.allowed" if allowed else "robots.redirect_origin"
        state.decisions.append(
            DecisionEvidence("robots.redirect", _safe_url(target), allowed, code)
        )
        state.redirects.append(
            RedirectEvidence(
                kind="robots",
                ordinal=len(state.redirects) + 1,
                source_url=_safe_url(current),
                target_url=_safe_url(target),
                status_code=response.status,
                decision_code=code,
            )
        )
        if not allowed:
            self._raise(code, state)
        return target

    def _redirect_target(
        self,
        response: TransportResponse,
        current: str,
        missing_code: str,
        state: _ReadState,
    ) -> str:
        location = _header(response.headers, "location")
        if not location:
            self._raise(missing_code, state)
        try:
            return canonicalize_url(urljoin(current, location))
        except ValueError:
            self._raise("gateway.redirect_invalid", state)

    def _resolve(self, url: str, state: _ReadState, stage: str) -> tuple[str, ...]:
        self._ensure_runtime(state)
        parsed = urlsplit(url)
        host = parsed.hostname
        if host is None:
            self._raise("scope.url_invalid", state)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            addresses = tuple(
                dict.fromkeys(
                    str(ipaddress.ip_address(item))
                    for item in self._resolver(host, port)
                )
            )
        except Exception:  # pylint: disable=broad-exception-caught
            state.decisions.append(
                DecisionEvidence(stage, _safe_url(url), False, "gateway.dns")
            )
            self._raise("gateway.dns", state)
        allowed = bool(addresses) and all(
            _is_public_address(item) for item in addresses
        )
        code = "policy.allowed" if allowed else "gateway.dns_not_public"
        state.decisions.append(DecisionEvidence(stage, _safe_url(url), allowed, code))
        if not allowed:
            self._raise(code, state)
        return addresses

    def _send(
        self, url: str, addresses: tuple[str, ...], state: _ReadState
    ) -> TransportResponse:
        timeout = self._reserve_request(url, state)
        try:
            response = self._transport.send(url, timeout=timeout, addresses=addresses)
        except _TransportSafetyError as exc:
            state.decisions.append(
                DecisionEvidence("transport.peer", _safe_url(url), False, exc.code)
            )
            self._raise(exc.code, state)
        except (TimeoutError, socket.timeout):
            self._raise("gateway.timeout", state)
        except ssl.SSLError:
            self._raise("gateway.tls", state)
        except (ConnectionError, OSError):
            self._raise("gateway.transport", state)
        except Exception:  # pylint: disable=broad-exception-caught
            self._raise("gateway.transport", state)
        try:
            self._ensure_runtime(state)
        except GatewayFailure:
            _close_response(response)
            raise
        return response

    def _reserve_request(self, url: str, state: _ReadState) -> float:
        timeout = self._remaining_runtime(state)
        if self._usage.requests >= self._policy.budgets.max_requests:
            state.decisions.append(
                DecisionEvidence(
                    "budget.request", _safe_url(url), False, "budget.requests"
                )
            )
            self._raise("budget.requests", state)
        if self._usage.bytes >= self._policy.budgets.max_bytes:
            state.decisions.append(
                DecisionEvidence("budget.bytes", _safe_url(url), False, "budget.bytes")
            )
            self._raise("budget.bytes", state)
        self._usage.requests += 1
        state.decisions.append(
            DecisionEvidence("budget.request", _safe_url(url), True, "policy.allowed")
        )
        return timeout

    def _read_body(
        self,
        response: TransportResponse,
        url: str,
        state: _ReadState,
        *,
        target_content: bool = False,
    ) -> bytes:
        remaining = self._policy.budgets.max_bytes - self._usage.bytes
        if remaining <= 0:
            self._raise("budget.bytes", state)
        header_names = {key.casefold() for key in response.headers}
        has_content_length = "content-length" in header_names
        has_transfer_encoding = "transfer-encoding" in header_names
        transfer_encoding = _header(response.headers, "transfer-encoding")
        invalid_framing = has_transfer_encoding and (
            has_content_length or transfer_encoding.strip(" \t").casefold() != "chunked"
        )
        if invalid_framing:
            state.decisions.append(
                DecisionEvidence(
                    "response.framing",
                    _safe_url(url),
                    False,
                    "gateway.framing_invalid",
                )
            )
            self._raise("gateway.framing_invalid", state)
        try:
            declared_length = _content_length(response.headers)
        except ValueError:
            state.decisions.append(
                DecisionEvidence(
                    "response.content_length",
                    _safe_url(url),
                    False,
                    "gateway.content_length_invalid",
                )
            )
            self._raise("gateway.content_length_invalid", state)
        if declared_length is not None and declared_length > remaining:
            state.decisions.append(
                DecisionEvidence(
                    "response.content_length",
                    _safe_url(url),
                    False,
                    "budget.bytes",
                )
            )
            self._raise("budget.bytes", state)
        try:
            read_limit = declared_length if declared_length is not None else remaining
            body = response.read(read_limit)
        except (TimeoutError, socket.timeout):
            self._raise("gateway.timeout", state)
        except (ConnectionError, OSError):
            self._raise("gateway.transport", state)
        except Exception:  # pylint: disable=broad-exception-caught
            self._raise("gateway.transport", state)
        if not isinstance(body, bytes):
            self._raise("gateway.transport_contract", state)
        self._usage.bytes += len(body)
        if target_content:
            state.content_bytes = len(body)
            state.content_sha256 = hashlib.sha256(body).hexdigest()
        if len(body) > remaining:
            self._raise("budget.bytes", state)
        if declared_length is not None and len(body) != declared_length:
            self._raise("gateway.body_incomplete", state)
        if declared_length is None and len(body) == remaining:
            self._raise("budget.bytes", state)
        return body

    def _check_peer(
        self,
        peer: str,
        addresses: tuple[str, ...],
        url: str,
        state: _ReadState,
    ) -> None:
        try:
            canonical_peer = str(ipaddress.ip_address(peer))
        except ValueError:
            canonical_peer = ""
        allowed = canonical_peer in addresses and _is_public_address(canonical_peer)
        code = "policy.allowed" if allowed else "gateway.peer_not_public"
        state.decisions.append(
            DecisionEvidence("transport.peer", _safe_url(url), allowed, code)
        )
        if not allowed:
            self._raise(code, state)

    def _remaining_runtime(self, state: _ReadState) -> float:
        remaining = self._policy.budgets.max_runtime_seconds - (
            self._clock() - self._usage.started_at
        )
        if remaining <= 0:
            self._raise("budget.runtime", state)
        return remaining

    def _ensure_runtime(self, state: _ReadState) -> None:
        if (
            self._clock() - self._usage.started_at
            > self._policy.budgets.max_runtime_seconds
        ):
            self._raise("budget.runtime", state)

    def _evidence(self, state: _ReadState) -> GatewayEvidence:
        return GatewayEvidence(
            requested_url=state.requested_url,
            current_url=state.current_url,
            final_url=state.final_url,
            decisions=tuple(state.decisions),
            redirects=tuple(state.redirects),
            robots=tuple(state.robots),
            usage=UsageEvidence(
                requests=self._usage.requests,
                bytes=self._usage.bytes,
                elapsed_seconds=round(
                    max(0.0, self._clock() - self._usage.started_at), 6
                ),
            ),
            response_status=state.response_status,
            response_mime_type=state.response_mime_type,
            content_bytes=state.content_bytes,
            content_sha256=state.content_sha256,
        )

    def _raise(self, code: str, state: _ReadState) -> NoReturn:
        raise GatewayFailure(code, self._evidence(state))


def _safe_url(value: object) -> str:
    if not isinstance(value, str):
        return "[invalid-url]"
    if value != value.strip() or any(
        ord(character) <= 32 or ord(character) == 127 for character in value
    ):
        return "[invalid-url]"
    try:
        parsed = urlsplit(value)
        if (
            parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
        ):
            return "[redacted-url]"
        query = ""
        if parsed.query:
            digest = hashlib.sha256(parsed.query.encode("utf-8")).hexdigest()
            query = f"query-sha256={digest}"
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
    except (TypeError, ValueError):
        return "[invalid-url]"


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _header(headers: Mapping[str, str], name: str) -> str:
    target = name.casefold()
    return next(
        (str(value) for key, value in headers.items() if key.casefold() == target),
        "",
    )


def _normalized_media_type(
    headers: Mapping[str, str],
) -> tuple[str | None, str | None]:
    raw = _header(headers, "content-type")
    if not raw:
        return None, "gateway.mime_missing"
    if "," in raw or any(
        ord(character) < 32 or ord(character) == 127 for character in raw
    ):
        return None, "gateway.mime_invalid"
    media_type = raw.split(";", 1)[0].strip().casefold()
    if not _MEDIA_TYPE.fullmatch(media_type):
        return None, "gateway.mime_invalid"
    return media_type, None


def _content_length(headers: Mapping[str, str]) -> int | None:
    raw = _header(headers, "content-length")
    if not raw:
        return None
    value = raw.strip()
    if not value.isascii() or not value.isdecimal() or len(value) > 19:
        raise ValueError("invalid content length")
    length = int(value)
    if length > _MAX_CONTENT_LENGTH:
        raise ValueError("invalid content length")
    return length


def _close_response(response: TransportResponse) -> None:
    try:
        response.close()
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def _is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return address.is_global and not address.is_multicast
    except ValueError:
        return False


def _resolve_public_addresses(host: str, port: int) -> tuple[str, ...]:
    rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = {str(ipaddress.ip_address(row[4][0])) for row in rows}
    return tuple(sorted(addresses, key=lambda item: (":" in item, item)))


def _host_header(host: str, port: int, scheme: str) -> str:
    rendered = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    return rendered if port == default_port else f"{rendered}:{port}"
