"""One-attempt parent Gateway bridge for browser navigation and resources.

The browser's native proxy path always denies traffic. Its versioned adapter
fulfils intercepted GETs using this authenticated loopback bridge. Only Gateway
performs target I/O, including DNS, robots and every redirect. There is no CONNECT
tunnel, native fallback, resource scope expansion or adapter-owned measurement.
"""

# pylint: disable=too-many-instance-attributes,too-few-public-methods
# pylint: disable=too-many-arguments,too-many-positional-arguments

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
from dataclasses import fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from web_listening.request.model import ContentType, Request, classify_mime_type
from web_listening.result.robots import RobotsDecision
from web_listening.tool_registry.acquisition.quality import response_failure_code
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionOutput,
    ParentMeasuredAcquisitionOutput,
    _record_parent_measurement,
)
from web_listening.tool_registry.runners.in_process import (
    GatewayEvidence,
    GatewayFailure,
    GovernedAccessGateway,
    Transport,
)


class _HeaderTransport:
    """Retain final response headers while Gateway owns every read."""

    def __init__(self, transport):
        self.transport = transport
        self.headers = {}
        self.status = None
        self.last_headers = {}

    def send(self, url, *, timeout, addresses):
        """Delegate the pinned read and retain relevant response headers."""
        response = self.transport.send(url, timeout=timeout, addresses=addresses)
        self.status = response.status
        self.last_headers = dict(response.headers)
        self.headers[url] = {
            key.lower(): value
            for key, value in response.headers.items()
            if key.lower()
            in {
                "content-type",
                "content-security-policy",
                "access-control-allow-origin",
                "access-control-allow-credentials",
                "access-control-expose-headers",
                "cross-origin-resource-policy",
                "referrer-policy",
            }
        }
        return response

    def close(self):
        """Close the wrapped transport."""
        self.transport.close()


class BrowserNetworkBridge:
    """Serialize all reads against a single Gateway ledger and deadline."""

    def __init__(
        self,
        request: Request,
        target_url: str,
        transport: Transport,
        *,
        resolver=None,
        deadline: float | None = None,
        should_cancel: Callable[[], bool] = lambda: False,
    ) -> None:
        self.target_url = target_url
        self.should_cancel = should_cancel
        self.started = time.monotonic()
        self.deadline = min(
            deadline or float("inf"), self.started + request.budgets.max_runtime_seconds
        )
        self._transport = _HeaderTransport(transport)
        self.gateway = GovernedAccessGateway(
            request, self._transport, resolver=resolver, runtime_deadline=self.deadline
        )
        self.requests = 0
        self.bytes_received = 0
        self.robots_decisions: tuple[RobotsDecision, ...] = ()
        self.failure_code: str | None = None
        self.events: list[dict[str, object]] = []
        self.native_denied = 0
        self._lock = threading.RLock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._token = secrets.token_hex(32)
        self._nonce_hash: str | None = None
        self._closed = False
        self._redirect_cache: dict[str, dict[str, object]] = {}
        self._document: dict[str, object] | None = None
        self._document_redirects: list[dict[str, object]] = []

    def status(self) -> dict[str, object]:
        """Return terminal state; never restart a failed attempt."""
        if self.should_cancel():
            self.failure_code = "runtime.cancelled"
        elif time.monotonic() >= self.deadline:
            self.failure_code = self.failure_code or "budget.runtime"
        elif self._closed:
            self.failure_code = self.failure_code or "gateway.closed"
        return {"ok": self.failure_code is None, "code": self.failure_code}

    def read(  # pylint: disable=too-many-return-statements
        self,
        url: str,
        method: str,
        *,
        navigation: bool = False,
        main_document: bool = True,
    ) -> dict[str, object]:
        """Read one browser request under the original Request authority."""
        with self._lock:
            status = self.status()
            if not status["ok"]:
                return status
            if method != "GET":
                self.failure_code = "browser.read_only"
                return self.status()
            if url in self._redirect_cache:
                return self._redirect_cache.pop(url)
            try:
                result = self.gateway.read(url)
            except GatewayFailure as exc:
                self._record(exc.evidence)
                code = exc.code
                if code == "gateway.http_status":
                    if exc.evidence.response_status in {401, 403}:
                        code = response_failure_code(
                            exc.evidence.response_status, self._transport.last_headers
                        )
                    elif not navigation:
                        code = "browser.resource_failed"
                self.failure_code = code
                return self.status()
            self._record(result.evidence)
            if (
                navigation
                and classify_mime_type(result.mime_type) is not ContentType.HTML
            ):
                self.failure_code = "browser.html_required"
                return self.status()
            final = {
                "ok": True,
                "url": result.final_url,
                "status": result.status_code,
                "mime_type": result.mime_type,
                "body": result.body,
                "headers": self._transport.headers.get(
                    result.final_url, {"content-type": result.mime_type}
                ),
            }
            redirects = [
                {
                    "from_url": item.source_url,
                    "to_url": item.target_url,
                    "status_code": item.status_code,
                }
                for item in result.evidence.redirects
                if item.kind == "target"
            ]
            if navigation and main_document:
                self._document = final
                self._document_redirects.extend(redirects)
            if not redirects:
                return final
            # Gateway already performed these reads. Replay only their responses
            # to Chromium so document.location/base URLs have normal semantics.
            self._redirect_cache[result.final_url] = final
            responses = []
            for hop in redirects:
                response = {
                    "ok": True,
                    "url": hop["from_url"],
                    "status": hop["status_code"],
                    "mime_type": "text/html",
                    "body": b"",
                    "headers": {"location": hop["to_url"]},
                }
                responses.append(response)
                self._redirect_cache[hop["from_url"]] = response
            return self._redirect_cache.pop(url)

    def _record(self, evidence: GatewayEvidence) -> None:
        self.requests = evidence.usage.requests
        self.bytes_received = evidence.usage.bytes
        self.robots_decisions += evidence.robots
        self.events.append(
            {
                "url": evidence.current_url,
                "requests": self.requests,
                "bytes_received": self.bytes_received,
                "decisions": [
                    {
                        "stage": item.stage,
                        "url": item.url,
                        "allowed": item.allowed,
                        "code": item.code,
                    }
                    for item in evidence.decisions
                ],
            }
        )

    def normalize(self, output: AcquisitionOutput | AcquisitionFailure):
        """Attach measured parent evidence; ignore adapter usage assertions."""
        status = self.status()
        code = self.failure_code
        if isinstance(output, AcquisitionOutput) and status["ok"]:
            if (
                self._document is None
                or output.final_url != self._document["url"]
                or output.mime_type != self._document["mime_type"]
                or output.status_code != self._document["status"]
                or [
                    (hop.from_url, hop.to_url, hop.status_code)
                    for hop in output.redirects
                ]
                != [
                    (hop["from_url"], hop["to_url"], hop["status_code"])
                    for hop in self._document_redirects
                ]
            ):
                code = "browser.parent_evidence_mismatch"
        if isinstance(output, AcquisitionFailure):
            code = code or output.code
        usage = {
            "requests": self.requests,
            "bytes_received": self.bytes_received,
            "runtime_ms": max(
                output.runtime_ms, round((time.monotonic() - self.started) * 1000)
            ),
            "robots_decisions": self.robots_decisions,
        }
        if code is not None:
            return AcquisitionFailure(
                output.tool_id, output.tool_version, code, **usage
            )
        values = {
            item.name: getattr(output, item.name)
            for item in fields(AcquisitionOutput)
            if not item.name.startswith("_")
        }
        values.update(usage)
        return _record_parent_measurement(ParentMeasuredAcquisitionOutput(**values))

    def observation(self, expected_nonce_sha256: str) -> dict[str, object]:
        """Expose the existing IsolatedRuntime parent-observation contract."""
        if self._nonce_hash != expected_nonce_sha256:
            raise ValueError("browser.attempt_mismatch")
        return {
            "attempt_nonce_sha256": self._nonce_hash,
            "request_count": self.requests,
            "response_bytes": self.bytes_received,
            "budget_enforced": True,
            "limit_exceeded": self.failure_code
            in {"budget.bytes", "budget.requests", "budget.runtime"},
        }

    def start(self) -> str:
        """Start an authenticated loopback endpoint, also denying native proxy I/O."""
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            # This nested handler implements its owning bridge's private IPC.
            # Exact types reject bool/int substitutions in the JSON contract.
            # pylint: disable=protected-access,unidiomatic-typecheck
            """Bounded local IPC only; never proxy a native browser request."""

            def log_message(self, _format, *args):  # pylint: disable=arguments-differ
                pass

            def do_CONNECT(self):  # pylint: disable=invalid-name
                """Deny native proxy tunnels."""
                bridge.native_denied += 1
                self.send_error(403)

            def do_GET(self):  # pylint: disable=invalid-name
                """Deny native proxy reads."""
                bridge.native_denied += 1
                self.send_error(403)

            def do_POST(self):  # pylint: disable=invalid-name
                """Handle authenticated, bounded bridge IPC only."""
                self.connection.settimeout(1)
                if (
                    self.path not in {"/read", "/status"}
                    or self.headers.get("Authorization") != "Bearer " + bridge._token
                ):
                    self.send_error(403)
                    return
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 16384:
                        raise ValueError("size")
                    value = json.loads(self.rfile.read(size))
                    nonce = value["nonce"]
                    if not isinstance(nonce, str) or len(nonce) != 64:
                        raise ValueError("nonce")
                    digest = hashlib.sha256(nonce.encode()).hexdigest()
                    with bridge._lock:
                        if bridge._nonce_hash not in {None, digest}:
                            raise ValueError("nonce")
                        bridge._nonce_hash = digest
                    if self.path == "/status":
                        result = bridge.status()
                    else:
                        if (
                            type(value.get("navigation")) is not bool
                            or type(value.get("main_document", True)) is not bool
                            or type(value.get("url")) is not str
                        ):
                            raise ValueError("request")
                        result = bridge.read(
                            value["url"],
                            value.get("method"),
                            navigation=value["navigation"],
                            main_document=value.get("main_document", True),
                        )
                    response = dict(result)
                    if "body" in response:
                        response["body"] = base64.b64encode(response["body"]).decode(
                            "ascii"
                        )
                    raw = json.dumps(response, separators=(",", ":")).encode()
                except (ValueError, KeyError, TypeError):
                    self.send_error(400)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self._thread.start()
        return f"http://127.0.0.1:{self._server.server_port}"

    @property
    def credentials(self) -> dict[str, str]:
        """Return inert, one-attempt IPC credentials for the installed adapter."""
        return {"protocol": "web-listening-browser-bridge.v1", "token": self._token}

    def close(self) -> None:
        """Close the listener and transport, including after failed reads."""
        if self._closed:
            return
        self._closed = True
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(1)
        self.gateway.close()
