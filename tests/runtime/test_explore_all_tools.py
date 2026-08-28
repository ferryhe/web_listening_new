"""Focused offline tests for controlled Acquisition tool switching."""

# pylint: disable=duplicate-code,missing-class-docstring,missing-function-docstring
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-lines
# pylint: disable=too-many-locals,too-many-positional-arguments

from __future__ import annotations

import hashlib
import inspect
import ssl
import time
from dataclasses import dataclass, field, fields, replace
from pathlib import Path

import pytest

import web_listening.runtime.workflow as workflow_module
from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.runtime.workflow import run_single_target
from web_listening.site_skill.model import SuccessChecks, ToolReference
from web_listening.site_skill.update import create_candidate
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
    AcquisitionRedirect,
)
from web_listening.tool_registry.registry import Registry

URL = "https://example.test/report"
ORIGIN = "https://example.test"
NOW = "2026-08-27T12:00:00Z"


def _manifest(
    tool_id: str,
    *,
    health: HealthStatus = HealthStatus.HEALTHY,
    qualification: QualificationStatus = QualificationStatus.QUALIFIED,
) -> ToolManifest:
    return ToolManifest(
        tool_id,
        "1.0.0",
        ToolCategory.ACQUISITION,
        ToolDistribution.INSTALLED,
        frozenset({"browser_render"}),
        ToolLimits(30, 4096, 4096),
        health,
        qualification,
    )


PREFERRED = ToolManifest(
    "acquisition.preferred",
    "1.0.0",
    ToolCategory.ACQUISITION,
    ToolDistribution.BUILTIN,
    frozenset({"http_get"}),
    ToolLimits(30, 4096, 4096),
    HealthStatus.HEALTHY,
    QualificationStatus.QUALIFIED,
)


@dataclass(slots=True)
class _Tool:
    manifest: ToolManifest
    output: AcquisitionOutput | AcquisitionFailure | BaseException
    delay_seconds: float = 0.0
    calls: int = 0
    budgets_seen: list[Budgets] = field(default_factory=list)

    def acquire(
        self, _tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        self.calls += 1
        self.budgets_seen.append(_tool_input.request.budgets)
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        if isinstance(self.output, BaseException):
            raise self.output
        return self.output


def _output(
    manifest: ToolManifest,
    body: bytes = b"enough governed words",
    *,
    runtime_ms: int = 7,
    requests: int | None = None,
    bytes_received: int | None = None,
) -> AcquisitionOutput:
    usage = {}
    if requests is not None:
        usage["requests"] = requests
    if bytes_received is not None:
        usage["bytes_received"] = bytes_received
    return AcquisitionOutput(
        manifest.tool_id,
        manifest.version,
        URL,
        URL,
        200,
        "text/html",
        body,
        hashlib.sha256(body).hexdigest(),
        (),
        runtime_ms,
        **usage,
    )


def _failure(
    manifest: ToolManifest,
    code: str,
    *,
    requests: int = 0,
    bytes_received: int = 0,
    runtime_ms: int = 0,
) -> AcquisitionFailure:
    return AcquisitionFailure(
        manifest.tool_id,
        manifest.version,
        code,
        requests,
        bytes_received,
        runtime_ms,
    )


def _redirected_output(
    manifest: ToolManifest,
    body: bytes,
    *,
    runtime_ms: int = 7,
) -> AcquisitionOutput:
    final_url = f"{URL}/final"
    return AcquisitionOutput(
        manifest.tool_id,
        manifest.version,
        URL,
        final_url,
        200,
        "text/html",
        body,
        hashlib.sha256(body).hexdigest(),
        (AcquisitionRedirect(URL, final_url, 302),),
        runtime_ms,
    )


def _request(
    *,
    explore: bool,
    requests: int = 5,
    bytes_budget: int = 4096,
    runtime_seconds: int = 30,
    attempts: int = 5,
    minimum_words: int = 2,
) -> Request:
    scope = Scope(
        (URL,),
        (ORIGIN,),
        ("/**",),
        (ContentType.HTML,),
    )
    budgets = Budgets(requests, bytes_budget, runtime_seconds, attempts)
    skill = create_candidate(
        site_key="example",
        version=1,
        previous=None,
        scope=scope,
        budgets=budgets,
        tool=ToolReference(
            PREFERRED.tool_id,
            PREFERRED.version,
            ToolCategory.ACQUISITION,
            frozenset({"http_get"}),
        ),
        success_checks=SuccessChecks(("text/html",), minimum_words),
        verified_at=NOW,
    ).skill
    return Request(scope, skill, explore, budgets)


def _run(
    tmp_path: Path,
    tools: tuple[_Tool, ...],
    *,
    explore: bool,
    requests: int = 5,
    bytes_budget: int = 4096,
    runtime_seconds: int = 30,
    attempts: int = 5,
    minimum_words: int = 2,
):
    registry = Registry()
    for tool in tools:
        registry.register(tool.manifest, tool)
    store = ArtifactStore(tmp_path / "artifacts")
    result = run_single_target(
        _request(
            explore=explore,
            requests=requests,
            bytes_budget=bytes_budget,
            runtime_seconds=runtime_seconds,
            attempts=attempts,
            minimum_words=minimum_words,
        ),
        registry,
        store,
        run_id="run-one",
        clock=lambda: NOW,
    )
    return result, store


def _run_request(tmp_path: Path, tools: tuple[_Tool, ...], request: Request):
    registry = Registry()
    for tool in tools:
        registry.register(tool.manifest, tool)
    store = ArtifactStore(tmp_path / "artifacts")
    result = run_single_target(
        request,
        registry,
        store,
        run_id="run-one",
        clock=lambda: NOW,
    )
    return result, store


def _request_without_site_skill(*, explore: bool) -> Request:
    return Request(
        Scope((URL,), (ORIGIN,), ("/**",), (ContentType.HTML,)),
        None,
        explore,
        Budgets(5, 4096, 30, 5),
    )


def test_explore_false_never_switches_after_retryable_failure(tmp_path: Path) -> None:
    preferred = _Tool(PREFERRED, _failure(PREFERRED, "gateway.timeout"))
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run(tmp_path, (alternate, preferred), explore=False)

    assert result.status.value == "failed"
    assert [attempt.tool_id for attempt in result.attempts] == [PREFERRED.tool_id]
    assert preferred.calls == 1
    assert alternate.calls == 0
    assert tuple(field.name for field in fields(Request)) == (
        "scope",
        "site_skill",
        "explore_all_tools",
        "budgets",
    )
    store.close()


def test_no_site_skill_and_explore_false_only_try_default_web_http(
    tmp_path: Path,
) -> None:
    default = _Tool(
        WEB_HTTP_MANIFEST,
        _failure(WEB_HTTP_MANIFEST, "gateway.timeout"),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run_request(
        tmp_path,
        (alternate, default),
        _request_without_site_skill(explore=False),
    )

    assert result.status.value == "failed"
    assert [attempt.tool_id for attempt in result.attempts] == [
        WEB_HTTP_MANIFEST.tool_id
    ]
    assert result.site_skill_used is None
    assert default.calls == 1
    assert alternate.calls == 0
    store.close()


def test_no_site_skill_and_explore_true_switches_after_retryable_default_failure(
    tmp_path: Path,
) -> None:
    default = _Tool(
        WEB_HTTP_MANIFEST,
        _failure(WEB_HTTP_MANIFEST, "gateway.timeout"),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run_request(
        tmp_path,
        (alternate, default),
        _request_without_site_skill(explore=True),
    )

    assert result.status.value == "partial"
    assert [attempt.tool_id for attempt in result.attempts] == [
        WEB_HTTP_MANIFEST.tool_id,
        alternate_manifest.tool_id,
    ]
    assert result.site_skill_used is None
    assert default.calls == alternate.calls == 1
    store.close()


@pytest.mark.parametrize("default_state", ["missing", "unqualified"])
def test_no_site_skill_rejects_missing_or_unqualified_default_without_invoking(
    tmp_path: Path, default_state: str
) -> None:
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))
    tools = [alternate]
    if default_state == "unqualified":
        default_manifest = ToolManifest(
            WEB_HTTP_MANIFEST.tool_id,
            WEB_HTTP_MANIFEST.version,
            WEB_HTTP_MANIFEST.category,
            WEB_HTTP_MANIFEST.distribution,
            WEB_HTTP_MANIFEST.capabilities,
            WEB_HTTP_MANIFEST.limits,
            WEB_HTTP_MANIFEST.health,
            QualificationStatus.UNQUALIFIED,
        )
        tools.append(_Tool(default_manifest, _output(default_manifest)))

    result, store = _run_request(
        tmp_path,
        tuple(tools),
        _request_without_site_skill(explore=True),
    )

    assert result.status.value == "rejected"
    assert result.errors[0].code == (
        "runtime.default_tool_missing"
        if default_state == "missing"
        else "eligibility.unqualified"
    )
    assert all(tool.calls == 0 for tool in tools)
    assert [attempt.outcome for attempt in result.attempts] == (
        [] if default_state == "missing" else ["skipped"]
    )
    assert result.usage.tool_attempts == 0
    store.close()


@pytest.mark.parametrize("failure_mode", ["technical", "quality"])
def test_retryable_technical_and_quality_failures_switch_to_first_valid_success(
    tmp_path: Path, failure_mode: str
) -> None:
    first_output = (
        _failure(PREFERRED, "gateway.timeout")
        if failure_mode == "technical"
        else _output(PREFERRED, b"short", runtime_ms=3)
    )
    preferred = _Tool(PREFERRED, first_output)
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run(tmp_path, (alternate, preferred), explore=True)

    assert result.status.value == "partial"
    assert [attempt.outcome for attempt in result.attempts] == [
        "failed",
        "succeeded",
    ]
    assert [attempt.tool_id for attempt in result.attempts] == [
        PREFERRED.tool_id,
        alternate_manifest.tool_id,
    ]
    assert preferred.calls == alternate.calls == 1
    assert len(result.artifacts) == 1
    assert store.get_observation(result.artifacts[0].observation_id).content == (
        b"enough governed words"
    )
    store.close()


def test_reported_success_usage_is_deducted_before_quality_fallback(
    tmp_path: Path,
) -> None:
    preferred = _Tool(
        PREFERRED,
        _output(
            PREFERRED,
            b"short",
            runtime_ms=3,
            requests=2,
            bytes_received=25,
        ),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate_body = b"valid alternate governed words"
    alternate = _Tool(alternate_manifest, _output(alternate_manifest, alternate_body))

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
        requests=3,
        bytes_budget=100,
        attempts=2,
    )

    assert alternate.budgets_seen == [Budgets(1, 75, 29, 1)]
    assert result.status.value == "partial"
    assert result.usage.to_dict() == {
        "requests": 3,
        "bytes_received": 25 + len(alternate_body),
        "runtime_ms": 10,
        "tool_attempts": 2,
    }
    store.close()


def test_replaced_legacy_usage_is_deducted_before_quality_fallback(
    tmp_path: Path,
) -> None:
    legacy = _output(PREFERRED, b"short", runtime_ms=3)
    preferred = _Tool(
        PREFERRED,
        replace(legacy, requests=2, bytes_received=25),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate_body = b"valid alternate governed words"
    alternate = _Tool(alternate_manifest, _output(alternate_manifest, alternate_body))

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
        requests=3,
        bytes_budget=100,
        attempts=2,
    )

    assert alternate.budgets_seen == [Budgets(1, 75, 29, 1)]
    assert result.usage.requests == 3
    assert result.usage.bytes_received == 25 + len(alternate_body)
    store.close()


def test_server_error_with_typed_usage_switches_to_alternate(tmp_path: Path) -> None:
    preferred = _Tool(
        PREFERRED,
        _failure(
            PREFERRED,
            "gateway.server_error",
            requests=2,
            runtime_ms=11,
        ),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
        requests=3,
        attempts=2,
    )

    assert result.status.value == "partial"
    assert [
        attempt.error.code if attempt.error else None for attempt in result.attempts
    ] == [
        "gateway.server_error",
        None,
    ]
    assert alternate.budgets_seen == [Budgets(1, 4096, 29, 1)]
    assert result.usage.requests == 3
    store.close()


def test_certificate_verification_failure_is_terminal_after_real_gateway(
    tmp_path: Path,
) -> None:
    class RobotsAbsentResponse:
        status = 404
        headers: dict[str, str] = {}
        peer_ip = "93.184.216.34"

        def close(self) -> None:
            return None

    class CertificateFailureTransport:
        def __init__(self) -> None:
            self.requests: list[str] = []
            self.closed = 0

        def send(
            self, url: str, *, timeout: float, addresses: tuple[str, ...]
        ) -> object:
            del timeout, addresses
            self.requests.append(url)
            if url.endswith("/robots.txt"):
                return RobotsAbsentResponse()
            raise ssl.SSLCertVerificationError(1, "private certificate diagnostic")

        def close(self) -> None:
            self.closed += 1

    transport = CertificateFailureTransport()
    preferred = WebHttpAcquisitionTool(
        lambda: transport,
        resolver=lambda _host, _port: ("93.184.216.34",),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run_request(
        tmp_path,
        (alternate, preferred),  # type: ignore[arg-type]
        _request_without_site_skill(explore=True),
    )

    assert result.status.value == "failed"
    assert len(result.attempts) == 1
    assert result.attempts[0].error.code == "gateway.tls_certificate_invalid"
    assert result.attempts[0].requests == 2
    assert result.attempts[0].bytes_received == 0
    assert result.usage.requests == 2
    assert result.usage.tool_attempts == 1
    assert alternate.calls == 0
    assert len(transport.requests) == 2
    assert transport.closed == 1
    store.close()


@pytest.mark.parametrize(
    ("headers", "expected_code", "allows_switch"),
    [
        ({"content-length": "2"}, "gateway.mime_missing", True),
        (
            {"content-type": "not-a-mime", "content-length": "2"},
            "gateway.mime_invalid",
            True,
        ),
        (
            {"content-type": "application/pdf", "content-length": "2"},
            "scope.content_type_not_allowed",
            False,
        ),
    ],
)
def test_real_gateway_mime_failures_only_switch_for_technical_codes(
    tmp_path: Path,
    headers: dict[str, str],
    expected_code: str,
    allows_switch: bool,
) -> None:
    class Response:
        status = 200
        peer_ip = "93.184.216.34"

        def __init__(self, response_headers: dict[str, str]) -> None:
            self.headers = response_headers
            self.reads = 0

        def set_timeout(self, _timeout: float) -> None:
            return None

        def read(self, _max_bytes: int) -> bytes:
            self.reads += 1
            return b"ok"

        def close(self) -> None:
            return None

    class MimeTransport:
        def __init__(self) -> None:
            self.target = Response(headers)
            self.requests: list[str] = []

        def send(
            self, url: str, *, timeout: float, addresses: tuple[str, ...]
        ) -> object:
            del timeout, addresses
            self.requests.append(url)
            if url.endswith("/robots.txt"):
                robots = Response({})
                robots.status = 404
                return robots
            return self.target

        def close(self) -> None:
            return None

    transport = MimeTransport()
    preferred = WebHttpAcquisitionTool(
        lambda: transport,
        resolver=lambda _host, _port: ("93.184.216.34",),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate_body = b"valid alternate governed words"
    alternate = _Tool(alternate_manifest, _output(alternate_manifest, alternate_body))

    result, store = _run_request(
        tmp_path,
        (alternate, preferred),  # type: ignore[arg-type]
        _request_without_site_skill(explore=True),
    )

    assert result.attempts[0].error.code == expected_code
    assert result.attempts[0].requests == 2
    assert result.attempts[0].bytes_received == 0
    assert transport.target.reads == 0
    if allows_switch:
        assert result.status.value == "partial"
        assert len(result.attempts) == 2
        assert alternate.calls == 1
        assert alternate.budgets_seen[0].max_requests == 3
        assert (
            alternate.budgets_seen[0].max_runtime_seconds
            == (30_000 - result.attempts[0].runtime_ms) // 1_000
        )
        assert result.usage.requests == 3
        assert result.usage.bytes_received == len(alternate_body)
    else:
        assert result.status.value == "failed"
        assert len(result.attempts) == 1
        assert alternate.calls == 0
        assert result.usage.requests == 2
        assert result.usage.bytes_received == 0
    assert result.usage.runtime_ms == sum(
        attempt.runtime_ms for attempt in result.attempts
    )
    assert result.usage.tool_attempts == len(result.attempts)
    store.close()


@pytest.mark.parametrize(
    ("stage", "failure_kind", "expected_code", "expected_bytes", "allows_switch"),
    [
        ("robots", "short_body", "robots.network_error", 1, False),
        ("robots", "tls", "robots.network_error", 0, False),
        ("target", "short_body", "gateway.body_incomplete", 1, True),
        ("target", "tls", "gateway.tls", 0, True),
    ],
)
def test_robots_failures_are_terminal_while_target_technical_failures_switch(
    tmp_path: Path,
    stage: str,
    failure_kind: str,
    expected_code: str,
    expected_bytes: int,
    allows_switch: bool,
) -> None:
    class Response:
        peer_ip = "93.184.216.34"

        def __init__(
            self, status: int, headers: dict[str, str], body: bytes = b""
        ) -> None:
            self.status = status
            self.headers = headers
            self.body = body

        def set_timeout(self, _timeout: float) -> None:
            return None

        def read(self, max_bytes: int) -> bytes:
            return self.body[:max_bytes]

        def close(self) -> None:
            return None

    class StageTransport:
        def __init__(self) -> None:
            self.requests: list[str] = []

        def send(
            self, url: str, *, timeout: float, addresses: tuple[str, ...]
        ) -> object:
            del timeout, addresses
            self.requests.append(url)
            current_stage = "robots" if url.endswith("/robots.txt") else "target"
            if current_stage == stage:
                if failure_kind == "tls":
                    raise ssl.SSLError(1, "private transient tls diagnostic")
                mime_type = "text/plain" if stage == "robots" else "text/html"
                return Response(
                    200,
                    {"content-type": mime_type, "content-length": "2"},
                    b"x",
                )
            if current_stage == "robots":
                return Response(404, {})
            raise AssertionError("target must be the scripted failure stage")

        def close(self) -> None:
            return None

    transport = StageTransport()
    preferred = WebHttpAcquisitionTool(
        lambda: transport,
        resolver=lambda _host, _port: ("93.184.216.34",),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate_body = b"valid alternate governed words"
    alternate = _Tool(alternate_manifest, _output(alternate_manifest, alternate_body))

    result, store = _run_request(
        tmp_path,
        (alternate, preferred),  # type: ignore[arg-type]
        _request_without_site_skill(explore=True),
    )

    expected_requests = 1 if stage == "robots" else 2
    first_attempt = result.attempts[0]
    assert first_attempt.error.code == expected_code
    assert first_attempt.requests == expected_requests
    assert first_attempt.bytes_received == expected_bytes
    if allows_switch:
        assert result.status.value == "partial"
        assert len(result.attempts) == 2
        assert alternate.calls == 1
        assert alternate.budgets_seen[0].max_requests == 5 - expected_requests
        assert alternate.budgets_seen[0].max_bytes == 4096 - expected_bytes
        assert result.usage.requests == expected_requests + 1
        assert result.usage.bytes_received == expected_bytes + len(alternate_body)
    else:
        assert result.status.value == "failed"
        assert len(result.attempts) == 1
        assert alternate.calls == 0
        assert result.usage.requests == expected_requests
        assert result.usage.bytes_received == expected_bytes
    assert result.usage.runtime_ms == sum(
        attempt.runtime_ms for attempt in result.attempts
    )
    assert result.usage.tool_attempts == len(result.attempts)
    store.close()


def test_incomplete_body_deducts_usage_then_switches_to_alternate(
    tmp_path: Path,
) -> None:
    preferred = _Tool(
        PREFERRED,
        _failure(
            PREFERRED,
            "gateway.body_incomplete",
            requests=2,
            bytes_received=1,
            runtime_ms=11,
        ),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate_body = b"valid alternate governed words"
    alternate = _Tool(alternate_manifest, _output(alternate_manifest, alternate_body))

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
        requests=3,
        bytes_budget=100,
        attempts=2,
    )

    assert result.status.value == "partial"
    assert [
        attempt.error.code if attempt.error else None for attempt in result.attempts
    ] == ["gateway.body_incomplete", None]
    assert alternate.budgets_seen == [Budgets(1, 99, 29, 1)]
    assert result.usage.requests == 3
    assert result.usage.bytes_received == 1 + len(alternate_body)
    assert result.usage.runtime_ms == 18
    assert result.usage.tool_attempts == 2
    store.close()


@pytest.mark.parametrize("status", [401, 403, 404, 410])
def test_auth_and_not_found_http_statuses_remain_terminal(
    tmp_path: Path, status: int
) -> None:
    class Response:
        peer_ip = "93.184.216.34"

        def __init__(self, response_status: int) -> None:
            self.status = response_status
            self.headers: dict[str, str] = {}
            self.reads = 0
            self.closed = 0

        def set_timeout(self, _timeout: float) -> None:
            return None

        def read(self, _max_bytes: int) -> bytes:
            self.reads += 1
            return b"must-not-be-read"

        def close(self) -> None:
            self.closed += 1

    class StatusTransport:
        def __init__(self) -> None:
            self.requests: list[str] = []
            self.target = Response(status)
            self.closed = 0

        def send(
            self, url: str, *, timeout: float, addresses: tuple[str, ...]
        ) -> object:
            del timeout, addresses
            self.requests.append(url)
            if url.endswith("/robots.txt"):
                return Response(404)
            return self.target

        def close(self) -> None:
            self.closed += 1

    transport = StatusTransport()
    preferred = WebHttpAcquisitionTool(
        lambda: transport,
        resolver=lambda _host, _port: ("93.184.216.34",),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run_request(
        tmp_path,
        (alternate, preferred),  # type: ignore[arg-type]
        _request_without_site_skill(explore=True),
    )

    assert result.status.value == "failed"
    assert [attempt.tool_id for attempt in result.attempts] == [
        WEB_HTTP_MANIFEST.tool_id
    ]
    assert result.errors[0].code == "gateway.http_status"
    assert result.usage.requests == 2
    assert alternate.calls == 0
    assert transport.requests == [f"{ORIGIN}/robots.txt", URL]
    assert transport.target.status == status
    assert transport.target.reads == 0
    assert transport.target.closed == 1
    assert transport.closed == 1
    store.close()


def test_untyped_registry_tool_exception_is_terminal_with_elapsed_runtime(
    tmp_path: Path,
) -> None:
    preferred = _Tool(
        PREFERRED,
        RuntimeError("private tool diagnostic"),
        delay_seconds=0.01,
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
    )

    assert result.status.value == "failed"
    assert result.errors[0].code == "registry.tool_exception"
    assert result.attempts[0].error.code == "registry.tool_exception"
    assert result.attempts[0].requests == result.attempts[0].bytes_received == 0
    assert result.attempts[0].runtime_ms >= 1
    assert result.usage.runtime_ms == result.attempts[0].runtime_ms
    assert preferred.calls == 1
    assert alternate.calls == 0
    store.close()


@pytest.mark.parametrize(
    "terminal_code",
    [
        "robots.disallowed",
        "scope.origin_not_allowed",
        "gateway.https_downgrade",
        "gateway.http_status",
        "budget.requests",
    ],
)
def test_policy_security_and_budget_rejections_stop_without_switching(
    tmp_path: Path, terminal_code: str
) -> None:
    preferred = _Tool(PREFERRED, _failure(PREFERRED, terminal_code))
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run(tmp_path, (alternate, preferred), explore=True)

    assert result.status.value == "failed"
    assert [attempt.error.code for attempt in result.attempts] == [terminal_code]
    assert preferred.calls == 1
    assert alternate.calls == 0
    store.close()


def test_unqualified_tool_is_skipped_and_rank_does_not_use_registration_order(
    tmp_path: Path,
) -> None:
    preferred = _Tool(PREFERRED, _failure(PREFERRED, "gateway.timeout"))
    zulu_manifest = _manifest("acquisition.zulu")
    zulu = _Tool(zulu_manifest, _output(zulu_manifest, b"zulu should not run"))
    alpha_manifest = _manifest("acquisition.alpha")
    alpha = _Tool(alpha_manifest, _output(alpha_manifest))
    unqualified_manifest = _manifest(
        "acquisition.disabled",
        qualification=QualificationStatus.UNQUALIFIED,
    )
    unqualified = _Tool(unqualified_manifest, _output(unqualified_manifest))

    result, store = _run(
        tmp_path,
        (zulu, unqualified, preferred, alpha),
        explore=True,
    )

    assert [attempt.tool_id for attempt in result.attempts] == [
        PREFERRED.tool_id,
        unqualified_manifest.tool_id,
        alpha_manifest.tool_id,
    ]
    assert [attempt.outcome for attempt in result.attempts] == [
        "failed",
        "skipped",
        "succeeded",
    ]
    assert result.attempts[1].error is not None
    assert result.attempts[1].error.code == "eligibility.unqualified"
    assert unqualified.calls == zulu.calls == 0
    assert preferred.calls == alpha.calls == 1
    store.close()


def test_attempt_reason_usage_and_order_are_complete_across_quality_skip_success(
    tmp_path: Path,
) -> None:
    preferred = _Tool(PREFERRED, _output(PREFERRED, b"short", runtime_ms=3))
    skipped_manifest = _manifest(
        "acquisition.disabled",
        qualification=QualificationStatus.UNQUALIFIED,
    )
    skipped = _Tool(skipped_manifest, _output(skipped_manifest))
    success_manifest = _manifest("acquisition.success")
    success_body = b"accepted governed acquisition"
    success = _Tool(
        success_manifest,
        _output(success_manifest, success_body, runtime_ms=5),
    )

    result, store = _run(
        tmp_path,
        (success, preferred, skipped),
        explore=True,
    )

    assert [attempt.order for attempt in result.attempts] == [0, 1, 2]
    assert len({attempt.attempt_id for attempt in result.attempts}) == 3
    assert [attempt.outcome for attempt in result.attempts] == [
        "failed",
        "skipped",
        "succeeded",
    ]
    quality, omitted, accepted = result.attempts
    assert quality.error is not None
    assert quality.error.code == "runtime.quality_minimum_words"
    assert (quality.requests, quality.bytes_received, quality.runtime_ms) == (
        1,
        len(b"short"),
        3,
    )
    assert omitted.error is not None
    assert omitted.error.code == "eligibility.unqualified"
    assert (omitted.requests, omitted.bytes_received, omitted.runtime_ms) == (0, 0, 0)
    assert (accepted.requests, accepted.bytes_received, accepted.runtime_ms) == (
        1,
        len(success_body),
        5,
    )
    assert result.usage.to_dict() == {
        "requests": 2,
        "bytes_received": len(b"short") + len(success_body),
        "runtime_ms": 8,
        "tool_attempts": 2,
    }
    assert result.manifest.attempts == result.attempts
    assert result.manifest.usage == result.usage
    assert store.get_observation(result.artifacts[0].observation_id).content == (
        success_body
    )
    store.close()


def test_each_fallback_receives_only_remaining_request_budgets(
    tmp_path: Path,
) -> None:
    preferred_body = b"x" * 60
    preferred = _Tool(
        PREFERRED,
        _output(PREFERRED, preferred_body, runtime_ms=1_500),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate_body = b"enough alternate governed words"
    alternate = _Tool(
        alternate_manifest,
        _output(alternate_manifest, alternate_body, runtime_ms=900),
    )

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
        requests=2,
        bytes_budget=100,
        runtime_seconds=3,
        attempts=2,
    )

    assert result.status.value == "partial"
    assert preferred.budgets_seen == [Budgets(2, 100, 3, 2)]
    assert alternate.budgets_seen == [Budgets(1, 40, 1, 1)]
    assert result.usage.to_dict() == {
        "requests": 2,
        "bytes_received": len(preferred_body) + len(alternate_body),
        "runtime_ms": 2_400,
        "tool_attempts": 2,
    }
    store.close()


def test_retryable_failure_usage_is_deducted_before_fallback(tmp_path: Path) -> None:
    preferred = _Tool(
        PREFERRED,
        _failure(
            PREFERRED,
            "gateway.timeout",
            requests=1,
            bytes_received=10,
            runtime_ms=1_100,
        ),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate_body = b"valid alternate governed words"
    alternate = _Tool(
        alternate_manifest,
        _output(alternate_manifest, alternate_body, runtime_ms=900),
    )

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
        requests=2,
        bytes_budget=100,
        runtime_seconds=3,
        attempts=2,
    )

    assert alternate.budgets_seen == [Budgets(1, 90, 1, 1)]
    assert result.status.value == "partial"
    assert result.usage.to_dict() == {
        "requests": 2,
        "bytes_received": 10 + len(alternate_body),
        "runtime_ms": 2_000,
        "tool_attempts": 2,
    }
    store.close()


@pytest.mark.parametrize("failure_mode", ["technical", "quality"])
def test_observed_normal_return_runtime_exhausts_budget_before_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    monkeypatch.setattr(
        workflow_module,
        "_elapsed_runtime_ms",
        lambda _started_ns, _finished_ns=None: 1_100,
    )
    preferred_result: AcquisitionOutput | AcquisitionFailure
    if failure_mode == "technical":
        preferred_result = _failure(PREFERRED, "gateway.timeout", runtime_ms=0)
    else:
        preferred_result = _output(PREFERRED, b"short", runtime_ms=0)
    preferred = _Tool(PREFERRED, preferred_result)
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
        runtime_seconds=1,
        attempts=2,
    )

    assert result.status.value == "failed"
    assert result.errors[0].code == "eligibility.runtime_budget_exhausted"
    assert len(result.attempts) == 1
    assert result.attempts[0].error.code == "eligibility.runtime_budget_exhausted"
    assert result.attempts[0].runtime_ms == 1_100
    assert result.usage.runtime_ms == 1_100
    assert result.usage.tool_attempts == 1
    assert preferred.calls == 1
    assert alternate.calls == 0
    store.close()


@pytest.mark.parametrize(
    ("reported_runtime", "observed_runtime", "expected_runtime"),
    [(0, 250, 250), (700, 100, 700)],
)
def test_success_runtime_uses_max_of_reported_and_observed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reported_runtime: int,
    observed_runtime: int,
    expected_runtime: int,
) -> None:
    monkeypatch.setattr(
        workflow_module,
        "_elapsed_runtime_ms",
        lambda _started_ns, _finished_ns=None: observed_runtime,
    )
    preferred = _Tool(
        PREFERRED,
        _output(PREFERRED, runtime_ms=reported_runtime),
    )

    result, store = _run(tmp_path, (preferred,), explore=False)

    assert result.status.value == "completed"
    assert len(result.attempts) == 1
    assert result.attempts[0].runtime_ms == expected_runtime
    assert result.usage.runtime_ms == expected_runtime
    store.close()


@pytest.mark.parametrize(
    ("observed_runtime", "expected_status", "artifact_count"),
    [
        (1_100, "failed", 0),
        (1_000, "completed", 1),
        (999, "completed", 1),
    ],
)
def test_success_observed_runtime_hard_limit_prevents_artifact_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    observed_runtime: int,
    expected_status: str,
    artifact_count: int,
) -> None:
    monkeypatch.setattr(
        workflow_module,
        "_elapsed_runtime_ms",
        lambda _started_ns, _finished_ns=None: observed_runtime,
    )
    preferred = _Tool(PREFERRED, _output(PREFERRED, runtime_ms=0))
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
        runtime_seconds=1,
        attempts=2,
    )

    assert result.status.value == expected_status
    assert len(result.attempts) == 1
    assert result.attempts[0].runtime_ms == observed_runtime
    assert result.usage.runtime_ms == observed_runtime
    assert len(result.artifacts) == artifact_count
    assert alternate.calls == 0
    if observed_runtime > 1_000:
        assert result.errors[0].code == "eligibility.runtime_budget_exhausted"
        assert result.attempts[0].outcome == "failed"
        assert result.attempts[0].error.code == "eligibility.runtime_budget_exhausted"
    else:
        assert not result.errors
        assert result.attempts[0].outcome == "succeeded"
        assert result.attempts[0].error is None
    store.close()


@pytest.mark.parametrize(
    (
        "explore",
        "failure_code",
        "request_budget",
        "byte_budget",
        "reported_requests",
        "reported_bytes",
        "observed_runtime",
        "expected_code",
    ),
    [
        (
            False,
            "gateway.timeout",
            1,
            100,
            2,
            0,
            0,
            "eligibility.request_budget_exhausted",
        ),
        (
            True,
            "gateway.timeout",
            5,
            100,
            0,
            101,
            0,
            "eligibility.byte_budget_exhausted",
        ),
        (
            False,
            "robots.disallowed",
            5,
            100,
            0,
            0,
            1_100,
            "eligibility.runtime_budget_exhausted",
        ),
        (
            True,
            "robots.disallowed",
            1,
            100,
            2,
            0,
            0,
            "eligibility.request_budget_exhausted",
        ),
        (
            True,
            "budget.runtime",
            1,
            100,
            2,
            101,
            1_100,
            "eligibility.request_budget_exhausted",
        ),
    ],
)
def test_failure_post_invoke_overage_uses_exact_dimension(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    explore: bool,
    failure_code: str,
    request_budget: int,
    byte_budget: int,
    reported_requests: int,
    reported_bytes: int,
    observed_runtime: int,
    expected_code: str,
) -> None:
    monkeypatch.setattr(
        workflow_module,
        "_elapsed_runtime_ms",
        lambda _started_ns, _finished_ns=None: observed_runtime,
    )
    preferred = _Tool(
        PREFERRED,
        _failure(
            PREFERRED,
            failure_code,
            requests=reported_requests,
            bytes_received=reported_bytes,
        ),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=explore,
        requests=request_budget,
        bytes_budget=byte_budget,
        runtime_seconds=1,
        attempts=2,
    )

    assert result.status.value == "failed"
    assert len(result.attempts) == 1
    assert result.attempts[0].error.code == expected_code
    assert result.errors[0].code == expected_code
    assert result.usage.to_dict() == {
        "requests": reported_requests,
        "bytes_received": reported_bytes,
        "runtime_ms": observed_runtime,
        "tool_attempts": 1,
    }
    assert alternate.calls == 0
    store.close()


@pytest.mark.parametrize(
    ("reported_requests", "reported_bytes", "observed_runtime"),
    [(1, 0, 0), (0, 100, 0), (0, 0, 1_000)],
)
def test_failure_post_invoke_budget_equality_preserves_original_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reported_requests: int,
    reported_bytes: int,
    observed_runtime: int,
) -> None:
    monkeypatch.setattr(
        workflow_module,
        "_elapsed_runtime_ms",
        lambda _started_ns, _finished_ns=None: observed_runtime,
    )
    preferred = _Tool(
        PREFERRED,
        _failure(
            PREFERRED,
            "robots.disallowed",
            requests=reported_requests,
            bytes_received=reported_bytes,
        ),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
        requests=1,
        bytes_budget=100,
        runtime_seconds=1,
        attempts=2,
    )

    assert result.errors[0].code == "robots.disallowed"
    assert result.attempts[0].error.code == "robots.disallowed"
    assert result.attempts[0].runtime_ms == observed_runtime
    assert alternate.calls == 0
    store.close()


@pytest.mark.parametrize(
    (
        "failure_code",
        "reported_requests",
        "reported_bytes",
        "reported_runtime",
        "observed_runtime",
    ),
    [
        ("budget.requests", 2, 0, 0, 0),
        ("budget.bytes", 0, 101, 0, 0),
        ("budget.runtime", 0, 0, 1_100, 100),
    ],
)
def test_matching_reported_budget_failure_code_is_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_code: str,
    reported_requests: int,
    reported_bytes: int,
    reported_runtime: int,
    observed_runtime: int,
) -> None:
    monkeypatch.setattr(
        workflow_module,
        "_elapsed_runtime_ms",
        lambda _started_ns, _finished_ns=None: observed_runtime,
    )
    preferred = _Tool(
        PREFERRED,
        _failure(
            PREFERRED,
            failure_code,
            requests=reported_requests,
            bytes_received=reported_bytes,
            runtime_ms=reported_runtime,
        ),
    )

    result, store = _run(
        tmp_path,
        (preferred,),
        explore=False,
        requests=1,
        bytes_budget=100,
        runtime_seconds=1,
        attempts=1,
    )

    assert result.errors[0].code == failure_code
    assert result.attempts[0].error.code == failure_code
    assert result.usage.to_dict() == {
        "requests": reported_requests,
        "bytes_received": reported_bytes,
        "runtime_ms": max(reported_runtime, observed_runtime),
        "tool_attempts": 1,
    }
    store.close()


def test_interrupted_body_partial_bytes_are_deducted_before_fallback(
    tmp_path: Path,
) -> None:
    preferred = _Tool(
        PREFERRED,
        _failure(
            PREFERRED,
            "gateway.transport",
            requests=2,
            bytes_received=5,
            runtime_ms=100,
        ),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
        requests=3,
        bytes_budget=100,
        attempts=2,
    )

    assert alternate.budgets_seen == [Budgets(1, 95, 29, 1)]
    assert result.usage.requests == 3
    assert result.usage.bytes_received == 5 + len(b"enough governed words")
    store.close()


def test_retryable_failure_that_consumes_request_budget_stops_fallback(
    tmp_path: Path,
) -> None:
    preferred = _Tool(
        PREFERRED,
        _failure(PREFERRED, "gateway.timeout", requests=1, runtime_ms=50),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
        requests=1,
        attempts=2,
    )

    assert result.errors[0].code == "eligibility.request_budget_exhausted"
    assert result.attempts[0].error.code == "gateway.timeout"
    assert result.usage.requests == 1
    assert preferred.calls == 1
    assert alternate.calls == 0
    store.close()


@pytest.mark.parametrize("dimension", ["request", "byte", "runtime"])
# pylint: disable-next=too-many-locals
def test_registry_rejected_output_preserves_usage_and_exact_budget_dimension(
    tmp_path: Path, dimension: str
) -> None:
    preferred_body = b"short"
    requests, bytes_budget, runtime_seconds = 3, 100, 30
    preferred_runtime = 7
    alternate_runtime = 7
    alternate_body = b"valid alternate governed words"
    if dimension == "request":
        requests = 2
    elif dimension == "byte":
        preferred_body = b"x" * 60
        alternate_body = b"valid words " + b"x" * 63
    else:
        runtime_seconds = 3
        preferred_runtime = 1_100
        alternate_runtime = 1_500
    preferred = _Tool(
        PREFERRED,
        _output(PREFERRED, preferred_body, runtime_ms=preferred_runtime),
    )
    alternate_manifest = _manifest("acquisition.alternate")
    alternate_output = (
        _redirected_output(
            alternate_manifest,
            alternate_body,
            runtime_ms=alternate_runtime,
        )
        if dimension == "request"
        else _output(
            alternate_manifest,
            alternate_body,
            runtime_ms=alternate_runtime,
        )
    )
    alternate = _Tool(alternate_manifest, alternate_output)
    zulu_manifest = _manifest("acquisition.zulu")
    zulu = _Tool(zulu_manifest, _output(zulu_manifest))

    result, store = _run(
        tmp_path,
        (zulu, alternate, preferred),
        explore=True,
        requests=requests,
        bytes_budget=bytes_budget,
        runtime_seconds=runtime_seconds,
        attempts=3,
    )

    expected_code = {
        "request": "budget.requests",
        "byte": "budget.bytes",
        "runtime": "budget.runtime",
    }[dimension]
    assert [attempt.error.code for attempt in result.attempts] == [
        "runtime.quality_minimum_words",
        expected_code,
    ]
    assert result.errors[0].code == expected_code
    assert result.usage.to_dict() == {
        "requests": 3 if dimension == "request" else 2,
        "bytes_received": len(preferred_body) + len(alternate_body),
        "runtime_ms": preferred_runtime + alternate_runtime,
        "tool_attempts": 2,
    }
    assert not result.artifacts
    assert zulu.calls == 0
    store.close()


@pytest.mark.parametrize(
    ("exhausted", "expected_code"),
    [
        ("request", "eligibility.request_budget_exhausted"),
        ("byte", "eligibility.byte_budget_exhausted"),
        ("runtime", "eligibility.runtime_budget_exhausted"),
        ("attempt", "eligibility.attempt_budget_exhausted"),
    ],
)
def test_budget_exhaustion_stops_before_fallback_with_specific_reason(
    tmp_path: Path, exhausted: str, expected_code: str
) -> None:
    requests, bytes_budget, runtime_seconds, attempts = 2, 100, 3, 2
    output: AcquisitionOutput | AcquisitionFailure
    if exhausted == "request":
        requests = 1
        output = _output(PREFERRED, b"short", runtime_ms=10)
    elif exhausted == "byte":
        bytes_budget = len(b"short")
        output = _output(PREFERRED, b"short", runtime_ms=10)
    elif exhausted == "runtime":
        output = _output(PREFERRED, b"short", runtime_ms=2_501)
    else:
        attempts = 1
        output = _failure(PREFERRED, "gateway.timeout")
    preferred = _Tool(PREFERRED, output)
    alternate_manifest = _manifest("acquisition.alternate")
    alternate = _Tool(alternate_manifest, _output(alternate_manifest))

    result, store = _run(
        tmp_path,
        (alternate, preferred),
        explore=True,
        requests=requests,
        bytes_budget=bytes_budget,
        runtime_seconds=runtime_seconds,
        attempts=attempts,
    )

    assert result.status.value == "failed"
    assert result.errors[0].code == expected_code
    assert preferred.calls == 1
    assert alternate.calls == 0
    assert result.usage.requests <= requests
    assert result.usage.bytes_received <= bytes_budget
    assert result.usage.runtime_ms <= runtime_seconds * 1_000
    assert result.usage.tool_attempts <= attempts
    store.close()


def test_first_success_stops_without_considering_or_skipping_other_tools(
    tmp_path: Path,
) -> None:
    preferred = _Tool(PREFERRED, _output(PREFERRED))
    alpha_manifest = _manifest("acquisition.alpha")
    alpha = _Tool(alpha_manifest, _output(alpha_manifest))

    result, store = _run(tmp_path, (alpha, preferred), explore=True)

    assert result.status.value == "completed"
    assert [attempt.tool_id for attempt in result.attempts] == [PREFERRED.tool_id]
    assert preferred.calls == 1
    assert alpha.calls == 0
    store.close()


def test_runtime_consumes_registry_selection_without_filter_or_tool_chain() -> None:
    workflow = inspect.getsource(workflow_module.run_single_target)
    source = inspect.getsource(workflow_module).casefold()

    assert "rank_eligible_tools(" in workflow
    assert workflow.count("registry.invoke(") == 1
    assert "sorted(" not in workflow
    assert "qualificationstatus" not in source
    assert "healthstatus" not in source
    assert "fallback_order" not in source
    assert "playwright" not in source
    assert "cloakbrowser" not in source
