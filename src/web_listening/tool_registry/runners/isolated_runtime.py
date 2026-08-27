"""Scope-bound execution for an external Acquisition subprocess.

This module carries no browser-specific behavior. It binds the existing
SubprocessRunner to explicit authorization and a parent-applied controlled proxy,
then exposes a qualified manifest only for the exact successful binding.
"""

# pylint: disable=duplicate-code,too-few-public-methods
# pylint: disable=too-many-arguments,too-many-instance-attributes
# pylint: disable=too-many-return-statements
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolManifest,
    ToolRegistryError,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.runners.subprocess import SubprocessRunner

_BOUNDARY_SCHEMA = "web-listening-network-boundary.v1"
_QUALIFICATION_PROTOCOL = "web-listening-tool-qualification.v1"
_REQUIRED_CHECKS = (
    "health",
    "protocol",
    "scope",
    "redirect",
    "output_bound",
    "controlled_proxy_or_network_isolation",
)
_MAX_CONTROL_BYTES = 64 * 1024
_OBSERVATION_FIELDS = {
    "attempt_nonce_sha256",
    "request_count",
    "response_bytes",
    "budget_enforced",
    "limit_exceeded",
}


@dataclass(frozen=True, slots=True)
class NetworkBoundary:
    """One parent-applied controlled proxy bound to exact allowed origins."""

    kind: str
    allowed_origins: tuple[str, ...]
    proxy_server: str | None = None
    isolation_proof: str | None = None
    browser_profile_home: str | None = None
    observation_reader: Callable[[str], dict[str, object]] | None = None

    def __post_init__(self) -> None:
        if (
            type(self.allowed_origins) is not tuple
            or not self.allowed_origins
            or any(not _origin_is_valid(value) for value in self.allowed_origins)
            or len(set(self.allowed_origins)) != len(self.allowed_origins)
        ):
            raise ToolRegistryError("isolated_runtime.boundary_invalid")
        if (
            self.kind != "controlled_proxy"
            or not _proxy_is_valid(self.proxy_server)
            or self.isolation_proof is not None
            or not _profile_home_is_valid(self.browser_profile_home)
        ):
            raise ToolRegistryError("isolated_runtime.boundary_invalid")

    def binding_payload(
        self,
        authorization_window: str,
        tool_input: AcquisitionInput | None = None,
        *,
        attempt_nonce: str | None = None,
    ) -> dict[str, object]:
        """Return inert Adapter input; the raw authorization value is never sent."""
        if not _authorization_is_valid(authorization_window):
            raise ToolRegistryError("isolated_runtime.authorization_required")
        payload: dict[str, object] = {
            "schema_version": _BOUNDARY_SCHEMA,
            "authorization_window_id": hashlib.sha256(
                authorization_window.encode("utf-8")
            ).hexdigest(),
            "kind": self.kind,
            "allowed_origins": list(self.allowed_origins),
            "proxy_server": self.proxy_server,
            "browser_profile_home": self.browser_profile_home,
        }
        if tool_input is not None:
            if not _nonce_is_valid(attempt_nonce):
                raise ToolRegistryError("isolated_runtime.attempt_nonce_invalid")
            budgets = tool_input.request.budgets
            payload.update(
                target_url=tool_input.target_url,
                attempt_nonce=attempt_nonce,
                attempt_directory=".",
                limits={
                    "max_requests": budgets.max_requests,
                    "max_response_bytes": budgets.max_bytes,
                    "max_output_bytes": budgets.max_bytes,
                    "max_runtime_seconds": budgets.max_runtime_seconds,
                    "max_redirects": max(0, budgets.max_requests - 1),
                },
            )
        return payload


@dataclass(frozen=True, slots=True)
class IsolationEvidence:
    """Sanitized parent-side evidence for the most recent attempted binding."""

    target_url: str | None
    allowed_origins: tuple[str, ...]
    boundary_kind: str | None
    adapter_invoked: bool
    preflight_closed: bool
    fetch_closed: bool
    cleanup_complete: bool
    exit_code: int | str | None
    error_code: str | None


@dataclass(frozen=True, slots=True)
class IsolationQualification:
    """One exact binding's qualification result and standard Tool result."""

    qualified: bool
    manifest: ToolManifest
    checks: tuple[tuple[str, bool], ...]
    result: AcquisitionOutput | AcquisitionFailure
    failure_code: str | None
    binding_sha256: str | None


class IsolatedRuntime:
    """Qualify and invoke one external Acquisition command under one boundary."""

    def __init__(
        self,
        manifest: ToolManifest,
        command: tuple[str, ...],
        authorization_window: str | None,
        boundary: NetworkBoundary | None,
        *,
        tool_directory: str | Path,
        state_reader: Callable[[], object] | None = None,
    ) -> None:
        if type(manifest) is not ToolManifest or (
            manifest.category is not ToolCategory.ACQUISITION
        ):
            raise ToolRegistryError("isolated_runtime.manifest_invalid")
        if (
            type(command) is not tuple
            or not command
            or any(type(item) is not str or not item for item in command)
        ):
            raise ToolRegistryError("isolated_runtime.command_invalid")
        if authorization_window is not None and type(authorization_window) is not str:
            raise ToolRegistryError("isolated_runtime.authorization_required")
        if boundary is not None and type(boundary) is not NetworkBoundary:
            raise ToolRegistryError("isolated_runtime.boundary_invalid")
        self._tool_directory = _require_tool_directory(tool_directory)
        self._installed_manifest = manifest
        self._manifest = manifest
        self._command = command
        self._authorization = authorization_window
        self._boundary = boundary
        self._state_reader = state_reader
        self._qualified_binding: str | None = None
        self._last_evidence = IsolationEvidence(
            target_url=None,
            allowed_origins=(),
            boundary_kind=None,
            adapter_invoked=False,
            preflight_closed=False,
            fetch_closed=False,
            cleanup_complete=False,
            exit_code=None,
            error_code=None,
        )

    @property
    def manifest(self) -> ToolManifest:
        """Return the current scope-bound view; initially it is unqualified."""
        return self._manifest

    @property
    def last_evidence(self) -> IsolationEvidence:
        """Return sanitized evidence for the most recent qualify/invoke call."""
        return self._last_evidence

    def qualify(self, tool_input: AcquisitionInput) -> IsolationQualification:
        """Qualify only the exact authorized input/boundary and retain its result."""
        tool_input = _require_input(tool_input)
        checks = dict.fromkeys(_REQUIRED_CHECKS, False)
        self._begin_evidence(tool_input)
        rejected = self._preflight_rejection(tool_input)
        if rejected is not None:
            return self._failed_qualification(rejected, adapter=False, checks=checks)
        checks["controlled_proxy_or_network_isolation"] = True
        attempt_nonce = secrets.token_hex(32)
        payload = self._binding_payload(tool_input, attempt_nonce)
        binding_sha256 = _binding_sha256(payload)
        command = self._bound_command(payload)
        describe = self._run_control(command, "describe", ())
        if describe != {
            "protocol_version": _QUALIFICATION_PROTOCOL,
            "operation": "describe",
            "status": "ok",
            "tool_id": self._installed_manifest.tool_id,
            "version": self._installed_manifest.version,
            "category": "acquisition",
        }:
            return self._failed_qualification(
                "isolated_runtime.describe_failed",
                adapter=True,
                checks=checks,
            )
        checks["protocol"] = True
        health = self._run_control(command, "health", ())
        if health != {
            "protocol_version": _QUALIFICATION_PROTOCOL,
            "operation": "health",
            "status": "ok",
            "health": "healthy",
        }:
            self._manifest = replace(
                self._installed_manifest, health=HealthStatus.UNHEALTHY
            )
            return self._failed_qualification(
                "isolated_runtime.health_failed",
                adapter=True,
                checks=checks,
            )
        checks["health"] = True
        self._last_evidence = replace(
            self._last_evidence, adapter_invoked=True, preflight_closed=True
        )
        probe = self._run_control(command, "probe", _REQUIRED_CHECKS)
        if probe != {
            "protocol_version": _QUALIFICATION_PROTOCOL,
            "operation": "probe",
            "status": "ok",
            "result": "qualified",
            "category": "acquisition",
            "checks": list(_REQUIRED_CHECKS),
        }:
            return self._failed_qualification(
                "isolated_runtime.probe_failed",
                adapter=True,
                checks=checks,
            )
        result = SubprocessRunner(self._installed_manifest, command).invoke(tool_input)
        self._record_result(tool_input, result)
        if type(result) is not AcquisitionOutput:
            assert isinstance(result, AcquisitionFailure)
            observation_failure = self._observation_failure(
                attempt_nonce, tool_input, require_observation=False
            )
            if observation_failure in {
                "isolated_runtime.proxy_request_limit",
                "isolated_runtime.proxy_response_limit",
            }:
                result = AcquisitionFailure(
                    self._installed_manifest.tool_id,
                    self._installed_manifest.version,
                    observation_failure,
                )
            return self._failed_qualification(
                result.code,
                adapter=True,
                result=result,
                binding_sha256=binding_sha256,
                checks=checks,
            )
        observation_failure = self._observation_failure(
            attempt_nonce, tool_input, require_observation=True
        )
        if observation_failure is not None:
            failure = AcquisitionFailure(
                self._installed_manifest.tool_id,
                self._installed_manifest.version,
                observation_failure,
            )
            return self._failed_qualification(
                observation_failure,
                adapter=True,
                result=failure,
                binding_sha256=binding_sha256,
                checks=checks,
            )
        for name in ("scope", "redirect", "output_bound"):
            checks[name] = True
        self._qualified_binding = binding_sha256
        self._manifest = replace(
            self._installed_manifest,
            health=HealthStatus.HEALTHY,
            qualification=QualificationStatus.QUALIFIED,
        )
        return IsolationQualification(
            True,
            self._manifest,
            tuple(checks.items()),
            result,
            None,
            binding_sha256,
        )

    def invoke(
        self, tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        """Invoke only after the same exact boundary binding qualified."""
        tool_input = _require_input(tool_input)
        rejected = self._preflight_rejection(tool_input)
        if rejected is not None:
            return self._failure(rejected, tool_input, adapter=False)
        attempt_nonce = secrets.token_hex(32)
        payload = self._binding_payload(tool_input, attempt_nonce)
        if (
            self._manifest.qualification is not QualificationStatus.QUALIFIED
            or self._qualified_binding != _binding_sha256(payload)
        ):
            return self._failure(
                "isolated_runtime.qualification_required", tool_input, adapter=False
            )
        result = SubprocessRunner(
            self._installed_manifest, self._bound_command(payload)
        ).invoke(tool_input)
        self._record_result(tool_input, result)
        if isinstance(result, AcquisitionOutput):
            observation_failure = self._observation_failure(
                attempt_nonce, tool_input, require_observation=True
            )
            if observation_failure is not None:
                return self._failure(observation_failure, tool_input, adapter=True)
        return result

    def _preflight_rejection(self, tool_input: AcquisitionInput) -> str | None:
        if not _authorization_is_valid(self._authorization):
            return "isolated_runtime.authorization_required"
        if self._boundary is None:
            return "isolated_runtime.network_unrestricted"
        if not callable(self._boundary.observation_reader):
            return "isolated_runtime.proxy_observation_required"
        if self._boundary.allowed_origins != tool_input.request.scope.allowed_origins:
            return "isolated_runtime.scope_mismatch"
        if self._state_reader is not None:
            try:
                state = self._state_reader()
                if bool(getattr(state, "disabled")):
                    return "isolated_runtime.disabled"
                if bool(getattr(state, "broken")):
                    return "isolated_runtime.broken"
            except (AttributeError, OSError, ToolRegistryError):
                return "isolated_runtime.state_invalid"
        return None

    def _binding_payload(
        self, tool_input: AcquisitionInput, attempt_nonce: str
    ) -> dict[str, object]:
        assert self._boundary is not None
        assert self._authorization is not None
        return self._boundary.binding_payload(
            self._authorization, tool_input, attempt_nonce=attempt_nonce
        )

    def _bound_command(self, payload: dict[str, object]) -> tuple[str, ...]:
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        return self._command + ("--web-listening-boundary", encoded)

    def _run_control(
        self, command: tuple[str, ...], operation: str, checks: tuple[str, ...]
    ) -> object:
        request: dict[str, object] = {
            "protocol_version": _QUALIFICATION_PROTOCOL,
            "operation": operation,
            "tool_id": self._installed_manifest.tool_id,
            "version": self._installed_manifest.version,
            "category": "acquisition",
        }
        if operation == "probe":
            request["checks"] = list(checks)
        try:
            completed = subprocess.run(  # pylint: disable=subprocess-run-check
                command,
                input=json.dumps(request, separators=(",", ":")).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self._tool_directory,
                env=_minimal_environment(),
                timeout=self._installed_manifest.limits.max_runtime_seconds,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if completed.returncode != 0 or len(completed.stdout) > _MAX_CONTROL_BYTES:
            return None
        try:
            return json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    def _failed_qualification(
        self,
        code: str,
        *,
        adapter: bool,
        checks: dict[str, bool],
        result: AcquisitionFailure | None = None,
        binding_sha256: str | None = None,
    ) -> IsolationQualification:
        failure = result or AcquisitionFailure(
            self._installed_manifest.tool_id, self._installed_manifest.version, code
        )
        if result is None:
            self._last_evidence = replace(
                self._last_evidence,
                adapter_invoked=adapter,
                exit_code=None if not adapter else code,
                error_code=code,
            )
        self._qualified_binding = None
        if code != "isolated_runtime.health_failed":
            self._manifest = self._installed_manifest
        return IsolationQualification(
            False,
            self._manifest,
            tuple(checks.items()),
            failure,
            code,
            binding_sha256,
        )

    def _failure(
        self, code: str, tool_input: AcquisitionInput, *, adapter: bool
    ) -> AcquisitionFailure:
        failure = AcquisitionFailure(
            self._installed_manifest.tool_id, self._installed_manifest.version, code
        )
        self._last_evidence = replace(
            self._last_evidence,
            target_url=tool_input.target_url,
            allowed_origins=tool_input.request.scope.allowed_origins,
            boundary_kind=None if self._boundary is None else self._boundary.kind,
            adapter_invoked=adapter,
            fetch_closed=False,
            cleanup_complete=False,
            exit_code=None if not adapter else code,
            error_code=code,
        )
        return failure

    def _begin_evidence(self, tool_input: AcquisitionInput) -> None:
        self._last_evidence = IsolationEvidence(
            target_url=tool_input.target_url,
            allowed_origins=tool_input.request.scope.allowed_origins,
            boundary_kind=None if self._boundary is None else self._boundary.kind,
            adapter_invoked=False,
            preflight_closed=False,
            fetch_closed=False,
            cleanup_complete=False,
            exit_code=None,
            error_code=None,
        )

    def _observation_failure(
        self,
        attempt_nonce: str,
        tool_input: AcquisitionInput,
        *,
        require_observation: bool,
    ) -> str | None:
        assert self._boundary is not None
        reader = self._boundary.observation_reader
        assert reader is not None
        expected_nonce = hashlib.sha256(attempt_nonce.encode("ascii")).hexdigest()
        try:
            observation = reader(expected_nonce)
        except (OSError, RuntimeError, ValueError, ToolRegistryError):
            return (
                "isolated_runtime.proxy_observation_failed"
                if require_observation
                else None
            )
        if type(observation) is not dict or set(observation) != _OBSERVATION_FIELDS:
            return (
                "isolated_runtime.proxy_observation_failed"
                if require_observation
                else None
            )
        requests = observation["request_count"]
        response_bytes = observation["response_bytes"]
        valid = (
            observation["attempt_nonce_sha256"] == expected_nonce
            and type(requests) is int
            and type(response_bytes) is int
            and observation["budget_enforced"] is True
            and type(observation["limit_exceeded"]) is bool
            and requests >= 0
            and response_bytes >= 0
        )
        if not valid:
            return (
                "isolated_runtime.proxy_observation_failed"
                if require_observation
                else None
            )
        budgets = tool_input.request.budgets
        if requests > budgets.max_requests:
            return "isolated_runtime.proxy_request_limit"
        if response_bytes > budgets.max_bytes or observation["limit_exceeded"]:
            return "isolated_runtime.proxy_response_limit"
        if require_observation and requests == 0:
            return "isolated_runtime.proxy_observation_failed"
        return None

    def _record_result(
        self,
        tool_input: AcquisitionInput,
        result: AcquisitionOutput | AcquisitionFailure,
    ) -> None:
        code = result.code if isinstance(result, AcquisitionFailure) else None
        runner_failure = code is not None and code.startswith("runner.")
        self._last_evidence = replace(
            self._last_evidence,
            target_url=tool_input.target_url,
            allowed_origins=tool_input.request.scope.allowed_origins,
            boundary_kind=None if self._boundary is None else self._boundary.kind,
            adapter_invoked=True,
            fetch_closed=isinstance(result, AcquisitionOutput),
            cleanup_complete=code != "runner.cleanup_error",
            exit_code=code if runner_failure else 0,
            error_code=code,
        )


def _require_input(value: AcquisitionInput) -> AcquisitionInput:
    if type(value) is not AcquisitionInput:
        raise ToolRegistryError("isolated_runtime.input_invalid")
    return value


def _require_tool_directory(value: object) -> Path:
    if not isinstance(value, (str, Path)):
        raise ToolRegistryError("isolated_runtime.tool_directory_invalid")
    try:
        candidate = Path(value)
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ToolRegistryError("isolated_runtime.tool_directory_invalid") from exc
    if not candidate.is_absolute() or not resolved.is_dir():
        raise ToolRegistryError("isolated_runtime.tool_directory_invalid")
    return resolved


def _authorization_is_valid(value: object) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 512


def _nonce_is_valid(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _origin_is_valid(value: object) -> bool:
    if type(value) is not str:
        return False
    parsed = urlsplit(value)
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
        and parsed.path == ""
        and not parsed.query
        and not parsed.fragment
    )


def _proxy_is_valid(value: object) -> bool:
    if type(value) is not str or len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https", "socks5", "socks5h"}
        and parsed.hostname is not None
        and port != 0
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
    )


def _profile_home_is_valid(value: object) -> bool:
    if type(value) is not str or not value or len(value) > 4096 or "\x00" in value:
        return False
    candidate = Path(value)
    return (
        candidate.is_absolute()
        and candidate.parent != candidate
        and candidate.as_posix() != "/root"
        and str(candidate) == value
    )


def _payload_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _binding_sha256(payload: dict[str, object]) -> str:
    binding = dict(payload)
    binding.pop("attempt_nonce", None)
    return _payload_sha256(binding)


def _minimal_environment() -> dict[str, str]:
    environment = {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    for name in ("PATH", "SystemRoot", "WINDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


__all__ = [
    "IsolatedRuntime",
    "IsolationEvidence",
    "IsolationQualification",
    "NetworkBoundary",
]
