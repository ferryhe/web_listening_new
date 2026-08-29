"""One-attempt JSON boundary for explicitly configured external tools."""

# pylint: disable=duplicate-code,too-few-public-methods,unidiomatic-typecheck

from __future__ import annotations

import base64
import hashlib
import json
import math
import numbers
import os
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO
from urllib.parse import urlsplit

from web_listening.request.model import ContentType
from web_listening.request.validate import compile_access_policy
from web_listening.tool_registry.manifest import (
    ToolCategory,
    ToolManifest,
    ToolRegistryError,
    validate_safe_code,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
    AcquisitionRedirect,
    validate_mime_type,
    validate_runtime,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryCoverage,
    DiscoveryFailure,
    DiscoveryInput,
    DiscoveryOutput,
)
from web_listening.tool_registry.protocols.transform import (
    TransformFailure,
    TransformInput,
    TransformOutput,
)

_PROTOCOL_VERSION = "web-listening-external-tool.v1"
_MIME_BY_SUFFIX = {
    ".htm": "text/html",
    ".html": "text/html",
    ".json": "application/json",
    ".md": "text/markdown",
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".xml": "application/xml",
}

ToolInput = DiscoveryInput | AcquisitionInput | TransformInput
ToolResult = (
    DiscoveryOutput
    | DiscoveryFailure
    | AcquisitionOutput
    | AcquisitionFailure
    | TransformOutput
    | TransformFailure
)


@dataclass(frozen=True, slots=True)
class SubprocessLimits:
    """Local process and control-stream limits for one external attempt."""

    timeout_seconds: float = 30.0
    stdout_bytes: int = 64 * 1024
    stderr_bytes: int = 64 * 1024
    terminate_grace_seconds: float = 1.0

    def __post_init__(self) -> None:
        time_values = (self.timeout_seconds, self.terminate_grace_seconds)
        if any(
            isinstance(value, bool)
            or not isinstance(value, numbers.Real)
            or not math.isfinite(value)
            or value <= 0
            for value in time_values
        ):
            raise ToolRegistryError("runner.limits_invalid")
        if any(
            type(value) is not int or value <= 0
            for value in (self.stdout_bytes, self.stderr_bytes)
        ):
            raise ToolRegistryError("runner.limits_invalid")


class _BoundedReader(threading.Thread):
    def __init__(self, pipe: BinaryIO, limit: int) -> None:
        super().__init__(daemon=True)
        self._pipe = pipe
        self._limit = limit
        self.data = bytearray()
        self.exceeded = threading.Event()

    def run(self) -> None:
        try:
            while True:
                chunk = self._pipe.read(
                    min(64 * 1024, self._limit + 1 - len(self.data))
                )
                if not chunk:
                    return
                self.data.extend(chunk)
                if len(self.data) > self._limit:
                    self.exceeded.set()
                    return
        finally:
            self._pipe.close()


class _StdinWriter(threading.Thread):
    def __init__(self, pipe: BinaryIO, data: bytes) -> None:
        super().__init__(daemon=True)
        self._pipe = pipe
        self._data = data

    def run(self) -> None:
        try:
            self._pipe.write(self._data)
            self._pipe.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                self._pipe.close()
            except OSError:
                pass


class SubprocessRunner:
    """Run one configured command without Registry, Runtime, or storage authority.

    The runner constrains the protocol and attempt workspace. It is deliberately
    not a general operating-system sandbox or an installer.
    """

    def __init__(
        self,
        manifest: ToolManifest,
        command: tuple[str, ...],
        *,
        limits: SubprocessLimits | None = None,
    ) -> None:
        if type(manifest) is not ToolManifest:
            raise ToolRegistryError("runner.manifest_invalid")
        if (
            type(command) is not tuple
            or not command
            or any(type(item) is not str or not item for item in command)
        ):
            raise ToolRegistryError("runner.command_invalid")
        self._manifest = manifest
        self._command = command
        self._limits = limits or SubprocessLimits(
            timeout_seconds=float(manifest.limits.max_runtime_seconds)
        )

    def invoke(  # pylint: disable=too-many-return-statements
        self, tool_input: ToolInput
    ) -> ToolResult:
        """Return a rebuilt Phase 5 output or stable category failure."""
        if _input_category(tool_input) is not self._manifest.category:
            return _failure(self._manifest, "runner.input_mismatch")
        if _input_bytes(tool_input) > self._manifest.limits.max_input_bytes:
            return _failure(self._manifest, "runner.input_limit")
        runtime_seconds = min(
            self._limits.timeout_seconds,
            float(self._manifest.limits.max_runtime_seconds),
        )
        acquisition_output_bytes = self._manifest.limits.max_output_bytes
        if type(tool_input) is AcquisitionInput:
            runtime_seconds, acquisition_output_bytes = _effective_acquisition_limits(
                self._manifest, self._limits, tool_input
            )
        wire = _encode_request(
            self._manifest,
            tool_input,
            acquisition_runtime_seconds=runtime_seconds,
            acquisition_output_bytes=acquisition_output_bytes,
        )
        started = time.monotonic()
        attempt_directory_ready = False
        try:
            with tempfile.TemporaryDirectory(prefix="web-listening-attempt-") as name:
                attempt_directory_ready = True
                attempt_directory = Path(name)
                process_code, stdout = self._execute(
                    wire, attempt_directory, started, runtime_seconds
                )
                runtime_ms = max(0, round((time.monotonic() - started) * 1000))
                if process_code is None and runtime_ms > runtime_seconds * 1000:
                    process_code = "runner.timeout"
                if process_code is not None:
                    return _failure(self._manifest, process_code)
                try:
                    return _decode_response(
                        self._manifest,
                        tool_input,
                        stdout,
                        attempt_directory,
                        runtime_ms,
                        acquisition_output_bytes,
                    )
                except ToolRegistryError as exc:
                    code = (
                        exc.code
                        if exc.code.startswith("runner.")
                        else "runner.output_mismatch"
                    )
                    return _failure(self._manifest, code)
                except Exception:  # pylint: disable=broad-exception-caught
                    return _failure(self._manifest, "runner.protocol_error")
        except OSError:
            code = (
                "runner.cleanup_error"
                if attempt_directory_ready
                else "runner.startup_error"
            )
            return _failure(self._manifest, code)

    def _execute(
        self,
        wire: bytes,
        attempt_directory: Path,
        started: float,
        runtime_seconds: float,
    ) -> tuple[str | None, bytes]:
        try:
            process = subprocess.Popen(  # pylint: disable=consider-using-with
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=attempt_directory,
                env=_minimal_environment(),
            )
        except (OSError, ValueError):
            return "runner.startup_error", b""
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        stdout = _BoundedReader(process.stdout, self._limits.stdout_bytes)
        stderr = _BoundedReader(process.stderr, self._limits.stderr_bytes)
        stdin = _StdinWriter(process.stdin, wire)
        workers = (stdout, stderr, stdin)
        for worker in workers:
            worker.start()
        code: str | None = None
        deadline = started + runtime_seconds
        while process.poll() is None or any(worker.is_alive() for worker in workers):
            if stdout.exceeded.is_set():
                code = "runner.stdout_limit"
                break
            if stderr.exceeded.is_set():
                code = "runner.stderr_limit"
                break
            if time.monotonic() >= deadline:
                code = "runner.timeout"
                break
            time.sleep(0.005)
        if code is not None or process.poll() is None:
            _terminate(process, self._limits.terminate_grace_seconds)
        for worker in workers:
            worker.join(self._limits.terminate_grace_seconds)
        if stdout.exceeded.is_set():
            code = code or "runner.stdout_limit"
        if stderr.exceeded.is_set():
            code = code or "runner.stderr_limit"
        if code is not None:
            return code, b""
        if process.returncode:
            return "runner.nonzero_exit", b""
        return None, bytes(stdout.data)


def _minimal_environment() -> dict[str, str]:
    environment = {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    for name in ("PATH", "SystemRoot", "WINDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _terminate(process: subprocess.Popen[bytes], grace_seconds: float) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=grace_seconds)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
            process.wait(timeout=grace_seconds)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _input_category(tool_input: object) -> ToolCategory | None:
    if type(tool_input) is DiscoveryInput:
        return ToolCategory.DISCOVERY
    if type(tool_input) is AcquisitionInput:
        return ToolCategory.ACQUISITION
    if type(tool_input) is TransformInput:
        return ToolCategory.TRANSFORM
    return None


def _input_bytes(tool_input: ToolInput) -> int:
    if type(tool_input) is DiscoveryInput:
        return len(tool_input.source_body)
    if type(tool_input) is TransformInput:
        return len(tool_input.source.content)
    return 0


def _effective_acquisition_limits(
    manifest: ToolManifest,
    limits: SubprocessLimits,
    tool_input: AcquisitionInput,
) -> tuple[float, int]:
    request_limits = tool_input.request.budgets
    return (
        min(
            limits.timeout_seconds,
            float(manifest.limits.max_runtime_seconds),
            float(request_limits.max_runtime_seconds),
        ),
        min(manifest.limits.max_output_bytes, request_limits.max_bytes),
    )


def _scope_payload(scope) -> dict[str, object]:
    return {
        "seeds": list(scope.seeds),
        "allowed_origins": list(scope.allowed_origins),
        "include_paths": list(scope.include_paths),
        "content_types": [value.value for value in scope.content_types],
    }


def _encode_request(
    manifest: ToolManifest,
    tool_input: ToolInput,
    *,
    acquisition_runtime_seconds: float | None = None,
    acquisition_output_bytes: int | None = None,
) -> bytes:
    """Encode the private one-request envelope without storage authorities."""
    if type(tool_input) is DiscoveryInput:
        payload = {
            "scope": _scope_payload(tool_input.scope),
            "source_url": tool_input.source_url,
            "source_mime_type": tool_input.source_mime_type,
            "source_body_base64": base64.b64encode(tool_input.source_body).decode(
                "ascii"
            ),
        }
    elif type(tool_input) is AcquisitionInput:
        request = tool_input.request
        payload = {
            "target_url": tool_input.target_url,
            "allowed_origins": list(request.scope.allowed_origins),
            "include_paths": list(request.scope.include_paths),
            "content_types": [value.value for value in request.scope.content_types],
            "limits": {
                "max_requests": request.budgets.max_requests,
                "max_bytes": (
                    request.budgets.max_bytes
                    if acquisition_output_bytes is None
                    else acquisition_output_bytes
                ),
                "max_runtime_seconds": (
                    request.budgets.max_runtime_seconds
                    if acquisition_runtime_seconds is None
                    else acquisition_runtime_seconds
                ),
            },
        }
    elif type(tool_input) is TransformInput:
        payload = {
            "source_artifact_id": tool_input.source.artifact.artifact_id,
            "source_mime_type": tool_input.source.artifact.mime_type,
            "source_body_base64": base64.b64encode(tool_input.source.content).decode(
                "ascii"
            ),
        }
    else:
        raise ToolRegistryError("runner.input_mismatch")
    envelope = {
        "protocol_version": _PROTOCOL_VERSION,
        "category": manifest.category.value,
        "tool_id": manifest.tool_id,
        "tool_version": manifest.version,
        "attempt_directory": ".",
        "input": payload,
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode_response(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    manifest: ToolManifest,
    tool_input: ToolInput,
    stdout: bytes,
    attempt_directory: Path,
    runtime_ms: int,
    acquisition_output_bytes: int,
) -> ToolResult:
    try:
        payload = json.loads(stdout.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ToolRegistryError("runner.protocol_error") from exc
    _require_fields(
        payload,
        {
            "protocol_version",
            "category",
            "status",
            "tool_id",
            "tool_version",
            "result",
        },
    )
    if payload["protocol_version"] != _PROTOCOL_VERSION:
        raise ToolRegistryError("runner.protocol_error")
    if (
        payload["category"] != manifest.category.value
        or payload["tool_id"] != manifest.tool_id
        or payload["tool_version"] != manifest.version
    ):
        raise ToolRegistryError("runner.output_mismatch")
    result = payload["result"]
    if payload["status"] in {"failed", "rejected"}:
        _require_fields(result, {"code"})
        try:
            validate_safe_code(result["code"])
        except ToolRegistryError as exc:
            raise ToolRegistryError("runner.output_mismatch") from exc
        return _failure(manifest, result["code"])
    if payload["status"] != "success":
        raise ToolRegistryError("runner.protocol_error")
    if manifest.category is ToolCategory.DISCOVERY:
        return _decode_discovery(manifest, tool_input, result)
    if manifest.category is ToolCategory.ACQUISITION:
        return _decode_acquisition(
            manifest,
            tool_input,
            result,
            attempt_directory,
            runtime_ms,
            acquisition_output_bytes,
        )
    return _decode_transform(
        manifest, tool_input, result, attempt_directory, runtime_ms
    )


def _decode_discovery(
    manifest: ToolManifest, tool_input: ToolInput, result: object
) -> DiscoveryOutput:
    _require_fields(result, {"candidates", "discovered_from"})
    candidates = _string_tuple(result["candidates"])
    discovered_from = _string_tuple(result["discovered_from"])
    output = DiscoveryOutput(
        manifest.tool_id,
        manifest.version,
        candidates,
        discovered_from,
        DiscoveryCoverage.UNKNOWN,
    )
    if type(tool_input) is not DiscoveryInput or any(
        source != tool_input.source_url for source in output.discovered_from
    ):
        raise ToolRegistryError("runner.output_mismatch")
    output_bytes = sum(
        len(value.encode("utf-8"))
        for values in (output.candidates, output.discovered_from)
        for value in values
    )
    if output_bytes > manifest.limits.max_output_bytes:
        raise ToolRegistryError("runner.output_limit")
    return output


def _decode_acquisition(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    manifest: ToolManifest,
    tool_input: ToolInput,
    result: object,
    attempt_directory: Path,
    runtime_ms: int,
    output_bytes: int,
) -> AcquisitionOutput:
    _require_fields(
        result,
        {
            "requested_url",
            "final_url",
            "status_code",
            "mime_type",
            "output_path",
            "size_bytes",
            "sha256",
            "redirects",
            "runtime_ms",
        },
    )
    _validate_claimed_runtime(result["runtime_ms"])
    body = _read_output(attempt_directory, result["output_path"], output_bytes)
    _validate_content_claims(result, body)
    redirects = _redirects(result["redirects"])
    output = AcquisitionOutput(
        manifest.tool_id,
        manifest.version,
        result["requested_url"],
        result["final_url"],
        result["status_code"],
        result["mime_type"],
        body,
        hashlib.sha256(body).hexdigest(),
        redirects,
        runtime_ms,
    )
    if type(tool_input) is not AcquisitionInput:
        raise ToolRegistryError("runner.output_mismatch")
    if output.requested_url != tool_input.target_url:
        raise ToolRegistryError("runner.output_mismatch")
    _validate_acquisition_policy(tool_input, output)
    return output


def _decode_transform(
    manifest: ToolManifest,
    tool_input: ToolInput,
    result: object,
    attempt_directory: Path,
    runtime_ms: int,
) -> TransformOutput:
    _require_fields(
        result,
        {
            "source_artifact_id",
            "mime_type",
            "output_path",
            "size_bytes",
            "sha256",
            "runtime_ms",
        },
    )
    _validate_claimed_runtime(result["runtime_ms"])
    body = _read_output(
        attempt_directory, result["output_path"], manifest.limits.max_output_bytes
    )
    _validate_content_claims(result, body)
    output = TransformOutput(
        manifest.tool_id,
        manifest.version,
        result["source_artifact_id"],
        result["mime_type"],
        body,
        hashlib.sha256(body).hexdigest(),
        runtime_ms,
    )
    if (
        type(tool_input) is not TransformInput
        or output.source_artifact_id != tool_input.source.artifact.artifact_id
    ):
        raise ToolRegistryError("runner.output_mismatch")
    return output


def _validate_claimed_runtime(value: object) -> None:
    try:
        validate_runtime(value)  # type: ignore[arg-type]
    except ToolRegistryError as exc:
        raise ToolRegistryError("runner.output_mismatch") from exc


def _validate_content_claims(result: dict[str, object], body: bytes) -> None:
    if type(result["size_bytes"]) is not int or result["size_bytes"] != len(body):
        raise ToolRegistryError("runner.output_mismatch")
    if result["sha256"] != hashlib.sha256(body).hexdigest():
        raise ToolRegistryError("runner.output_mismatch")
    try:
        mime_type = validate_mime_type(result["mime_type"])  # type: ignore[arg-type]
    except ToolRegistryError as exc:
        raise ToolRegistryError("runner.output_mismatch") from exc
    if body.startswith(b"%PDF-") != (mime_type == "application/pdf"):
        raise ToolRegistryError("runner.output_mismatch")
    suffix = PurePosixPath(result["output_path"]).suffix.casefold()  # type: ignore[arg-type]
    expected = _MIME_BY_SUFFIX.get(suffix)
    if expected is not None and mime_type != expected:
        raise ToolRegistryError("runner.output_mismatch")


def _read_output(root: Path, value: object, limit: int) -> bytes:
    if type(value) is not str or not value or "\\" in value:
        raise ToolRegistryError("runner.output_path_invalid")
    relative = PurePosixPath(value)
    windows_relative = PureWindowsPath(value)
    if (
        windows_relative.drive
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ToolRegistryError("runner.output_path_invalid")
    root_before = root.resolve(strict=True)
    candidate = root.joinpath(*relative.parts)
    _reject_symlink_components(root, candidate)
    try:
        resolved_before = candidate.resolve(strict=True)
    except OSError as exc:
        raise ToolRegistryError("runner.output_path_invalid") from exc
    if not resolved_before.is_relative_to(root_before) or not candidate.is_file():
        raise ToolRegistryError("runner.output_path_invalid")
    try:
        with candidate.open("rb") as stream:
            body = stream.read(limit + 1)
    except OSError as exc:
        raise ToolRegistryError("runner.output_path_invalid") from exc
    if len(body) > limit:
        raise ToolRegistryError("runner.output_limit")
    _reject_symlink_components(root, candidate)
    try:
        root_after = root.resolve(strict=True)
        resolved_after = candidate.resolve(strict=True)
    except OSError as exc:
        raise ToolRegistryError("runner.output_path_invalid") from exc
    if (
        root_after != root_before
        or resolved_after != resolved_before
        or not resolved_after.is_relative_to(root_after)
    ):
        raise ToolRegistryError("runner.output_path_invalid")
    return body


def _reject_symlink_components(root: Path, candidate: Path) -> None:
    current = root
    for part in candidate.relative_to(root).parts:
        current /= part
        try:
            if current.is_symlink() or current.is_junction():
                raise ToolRegistryError("runner.output_path_invalid")
        except OSError as exc:
            raise ToolRegistryError("runner.output_path_invalid") from exc


def _redirects(value: object) -> tuple[AcquisitionRedirect, ...]:
    if type(value) is not list:
        raise ToolRegistryError("runner.output_mismatch")
    redirects = []
    for item in value:
        _require_fields(item, {"from_url", "to_url", "status_code"})
        redirects.append(
            AcquisitionRedirect(item["from_url"], item["to_url"], item["status_code"])
        )
    return tuple(redirects)


def _validate_acquisition_policy(
    tool_input: AcquisitionInput, output: AcquisitionOutput
) -> None:
    policy = compile_access_policy(tool_input.request)
    for redirect in output.redirects:
        if (
            urlsplit(redirect.from_url).scheme == "https"
            and urlsplit(redirect.to_url).scheme == "http"
        ):
            raise ToolRegistryError("runner.output_mismatch")
    urls = (
        output.requested_url,
        *(
            url
            for redirect in output.redirects
            for url in (redirect.from_url, redirect.to_url)
        ),
        output.final_url,
    )
    if any(not policy.decide_url(url).allowed for url in urls):
        raise ToolRegistryError("runner.output_mismatch")
    content_type = (
        ContentType.HTML if output.mime_type == "text/html" else ContentType.FILE
    )
    if not policy.decide_content_type(content_type).allowed:
        raise ToolRegistryError("runner.output_mismatch")
    for name, amount in (
        ("max_requests", len(output.redirects) + 1),
        ("max_bytes", len(output.body)),
        ("max_runtime_seconds", (output.runtime_ms + 999) // 1000),
    ):
        if not policy.decide_budget(name, amount).allowed:
            raise ToolRegistryError("runner.output_mismatch")


def _failure(manifest: ToolManifest, code: str) -> ToolResult:
    if manifest.category is ToolCategory.DISCOVERY:
        return DiscoveryFailure(manifest.tool_id, manifest.version, code)
    if manifest.category is ToolCategory.ACQUISITION:
        return AcquisitionFailure(manifest.tool_id, manifest.version, code)
    return TransformFailure(manifest.tool_id, manifest.version, code)


def _require_fields(value: object, expected: set[str]) -> None:
    if type(value) is not dict or set(value) != expected:
        raise ToolRegistryError("runner.protocol_error")


def _string_tuple(value: object) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise ToolRegistryError("runner.output_mismatch")
    return tuple(value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


__all__ = ["SubprocessLimits", "SubprocessRunner"]
