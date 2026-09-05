"""Single-process Uvicorn composition for the authenticated REST service."""

# pylint: disable=too-many-instance-attributes,too-few-public-methods
# pylint: disable=broad-exception-caught,import-outside-toplevel

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI

from web_listening.interfaces.rest import RestConfig, create_app
from web_listening.request.model import Budgets
from web_listening.runtime.acquisition_service import AcquisitionService
from web_listening.runtime.service import RuntimeService

_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class ServerConfig:
    """Explicit server authority and transport settings."""

    data_root: Path
    token_file: Path
    host: str = "127.0.0.1"
    port: int = 8000
    concurrency: int = 2
    max_requests: int = 100
    max_bytes: int = 100 * 1024 * 1024
    max_runtime_seconds: int = 600
    max_attempts: int = 4
    binary_cap_bytes: int = 100 * 1024 * 1024
    base64_cap_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if not 1 <= self.concurrency <= 32:
            raise ValueError("worker.concurrency_invalid")
        if not 1 <= self.port <= 65535:
            raise ValueError("server.port_invalid")
        Budgets(
            self.max_requests,
            self.max_bytes,
            self.max_runtime_seconds,
            self.max_attempts,
        )
        if (
            self.max_requests > 100
            or self.max_bytes > 100 * 1024 * 1024
            or self.max_runtime_seconds > 600
            or self.max_attempts > 4
        ):
            raise ValueError("server.admission_invalid")
        if self.binary_cap_bytes <= 0 or self.base64_cap_bytes <= 0:
            raise ValueError("server.cap_invalid")


def write_token_file(path: Path, caller_id: str) -> str:
    """Generate a high-entropy opaque token and its owner-only digest file."""
    token = secrets.token_urlsafe(48)
    payload = {
        "caller_id": caller_id,
        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
    }
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, separators=(",", ":"))
        stream.write("\n")
    return token


def load_token_file(path: Path) -> tuple[str, str]:
    """Load an exact owner-only, regular, non-symlink token digest file."""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ValueError("token.path_invalid") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024:
            raise ValueError("token.path_invalid")
        if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid():
            raise ValueError("token.permissions_invalid")
        content = b""
        while len(content) <= 16 * 1024:
            chunk = os.read(descriptor, min(4096, 16 * 1024 + 1 - len(content)))
            if not chunk:
                break
            content += chunk
        if len(content) > 16 * 1024:
            raise ValueError("token.path_invalid")
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("token.format_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {"caller_id", "token_sha256"}:
        raise ValueError("token.format_invalid")
    caller_id, digest = payload["caller_id"], payload["token_sha256"]
    if not isinstance(caller_id, str) or not caller_id or len(caller_id) > 256:
        raise ValueError("token.caller_invalid")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise ValueError("token.digest_invalid")
    return caller_id, digest


class DataRootLock:
    """Exclusive process-lifetime lock for one canonical data root."""

    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        path = root / ".server.lock"
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise RuntimeError("server.lock_invalid")
        self._stream = os.fdopen(descriptor, "a+", encoding="ascii")
        try:
            fcntl.flock(self._stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._stream.close()
            raise RuntimeError("server.data_root_locked") from exc

    def close(self) -> None:
        """Release the process lock and descriptor."""
        fcntl.flock(self._stream, fcntl.LOCK_UN)
        self._stream.close()


def build_app(config: ServerConfig) -> FastAPI:
    """Compose repositories, worker, readiness, and ordered shutdown."""
    caller_id, digest = load_token_file(config.token_file)
    state: dict[str, object] = {"ready": False}

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        """Own startup readiness and ordered cooperative shutdown."""
        lock = DataRootLock(config.data_root)
        runtime = RuntimeService.open(
            config.data_root,
            admission_maxima=Budgets(
                config.max_requests,
                config.max_bytes,
                config.max_runtime_seconds,
                config.max_attempts,
            ),
        )
        worker = AcquisitionService(
            runtime,
            runtime.job_repository,
            concurrency=config.concurrency,
            clock=runtime.clock,
        )
        state.update(runtime=runtime, worker=worker, ready=True)
        worker.wake()
        try:
            yield
        finally:
            state["ready"] = False
            worker.close()
            runtime.close()
            lock.close()

    def runtime_provider() -> RuntimeService:
        runtime = state.get("runtime")
        if not isinstance(runtime, RuntimeService):
            raise RuntimeError("server.starting")
        return runtime

    def is_ready() -> bool:
        worker = state.get("worker")
        if not state["ready"] or worker is None or not worker.healthy:
            return False
        try:
            runtime_provider().repository_check()
            return True
        except Exception:
            return False

    def wake() -> None:
        """Wake the started worker without exposing composition state to REST."""
        worker = state.get("worker")
        if not isinstance(worker, AcquisitionService):
            raise RuntimeError("server.starting")
        worker.wake()

    app = create_app(
        runtime_provider,
        RestConfig(caller_id, digest, config.binary_cap_bytes, config.base64_cap_bytes),
        wake=wake,
        ready=is_ready,
    )
    app.router.lifespan_context = lifespan
    return app


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="web-listening-server")
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--worker-count", type=int, default=2, dest="concurrency")
    parser.add_argument("--max-requests", type=int, default=100)
    parser.add_argument("--max-bytes", type=int, default=100 * 1024 * 1024)
    parser.add_argument("--max-runtime-seconds", type=int, default=600)
    parser.add_argument("--max-attempts", type=int, default=4)
    parser.add_argument("--binary-cap-bytes", type=int, default=100 * 1024 * 1024)
    parser.add_argument("--base64-cap-bytes", type=int, default=1024 * 1024)
    return parser


def main() -> None:
    """Run exactly one Uvicorn process."""
    import uvicorn

    config = ServerConfig(**vars(_parser().parse_args()))
    uvicorn.run(build_app(config), host=config.host, port=config.port, workers=1)


__all__ = [
    "DataRootLock",
    "ServerConfig",
    "build_app",
    "load_token_file",
    "main",
    "write_token_file",
]
