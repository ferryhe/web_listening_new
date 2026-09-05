"""Focused server configuration, token, lock, and readiness tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from web_listening.interfaces.server import (
    DataRootLock,
    ServerConfig,
    build_app,
    load_token_file,
)
from web_listening.runtime.jobs import JobRepository


def token_file(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "caller_id": "alice",
                "token_sha256": hashlib.sha256(b"secret").hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def test_token_file_is_exact_owner_only_regular(tmp_path: Path) -> None:
    path = token_file(tmp_path / "token.json")
    assert load_token_file(path)[0] == "alice"
    path.chmod(0o644)
    with pytest.raises(ValueError, match="token.permissions_invalid"):
        load_token_file(path)


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b'{"caller_id":"alice"}',
        b'{"caller_id":"alice","token_sha256":"' + b"a" * 64 + b'","extra":1}',
    ],
)
def test_token_file_rejects_malformed_and_extra_fields(
    tmp_path: Path, payload: bytes
) -> None:
    path = tmp_path / "token.json"
    path.write_bytes(payload)
    path.chmod(0o600)
    with pytest.raises(ValueError, match="token.format_invalid"):
        load_token_file(path)


def test_token_loader_reads_the_single_pinned_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = token_file(tmp_path / "token.json")
    replacement = token_file(tmp_path / "replacement.json")
    original_open = os.open

    def replace_after_open(target, flags, *args):
        descriptor = original_open(target, flags, *args)
        if Path(target) == path:
            path.unlink()
            path.symlink_to(replacement)
        return descriptor

    monkeypatch.setattr(os, "open", replace_after_open)
    assert load_token_file(path)[0] == "alice"


def test_data_root_lock_is_exclusive(tmp_path: Path) -> None:
    first = DataRootLock(tmp_path / "data")
    try:
        with pytest.raises(RuntimeError, match="server.data_root_locked"):
            DataRootLock(tmp_path / "data")
    finally:
        first.close()


def test_config_bounds_worker_and_server_starts_ready(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="worker.concurrency_invalid"):
        ServerConfig(tmp_path / "data", tmp_path / "token", concurrency=33)
    config = ServerConfig(tmp_path / "data", token_file(tmp_path / "token.json"))
    with TestClient(build_app(config)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 200
    assert oct(os.stat(config.token_file).st_mode & 0o777) == "0o600"


@pytest.mark.parametrize(
    "override",
    [
        {"max_requests": 101},
        {"max_bytes": 100 * 1024 * 1024 + 1},
        {"max_runtime_seconds": 601},
        {"max_attempts": 5},
    ],
)
def test_server_rejects_admission_authority_above_fixed_ceiling(
    tmp_path: Path, override: dict[str, int]
) -> None:
    with pytest.raises(ValueError, match="server.admission_invalid"):
        ServerConfig(tmp_path / "data", tmp_path / "token", **override)


def test_server_accepts_exact_admission_ceiling(tmp_path: Path) -> None:
    config = ServerConfig(
        tmp_path / "data",
        tmp_path / "token",
        max_requests=100,
        max_bytes=100 * 1024 * 1024,
        max_runtime_seconds=600,
        max_attempts=4,
    )
    assert config.max_requests == 100


def test_ready_fails_closed_after_worker_repository_claim_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_claim(*_args, **_kwargs):
        raise RuntimeError("repository failed")

    monkeypatch.setattr(JobRepository, "claim_next", fail_claim)
    config = ServerConfig(tmp_path / "data", token_file(tmp_path / "token.json"))
    with TestClient(build_app(config)) as client:
        for _unused in range(100):
            if client.get("/ready").status_code == 503:
                break
        assert client.get("/ready").status_code == 503
