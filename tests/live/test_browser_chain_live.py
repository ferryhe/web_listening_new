"""Explicit real SDK/loopback and frozen public validation for Issue 102.

No fake SDK or manual Registry registration is used here. Missing engines are
BLOCKED. URLs come exclusively from the frozen fixture/public snapshots.
"""

# pylint: disable=missing-function-docstring,too-many-locals,duplicate-code
# pylint: disable=too-many-arguments

from __future__ import annotations

import hashlib
import http.client
import json
import os
import runpy
import time
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from tests.fixtures.browser_chain.server import fixture_server
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.runtime.service import RuntimeService
from web_listening.tool_registry.acquisition.quality import quality_failure_code
from web_listening.tool_registry.lifecycle import ToolLifecycle
from web_listening.tool_registry.manifest import ToolCategory
from web_listening.tool_registry.runners import in_process
from web_listening.tool_registry.runners.browser_network import BrowserNetworkBridge

pytestmark = pytest.mark.live
ROOT = Path(__file__).parents[2]
LOCK = ROOT / "tools/browser/runtime-lock.json"
TARGETS = Path(__file__).with_name("browser_chain_targets.json")
CASES = ROOT / "tests/fixtures/browser_chain/cases.json"


def environment():
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("explicit live execution is disabled")
    window = os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip()
    root = os.environ.get("WEB_LISTENING_BROWSER_DATA_DIR", "").strip()
    if not window or not root:
        pytest.fail(
            "BLOCKED: explicit authorization window and browser data directory are required"
        )
    return Path(root).resolve(), window


def request(
    url, origins, *, requests=24, size=8 * 1024 * 1024, seconds=60, explore=True
):
    return Request(
        Scope((url,), tuple(origins), ("/**",), (ContentType.HTML, ContentType.FILE)),
        None,
        explore,
        Budgets(requests, size, seconds, 3),
    )


def verify_installations(data_root):
    lock = json.loads(LOCK.read_bytes())
    active = {
        item.manifest.tool_id: item
        for item in ToolLifecycle(data_root).active_versions(ToolCategory.ACQUISITION)
    }
    for name, entry in lock["tools"].items():
        if entry["tool_id"] not in active:
            pytest.fail(f"BLOCKED: {name} is not installed and active")
        installed = active[entry["tool_id"]]
        assert installed.manifest.version == entry["adapter_version"]
        directory = Path(installed.command[-1]).parent
        for filename, digest in entry["adapter_files_sha256"].items():
            assert (
                hashlib.sha256((directory / filename).read_bytes()).hexdigest()
                == digest
            )
    return lock


def ensure_fixture_installations(data_root, origin, window, deadline):
    """Qualify absent tools against the owned fixture and count those reads."""
    install_module = runpy.run_path(str(ROOT / "tools/browser/install.py"))
    lock = json.loads(LOCK.read_bytes())
    evidence = []
    for name, entry in lock["tools"].items():
        lifecycle = ToolLifecycle(data_root)
        if lifecycle.active(ToolCategory.ACQUISITION, entry["tool_id"]) is not None:
            continue
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            pytest.fail("BLOCKED: fixture installation exhausted its shared deadline")
        req = request(
            origin + "/qualification",
            (origin,),
            requests=24 - sum(item["requests"] for item in evidence),
            size=8 * 1024 * 1024 - sum(item["bytes_received"] for item in evidence),
            seconds=remaining,
        )
        data_root.mkdir(parents=True, exist_ok=True)
        request_path = data_root / "fixture-install-request.json"
        request_path.write_text(json.dumps(asdict(req)))
        args = SimpleNamespace(
            action="install",
            tool=name,
            version=None,
            data_dir=str(data_root),
            runtime_root=str(data_root / "browser-runtimes/playwright"),
            docker="docker",
            request=str(request_path),
            authorization_window=window,
        )
        try:
            installed = install_module["install"](args)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # Explicit BLOCKED, never a successful skip.
            pytest.fail(
                f"BLOCKED: {name} runtime preparation failed ({type(exc).__name__})"
            )
        evidence.append(installed)
        assert installed["active"], installed
    verify_installations(data_root)
    return evidence


def record(data_root, name, jobs, bridges, *, setup=(), extra=None):
    directory = data_root / "browser-validation"
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "scenario": name,
        "runtime_lock_sha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
        "targets_sha256": hashlib.sha256(TARGETS.read_bytes()).hexdigest(),
        "setup": list(setup),
        "jobs": [
            {
                "job_id": job.job_id,
                "status": job.status.value,
                "submitted_at": job.submitted_at,
                "started_at": job.started_at,
                "finished_at": job.finished_at,
                "result": None if job.result is None else job.result.to_dict(),
                "failure_code": job.failure_code,
            }
            for job in jobs
        ],
        "bridges": bridges,
        "extra": extra,
        "installed_runtime": [
            json.loads(Path(item.command[-1]).with_name("runtime.json").read_bytes())
            for item in ToolLifecycle(data_root).active_versions(
                ToolCategory.ACQUISITION
            )
        ],
    }
    (directory / (name + ".json")).write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n"
    )


def observe_bridges(monkeypatch, *, probe_native=False):
    evidence = []
    original_start, original_close = (
        BrowserNetworkBridge.start,
        BrowserNetworkBridge.close,
    )

    def start(bridge):
        endpoint = original_start(bridge)
        if probe_native:
            parsed = urlsplit(endpoint)
            for method, target in (
                ("GET", "http://outside.invalid/"),
                ("CONNECT", "outside.invalid:443"),
            ):
                connection = http.client.HTTPConnection(
                    parsed.hostname, parsed.port, timeout=2
                )
                try:
                    connection.request(method, target)
                    response = connection.getresponse()
                    assert response.status == 403
                    response.read()
                    assert bridge.requests == 0
                finally:
                    connection.close()
        return endpoint

    def close(bridge):
        original_close(bridge)
        evidence.append(
            {
                "target_url": bridge.target_url,
                "requests": bridge.requests,
                "bytes_received": bridge.bytes_received,
                "native_denied": bridge.native_denied,
                "failure_code": bridge.failure_code,
                "reads": bridge.events,
                "closed": True,
            }
        )

    monkeypatch.setattr(BrowserNetworkBridge, "start", start)
    monkeypatch.setattr(BrowserNetworkBridge, "close", close)
    return evidence


@pytest.mark.parametrize(
    "case", json.loads(CASES.read_bytes())["cases"], ids=lambda item: item["name"]
)
def test_real_browser_fixture(case, monkeypatch):
    data_root, window = environment()
    started = time.monotonic()
    # The fixture alone authorizes loopback. Public tests use the unchanged
    # production network predicate; all other private addresses remain denied.
    public_address = in_process._is_public_address  # pylint: disable=protected-access
    monkeypatch.setattr(
        in_process,
        "_is_public_address",
        lambda ip: ip == "127.0.0.1" or public_address(ip),
    )
    bridges = observe_bridges(monkeypatch, probe_native=True)
    with fixture_server(robots_status=case.get("robots_status", 200)) as (
        origin,
        reads,
    ):
        setup = ensure_fixture_installations(data_root, origin, window, started + 60)
        remaining_seconds = int(started + 60 - time.monotonic())
        assert remaining_seconds > 0
        req = request(
            origin + case["path"],
            (origin,),
            requests=min(
                case.get("max_requests", 24),
                24 - sum(item["requests"] for item in setup),
            ),
            size=8 * 1024 * 1024 - sum(item["bytes_received"] for item in setup),
            seconds=remaining_seconds,
            explore=case.get("explore", True),
        )
        runtime = RuntimeService.open(data_root)
        try:
            retrieval = None
            if "operation" in case:
                if case["operation"] == "retrieve-file":
                    req = replace(
                        req, scope=replace(req.scope, content_types=(ContentType.FILE,))
                    )
                alternates = ()
                if case.get("alternate"):
                    alternates = (
                        replace(
                            req,
                            scope=replace(
                                req.scope, seeds=(origin + case["alternate"],)
                            ),
                        ),
                    )
                retrieval = (
                    runtime.retrieve_file(req)
                    if case["operation"] == "retrieve-file"
                    else runtime.retrieve(req, alternates=alternates)
                )
                case_jobs = tuple(
                    runtime.get_job(j["job_id"]) for j in retrieval["jobs"]
                )
                job = case_jobs[-1]
            else:
                job = runtime.run(req)
                case_jobs = (job,)
            record(
                data_root,
                "fixture-" + case["name"],
                case_jobs,
                bridges,
                setup=setup,
                extra={"server_reads": reads, "retrieval": retrieval},
            )
            result = job.result
            tools = [
                item.tool_id
                for case_job in case_jobs
                for item in case_job.result.attempts
                if item.tool_id.startswith("acquisition.") and item.outcome != "skipped"
            ]
            assert tools == case["tools"]
            if not case.get("alternate"):
                assert len(tools) == len(set(tools))
            assert bool(result.artifacts) == case["delivered"]
            assert (
                sum(j.result.usage.requests for j in case_jobs)
                + sum(item["requests"] for item in setup)
                == len(reads)
                <= 24
            )
            assert (
                sum(j.result.usage.bytes_received for j in case_jobs)
                + sum(item["bytes_received"] for item in setup)
                <= 8 * 1024 * 1024
            )
            assert time.monotonic() - started <= 60
            if case["name"] in {"browser", "cloak", "robots-unknown"}:
                assert {"/app.js", "/data.json"} <= {item["path"] for item in reads}
            if result.artifacts:
                assert runtime.get_handoff(job.job_id).to_dict()
                for artifact in result.artifacts:
                    assert (
                        hashlib.sha256(
                            runtime.read_artifact(artifact.artifact_id).content
                        ).hexdigest()
                        == artifact.sha256
                    )
            assert runtime.get_job(job.job_id).result.to_dict() == result.to_dict()
        finally:
            runtime.close()


def test_fixed_public_targets(monkeypatch):
    data_root, _window = environment()
    verify_installations(data_root)
    snapshot = json.loads(TARGETS.read_bytes())
    bridges = observe_bridges(monkeypatch)
    started = time.monotonic()
    jobs = []
    runtime = RuntimeService.open(data_root)
    try:
        for target in snapshot["targets"]:
            remaining_seconds = int(started + 120 - time.monotonic())
            used_requests = sum(job.result.usage.requests for job in jobs)
            used_bytes = sum(job.result.usage.bytes_received for job in jobs)
            assert (
                remaining_seconds > 0
                and used_requests < 36
                and used_bytes < 16 * 1024 * 1024
            )
            req = request(
                target["target_url"],
                target["allowed_origins"],
                requests=min(18, 36 - used_requests),
                size=min(8 * 1024 * 1024, 16 * 1024 * 1024 - used_bytes),
                seconds=min(60, remaining_seconds),
            )
            retrieval = runtime.retrieve(req)
            job = runtime.get_job(retrieval["jobs"][-1]["job_id"])
            jobs.append(job)
            record(
                data_root,
                "public",
                jobs,
                bridges,
                extra={"expected": snapshot["targets"], "retrieval": retrieval},
            )
            sources = [item for item in job.result.artifacts if item.role == "source"]
            if not sources:
                assert (
                    "UNRESOLVED/CLOUDFLARE_BLOCKED"
                    in target["expected"]["retrieval_outcomes"]
                )
                assert retrieval["retrieval"]["outcome"] == "UNRESOLVED"
                assert retrieval["retrieval"]["reason"] == "CLOUDFLARE_BLOCKED"
                called = [
                    a.tool_id for a in job.result.attempts if a.outcome != "skipped"
                ]
                assert called == ["acquisition.web_http", "acquisition.playwright"]
                assert not job.result.artifacts
                continue
            assert retrieval["retrieval"]["outcome"] == "FETCHED"
            assert sources[0].mime_type in {"text/html", "application/xhtml+xml"}
            content = runtime.read_artifact(sources[0].artifact_id).content
            assert content and hashlib.sha256(content).hexdigest() == sources[0].sha256
            # Registry already validated the protocol; apply the frozen readable
            # content threshold without inventing a second acquisition result.
            checked = SimpleNamespace(mime_type=sources[0].mime_type, body=content)

            assert (
                quality_failure_code(
                    checked, minimum_words=target["expected"]["minimum_words"]
                )
                is None
            )
            assert runtime.get_handoff(job.job_id).to_dict()
        assert sum(job.result.usage.requests for job in jobs) <= 36
        assert sum(job.result.usage.bytes_received for job in jobs) <= 16 * 1024 * 1024
        assert time.monotonic() - started <= 120
    finally:
        runtime.close()
