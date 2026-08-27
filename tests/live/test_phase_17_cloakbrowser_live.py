"""Authorized Phase 17 CloakBrowser qualification; offline by default."""

# pylint: disable=duplicate-code,missing-function-docstring,too-few-public-methods
# pylint: disable=too-many-boolean-expressions,too-many-branches,too-many-locals
# pylint: disable=too-many-arguments,too-many-statements,unidiomatic-typecheck

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pytest

from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.tool_registry.eligibility import EligibilityRequirements
from web_listening.tool_registry.lifecycle import ToolLifecycle
from web_listening.tool_registry.manifest import ToolCategory
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners.isolated_runtime import (
    IsolatedRuntime,
    NetworkBoundary,
)

pytestmark = pytest.mark.live

ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "tests/fixtures/tools/cloakbrowser/0.5.9"
TARGETS = Path(__file__).with_name("phase_17_site_targets.json")
TOOL_ID = "acquisition.cloakbrowser"
VERSION = "0.5.9"
SITE_KEY = "tnfd"
CATALOG_SHA256 = "CE378F743C6363F1DC22A25758B958E3ADA695F8996B3F619AFA4CF0CD5D5322"
OCI_INDEX = "sha256:e270e34573ca186b71dbcab9320672f2b671e048753921411148865c6530c721"
AMD64_MANIFEST = (
    "sha256:6c17fac77e4cc7818159d9083c6868cfa220200ab7646036a7cc8861e51d17db"
)
RUNTIME_EVIDENCE_SCHEMA = "phase-17-cloakbrowser-runtime-evidence.v2"
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_EVIDENCE_AGE_NS = 120 * 1_000_000_000
MAX_CLOCK_SKEW_NS = 5 * 1_000_000_000


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate runtime evidence key")
        value[key] = item
    return value


def _evidence_path() -> Path:
    raw = os.environ.get("WEB_LISTENING_CLOAKBROWSER_RUNTIME_EVIDENCE", "").strip()
    candidate = Path(raw)
    if not raw or not candidate.is_absolute():
        pytest.fail("an absolute external runtime/proxy evidence path is required")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        pytest.fail("runtime/proxy evidence is unavailable")
    if resolved.is_relative_to(ROOT.resolve()):
        pytest.fail("runtime/proxy evidence must remain outside the repository")
    return resolved


def _browser_profile_home() -> str:
    raw = os.environ.get("WEB_LISTENING_CLOAKBROWSER_PROFILE_HOME", "").strip()
    candidate = Path(raw)
    if (
        not raw
        or not candidate.is_absolute()
        or candidate.parent == candidate
        or candidate.as_posix() == "/root"
        or str(candidate) != raw
    ):
        pytest.fail("an explicit dedicated absolute browser profile home is required")
    try:
        resolved = candidate.resolve(strict=True)
        certificate_database = resolved / ".pki" / "nssdb" / "cert9.db"
        if (
            resolved != candidate
            or not resolved.is_dir()
            or not certificate_database.is_file()
            or certificate_database.stat().st_size <= 0
        ):
            pytest.fail("the dedicated browser profile has no NSS certificate database")
    except OSError:
        pytest.fail("the dedicated browser profile is unavailable")
    if resolved.is_relative_to(ROOT.resolve()):
        pytest.fail("the dedicated browser profile must remain outside the repository")
    return str(resolved)


def _read_runtime_evidence(
    path: Path,
    payload: dict[str, object],
    target: dict[str, object],
    proxy: str,
    *,
    require_observation: bool,
    initial_snapshot: dict[str, object] | None = None,
    expected_nonce_sha256: str | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("runtime evidence non-atomic read")
    if len(raw) > MAX_EVIDENCE_BYTES:
        raise ValueError("runtime evidence size")
    evidence = json.loads(raw, object_pairs_hook=_unique_object)
    if type(evidence) is not dict or set(evidence) != {
        "schema_version",
        "generation",
        "observed_at_unix_ns",
        "previous_evidence_sha256",
        "attempt_nonce_sha256",
        "image",
        "network",
        "target",
        "limits",
        "observed",
    }:
        raise ValueError("runtime evidence contract")
    if evidence["schema_version"] != RUNTIME_EVIDENCE_SCHEMA:
        raise ValueError("runtime evidence schema")
    observed_at = evidence["observed_at_unix_ns"]
    now = time.time_ns()
    if (
        type(observed_at) is not int
        or observed_at > now + MAX_CLOCK_SKEW_NS
        or now - observed_at > MAX_EVIDENCE_AGE_NS
        or now - after.st_mtime_ns > MAX_EVIDENCE_AGE_NS
    ):
        raise ValueError("runtime evidence stale")
    expected_image = {
        "reference": payload["cloakbrowser"]["image"],
        "oci_index_digest": OCI_INDEX,
        "platform": "linux/amd64",
        "platform_manifest_digest": AMD64_MANIFEST,
    }
    if evidence["image"] != expected_image:
        raise ValueError("runtime evidence image")
    network = evidence["network"]
    expected_origins = target["allowed_origins"]
    if (
        type(network) is not dict
        or set(network)
        != {
            "mode",
            "internal_network",
            "direct_egress",
            "allowlist_enforced",
            "allowed_origins",
            "proxy_identity",
            "proxy_url_sha256",
        }
        or network["mode"] != "docker_internal_allowlist_proxy"
        or network["internal_network"] is not True
        or network["direct_egress"] is not False
        or network["allowlist_enforced"] is not True
        or network["allowed_origins"] != expected_origins
        or type(network["proxy_identity"]) is not str
        or not network["proxy_identity"].strip()
        or len(network["proxy_identity"]) > 256
        or network["proxy_url_sha256"]
        != hashlib.sha256(proxy.encode("utf-8")).hexdigest()
    ):
        raise ValueError("runtime evidence network")
    if evidence["target"] != {
        "url": target["urls"]["monitor"],
        "allowed_origins": expected_origins,
    }:
        raise ValueError("runtime evidence target")
    if evidence["limits"] != payload["network_limits"]:
        raise ValueError("runtime evidence limits")
    observed = evidence["observed"]
    if type(observed) is not dict or set(observed) != {
        "target_count",
        "request_count",
        "response_bytes",
        "limit_exceeded",
    }:
        raise ValueError("runtime evidence observed")
    target_count = observed["target_count"]
    request_count = observed["request_count"]
    response_bytes = observed["response_bytes"]
    if (
        any(
            type(value) is not int
            for value in (target_count, request_count, response_bytes)
        )
        or type(observed["limit_exceeded"]) is not bool
        or min(target_count, request_count, response_bytes) < 0
    ):
        raise ValueError("runtime evidence observed")
    if require_observation:
        valid_counts = target_count == 1 and request_count >= 1 and response_bytes > 0
    else:
        valid_counts = (
            target_count == request_count == response_bytes == 0
            and observed["limit_exceeded"] is False
        )
    if not valid_counts:
        raise ValueError("runtime evidence observed")
    snapshot: dict[str, object] = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "device": after.st_dev,
        "inode": after.st_ino,
        "mtime_ns": after.st_mtime_ns,
        "observed_at_unix_ns": observed_at,
        "read_monotonic_ns": time.monotonic_ns(),
    }
    if require_observation:
        if (
            initial_snapshot is None
            or expected_nonce_sha256 is None
            or evidence["generation"] != 1
            or evidence["previous_evidence_sha256"] != initial_snapshot.get("sha256")
            or evidence["attempt_nonce_sha256"] != expected_nonce_sha256
        ):
            raise ValueError("runtime evidence attempt binding")
        if (
            (snapshot["device"], snapshot["inode"])
            == (initial_snapshot.get("device"), initial_snapshot.get("inode"))
            or snapshot["mtime_ns"] <= initial_snapshot.get("mtime_ns", 0)
            or observed_at <= initial_snapshot.get("observed_at_unix_ns", 0)
            or snapshot["read_monotonic_ns"]
            <= initial_snapshot.get("read_monotonic_ns", 0)
        ):
            raise ValueError("runtime evidence non-atomic or time reversal")
    elif (
        initial_snapshot is not None
        or expected_nonce_sha256 is not None
        or evidence["generation"] != 0
        or evidence["previous_evidence_sha256"] is not None
        or evidence["attempt_nonce_sha256"] is not None
    ):
        raise ValueError("runtime evidence initial generation")
    return evidence, snapshot


def _authorized_context() -> tuple[
    dict[str, object],
    str,
    NetworkBoundary,
    dict[str, object],
    dict[str, object],
]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("Phase 17 CloakBrowser live qualification is offline by default")
    authorization = os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip()
    if not authorization:
        pytest.fail("Phase 17 requires a non-empty authorized live window")
    if os.environ.get("WEB_LISTENING_LIVE_SITE", "").strip() != SITE_KEY:
        pytest.fail("WEB_LISTENING_LIVE_SITE must be exactly tnfd")
    payload = json.loads(TARGETS.read_bytes())
    if payload.get("source_catalog_sha256") != CATALOG_SHA256:
        pytest.fail("the Phase 17 source catalog digest drifted")
    targets = payload.get("targets")
    if not isinstance(targets, list) or len(targets) != 1:
        pytest.fail("Phase 17 must contain exactly one frozen target")
    target = targets[0]
    if not isinstance(target, dict) or target.get("site_key") != SITE_KEY:
        pytest.fail("Phase 17 target must be the frozen tnfd row")
    if target.get("urls", {}).get("monitor") != "https://tnfd.global/news/":
        pytest.fail("the Phase 17 target URL drifted")
    if target.get("allowed_origins") != ["https://tnfd.global"]:
        pytest.fail("the Phase 17 allowed origin drifted")
    historical = target.get("historical_classification", {})
    if historical.get("expectation") != "pass_http_limited" or not historical.get(
        "js_heavy_candidate"
    ):
        pytest.fail("the Phase 17 historical candidate facts drifted")

    proxy = os.environ.get("WEB_LISTENING_CLOAKBROWSER_PROXY", "").strip()
    if not proxy:
        pytest.fail("the fresh agent's controlled allowlist proxy is required")
    profile_home = _browser_profile_home()
    origins = tuple(str(item) for item in target["allowed_origins"])
    evidence_path = _evidence_path()
    try:
        initial_evidence, initial_snapshot = _read_runtime_evidence(
            evidence_path, payload, target, proxy, require_observation=False
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        pytest.fail(f"fresh runtime/proxy evidence is invalid before fetch: {exc}")
    final_holder: dict[str, object] = {}

    def observe(expected_nonce_sha256: str) -> dict[str, object]:
        evidence, snapshot = _read_runtime_evidence(
            evidence_path,
            payload,
            target,
            proxy,
            require_observation=True,
            initial_snapshot=initial_snapshot,
            expected_nonce_sha256=expected_nonce_sha256,
        )
        if (
            evidence["network"]["proxy_identity"]
            != initial_evidence["network"]["proxy_identity"]
        ):
            raise ValueError("the controlled proxy identity changed")
        final_holder.update(evidence=evidence, snapshot=snapshot)
        observed = evidence["observed"]
        return {
            "attempt_nonce_sha256": expected_nonce_sha256,
            "request_count": observed["request_count"],
            "response_bytes": observed["response_bytes"],
            "budget_enforced": evidence["network"]["allowlist_enforced"],
            "limit_exceeded": observed["limit_exceeded"],
        }

    return (
        payload,
        authorization,
        NetworkBoundary(
            kind="controlled_proxy",
            allowed_origins=origins,
            proxy_server=proxy,
            browser_profile_home=profile_home,
            observation_reader=observe,
        ),
        initial_evidence,
        final_holder,
    )


def _cloakbrowser_info() -> dict[str, object]:
    environment = dict(os.environ)
    for name in ("CLOAKBROWSER_LICENSE_KEY", "CLOAKBROWSER_DOWNLOAD_URL"):
        environment.pop(name, None)
    completed = subprocess.run(
        (sys.executable, "-m", "cloakbrowser", "info", "--json"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        pytest.fail("CloakBrowser info/preflight is unavailable")
    try:
        info = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        pytest.fail("CloakBrowser info did not return JSON")
    if info.get("environment", {}).get("wrapper") != VERSION:
        pytest.fail("CloakBrowser wrapper version drifted")
    if info.get("binary", {}).get("bundled_version") != "146.0.7680.177.5":
        pytest.fail("CloakBrowser bundled Chromium version drifted")
    launch = info.get("launch", {})
    if not launch.get("tested") or not launch.get("ok"):
        pytest.fail("CloakBrowser binary launch preflight failed")
    if "146.0.7680.177" not in str(launch.get("version")):
        pytest.fail("CloakBrowser reported Chromium version drifted")
    return info


def _request(target: dict[str, object]) -> AcquisitionInput:
    url = str(target["urls"]["monitor"])
    request = Request(
        Scope(
            seeds=(url,),
            allowed_origins=tuple(str(item) for item in target["allowed_origins"]),
            include_paths=("/**",),
            content_types=(ContentType.HTML,),
        ),
        None,
        False,
        Budgets(6, 4 * 1024 * 1024, 60, 1),
    )
    return AcquisitionInput(request, url)


@pytest.mark.live
def test_phase_17_cloakbrowser_live(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload, authorization, boundary, _initial_evidence, final_holder = (
        _authorized_context()
    )
    target = payload["targets"][0]
    record: dict[str, object] = {
        "schema_version": "phase-17-cloakbrowser-live-evidence.v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "authorization_window_id": hashlib.sha256(
            authorization.encode("utf-8")
        ).hexdigest(),
        "input": {
            "site_key": SITE_KEY,
            "target_url": target["urls"]["monitor"],
            "allowed_origins": target["allowed_origins"],
        },
        "limits": payload["network_limits"],
        "qualification": {},
        "tool_result": {},
        "artifact_store_writes": 0,
        "exit_code": "blocked",
    }
    runtime: IsolatedRuntime | None = None
    try:
        if importlib.metadata.version("cloakbrowser") != VERSION:
            pytest.fail("CloakBrowser 0.5.9 is not installed")
        info = _cloakbrowser_info()
        source = tmp_path / "source"
        shutil.copytree(SOURCE, source)
        lifecycle = ToolLifecycle(tmp_path / "lifecycle")
        installed = lifecycle.install(source)
        command = (
            sys.executable,
            str(
                lifecycle.data_root
                / "tools"
                / "acquisition"
                / TOOL_ID
                / VERSION
                / "tool.py"
            ),
        )
        runtime = IsolatedRuntime(
            installed.manifest,
            command,
            authorization,
            boundary,
            state_reader=lambda: lifecycle.inspect(
                ToolCategory.ACQUISITION, TOOL_ID, VERSION
            ),
        )
        report = runtime.qualify(_request(target))
        record["runtime"] = {
            "wrapper_version": info["environment"]["wrapper"],
            "bundled_chromium_version": info["binary"]["bundled_version"],
            "reported_chromium_version": info["launch"]["version"],
            "source": "cloakbrowser info --json",
        }
        record["qualification"] = {
            "qualified": False,
            "adapter_binding_qualified": report.qualified,
            "checks": dict(report.checks),
            "failure_code": report.failure_code,
            "binding_sha256": report.binding_sha256,
            "generic_lifecycle_qualified": installed.qualified,
        }
        result = report.result
        if isinstance(result, AcquisitionFailure):
            record["tool_result"] = {
                "status": "failed_or_rejected",
                "tool_id": result.tool_id,
                "tool_version": result.tool_version,
                "code": result.code,
            }
            pytest.fail(f"CloakBrowser qualification failed: {result.code}")
        assert isinstance(result, AcquisitionOutput)
        assert boundary.proxy_server is not None
        runtime_evidence = final_holder.get("evidence")
        if type(runtime_evidence) is not dict:
            pytest.fail("fresh runtime/proxy evidence was not consumed during fetch")
        record["qualification"]["qualified"] = report.qualified
        record["tool_result"] = {
            "status": "success",
            "tool_id": result.tool_id,
            "tool_version": result.tool_version,
            "requested_url": result.requested_url,
            "final_url": result.final_url,
            "status_code": result.status_code,
            "mime_type": result.mime_type,
            "size_bytes": len(result.body),
            "sha256": result.sha256,
            "redirects": [asdict(item) for item in result.redirects],
            "runtime_ms": result.runtime_ms,
        }
        registry = Registry()
        registry.register(runtime.manifest, _ExternalLiveTool(runtime))
        eligible = registry.eligible(
            EligibilityRequirements(
                ToolCategory.ACQUISITION,
                frozenset({"browser_render", "governed_network"}),
                output_bytes=4 * 1024 * 1024,
                runtime_seconds=60,
            )
        )
        assert eligible == (runtime.manifest,)
        assert report.qualified is True
        assert installed.qualified is False
        assert result.requested_url == target["urls"]["monitor"]
        assert result.sha256 == hashlib.sha256(result.body).hexdigest()
        assert len(result.body) <= 4 * 1024 * 1024
        assert len(result.redirects) <= 5
        assert runtime.last_evidence.cleanup_complete is True
        assert runtime.last_evidence.preflight_closed is True
        assert runtime.last_evidence.fetch_closed is True
        record["runtime_boundary"] = {
            "image": runtime_evidence["image"],
            "network": runtime_evidence["network"],
            "enforced_limits": runtime_evidence["limits"],
            "actual": runtime_evidence["observed"],
        }
    except importlib.metadata.PackageNotFoundError:
        pytest.fail("CloakBrowser 0.5.9 is not installed")
    finally:
        if runtime is not None:
            record["cleanup"] = {
                "preflight_browser_closed": runtime.last_evidence.preflight_closed,
                "fetch_browser_closed": runtime.last_evidence.fetch_closed,
                "attempt_directory_cleaned": runtime.last_evidence.cleanup_complete,
            }
            record["exit_code"] = runtime.last_evidence.exit_code
        with capsys.disabled():
            print(json.dumps({"phase_17_live_evidence": record}, sort_keys=True))


class _ExternalLiveTool:
    def __init__(self, runtime: IsolatedRuntime) -> None:
        self._runtime = runtime
        self.manifest = runtime.manifest

    def acquire(self, tool_input: AcquisitionInput):
        return self._runtime.invoke(tool_input)
