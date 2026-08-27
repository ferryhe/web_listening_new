"""Phase 17 governed CloakBrowser Adapter integration.

README 1-2 Alignment:
- Purpose: this advances governed acquisition for one explicit target while
  retaining Request scope/budget authority and consistent Tool evidence.
- Product model: Registry and the generic isolated runner remain the only
  selection/execution boundary; the thin external Adapter receives no Artifact,
  Manifest, Site Skill, Result, Runtime, robots, or policy power.
- Sections 10/11/18: the pinned Adapter stays inspectable but unqualified under
  generic Lifecycle qualification. Only explicit authorization plus a bound,
  parent-applied controlled proxy can create a scope-bound qualified view.
  No parser, RAG, search, question answering, content analysis, login, fallback,
  or second browser is added.
"""

# pylint: disable=duplicate-code,missing-function-docstring,protected-access
# pylint: disable=too-few-public-methods,too-many-lines,too-many-locals

from __future__ import annotations

import ast
import base64
import builtins
import hashlib
import importlib.metadata
import json
import runpy
import shutil
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.tool_registry.eligibility import EligibilityRequirements
from web_listening.tool_registry.lifecycle import ToolLifecycle, ToolLifecycleError
from web_listening.tool_registry.manifest import (
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
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners.isolated_runtime import (
    IsolatedRuntime,
    NetworkBoundary,
)
from web_listening.tool_registry.runners.subprocess import SubprocessRunner

ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "tests/fixtures/tools/cloakbrowser/0.5.9"
FAKE_SDK = ROOT / "tests/fixtures/tools/cloakbrowser/fake_sdk/cloakbrowser.py"
QUALIFICATION = ROOT / "tests/fixtures/tools/cloakbrowser/qualification"
MISREPORT = ROOT / "tests/fixtures/tools/cloakbrowser/fakes/misreport.py"
TARGET_SNAPSHOT = ROOT / "tests/live/phase_17_site_targets.json"
CURRENT_CATALOG = ROOT / "tests/live/catalog/smoke_site_catalog.json"
TOOL_ID = "acquisition.cloakbrowser"
VERSION = "0.5.9"
URL = "https://example.test/page"
ORIGIN = "https://example.test"
OLD_COMMIT = "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5"
REQUIRED_CHECKS = (
    "health",
    "protocol",
    "scope",
    "redirect",
    "output_bound",
    "controlled_proxy_or_network_isolation",
)

# Fixed-SHA migration table required by Issue #18. Every source was read only
# with git show at OLD_COMMIT; the old repository's current branch was not read.
MIGRATION = (
    (
        "web_listening/blocks/acquisition_capture.py, "
        "web_listening/executors/cloakbrowser_wrapper.py, and "
        "tests/test_acquisition_capture.py @ " + OLD_COMMIT,
        "test_initial_scope_rejection_precedes_optional_dependency_import",
        "tests/fixtures/tools/cloakbrowser/0.5.9/tool.py",
        "rewrite: retain disabled-before-launch, then admit only a bound request",
    ),
    (
        "tests/test_acquisition_capture.py @ " + OLD_COMMIT,
        "test_version_manifest_and_describe_are_dependency_lazy",
        "tests/fixtures/tools/cloakbrowser/0.5.9/tool.json and tool.py",
        "preserve: pin metadata and avoid importing the optional SDK for describe",
    ),
    (
        "web_listening/blocks/acquisition_profile.py and "
        "tests/test_acquisition_profile.py @ " + OLD_COMMIT,
        "test_generic_lifecycle_and_authorization_only_cannot_qualify",
        "src/web_listening/tool_registry/runners/isolated_runtime.py",
        "rewrite: authorization alone no longer qualifies browser target reads",
    ),
    (
        "web_listening/blocks/staged_workflow.py and "
        "tests/test_staged_acquisition.py @ " + OLD_COMMIT,
        "test_bound_runtime_preflights_closes_qualifies_and_runs_protocol",
        "tests/fixtures/tools/cloakbrowser/0.5.9/tool.py",
        "preserve: headless preflight and reliable close; discard workflow coupling",
    ),
    (
        "web_listening/executors/registry.py @ " + OLD_COMMIT,
        "test_disable_and_rollback_remain_effective",
        "reused read-only lifecycle.py/registry.py plus isolated_runtime.py",
        "rewrite: current explicit state and bound qualification replace preview metadata",
    ),
    (
        "tests/live/test_authorized_access_gateway_canary.py and "
        "config/smoke_site_catalog.json @ " + OLD_COMMIT,
        "test_live_snapshot_freezes_one_current_tnfd_catalog_row and "
        "test_phase_17_cloakbrowser_live",
        "tests/live/phase_17_site_targets.json and "
        "tests/live/test_phase_17_cloakbrowser_live.py",
        "rewrite: freeze one reviewed TNFD target; discard the broad legacy canary",
    ),
)


def _proxy_observation_reader(command: tuple[str, ...]):
    audit_path = Path(command[1]).with_name("fake_audit.jsonl")

    def read(expected_nonce_sha256: str) -> dict[str, object]:
        events = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
        ]
        requests = [
            item
            for item in events
            if item.get("event") == "proxy_request"
            and item.get("attempt_nonce_sha256") == expected_nonce_sha256
        ]
        responses = [
            item
            for item in events
            if item.get("event") == "proxy_response"
            and item.get("attempt_nonce_sha256") == expected_nonce_sha256
        ]
        exceeded = any(
            item.get("event") == "proxy_limit"
            and item.get("attempt_nonce_sha256") == expected_nonce_sha256
            for item in events
        )
        return {
            "attempt_nonce_sha256": expected_nonce_sha256,
            "request_count": len(requests),
            "response_bytes": sum(int(item["response_bytes"]) for item in responses),
            "budget_enforced": True,
            "limit_exceeded": exceeded,
        }

    return read


def _unobserved(_expected_nonce_sha256: str) -> dict[str, object]:
    raise ValueError("no proxy attempt was run")


def _boundary(command: tuple[str, ...] | None = None) -> NetworkBoundary:
    if command is None:
        profile_home = (
            ROOT / "tests/fixtures/tools/cloakbrowser/profile-home"
        ).resolve()
    else:
        profile_home = _profile_home(Path(command[1]).parent)
    return NetworkBoundary(
        kind="controlled_proxy",
        allowed_origins=(ORIGIN,),
        proxy_server="http://proxy.test:8080",
        browser_profile_home=str(profile_home),
        observation_reader=(
            _unobserved if command is None else _proxy_observation_reader(command)
        ),
    )


def _request(
    *,
    max_requests: int = 4,
    max_bytes: int = 4096,
    timeout: int = 2,
    target_url: str = URL,
    include_paths: tuple[str, ...] = ("/**",),
) -> AcquisitionInput:
    request = Request(
        Scope(
            seeds=(target_url,),
            allowed_origins=(ORIGIN,),
            include_paths=include_paths,
            content_types=(ContentType.HTML,),
        ),
        None,
        False,
        Budgets(max_requests, max_bytes, timeout, 1),
    )
    return AcquisitionInput(request, target_url)


def _source(
    tmp_path: Path,
    *,
    scenario: dict[str, object] | None = None,
    include_sdk: bool = True,
    name: str = "source",
) -> Path:
    target = tmp_path / name
    shutil.copytree(SOURCE, target)
    if include_sdk:
        shutil.copyfile(FAKE_SDK, target / "cloakbrowser.py")
    if scenario is not None:
        (target / "fake_scenario.json").write_text(
            json.dumps(scenario, sort_keys=True), encoding="utf-8"
        )
    return target


def _installed(
    tmp_path: Path,
    *,
    scenario: dict[str, object] | None = None,
    name: str = "source",
) -> tuple[ToolLifecycle, ToolManifest, tuple[str, ...]]:
    lifecycle = ToolLifecycle(tmp_path / f"lifecycle-{name}")
    lifecycle.install(_source(tmp_path, scenario=scenario, name=name))
    state = lifecycle.qualify(ToolCategory.ACQUISITION, TOOL_ID, VERSION)
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
    return lifecycle, state.manifest, command


class _ExternalAcquisition:
    def __init__(self, runtime: IsolatedRuntime) -> None:
        self._runtime = runtime
        self.manifest = runtime.manifest

    def acquire(
        self, tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        return self._runtime.invoke(tool_input)


def _raw_tool(source: Path, envelope: dict[str, object]) -> dict[str, object]:
    completed = subprocess.run(
        (sys.executable, str(source / "tool.py")),
        input=json.dumps(envelope).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=source,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    return json.loads(completed.stdout)


def _profile_home(root: Path, name: str = "browser-profile") -> Path:
    profile = root / name
    nssdb = profile / ".pki" / "nssdb"
    nssdb.mkdir(parents=True)
    (nssdb / "cert9.db").write_bytes(b"offline-nss-profile")
    return profile.resolve()


def _raw_bound_tool(
    source: Path,
    envelope: dict[str, object],
    boundary: dict[str, object],
) -> dict[str, object]:
    encoded = base64.urlsafe_b64encode(
        json.dumps(boundary, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    completed = subprocess.run(
        (
            sys.executable,
            str(source / "tool.py"),
            "--web-listening-boundary",
            encoded,
        ),
        input=json.dumps(envelope).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=source,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    return json.loads(completed.stdout)


def _external_envelope() -> dict[str, object]:
    return {
        "protocol_version": "web-listening-external-tool.v1",
        "category": "acquisition",
        "tool_id": TOOL_ID,
        "tool_version": VERSION,
        "attempt_directory": ".",
        "input": {
            "target_url": URL,
            "allowed_origins": [ORIGIN],
            "include_paths": ["/**"],
            "content_types": ["html"],
            "limits": {
                "max_requests": 4,
                "max_bytes": 4096,
                "max_runtime_seconds": 2,
            },
        },
    }


def _external_boundary(profile_home: str) -> dict[str, object]:
    return {
        "schema_version": "web-listening-network-boundary.v1",
        "authorization_window_id": "a" * 64,
        "kind": "controlled_proxy",
        "allowed_origins": [ORIGIN],
        "proxy_server": "http://proxy.test:8080",
        "browser_profile_home": profile_home,
        "target_url": URL,
        "attempt_nonce": "b" * 64,
        "attempt_directory": ".",
        "limits": {
            "max_requests": 4,
            "max_response_bytes": 4096,
            "max_output_bytes": 4096,
            "max_runtime_seconds": 2,
            "max_redirects": 3,
        },
    }


def test_version_manifest_and_describe_are_dependency_lazy() -> None:
    declaration = json.loads((SOURCE / "tool.json").read_bytes())
    assert declaration["source"]["version"] == VERSION
    assert declaration["manifest"] == {
        "tool_id": TOOL_ID,
        "version": VERSION,
        "category": "acquisition",
        "distribution": "installed",
        "capabilities": ["browser_render", "governed_network"],
        "limits": {
            "max_runtime_seconds": 60,
            "max_input_bytes": 4096,
            "max_output_bytes": 4 * 1024 * 1024,
        },
        "health": "healthy",
        "qualification": "unqualified",
    }
    response = _raw_tool(
        SOURCE,
        {
            "protocol_version": "web-listening-tool-qualification.v1",
            "operation": "describe",
            "tool_id": TOOL_ID,
            "version": VERSION,
            "category": "acquisition",
        },
    )
    assert response["status"] == "ok"
    assert response["version"] == VERSION


def test_live_snapshot_freezes_one_current_tnfd_catalog_row() -> None:
    payload = json.loads(TARGET_SNAPSHOT.read_bytes())
    raw_catalog = CURRENT_CATALOG.read_bytes()
    lf_catalog = raw_catalog.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    crlf_catalog = lf_catalog.replace(b"\n", b"\r\n")
    catalog = json.loads(raw_catalog)
    current = [item for item in catalog["sites"] if item["site_key"] == "tnfd"]
    expected_digest = "FDD7BA84B83C06D7CF032B50162DD03AFBBA7632CF8037C1D137CC64F8BDCA0C"
    assert hashlib.sha256(lf_catalog).hexdigest().upper() == expected_digest
    assert (
        hashlib.sha256(crlf_catalog.replace(b"\r\n", b"\n")).hexdigest().upper()
        == expected_digest
    )
    assert payload["source_catalog_sha256"] == expected_digest
    assert payload["source_catalog_sha256_basis"] == "lf_normalized_bytes"
    assert payload["targets"] == current
    assert payload["network_limits"] == {
        "max_targets": 1,
        "max_total_requests": 6,
        "max_total_response_bytes": 4 * 1024 * 1024,
        "max_redirects": 5,
        "timeout_seconds": 60,
        "concurrency": 1,
        "retry": 0,
        "acquisition_fallback": 0,
    }
    assert payload["cloakbrowser"]["wrapper_version"] == VERSION
    assert payload["cloakbrowser"]["bundled_chromium_version"] == ("146.0.7680.177.5")
    assert (
        payload["cloakbrowser"]["runtime_evidence_schema"]
        == "phase-17-cloakbrowser-runtime-evidence.v2"
    )


def test_generic_lifecycle_and_authorization_only_cannot_qualify(
    tmp_path: Path,
) -> None:
    lifecycle, manifest, command = _installed(tmp_path)
    state = lifecycle.inspect(ToolCategory.ACQUISITION, TOOL_ID, VERSION)
    assert (state.qualified, state.broken, state.failure_code) == (
        False,
        False,
        "lifecycle.contract_failed",
    )
    with pytest.raises(ToolLifecycleError, match="lifecycle.not_activatable"):
        lifecycle.activate(ToolCategory.ACQUISITION, TOOL_ID, VERSION)

    runtime = IsolatedRuntime(manifest, command, "offline-authorized", None)
    report = runtime.qualify(_request())
    assert report.qualified is False
    assert report.failure_code == "isolated_runtime.network_unrestricted"
    assert report.result.code == report.failure_code
    assert runtime.last_evidence.adapter_invoked is False

    registry = Registry()
    registry.register(manifest, _ExternalAcquisition(runtime))
    assert not registry.eligible(EligibilityRequirements(ToolCategory.ACQUISITION))


@pytest.mark.parametrize(
    ("authorization", "boundary", "code"),
    [
        (None, _boundary(), "isolated_runtime.authorization_required"),
        ("offline-authorized", None, "isolated_runtime.network_unrestricted"),
    ],
)
def test_missing_authorization_or_network_boundary_rejects_before_adapter(
    tmp_path: Path,
    authorization: str | None,
    boundary: NetworkBoundary | None,
    code: str,
) -> None:
    _lifecycle, manifest, command = _installed(tmp_path)
    runtime = IsolatedRuntime(manifest, command, authorization, boundary)
    report = runtime.qualify(_request())
    assert report.qualified is False
    assert isinstance(report.result, AcquisitionFailure)
    assert report.result.code == code
    assert runtime.last_evidence.adapter_invoked is False


def test_initial_scope_rejection_precedes_optional_dependency_import(
    tmp_path: Path,
) -> None:
    source = _source(tmp_path, include_sdk=False)
    shutil.copyfile(QUALIFICATION / "qualified_proxy.json", source / "boundary.json")
    response = _raw_tool(
        source,
        {
            "protocol_version": "web-listening-external-tool.v1",
            "category": "acquisition",
            "tool_id": TOOL_ID,
            "tool_version": VERSION,
            "attempt_directory": ".",
            "input": {
                "target_url": "https://outside.test/blocked",
                "allowed_origins": [ORIGIN],
                "include_paths": ["/**"],
                "content_types": ["html"],
                "limits": {
                    "max_requests": 2,
                    "max_bytes": 100,
                    "max_runtime_seconds": 2,
                },
            },
        },
    )
    assert response["status"] == "rejected"
    assert response["result"] == {"code": "cloakbrowser.scope_rejected"}


@pytest.mark.parametrize(
    "claim",
    [
        "authorized_no_network.json",
        "qualified_network_isolation.json",
        "qualified_proxy.json",
    ],
)
def test_static_network_claim_cannot_authorize_target_read(
    tmp_path: Path, claim: str
) -> None:
    source = _source(tmp_path)
    shutil.copyfile(QUALIFICATION / claim, source / "boundary.json")
    response = _raw_tool(
        source,
        {
            "protocol_version": "web-listening-external-tool.v1",
            "category": "acquisition",
            "tool_id": TOOL_ID,
            "tool_version": VERSION,
            "attempt_directory": ".",
            "input": {
                "target_url": URL,
                "allowed_origins": [ORIGIN],
                "include_paths": ["/**"],
                "content_types": ["html"],
                "limits": {
                    "max_requests": 2,
                    "max_bytes": 100,
                    "max_runtime_seconds": 2,
                },
            },
        },
    )
    assert response["status"] == "rejected"
    assert response["result"] == {"code": "cloakbrowser.network_unrestricted"}


def test_bound_runtime_preflights_closes_qualifies_and_runs_protocol(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario = {
        "body": "<html><body>governed</body></html>",
        "mime_type": "text/html",
        "status_code": 200,
        "redirects": [],
    }
    lifecycle, manifest, command = _installed(tmp_path, scenario=scenario)
    monkeypatch.setenv("WEB_LISTENING_HOST_SECRET", "must-not-be-inherited")
    runtime = IsolatedRuntime(
        manifest,
        command,
        "offline-authorized",
        _boundary(command),
        state_reader=lambda: lifecycle.inspect(
            ToolCategory.ACQUISITION, TOOL_ID, VERSION
        ),
    )
    report = runtime.qualify(_request())
    assert report.qualified is True
    assert report.failure_code is None
    assert dict(report.checks) == dict.fromkeys(REQUIRED_CHECKS, True)
    assert isinstance(report.result, AcquisitionOutput)
    assert runtime.manifest.qualification is QualificationStatus.QUALIFIED

    audit_path = Path(command[1]).with_name("fake_audit.jsonl")
    audit = [
        json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    launch = next(
        entry
        for entry in audit
        if entry["event"] == "launch" and entry["proxy"] is not None
    )
    assert launch["headless"] is True
    assert launch["proxy"] == "http://proxy.test:8080"
    assert launch["home"] == str(
        (Path(command[1]).parent / "browser-profile").resolve()
    )
    assert "HOME" in launch["environment_keys"]
    assert "WEB_LISTENING_HOST_SECRET" not in launch["environment_keys"]
    assert any(entry["event"] == "close" for entry in audit)
    assert sum(entry["event"] == "close" for entry in audit) >= 2
    proxy_requests = [entry for entry in audit if entry["event"] == "proxy_request"]
    proxy_responses = [entry for entry in audit if entry["event"] == "proxy_response"]
    assert len(proxy_requests) == len(proxy_responses) == 1
    assert (
        proxy_requests[0]["attempt_nonce_sha256"]
        == proxy_responses[0]["attempt_nonce_sha256"]
    )
    assert runtime.last_evidence.preflight_closed is True
    assert runtime.last_evidence.fetch_closed is True

    registry = Registry()
    registry.register(runtime.manifest, _ExternalAcquisition(runtime))
    assert registry.eligible(
        EligibilityRequirements(
            ToolCategory.ACQUISITION,
            frozenset({"browser_render", "governed_network"}),
            output_bytes=4096,
            runtime_seconds=2,
        )
    ) == (runtime.manifest,)
    output = registry.invoke(TOOL_ID, _request())
    assert isinstance(output, AcquisitionOutput)
    assert output.requested_url == output.final_url == URL
    assert output.body == scenario["body"].encode("utf-8")
    assert output.sha256 == hashlib.sha256(output.body).hexdigest()
    assert runtime.last_evidence.cleanup_complete is True
    assert runtime.last_evidence.exit_code == 0


def test_binding_delivers_exact_target_limits_and_attempt_directory() -> None:
    payload = _boundary().binding_payload(
        "offline-authorized", _request(), attempt_nonce="a" * 64
    )
    assert payload["target_url"] == URL
    assert payload["allowed_origins"] == [ORIGIN]
    assert payload["browser_profile_home"] == str(
        (ROOT / "tests/fixtures/tools/cloakbrowser/profile-home").resolve()
    )
    assert payload["attempt_directory"] == "."
    assert payload["limits"] == {
        "max_requests": 4,
        "max_response_bytes": 4096,
        "max_output_bytes": 4096,
        "max_runtime_seconds": 2,
        "max_redirects": 3,
    }


def test_profile_home_is_required_and_changes_the_binding(tmp_path: Path) -> None:
    first = _profile_home(tmp_path, "profile-one")
    second = _profile_home(tmp_path, "profile-two")
    with pytest.raises(ToolRegistryError, match="isolated_runtime.boundary_invalid"):
        NetworkBoundary(
            kind="controlled_proxy",
            allowed_origins=(ORIGIN,),
            proxy_server="http://proxy.test:8080",
            observation_reader=_unobserved,
        )
    with pytest.raises(ToolRegistryError, match="isolated_runtime.boundary_invalid"):
        NetworkBoundary(
            kind="controlled_proxy",
            allowed_origins=(ORIGIN,),
            proxy_server="http://proxy.test:8080",
            browser_profile_home="relative-profile",
            observation_reader=_unobserved,
        )
    payloads = [
        NetworkBoundary(
            kind="controlled_proxy",
            allowed_origins=(ORIGIN,),
            proxy_server="http://proxy.test:8080",
            browser_profile_home=str(profile),
            observation_reader=_unobserved,
        ).binding_payload("offline-authorized", _request(), attempt_nonce="a" * 64)
        for profile in (first, second)
    ]
    assert payloads[0]["browser_profile_home"] == str(first)
    assert payloads[0] != payloads[1]
    assert (
        hashlib.sha256(json.dumps(payloads[0], sort_keys=True).encode("utf-8")).digest()
        != hashlib.sha256(
            json.dumps(payloads[1], sort_keys=True).encode("utf-8")
        ).digest()
    )


@pytest.mark.parametrize("case", ["missing", "relative", "mismatch", "invalid"])
def test_invalid_browser_profile_rejects_before_target_read(
    tmp_path: Path, case: str
) -> None:
    source = _source(tmp_path, name=f"source-{case}")
    valid = _profile_home(tmp_path, f"profile-{case}")
    invalid = (tmp_path / f"invalid-{case}").resolve()
    invalid.mkdir()
    boundary = _external_boundary(str(valid))
    if case == "missing":
        boundary.pop("browser_profile_home")
    elif case == "relative":
        boundary["browser_profile_home"] = "relative-profile"
    elif case == "mismatch":
        boundary["browser_profile_home"] = str(
            valid.parent / "unused" / ".." / valid.name
        )
    else:
        boundary["browser_profile_home"] = str(invalid)
    response = _raw_bound_tool(source, _external_envelope(), boundary)
    assert response["status"] == "rejected"
    assert response["result"] == {"code": "cloakbrowser.network_unrestricted"}
    audit_path = source / "fake_audit.jsonl"
    audit = (
        [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
        ]
        if audit_path.exists()
        else []
    )
    assert not any(
        item["event"] in {"goto", "proxy_request", "content"} for item in audit
    )


def test_in_scope_redirect_chain_is_parent_rechecked(tmp_path: Path) -> None:
    _lifecycle, manifest, command = _installed(
        tmp_path,
        scenario={
            "body": "<html>redirected</html>",
            "mime_type": "text/html",
            "status_code": 200,
            "redirects": [
                {
                    "from_url": URL,
                    "to_url": "https://example.test/final",
                    "status_code": 302,
                }
            ],
        },
    )
    report = IsolatedRuntime(
        manifest, command, "offline-authorized", _boundary(command)
    ).qualify(_request())
    assert report.qualified is True
    assert isinstance(report.result, AcquisitionOutput)
    assert report.result.final_url == "https://example.test/final"
    assert tuple(
        (item.from_url, item.to_url, item.status_code)
        for item in report.result.redirects
    ) == (
        (URL, "https://example.test/final", 302),
    )


def test_request_bound_aborts_excess_redirect_before_content(tmp_path: Path) -> None:
    _lifecycle, manifest, command = _installed(
        tmp_path,
        scenario={
            "body": "must not be read",
            "redirects": [
                {"from_url": URL, "to_url": ORIGIN + "/one", "status_code": 302},
                {
                    "from_url": ORIGIN + "/one",
                    "to_url": ORIGIN + "/two",
                    "status_code": 302,
                },
            ],
        },
    )
    report = IsolatedRuntime(
        manifest, command, "offline-authorized", _boundary(command)
    ).qualify(_request(max_requests=2))
    assert report.qualified is False
    assert report.failure_code == "cloakbrowser.request_limit"


def _allowed_subresponses() -> list[dict[str, object]]:
    return [
        {
            "url": f"{ORIGIN}/asset-{index}.js",
            "response_bytes": size,
            "is_navigation_request": False,
            "resource_type": "script",
        }
        for index, size in enumerate((11, 12, 13, 14, 15), start=1)
    ]


def test_budget_excess_plain_subresources_are_aborted_but_document_succeeds(
    tmp_path: Path,
) -> None:
    body = "x" * 32
    excess = [
        {
            "url": f"{ORIGIN}/discarded-{index}.png",
            "response_bytes": 1000,
            "is_navigation_request": False,
            "resource_type": "image",
        }
        for index in (7, 8)
    ]
    _lifecycle, manifest, command = _installed(
        tmp_path,
        scenario={
            "body": body,
            "mime_type": "text/html",
            "status_code": 200,
            "subresponses": _allowed_subresponses() + excess,
        },
    )
    report = IsolatedRuntime(
        manifest, command, "offline-authorized", _boundary(command)
    ).qualify(_request(max_requests=6, max_bytes=4096))
    assert report.qualified is True
    assert isinstance(report.result, AcquisitionOutput)
    assert report.result.requested_url == report.result.final_url == URL
    assert report.result.status_code == 200
    assert report.result.mime_type == "text/html"
    assert report.result.body == body.encode("utf-8")
    assert report.result.sha256 == hashlib.sha256(report.result.body).hexdigest()
    audit = [
        json.loads(line)
        for line in Path(command[1])
        .with_name("fake_audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    requests = [item for item in audit if item["event"] == "proxy_request"]
    responses = [item for item in audit if item["event"] == "proxy_response"]
    assert len(requests) == len(responses) == 6
    assert sum(item["response_bytes"] for item in responses) == 97
    assert [item["url"] for item in audit if item["event"] == "abort"] == [
        item["url"] for item in excess
    ]
    assert not any(
        item["url"] in {value["url"] for value in excess} for item in requests
    )
    assert any(item["event"] == "content" for item in audit)


@pytest.mark.parametrize(
    "excess_metadata",
    [
        {"is_navigation_request": True, "resource_type": "script"},
        {"is_navigation_request": False, "resource_type": "document"},
        {
            "is_navigation_request": False,
            "resource_type": "script",
            "redirected_from": True,
        },
        {"missing_fields": ["is_navigation_request"]},
        {"missing_fields": ["resource_type"]},
        {"missing_fields": ["redirected_from"]},
        {"error_fields": ["is_navigation_request"]},
        {"error_fields": ["resource_type"]},
        {"error_fields": ["redirected_from"]},
    ],
)
def test_uncertain_or_navigation_budget_excess_remains_fatal(
    tmp_path: Path, excess_metadata: dict[str, object]
) -> None:
    blocked_url = ORIGIN + "/blocked-budget-request"
    excess = {
        "url": blocked_url,
        "response_bytes": 1000,
        "is_navigation_request": False,
        "resource_type": "script",
        **excess_metadata,
    }
    _lifecycle, manifest, command = _installed(
        tmp_path,
        scenario={
            "body": "must not be read",
            "mime_type": "text/html",
            "status_code": 200,
            "subresponses": _allowed_subresponses() + [excess],
        },
    )
    runtime = IsolatedRuntime(
        manifest, command, "offline-authorized", _boundary(command)
    )
    report = runtime.qualify(_request(max_requests=6, max_bytes=4096))
    assert report.qualified is False
    assert report.failure_code == "cloakbrowser.request_limit"
    assert runtime.manifest.qualification is QualificationStatus.UNQUALIFIED
    audit = [
        json.loads(line)
        for line in Path(command[1])
        .with_name("fake_audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert {"event": "abort", "url": blocked_url} in audit
    assert not any(
        item["event"] == "proxy_request" and item["url"] == blocked_url
        for item in audit
    )
    assert not any(item["event"] == "content" for item in audit)


def test_free_form_network_isolation_claim_is_not_a_boundary() -> None:
    with pytest.raises(ToolRegistryError, match="isolated_runtime.boundary_invalid"):
        NetworkBoundary(
            kind="network_isolation",
            allowed_origins=(ORIGIN,),
            isolation_proof="I promise this runtime is isolated",
        )


def test_close_failure_keeps_adapter_unqualified(tmp_path: Path) -> None:
    _lifecycle, manifest, command = _installed(tmp_path, scenario={"close_error": True})
    report = IsolatedRuntime(
        manifest, command, "offline-authorized", _boundary(command)
    ).qualify(_request())
    assert report.qualified is False
    assert report.failure_code == "isolated_runtime.health_failed"
    assert dict(report.checks) == {
        "health": False,
        "protocol": True,
        "scope": False,
        "redirect": False,
        "output_bound": False,
        "controlled_proxy_or_network_isolation": True,
    }


def test_out_of_scope_redirect_is_aborted_before_content_read(tmp_path: Path) -> None:
    lifecycle, manifest, command = _installed(
        tmp_path,
        scenario={
            "body": "must not be read",
            "mime_type": "text/html",
            "status_code": 200,
            "redirects": [
                {
                    "from_url": URL,
                    "to_url": "https://outside.test/blocked",
                    "status_code": 302,
                }
            ],
        },
    )
    runtime = IsolatedRuntime(
        manifest, command, "offline-authorized", _boundary(command)
    )
    report = runtime.qualify(_request())
    assert report.qualified is False
    assert report.failure_code == "cloakbrowser.scope_rejected"
    audit_path = Path(command[1]).with_name("fake_audit.jsonl")
    audit = [
        json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert any(entry["event"] == "abort" for entry in audit)
    assert not any(entry["event"] == "content" for entry in audit)
    assert dict(report.checks) == {
        "health": True,
        "protocol": True,
        "scope": False,
        "redirect": False,
        "output_bound": False,
        "controlled_proxy_or_network_isolation": True,
    }
    assert (
        lifecycle.inspect(ToolCategory.ACQUISITION, TOOL_ID, VERSION).qualified is False
    )


def test_path_subtree_does_not_admit_same_prefix_redirect(tmp_path: Path) -> None:
    start = ORIGIN + "/news/start"
    outside = ORIGIN + "/newspaper"
    _lifecycle, manifest, command = _installed(
        tmp_path,
        scenario={
            "body": "must not be read",
            "redirects": [{"from_url": start, "to_url": outside, "status_code": 302}],
        },
    )
    report = IsolatedRuntime(
        manifest, command, "offline-authorized", _boundary(command)
    ).qualify(_request(target_url=start, include_paths=("/news/**",)))
    assert report.qualified is False
    assert report.failure_code == "cloakbrowser.scope_rejected"
    audit_path = Path(command[1]).with_name("fake_audit.jsonl")
    audit = [
        json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert {"event": "abort", "url": outside} in audit
    assert {"event": "continue", "url": outside} not in audit
    assert not any(entry["event"] == "content" for entry in audit)


def _runtime_evidence(
    payload: dict[str, object], target: dict[str, object], proxy: str
) -> dict[str, object]:
    return {
        "schema_version": "phase-17-cloakbrowser-runtime-evidence.v2",
        "generation": 0,
        "observed_at_unix_ns": time.time_ns(),
        "previous_evidence_sha256": None,
        "attempt_nonce_sha256": None,
        "image": {
            "reference": payload["cloakbrowser"]["image"],
            "oci_index_digest": payload["cloakbrowser"]["oci_index_digest"],
            "platform": "linux/amd64",
            "platform_manifest_digest": payload["cloakbrowser"][
                "linux_amd64_manifest_digest"
            ],
        },
        "network": {
            "mode": "docker_internal_allowlist_proxy",
            "internal_network": True,
            "direct_egress": False,
            "allowlist_enforced": True,
            "allowed_origins": target["allowed_origins"],
            "proxy_identity": "offline-proxy-fixture",
            "proxy_url_sha256": hashlib.sha256(proxy.encode("utf-8")).hexdigest(),
        },
        "target": {
            "url": target["urls"]["monitor"],
            "allowed_origins": target["allowed_origins"],
        },
        "limits": payload["network_limits"],
        "observed": {
            "target_count": 0,
            "request_count": 0,
            "response_bytes": 0,
            "limit_exceeded": False,
        },
    }


def test_live_runtime_evidence_contract_uses_measured_proxy_counts(
    tmp_path: Path,
) -> None:
    live = runpy.run_path(str(ROOT / "tests/live/test_phase_17_cloakbrowser_live.py"))
    validate = live["_read_runtime_evidence"]
    payload = json.loads(TARGET_SNAPSHOT.read_bytes())
    target = payload["targets"][0]
    proxy = "http://proxy.test:8080"
    evidence = {
        "schema_version": "phase-17-cloakbrowser-runtime-evidence.v2",
        "generation": 0,
        "observed_at_unix_ns": time.time_ns(),
        "previous_evidence_sha256": None,
        "attempt_nonce_sha256": None,
        "image": {
            "reference": payload["cloakbrowser"]["image"],
            "oci_index_digest": payload["cloakbrowser"]["oci_index_digest"],
            "platform": "linux/amd64",
            "platform_manifest_digest": payload["cloakbrowser"][
                "linux_amd64_manifest_digest"
            ],
        },
        "network": {
            "mode": "docker_internal_allowlist_proxy",
            "internal_network": True,
            "direct_egress": False,
            "allowlist_enforced": True,
            "allowed_origins": target["allowed_origins"],
            "proxy_identity": "offline-proxy-fixture",
            "proxy_url_sha256": hashlib.sha256(proxy.encode("utf-8")).hexdigest(),
        },
        "target": {
            "url": target["urls"]["monitor"],
            "allowed_origins": target["allowed_origins"],
        },
        "limits": payload["network_limits"],
        "observed": {
            "target_count": 0,
            "request_count": 0,
            "response_bytes": 0,
            "limit_exceeded": False,
        },
    }
    path = tmp_path / "runtime-evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    _initial, snapshot = validate(
        path, payload, target, proxy, require_observation=False
    )
    nonce_sha256 = hashlib.sha256(b"fresh-offline-challenge").hexdigest()
    evidence.update(
        generation=1,
        observed_at_unix_ns=time.time_ns(),
        previous_evidence_sha256=snapshot["sha256"],
        attempt_nonce_sha256=nonce_sha256,
        observed={
            "target_count": 1,
            "request_count": 4,
            "response_bytes": 1024,
            "limit_exceeded": False,
        },
    )
    time.sleep(0.02)
    replacement = tmp_path / "runtime-evidence.next.json"
    replacement.write_text(json.dumps(evidence), encoding="utf-8")
    replacement.replace(path)
    observed, _final_snapshot = validate(
        path,
        payload,
        target,
        proxy,
        require_observation=True,
        initial_snapshot=snapshot,
        expected_nonce_sha256=nonce_sha256,
    )
    assert observed["observed"] == {
        "target_count": 1,
        "request_count": 4,
        "response_bytes": 1024,
        "limit_exceeded": False,
    }


@pytest.mark.parametrize("case", ["stale", "prepopulated"])
def test_live_runtime_evidence_rejects_invalid_initial_generation(
    tmp_path: Path, case: str
) -> None:
    live = runpy.run_path(str(ROOT / "tests/live/test_phase_17_cloakbrowser_live.py"))
    validate = live["_read_runtime_evidence"]
    payload = json.loads(TARGET_SNAPSHOT.read_bytes())
    target = payload["targets"][0]
    proxy = "http://proxy.test:8080"
    evidence = _runtime_evidence(payload, target, proxy)
    if case == "stale":
        evidence["observed_at_unix_ns"] = time.time_ns() - 121_000_000_000
    else:
        evidence["observed"]["request_count"] = 1
    path = tmp_path / "runtime-evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(ValueError, match="stale|observed"):
        validate(path, payload, target, proxy, require_observation=False)


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("nonce", "attempt binding"),
        ("generation", "attempt binding"),
        ("digest", "attempt binding"),
        ("non_atomic", "non-atomic or time reversal"),
        ("time_reverse", "non-atomic or time reversal"),
    ],
)
def test_live_runtime_evidence_rejects_unbound_final_generation(
    tmp_path: Path, case: str, expected: str
) -> None:
    live = runpy.run_path(str(ROOT / "tests/live/test_phase_17_cloakbrowser_live.py"))
    validate = live["_read_runtime_evidence"]
    payload = json.loads(TARGET_SNAPSHOT.read_bytes())
    target = payload["targets"][0]
    proxy = "http://proxy.test:8080"
    evidence = _runtime_evidence(payload, target, proxy)
    path = tmp_path / "runtime-evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    _initial, snapshot = validate(
        path, payload, target, proxy, require_observation=False
    )
    nonce_sha256 = hashlib.sha256(b"fresh-offline-challenge").hexdigest()
    time.sleep(0.02)
    evidence.update(
        generation=1,
        observed_at_unix_ns=time.time_ns(),
        previous_evidence_sha256=snapshot["sha256"],
        attempt_nonce_sha256=nonce_sha256,
        observed={
            "target_count": 1,
            "request_count": 1,
            "response_bytes": 32,
            "limit_exceeded": False,
        },
    )
    if case == "nonce":
        evidence["attempt_nonce_sha256"] = "0" * 64
    elif case == "generation":
        evidence["generation"] = 2
    elif case == "digest":
        evidence["previous_evidence_sha256"] = "0" * 64
    elif case == "time_reverse":
        evidence["observed_at_unix_ns"] = snapshot["observed_at_unix_ns"]
    if case == "non_atomic":
        path.write_text(json.dumps(evidence), encoding="utf-8")
    else:
        replacement = tmp_path / "runtime-evidence.next.json"
        replacement.write_text(json.dumps(evidence), encoding="utf-8")
        replacement.replace(path)
    with pytest.raises(ValueError, match=expected):
        validate(
            path,
            payload,
            target,
            proxy,
            require_observation=True,
            initial_snapshot=snapshot,
            expected_nonce_sha256=nonce_sha256,
        )


def test_live_failure_prints_actual_exit_and_cleanup_without_swallowing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    live = runpy.run_path(str(ROOT / "tests/live/test_phase_17_cloakbrowser_live.py"))
    test_live = live["test_phase_17_cloakbrowser_live"]
    function_globals = test_live.__globals__
    payload = json.loads(TARGET_SNAPSHOT.read_bytes())
    target = payload["targets"][0]
    source = _source(tmp_path, scenario={"timeout": True}, name="live-fixture")
    boundary = NetworkBoundary(
        kind="controlled_proxy",
        allowed_origins=tuple(target["allowed_origins"]),
        proxy_server="http://proxy.test:8080",
        browser_profile_home=str(_profile_home(tmp_path, "live-profile")),
        observation_reader=_unobserved,
    )
    function_globals["SOURCE"] = source
    function_globals["_authorized_context"] = lambda: (
        payload,
        "offline-authorized",
        boundary,
        {},
        {},
    )
    function_globals["_cloakbrowser_info"] = lambda: {
        "environment": {"wrapper": VERSION},
        "binary": {"bundled_version": "146.0.7680.177.5"},
        "launch": {"version": "146.0.7680.177", "tested": True, "ok": True},
    }
    monkeypatch.setattr(importlib.metadata, "version", lambda _name: VERSION)
    emitted: list[str] = []
    monkeypatch.setattr(
        builtins,
        "print",
        lambda *values, **_kwargs: emitted.append(" ".join(map(str, values))),
    )
    attempt_root = tmp_path / "live-attempt"
    attempt_root.mkdir()
    with pytest.raises(pytest.fail.Exception, match="cloakbrowser.timeout"):
        test_live(attempt_root, capsys)
    record = json.loads(emitted[-1])["phase_17_live_evidence"]
    assert record["tool_result"]["code"] == "cloakbrowser.timeout"
    assert record["exit_code"] == 0
    assert record["cleanup"] == {
        "preflight_browser_closed": True,
        "fetch_browser_closed": False,
        "attempt_directory_cleaned": True,
    }


@pytest.mark.parametrize(
    ("scenario", "request_kwargs", "expected"),
    [
        ({"timeout": True}, {}, "cloakbrowser.timeout"),
        (
            {"body": "x" * 65, "mime_type": "text/html", "status_code": 200},
            {"max_bytes": 64},
            "isolated_runtime.proxy_response_limit",
        ),
        (
            {
                "body": "x" * 65,
                "mime_type": "text/html",
                "status_code": 200,
                "omit_content_length": True,
            },
            {"max_bytes": 64},
            "isolated_runtime.proxy_response_limit",
        ),
    ],
)
def test_adapter_enforces_timeout_and_output_bound(
    tmp_path: Path,
    scenario: dict[str, object],
    request_kwargs: dict[str, int],
    expected: str,
) -> None:
    _lifecycle, manifest, command = _installed(tmp_path, scenario=scenario)
    report = IsolatedRuntime(
        manifest, command, "offline-authorized", _boundary(command)
    ).qualify(_request(**request_kwargs))
    assert report.qualified is False
    assert report.failure_code == expected


def test_proxy_cumulative_response_limit_keeps_tool_unqualified(
    tmp_path: Path,
) -> None:
    _lifecycle, manifest, command = _installed(
        tmp_path,
        scenario={
            "body": "x" * 32,
            "mime_type": "text/html",
            "status_code": 200,
            "subresponses": [
                {"url": ORIGIN + "/one.js", "response_bytes": 24},
                {"url": ORIGIN + "/two.css", "response_bytes": 24},
            ],
        },
    )
    runtime = IsolatedRuntime(
        manifest, command, "offline-authorized", _boundary(command)
    )
    report = runtime.qualify(_request(max_requests=4, max_bytes=64))
    assert report.qualified is False
    assert report.failure_code == "isolated_runtime.proxy_response_limit"
    assert dict(report.checks)["output_bound"] is False
    assert runtime.manifest.qualification is QualificationStatus.UNQUALIFIED


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("url", "runner.output_mismatch"),
        ("path", "runner.output_path_invalid"),
        ("mime", "runner.output_mismatch"),
        ("size", "runner.output_mismatch"),
        ("sha256", "runner.output_mismatch"),
    ],
)
def test_parent_rechecks_external_url_path_mime_size_and_hash(
    tmp_path: Path, case: str, expected: str
) -> None:
    _lifecycle, manifest, _command = _installed(tmp_path)
    manifest = replace(manifest, qualification=QualificationStatus.QUALIFIED)
    result = SubprocessRunner(manifest, (sys.executable, str(MISREPORT), case)).invoke(
        _request()
    )
    assert isinstance(result, AcquisitionFailure)
    assert result.code == expected


def test_disable_and_rollback_remain_effective(tmp_path: Path) -> None:
    lifecycle, manifest, command = _installed(tmp_path)
    runtime = IsolatedRuntime(
        manifest,
        command,
        "offline-authorized",
        _boundary(command),
        state_reader=lambda: lifecycle.inspect(
            ToolCategory.ACQUISITION, TOOL_ID, VERSION
        ),
    )
    assert runtime.qualify(_request()).qualified is True
    disabled = lifecycle.disable(ToolCategory.ACQUISITION, TOOL_ID, VERSION)
    assert disabled.disabled is True
    blocked = runtime.invoke(_request())
    assert isinstance(blocked, AcquisitionFailure)
    assert blocked.code == "isolated_runtime.disabled"
    with pytest.raises(ToolLifecycleError, match="lifecycle.rollback_invalid"):
        lifecycle.rollback(ToolCategory.ACQUISITION, TOOL_ID, VERSION)


def test_adapter_has_no_policy_storage_or_second_browser_authority() -> None:
    paths = [
        SOURCE / "tool.py",
        ROOT / "src/web_listening/tool_registry/runners/isolated_runtime.py",
    ]
    imports: set[str] = set()
    text = ""
    for path in paths:
        source = path.read_text(encoding="utf-8")
        text += source
        tree = ast.parse(source, filename=str(path))
        imports.update(
            (node.module or "")
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
    assert imports.isdisjoint(
        {
            "web_listening.artifact.store",
            "web_listening.result",
            "web_listening.runtime",
            "web_listening.site_skill",
        }
    )
    for token in (
        "playwright",
        "browseract",
        "robots.txt",
        "ArtifactStore",
        "SiteSkill",
        "fallback",
        "login",
    ):
        assert token.casefold() not in text.casefold()
    assert all(OLD_COMMIT in row[0] for row in MIGRATION)
    assert len(MIGRATION) == 6
