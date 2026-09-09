"""Issue 102 parent-owned browser integration contracts (offline by default)."""

# Intentional cross-test fixtures: pytest resolves the repository namespace.
# pylint: disable=import-error
# pylint: disable=missing-function-docstring,duplicate-code,protected-access,too-many-lines

import base64
import hashlib
import json
import os
import runpy
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import asdict, fields, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.tool_registry.test_access_gateway import Resolver
from tests.tool_registry.test_browser_network import ORIGIN, bridge, request
from web_listening.runtime import service as service_module
from web_listening.tool_registry.acquisition.builtins.web_http import WEB_HTTP_MANIFEST
from web_listening.tool_registry.lifecycle import ToolLifecycle
from web_listening.tool_registry.manifest import ToolCategory, ToolRegistryError
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionInput,
    AcquisitionOutput,
    ParentMeasuredAcquisitionOutput,
)
from web_listening.tool_registry.registry import _validate_output
from web_listening.tool_registry.runners import browser_acquisition as composition
from web_listening.tool_registry.runners import in_process
from web_listening.tool_registry.runners import subprocess as runner_module
from web_listening.tool_registry.runners.browser_acquisition import (
    BrowserAcquisitionTool,
    installed_browser_tools,
)
from web_listening.tool_registry.runners.browser_network import BrowserNetworkBridge
from web_listening.tool_registry.runners.isolated_runtime import IsolatedRuntime


def test_parent_measured_rendered_output_preserves_network_bytes_and_wire_fields():
    body = b"<main>" + b"Governed browser content. " * 200 + b"</main>"
    output = ParentMeasuredAcquisitionOutput(
        "acquisition.playwright",
        "1.0.0",
        "https://example.test/",
        "https://example.test/",
        200,
        "text/html",
        body,
        hashlib.sha256(body).hexdigest(),
        (),
        10,
        requests=3,
        bytes_received=209,
    )
    assert output.bytes_received == 209 < len(body)
    assert fields(output) == fields(AcquisitionOutput)
    for values in (
        {"bytes_received": -1},
        {"requests": 0},
        {"bytes_received": True},
        {"sha256": "0" * 64},
    ):
        with pytest.raises(ToolRegistryError):
            replace(output, **values)
    legacy = AcquisitionOutput(
        "acquisition.playwright",
        "1.0.0",
        "https://example.test/",
        "https://example.test/",
        200,
        "text/html",
        body,
        hashlib.sha256(body).hexdigest(),
        (),
        10,
    )
    assert legacy.bytes_received == len(body)
    with pytest.raises(ToolRegistryError, match="protocol.usage_invalid"):
        replace(legacy, requests=3, bytes_received=209)


@pytest.mark.parametrize(
    "name,version", [("playwright", "1.0.0"), ("cloakbrowser", "0.5.9")]
)
def test_production_adapter_describe_is_dependency_lazy(name, version):
    source = Path(__file__).parents[2] / "tools/browser" / name / version
    envelope = {
        "protocol_version": "web-listening-tool-qualification.v1",
        "operation": "describe",
        "tool_id": "acquisition." + name,
        "version": version,
        "category": "acquisition",
    }
    completed = subprocess.run(
        (sys.executable, str(source / "tool.py")),
        input=json.dumps(envelope),
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {**envelope, "status": "ok"}


FAKE_SDK = """
import json
class Request:
    def __init__(self, url, navigation):
        self.url, self.method, self.navigation = url, 'GET', navigation
    def is_navigation_request(self): return self.navigation
class Route:
    def __init__(self, url, navigation): self.request = Request(url, navigation)
    def fulfill(self, **values):
        if 300 <= values['status'] < 400: raise RuntimeError('native redirect denied')
        self.values = values
    @property
    def _impl_obj(self): return self
    async def _redirected_navigation_request(self, url): self.values = {'replay_url': url}
    def _sync(self, operation):
        try: operation.send(None)
        except StopIteration as done: return done.value
    def abort(self, reason): raise RuntimeError(reason)
class Response:
    def __init__(self, status): self.status = status
class Page:
    def __init__(self, context): self.context = context
    def goto(self, url, **options):
        route = Route(url, True)
        self.context.handler(route)
        replayed = 'replay_url' in route.values
        while 'replay_url' in route.values:
            url = route.values['replay_url']
            route = Route(url, True)
            self.context.handler(route)
        self.url = url
        self.body = route.values['body']
        if b'app.js' in self.body:
            from urllib.parse import urljoin
            script = Route(urljoin(url, '/app.js'), False)
            self.context.handler(script)
            data = Route(urljoin(url, '/data.json'), False)
            self.context.handler(data)
            value = json.loads(data.values['body'])['value']
            self.body = ('<html><body><main>' + value * 200 + '</main></body></html>').encode()
        self.ready_body = self.body
        if replayed: self.body = b'<script>pending asynchronous render</script>'
        return Response(route.values['status'])
    def wait_for_load_state(self, state, **options):
        assert state == 'networkidle' and options['timeout'] > 0
        self.body = self.ready_body
    def content(self): return self.body.decode()
    def close(self): pass
class Context:
    def route(self, pattern, handler): self.handler = handler
    def route_web_socket(self, pattern, handler): pass
    def new_page(self): return Page(self)
    def close(self): pass
class Browser:
    version = '151.0.7922.34'
    def new_context(self, **options): return Context()
    def close(self): pass
class Chromium:
    def launch(self, **options): return Browser()
class Playwright:
    chromium = Chromium()
    def start(self): return self
    def stop(self): pass
def sync_playwright(): return Playwright()
def launch(**options): return Browser()
"""


def fixture_runtime_config(tmp_path, name, entry):
    """Describe explicitly fake runtime files, never production qualification."""
    root = tmp_path / "data/browser-runtimes" / name
    config = {
        "python": str(root / "bin/python"),
        "sdk": name,
        "sdk_version": entry["sdk_version"],
        "browser": str(root / "fake-browser"),
        "browser_sha256": hashlib.sha256(
            b"explicit offline fixture, not a browser"
        ).hexdigest(),
        "browser_version": entry["browser_version"],
        "browser_channel": entry["browser_channel"],
    }
    if name == "playwright":
        config.update(
            browser=str(
                root
                / "browsers"
                / ("chromium-" + entry["browser_revision"])
                / "chrome-linux64/chrome"
            ),
            browser_revision=entry["browser_revision"],
            sdk_tree_sha256=entry["sdk_tree_sha256"],
        )
    else:
        config.update(
            container_image=entry["image"],
            docker=sys.executable,
            browser_build=entry["browser_build"],
        )
    return config


def offline_runtime_lock(monkeypatch, tmp_path):
    """Trust only a test-owned lock for fake SDKs; production keeps its frozen SHA."""
    lock = json.loads(
        (Path(__file__).parents[2] / "tools/browser/runtime-lock.json").read_bytes()
    )
    package = tmp_path / "fixture-sdk"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "sync_api.py").write_text(FAKE_SDK)
    lock["tools"]["playwright"]["sdk_tree_sha256"] = composition.tree_digest(package)
    for entry in lock["tools"].values():
        entry["browser_version"] = "151.0.7922.34"
        entry["browser_sha256"] = hashlib.sha256(
            b"explicit offline fixture, not a browser"
        ).hexdigest()
    lock_bytes = json.dumps(lock, sort_keys=True).encode()
    (tmp_path / "fixture-runtime-lock.json").write_bytes(lock_bytes)
    monkeypatch.setattr(
        composition,
        "FROZEN_RUNTIME_LOCK_SHA256",
        hashlib.sha256(lock_bytes).hexdigest(),
    )
    # Docker is unavailable here. Simulate measurement from the fixed test image,
    # independently of the installed runtime.json under test.
    monkeypatch.setattr(
        composition,
        "cloak_runtime",
        lambda entry, _docker: fixture_runtime_config(tmp_path, "cloakbrowser", entry),
    )


def fake_install(
    tmp_path,
    name="playwright",
    version="1.0.0",
    *,
    installed_version=None,
    mutate_source=None,
):  # pylint: disable=too-many-locals
    """Install the production adapter beside an explicitly fake offline SDK."""
    runtime_dir = tmp_path / "data/browser-runtimes" / name
    subprocess.run(
        (sys.executable, "-m", "venv", "--without-pip", str(runtime_dir)), check=True
    )
    library = (
        runtime_dir
        / f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
    )
    package = library / name
    package.mkdir()
    (package / "__init__.py").write_text(FAKE_SDK if name == "cloakbrowser" else "")
    if name == "playwright":
        (package / "sync_api.py").write_text(FAKE_SDK)
    sdk_version = "1.62.0" if name == "playwright" else "0.5.9"
    metadata = library / f"{name}-{sdk_version}.dist-info"
    metadata.mkdir()
    (metadata / "METADATA").write_text(f"Name: {name}\nVersion: {sdk_version}\n")
    lock_path = tmp_path / "fixture-runtime-lock.json"
    if not lock_path.exists():
        lock_path = Path(__file__).parents[2] / "tools/browser/runtime-lock.json"
    lock_bytes = lock_path.read_bytes()
    entry = json.loads(lock_bytes)["tools"][name]
    config = fixture_runtime_config(tmp_path, name, entry)
    binary = Path(config["browser"])
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(b"explicit offline fixture, not a browser")
    source = tmp_path / (name + "-source")
    shutil.copytree(
        Path(__file__).parents[2] / "tools/browser" / name / version, source
    )
    if installed_version is not None:
        manifest = json.loads((source / "tool.json").read_text())
        manifest["source"]["version"] = installed_version
        manifest["manifest"]["version"] = installed_version
        (source / "tool.json").write_text(json.dumps(manifest))
        adapter = source / "tool.py"
        adapter.write_text(
            adapter.read_text().replace(
                f'VERSION = "{version}"', f'VERSION = "{installed_version}"'
            )
        )
        version = installed_version
    (source / "runtime-lock.json").write_bytes(lock_bytes)
    (source / "runtime.json").write_text(json.dumps(config))
    if mutate_source is not None:
        mutate_source(source)
    lifecycle = ToolLifecycle(tmp_path / "data")
    state = lifecycle.install(source)
    command = (
        sys.executable,
        str(
            tmp_path
            / "data/tools/acquisition"
            / ("acquisition." + name)
            / version
            / "tool.py"
        ),
    )
    tool = BrowserAcquisitionTool(
        state.manifest,
        command,
        lifecycle,
        transport_factory=lambda: bridge()[1],
        resolver=Resolver(),
    )
    runtime, report = tool.qualify(
        AcquisitionInput(request(), "https://example.com/"), "offline-fixture"
    )
    assert report.qualified, report.failure_code
    lifecycle.activate_qualified(runtime, report)
    assert lifecycle.active(ToolCategory.ACQUISITION, "acquisition." + name)
    return lifecycle, report


def test_installed_production_adapter_uses_parent_js_reads_and_qualification_once(
    tmp_path,
    monkeypatch,
):
    offline_runtime_lock(monkeypatch, tmp_path)
    try:
        probe = socket.socket()
    except PermissionError:
        pytest.skip(
            "sandbox prohibits AF_INET; controller must run loopback IPC validation"
        )
    probe.close()
    lifecycle, report = fake_install(tmp_path)
    assert report.result.requests == 4
    assert report.result.bytes_received < len(report.result.body)
    assert len(report.result.robots_decisions) == 3
    assert len(installed_browser_tools(lifecycle.data_root)) == 1


def test_lock_pins_delivered_adapters_and_exact_reviewed_public_targets():
    root = Path(__file__).parents[2]
    lock_bytes = (root / "tools/browser/runtime-lock.json").read_bytes()
    assert (
        hashlib.sha256(lock_bytes).hexdigest() == composition.FROZEN_RUNTIME_LOCK_SHA256
    )
    lock = json.loads(lock_bytes)
    for name, entry in lock["tools"].items():
        directory = root / "tools/browser" / name / entry["adapter_version"]
        for filename in ("tool.py", "tool.json"):
            assert (
                entry["adapter_files_sha256"][filename]
                == hashlib.sha256((directory / filename).read_bytes()).hexdigest()
            )
    snapshot = json.loads((root / "tests/live/browser_chain_targets.json").read_bytes())
    catalog = root / snapshot["source_catalog"]
    assert (
        snapshot["source_catalog_sha256"]
        == hashlib.sha256(catalog.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    )
    assert [(item["site_key"], item["target_url"]) for item in snapshot["targets"]] == [
        ("ipcc", "https://www.ipcc.ch/"),
        ("tnfd", "https://tnfd.global/news/"),
    ]
    assert snapshot["limits"] == {
        "targets": 2,
        "requests": 36,
        "bytes": 16 * 1024 * 1024,
        "seconds": 120,
        "concurrency": 1,
        "retry": 0,
    }


def offline_adapter_io(monkeypatch, tmp_path):
    """Use a fake lock, IPC and SDK; run installed adapter/runner decoding.

    The real loopback subprocess case above remains a separate controller gate.
    """
    offline_runtime_lock(monkeypatch, tmp_path)
    current = {}
    sdk = {}
    exec(FAKE_SDK, sdk)  # pylint: disable=exec-used

    def start(reader):
        current["reader"] = reader
        return "http://127.0.0.1:9999"

    def adapter(command):
        namespace = runpy.run_path(command[1])
        namespace = namespace["_acquire"].__globals__
        boundary = json.loads(base64.urlsafe_b64decode(command[-1]))
        configuration = json.loads(
            Path(command[1]).with_name("runtime.json").read_bytes()
        )
        namespace["_boundary"] = lambda: boundary
        namespace["_configuration"] = lambda: configuration
        browser = sdk["Browser"]()
        browser.version = configuration["browser_version"]
        namespace["_launch"] = lambda *_args: (browser, None)

        def ipc(_boundary, path, **values):
            reader = current["reader"]
            reader._nonce_hash = hashlib.sha256(
                boundary["attempt_nonce"].encode()
            ).hexdigest()
            if path == "/status":
                return reader.status()
            response = dict(
                reader.read(
                    values["url"],
                    values["method"],
                    navigation=values["navigation"],
                    main_document=values.get("main_document", True),
                )
            )
            if "body" in response:
                response["body"] = base64.b64encode(response["body"]).decode()
            return response

        namespace["_ipc"] = ipc
        return namespace

    def control(runtime, command, operation, checks):
        value = {
            "protocol_version": "web-listening-tool-qualification.v1",
            "operation": operation,
            "tool_id": runtime.manifest.tool_id,
            "version": runtime.manifest.version,
            "category": "acquisition",
        }
        if operation == "probe":
            value["checks"] = list(checks)
        return adapter(command)["_control"](value)

    original_execute = runner_module.SubprocessRunner._execute

    def execute(runner, wire, attempt_directory, started, runtime_seconds):
        if "--web-listening-boundary" not in runner._command:
            return original_execute(
                runner, wire, attempt_directory, started, runtime_seconds
            )
        namespace = adapter(runner._command)
        before = Path.cwd()
        try:
            os.chdir(attempt_directory)
            output = namespace["_acquire"](json.loads(wire))
            return None, json.dumps(output).encode()
        finally:
            os.chdir(before)

    monkeypatch.setattr(BrowserNetworkBridge, "start", start)
    monkeypatch.setattr(IsolatedRuntime, "_run_control", control)
    monkeypatch.setattr(runner_module.SubprocessRunner, "_execute", execute)


@pytest.mark.parametrize(
    "scenario,expected",
    [
        ("http", ["acquisition.web_http"]),
        ("browser", ["acquisition.web_http", "acquisition.playwright"]),
        (
            "cloak",
            [
                "acquisition.web_http",
                "acquisition.playwright",
                "acquisition.cloakbrowser",
            ],
        ),
        (
            "resource-failed",
            [
                "acquisition.web_http",
                "acquisition.playwright",
                "acquisition.cloakbrowser",
            ],
        ),
        (
            "failed",
            [
                "acquisition.web_http",
                "acquisition.playwright",
                "acquisition.cloakbrowser",
            ],
        ),
        ("switch-disabled", ["acquisition.web_http"]),
        ("auth", ["acquisition.web_http"]),
        ("robots-denied", ["acquisition.web_http"]),
        ("budget", ["acquisition.web_http"]),
    ],
)
def test_runtime_opens_installed_defaults_and_commits_only_valid_content(
    tmp_path, monkeypatch, scenario, expected
):
    offline_adapter_io(monkeypatch, tmp_path)
    fake_install(tmp_path)
    if scenario in {"cloak", "failed", "resource-failed"}:
        fake_install(tmp_path, "cloakbrowser", "0.5.9")
    transports = []
    browser_budgets = []
    qualify = BrowserAcquisitionTool.qualify

    def record_qualification(tool, tool_input, *args, **kwargs):
        browser_budgets.append(tool_input.request.budgets)
        return qualify(tool, tool_input, *args, **kwargs)

    monkeypatch.setattr(BrowserAcquisitionTool, "qualify", record_qualification)

    def transport():
        value = bridge()[1]
        body = (
            b"<main>Valid governed public content</main>"
            if scenario == "http"
            else b"<script src='/app.js'></script>"
        )
        if scenario == "failed" or (scenario == "cloak" and len(transports) == 1):
            body = b"<title>Just a moment...</title><script></script>"
        if scenario == "resource-failed" and len(transports) == 1:
            value.scripts[ORIGIN + "/app.js"][0].status = 404
        if scenario == "auth":
            value.scripts[ORIGIN + "/"][0].status = 401
        if scenario == "robots-denied":
            value.scripts[ORIGIN + "/robots.txt"][
                0
            ].body = b"User-agent: *\nDisallow: /\n"
        value.scripts[ORIGIN + "/"][0].body = body
        transports.append(value)
        return value

    monkeypatch.setattr(service_module, "PinnedHttpTransport", transport)
    monkeypatch.setattr(
        in_process, "_resolve_public_addresses", lambda *_args: ("93.184.216.34",)
    )
    runtime = service_module.RuntimeService.open(tmp_path / "data")
    try:
        req = request(2 if scenario == "budget" else 12)
        if scenario == "switch-disabled":
            req = replace(req, explore_all_tools=False)
        job = runtime.run(req)
        assert [
            attempt.tool_id
            for attempt in job.result.attempts
            if attempt.tool_id.startswith("acquisition.")
            and attempt.outcome != "skipped"
        ] == expected
        assert job.result.usage.requests == sum(
            len(item.requests) for item in transports
        )
        successful = scenario in {"http", "browser", "cloak", "resource-failed"}
        assert bool(job.result.artifacts) is successful
        if scenario == "resource-failed":
            attempts = [
                item
                for item in job.result.attempts
                if item.tool_id.startswith("acquisition.") and item.outcome != "skipped"
            ]
            assert [item.error.code if item.error else None for item in attempts] == [
                "acquisition.script_only",
                "browser.resource_failed",
                None,
            ]
            assert job.result.usage.requests == 9
            assert job.result.usage.bytes_received == sum(
                item.bytes_received for item in attempts
            )
            assert [budget.max_requests for budget in browser_budgets] == [10, 7]
            assert [budget.max_bytes for budget in browser_budgets] == [
                req.budgets.max_bytes
                - sum(item.bytes_received for item in attempts[:index])
                for index in (1, 2)
            ]
        if successful:
            source = next(
                item for item in job.result.artifacts if item.role == "source"
            )
            assert (
                hashlib.sha256(
                    runtime.read_artifact(source.artifact_id).content
                ).hexdigest()
                == source.sha256
            )
        assert all(item.closed == 1 for item in transports)
    finally:
        runtime.close()


def test_http_uses_shared_absolute_deadline_and_auth_is_terminal(monkeypatch):
    transport = bridge()[1]
    transport.scripts[ORIGIN + "/"][0].status = 401
    observed = []
    original = composition.WebHttpAcquisitionTool

    def factory(*args, **kwargs):
        observed.append(kwargs["runtime_deadline"])
        return original(*args, **kwargs)

    monkeypatch.setattr(composition, "WebHttpAcquisitionTool", factory)
    deadline = time.monotonic() + 5
    tool = composition.GovernedHttpAcquisitionTool(
        lambda: transport, resolver=Resolver()
    )
    try:
        with composition.acquisition_execution(lambda: False, deadline):
            output = tool.acquire(AcquisitionInput(request(), ORIGIN + "/"))
        assert output.code == "acquisition.auth_required"
        assert observed == [deadline]
        assert output.requests == 2 and transport.closed == 1
    finally:
        tool.close()


def test_rendered_expansion_fits_network_budget_through_installed_runner(
    tmp_path, monkeypatch
):
    """Network bytes and rendered bytes have independent authoritative limits."""

    offline_adapter_io(monkeypatch, tmp_path)
    lifecycle, _ = fake_install(tmp_path)
    installed = lifecycle.active(ToolCategory.ACQUISITION, "acquisition.playwright")
    command = (
        sys.executable,
        str(
            lifecycle.data_root
            / "tools/acquisition/acquisition.playwright/1.0.0/tool.py"
        ),
    )
    tool = BrowserAcquisitionTool(
        installed.manifest,
        command,
        lifecycle,
        transport_factory=lambda: bridge()[1],
        resolver=Resolver(),
    )
    req = request()
    req = replace(req, budgets=replace(req.budgets, max_bytes=512))
    try:
        output = tool.acquire(AcquisitionInput(req, ORIGIN + "/"))
        assert isinstance(output, AcquisitionOutput), getattr(output, "code", None)
        assert output.bytes_received < 512 < len(output.body)
        assert output.requests == 4
    finally:
        tool.close()


@pytest.mark.parametrize(
    "state,reason",
    [
        ("absent", "eligibility.not_installed"),
        ("disabled", "eligibility.disabled"),
        ("wrong-version", "eligibility.version_mismatch"),
    ],
)
def test_runtime_reopen_reports_unavailable_browser_without_execution(
    tmp_path, monkeypatch, state, reason
):
    offline_adapter_io(monkeypatch, tmp_path)
    if state == "wrong-version":
        lifecycle, _ = fake_install(tmp_path, installed_version="9.9.9")
        assert (
            lifecycle.active(
                ToolCategory.ACQUISITION, "acquisition.playwright"
            ).manifest.version
            == "9.9.9"
        )
        assert not installed_browser_tools(tmp_path / "data")
    if state == "disabled":
        lifecycle, _ = fake_install(tmp_path)
        lifecycle.disable(ToolCategory.ACQUISITION, "acquisition.playwright", "1.0.0")
    transports = []

    def transport():
        result = bridge()[1]
        transports.append(result)
        return result

    monkeypatch.setattr(service_module, "PinnedHttpTransport", transport)
    monkeypatch.setattr(
        in_process, "_resolve_public_addresses", lambda *_args: ("93.184.216.34",)
    )
    runtime = service_module.RuntimeService.open(tmp_path / "data")
    try:
        job = runtime.run(request(12))
        attempts = job.result.attempts
        skipped = {
            item.tool_id: item.error.code
            for item in attempts
            if item.outcome == "skipped"
        }
        assert skipped["acquisition.playwright"] == reason
        if state == "wrong-version":
            assert (
                next(
                    item.tool_version
                    for item in attempts
                    if item.tool_id == "acquisition.playwright"
                )
                == "9.9.9"
            )
            assert (
                ToolLifecycle(tmp_path / "data")
                .active(ToolCategory.ACQUISITION, "acquisition.playwright")
                .manifest.version
                == "9.9.9"
            )
        assert skipped["acquisition.cloakbrowser"] == "eligibility.not_installed"
        assert len(transports) == 1 and transports[0].closed == 1
        assert not job.result.artifacts
    finally:
        runtime.close()


def test_registry_rejects_unsealed_parent_output_and_preserves_render_limit():
    body = b"<p>Rendered output beyond network bytes</p>"
    output = ParentMeasuredAcquisitionOutput(
        "acquisition.web_http",
        "1.0.0",
        ORIGIN + "/",
        ORIGIN + "/",
        200,
        "text/html",
        body,
        hashlib.sha256(body).hexdigest(),
        (),
        1,
        requests=2,
        bytes_received=1,
    )
    with pytest.raises(ToolRegistryError):
        _validate_output(
            WEB_HTTP_MANIFEST, AcquisitionInput(request(), ORIGIN + "/"), output
        )
    reader, _ = bridge()
    try:
        assert reader.read(ORIGIN + "/", "GET", navigation=True)["ok"]
        sealed = reader.normalize(output)
        limited = replace(
            WEB_HTTP_MANIFEST,
            limits=replace(WEB_HTTP_MANIFEST.limits, max_output_bytes=1),
        )
        with pytest.raises(ToolRegistryError, match="registry.output_limit"):
            _validate_output(limited, AcquisitionInput(request(), ORIGIN + "/"), sealed)
    finally:
        reader.close()


@pytest.mark.parametrize(
    "name,version", [("playwright", "1.0.0"), ("cloakbrowser", "0.5.9")]
)
@pytest.mark.parametrize(
    "mutation",
    [
        "binary",
        "adapter",
        "sdk",
        "version",
        "build",
        "channel",
        "lock",
        "missing-lock",
        "image",
    ],
)
def test_runtime_reopen_excludes_self_consistent_substitute_browser(
    tmp_path, monkeypatch, name, version, mutation
):
    offline_adapter_io(monkeypatch, tmp_path)

    def substitute(source):
        config = json.loads((source / "runtime.json").read_bytes())
        if mutation == "binary":
            binary = tmp_path / "substitute-browser"
            binary.write_bytes(
                b"a different executable with a self-consistent identity"
            )
            config["browser"] = str(binary)
            config["browser_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        elif mutation == "adapter":
            adapter = source / "tool.py"
            adapter.write_text(adapter.read_text() + "\n# substitute adapter\n")
        elif mutation == "sdk":
            if name == "playwright":
                package = (
                    Path(config["python"]).parent.parent
                    / "lib/python3.12/site-packages/playwright"
                )
                (package / "__init__.py").write_text("# substitute SDK\n")
                config["sdk_tree_sha256"] = composition.tree_digest(package)
            else:
                config["sdk_version"] = "9.9.9"
        elif mutation == "version":
            config["browser_version"] = "999.0.0.0"
        elif mutation == "build":
            config["browser_revision" if name == "playwright" else "browser_build"] = (
                "999"
            )
        elif mutation == "channel":
            config["browser_channel"] = "substitute"
        elif mutation == "lock":
            lock = json.loads((source / "runtime-lock.json").read_bytes())
            lock["tools"][name]["browser_version"] = "999"
            (source / "runtime-lock.json").write_text(json.dumps(lock))
        elif mutation == "missing-lock":
            (source / "runtime-lock.json").unlink()
        else:
            config["container_image"] = "substitute@sha256:" + "0" * 64
        (source / "runtime.json").write_text(json.dumps(config))

    lifecycle, _ = fake_install(tmp_path, name, version, mutate_source=substitute)
    assert lifecycle.active(ToolCategory.ACQUISITION, "acquisition." + name)
    runtime = service_module.RuntimeService.open(tmp_path / "data")
    try:
        assert not installed_browser_tools(tmp_path / "data")
        exclusions = composition.browser_catalog_exclusions(tmp_path / "data", set())
        assert (
            next(
                reason
                for manifest, reason in exclusions
                if manifest.tool_id == "acquisition." + name
            )
            == "eligibility.runtime_identity_mismatch"
        )
    finally:
        runtime.close()


def test_installer_persists_frozen_lock_before_qualification(tmp_path, monkeypatch):
    installer = runpy.run_path(
        str(Path(__file__).parents[2] / "tools/browser/install.py")
    )
    install = installer["install"]
    install.__globals__["host_runtime"] = lambda *_args: {"explicit": "offline fixture"}
    original = ToolLifecycle.install

    def stop_after_atomic_install(lifecycle, source):
        original(lifecycle, source)
        raise ValueError("offline.stop_before_qualification")

    monkeypatch.setattr(ToolLifecycle, "install", stop_after_atomic_install)
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(asdict(request())))
    with pytest.raises(ValueError, match="offline.stop_before_qualification"):
        install(
            SimpleNamespace(
                action="install",
                tool="playwright",
                version=None,
                data_dir=str(tmp_path / "data"),
                runtime_root=str(tmp_path / "runtime"),
                request=str(request_path),
                authorization_window="explicit offline test",
            )
        )
    installed = tmp_path / "data/tools/acquisition/acquisition.playwright/1.0.0"
    assert (
        hashlib.sha256((installed / "runtime-lock.json").read_bytes()).hexdigest()
        == composition.FROZEN_RUNTIME_LOCK_SHA256
    )
    state = ToolLifecycle(tmp_path / "data").inspect(
        ToolCategory.ACQUISITION, "acquisition.playwright", "1.0.0"
    )
    assert not state.qualified and not state.active


@pytest.mark.parametrize("alternate", [False, True])
def test_cloak_identity_measurement_uses_frozen_image_without_network(
    monkeypatch, alternate
):
    entry = json.loads(
        (Path(__file__).parents[2] / "tools/browser/runtime-lock.json").read_bytes()
    )["tools"]["cloakbrowser"]
    assert (
        entry["browser_sha256"]
        == "715722e8605ae3ce81523c1218aba1ec89425786ab33ceaf99f8a6cb5e70e6e8"
    )
    observed = []

    def measure(command, **kwargs):
        observed.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {
                    "python": "/usr/bin/python",
                    "sdk": "cloakbrowser",
                    "sdk_version": entry["sdk_version"],
                    "browser": "/opt/chrome",
                    "browser_sha256": (
                        "a" * 64 if alternate else entry["browser_sha256"]
                    ),
                }
            ),
        )

    monkeypatch.setattr(composition.shutil, "which", lambda _docker: "/usr/bin/docker")
    monkeypatch.setattr(composition.subprocess, "run", measure)
    if alternate:
        with pytest.raises(ValueError, match="browser.binary_digest_mismatch"):
            composition.cloak_runtime(entry, "docker")
    else:
        config = composition.cloak_runtime(entry, "docker")
        assert config["container_image"] == entry["image"]
        assert config["browser_build"] == entry["browser_build"]
        assert config["browser_channel"] == entry["browser_channel"]
        assert config["browser_sha256"] == entry["browser_sha256"]
    command, options = observed[0]
    assert "--network=none" in command and "--pull=never" in command
    assert "--read-only" in command and entry["image"] in command
    assert options["check"] and options["timeout"] == 30


def test_reopen_rejects_self_consistent_alternate_cloak_measurement(
    tmp_path, monkeypatch
):
    real_measurement = composition.cloak_runtime
    offline_adapter_io(monkeypatch, tmp_path)

    def substitute(source):
        config = json.loads((source / "runtime.json").read_bytes())
        config["browser_sha256"] = "a" * 64
        (source / "runtime.json").write_text(json.dumps(config))

    lifecycle, _ = fake_install(
        tmp_path, "cloakbrowser", "0.5.9", mutate_source=substitute
    )
    directory = tmp_path / "data/tools/acquisition/acquisition.cloakbrowser/0.5.9"
    config = json.loads((directory / "runtime.json").read_bytes())
    monkeypatch.setattr(composition, "cloak_runtime", real_measurement)
    monkeypatch.setattr(composition.shutil, "which", lambda _docker: sys.executable)
    monkeypatch.setattr(
        composition.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, json.dumps(config)
        ),
    )
    runtime = service_module.RuntimeService.open(tmp_path / "data")
    try:
        assert not installed_browser_tools(tmp_path / "data")
        assert (
            next(
                reason
                for manifest, reason in composition.browser_catalog_exclusions(
                    tmp_path / "data", set()
                )
                if manifest.tool_id == "acquisition.cloakbrowser"
            )
            == "eligibility.runtime_identity_mismatch"
        )
        assert lifecycle.active(ToolCategory.ACQUISITION, "acquisition.cloakbrowser")
    finally:
        runtime.close()


def test_cloak_bootstrap_uses_tmpfs_home_without_weakening_container(
    tmp_path, monkeypatch
):
    adapter = tmp_path / "tool.py"
    shutil.copyfile(
        Path(__file__).parents[2] / "tools/browser/cloakbrowser/0.5.9/tool.py", adapter
    )
    image = "cloakhq/cloakbrowser@sha256:" + "a" * 64
    config = {
        "container_image": image,
        "docker": "/usr/bin/docker",
        "python": "/usr/local/bin/python",
    }
    (tmp_path / "runtime.json").write_text(json.dumps(config))
    attempt = tmp_path / "attempt"
    attempt.mkdir()
    monkeypatch.chdir(attempt)
    monkeypatch.delenv("WEB_LISTENING_RUNTIME_IMAGE", raising=False)
    monkeypatch.setattr(
        sys, "argv", [str(adapter), "--web-listening-boundary", "fixture"]
    )
    observed = []

    def capture(executable, command):
        observed.append((executable, command))
        raise RuntimeError("offline.exec_captured")

    monkeypatch.setattr(os, "execv", capture)
    with pytest.raises(RuntimeError, match="offline.exec_captured"):
        runpy.run_path(str(adapter))["_bootstrap"]()
    executable, command = observed[0]
    assert executable == "/usr/bin/docker"
    assert command == (
        "/usr/bin/docker run --rm -i --pull=never --network=host --read-only "
        "--cap-drop=ALL --security-opt=no-new-privileges "
        "--tmpfs=/tmp:rw,nosuid,size=512m"
    ).split() + [
        "--mount",
        f"type=bind,src={tmp_path},dst={tmp_path},readonly",
        "--mount",
        f"type=bind,src={attempt},dst={attempt}",
        "--workdir",
        str(attempt),
        "--env",
        "WEB_LISTENING_RUNTIME_IMAGE=" + image,
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "HOME=/tmp",
        "--entrypoint",
        "/usr/local/bin/python",
        image,
        str(adapter),
        "--web-listening-boundary",
        "fixture",
    ]


@pytest.mark.parametrize(
    "name,version", [("playwright", "1.0.0"), ("cloakbrowser", "0.5.9")]
)
def test_exact_retrieval_preserves_authorized_script_and_xhr_reads(
    tmp_path, monkeypatch, name, version
):
    offline_adapter_io(monkeypatch, tmp_path)
    fake_install(tmp_path, name, version)
    transports = []

    def transport():
        value = bridge()[1]
        transports.append(value)
        return value

    monkeypatch.setattr(service_module, "PinnedHttpTransport", transport)
    monkeypatch.setattr(
        in_process, "_resolve_public_addresses", lambda *_args: ("93.184.216.34",)
    )
    runtime = service_module.RuntimeService.open(tmp_path / "data")
    try:
        method = (
            runtime.retrieve_browser if name == "playwright" else runtime.retrieve_cloak
        )
        response = method(request(12))
        assert response["retrieval"]["outcome"] == "FETCHED"
        job = runtime.get_job(response["retrieval"]["job_ids"][0])
        assert [
            a.tool_id
            for a in job.result.attempts
            if a.outcome != "skipped" and a.tool_id.startswith("acquisition.")
        ] == ["acquisition." + name]
        assert (
            job.result.usage.requests == 4 == sum(len(t.requests) for t in transports)
        )
        assert all(t.closed == 1 for t in transports)
    finally:
        runtime.close()
