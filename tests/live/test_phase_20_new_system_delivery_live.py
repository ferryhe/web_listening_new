"""Authorized new-system multi-site delivery and refresh; offline by default."""

# pylint: disable=broad-exception-caught,duplicate-code,missing-function-docstring
# pylint: disable=protected-access
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-locals
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-positional-arguments
# pylint: disable=too-many-lines,too-many-statements
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import hashlib
import json
import os
import runpy
import sqlite3
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeAlias
from urllib.parse import urlsplit

import pytest

from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.request.site_batch import (
    FileDiscoveryGoal,
    SiteBatchPhase,
    SiteBatchRequest,
    SiteBatchSite,
    SiteRefreshContext,
    site_batch_request_from_mapping,
)
from web_listening.result.model import Result
from web_listening.result.site_batch import FileDiscoveryStatus, SiteBatchResult
from web_listening.result.site_explore import SiteExploreResult
from web_listening.result.site_refresh import SiteRefreshResult
from web_listening.runtime.site_batch import (
    run_site_batch,
    site_batch_result_from_mapping,
)
from web_listening.runtime.workflow import (
    acquire_discovered_candidates,
    run_single_target,
)
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
    WebHttpAcquisitionTool,
)
from web_listening.tool_registry.discovery.builtins.html_links import (
    HTML_FILE_LINKS_MANIFEST,
    HTML_LINKS_MANIFEST,
    HtmlFileLinksDiscoveryTool,
    HtmlLinksDiscoveryTool,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryCoverage,
    DiscoveryOutput,
)
from web_listening.tool_registry.registry import Registry
from web_listening.tool_registry.runners import in_process as in_process_runner
from web_listening.tool_registry.runners.in_process import (
    PinnedHttpTransport,
    TransportResponse,
)
from web_listening.tool_registry.transform.builtins.simple_html_markdown import (
    SIMPLE_HTML_MARKDOWN_MANIFEST,
    SimpleHtmlMarkdownTransform,
)

ROOT = Path(__file__).resolve().parents[2]
TARGETS = Path(__file__).with_name("phase_20_new_system_delivery_targets.json")
HELPERS = runpy.run_path(
    str(ROOT / "tests" / "parity" / "phase_20_new_system_delivery.py")
)
delivery_record = HELPERS["delivery_record"]
load_site_skill = HELPERS["load_site_skill"]
load_site_state = HELPERS["load_site_state"]
persist_site_skill = HELPERS["persist_site_skill"]
persist_site_state = HELPERS["persist_site_state"]
project_current_state = HELPERS["project_current_state"]
refresh_record = HELPERS["refresh_record"]
site_state_record = HELPERS["site_state_record"]

EXPECTED_ORDER = ("soa", "cas", "iaa", "ipcc")
EXPECTED_SCHEMA_VERSION = "phase-20-new-system-delivery-targets.v3"
EXPECTED_ROOT_FIELDS = {
    "schema_version",
    "phase",
    "network_limits_per_request",
    "target_plans",
    "targets",
}
EXPECTED_TARGET_FIELDS = {
    "site_key",
    "display_name",
    "urls",
    "allowed_origins",
    "evidence_thresholds",
    "site_skill_case",
    "site_skill_digest",
    "tree_include_paths",
    "tool_facts",
}
EXPECTED_URL_FIELDS = {"homepage", "monitor", "document", "tree_seed"}
EXPECTED_THRESHOLD_FIELDS = {
    "monitor_min_words",
    "document_min_words",
    "document_min_links",
}
EXPECTED_PLAN_FIELDS = {
    "site_key",
    "source_url_field",
    "required_capability",
    "file_discovery_goal",
}
EXPECTED_PLAN_ROWS = (
    {
        "site_key": "soa",
        "source_url_field": "monitor",
        "required_capability": "ordinary_html",
        "file_discovery_goal": "not_required",
    },
    {
        "site_key": "cas",
        "source_url_field": "document",
        "required_capability": "ordinary_html",
        "file_discovery_goal": "required",
    },
    {
        "site_key": "iaa",
        "source_url_field": "document",
        "required_capability": "ordinary_html",
        "file_discovery_goal": "required",
    },
    {
        "site_key": "ipcc",
        "source_url_field": "monitor",
        "required_capability": "markdown",
        "file_discovery_goal": "not_required",
    },
)
EXPECTED_TARGET_AUTHORIZATION = {
    "soa": {
        "urls": {
            "homepage": "https://www.soa.org/",
            "monitor": "https://www.soa.org/",
            "document": "https://www.soa.org/publications/publications-landing/",
            "tree_seed": None,
        },
        "allowed_origins": ["https://www.soa.org"],
    },
    "cas": {
        "urls": {
            "homepage": "https://www.casact.org/",
            "monitor": "https://www.casact.org/",
            "document": "https://www.casact.org/about/governance/annual-reports",
            "tree_seed": None,
        },
        "allowed_origins": ["https://www.casact.org"],
    },
    "iaa": {
        "urls": {
            "homepage": "https://actuaries.org/",
            "monitor": "https://actuaries.org/",
            "document": "https://actuaries.org/annual-reports/",
            "tree_seed": None,
        },
        "allowed_origins": ["https://actuaries.org"],
    },
    "ipcc": {
        "urls": {
            "homepage": "https://www.ipcc.ch/",
            "monitor": "https://www.ipcc.ch/",
            "document": None,
            "tree_seed": None,
        },
        "allowed_origins": ["https://www.ipcc.ch"],
    },
}
AUDIT_BUNDLE_ROOT = ROOT.parent / ".web-listening-audit-bundles" / "issue-72"
EXPECTED_REQUEST_LIMITS = {
    "max_requests": 12,
    "max_bytes": 52_428_800,
    "max_runtime_seconds": 60,
    "concurrency": 1,
    "retry": 0,
}
SiteResult: TypeAlias = SiteExploreResult | SiteRefreshResult


@dataclass
class _OfflineFailureAcquisition:
    manifest = WEB_HTTP_MANIFEST

    def acquire(self, _tool_input):
        return AcquisitionFailure(
            self.manifest.tool_id,
            self.manifest.version,
            "gateway.transport",
            requests=1,
        )


@dataclass
class _OfflineSuccessAcquisition:
    manifest = WEB_HTTP_MANIFEST

    def acquire(self, tool_input):
        body = b"<!doctype html><p>offline bundle fixture words</p>"
        return AcquisitionOutput(
            self.manifest.tool_id,
            self.manifest.version,
            tool_input.target_url,
            tool_input.target_url,
            200,
            "text/html",
            body,
            hashlib.sha256(body).hexdigest(),
            (),
            1,
            requests=1,
            bytes_received=len(body),
        )


def _load_snapshot() -> dict[str, object]:
    # pylint: disable=too-many-branches,too-many-boolean-expressions
    payload = json.loads(TARGETS.read_bytes())
    if not isinstance(payload, dict) or set(payload) != EXPECTED_ROOT_FIELDS:
        pytest.fail("new-system delivery snapshot shape is invalid")
    if payload.get("schema_version") != EXPECTED_SCHEMA_VERSION:
        pytest.fail("new-system delivery target schema drifted")
    if payload.get("phase") != "20-replacement":
        pytest.fail("new-system delivery phase drifted")
    if payload.get("network_limits_per_request") != EXPECTED_REQUEST_LIMITS:
        pytest.fail("new-system delivery limits drifted")
    targets = payload.get("targets")
    plans = payload.get("target_plans")
    if not isinstance(targets, list) or not isinstance(plans, list):
        pytest.fail("new-system delivery snapshot shape is invalid")
    if tuple(plans) != EXPECTED_PLAN_ROWS or any(
        not isinstance(plan, dict) or set(plan) != EXPECTED_PLAN_FIELDS
        for plan in plans
    ):
        pytest.fail("new-system delivery operational plan drifted")
    if any(not isinstance(target, dict) for target in targets):
        pytest.fail("new-system delivery operational target shape drifted")
    if tuple(item.get("site_key") for item in targets) != EXPECTED_ORDER:
        pytest.fail("new-system delivery target order drifted")
    if tuple(item.get("site_key") for item in plans) != EXPECTED_ORDER:
        pytest.fail("new-system delivery plan order drifted")
    for target in targets:
        if not isinstance(target, dict) or set(target) != EXPECTED_TARGET_FIELDS:
            pytest.fail("new-system delivery operational target shape drifted")
        site_key = target["site_key"]
        authorization = EXPECTED_TARGET_AUTHORIZATION[site_key]
        if (
            target["urls"] != authorization["urls"]
            or target["allowed_origins"] != authorization["allowed_origins"]
        ):
            pytest.fail("new-system delivery target authorization drifted")
        if set(target["urls"]) != EXPECTED_URL_FIELDS:
            pytest.fail("new-system delivery target URL shape drifted")
        thresholds = target["evidence_thresholds"]
        if (
            not isinstance(target["display_name"], str)
            or not target["display_name"]
            or not isinstance(thresholds, dict)
            or set(thresholds) != EXPECTED_THRESHOLD_FIELDS
            or any(
                value is not None and (not isinstance(value, int) or value < 0)
                for value in thresholds.values()
            )
            or target["site_skill_case"] != site_key
            or not isinstance(target["site_skill_digest"], str)
            or not target["site_skill_digest"].startswith("sha256:")
            or len(target["site_skill_digest"]) != 71
            or target["tree_include_paths"] != []
        ):
            pytest.fail("new-system delivery operational target metadata drifted")
        tool_facts = target["tool_facts"]
        if (
            not isinstance(tool_facts, dict)
            or not {"tool_id", "version", "category", "capabilities"}.issubset(
                tool_facts
            )
            or set(tool_facts)
            - {
                "tool_id",
                "version",
                "category",
                "capabilities",
                "recipe_id",
            }
            or tool_facts["tool_id"] != WEB_HTTP_MANIFEST.tool_id
            or tool_facts["version"] != WEB_HTTP_MANIFEST.version
            or tool_facts["category"] != "acquisition"
            or tool_facts["capabilities"] != ["http_get"]
        ):
            pytest.fail("new-system delivery tool facts drifted")
    return payload


def _authorized_snapshot() -> dict[str, object]:
    if os.environ.get("WEB_LISTENING_RUN_LIVE") != "1":
        pytest.skip("new-system delivery live test is offline by default")
    if not os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", "").strip():
        pytest.fail("a non-empty authorized live window is required")
    return _load_snapshot()


class _NetworkBudget:
    def __init__(
        self,
        requests: int,
        response_bytes: int,
        timeout: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        start: bool = True,
    ) -> None:
        self.max_requests = requests
        self.max_response_bytes = response_bytes
        self.requests = 0
        self.response_bytes = 0
        self._clock = clock
        self._timeout = timeout
        self.started_at: float | None = None
        self.deadline: float | None = None
        self.finished_at: float | None = None
        if start:
            self.activate()

    def activate(self) -> None:
        if self.started_at is not None:
            return
        self.started_at = self._clock()
        self.deadline = self.started_at + self._timeout

    def finish(self) -> None:
        if self.started_at is not None and self.finished_at is None:
            self.finished_at = self._clock()

    @property
    def elapsed_seconds(self) -> float:
        if self.started_at is None:
            return 0.0
        endpoint = self._clock() if self.finished_at is None else self.finished_at
        return max(0.0, endpoint - self.started_at)

    @property
    def within_deadline(self) -> bool:
        if self.deadline is None:
            return True
        endpoint = self._clock() if self.finished_at is None else self.finished_at
        return endpoint <= self.deadline

    @property
    def remaining_seconds(self) -> float:
        if self.deadline is None:
            return float(self._timeout)
        return max(0.0, self.deadline - self._clock())


class _PhaseNetworkBudgets:
    """One fresh physical ledger per site for one batch phase."""

    def __init__(
        self,
        site_keys: tuple[str, ...],
        limits: dict[str, int],
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.by_site = {
            site_key: _new_request_budget(limits, clock=clock, start=False)
            for site_key in site_keys
        }
        self._site_positions = {
            site_key: position for position, site_key in enumerate(site_keys)
        }
        self._active_site_key: str | None = None
        self._active_position = -1

    def for_url(self, url: str) -> _NetworkBudget:
        site_key = urlsplit(url).hostname or "invalid"
        position = self._site_positions.get(site_key)
        if position is None or position < self._active_position:
            raise ValueError("budget.site_order")
        budget = self.by_site[site_key]
        if self._active_site_key != site_key:
            if self._active_site_key is not None:
                self.by_site[self._active_site_key].finish()
            budget.activate()
            self._active_site_key = site_key
            self._active_position = position
        return budget

    def evidence(self, limits: dict[str, int]) -> dict[str, dict[str, object]]:
        if self._active_site_key is not None:
            self.by_site[self._active_site_key].finish()
        return {
            site_key: _physical_budget_record(budget, limits)
            for site_key, budget in self.by_site.items()
        }


class _CappedResponse:
    def __init__(self, response: TransportResponse, budget: _NetworkBudget) -> None:
        self.status = response.status
        self.headers = response.headers
        self.peer_ip = response.peer_ip
        self._response = response
        self._budget = budget

    def read(self, max_bytes: int) -> bytes:
        remaining = self._budget.max_response_bytes - self._budget.response_bytes
        if self._budget.remaining_seconds <= 0 or remaining <= 0:
            raise TimeoutError
        try:
            content = self._response.read(min(max_bytes, remaining))
        except in_process_runner._PartialBodyRead as exc:
            self._budget.response_bytes += len(exc.partial)
            raise
        self._budget.response_bytes += len(content)
        return content

    def set_timeout(self, timeout: float) -> None:
        remaining = self._budget.remaining_seconds
        if remaining <= 0:
            raise TimeoutError
        setter = getattr(self._response, "set_timeout", None)
        if callable(setter):
            setter(min(timeout, remaining))

    def close(self) -> None:
        self._response.close()


class _CappedTransport:
    def __init__(self, budget: _NetworkBudget | _PhaseNetworkBudgets) -> None:
        self._budgets = budget
        self._transport = PinnedHttpTransport()

    def _budget_for_url(self, url: str) -> _NetworkBudget:
        if isinstance(self._budgets, _NetworkBudget):
            return self._budgets
        return self._budgets.for_url(url)

    def send(
        self, url: str, *, timeout: float, addresses: tuple[str, ...]
    ) -> _CappedResponse:
        budget = self._budget_for_url(url)
        if budget.remaining_seconds <= 0 or budget.requests >= budget.max_requests:
            raise TimeoutError
        budget.requests += 1
        response = self._transport.send(
            url,
            timeout=min(timeout, budget.remaining_seconds),
            addresses=addresses,
        )
        return _CappedResponse(response, budget)

    def close(self) -> None:
        self._transport.close()


class _PhaseBudgetedAcquisition:
    """Activate one site's phase ledger before its governed resolver starts."""

    manifest = WEB_HTTP_MANIFEST

    def __init__(
        self,
        budgets: _PhaseNetworkBudgets,
        acquisition_factory: Callable[[float], WebHttpAcquisitionTool] | None = None,
    ) -> None:
        self._budgets = budgets
        self._acquisition_factory = acquisition_factory
        self._closed = False

    def acquire(
        self, tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        if self._closed:
            return AcquisitionFailure(
                self.manifest.tool_id,
                self.manifest.version,
                "gateway.closed",
            )
        try:
            budget = self._budgets.for_url(tool_input.target_url)
        except ValueError:
            return AcquisitionFailure(
                self.manifest.tool_id,
                self.manifest.version,
                "budget.site_order",
            )
        assert budget.deadline is not None
        acquisition = (
            WebHttpAcquisitionTool(
                lambda: _CappedTransport(self._budgets),
                runtime_deadline=budget.deadline,
            )
            if self._acquisition_factory is None
            else self._acquisition_factory(budget.deadline)
        )
        try:
            result = acquisition.acquire(tool_input)
        finally:
            acquisition.close()
        if not budget.within_deadline:
            return AcquisitionFailure(
                self.manifest.tool_id,
                self.manifest.version,
                "budget.runtime",
                requests=result.requests,
                bytes_received=result.bytes_received,
                runtime_ms=result.runtime_ms,
            )
        return result

    def close(self) -> None:
        self._closed = True


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _url_id(value: str | None) -> str | None:
    if value is None:
        return None
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _atomic_json(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.partial")
    temporary.write_bytes(_canonical_json_bytes(value))
    temporary.replace(path)


def _resolve_bundle_member(root: Path, relative_path: str) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("audit_bundle.path_escape")
    resolved_root = root.resolve()
    resolved = (resolved_root / relative).resolve()
    if resolved == resolved_root or resolved_root not in resolved.parents:
        raise ValueError("audit_bundle.path_escape")
    return resolved


def _bundle_file_record(root: Path, path: Path) -> dict[str, object]:
    content = path.read_bytes()
    return {
        "relative_path": path.relative_to(root).as_posix(),
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _finalize_audit_bundle(
    staging: Path,
    final: Path,
    run_id: str,
    evidence: dict[str, object],
) -> dict[str, object]:
    if (
        staging.parent.resolve() != final.parent.resolve()
        or staging.name != f".{run_id}.partial"
        or final.name != run_id
        or not staging.is_dir()
        or final.exists()
    ):
        raise ValueError("audit_bundle.path_invalid")
    _atomic_json(staging / "evidence.json", evidence)
    files = tuple(
        _bundle_file_record(staging, path)
        for path in sorted(staging.rglob("*"))
        if path.is_file() and path.name != "bundle-manifest.json"
    )
    manifest = {
        "schema_version": "phase-20-new-system-delivery-bundle.v1",
        "run_id": run_id,
        "retention": "retain_until_fresh_io_audit_then_remove",
        "files": files,
    }
    _atomic_json(staging / "bundle-manifest.json", manifest)
    staging.replace(final)
    manifest_path = final / "bundle-manifest.json"
    manifest_content = manifest_path.read_bytes()
    return {
        "schema_version": "phase-20-new-system-delivery-locator.v1",
        "run_id": run_id,
        "path": str(final.resolve()),
        "manifest_size_bytes": len(manifest_content),
        "manifest_sha256": hashlib.sha256(manifest_content).hexdigest(),
        "retention": "retain_until_fresh_io_audit_then_remove",
    }


def _verify_audit_bundle(locator: dict[str, object]) -> dict[str, object]:
    root = Path(str(locator["path"])).resolve()
    manifest_path = _resolve_bundle_member(root, "bundle-manifest.json")
    manifest_content = manifest_path.read_bytes()
    if (
        len(manifest_content) != locator["manifest_size_bytes"]
        or hashlib.sha256(manifest_content).hexdigest() != locator["manifest_sha256"]
    ):
        raise ValueError("audit_bundle.manifest_mismatch")
    manifest = json.loads(manifest_content)
    if (
        manifest.get("schema_version") != "phase-20-new-system-delivery-bundle.v1"
        or manifest.get("run_id") != locator["run_id"]
    ):
        raise ValueError("audit_bundle.manifest_invalid")
    declared_paths: set[str] = set()
    for record in manifest.get("files", []):
        relative_path = record.get("relative_path")
        if not isinstance(relative_path, str) or relative_path in declared_paths:
            raise ValueError("audit_bundle.manifest_invalid")
        declared_paths.add(relative_path)
        path = _resolve_bundle_member(root, relative_path)
        content = path.read_bytes()
        if len(content) != record.get("size_bytes") or hashlib.sha256(
            content
        ).hexdigest() != record.get("sha256"):
            raise ValueError("audit_bundle.file_mismatch")
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "bundle-manifest.json"
    }
    if declared_paths != actual_paths:
        raise ValueError("audit_bundle.file_set_mismatch")
    sqlite_audit: list[dict[str, object]] = []
    for database_path in sorted(root.glob("*/artifacts/artifact.sqlite3")):
        connection = sqlite3.connect(
            f"{database_path.resolve().as_uri()}?mode=ro&immutable=1",
            uri=True,
        )
        try:
            observations = connection.execute(
                "SELECT COUNT(*) FROM observations"
            ).fetchone()[0]
            blob_rows = connection.execute(
                "SELECT sha256, size_bytes, relative_path FROM blobs"
            ).fetchall()
        finally:
            connection.close()
        artifact_root = database_path.parent
        for sha256, size_bytes, relative_path in blob_rows:
            blob_path = _resolve_bundle_member(artifact_root, relative_path)
            content = blob_path.read_bytes()
            if (
                len(content) != size_bytes
                or hashlib.sha256(content).hexdigest() != sha256
            ):
                raise ValueError("audit_bundle.blob_mismatch")
        sqlite_audit.append(
            {
                "store_relative_path": database_path.parent.relative_to(
                    root
                ).as_posix(),
                "open_mode": "read_only_immutable",
                "observation_count": observations,
                "blob_count": len(blob_rows),
            }
        )
    return {
        "manifest_matches": True,
        "file_count": len(declared_paths),
        "readonly_sqlite": sqlite_audit,
    }


def _new_live_bundle_paths() -> tuple[str, Path, Path]:
    root = AUDIT_BUNDLE_ROOT.resolve()
    checkout = ROOT.resolve()
    if root == checkout or checkout in root.parents:
        raise ValueError("audit_bundle.must_be_outside_checkout")
    root.mkdir(parents=True, exist_ok=True)
    run_id = f"phase-20-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex}"
    staging = root / f".{run_id}.partial"
    final = root / run_id
    staging.mkdir()
    return run_id, staging, final


def _request_budgets(limits: dict[str, int]) -> Budgets:
    return Budgets(
        limits["max_requests"],
        limits["max_bytes"],
        limits["max_runtime_seconds"],
        4,
    )


def _new_request_budget(
    limits: dict[str, int],
    *,
    clock: Callable[[], float] = time.monotonic,
    start: bool = True,
) -> _NetworkBudget:
    return _NetworkBudget(
        limits["max_requests"],
        limits["max_bytes"],
        limits["max_runtime_seconds"],
        clock=clock,
        start=start,
    )


def _target_plan_pairs(
    targets: list[dict[str, object]],
    plans: list[dict[str, object]],
    *,
    site_keys: tuple[str, ...] | None = None,
) -> tuple[tuple[dict[str, object], dict[str, object]], ...]:
    selected = None if site_keys is None else set(site_keys)
    pairs = tuple(
        (target, plan)
        for target, plan in zip(targets, plans, strict=True)
        if selected is None or _production_site_key(target, plan) in selected
    )
    if (
        site_keys is not None
        and tuple(_production_site_key(target, plan) for target, plan in pairs)
        != site_keys
    ):
        raise ValueError("delivery.site_order")
    return pairs


def _site_scope(
    target: dict[str, object],
    plan: dict[str, object],
) -> Scope:
    source_url = target["urls"][plan["source_url_field"]]
    if not isinstance(source_url, str):
        raise ValueError("delivery.source_url_missing")
    tree_paths = tuple(target["tree_include_paths"])
    include_paths = (
        tuple(dict.fromkeys((urlsplit(source_url).path or "/", *tree_paths)))
        if tree_paths
        else ("/**",)
    )
    return Scope(
        (source_url,),
        tuple(target["allowed_origins"]),
        include_paths,
        (ContentType.HTML, ContentType.FILE),
    )


def _batch_parent_request(
    targets: list[dict[str, object]],
    plans: list[dict[str, object]],
    limits: dict[str, int],
    *,
    site_keys: tuple[str, ...] | None = None,
) -> Request:
    scopes = tuple(
        _site_scope(target, plan)
        for target, plan in _target_plan_pairs(
            targets,
            plans,
            site_keys=site_keys,
        )
    )
    return Request(
        Scope(
            tuple(scope.seeds[0] for scope in scopes),
            tuple(
                dict.fromkeys(
                    origin for scope in scopes for origin in scope.allowed_origins
                )
            ),
            tuple(
                dict.fromkeys(path for scope in scopes for path in scope.include_paths)
            ),
            (ContentType.HTML, ContentType.FILE),
        ),
        None,
        False,
        _request_budgets(limits),
    )


def _batch_sites(
    targets: list[dict[str, object]],
    plans: list[dict[str, object]],
    *,
    site_keys: tuple[str, ...] | None = None,
) -> tuple[SiteBatchSite, ...]:
    return tuple(
        SiteBatchSite(
            _site_scope(target, plan),
            FileDiscoveryGoal(plan["file_discovery_goal"]),
        )
        for target, plan in _target_plan_pairs(
            targets,
            plans,
            site_keys=site_keys,
        )
    )


def _production_site_key(target: dict[str, object], plan: dict[str, object]) -> str:
    source_url = target["urls"][plan["source_url_field"]]
    if not isinstance(source_url, str):
        raise ValueError("delivery.source_url_missing")
    site_key = urlsplit(source_url).hostname
    if not site_key:
        raise ValueError("delivery.site_key_missing")
    return site_key


def _partition_candidate_results(
    acquired,
) -> tuple[tuple[object, ...], tuple[object, ...]]:
    all_results = tuple(item.result for item in acquired)
    successful_results = tuple(
        result
        for result in all_results
        if any(artifact.role == "source" for artifact in result.artifacts)
    )
    return all_results, successful_results


def _usage_reconciliation(
    results: tuple[object, ...], physical: dict[str, object]
) -> dict[str, object]:
    logical_requests = sum(result.usage.requests for result in results)
    logical_bytes = sum(result.usage.bytes_received for result in results)
    physical_requests = physical["requests"]
    physical_bytes = physical["response_bytes"]
    return {
        "logical_requests": logical_requests,
        "logical_response_bytes": logical_bytes,
        "physical_requests": physical_requests,
        "physical_response_bytes": physical_bytes,
        "matches": logical_requests == physical_requests
        and logical_bytes == physical_bytes,
    }


def _batch_usage_reconciliation(
    result: SiteBatchResult,
    physical: dict[str, dict[str, object]],
) -> dict[str, object]:
    per_site = {}
    for site_key, child in zip(
        result.site_keys,
        result.site_results,
        strict=False,
    ):
        row = physical[site_key]
        per_site[site_key] = {
            "logical_requests": child.usage.requests,
            "logical_response_bytes": child.usage.bytes_received,
            "logical_runtime_seconds": child.usage.runtime_ms / 1000,
            "physical_requests": row["requests"],
            "physical_response_bytes": row["response_bytes"],
            "physical_runtime_seconds": row["runtime_seconds"],
            "runtime_comparable": False,
            "matches": child.usage.requests == row["requests"]
            and child.usage.bytes_received == row["response_bytes"],
        }
    aggregate_physical_requests = sum(row["requests"] for row in physical.values())
    aggregate_physical_bytes = sum(row["response_bytes"] for row in physical.values())
    aggregate_physical_runtime = sum(
        row["runtime_seconds"] for row in physical.values()
    )
    return {
        "per_site": per_site,
        "aggregate_audit": {
            "logical_requests": result.usage.requests,
            "logical_response_bytes": result.usage.bytes_received,
            "logical_runtime_seconds": result.usage.runtime_ms / 1000,
            "physical_requests": aggregate_physical_requests,
            "physical_response_bytes": aggregate_physical_bytes,
            "physical_runtime_seconds": aggregate_physical_runtime,
            "runtime_comparable": False,
            "budget_gate": False,
        },
        "matches": all(row["matches"] for row in per_site.values())
        and result.usage.requests == aggregate_physical_requests
        and result.usage.bytes_received == aggregate_physical_bytes,
    }


def _combined_budget_audit(
    first: dict[str, dict[str, object]],
    refresh: dict[str, dict[str, object]],
) -> dict[str, object]:
    site_keys = tuple(dict.fromkeys((*first, *refresh)))
    per_site = {
        site_key: {
            "requests": first.get(site_key, {}).get("requests", 0)
            + refresh.get(site_key, {}).get("requests", 0),
            "response_bytes": first.get(site_key, {}).get("response_bytes", 0)
            + refresh.get(site_key, {}).get("response_bytes", 0),
            "runtime_seconds": round(
                first.get(site_key, {}).get("runtime_seconds", 0)
                + refresh.get(site_key, {}).get("runtime_seconds", 0),
                6,
            ),
        }
        for site_key in site_keys
    }
    return {
        "per_site": per_site,
        "requests": sum(row["requests"] for row in per_site.values()),
        "response_bytes": sum(row["response_bytes"] for row in per_site.values()),
        "runtime_seconds": round(
            sum(row["runtime_seconds"] for row in per_site.values()), 6
        ),
        "budget_gate": False,
    }


def _request_evidence(
    request_id: str,
    request: SiteBatchRequest,
    result: SiteBatchResult,
    physical: dict[str, dict[str, object]],
    reconciliation: dict[str, object],
) -> dict[str, object]:
    request_payload = request.to_dict()
    rebuilt_request = site_batch_request_from_mapping(request_payload)
    rebuilt_result = site_batch_result_from_mapping(result.to_dict())
    if rebuilt_request != request:
        raise ValueError("delivery.request_roundtrip")
    if rebuilt_result != result:
        raise ValueError("delivery.result_roundtrip")
    if result.run_id != request_id or result.request_sha256 != request.request_sha256:
        raise ValueError("delivery.request_identity")
    target_manifest_run_ids = {
        site_key: [target.manifest.run_id for target in child.target_results]
        for site_key, child in zip(
            result.site_keys,
            result.site_results,
            strict=False,
        )
    }
    return {
        "request_id": request_id,
        "run_id": result.run_id,
        "request_contract": request.schema_version,
        "request_sha256": request.request_sha256,
        "strict_request_round_trip": True,
        "result_schema_version": rebuilt_result.schema_version,
        "strict_result_round_trip": True,
        "site_keys": list(request.site_keys),
        "usable_site_keys": list(result.usable_site_keys),
        "file_discovery_goals": {
            site_key: site.file_discovery_goal.value
            for site_key, site in zip(request.site_keys, request.sites, strict=True)
        },
        "file_discovery_statuses": {
            site_key: status.value
            for site_key, status in zip(
                result.site_keys,
                result.file_discovery_statuses,
                strict=False,
            )
        },
        "target_manifest_run_ids": target_manifest_run_ids,
        "initial_usage_by_site": {
            site_key: {
                "requests": 0,
                "response_bytes": 0,
                "runtime_seconds": 0.0,
            }
            for site_key in request.site_keys
        },
        "limits_per_site": {
            site_key: {
                "max_requests": row["max_requests"],
                "max_bytes": row["max_bytes"],
                "max_runtime_seconds": row["max_runtime_seconds"],
                "concurrency": row["concurrency"],
                "retry": row["retry"],
            }
            for site_key, row in physical.items()
        },
        "result_usage": rebuilt_result.usage.to_dict(),
        "within_budget": all(row["within_budget"] for row in physical.values()),
        "physical_network_by_site": physical,
        "usage_reconciliation": reconciliation,
    }


def _pdf_refresh_proof(
    first_pdf: Result | None,
    refresh_child: SiteResult,
    context: SiteRefreshContext,
    store: ArtifactStore,
) -> dict[str, object]:
    first_source = (
        None
        if first_pdf is None
        else next(
            (
                artifact
                for artifact in first_pdf.artifacts
                if artifact.role == "source" and artifact.mime_type == "application/pdf"
            ),
            None,
        )
    )
    if first_source is None:
        return {"passed": False, "same_canonical_target": False}
    canonical_url = first_source.source_url
    refresh_source = next(
        (
            artifact
            for result in refresh_child.target_results
            for artifact in result.artifacts
            if artifact.role == "source"
            and artifact.mime_type == "application/pdf"
            and artifact.source_url == canonical_url
        ),
        None,
    )
    previous_page = next(
        (
            page
            for page in context.previous_state.pages
            if page.canonical_url == canonical_url
        ),
        None,
    )
    current_page = next(
        (
            page
            for page in refresh_child.current_state.pages
            if page.canonical_url == canonical_url
        ),
        None,
    )
    if refresh_source is None or previous_page is None or current_page is None:
        return {
            "passed": False,
            "same_canonical_target": False,
            "url_id": _url_id(canonical_url),
            "first_observation_id": first_source.observation_id,
            "first_artifact_id": first_source.artifact_id,
            "first_sha256": first_source.sha256,
        }
    first_stored = store.get_observation(first_source.observation_id)
    refresh_stored = store.get_observation(refresh_source.observation_id)
    first_matches = (
        previous_page.observation_id == first_source.observation_id
        and previous_page.artifact_id == first_source.artifact_id
        and previous_page.content_digest == f"sha256:{first_source.sha256}"
        and first_stored.observation.source_url == canonical_url
        and first_stored.artifact.artifact_id == first_source.artifact_id
        and first_stored.blob.sha256 == first_source.sha256
    )
    refresh_matches = (
        current_page.observation_id == refresh_source.observation_id
        and current_page.artifact_id == refresh_source.artifact_id
        and current_page.content_digest == f"sha256:{refresh_source.sha256}"
        and refresh_stored.observation.source_url == canonical_url
        and refresh_stored.artifact.artifact_id == refresh_source.artifact_id
        and refresh_stored.blob.sha256 == refresh_source.sha256
    )
    new_observation = first_source.observation_id != refresh_source.observation_id
    content_unchanged = first_source.sha256 == refresh_source.sha256
    artifact_reused = first_source.artifact_id == refresh_source.artifact_id
    artifact_identity_valid = artifact_reused == content_unchanged
    return {
        "passed": (
            first_matches
            and refresh_matches
            and new_observation
            and artifact_identity_valid
        ),
        "same_canonical_target": True,
        "url_id": _url_id(canonical_url),
        "first_observation_id": first_source.observation_id,
        "refresh_observation_id": refresh_source.observation_id,
        "first_artifact_id": first_source.artifact_id,
        "refresh_artifact_id": refresh_source.artifact_id,
        "first_sha256": first_source.sha256,
        "refresh_sha256": refresh_source.sha256,
        "new_observation": new_observation,
        "content_unchanged": content_unchanged,
        "artifact_reused": artifact_reused,
        "artifact_identity_valid": artifact_identity_valid,
    }


def _plan_capabilities_met(
    plan: dict[str, object],
    *,
    has_html: bool,
    has_markdown: bool,
    file_goal_satisfied: bool,
    same_pdf_refresh_proved: bool,
) -> bool:
    required_met = has_html and (
        plan["required_capability"] != "markdown" or has_markdown
    )
    if plan["file_discovery_goal"] == FileDiscoveryGoal.REQUIRED.value:
        required_met = required_met and file_goal_satisfied and same_pdf_refresh_proved
    return required_met


def _persist_refresh_contexts(
    bundle_staging: Path,
    contexts: tuple[object, ...],
) -> tuple[tuple[SiteRefreshContext, ...], dict[str, dict[str, str]]]:
    persisted: list[SiteRefreshContext] = []
    paths: dict[str, dict[str, str]] = {}
    for context in contexts:
        if not isinstance(context, SiteRefreshContext):
            raise ValueError("delivery.refresh_context_type")
        site_key = context.site_skill.site_key
        site_root = bundle_staging / site_key
        site_root.mkdir()
        skill_path = site_root / "site-skill.json"
        state_path = site_root / "current-site-state.json"
        persist_site_skill(skill_path, context.site_skill)
        persist_site_state(state_path, context.previous_state)
        reloaded = SiteRefreshContext(
            load_site_skill(skill_path),
            load_site_state(state_path),
        )
        if SiteRefreshContext.from_dict(reloaded.to_dict()) != reloaded:
            raise ValueError("delivery.refresh_context_roundtrip")
        persisted.append(reloaded)
        paths[site_key] = {
            "state_relative_path": state_path.relative_to(bundle_staging).as_posix(),
            "site_skill_relative_path": skill_path.relative_to(
                bundle_staging
            ).as_posix(),
        }
    return tuple(persisted), paths


def _child_results_by_site(batch: SiteBatchResult) -> dict[str, SiteResult]:
    return dict(
        zip(
            batch.site_keys,
            batch.site_results,
            strict=False,
        )
    )


def _blocked_site_record(
    target: dict[str, object],
    first_child: SiteResult | None,
    reason: str,
) -> dict[str, object]:
    return {
        "site_key": target["site_key"],
        "status": "BLOCKED",
        "reason": reason,
        "first_results": (
            []
            if first_child is None
            else [delivery_record(result) for result in first_child.target_results]
        ),
    }


def _site_delivery_record(
    bundle_staging: Path,
    target: dict[str, object],
    plan: dict[str, object],
    first: SiteBatchResult,
    refresh: SiteBatchResult,
    persisted_contexts: dict[str, SiteRefreshContext],
    context_paths: dict[str, dict[str, str]],
    first_physical: dict[str, dict[str, object]],
    refresh_physical: dict[str, dict[str, object]],
    store: ArtifactStore,
) -> dict[str, object]:
    site_key = str(target["site_key"])
    production_site_key = _production_site_key(target, plan)
    first_child = _child_results_by_site(first).get(production_site_key)
    refresh_child = _child_results_by_site(refresh).get(production_site_key)
    context = persisted_contexts.get(production_site_key)
    if first_child is None:
        return _blocked_site_record(target, None, "first_site_result_missing")
    if context is None:
        return _blocked_site_record(
            target,
            first_child,
            "first_refresh_context_unavailable",
        )
    if refresh_child is None:
        return _blocked_site_record(
            target,
            first_child,
            "refresh_site_result_missing",
        )

    first_deliveries = [
        delivery_record(result) for result in first_child.target_results
    ]
    refresh_evidence = refresh_record(refresh_child, store)
    seed_delivery = first_deliveries[0] if first_deliveries else {"artifacts": []}
    candidate_delivery = first_deliveries[1:]
    has_html = any(
        artifact["role"] == "source" and artifact["mime_type"] == "text/html"
        for artifact in seed_delivery["artifacts"]
    )
    has_markdown = any(
        artifact["role"] == "derived"
        and artifact["mime_type"] == "text/markdown"
        and artifact["lineage"]
        for artifact in seed_delivery["artifacts"]
    )
    has_pdf_first = any(
        artifact["role"] == "source" and artifact["mime_type"] == "application/pdf"
        for record in candidate_delivery
        for artifact in record["artifacts"]
    )
    has_pdf_refresh = any(
        artifact["role"] == "source" and artifact["mime_type"] == "application/pdf"
        for record in refresh_evidence["target_results"]
        for artifact in record["artifacts"]
    )
    first_file_status = first.file_discovery_statuses[
        first.site_keys.index(production_site_key)
    ]
    refresh_file_status = refresh.file_discovery_statuses[
        refresh.site_keys.index(production_site_key)
    ]
    file_goal = FileDiscoveryGoal(plan["file_discovery_goal"])
    file_goal_satisfied = (
        first_file_status is FileDiscoveryStatus.SATISFIED
        and refresh_file_status is FileDiscoveryStatus.SATISFIED
        if file_goal is FileDiscoveryGoal.REQUIRED
        else first_file_status is FileDiscoveryStatus.NOT_REQUESTED
        and refresh_file_status is FileDiscoveryStatus.NOT_REQUESTED
    )
    first_pdf = (
        next(
            (
                result
                for result in first_child.target_results[1:]
                if any(
                    artifact.role == "source"
                    and artifact.mime_type == "application/pdf"
                    for artifact in result.artifacts
                )
            ),
            None,
        )
        if file_goal is FileDiscoveryGoal.REQUIRED
        else None
    )
    file_discovery = next(
        (
            evidence
            for evidence in first_child.discovery
            if first_pdf is not None
            and first_pdf.manifest.requested_url in evidence.candidates
        ),
        None,
    )
    file_index = (
        None
        if file_discovery is None or first_pdf is None
        else file_discovery.candidates.index(first_pdf.manifest.requested_url)
    )
    pdf_refresh_proof = (
        _pdf_refresh_proof(first_pdf, refresh_child, context, store)
        if first_file_status is FileDiscoveryStatus.SATISFIED
        and file_discovery is not None
        else {"passed": False, "same_canonical_target": False}
    )
    source = next(
        (
            artifact
            for result in first_child.target_results[:1]
            for artifact in result.artifacts
            if artifact.role == "source"
        ),
        None,
    )
    if source is None:
        return _blocked_site_record(target, first_child, "initial_source_failed")
    previous_source = next(
        (
            page
            for page in context.previous_state.pages
            if page.canonical_url == source.source_url
        ),
        None,
    )
    refreshed_source = next(
        (
            page
            for page in refresh_child.current_state.pages
            if page.canonical_url == source.source_url
        ),
        None,
    )
    refreshed = (
        previous_source is not None
        and refreshed_source is not None
        and previous_source.observation_id != refreshed_source.observation_id
    )
    required_met = _plan_capabilities_met(
        plan,
        has_html=has_html,
        has_markdown=has_markdown,
        file_goal_satisfied=file_goal_satisfied,
        same_pdf_refresh_proved=bool(pdf_refresh_proof["passed"]),
    )
    site_paths = context_paths[production_site_key]
    return {
        "site_key": site_key,
        "status": (
            "PASS"
            if required_met
            and refreshed
            and production_site_key in first.usable_site_keys
            and production_site_key in refresh.usable_site_keys
            and first_physical[production_site_key]["within_budget"]
            and refresh_physical[production_site_key]["within_budget"]
            else "BLOCKED"
        ),
        "expected_to_observed": {
            "required_capability": plan["required_capability"],
            "file_discovery_goal": file_goal.value,
            "first_file_status": first_file_status.value,
            "refresh_file_status": refresh_file_status.value,
            "file_goal_satisfied": file_goal_satisfied,
            "html": has_html,
            "markdown": has_markdown,
            "pdf_initial": has_pdf_first,
            "pdf_refresh": has_pdf_refresh,
            "same_pdf_refresh_proved": pdf_refresh_proof["passed"],
            "refresh_source_observed": refreshed,
        },
        "discovery": {
            "outcome": (
                "failed"
                if not first_child.discovery
                else (
                    "succeeded"
                    if any(
                        item.outcome == "succeeded" for item in first_child.discovery
                    )
                    else "failed"
                )
            ),
            "coverage": (None if file_discovery is None else file_discovery.coverage),
            "candidate_count": sum(
                len(item.candidates) for item in first_child.discovery
            ),
            "file_url_id": (
                None if first_pdf is None else _url_id(first_pdf.manifest.requested_url)
            ),
            "discovered_from_url_id": (
                None
                if file_discovery is None or file_index is None
                else _url_id(file_discovery.discovered_from[file_index])
            ),
            "candidate_reauthorized": (
                first_file_status is FileDiscoveryStatus.SATISFIED
                and file_discovery is not None
            ),
            "pdf_refresh_proof": pdf_refresh_proof,
        },
        "first_results": first_deliveries,
        "site_skill_candidate": {
            "site_key": context.site_skill.site_key,
            "version": context.site_skill.version,
            "digest": context.site_skill.digest,
            "previous_digest": context.site_skill.previous_digest,
            "validated": True,
            "active": False,
        },
        "site_skill_round_trip": True,
        "first_state": site_state_record(context.previous_state, store),
        "state_round_trip": True,
        "refresh": refresh_evidence,
        "physical_network": {
            "first": first_physical[production_site_key],
            "refresh": refresh_physical[production_site_key],
        },
        "io_audit": {
            "artifact_store_relative_path": store.root.relative_to(
                bundle_staging
            ).as_posix(),
            "sqlite_relative_path": store.database_path.relative_to(
                bundle_staging
            ).as_posix(),
            **site_paths,
        },
    }


def _batch_run(
    bundle_staging: Path,
    targets: list[dict[str, object]],
    plans: list[dict[str, object]],
    limits: dict[str, int],
    run_id: str,
) -> dict[str, object]:
    first_request_id = f"{run_id}-first"
    refresh_request_id = f"{run_id}-refresh"
    parent = _batch_parent_request(targets, plans, limits)
    first_sites = _batch_sites(targets, plans)
    first_request = site_batch_request_from_mapping(
        SiteBatchRequest(
            SiteBatchPhase.FIRST,
            parent,
            (),
            sites=first_sites,
        ).to_dict()
    )
    first_network = _PhaseNetworkBudgets(first_request.site_keys, limits)
    first_acquisition = _PhaseBudgetedAcquisition(first_network)
    first_registry = Registry()
    first_registry.register(WEB_HTTP_MANIFEST, first_acquisition)
    first_registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
    first_registry.register(
        HTML_FILE_LINKS_MANIFEST,
        HtmlFileLinksDiscoveryTool(),
    )
    first_registry.register(
        SIMPLE_HTML_MARKDOWN_MANIFEST,
        SimpleHtmlMarkdownTransform(),
    )
    refresh_acquisition = None
    batch_root = bundle_staging / "batch"
    batch_root.mkdir()
    store = ArtifactStore(batch_root / "artifacts")
    try:
        first = run_site_batch(
            first_request,
            first_registry,
            store,
            run_id=first_request_id,
            clock=_now,
        )
        first = site_batch_result_from_mapping(first.to_dict())
        first_physical = first_network.evidence(limits)
        first_reconciliation = _batch_usage_reconciliation(
            first,
            first_physical,
        )
        first_evidence = _request_evidence(
            first_request_id,
            first_request,
            first,
            first_physical,
            first_reconciliation,
        )
        persisted, context_paths = _persist_refresh_contexts(
            bundle_staging,
            first.next_refresh_contexts,
        )
        context_keys = tuple(context.site_skill.site_key for context in persisted)
        if len(context_keys) < 2:
            return {
                "sites": [
                    _blocked_site_record(
                        target,
                        _child_results_by_site(first).get(
                            _production_site_key(target, plan)
                        ),
                        "fewer_than_two_refresh_contexts",
                    )
                    for target, plan in zip(targets, plans, strict=True)
                ],
                "requests": {
                    "first": first_evidence,
                    "refresh": None,
                    "combined_audit": None,
                },
                "first_status": first.status.value,
                "first_usable_site_keys": list(first.usable_site_keys),
                "refresh_context_site_keys": list(context_keys),
            }
        refresh_parent = _batch_parent_request(
            targets,
            plans,
            limits,
            site_keys=context_keys,
        )
        refresh_sites = _batch_sites(
            targets,
            plans,
            site_keys=context_keys,
        )
        refresh_request = site_batch_request_from_mapping(
            SiteBatchRequest(
                SiteBatchPhase.REFRESH,
                refresh_parent,
                persisted,
                sites=refresh_sites,
            ).to_dict()
        )
        refresh_network = _PhaseNetworkBudgets(
            refresh_request.site_keys,
            limits,
        )
        refresh_acquisition = _PhaseBudgetedAcquisition(refresh_network)
        refresh_registry = Registry()
        refresh_registry.register(WEB_HTTP_MANIFEST, refresh_acquisition)
        refresh_registry.register(HTML_LINKS_MANIFEST, HtmlLinksDiscoveryTool())
        refresh_registry.register(
            HTML_FILE_LINKS_MANIFEST,
            HtmlFileLinksDiscoveryTool(),
        )
        refresh_registry.register(
            SIMPLE_HTML_MARKDOWN_MANIFEST,
            SimpleHtmlMarkdownTransform(),
        )
        refresh = run_site_batch(
            refresh_request,
            refresh_registry,
            store,
            run_id=refresh_request_id,
            clock=_now,
        )
        refresh = site_batch_result_from_mapping(refresh.to_dict())

        refresh_physical = refresh_network.evidence(limits)
        refresh_reconciliation = _batch_usage_reconciliation(
            refresh,
            refresh_physical,
        )
        requests = {
            "first": first_evidence,
            "refresh": _request_evidence(
                refresh_request_id,
                refresh_request,
                refresh,
                refresh_physical,
                refresh_reconciliation,
            ),
            "combined_audit": _combined_budget_audit(
                first_physical,
                refresh_physical,
            ),
        }
        persisted_by_site = {
            context.site_skill.site_key: context for context in persisted
        }
        return {
            "sites": [
                _site_delivery_record(
                    bundle_staging,
                    target,
                    plan,
                    first,
                    refresh,
                    persisted_by_site,
                    context_paths,
                    first_physical,
                    refresh_physical,
                    store,
                )
                for target, plan in zip(targets, plans, strict=True)
            ],
            "requests": requests,
            "first_status": first.status.value,
            "refresh_status": refresh.status.value,
            "first_usable_site_keys": list(first.usable_site_keys),
            "refresh_usable_site_keys": list(refresh.usable_site_keys),
            "refresh_context_site_keys": list(context_keys),
        }
    finally:
        first_acquisition.close()
        if refresh_acquisition is not None:
            refresh_acquisition.close()
        store.close()


def _physical_budget_record(
    budget: _NetworkBudget, limits: dict[str, int]
) -> dict[str, object]:
    return {
        "requests": budget.requests,
        "response_bytes": budget.response_bytes,
        "runtime_seconds": round(budget.elapsed_seconds, 6),
        "max_requests": limits["max_requests"],
        "max_bytes": limits["max_bytes"],
        "max_runtime_seconds": limits["max_runtime_seconds"],
        "concurrency": limits["concurrency"],
        "retry": limits["retry"],
        "within_budget": (
            budget.requests <= limits["max_requests"]
            and budget.response_bytes <= limits["max_bytes"]
            and budget.within_deadline
        ),
    }


def _capability_summary(
    records: list[dict[str, object]],
) -> dict[str, bool]:
    observations = [
        record.get("expected_to_observed", {})
        for record in records
        if record.get("status") == "PASS"
    ]
    return {
        "ordinary_html": any(item.get("html") for item in observations),
        "markdown": any(item.get("markdown") for item in observations),
        "discovered_pdf_initial": any(item.get("pdf_initial") for item in observations),
        "discovered_pdf_refresh": any(item.get("pdf_refresh") for item in observations),
        "discovered_pdf_initial_and_refresh": any(
            item.get("same_pdf_refresh_proved") for item in observations
        ),
    }


def test_phase_20_new_system_delivery_snapshot_is_exact_and_bounded() -> None:
    payload = _load_snapshot()
    source = Path(__file__).read_text(encoding="utf-8")

    assert payload["phase"] == "20-replacement"
    assert len(payload["targets"]) == 4
    assert [
        plan["site_key"]
        for plan in payload["target_plans"]
        if plan["file_discovery_goal"] == FileDiscoveryGoal.REQUIRED.value
    ] == ["cas", "iaa"]
    assert (
        sum(
            line.strip().startswith(
                ("first = run_site_batch(", "refresh = run_site_batch(")
            )
            for line in source.splitlines()
        )
        == 2
    )
    assert "run_site_" + "explore(" not in source
    assert "run_site_" + "refresh(" not in source
    assert "WEB_LISTENING_" + "LIVE_URL" not in source
    assert "WEB_LISTENING_" + "AUDIT_BUNDLE" not in source
    assert "legacy_" + "live_probe" not in source
    assert "phase_20_" + "parity" not in source
    assert ROOT.resolve() not in AUDIT_BUNDLE_ROOT.resolve().parents


def test_phase_20_frozen_site_scopes_and_file_goals_round_trip() -> None:
    payload = _load_snapshot()
    parent = _batch_parent_request(
        payload["targets"],
        payload["target_plans"],
        payload["network_limits_per_request"],
    )
    sites = _batch_sites(payload["targets"], payload["target_plans"])
    request = site_batch_request_from_mapping(
        SiteBatchRequest(
            SiteBatchPhase.FIRST,
            parent,
            (),
            sites=sites,
        ).to_dict()
    )

    assert request.sites == sites
    assert tuple(site.scope.seeds[0] for site in sites) == parent.scope.seeds
    assert tuple(site.scope.include_paths for site in sites) == (("/**",),) * 4
    assert tuple(site.file_discovery_goal for site in sites) == (
        FileDiscoveryGoal.NOT_REQUIRED,
        FileDiscoveryGoal.REQUIRED,
        FileDiscoveryGoal.REQUIRED,
        FileDiscoveryGoal.NOT_REQUIRED,
    )
    assert all(
        site.scope.allowed_origins == tuple(target["allowed_origins"])
        for site, target in zip(sites, payload["targets"], strict=True)
    )


def test_phase_20_live_gate_requires_opt_in_and_authorized_window(monkeypatch) -> None:
    monkeypatch.delenv("WEB_LISTENING_RUN_LIVE", raising=False)
    monkeypatch.delenv("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW", raising=False)
    with pytest.raises(pytest.skip.Exception):
        _authorized_snapshot()

    monkeypatch.setenv("WEB_LISTENING_RUN_LIVE", "1")
    with pytest.raises(pytest.fail.Exception):
        _authorized_snapshot()


def test_phase_20_physical_budget_reports_a_real_deadline_overrun() -> None:
    now = [0.0]
    budget = _NetworkBudget(12, 52_428_800, 60, clock=lambda: now[0])
    now[0] = 61.0

    record = _physical_budget_record(budget, EXPECTED_REQUEST_LIMITS)

    assert record["runtime_seconds"] == 61.0
    assert record["within_budget"] is False


def test_phase_20_failed_discovered_result_is_retained_and_reconciled(
    tmp_path: Path,
) -> None:
    request = Request(
        Scope(
            ("https://example.test/",),
            ("https://example.test",),
            ("/**",),
            (ContentType.HTML, ContentType.FILE),
        ),
        None,
        False,
        Budgets(12, 52_428_800, 60, 4),
    )
    discovery = DiscoveryOutput(
        HTML_LINKS_MANIFEST.tool_id,
        HTML_LINKS_MANIFEST.version,
        (
            "https://example.test/report.pdf",
            "https://outside.test/rejected.pdf",
        ),
        request.scope.seeds * 2,
        DiscoveryCoverage.COMPLETE,
    )
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, _OfflineFailureAcquisition())
    store = ArtifactStore(tmp_path / "artifacts")
    acquired = acquire_discovered_candidates(
        request,
        registry,
        store,
        discovery,
        max_candidates=2,
        run_id="offline-candidate-failure",
        clock=lambda: "2026-08-31T12:00:00Z",
    )

    all_results, successful_results = _partition_candidate_results(acquired)
    reconciliation = _usage_reconciliation(
        all_results, {"requests": 1, "response_bytes": 0}
    )

    assert len(all_results) == 2
    assert not successful_results
    assert all_results[0].status.value == "failed"
    assert all_results[0].attempts[0].outcome == "failed"
    assert all_results[0].usage.requests == 1
    assert all_results[0].errors[0].code == "gateway.transport"
    assert all_results[1].status.value == "rejected"
    assert all_results[1].artifacts == ()
    assert all_results[1].usage.requests == 0
    assert reconciliation == {
        "logical_requests": 1,
        "logical_response_bytes": 0,
        "physical_requests": 1,
        "physical_response_bytes": 0,
        "matches": True,
    }
    store.close()


def test_phase_20_audit_bundle_is_atomic_locatable_and_read_only_reopenable(
    tmp_path: Path,
) -> None:
    run_id = "phase-20-offline-bundle"
    staging = tmp_path / f".{run_id}.partial"
    final = tmp_path / run_id
    site_root = staging / "example" / "artifacts"
    site_root.parent.mkdir(parents=True)
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, _OfflineSuccessAcquisition())
    store = ArtifactStore(site_root)
    request = Request(
        Scope(
            ("https://example.test/",),
            ("https://example.test",),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(12, 52_428_800, 60, 4),
    )
    result = run_single_target(
        request,
        registry,
        store,
        run_id="offline-bundle-source",
        clock=lambda: "2026-08-31T12:00:00Z",
    )
    state = project_current_state(
        (result,),
        store,
        site_key="example.test",
        site_skill_digest=f"sha256:{'0' * 64}",
        generated_at="2026-08-31T12:00:00Z",
        complete=True,
    )
    persist_site_state(site_root.parent / "current-site-state.json", state)
    store.close()
    packet = {
        "schema_version": "phase-20-new-system-delivery-evidence.v1",
        "run_id": run_id,
        "sites": [{"site_key": "example", "result": delivery_record(result)}],
    }

    locator = _finalize_audit_bundle(staging, final, run_id, packet)
    audit = _verify_audit_bundle(locator)

    assert not staging.exists()
    assert final.is_dir()
    assert locator["path"] == str(final.resolve())
    assert locator["run_id"] == run_id
    assert len(locator["manifest_sha256"]) == 64
    assert audit["manifest_matches"] is True
    assert audit["readonly_sqlite"][0]["observation_count"] == 1
    assert audit["readonly_sqlite"][0]["blob_count"] == 1
    encoded_public_files = (final / "evidence.json").read_text(encoding="utf-8") + (
        final / "bundle-manifest.json"
    ).read_text(encoding="utf-8")
    assert "https://example.test/" not in encoded_public_files
    assert "offline bundle fixture words" not in encoded_public_files
    with pytest.raises(ValueError, match="audit_bundle.path_escape"):
        _resolve_bundle_member(final, "../escape")


def test_phase_20_pdf_capability_requires_one_site_to_refresh_its_pdf() -> None:
    records = [
        {
            "status": "PASS",
            "expected_to_observed": {
                "html": True,
                "markdown": True,
                "pdf_initial": True,
                "pdf_refresh": False,
            },
        },
        {
            "status": "PASS",
            "expected_to_observed": {
                "html": True,
                "markdown": False,
                "pdf_initial": False,
                "pdf_refresh": True,
            },
        },
    ]

    capabilities = _capability_summary(records)

    assert capabilities["discovered_pdf_initial"] is True
    assert capabilities["discovered_pdf_refresh"] is True
    assert capabilities["discovered_pdf_initial_and_refresh"] is False
    pdf_plan = {
        "required_capability": "html",
        "file_discovery_goal": "required",
    }
    assert not _plan_capabilities_met(
        pdf_plan,
        has_html=True,
        has_markdown=False,
        file_goal_satisfied=False,
        same_pdf_refresh_proved=False,
    )
    assert not _plan_capabilities_met(
        pdf_plan,
        has_html=True,
        has_markdown=False,
        file_goal_satisfied=True,
        same_pdf_refresh_proved=False,
    )


@pytest.mark.live
def test_phase_20_new_system_multi_site_delivery_and_refresh_live() -> None:
    payload = _authorized_snapshot()
    limits = payload["network_limits_per_request"]
    targets = payload["targets"]
    plans = payload["target_plans"]
    run_id, staging, final = _new_live_bundle_paths()
    batch = _batch_run(staging, targets, plans, limits, run_id)
    records = batch["sites"]
    passed = sum(record["status"] == "PASS" for record in records)
    capabilities = _capability_summary(records)
    evidence = {
        "schema_version": "phase-20-new-system-delivery-evidence.v1",
        "run_id": run_id,
        "phase_20_new_system_delivery_live_evidence": {
            "authorized_window_id": _url_id(
                os.environ["WEB_LISTENING_LIVE_AUTHORIZED_WINDOW"]
            ),
            "collected": len(records),
            "passed": passed,
            "blocked": len(records) - passed,
            "skipped": 0,
            "site_order": [record["site_key"] for record in records],
            "capabilities": capabilities,
            "limits_per_request": limits,
            "requests": batch["requests"],
            "first_status": batch.get("first_status"),
            "refresh_status": batch.get("refresh_status"),
            "first_usable_site_keys": batch["first_usable_site_keys"],
            "refresh_usable_site_keys": batch.get("refresh_usable_site_keys", []),
            "refresh_context_site_keys": batch["refresh_context_site_keys"],
            "sites": records,
        },
    }
    locator = _finalize_audit_bundle(staging, final, run_id, evidence)
    bundle_audit = _verify_audit_bundle(locator)
    print(
        json.dumps(
            {
                "audit_bundle": locator,
                "bundle_verification": bundle_audit,
                **evidence,
            },
            sort_keys=True,
        )
    )

    assert len(records) == 4
    assert [record["site_key"] for record in records] == list(EXPECTED_ORDER)
    assert passed >= 3
    assert all(capabilities.values())
    assert batch["requests"]["first"]["within_budget"] is True
    assert batch["requests"]["refresh"]["within_budget"] is True
    assert batch["requests"]["first"]["usage_reconciliation"]["matches"] is True
    assert batch["requests"]["refresh"]["usage_reconciliation"]["matches"] is True
    assert bundle_audit["manifest_matches"] is True
