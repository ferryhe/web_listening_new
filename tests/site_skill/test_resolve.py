"""Site Skill narrowing and Registry eligibility tests."""

# pylint: disable=duplicate-code,missing-class-docstring,missing-function-docstring
# pylint: disable=invalid-length-returned,non-iterator-returned,too-few-public-methods

from __future__ import annotations

import traceback
from dataclasses import dataclass

import pytest

from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.site_skill.model import SiteSkillError, SuccessChecks, ToolReference
from web_listening.site_skill.resolve import resolve_site_skill
from web_listening.site_skill.update import create_candidate
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
    ToolRegistryError,
)
from web_listening.tool_registry.registry import Registry


def _request() -> Request:
    return Request(
        scope=Scope(
            seeds=(
                "https://example.test/reports/",
                "https://example.test/archive/",
            ),
            allowed_origins=("https://example.test",),
            include_paths=("/**",),
            content_types=(ContentType.HTML, ContentType.FILE),
        ),
        site_skill=None,
        explore_all_tools=False,
        budgets=Budgets(10, 8192, 30, 2),
    )


def _skill(
    *,
    scope: Scope | None = None,
    budgets: Budgets | None = None,
    tool: ToolReference | None = None,
):
    return create_candidate(
        site_key="example",
        version=1,
        previous=None,
        scope=scope
        or Scope(
            seeds=("https://example.test/reports/",),
            allowed_origins=("https://example.test",),
            include_paths=("/reports/**",),
            content_types=(ContentType.HTML,),
        ),
        budgets=budgets or Budgets(4, 4096, 20, 1),
        tool=tool
        or ToolReference(
            "acquisition.web_http",
            "1.0.0",
            ToolCategory.ACQUISITION,
            frozenset({"http_get"}),
        ),
        success_checks=SuccessChecks(("text/html",), 100),
        verified_at="2026-08-25T00:00:00Z",
    ).skill


def _manifest(
    *,
    version: str = "1.0.0",
    category: ToolCategory = ToolCategory.ACQUISITION,
    capabilities: frozenset[str] = frozenset({"http_get"}),
    health: HealthStatus = HealthStatus.HEALTHY,
    qualification: QualificationStatus = QualificationStatus.QUALIFIED,
) -> ToolManifest:
    return ToolManifest(
        "acquisition.web_http",
        version,
        category,
        ToolDistribution.BUILTIN,
        capabilities,
        ToolLimits(30, 8192, 8192),
        health,
        qualification,
    )


@dataclass(slots=True)
class _AcquisitionFake:
    manifest: ToolManifest

    def acquire(self, _value):
        raise AssertionError("resolution must not execute a tool")


@dataclass(slots=True)
class _DiscoveryFake:
    manifest: ToolManifest

    def discover(self, _value):
        raise AssertionError("resolution must not execute a tool")


class _HostileRequestObject:
    def __init__(self, calls: list[int]) -> None:
        object.__setattr__(self, "_calls", calls)

    def __getattribute__(self, _name):
        object.__getattribute__(self, "_calls")[0] += 1
        raise RuntimeError("PRIVATE-HOOK-CANARY")


class _HostileRequest(Request):
    def __getattribute__(self, _name):
        object.__getattribute__(self, "_calls")[0] += 1
        raise RuntimeError("PRIVATE-REQUEST-CANARY")


class _HostileScope(Scope):
    def __getattribute__(self, _name):
        object.__getattribute__(self, "_calls")[0] += 1
        raise RuntimeError("PRIVATE-SCOPE-CANARY")


class _HostileTuple(tuple):
    def __new__(cls, values, calls: list[int]):
        value = super().__new__(cls, values)
        value._calls = calls
        return value

    def __iter__(self):
        self._calls[0] += 1
        raise RuntimeError("PRIVATE-TUPLE-CANARY")

    def __len__(self):
        self._calls[0] += 1
        raise RuntimeError("PRIVATE-TUPLE-CANARY")


class _HostileInt(int):
    def __new__(cls, value: int, calls: list[int]):
        result = super().__new__(cls, value)
        result._calls = calls
        return result

    def __le__(self, _other):
        self._calls[0] += 1
        raise RuntimeError("PRIVATE-INT-CANARY")

    def __lt__(self, _other):
        self._calls[0] += 1
        raise RuntimeError("PRIVATE-INT-CANARY")


class _CallCountingRegistry:
    def __init__(self) -> None:
        self.calls = 0

    def query(self):
        self.calls += 1
        return ()


class _RejectingRegistry:
    def __init__(self, stage: str) -> None:
        self.stage = stage

    def query(self):
        if self.stage == "query":
            raise ToolRegistryError("registry.category_invalid")
        return (_manifest(),)

    def eligibility(self, _requirements):
        raise ToolRegistryError("eligibility.requirements_invalid")


def _registry(manifest: ToolManifest | None = None) -> Registry:
    registry = Registry()
    if manifest is not None:
        fake = (
            _AcquisitionFake(manifest)
            if manifest.category is ToolCategory.ACQUISITION
            else _DiscoveryFake(manifest)
        )
        registry.register(manifest, fake)
    return registry


def _hostile_request(case: str, calls: list[int]) -> object:
    request = _request()
    if case == "plain":
        return _HostileRequestObject(calls)
    if case == "request":
        value = _HostileRequest(
            request.scope,
            request.site_skill,
            request.explore_all_tools,
            request.budgets,
        )
        object.__setattr__(value, "_calls", calls)
        return value
    if case == "scope":
        scope = _HostileScope(
            request.scope.seeds,
            request.scope.allowed_origins,
            request.scope.include_paths,
            request.scope.content_types,
        )
        object.__setattr__(scope, "_calls", calls)
        return Request(
            scope, request.site_skill, request.explore_all_tools, request.budgets
        )
    if case == "tuple":
        scope = Scope(
            _HostileTuple(request.scope.seeds, calls),
            request.scope.allowed_origins,
            request.scope.include_paths,
            request.scope.content_types,
        )
        return Request(
            scope, request.site_skill, request.explore_all_tools, request.budgets
        )
    budgets = Budgets(
        _HostileInt(request.budgets.max_requests, calls),
        request.budgets.max_bytes,
        request.budgets.max_runtime_seconds,
        request.budgets.max_tool_attempts_per_target,
    )
    return Request(
        request.scope, request.site_skill, request.explore_all_tools, budgets
    )


def _assert_stable_error(call, code: str, canary: str = "") -> None:
    with pytest.raises(SiteSkillError) as caught:
        call()

    assert caught.value.code == code
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    if canary:
        assert canary not in "".join(traceback.format_exception(caught.value))


def test_resolution_intersects_scope_and_budgets_without_invoking_tool() -> None:
    skill = _skill()
    request = _request()
    resolution = resolve_site_skill(request, skill, _registry(_manifest()))

    assert resolution.eligible is True
    assert not resolution.reasons
    assert resolution.request.scope == skill.scope
    assert resolution.request.budgets == skill.budgets
    assert resolution.request.site_skill == skill
    assert resolution.request == Request(skill.scope, skill, False, skill.budgets)
    assert request.site_skill is None
    assert request.scope.seeds == (
        "https://example.test/reports/",
        "https://example.test/archive/",
    )


@pytest.mark.parametrize(
    ("case", "canary"),
    [
        ("plain", "PRIVATE-HOOK-CANARY"),
        ("request", "PRIVATE-REQUEST-CANARY"),
        ("scope", "PRIVATE-SCOPE-CANARY"),
        ("tuple", "PRIVATE-TUPLE-CANARY"),
        ("budget", "PRIVATE-INT-CANARY"),
    ],
)
def test_resolution_rejects_hostile_request_values_before_hooks_or_registry(
    case: str, canary: str
) -> None:
    calls = [0]
    request = _hostile_request(case, calls)
    registry = _CallCountingRegistry()

    _assert_stable_error(
        lambda: resolve_site_skill(request, _skill(), registry),
        "request.invalid",
        canary,
    )

    assert calls == [0]
    assert registry.calls == 0


@pytest.mark.parametrize(
    ("scope", "budgets", "code"),
    [
        (
            Scope(
                seeds=("https://outside.test/",),
                allowed_origins=("https://outside.test",),
                include_paths=("/**",),
                content_types=(ContentType.HTML,),
            ),
            None,
            "policy.scope_expansion",
        ),
        (None, Budgets(11, 8192, 30, 2), "policy.budget_expansion"),
    ],
)
def test_resolution_rejects_scope_or_budget_expansion(
    scope: Scope | None, budgets: Budgets | None, code: str
) -> None:
    _assert_stable_error(
        lambda: resolve_site_skill(
            _request(), _skill(scope=scope, budgets=budgets), _registry(_manifest())
        ),
        code,
    )


@pytest.mark.parametrize(
    ("stage", "code"),
    [
        ("query", "registry.category_invalid"),
        ("eligibility", "eligibility.requirements_invalid"),
    ],
)
def test_resolution_contains_registry_errors(stage: str, code: str) -> None:
    _assert_stable_error(
        lambda: resolve_site_skill(_request(), _skill(), _RejectingRegistry(stage)),
        code,
    )


@pytest.mark.parametrize(
    ("skill_tool", "manifest", "code"),
    [
        (
            ToolReference(
                "acquisition.unknown",
                "1.0.0",
                ToolCategory.ACQUISITION,
                frozenset({"http_get"}),
            ),
            None,
            "site_skill.tool_unknown",
        ),
        (None, _manifest(version="2.0.0"), "site_skill.tool_version_mismatch"),
        (
            None,
            _manifest(category=ToolCategory.DISCOVERY),
            "eligibility.category_mismatch",
        ),
        (
            None,
            _manifest(capabilities=frozenset({"html"})),
            "eligibility.capability_missing:http_get",
        ),
        (None, _manifest(health=HealthStatus.UNHEALTHY), "eligibility.unhealthy"),
        (
            None,
            _manifest(qualification=QualificationStatus.UNQUALIFIED),
            "eligibility.unqualified",
        ),
    ],
)
def test_resolution_exposes_exact_ineligibility_reasons(
    skill_tool: ToolReference | None,
    manifest: ToolManifest | None,
    code: str,
) -> None:
    resolution = resolve_site_skill(
        _request(), _skill(tool=skill_tool), _registry(manifest)
    )

    assert resolution.eligible is False
    assert code in resolution.reasons
