"""Focused tests for explicit registration and minimum eligibility filtering."""

# pylint: disable=duplicate-code,missing-class-docstring,missing-function-docstring
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-lines
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import ast
import hashlib
import inspect
import traceback
from dataclasses import dataclass, fields, replace
from pathlib import Path

import pytest

from web_listening.artifact.identity import artifact_id as make_artifact_id
from web_listening.artifact.identity import (
    blob_relative_path,
)
from web_listening.artifact.model import (
    Artifact,
    ArtifactRole,
    Blob,
    Observation,
    StoredObservation,
)
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.tool_registry.eligibility import EligibilityRequirements
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
    ToolRegistryError,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionInput,
    AcquisitionOutput,
    AcquisitionRedirect,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryInput,
    DiscoveryOutput,
)
from web_listening.tool_registry.protocols.transform import (
    TransformInput,
    TransformOutput,
)
from web_listening.tool_registry.registry import Registry


def _request(
    *,
    max_requests: int = 2,
    max_bytes: int = 4096,
    max_runtime_seconds: int = 10,
    allowed_origins: tuple[str, ...] = ("https://example.test",),
    content_types: tuple[ContentType, ...] = (ContentType.HTML,),
) -> Request:
    return Request(
        scope=Scope(
            seeds=("https://example.test/",),
            allowed_origins=allowed_origins,
            include_paths=("/**",),
            content_types=content_types,
        ),
        site_skill=None,
        explore_all_tools=False,
        budgets=Budgets(max_requests, max_bytes, max_runtime_seconds, 1),
    )


def _stored_observation() -> StoredObservation:
    content = b"source"
    digest = hashlib.sha256(content).hexdigest()
    identifier = make_artifact_id(digest, "text/plain", ArtifactRole.SOURCE)
    return StoredObservation(
        Blob(digest, len(content), blob_relative_path(digest)),
        Artifact(identifier, digest, "text/plain", ArtifactRole.SOURCE),
        Observation(
            "observation-" + "1" * 32,
            identifier,
            "https://example.test/report",
            "2026-08-25T00:00:00Z",
        ),
        (),
        content,
    )


def _manifest(
    tool_id: str,
    category: ToolCategory = ToolCategory.DISCOVERY,
    *,
    distribution: ToolDistribution = ToolDistribution.BUILTIN,
    capabilities: frozenset[str] = frozenset({"html"}),
    health: HealthStatus = HealthStatus.HEALTHY,
    qualification: QualificationStatus = QualificationStatus.QUALIFIED,
    limits: ToolLimits | None = None,
) -> ToolManifest:
    return ToolManifest(
        tool_id=tool_id,
        version="1.2.3",
        category=category,
        distribution=distribution,
        capabilities=capabilities,
        limits=limits or ToolLimits(10, 4096, 4096),
        health=health,
        qualification=qualification,
    )


@dataclass
class _DiscoveryFake:
    manifest: ToolManifest
    output: object | None = None

    def discover(self, tool_input: DiscoveryInput) -> object:
        if self.output is not None:
            return self.output
        return DiscoveryOutput(
            tool_id=self.manifest.tool_id,
            tool_version=self.manifest.version,
            candidates=tool_input.scope.seeds,
        )


@dataclass
class _AcquisitionFake:
    manifest: ToolManifest
    output: object | None = None
    calls: int = 0

    def acquire(self, tool_input: AcquisitionInput) -> object:
        self.calls += 1
        if self.output is not None:
            return self.output
        body = b"ok"
        return AcquisitionOutput(
            tool_id=self.manifest.tool_id,
            tool_version=self.manifest.version,
            requested_url=tool_input.target_url,
            final_url=tool_input.target_url,
            status_code=200,
            mime_type="text/html",
            body=body,
            sha256=hashlib.sha256(body).hexdigest(),
            redirects=(),
            runtime_ms=1,
        )


@dataclass
class _TransformFake:
    manifest: ToolManifest
    output: object | None = None
    calls: int = 0

    def transform(self, tool_input: TransformInput) -> object:
        self.calls += 1
        if self.output is not None:
            return self.output
        body = tool_input.source.content.upper()
        return TransformOutput(
            tool_id=self.manifest.tool_id,
            tool_version=self.manifest.version,
            source_artifact_id=tool_input.source.artifact.artifact_id,
            mime_type="text/plain",
            body=body,
            sha256=hashlib.sha256(body).hexdigest(),
            runtime_ms=1,
        )


class _AmbiguousFake(_DiscoveryFake):
    def acquire(self, tool_input: AcquisitionInput) -> object:
        del tool_input
        return object()


@dataclass
class _NonCallableDiscoveryFake:
    manifest: ToolManifest
    discover: int = 1


def _safe_error(callable_, code: str, canary: str) -> None:
    with pytest.raises(ToolRegistryError) as caught:
        callable_()
    error = caught.value
    assert error.code == code
    assert str(error) == code
    assert error.__cause__ is None
    assert error.__context__ is None
    assert canary not in "".join(
        traceback.format_exception(type(error), error, error.__traceback__)
    )


def _code(callable_) -> str:
    with pytest.raises(ToolRegistryError) as caught:
        callable_()
    return caught.value.code


def _forged_acquisition_output(
    manifest: ToolManifest, body: bytes, runtime_ms: int
) -> AcquisitionOutput:
    output = object.__new__(AcquisitionOutput)
    for name, value in (
        ("tool_id", manifest.tool_id),
        ("tool_version", manifest.version),
        ("requested_url", "https://example.test/"),
        ("final_url", "https://example.test/"),
        ("status_code", 200),
        ("mime_type", "text/plain"),
        ("body", body),
        ("sha256", hashlib.sha256(bytes(body)).hexdigest()),
        ("redirects", ()),
        ("runtime_ms", runtime_ms),
    ):
        object.__setattr__(output, name, value)
    return output


def _acquisition_output(
    manifest: ToolManifest,
    *,
    requested_url: str = "https://example.test/",
    final_url: str | None = None,
    mime_type: str = "text/html",
    redirects: tuple[AcquisitionRedirect, ...] = (),
) -> AcquisitionOutput:
    body = b"ok"
    return AcquisitionOutput(
        manifest.tool_id,
        manifest.version,
        requested_url,
        final_url or requested_url,
        200,
        mime_type,
        body,
        hashlib.sha256(body).hexdigest(),
        redirects,
        1,
    )


def test_register_and_query_preserve_order_and_independent_distribution() -> None:
    registry = Registry()
    installed = _manifest(
        "discovery.installed",
        distribution=ToolDistribution.INSTALLED,
    )
    builtin = _manifest("discovery.builtin")

    registry.register(installed, _DiscoveryFake(installed))
    registry.register(builtin, _DiscoveryFake(builtin))

    assert registry.query() == (installed, builtin)
    assert registry.query(category=ToolCategory.DISCOVERY) == (installed, builtin)
    assert installed.category is builtin.category
    assert installed.distribution is not builtin.distribution


def test_register_rejects_duplicates_identity_and_protocol_mismatch() -> None:
    registry = Registry()
    discovery = _manifest("discovery.soa")
    acquisition = _manifest("acquisition.http", ToolCategory.ACQUISITION)
    registry.register(discovery, _DiscoveryFake(discovery))

    assert (
        _code(lambda: registry.register(discovery, _DiscoveryFake(discovery)))
        == "registry.duplicate_id"
    )
    assert (
        _code(lambda: Registry().register(discovery, _DiscoveryFake(acquisition)))
        == "registry.identity_mismatch"
    )
    assert (
        _code(lambda: Registry().register(acquisition, _DiscoveryFake(acquisition)))
        == "registry.protocol_mismatch"
    )
    assert (
        _code(lambda: Registry().register(discovery, _AmbiguousFake(discovery)))
        == "registry.protocol_mismatch"
    )
    assert (
        _code(
            lambda: Registry().register(discovery, _NonCallableDiscoveryFake(discovery))
        )
        == "registry.protocol_mismatch"
    )


def test_registry_snapshots_manifest_and_returns_detached_metadata() -> None:
    registry = Registry()
    limits = ToolLimits(10, 4096, 4096)
    manifest = _manifest("discovery.snapshot", limits=limits)
    tool = _DiscoveryFake(manifest)
    registry.register(manifest, tool)

    first = registry.query()[0]
    assert first == manifest
    assert first is not manifest
    assert first.limits is not limits
    object.__setattr__(first, "health", HealthStatus.UNHEALTHY)
    object.__setattr__(first.limits, "max_output_bytes", 1)

    second = registry.query()[0]
    assert second.health is HealthStatus.HEALTHY
    assert second.limits.max_output_bytes == 4096
    selected = registry.eligible(
        EligibilityRequirements(category=ToolCategory.DISCOVERY)
    )[0]
    object.__setattr__(selected.limits, "max_runtime_seconds", 1)
    assert registry.query()[0].limits.max_runtime_seconds == 10


def test_registry_revalidates_tool_manifest_and_rejects_forged_metadata() -> None:
    manifest = _manifest("discovery.mutable")
    tool = _DiscoveryFake(manifest)
    registry = Registry()
    registry.register(manifest, tool)
    object.__setattr__(manifest.limits, "max_runtime_seconds", 0)

    assert registry.query()[0].limits.max_runtime_seconds == 10
    assert (
        _code(
            lambda: registry.invoke(
                manifest.tool_id, DiscoveryInput(scope=_request().scope)
            )
        )
        == "manifest.limits_invalid"
    )


def test_registration_never_executes_manifest_or_category_properties() -> None:
    canary = "descriptor-private-canary"
    manifest = _manifest("discovery.descriptor")
    safe_manifest = manifest

    class ManifestPropertyFake:
        @property
        def manifest(self):
            raise RuntimeError(canary)

        def discover(self, tool_input: DiscoveryInput) -> object:
            del tool_input
            return object()

    class MethodPropertyFake:
        manifest = safe_manifest

        @property
        def discover(self):
            raise RuntimeError(canary)

    _safe_error(
        lambda: Registry().register(manifest, ManifestPropertyFake()),
        "registry.manifest_invalid",
        canary,
    )
    _safe_error(
        lambda: Registry().register(manifest, MethodPropertyFake()),
        "registry.protocol_mismatch",
        canary,
    )


def test_slotted_tool_manifest_registers_and_invokes() -> None:
    @dataclass(slots=True)
    class SlottedDiscoveryFake:
        manifest: ToolManifest

        def discover(self, tool_input: DiscoveryInput) -> DiscoveryOutput:
            return DiscoveryOutput(
                self.manifest.tool_id,
                self.manifest.version,
                tool_input.scope.seeds,
            )

    manifest = _manifest("discovery.slotted")
    tool = SlottedDiscoveryFake(manifest)
    registry = Registry()

    registry.register(manifest, tool)
    output = registry.invoke(manifest.tool_id, DiscoveryInput(_request().scope))

    assert output == DiscoveryOutput(
        manifest.tool_id, manifest.version, _request().scope.seeds
    )


def test_slotted_tool_manifest_failures_are_stable_and_context_free() -> None:
    class UnsetSlotFake:
        __slots__ = ("manifest",)

        def discover(self, tool_input: DiscoveryInput) -> DiscoveryOutput:
            raise AssertionError(tool_input)

    @dataclass(slots=True)
    class BrokenSlotFake:
        manifest: object

        def discover(self, tool_input: DiscoveryInput) -> DiscoveryOutput:
            raise AssertionError(tool_input)

    manifest = _manifest("discovery.broken-slot")
    for tool in (UnsetSlotFake(), BrokenSlotFake(object())):
        _safe_error(
            lambda tool=tool: Registry().register(manifest, tool),
            "registry.manifest_invalid",
            "private-slot-canary",
        )


def test_invoke_statically_retrieves_manifest_after_registration() -> None:
    canary = "invoke-manifest-private-canary"
    manifest = _manifest("discovery.static")
    safe_manifest = manifest

    class MutableClassManifestFake:
        manifest = safe_manifest

        def discover(self, tool_input: DiscoveryInput) -> object:
            return DiscoveryOutput(
                safe_manifest.tool_id, safe_manifest.version, tool_input.scope.seeds
            )

    tool = MutableClassManifestFake()
    registry = Registry()
    registry.register(manifest, tool)

    def fail_manifest(_self):
        raise RuntimeError(canary)

    MutableClassManifestFake.manifest = property(fail_manifest)
    _safe_error(
        lambda: registry.invoke(
            manifest.tool_id, DiscoveryInput(scope=_request().scope)
        ),
        "registry.manifest_invalid",
        canary,
    )


def test_manifest_snapshot_rejects_exotic_string_without_equality_hook() -> None:
    canary = "evil-string-private-canary"

    class EvilStr(str):
        def __eq__(self, other):
            raise RuntimeError(canary)

        __hash__ = str.__hash__

    evil = object.__new__(ToolManifest)
    for name, value in (
        ("tool_id", EvilStr("discovery.evil")),
        ("version", "1.2.3"),
        ("category", ToolCategory.DISCOVERY),
        ("distribution", ToolDistribution.BUILTIN),
        ("capabilities", frozenset({"html"})),
        ("limits", ToolLimits(10, 4096, 4096)),
        ("health", HealthStatus.HEALTHY),
        ("qualification", QualificationStatus.QUALIFIED),
    ):
        object.__setattr__(evil, name, value)
    _safe_error(
        lambda: Registry().register(evil, _DiscoveryFake(evil)),
        "manifest.id_invalid",
        canary,
    )

    forged_limits = object.__new__(ToolLimits)
    object.__setattr__(forged_limits, "max_runtime_seconds", 0)
    object.__setattr__(forged_limits, "max_input_bytes", 1)
    object.__setattr__(forged_limits, "max_output_bytes", 1)
    forged_manifest = object.__new__(ToolManifest)
    for name, value in (
        ("tool_id", "discovery.forged"),
        ("version", "1.2.3"),
        ("category", ToolCategory.DISCOVERY),
        ("distribution", ToolDistribution.BUILTIN),
        ("capabilities", frozenset({"html"})),
        ("limits", forged_limits),
        ("health", HealthStatus.HEALTHY),
        ("qualification", QualificationStatus.QUALIFIED),
    ):
        object.__setattr__(forged_manifest, name, value)
    assert (
        _code(
            lambda: Registry().register(
                forged_manifest, _DiscoveryFake(forged_manifest)
            )
        )
        == "manifest.limits_invalid"
    )


@pytest.mark.parametrize(
    "builder, code",
    [
        (lambda: _manifest("BAD ID"), "manifest.id_invalid"),
        (
            lambda: replace(_manifest("discovery.soa"), version="latest"),
            "manifest.version_invalid",
        ),
        (
            lambda: replace(_manifest("discovery.soa"), capabilities=frozenset()),
            "manifest.capabilities_invalid",
        ),
        (
            lambda: replace(_manifest("discovery.soa"), limits=ToolLimits(0, 1, 1)),
            "manifest.limits_invalid",
        ),
        (
            lambda: replace(_manifest("discovery.soa"), category="discovery"),
            "manifest.category_invalid",
        ),
        (
            lambda: replace(_manifest("discovery.soa"), distribution="builtin"),
            "manifest.distribution_invalid",
        ),
        (
            lambda: replace(_manifest("discovery.soa"), health="healthy"),
            "manifest.health_invalid",
        ),
        (
            lambda: replace(_manifest("discovery.soa"), qualification="qualified"),
            "manifest.qualification_invalid",
        ),
    ],
)
def test_manifest_rejects_invalid_metadata(builder, code: str) -> None:
    assert _code(builder) == code


def test_eligibility_reasons_are_complete_stable_and_observable() -> None:
    registry = Registry()
    wrong_category = _manifest("acquisition.http", ToolCategory.ACQUISITION)
    unhealthy = _manifest("discovery.unhealthy", health=HealthStatus.UNHEALTHY)
    unqualified = _manifest(
        "discovery.unqualified",
        qualification=QualificationStatus.UNQUALIFIED,
    )
    too_small = _manifest(
        "discovery.small",
        capabilities=frozenset({"xml"}),
        limits=ToolLimits(1, 1, 1),
    )
    for manifest, tool in (
        (wrong_category, _AcquisitionFake(wrong_category)),
        (unhealthy, _DiscoveryFake(unhealthy)),
        (unqualified, _DiscoveryFake(unqualified)),
        (too_small, _DiscoveryFake(too_small)),
    ):
        registry.register(manifest, tool)

    requirements = EligibilityRequirements(
        category=ToolCategory.DISCOVERY,
        capabilities=frozenset({"html"}),
        input_bytes=2,
        output_bytes=2,
        runtime_seconds=2,
    )
    decisions = registry.eligibility(requirements)

    assert tuple(decision.tool_id for decision in decisions) == (
        "acquisition.http",
        "discovery.unhealthy",
        "discovery.unqualified",
        "discovery.small",
    )
    assert decisions[0].reasons == ("eligibility.category_mismatch",)
    assert decisions[1].reasons == ("eligibility.unhealthy",)
    assert decisions[2].reasons == ("eligibility.unqualified",)
    assert decisions[3].reasons == (
        "eligibility.capability_missing:html",
        "eligibility.input_limit",
        "eligibility.output_limit",
        "eligibility.runtime_limit",
    )
    assert not registry.eligible(requirements)


def test_eligibility_returns_compatible_tools_without_ranking() -> None:
    registry = Registry()
    first = _manifest("discovery.first")
    second = _manifest("discovery.second", distribution=ToolDistribution.INSTALLED)
    registry.register(first, _DiscoveryFake(first))
    registry.register(second, _DiscoveryFake(second))
    requirements = EligibilityRequirements(
        category=ToolCategory.DISCOVERY,
        capabilities=frozenset({"html"}),
        input_bytes=100,
        output_bytes=100,
        runtime_seconds=2,
    )

    decisions = registry.eligibility(requirements)

    assert all(decision.eligible for decision in decisions)
    assert registry.eligible(requirements) == (first, second)


def test_eligibility_rejects_untrusted_capability_text_without_echoing_it() -> None:
    with pytest.raises(ToolRegistryError) as caught:
        EligibilityRequirements(
            category=ToolCategory.DISCOVERY,
            capabilities=frozenset({"token=private"}),
        )
    assert caught.value.code == "eligibility.requirements_invalid"


def test_eligibility_rebuild_contains_forged_hostile_capability_iterable() -> None:
    canary = "eligibility-iterator-private-canary"

    class HostileFrozenSet(frozenset):
        def __iter__(self):
            raise RuntimeError(canary)

    forged = object.__new__(EligibilityRequirements)
    object.__setattr__(forged, "category", ToolCategory.DISCOVERY)
    object.__setattr__(forged, "capabilities", HostileFrozenSet({"html"}))
    object.__setattr__(forged, "input_bytes", 0)
    object.__setattr__(forged, "output_bytes", 0)
    object.__setattr__(forged, "runtime_seconds", 0)
    registry = Registry()
    _safe_error(
        lambda: registry.eligibility(forged),
        "eligibility.requirements_invalid",
        canary,
    )


def test_invoke_validates_unhashable_tool_id_before_lookup() -> None:
    _safe_error(
        lambda: Registry().invoke([], DiscoveryInput(scope=_request().scope)),
        "manifest.id_invalid",
        "unhashable",
    )


def test_invoke_accepts_conforming_fake_and_rejects_wrong_input() -> None:
    registry = Registry()
    manifest = _manifest("discovery.soa")
    registry.register(manifest, _DiscoveryFake(manifest))

    result = registry.invoke(manifest.tool_id, DiscoveryInput(scope=_request().scope))

    assert isinstance(result, DiscoveryOutput)
    assert result.candidates == _request().scope.seeds
    assert (
        _code(
            lambda: registry.invoke(
                manifest.tool_id,
                AcquisitionInput(_request(), "https://example.test/"),
            )
        )
        == "registry.input_mismatch"
    )


@pytest.mark.parametrize(
    "output, code",
    [
        ({"candidates": ["https://example.test/"]}, "registry.output_invalid"),
        (
            DiscoveryOutput("discovery.other", "1.2.3", ("https://example.test/",)),
            "registry.output_identity_mismatch",
        ),
        (
            DiscoveryOutput("discovery.soa", "2.0.0", ("https://example.test/",)),
            "registry.output_identity_mismatch",
        ),
    ],
)
def test_invoke_rejects_untrusted_or_identity_drifting_outputs(
    output: object, code: str
) -> None:
    manifest = _manifest("discovery.soa")
    registry = Registry()
    registry.register(manifest, _DiscoveryFake(manifest, output))

    assert (
        _code(
            lambda: registry.invoke(
                manifest.tool_id, DiscoveryInput(scope=_request().scope)
            )
        )
        == code
    )


def test_invoke_revalidates_a_forged_output_instead_of_trusting_its_type() -> None:
    forged = object.__new__(DiscoveryOutput)
    object.__setattr__(forged, "tool_id", "discovery.soa")
    object.__setattr__(forged, "tool_version", "1.2.3")
    object.__setattr__(forged, "candidates", ("not-a-url",))
    manifest = _manifest("discovery.soa")
    registry = Registry()
    registry.register(manifest, _DiscoveryFake(manifest, forged))

    assert (
        _code(
            lambda: registry.invoke(
                manifest.tool_id, DiscoveryInput(scope=_request().scope)
            )
        )
        == "protocol.url_invalid"
    )


def test_discovery_output_limit_accepts_exact_aggregate_utf8_bytes() -> None:
    candidates = (
        "https://example.test/%C3%A9",
        "https://example.test/%E4%BA%8C",
    )
    aggregate_bytes = sum(len(value.encode("utf-8")) for value in candidates)
    manifest = _manifest(
        "discovery.bounded",
        limits=ToolLimits(10, 4096, aggregate_bytes),
    )
    registry = Registry()
    registry.register(
        manifest,
        _DiscoveryFake(
            manifest,
            DiscoveryOutput(manifest.tool_id, manifest.version, candidates),
        ),
    )

    output = registry.invoke(manifest.tool_id, DiscoveryInput(_request().scope))

    assert output.candidates == candidates


@pytest.mark.parametrize(
    "candidates",
    [
        ("https://example.test/report",),
        ("https://example.test/a", "https://example.test/b"),
    ],
)
def test_discovery_output_limit_rejects_aggregate_one_byte_over(
    candidates: tuple[str, ...],
) -> None:
    aggregate_bytes = sum(len(value.encode("utf-8")) for value in candidates)
    manifest = _manifest(
        "discovery.oversize",
        limits=ToolLimits(10, 4096, aggregate_bytes - 1),
    )
    registry = Registry()
    registry.register(
        manifest,
        _DiscoveryFake(
            manifest,
            DiscoveryOutput(manifest.tool_id, manifest.version, candidates),
        ),
    )

    _safe_error(
        lambda: registry.invoke(manifest.tool_id, DiscoveryInput(_request().scope)),
        "registry.output_limit",
        "private-discovery-limit-canary",
    )


def test_invoke_contains_hostile_nested_output_and_input_reconstruction() -> None:
    output_canary = "output-iterator-private-canary"

    class HostileTuple(tuple):
        def __iter__(self):
            raise RuntimeError(output_canary)

    manifest = _manifest("acquisition.hostile", ToolCategory.ACQUISITION)
    forged_output = object.__new__(AcquisitionOutput)
    for name, value in (
        ("tool_id", manifest.tool_id),
        ("tool_version", manifest.version),
        ("requested_url", "https://example.test/"),
        ("final_url", "https://example.test/"),
        ("status_code", 200),
        ("mime_type", "text/plain"),
        ("body", b"ok"),
        ("sha256", hashlib.sha256(b"ok").hexdigest()),
        ("redirects", HostileTuple()),
        ("runtime_ms", 1),
    ):
        object.__setattr__(forged_output, name, value)
    registry = Registry()
    registry.register(manifest, _AcquisitionFake(manifest, forged_output))
    _safe_error(
        lambda: registry.invoke(
            manifest.tool_id, AcquisitionInput(_request(), "https://example.test/")
        ),
        "registry.output_invalid",
        output_canary,
    )

    input_canary = "input-rebuild-private-canary"

    class HostileScope(Scope):
        def __getattribute__(self, name):
            if name == "seeds":
                raise RuntimeError(input_canary)
            return super().__getattribute__(name)

    discovery = _manifest("discovery.hostile")
    discovery_registry = Registry()
    discovery_registry.register(discovery, _DiscoveryFake(discovery))
    forged_input = object.__new__(DiscoveryInput)
    object.__setattr__(
        forged_input,
        "scope",
        HostileScope(
            ("https://example.test/",),
            ("https://example.test",),
            ("/**",),
            (ContentType.HTML,),
        ),
    )
    _safe_error(
        lambda: discovery_registry.invoke(discovery.tool_id, forged_input),
        "protocol.input_invalid",
        input_canary,
    )


def test_invoke_contains_hostile_acquisition_body_length() -> None:
    canary = "private-body-canary"

    class HostileBytes(bytes):
        def __len__(self):
            raise RuntimeError(canary)

    manifest = _manifest("acquisition.hostile-body", ToolCategory.ACQUISITION)
    body = HostileBytes(b"ok")
    output = _forged_acquisition_output(manifest, body, 1)
    tool = _AcquisitionFake(manifest, output)
    registry = Registry()
    registry.register(manifest, tool)

    _safe_error(
        lambda: registry.invoke(
            manifest.tool_id, AcquisitionInput(_request(), "https://example.test/")
        ),
        "protocol.hash_mismatch",
        canary,
    )
    assert tool.calls == 1


def test_invoke_contains_hostile_acquisition_runtime_comparison() -> None:
    canary = "private-runtime-canary"

    class HostileInt(int):
        def __gt__(self, other):
            raise RuntimeError(canary)

    manifest = _manifest("acquisition.hostile-runtime", ToolCategory.ACQUISITION)
    body = b"ok"
    output = _forged_acquisition_output(manifest, body, HostileInt(1))
    tool = _AcquisitionFake(manifest, output)
    registry = Registry()
    registry.register(manifest, tool)

    _safe_error(
        lambda: registry.invoke(
            manifest.tool_id, AcquisitionInput(_request(), "https://example.test/")
        ),
        "protocol.runtime_invalid",
        canary,
    )
    assert tool.calls == 1


def test_invoke_rejects_hostile_request_budget_before_tool_call() -> None:
    canary = "private-budget-canary"

    class HostileInt(int):
        def __lt__(self, other):
            raise RuntimeError(canary)

    request = _request()
    object.__setattr__(
        request,
        "budgets",
        Budgets(HostileInt(2), 4096, 10, 1),
    )
    forged_input = object.__new__(AcquisitionInput)
    object.__setattr__(forged_input, "request", request)
    object.__setattr__(forged_input, "target_url", "https://example.test/")
    manifest = _manifest("acquisition.hostile-budget", ToolCategory.ACQUISITION)
    tool = _AcquisitionFake(manifest)
    registry = Registry()
    registry.register(manifest, tool)

    _safe_error(
        lambda: registry.invoke(manifest.tool_id, forged_input),
        "protocol.input_invalid",
        canary,
    )
    assert tool.calls == 0


def test_invoke_contains_hostile_transform_source_identity() -> None:
    canary = "private-source-canary"

    class HostileStr(str):
        def __ne__(self, other):
            raise RuntimeError(canary)

    stored = _stored_observation()
    manifest = _manifest("transform.hostile-source", ToolCategory.TRANSFORM)
    body = b"derived"
    output = object.__new__(TransformOutput)
    for name, value in (
        ("tool_id", manifest.tool_id),
        ("tool_version", manifest.version),
        ("source_artifact_id", HostileStr(stored.artifact.artifact_id)),
        ("mime_type", "text/plain"),
        ("body", body),
        ("sha256", hashlib.sha256(body).hexdigest()),
        ("runtime_ms", 1),
    ):
        object.__setattr__(output, name, value)
    tool = _TransformFake(manifest, output)
    registry = Registry()
    registry.register(manifest, tool)

    _safe_error(
        lambda: registry.invoke(manifest.tool_id, TransformInput(stored)),
        "protocol.source_invalid",
        canary,
    )
    assert tool.calls == 1


def test_invoke_rejects_stateful_transform_content_before_tool_call() -> None:
    canary = "private-input-content-canary"

    class StatefulBytes(bytes):
        calls = 0

        def __len__(self):
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError(canary)
            return super().__len__()

    stored = replace(_stored_observation(), content=StatefulBytes(b"source"))
    forged_input = object.__new__(TransformInput)
    object.__setattr__(forged_input, "source", stored)
    manifest = _manifest("transform.hostile-content", ToolCategory.TRANSFORM)
    tool = _TransformFake(manifest)
    registry = Registry()
    registry.register(manifest, tool)

    _safe_error(
        lambda: registry.invoke(manifest.tool_id, forged_input),
        "blob.content_invalid",
        canary,
    )
    assert tool.calls == 0


def test_invoke_returns_exact_builtin_protocol_scalars() -> None:
    acquisition_manifest = _manifest("acquisition.exact", ToolCategory.ACQUISITION)
    transform_manifest = _manifest("transform.exact", ToolCategory.TRANSFORM)
    registry = Registry()
    registry.register(acquisition_manifest, _AcquisitionFake(acquisition_manifest))
    registry.register(transform_manifest, _TransformFake(transform_manifest))

    acquired = registry.invoke(
        acquisition_manifest.tool_id,
        AcquisitionInput(_request(), "https://example.test/"),
    )
    transformed = registry.invoke(
        transform_manifest.tool_id, TransformInput(_stored_observation())
    )

    assert type(acquired.body) is bytes
    assert type(acquired.runtime_ms) is int
    assert type(transformed.source_artifact_id) is str
    assert type(transformed.body) is bytes
    assert type(transformed.runtime_ms) is int


@pytest.mark.parametrize(
    "limits, expected",
    [
        (ToolLimits(10, 4096, 1), "registry.output_limit"),
        (ToolLimits(1, 4096, 4096), "registry.runtime_limit"),
    ],
)
def test_invoke_enforces_declared_output_and_runtime_limits(
    limits: ToolLimits, expected: str
) -> None:
    manifest = _manifest("acquisition.http", ToolCategory.ACQUISITION, limits=limits)
    body = b"ok"
    output = AcquisitionOutput(
        tool_id=manifest.tool_id,
        tool_version=manifest.version,
        requested_url="https://example.test/",
        final_url="https://example.test/",
        status_code=200,
        mime_type="text/html",
        body=body,
        sha256=hashlib.sha256(body).hexdigest(),
        redirects=(),
        runtime_ms=1001,
    )
    registry = Registry()
    registry.register(manifest, _AcquisitionFake(manifest, output))

    assert (
        _code(
            lambda: registry.invoke(
                manifest.tool_id,
                AcquisitionInput(_request(), "https://example.test/"),
            )
        )
        == expected
    )


@pytest.mark.parametrize(
    "content_types, mime_type, allowed",
    [
        ((ContentType.HTML,), "text/plain", False),
        ((ContentType.FILE,), "text/html", False),
        ((ContentType.HTML,), "text/html", True),
        ((ContentType.FILE,), "application/pdf", True),
    ],
)
def test_acquisition_mime_must_match_request_content_type(
    content_types: tuple[ContentType, ...], mime_type: str, allowed: bool
) -> None:
    manifest = _manifest("acquisition.mime", ToolCategory.ACQUISITION)
    registry = Registry()
    registry.register(
        manifest,
        _AcquisitionFake(manifest, _acquisition_output(manifest, mime_type=mime_type)),
    )
    tool_input = AcquisitionInput(
        _request(content_types=content_types), "https://example.test/"
    )

    if allowed:
        assert isinstance(
            registry.invoke(manifest.tool_id, tool_input), AcquisitionOutput
        )
    else:
        _safe_error(
            lambda: registry.invoke(manifest.tool_id, tool_input),
            "scope.content_type_not_allowed",
            "private-mime-policy-canary",
        )


def test_acquisition_invoke_enforces_request_scope_for_redirect_and_final() -> None:
    manifest = _manifest("acquisition.http", ToolCategory.ACQUISITION)
    body = b"ok"
    output = AcquisitionOutput(
        tool_id=manifest.tool_id,
        tool_version=manifest.version,
        requested_url="https://example.test/start",
        final_url="https://outside.test/final",
        status_code=200,
        mime_type="text/plain",
        body=body,
        sha256=hashlib.sha256(body).hexdigest(),
        redirects=(
            AcquisitionRedirect(
                "https://example.test/start",
                "https://outside.test/final",
                302,
            ),
        ),
        runtime_ms=1,
    )
    registry = Registry()
    registry.register(manifest, _AcquisitionFake(manifest, output))

    assert (
        _code(
            lambda: registry.invoke(
                manifest.tool_id,
                AcquisitionInput(_request(), "https://example.test/start"),
            )
        )
        == "scope.origin_not_allowed"
    )

    intermediate_output = replace(
        output,
        final_url="https://example.test/final",
        redirects=(
            AcquisitionRedirect(
                "https://example.test/start", "https://outside.test/middle", 302
            ),
            AcquisitionRedirect(
                "https://outside.test/middle", "https://example.test/final", 302
            ),
        ),
    )
    intermediate_registry = Registry()
    intermediate_registry.register(
        manifest, _AcquisitionFake(manifest, intermediate_output)
    )
    assert (
        _code(
            lambda: intermediate_registry.invoke(
                manifest.tool_id,
                AcquisitionInput(_request(), "https://example.test/start"),
            )
        )
        == "scope.origin_not_allowed"
    )


@pytest.mark.parametrize(
    "governed_request, body, runtime_ms",
    [
        (_request(max_bytes=1), b"ok", 1),
        (_request(max_runtime_seconds=1), b"ok", 1001),
    ],
)
def test_acquisition_invoke_enforces_request_owned_byte_and_runtime_budget(
    governed_request: Request, body: bytes, runtime_ms: int
) -> None:
    manifest = _manifest("acquisition.http", ToolCategory.ACQUISITION)
    output = AcquisitionOutput(
        tool_id=manifest.tool_id,
        tool_version=manifest.version,
        requested_url="https://example.test/",
        final_url="https://example.test/",
        status_code=200,
        mime_type="text/html",
        body=body,
        sha256=hashlib.sha256(body).hexdigest(),
        redirects=(),
        runtime_ms=runtime_ms,
    )
    registry = Registry()
    registry.register(manifest, _AcquisitionFake(manifest, output))

    assert (
        _code(
            lambda: registry.invoke(
                manifest.tool_id,
                AcquisitionInput(governed_request, governed_request.scope.seeds[0]),
            )
        )
        == "budget.exceeded"
    )


def test_acquisition_request_count_includes_redirects_and_final_response() -> None:
    manifest = _manifest("acquisition.http", ToolCategory.ACQUISITION)
    body = b"ok"
    redirected = AcquisitionOutput(
        manifest.tool_id,
        manifest.version,
        "https://example.test/start",
        "https://example.test/final",
        200,
        "text/html",
        body,
        hashlib.sha256(body).hexdigest(),
        (
            AcquisitionRedirect(
                "https://example.test/start", "https://example.test/final", 302
            ),
        ),
        1,
    )

    blocked = Registry()
    blocked.register(manifest, _AcquisitionFake(manifest, redirected))
    assert (
        _code(
            lambda: blocked.invoke(
                manifest.tool_id,
                AcquisitionInput(
                    _request(max_requests=1), "https://example.test/start"
                ),
            )
        )
        == "budget.exceeded"
    )

    allowed = Registry()
    allowed.register(manifest, _AcquisitionFake(manifest, redirected))
    assert isinstance(
        allowed.invoke(
            manifest.tool_id,
            AcquisitionInput(_request(max_requests=2), "https://example.test/start"),
        ),
        AcquisitionOutput,
    )

    direct = replace(
        redirected,
        requested_url="https://example.test/final",
        redirects=(),
    )
    direct_registry = Registry()
    direct_registry.register(manifest, _AcquisitionFake(manifest, direct))
    assert isinstance(
        direct_registry.invoke(
            manifest.tool_id,
            AcquisitionInput(_request(max_requests=1), "https://example.test/final"),
        ),
        AcquisitionOutput,
    )


@pytest.mark.parametrize(
    "requested_url, final_url",
    [
        ("https://example.test/start", "https://example.test/final"),
        ("http://example.test/start", "https://example.test/final"),
    ],
)
def test_acquisition_redirect_allows_non_downgrade_transitions(
    requested_url: str, final_url: str
) -> None:
    manifest = _manifest("acquisition.redirect-safe", ToolCategory.ACQUISITION)
    redirect = AcquisitionRedirect(requested_url, final_url, 302)
    output = _acquisition_output(
        manifest,
        requested_url=requested_url,
        final_url=final_url,
        redirects=(redirect,),
    )
    registry = Registry()
    registry.register(manifest, _AcquisitionFake(manifest, output))
    request = _request(allowed_origins=("https://example.test", "http://example.test"))

    assert isinstance(
        registry.invoke(manifest.tool_id, AcquisitionInput(request, requested_url)),
        AcquisitionOutput,
    )


@pytest.mark.parametrize(
    "urls",
    [
        ("https://example.test/start", "http://example.test/final"),
        (
            "https://example.test/start",
            "https://example.test/middle",
            "http://example.test/final",
        ),
    ],
)
def test_acquisition_redirect_rejects_any_https_downgrade(
    urls: tuple[str, ...],
) -> None:
    manifest = _manifest("acquisition.redirect-downgrade", ToolCategory.ACQUISITION)
    redirects = tuple(
        AcquisitionRedirect(from_url, to_url, 302)
        for from_url, to_url in zip(urls, urls[1:])
    )
    output = _acquisition_output(
        manifest,
        requested_url=urls[0],
        final_url=urls[-1],
        redirects=redirects,
    )
    registry = Registry()
    registry.register(manifest, _AcquisitionFake(manifest, output))
    request = _request(
        max_requests=len(redirects) + 1,
        allowed_origins=("https://example.test", "http://example.test"),
    )

    _safe_error(
        lambda: registry.invoke(manifest.tool_id, AcquisitionInput(request, urls[0])),
        "gateway.https_downgrade",
        "private-redirect-policy-canary",
    )


def test_transform_invoke_rebuilds_mutated_stored_observation() -> None:
    manifest = _manifest("transform.text", ToolCategory.TRANSFORM)
    stored = _stored_observation()
    tool_input = TransformInput(stored)
    registry = Registry()
    registry.register(manifest, _TransformFake(manifest))
    object.__setattr__(tool_input.source.blob, "size_bytes", 999)

    assert (
        _code(lambda: registry.invoke(manifest.tool_id, tool_input))
        == "blob.size_mismatch"
    )


def test_invoke_rejects_unhealthy_tools_and_contains_fake_exceptions() -> None:
    unhealthy = _manifest("discovery.unhealthy", health=HealthStatus.UNHEALTHY)
    registry = Registry()
    registry.register(unhealthy, _DiscoveryFake(unhealthy))
    assert (
        _code(
            lambda: registry.invoke(
                unhealthy.tool_id, DiscoveryInput(scope=_request().scope)
            )
        )
        == "registry.ineligible"
    )

    class RaisingFake(_DiscoveryFake):
        """A fake that proves arbitrary exception text is contained."""

        def discover(self, tool_input: DiscoveryInput) -> object:
            del tool_input
            raise RuntimeError("private failure")

    healthy = _manifest("discovery.raises")
    registry.register(healthy, RaisingFake(healthy))
    with pytest.raises(ToolRegistryError) as caught:
        registry.invoke(healthy.tool_id, DiscoveryInput(scope=_request().scope))
    assert caught.value.code == "registry.tool_exception"
    assert str(caught.value) == "registry.tool_exception"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    formatted = "".join(
        traceback.format_exception(
            type(caught.value), caught.value, caught.value.__traceback__
        )
    )
    assert "private failure" not in formatted


def test_registration_does_not_change_public_request_shape_or_source() -> None:
    request_path = Path(inspect.getfile(Request))
    before_source = request_path.read_bytes()
    before_fields = tuple(field.name for field in fields(Request))
    request = _request()
    registry = Registry()
    manifest = _manifest("discovery.soa")

    registry.register(manifest, _DiscoveryFake(manifest))

    assert request_path.read_bytes() == before_source
    assert (
        tuple(field.name for field in fields(Request))
        == before_fields
        == (
            "scope",
            "site_skill",
            "explore_all_tools",
            "budgets",
        )
    )
    assert request == _request()


def test_registry_modules_have_no_forbidden_authority_or_discovery_hooks() -> None:
    package = Path(__file__).parents[2] / "src/web_listening/tool_registry"
    paths = (
        package / "manifest.py",
        package / "registry.py",
        package / "eligibility.py",
        package / "protocols/discovery.py",
        package / "protocols/acquisition.py",
        package / "protocols/transform.py",
    )
    forbidden_imports = {
        "http",
        "httpx",
        "os",
        "pathlib",
        "requests",
        "shutil",
        "socket",
        "sqlite3",
        "subprocess",
        "urllib.request",
        "web_listening.artifact.store",
        "web_listening.result",
        "web_listening.site_skill",
        "web_listening.tool_registry.runners",
    }
    forbidden_names = {"entry_points", "glob", "walk", "scan", "discover_plugins"}

    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert imports.isdisjoint(forbidden_imports), path
        assert names.isdisjoint(forbidden_names), path
