"""Explicit in-memory registration for typed tool contracts."""

# pylint: disable=too-many-return-statements,unidiomatic-typecheck

from __future__ import annotations

import inspect
from dataclasses import dataclass, replace
from types import MemberDescriptorType
from typing import Any
from urllib.parse import urlsplit

from web_listening.request.model import ContentType
from web_listening.request.validate import compile_access_policy
from web_listening.tool_registry.eligibility import (
    EligibilityDecision,
    EligibilityRequirements,
    _rebuild_requirements,
    evaluate_eligibility,
)
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
    ToolRegistryError,
    validate_tool_id,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryFailure,
    DiscoveryInput,
    DiscoveryOutput,
)
from web_listening.tool_registry.protocols.transform import (
    TransformFailure,
    TransformInput,
    TransformOutput,
)

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
class _Registration:
    manifest: ToolManifest
    tool: Any


_METHODS = {
    ToolCategory.DISCOVERY: "discover",
    ToolCategory.ACQUISITION: "acquire",
    ToolCategory.TRANSFORM: "transform",
}
_CALL_FAILED = object()
_ATTRIBUTE_MISSING = object()


class Registry:
    """Register caller-supplied tools without scanning or installation authority."""

    def __init__(self) -> None:
        self._registrations: dict[str, _Registration] = {}

    def register(self, manifest: ToolManifest, tool: Any) -> None:
        """Register one exactly matching manifest and protocol implementation."""
        snapshot = _snapshot_manifest(manifest)
        if snapshot.tool_id in self._registrations:
            raise ToolRegistryError("registry.duplicate_id")
        tool_manifest = _snapshot_manifest(_static_manifest(tool))
        if not _manifests_equal(tool_manifest, snapshot):
            raise ToolRegistryError("registry.identity_mismatch")
        matches = tuple(
            category
            for category, method_name in _METHODS.items()
            if _static_callable(tool, method_name)
        )
        if matches != (snapshot.category,):
            raise ToolRegistryError("registry.protocol_mismatch")
        self._registrations[snapshot.tool_id] = _Registration(snapshot, tool)

    def query(
        self, *, category: ToolCategory | None = None
    ) -> tuple[ToolManifest, ...]:
        """Return immutable metadata in explicit registration order."""
        if category is not None and not isinstance(category, ToolCategory):
            raise ToolRegistryError("registry.category_invalid")
        return tuple(
            _snapshot_manifest(registration.manifest)
            for registration in self._registrations.values()
            if category is None or registration.manifest.category is category
        )

    def eligibility(
        self, requirements: EligibilityRequirements
    ) -> tuple[EligibilityDecision, ...]:
        """Return one deterministic decision for every registered tool."""
        requirements = _rebuild_requirements(requirements)
        return tuple(
            evaluate_eligibility(registration.manifest, requirements)
            for registration in self._registrations.values()
        )

    def eligible(
        self, requirements: EligibilityRequirements
    ) -> tuple[ToolManifest, ...]:
        """Filter compatible manifests without ranking or choosing among them."""
        decisions = self.eligibility(requirements)
        return tuple(
            _snapshot_manifest(self._registrations[decision.tool_id].manifest)
            for decision in decisions
            if decision.eligible and decision.tool_id in self._registrations
        )

    def invoke(self, tool_id: str, tool_input: ToolInput) -> ToolResult:
        """Call one registered fake/protocol implementation and validate its value."""
        if type(tool_id) is not str:
            raise ToolRegistryError("manifest.id_invalid")
        validate_tool_id(tool_id)
        registration = self._registrations.get(tool_id)
        if registration is None:
            raise ToolRegistryError("registry.not_found")
        current_manifest = _snapshot_manifest(_static_manifest(registration.tool))
        if not _manifests_equal(current_manifest, registration.manifest):
            raise ToolRegistryError("registry.identity_mismatch")
        tool_input = _rebuild_input(tool_input)
        category = _input_category(tool_input)
        if registration.manifest.category is not category:
            raise ToolRegistryError("registry.input_mismatch")
        if isinstance(tool_input, DiscoveryInput):
            input_bytes = len(tool_input.source_body)
        elif isinstance(tool_input, TransformInput):
            input_bytes = len(tool_input.source.content)
        else:
            input_bytes = 0
        decision = evaluate_eligibility(
            registration.manifest,
            EligibilityRequirements(category=category, input_bytes=input_bytes),
        )
        if not decision.eligible:
            raise ToolRegistryError("registry.ineligible")
        output = _contained_call(registration.tool, tool_input)
        if output is _CALL_FAILED:
            raise ToolRegistryError("registry.tool_exception")
        return _validate_output(registration.manifest, tool_input, output)


def _snapshot_manifest(value: object) -> ToolManifest:
    snapshot, error = _contained_manifest_snapshot(value)
    if error is not None:
        raise ToolRegistryError(error)
    return snapshot  # type: ignore[return-value]


def _contained_manifest_snapshot(
    value: object,
) -> tuple[ToolManifest | None, str | None]:
    try:
        if type(value) is not ToolManifest:
            return None, "registry.manifest_invalid"
        if type(value.tool_id) is not str:
            return None, "manifest.id_invalid"
        if type(value.version) is not str:
            return None, "manifest.version_invalid"
        if type(value.category) is not ToolCategory:
            return None, "manifest.category_invalid"
        if type(value.distribution) is not ToolDistribution:
            return None, "manifest.distribution_invalid"
        if type(value.capabilities) is not frozenset or any(
            type(item) is not str for item in value.capabilities
        ):
            return None, "manifest.capabilities_invalid"
        if type(value.limits) is not ToolLimits:
            return None, "manifest.limits_invalid"
        limit_values = (
            value.limits.max_runtime_seconds,
            value.limits.max_input_bytes,
            value.limits.max_output_bytes,
        )
        if any(type(item) is not int for item in limit_values):
            return None, "manifest.limits_invalid"
        if type(value.health) is not HealthStatus:
            return None, "manifest.health_invalid"
        if type(value.qualification) is not QualificationStatus:
            return None, "manifest.qualification_invalid"
        limits = ToolLimits(
            *limit_values,
        )
        return (
            ToolManifest(
                value.tool_id,
                value.version,
                value.category,
                value.distribution,
                value.capabilities,
                limits,
                value.health,
                value.qualification,
            ),
            None,
        )
    except ToolRegistryError as exc:
        return None, exc.code
    except Exception:  # pylint: disable=broad-exception-caught
        return None, "registry.manifest_invalid"


def _static_attribute(value: object, name: str) -> object:
    try:
        return inspect.getattr_static(value, name, _ATTRIBUTE_MISSING)
    except Exception:  # pylint: disable=broad-exception-caught
        return _ATTRIBUTE_MISSING


def _static_manifest(value: object) -> object:
    descriptor = _static_attribute(value, "manifest")
    if type(descriptor) is not MemberDescriptorType:
        return descriptor
    try:
        # pylint: disable-next=unnecessary-dunder-call
        return descriptor.__get__(value, type(value))
    except Exception:  # pylint: disable=broad-exception-caught
        return _ATTRIBUTE_MISSING


def _static_callable(value: object, name: str) -> bool:
    attribute = _static_attribute(value, name)
    try:
        return attribute is not _ATTRIBUTE_MISSING and callable(attribute)
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def _manifests_equal(left: ToolManifest, right: ToolManifest) -> bool:
    try:
        return left == right
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def _rebuild_input(tool_input: ToolInput) -> ToolInput:
    rebuilt, error = _contained_input(tool_input)
    if error is not None:
        raise ToolRegistryError(error)
    return rebuilt  # type: ignore[return-value]


def _contained_input(tool_input: object) -> tuple[ToolInput | None, str | None]:
    try:
        if type(tool_input) is DiscoveryInput:
            return (
                DiscoveryInput(
                    tool_input.scope,
                    getattr(tool_input, "source_url", None),
                    getattr(tool_input, "source_body", b""),
                    getattr(
                        tool_input,
                        "source_mime_type",
                        "application/octet-stream",
                    ),
                ),
                None,
            )
        if type(tool_input) is AcquisitionInput:
            return AcquisitionInput(tool_input.request, tool_input.target_url), None
        if type(tool_input) is TransformInput:
            return TransformInput(tool_input.source), None
    except ToolRegistryError as exc:
        return None, exc.code
    except Exception:  # pylint: disable=broad-exception-caught
        return None, "registry.input_mismatch"
    return None, "registry.input_mismatch"


def _input_category(tool_input: ToolInput) -> ToolCategory:
    if type(tool_input) is DiscoveryInput:
        return ToolCategory.DISCOVERY
    if type(tool_input) is AcquisitionInput:
        return ToolCategory.ACQUISITION
    if type(tool_input) is TransformInput:
        return ToolCategory.TRANSFORM
    raise ToolRegistryError("registry.input_mismatch")


def _call(tool: Any, tool_input: ToolInput) -> object:
    if type(tool_input) is DiscoveryInput:
        return tool.discover(tool_input)
    if type(tool_input) is AcquisitionInput:
        return tool.acquire(tool_input)
    return tool.transform(tool_input)


def _contained_call(tool: Any, tool_input: ToolInput) -> object:
    try:
        return _call(tool, tool_input)
    except Exception:  # pylint: disable=broad-exception-caught
        return _CALL_FAILED


def _validate_output(  # pylint: disable=too-many-branches
    manifest: ToolManifest, tool_input: ToolInput, output: object
) -> ToolResult:
    allowed_types: tuple[type[Any], ...]
    if type(tool_input) is DiscoveryInput:
        allowed_types = (DiscoveryOutput, DiscoveryFailure)
    elif type(tool_input) is AcquisitionInput:
        allowed_types = (AcquisitionOutput, AcquisitionFailure)
    else:
        allowed_types = (TransformOutput, TransformFailure)
    if type(output) not in allowed_types:
        raise ToolRegistryError("registry.output_invalid")
    output, error = _contained_output(output)
    if error is not None:
        raise ToolRegistryError(error)
    if output.tool_id != manifest.tool_id or output.tool_version != manifest.version:
        raise ToolRegistryError("registry.output_identity_mismatch")
    if isinstance(output, DiscoveryOutput):
        assert output.discovered_from is not None
        assert isinstance(tool_input, DiscoveryInput)
        if any(source != tool_input.source_url for source in output.discovered_from):
            raise ToolRegistryError("registry.output_invalid")
        output_bytes = sum(
            len(value.encode("utf-8"))
            for values in (output.candidates, output.discovered_from)
            for value in values
        )
        if output_bytes > manifest.limits.max_output_bytes:
            raise ToolRegistryError("registry.output_limit")
    elif isinstance(output, AcquisitionOutput):
        if output.requested_url != tool_input.target_url:
            raise ToolRegistryError("registry.output_invalid")
        _validate_acquisition_authority(tool_input, output)
        _validate_resource_use(manifest, len(output.body), output.runtime_ms)
    elif isinstance(output, TransformOutput):
        if output.source_artifact_id != tool_input.source.artifact.artifact_id:
            raise ToolRegistryError("registry.output_invalid")
        _validate_resource_use(manifest, len(output.body), output.runtime_ms)
    return output


def _revalidate_output(output: ToolResult) -> ToolResult:
    """Reconstruct an untrusted value so frozen type identity is not sufficient."""
    if isinstance(output, DiscoveryOutput):
        return DiscoveryOutput(
            output.tool_id,
            output.tool_version,
            output.candidates,
            getattr(output, "discovered_from", None),
        )
    if isinstance(output, AcquisitionOutput):
        redirects = tuple(replace(redirect) for redirect in output.redirects)
        return replace(output, redirects=redirects)
    return replace(output)


def _contained_output(value: object) -> tuple[ToolResult | None, str | None]:
    try:
        return _revalidate_output(value), None  # type: ignore[arg-type]
    except ToolRegistryError as exc:
        return None, exc.code
    except Exception:  # pylint: disable=broad-exception-caught
        return None, "registry.output_invalid"


def _validate_resource_use(
    manifest: ToolManifest, output_bytes: int, runtime_ms: int
) -> None:
    if output_bytes > manifest.limits.max_output_bytes:
        raise ToolRegistryError("registry.output_limit")
    if runtime_ms > manifest.limits.max_runtime_seconds * 1000:
        raise ToolRegistryError("registry.runtime_limit")


def _validate_acquisition_authority(
    tool_input: AcquisitionInput, output: AcquisitionOutput
) -> None:
    policy = compile_access_policy(tool_input.request)
    for redirect in output.redirects:
        if (
            urlsplit(redirect.from_url).scheme == "https"
            and urlsplit(redirect.to_url).scheme == "http"
        ):
            raise ToolRegistryError("gateway.https_downgrade")
    urls = (
        output.requested_url,
        *(
            url
            for redirect in output.redirects
            for url in (redirect.from_url, redirect.to_url)
        ),
        output.final_url,
    )
    for url in urls:
        decision = policy.decide_url(url)
        if not decision.allowed:
            raise ToolRegistryError(decision.code)
    content_type = (
        ContentType.HTML if output.mime_type == "text/html" else ContentType.FILE
    )
    decision = policy.decide_content_type(content_type)
    if not decision.allowed:
        raise ToolRegistryError(decision.code)
    runtime_seconds = (output.runtime_ms + 999) // 1000
    for name, amount in (
        ("max_requests", len(output.redirects) + 1),
        ("max_bytes", len(output.body)),
        ("max_runtime_seconds", runtime_seconds),
    ):
        decision = policy.decide_budget(name, amount)
        if not decision.allowed:
            raise ToolRegistryError(decision.code)
