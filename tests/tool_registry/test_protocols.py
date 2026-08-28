"""Contract tests for the three deliberately separate tool protocols."""

# pylint: disable=duplicate-code,missing-class-docstring,missing-function-docstring
# pylint: disable=too-few-public-methods,unidiomatic-typecheck

from __future__ import annotations

import hashlib
import traceback
from dataclasses import FrozenInstanceError, replace

import pytest

from web_listening.artifact.identity import artifact_id as make_artifact_id
from web_listening.artifact.identity import (
    blob_relative_path,
)
from web_listening.artifact.lineage import DERIVED_FROM, lineage_id
from web_listening.artifact.model import (
    Artifact,
    ArtifactRole,
    Blob,
    Lineage,
    Observation,
    StoredObservation,
)
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.tool_registry.manifest import ToolRegistryError
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
    AcquisitionRedirect,
    AcquisitionTool,
    validate_mime_type,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryFailure,
    DiscoveryInput,
    DiscoveryOutput,
    DiscoveryTool,
)
from web_listening.tool_registry.protocols.transform import (
    TransformFailure,
    TransformInput,
    TransformOutput,
    TransformTool,
)


def _request() -> Request:
    return Request(
        scope=Scope(
            seeds=("https://example.test/",),
            allowed_origins=("https://example.test",),
            include_paths=("/**",),
            content_types=(ContentType.HTML,),
        ),
        site_skill=None,
        explore_all_tools=False,
        budgets=Budgets(
            max_requests=2,
            max_bytes=2048,
            max_runtime_seconds=10,
            max_tool_attempts_per_target=1,
        ),
    )


def _stored_observation() -> StoredObservation:
    content = b"source"
    digest = hashlib.sha256(content).hexdigest()
    artifact_id = make_artifact_id(digest, "text/plain", ArtifactRole.SOURCE)
    return StoredObservation(
        blob=Blob(
            sha256=digest,
            size_bytes=len(content),
            relative_path=blob_relative_path(digest),
        ),
        artifact=Artifact(
            artifact_id=artifact_id,
            blob_sha256=digest,
            mime_type="text/plain",
            role=ArtifactRole.SOURCE,
        ),
        observation=Observation(
            observation_id="observation-" + "1" * 32,
            artifact_id=artifact_id,
            source_url="https://example.test/report",
            observed_at="2026-08-25T00:00:00Z",
        ),
        lineage=(),
        content=content,
    )


class _DiscoveryFake:
    manifest = object()

    def discover(self, tool_input: DiscoveryInput) -> DiscoveryOutput:
        return DiscoveryOutput(
            tool_id="discovery.soa",
            tool_version="1.0.0",
            candidates=tool_input.scope.seeds,
            discovered_from=(tool_input.source_url,) * len(tool_input.scope.seeds),
        )


class _AcquisitionFake:
    manifest = object()

    def acquire(self, tool_input: AcquisitionInput) -> AcquisitionOutput:
        body = tool_input.target_url.encode("ascii")
        return AcquisitionOutput(
            tool_id="acquisition.http",
            tool_version="1.0.0",
            requested_url=tool_input.target_url,
            final_url=tool_input.target_url,
            status_code=200,
            mime_type="text/plain",
            body=body,
            sha256=hashlib.sha256(body).hexdigest(),
            redirects=(),
            runtime_ms=1,
        )


class _TransformFake:
    manifest = object()

    def transform(self, tool_input: TransformInput) -> TransformOutput:
        body = tool_input.source.content.upper()
        return TransformOutput(
            tool_id="transform.text",
            tool_version="1.0.0",
            source_artifact_id=tool_input.source.artifact.artifact_id,
            mime_type="text/plain",
            body=body,
            sha256=hashlib.sha256(body).hexdigest(),
            runtime_ms=1,
        )


def test_protocols_are_runtime_checkable_and_category_distinct() -> None:
    discovery = _DiscoveryFake()
    acquisition = _AcquisitionFake()
    transform = _TransformFake()

    assert isinstance(discovery, DiscoveryTool)
    assert not isinstance(discovery, (AcquisitionTool, TransformTool))
    assert isinstance(acquisition, AcquisitionTool)
    assert not isinstance(acquisition, (DiscoveryTool, TransformTool))
    assert isinstance(transform, TransformTool)
    assert not isinstance(transform, (DiscoveryTool, AcquisitionTool))


def test_protocol_inputs_and_outputs_are_immutable_and_category_specific() -> None:
    discovery_input = DiscoveryInput(
        scope=_request().scope,
        source_url="https://example.test/feed.xml",
        source_body=b"<feed/>",
        source_mime_type="application/xml",
    )
    acquisition_input = AcquisitionInput(
        request=_request(), target_url="https://example.test/report"
    )
    transform_input = TransformInput(source=_stored_observation())

    with pytest.raises(FrozenInstanceError):
        discovery_input.scope = _request().scope  # type: ignore[misc]
    assert not isinstance(discovery_input, (AcquisitionInput, TransformInput))
    assert not isinstance(acquisition_input, (DiscoveryInput, TransformInput))
    assert not isinstance(transform_input, (DiscoveryInput, AcquisitionInput))


def test_discovery_contract_carries_only_governed_source_and_provenance() -> None:
    tool_input = DiscoveryInput(
        scope=_request().scope,
        source_url="HTTPS://EXAMPLE.TEST:443/feed.xml",
        source_body=b"<feed/>",
        source_mime_type="application/xml",
    )
    output = DiscoveryOutput(
        "discovery.soa",
        "1.0.0",
        ("https://example.test/b", "https://example.test/a"),
        (tool_input.source_url, tool_input.source_url),
    )

    assert tool_input.source_url == "https://example.test/feed.xml"
    assert tool_input.source_body == b"<feed/>"
    assert tool_input.source_mime_type == "application/xml"
    assert output.discovered_from == (
        "https://example.test/feed.xml",
        "https://example.test/feed.xml",
    )


def test_discovery_contract_rejects_out_of_scope_source_or_unpaired_evidence() -> None:
    with pytest.raises(ToolRegistryError) as source_error:
        DiscoveryInput(
            scope=_request().scope,
            source_url="https://outside.test/feed.xml",
            source_body=b"<feed/>",
            source_mime_type="application/xml",
        )
    assert source_error.value.code == "scope.origin_not_allowed"

    with pytest.raises(ToolRegistryError) as output_error:
        DiscoveryOutput(
            "discovery.soa",
            "1.0.0",
            ("https://example.test/a",),
            (),
        )
    assert output_error.value.code == "protocol.output_invalid"


def test_discovery_contract_rejects_omitted_provenance() -> None:
    with pytest.raises(ToolRegistryError) as caught:
        DiscoveryOutput(
            "discovery.soa",
            "1.0.0",
            ("https://example.test/a",),
        )

    assert caught.value.code == "protocol.output_invalid"


def test_url_values_use_request_canonical_syntax_without_network_policy() -> None:
    source = "https://example.test/feed.xml"
    output = DiscoveryOutput(
        tool_id="discovery.soa",
        tool_version="1.0.0",
        candidates=(
            "HTTPS://BÜCHER.EXAMPLE:443/a/%7e?x=%41",
            "http://127.0.0.1:8080/",
            "http://[2001:0db8::1]/",
        ),
        discovered_from=(source, source, source),
    )

    assert output.candidates == (
        "https://xn--bcher-kva.example/a/~?x=A",
        "http://127.0.0.1:8080/",
        "http://[2001:db8::1]/",
    )
    assert type(output.candidates) is tuple
    assert all(type(value) is str for value in output.candidates)


@pytest.mark.parametrize(
    "hostile_hook, canary",
    [
        ("len", "private-discovery-length-canary"),
        ("iter", "private-discovery-iterator-canary"),
    ],
)
def test_discovery_output_rejects_tuple_subclass_hooks(
    hostile_hook: str, canary: str
) -> None:
    class HostileTuple(tuple):
        def __len__(self):
            if hostile_hook == "len":
                raise RuntimeError(canary)
            return super().__len__()

        def __iter__(self):
            if hostile_hook == "iter":
                raise RuntimeError(canary)
            return super().__iter__()

    with pytest.raises(ToolRegistryError) as caught:
        DiscoveryOutput(
            "discovery.hostile",
            "1.0.0",
            HostileTuple(("https://example.test/",)),
        )
    error = caught.value
    assert error.code == "protocol.output_invalid"
    assert str(error) == "protocol.output_invalid"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert canary not in "".join(
        traceback.format_exception(type(error), error, error.__traceback__)
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://-bad.example/",
        "https://256.1.1.1/",
        "https://example.test/%GG",
        "https://alice@example.test/",
        "https://example.test/#fragment",
        "https://example.test/a\\b",
    ],
)
def test_all_url_evidence_rejects_malformed_authority_or_path(value: str) -> None:
    with pytest.raises(ValueError) as caught:
        DiscoveryOutput("discovery.soa", "1.0.0", (value,))
    assert getattr(caught.value, "code", None) == "protocol.url_invalid"


def test_malformed_port_is_contained_without_private_exception_chain() -> None:
    canary = "private-port-canary"
    value = f"https://example.test:{canary}/"
    with pytest.raises(ValueError) as caught:
        DiscoveryOutput("discovery.soa", "1.0.0", (value,))
    error = caught.value
    assert getattr(error, "code", None) == "protocol.url_invalid"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert canary not in "".join(
        __import__("traceback").format_exception(
            type(error), error, error.__traceback__
        )
    )


@pytest.mark.parametrize("value", ["text/.", "./plain", "text/-"])
def test_protocol_mime_uses_artifact_token_rules_without_error_context(
    value: str,
) -> None:
    with pytest.raises(ValueError) as caught:
        validate_mime_type(value)
    assert getattr(caught.value, "code", None) == "protocol.mime_invalid"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_protocol_mime_accepts_plain_and_vendor_json_tokens() -> None:
    assert validate_mime_type("text/plain") == "text/plain"
    assert validate_mime_type("application/vnd.example+json") == (
        "application/vnd.example+json"
    )


def test_acquisition_input_rebuilds_request_and_enforces_scope() -> None:
    canonical = AcquisitionInput(
        Request(
            scope=Scope(
                seeds=("HTTPS://EXAMPLE.TEST:443/",),
                allowed_origins=("HTTPS://EXAMPLE.TEST:443",),
                include_paths=("/**",),
                content_types=(ContentType.HTML,),
            ),
            site_skill=None,
            explore_all_tools=False,
            budgets=Budgets(2, 2048, 10, 1),
        ),
        "HTTPS://EXAMPLE.TEST:443/report/%7e",
    )

    assert canonical.target_url == "https://example.test/report/~"
    assert canonical.request.scope.allowed_origins == ("https://example.test",)
    with pytest.raises(ValueError) as caught:
        AcquisitionInput(_request(), "https://outside.test/report")
    assert getattr(caught.value, "code", None) == "scope.origin_not_allowed"


def test_valid_outputs_bind_content_hashes_and_redirect_evidence() -> None:
    body = b"report"
    redirect = AcquisitionRedirect(
        from_url="https://example.test/start",
        to_url="https://example.test/report",
        status_code=302,
    )
    acquisition = AcquisitionOutput(
        tool_id="acquisition.http",
        tool_version="1.0.0",
        requested_url=redirect.from_url,
        final_url=redirect.to_url,
        status_code=200,
        mime_type="text/html",
        body=body,
        sha256=hashlib.sha256(body).hexdigest(),
        redirects=(redirect,),
        runtime_ms=25,
    )
    transformed = TransformOutput(
        tool_id="transform.text",
        tool_version="1.0.0",
        source_artifact_id=_stored_observation().artifact.artifact_id,
        mime_type="text/plain",
        body=body,
        sha256=hashlib.sha256(body).hexdigest(),
        runtime_ms=3,
    )

    assert acquisition.redirects == (redirect,)
    assert transformed.source_artifact_id.startswith("artifact-")


def test_acquisition_redirect_evidence_must_connect_requested_to_final() -> None:
    body = b"report"
    with pytest.raises(ValueError) as caught:
        AcquisitionOutput(
            tool_id="acquisition.http",
            tool_version="1.0.0",
            requested_url="https://example.test/start",
            final_url="https://example.test/report",
            status_code=200,
            mime_type="text/html",
            body=body,
            sha256=hashlib.sha256(body).hexdigest(),
            redirects=(
                AcquisitionRedirect(
                    from_url="https://unrelated.test/",
                    to_url="https://example.test/report",
                    status_code=302,
                ),
            ),
            runtime_ms=25,
        )
    assert getattr(caught.value, "code", None) == "protocol.redirects_invalid"


@pytest.mark.parametrize(
    "factory, code",
    [
        (
            lambda: DiscoveryOutput(
                tool_id="discovery.soa",
                tool_version="1.0.0",
                candidates=("not-a-url",),
            ),
            "protocol.url_invalid",
        ),
        (
            lambda: AcquisitionOutput(
                tool_id="acquisition.http",
                tool_version="1.0.0",
                requested_url="https://example.test/",
                final_url="https://example.test/",
                status_code=200,
                mime_type="text/plain",
                body=b"x",
                sha256="0" * 64,
                redirects=(),
                runtime_ms=1,
            ),
            "protocol.hash_mismatch",
        ),
        (
            lambda: TransformOutput(
                tool_id="transform.text",
                tool_version="1.0.0",
                source_artifact_id="artifact-" + "1" * 64,
                mime_type="text/plain; charset=utf-8",
                body=b"x",
                sha256=hashlib.sha256(b"x").hexdigest(),
                runtime_ms=1,
            ),
            "protocol.mime_invalid",
        ),
    ],
)
def test_malformed_outputs_fail_with_stable_safe_codes(factory, code: str) -> None:
    with pytest.raises(ValueError) as caught:
        factory()
    assert getattr(caught.value, "code", None) == code


def test_failures_are_separate_immutable_safe_values() -> None:
    failures = (
        DiscoveryFailure("discovery.soa", "1.0.0", "discovery.no_candidates"),
        AcquisitionFailure("acquisition.http", "1.0.0", "gateway.timeout"),
        TransformFailure("transform.text", "1.0.0", "transform.unsupported"),
    )

    assert len({type(failure) for failure in failures}) == 3
    with pytest.raises(FrozenInstanceError):
        failures[0].code = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError) as caught:
        AcquisitionFailure("acquisition.http", "1.0.0", "secret=private")
    assert getattr(caught.value, "code", None) == "protocol.error_code_invalid"


def test_acquisition_failure_preserves_validated_usage_evidence() -> None:
    failure = AcquisitionFailure(
        "acquisition.http",
        "1.0.0",
        "gateway.timeout",
        requests=2,
        bytes_received=17,
        runtime_ms=901,
    )

    assert (failure.requests, failure.bytes_received, failure.runtime_ms) == (
        2,
        17,
        901,
    )
    for name in ("requests", "bytes_received", "runtime_ms"):
        with pytest.raises(ToolRegistryError) as caught:
            replace(failure, **{name: -1})
        assert caught.value.code == "protocol.usage_invalid"


def test_acquisition_output_usage_is_validated_and_legacy_construction_is_compatible() -> (
    None
):
    body = b"body"
    legacy = AcquisitionOutput(
        "acquisition.http",
        "1.0.0",
        "https://example.test/",
        "https://example.test/",
        200,
        "text/html",
        body,
        hashlib.sha256(body).hexdigest(),
        (),
        5,
    )
    measured = AcquisitionOutput(
        "acquisition.http",
        "1.0.0",
        "https://example.test/",
        "https://example.test/",
        200,
        "text/html",
        body,
        hashlib.sha256(body).hexdigest(),
        (),
        5,
        requests=2,
        bytes_received=17,
    )

    assert (legacy.requests, legacy.bytes_received) == (1, len(body))
    assert (measured.requests, measured.bytes_received) == (2, 17)
    for values in ((0, 17), (2, 3), (True, 17), (2, False)):
        with pytest.raises(ToolRegistryError) as caught:
            replace(measured, requests=values[0], bytes_received=values[1])
        assert caught.value.code == "protocol.usage_invalid"


def test_replace_legacy_acquisition_output_honors_new_explicit_usage() -> None:
    body = b"body"
    legacy = AcquisitionOutput(
        "acquisition.http",
        "1.0.0",
        "https://example.test/",
        "https://example.test/",
        200,
        "text/html",
        body,
        hashlib.sha256(body).hexdigest(),
        (),
        5,
    )

    measured = replace(legacy, requests=2, bytes_received=17)

    assert (measured.requests, measured.bytes_received) == (2, 17)


@pytest.mark.parametrize(
    "mutate, code",
    [
        (
            lambda value: replace(value, content=b"tampered"),
            "blob.sha256_mismatch",
        ),
        (
            lambda value: replace(
                value,
                blob=replace(value.blob, relative_path="blobs/aa/not-canonical.blob"),
            ),
            "blob.path_invalid",
        ),
        (
            lambda value: replace(
                value,
                artifact=replace(value.artifact, artifact_id="artifact-not-hex"),
            ),
            "artifact.id_invalid",
        ),
        (
            lambda value: replace(
                value,
                observation=replace(
                    value.observation, artifact_id="artifact-" + "2" * 64
                ),
            ),
            "observation.invalid",
        ),
        (
            lambda value: replace(
                value,
                observation=replace(value.observation, observed_at="not-a-time"),
            ),
            "observation.time_invalid",
        ),
    ],
)
def test_transform_input_rebuilds_and_validates_stored_observation(
    mutate, code: str
) -> None:
    with pytest.raises(ValueError) as caught:
        TransformInput(mutate(_stored_observation()))
    assert getattr(caught.value, "code", None) == code


def test_transform_input_validates_role_and_lineage_cross_links() -> None:
    stored = _stored_observation()
    source_observation_id = "observation-" + "2" * 32
    source_artifact_id = "artifact-" + "2" * 64
    edge = Lineage(
        lineage_id=lineage_id(
            observation_id=stored.observation.observation_id,
            artifact_id=stored.artifact.artifact_id,
            source_observation_id=source_observation_id,
            source_artifact_id=source_artifact_id,
        ),
        observation_id=stored.observation.observation_id,
        artifact_id=stored.artifact.artifact_id,
        relation=DERIVED_FROM,
        source_observation_id=source_observation_id,
        source_artifact_id=source_artifact_id,
    )

    with pytest.raises(ValueError) as caught:
        TransformInput(replace(stored, lineage=(edge,)))
    assert getattr(caught.value, "code", None) == "lineage.forbidden"
