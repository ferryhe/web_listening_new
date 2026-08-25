"""Offline contract tests for the pure Result and Manifest boundary."""

# pylint: disable=too-many-lines,duplicate-code

from __future__ import annotations

import ast
import copy
import hashlib
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from web_listening.artifact.identity import artifact_id, blob_relative_path
from web_listening.artifact.lineage import lineage_id
from web_listening.artifact.model import (
    Artifact,
    ArtifactRole,
    Blob,
    Lineage,
    Observation,
    StoredObservation,
)
from web_listening.result.errors import (
    ResultValidationError,
    SafeError,
    canonical_json_bytes,
)
from web_listening.result.manifest import (
    manifest_from_observations,
)
from web_listening.result.model import Result, ResultStatus, Usage

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_STATUS = {
    "completed.v1.json": ResultStatus.COMPLETED,
    "partial.v1.json": ResultStatus.PARTIAL,
    "rejected-boundary.v1.json": ResultStatus.REJECTED,
    "failed.v1.json": ResultStatus.FAILED,
}
HTML = b"<!doctype html><html><body>offline annual report</body></html>"
MARKDOWN = b"# Offline annual report\n"


def fixture_payload(name: str) -> dict[str, object]:
    """Load one fixed, versioned, offline Result fixture."""
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(("name", "status"), FIXTURE_STATUS.items())
def test_versioned_fixtures_round_trip_to_byte_stable_canonical_json(
    name: str, status: ResultStatus
) -> None:
    """The same fixed facts always produce identical canonical Result bytes."""
    payload = fixture_payload(name)

    first = Result.from_dict(payload)
    second = Result.from_dict(copy.deepcopy(payload))

    assert first.status is status
    assert first.schema_version == "web-listening-result.v1"
    assert first.manifest.schema_version == "web-listening-manifest.v1"
    assert first.canonical_json_bytes() == second.canonical_json_bytes()
    assert json.loads(first.canonical_json_bytes()) == payload


def test_result_status_has_exactly_the_four_versioned_values() -> None:
    """Interfaces cannot invent an additional outcome outside the contract."""
    assert [status.value for status in ResultStatus] == [
        "completed",
        "partial",
        "rejected",
        "failed",
    ]


def test_partial_fixture_retains_explicit_attempt_order_and_all_evidence() -> None:
    """Failed, skipped, and successful attempts remain in their given order."""
    result = Result.from_dict(fixture_payload("partial.v1.json"))
    payload = result.to_dict()

    assert [attempt.order for attempt in result.attempts] == [0, 1, 2]
    assert [attempt.outcome for attempt in result.attempts] == [
        "failed",
        "skipped",
        "succeeded",
    ]
    assert [attempt.attempt_id for attempt in result.attempts] == [
        "attempt-partial-0",
        "attempt-partial-1",
        "attempt-partial-2",
    ]
    assert payload["manifest"]["redirects"] == [
        {
            "order": 0,
            "from_url": "https://www.casact.org/about/governance/annual-reports",
            "to_url": "https://www.casact.org/about/governance/annual-reports/",
            "http_status": 301,
            "decision": "followed",
        }
    ]
    assert payload["manifest"]["site_skill"] == {
        "version": "7",
        "sha256": "1" * 64,
    }
    derived = result.artifacts[1]
    assert derived.role == "derived"
    assert derived.lineage[0].source_artifact_id == result.artifacts[0].artifact_id
    assert result.usage == Usage(2, 30, 200, 2)


def test_manifest_builds_only_from_public_artifact_facts() -> None:
    """Existing immutable Artifact models are copied without store/path access."""
    source_sha = hashlib.sha256(HTML).hexdigest()
    source_artifact_id = artifact_id(source_sha, "text/html", ArtifactRole.SOURCE)
    source_observation_id = "observation-11111111111111111111111111111111"
    source = StoredObservation(
        blob=Blob(source_sha, len(HTML), blob_relative_path(source_sha)),
        artifact=Artifact(
            source_artifact_id, source_sha, "text/html", ArtifactRole.SOURCE
        ),
        observation=Observation(
            source_observation_id,
            source_artifact_id,
            "https://www.soa.org/research/annual/",
            "2026-08-25T12:00:00Z",
        ),
        lineage=(),
        content=HTML,
    )
    derived_sha = hashlib.sha256(MARKDOWN).hexdigest()
    derived_artifact_id = artifact_id(
        derived_sha, "text/markdown", ArtifactRole.DERIVED
    )
    derived_observation_id = "observation-22222222222222222222222222222222"
    edge = Lineage(
        lineage_id=lineage_id(
            observation_id=derived_observation_id,
            artifact_id=derived_artifact_id,
            source_observation_id=source_observation_id,
            source_artifact_id=source_artifact_id,
        ),
        observation_id=derived_observation_id,
        artifact_id=derived_artifact_id,
        relation="derived_from",
        source_observation_id=source_observation_id,
        source_artifact_id=source_artifact_id,
    )
    derived = StoredObservation(
        blob=Blob(derived_sha, len(MARKDOWN), blob_relative_path(derived_sha)),
        artifact=Artifact(
            derived_artifact_id,
            derived_sha,
            "text/markdown",
            ArtifactRole.DERIVED,
        ),
        observation=Observation(
            derived_observation_id,
            derived_artifact_id,
            "urn:web-listening:derived:markdown",
            "2026-08-25T12:00:01Z",
        ),
        lineage=(edge,),
        content=MARKDOWN,
    )
    completed = Result.from_dict(fixture_payload("completed.v1.json"))

    manifest = manifest_from_observations(
        run_id="run-public-artifacts-001",
        generated_at="2026-08-25T12:00:02Z",
        requested_url="https://www.soa.org/research/annual",
        current_url="https://www.soa.org/research/annual/",
        final_url="https://www.soa.org/research/annual/",
        http_status=200,
        tool_id="web_http",
        tool_version="1.0.0",
        redirects=completed.manifest.redirects,
        site_skill=completed.site_skill_used,
        attempts=completed.attempts,
        observations=(source, derived),
        usage=completed.usage,
    )
    result = Result(
        status=ResultStatus.COMPLETED,
        manifest=manifest,
        site_skill_used=completed.site_skill_used,
        site_skill_update=None,
        attempts=completed.attempts,
        errors=(),
        usage=completed.usage,
    )
    rendered = result.to_dict()

    assert manifest.sha256 == source_sha
    assert manifest.size_bytes == len(HTML)
    assert [artifact.role for artifact in manifest.artifacts] == [
        "source",
        "derived",
    ]
    assert manifest.artifacts[1].lineage == (edge,)
    assert "relative_path" not in json.dumps(rendered)
    assert HTML not in result.canonical_json_bytes()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("final_url", "https://www.soa.org/research/different/"),
        ("tool_id", "different_tool"),
        ("http_status", 201),
    ],
)
def test_manifest_rejects_success_facts_that_disagree_with_attempt_or_artifact(
    field: str, value: object
) -> None:
    """Top-level success evidence must identify the successful attempt/snapshot."""
    payload = fixture_payload("completed.v1.json")
    payload["manifest"][field] = value

    with pytest.raises(ResultValidationError) as caught:
        Result.from_dict(payload)

    assert caught.value.code == "manifest.success_facts_invalid"


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("duplicate", "attempt.duplicate"),
        ("gap", "attempt.order_invalid"),
    ],
)
def test_attempts_reject_duplicates_or_non_explicit_order(
    mutation: str, expected_code: str
) -> None:
    """Attempt order is caller evidence and is never sorted or deduplicated."""
    payload = fixture_payload("partial.v1.json")
    attempts = payload["attempts"]
    manifest_attempts = payload["manifest"]["attempts"]
    if mutation == "duplicate":
        duplicate = copy.deepcopy(attempts[-1])
        duplicate["order"] = 3
        attempts.append(duplicate)
        manifest_attempts.append(copy.deepcopy(duplicate))
    else:
        attempts[1]["order"] = 7
        manifest_attempts[1]["order"] = 7

    with pytest.raises(ResultValidationError) as caught:
        Result.from_dict(payload)

    assert caught.value.code == expected_code


@pytest.mark.parametrize(
    ("field", "value", "expected_code"),
    [
        ("requests", 9, "usage.requests_mismatch"),
        ("bytes_received", 99, "usage.bytes_mismatch"),
        ("tool_attempts", 3, "usage.tool_attempts_mismatch"),
        ("runtime_ms", 10, "usage.runtime_mismatch"),
        ("requests", -1, "usage.invalid"),
        ("requests", True, "usage.invalid"),
    ],
)
def test_usage_is_nonnegative_and_consistent_with_attempt_facts(
    field: str, value: object, expected_code: str
) -> None:
    """Actual usage cannot contradict values explicitly recorded per attempt."""
    payload = fixture_payload("partial.v1.json")
    payload["usage"][field] = value
    payload["manifest"]["usage"][field] = value

    with pytest.raises(ResultValidationError) as caught:
        Result.from_dict(payload)

    assert caught.value.code == expected_code


@pytest.mark.parametrize(
    ("fixture", "status", "expected_code"),
    [
        ("failed.v1.json", "completed", "result.completed_requires_artifact"),
        ("completed.v1.json", "partial", "result.partial_requires_failure"),
        ("completed.v1.json", "rejected", "result.rejected_has_artifact"),
        ("completed.v1.json", "failed", "result.failed_has_artifact"),
    ],
)
def test_result_status_invariants_are_explicit(
    fixture: str, status: str, expected_code: str
) -> None:
    """Four statuses have stable successful-fact and failure-evidence rules."""
    payload = fixture_payload(fixture)
    payload["status"] = status

    with pytest.raises(ResultValidationError) as caught:
        Result.from_dict(payload)

    assert caught.value.code == expected_code


@pytest.mark.parametrize("name", ["failed.v1.json", "rejected-boundary.v1.json"])
def test_failed_or_rejected_results_keep_evidence_without_snapshot(name: str) -> None:
    """Policy/attempt evidence survives without a successful Observation."""
    result = Result.from_dict(fixture_payload(name))

    assert not result.artifacts
    assert not result.manifest.artifacts
    assert result.errors
    assert result.attempts
    assert all(attempt.outcome != "succeeded" for attempt in result.attempts)


@pytest.mark.parametrize(
    "location",
    [
        "result",
        "manifest",
        "attempt",
        "error",
        "usage",
        "redirect",
        "site_skill",
        "artifact",
        "lineage",
    ],
)
def test_unknown_fields_reject_at_every_contract_boundary(location: str) -> None:
    """Versioned objects never silently accept schema drift."""
    payload = fixture_payload("failed.v1.json")
    if location == "result":
        payload["unexpected"] = "value"
    elif location == "manifest":
        payload["manifest"]["unexpected"] = "value"
    elif location == "attempt":
        payload["attempts"][0]["unexpected"] = "value"
    elif location == "error":
        payload["errors"][0]["unexpected"] = "value"
    elif location == "usage":
        payload["usage"]["unexpected"] = 1
    elif location == "redirect":
        payload = fixture_payload("completed.v1.json")
        payload["manifest"]["redirects"][0]["unexpected"] = "value"
    elif location == "site_skill":
        payload = fixture_payload("completed.v1.json")
        payload["manifest"]["site_skill"]["unexpected"] = "value"
    elif location == "artifact":
        payload = fixture_payload("completed.v1.json")
        payload["manifest"]["artifacts"][0]["unexpected"] = "value"
    else:
        payload = fixture_payload("partial.v1.json")
        payload["manifest"]["artifacts"][1]["lineage"][0]["unexpected"] = "value"

    with pytest.raises(ResultValidationError) as caught:
        Result.from_dict(payload)

    assert caught.value.code == "schema.unknown_fields"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("api_key", "private-value"),
        ("note", "Authorization: Bearer private-value"),
        ("note", "cookie=sessionid=private-value"),
        ("note", "api_key=private-value"),
        ("x-api-key", "private-value"),
        ("note", "sk-privatevalue1234567890"),
        ("note", "C:\\Users\\alice\\private.txt"),
        ("note", "/home/alice/private.txt"),
        ("note", "https://alice:private@www.soa.org/research/"),
    ],
)
def test_secret_like_keys_values_and_absolute_paths_are_rejected(
    key: str, value: str
) -> None:
    """Unsafe evidence is rejected instead of redacted into final JSON."""
    payload = fixture_payload("failed.v1.json")
    payload["errors"][0]["details"] = {key: value}

    with pytest.raises(ResultValidationError) as caught:
        Result.from_dict(payload)

    assert caught.value.code in {"result.sensitive_data", "result.absolute_path"}


def test_safe_error_details_are_sorted_and_frozen() -> None:
    """Safe details serialize deterministically and returned models are immutable."""
    error = SafeError.from_dict(
        {
            "code": "gateway.transport",
            "message": "The transport failed safely",
            "details": {"zeta": "last", "alpha": "first"},
        }
    )

    assert error.to_dict()["details"] == {"alpha": "first", "zeta": "last"}
    with pytest.raises(FrozenInstanceError):
        error.code = "changed"  # type: ignore[misc]


def test_result_modules_have_zero_execution_or_network_authority() -> None:
    """Result imports only pure data/serialization dependencies and Artifact models."""
    root = Path(__file__).parents[2] / "src" / "web_listening" / "result"
    forbidden_roots = {
        "http",
        "httpx",
        "requests",
        "socket",
        "urllib",
        "web_listening.interfaces",
        "web_listening.request",
        "web_listening.runtime",
        "web_listening.site_skill",
        "web_listening.tool_registry",
    }
    observed: set[str] = set()
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                observed.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                observed.add(node.module)

    assert not {
        name
        for name in observed
        if any(
            name == root_name or name.startswith(f"{root_name}.")
            for root_name in forbidden_roots
        )
    }


def test_serialized_fixtures_contain_no_secret_or_local_path_markers() -> None:
    """Accepted fixed evidence remains safe on the final JSON surface."""
    rendered = b"".join(
        Result.from_dict(fixture_payload(name)).canonical_json_bytes()
        for name in FIXTURE_STATUS
    ).lower()

    for forbidden in (
        b"authorization:",
        b"bearer ",
        b"api_key",
        b"password",
        b"cookie=",
        b"c:\\\\users\\",
        b"/home/",
        b"/tmp/",
        b"?auth=",
        b"api%5fkey",
        b"file%3a%2f%2f",
        b"//server/share",
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    ("key", "value", "expected_code"),
    [
        ("auth", "private", "result.sensitive_data"),
        ("note", "//server/share", "result.absolute_path"),
        (
            "note",
            "https://example.com/?auth=private",
            "result.sensitive_data",
        ),
        ("note", "api%5Fkey=private", "result.sensitive_data"),
        (
            "note",
            "file%3A%2F%2F%2Fhome%2Falice%2Fprivate.txt",
            "result.absolute_path",
        ),
        (
            "note",
            "https://alice%3Aprivate%40www.soa.org/research/",
            "result.sensitive_data",
        ),
    ],
)
def test_decoded_secret_and_path_forms_fail_at_parse_and_canonical_boundaries(
    key: str, value: str, expected_code: str
) -> None:
    """Raw and percent-encoded unsafe evidence share one fail-closed boundary."""
    payload = fixture_payload("failed.v1.json")
    payload["errors"][0]["details"] = {key: value}

    with pytest.raises(ResultValidationError) as parsed:
        Result.from_dict(payload)
    with pytest.raises(ResultValidationError) as rendered:
        canonical_json_bytes({key: value})
    with pytest.raises(ResultValidationError) as direct:
        SafeError("gateway.transport", "Safe failure", ((key, value),))

    assert parsed.value.code == expected_code
    assert rendered.value.code == expected_code
    assert direct.value.code == expected_code


@pytest.mark.parametrize(
    "url",
    [
        "https://?x=y",
        "https://#fragment",
        "http://:80/path",
        "https://[::::]/path",
        "https://999.999.999.999/path",
        "https://example..com/path",
        "https://example.com:70000/path",
    ],
)
def test_malformed_http_authorities_return_stable_url_error(url: str) -> None:
    """HTTP evidence requires a real inert host and valid optional port."""
    payload = fixture_payload("failed.v1.json")
    payload["manifest"]["requested_url"] = url

    with pytest.raises(ResultValidationError) as caught:
        Result.from_dict(payload)

    assert caught.value.code == "url.invalid"


def _append_success_attempt(payload: dict[str, object]) -> None:
    """Add one coherent second success solely for cardinality tests."""
    for owner in (payload, payload["manifest"]):
        attempt = copy.deepcopy(owner["attempts"][0])
        attempt["order"] = 1
        attempt["attempt_id"] = "attempt-completed-1"
        owner["attempts"].append(attempt)
        owner["usage"]["requests"] += attempt["requests"]
        owner["usage"]["bytes_received"] += attempt["bytes_received"]
        owner["usage"]["runtime_ms"] += attempt["runtime_ms"]
        owner["usage"]["tool_attempts"] += 1


def _append_source_artifact(payload: dict[str, object]) -> None:
    """Add one coherent second source solely for cardinality tests."""
    digest = "9" * 64
    identity = artifact_id(digest, "text/html", ArtifactRole.SOURCE)
    for owner in (payload, payload["manifest"]):
        extra = copy.deepcopy(owner["artifacts"][0])
        extra["artifact_id"] = identity
        extra["observation_id"] = "observation-99999999999999999999999999999999"
        extra["sha256"] = digest
        owner["artifacts"].append(extra)


@pytest.mark.parametrize(
    ("second_success", "second_source", "expected_code"),
    [
        (True, False, "manifest.success_cardinality_invalid"),
        (False, True, "manifest.source_cardinality_invalid"),
        (True, True, "manifest.source_cardinality_invalid"),
    ],
)
def test_success_manifest_requires_one_source_and_one_successful_attempt(
    second_success: bool, second_source: bool, expected_code: str
) -> None:
    """One Result cannot silently become a multi-target acquisition schema."""
    payload = fixture_payload("completed.v1.json")
    if second_success:
        _append_success_attempt(payload)
    if second_source:
        _append_source_artifact(payload)

    with pytest.raises(ResultValidationError) as caught:
        Result.from_dict(payload)

    assert caught.value.code == expected_code


def test_derived_lineage_must_reference_a_source_role_pair() -> None:
    """An existing derived parent is not a valid source-role lineage target."""
    payload = fixture_payload("partial.v1.json")
    digest = "2" * 64
    child_id = artifact_id(digest, "text/markdown", ArtifactRole.DERIVED)
    child_observation_id = "observation-22222222222222222222222222222222"
    for owner in (payload, payload["manifest"]):
        source = owner["artifacts"][0]
        parent = owner["artifacts"][1]
        child = copy.deepcopy(parent)
        child["artifact_id"] = child_id
        child["observation_id"] = child_observation_id
        child["sha256"] = digest
        child["lineage"] = [
            {
                "lineage_id": lineage_id(
                    observation_id=child_observation_id,
                    artifact_id=child_id,
                    source_observation_id=source["observation_id"],
                    source_artifact_id=source["artifact_id"],
                ),
                "observation_id": child_observation_id,
                "artifact_id": child_id,
                "relation": "derived_from",
                "source_observation_id": source["observation_id"],
                "source_artifact_id": source["artifact_id"],
            }
        ]
        parent_edge = parent["lineage"][0]
        parent_edge["source_observation_id"] = child_observation_id
        parent_edge["source_artifact_id"] = child_id
        parent_edge["lineage_id"] = lineage_id(
            observation_id=parent["observation_id"],
            artifact_id=parent["artifact_id"],
            source_observation_id=child_observation_id,
            source_artifact_id=child_id,
        )
        owner["artifacts"].append(child)

    with pytest.raises(ResultValidationError) as caught:
        Result.from_dict(payload)

    assert caught.value.code == "lineage.source_role_invalid"


def test_success_without_redirect_accepts_one_unchanged_endpoint() -> None:
    """A no-redirect success is valid when request/current/final all agree."""
    payload = fixture_payload("completed.v1.json")
    endpoint = payload["manifest"]["final_url"]
    payload["manifest"]["requested_url"] = endpoint
    payload["manifest"]["current_url"] = endpoint
    payload["manifest"]["redirects"] = []
    payload["manifest"]["attempts"][0]["requested_url"] = endpoint
    payload["attempts"][0]["requested_url"] = endpoint

    assert not Result.from_dict(payload).manifest.redirects


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("current_url", "https://www.soa.org/research/unrelated/"),
        ("from_url", "https://www.soa.org/research/unrelated/"),
        ("to_url", "https://www.soa.org/research/unrelated/"),
        ("decision", "rejected"),
    ],
)
def test_success_redirect_chain_rejects_unrelated_or_rejected_transition(
    field: str, value: str
) -> None:
    """A successful redirect chain is ordered, followed, and endpoint-bound."""
    payload = fixture_payload("completed.v1.json")
    if field == "current_url":
        payload["manifest"][field] = value
    else:
        payload["manifest"]["redirects"][0][field] = value

    with pytest.raises(ResultValidationError) as caught:
        Result.from_dict(payload)

    assert caught.value.code == "redirect.chain_invalid"


def test_rejected_manifest_can_retain_one_coherent_rejected_redirect() -> None:
    """A rejected target records the unvisited candidate and current endpoint."""
    payload = fixture_payload("rejected-boundary.v1.json")
    requested = payload["manifest"]["requested_url"]
    payload["manifest"]["redirects"] = [
        {
            "order": 0,
            "from_url": requested,
            "to_url": "https://www.actuaries.org/out-of-scope/",
            "http_status": 302,
            "decision": "rejected",
        }
    ]

    assert Result.from_dict(payload).manifest.redirects[0].decision == "rejected"


@pytest.mark.parametrize("value", [{"bad": 1}, ["bad"], None, True])
@pytest.mark.parametrize("location", ["outcome", "decision"])
def test_malformed_enum_shapes_return_stable_validation_error(
    location: str, value: object
) -> None:
    """Unhashable and non-string enum shapes never leak a TypeError."""
    payload = fixture_payload("completed.v1.json")
    if location == "outcome":
        payload["attempts"][0]["outcome"] = value
        expected = "attempt.outcome_invalid"
    else:
        payload["manifest"]["redirects"][0]["decision"] = value
        expected = "redirect.decision_invalid"

    with pytest.raises(ResultValidationError) as caught:
        Result.from_dict(payload)

    assert caught.value.code == expected


@pytest.mark.parametrize(
    ("value", "expected_code"),
    [
        (
            "https://example.com/?ａｕｔｈ=private",
            "result.sensitive_data",
        ),
        (
            "https://example.com/?%EF%BD%81%EF%BD%95%EF%BD%94%EF%BD%88=private",
            "result.sensitive_data",
        ),
        ("saved at //server/share", "result.absolute_path"),
        ("saved at \\\\server\\share", "result.absolute_path"),
        ("https://alice@example.com/", "result.sensitive_data"),
        ("C：＼Users＼alice＼private.txt", "result.absolute_path"),
        ("safe\u202eprivate", "result.sensitive_data"),
        ("safe\u0085private", "result.sensitive_data"),
        ("https://example.com/%GG", "url.invalid"),
        ("https://example.com/path\\private", "url.invalid"),
        ("api%255Fkey=private", "result.sensitive_data"),
        ("api%25255Fkey=private", "result.sensitive_data"),
    ],
)
def test_unicode_and_encoded_ambiguity_rejects_on_all_safe_output_surfaces(
    value: str, expected_code: str
) -> None:
    """Parsing, direct errors, and canonical JSON share normalized safety rules."""
    payload = fixture_payload("failed.v1.json")
    payload["errors"][0]["details"] = {"note": value}

    with pytest.raises(ResultValidationError) as parsed:
        Result.from_dict(payload)
    with pytest.raises(ResultValidationError) as direct:
        SafeError("gateway.transport", "Safe failure", (("note", value),))
    with pytest.raises(ResultValidationError) as rendered:
        canonical_json_bytes({"note": value})

    assert parsed.value.code == expected_code
    assert direct.value.code == expected_code
    assert rendered.value.code == expected_code


@pytest.mark.parametrize("value", ["普通中文说明", "Coverage is 100% complete"])
def test_safe_unicode_and_plain_percent_text_remain_accepted(value: str) -> None:
    """Normalization does not reject ordinary Unicode or non-URL percent text."""
    payload = fixture_payload("failed.v1.json")
    payload["errors"][0]["details"] = {"note": value}

    assert Result.from_dict(payload).errors[0].details == (("note", value),)
    assert SafeError("gateway.transport", "Safe failure", (("note", value),))
    assert canonical_json_bytes({"note": value})


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/report",
        "http://192.0.2.10:8080/report",
        "https://[2001:db8::1]/report",
    ],
)
def test_valid_dns_ipv4_and_ipv6_urls_remain_accepted(url: str) -> None:
    """Strict inert URL checks retain ordinary supported authorities."""
    payload = fixture_payload("failed.v1.json")
    payload["manifest"]["requested_url"] = url
    payload["manifest"]["current_url"] = url
    payload["manifest"]["attempts"][0]["requested_url"] = url
    payload["attempts"][0]["requested_url"] = url

    assert Result.from_dict(payload).manifest.requested_url == url
    assert SafeError("gateway.transport", "Safe failure", (("note", url),))
    assert canonical_json_bytes({"note": url})


@pytest.mark.parametrize(
    ("value", "expected_code"),
    [
        ("failed at https://alice@example.com/", "result.sensitive_data"),
        ("path:/home/alice/private.txt", "result.absolute_path"),
        ("path:C:\\Users\\alice\\private.txt", "result.absolute_path"),
        ("source:file:///home/alice/private.txt", "result.absolute_path"),
        ("bad\ud800value", "result.sensitive_data"),
    ],
)
def test_embedded_labeled_unsafe_values_reject_on_all_output_surfaces(
    value: str, expected_code: str
) -> None:
    """Labels and punctuation cannot hide userinfo, paths, or surrogates."""
    payload = fixture_payload("failed.v1.json")
    payload["errors"][0]["details"] = {"note": value}

    with pytest.raises(ResultValidationError) as parsed:
        Result.from_dict(payload)
    with pytest.raises(ResultValidationError) as direct:
        SafeError("gateway.transport", "Safe failure", (("note", value),))
    with pytest.raises(ResultValidationError) as rendered:
        canonical_json_bytes({"note": value})

    assert parsed.value.code == expected_code
    assert direct.value.code == expected_code
    assert rendered.value.code == expected_code


@pytest.mark.parametrize(
    "url",
    [
        "https://ｅｘａｍｐｌｅ.com/report",
        "https://example.com:８０/report",
        "https://example.com:٨٠/report",
    ],
)
def test_non_ascii_output_authority_rejects_on_all_public_surfaces(url: str) -> None:
    """NFKC safety scanning never legitimizes the URL string being output."""
    payload = fixture_payload("failed.v1.json")
    payload["manifest"]["requested_url"] = url

    with pytest.raises(ResultValidationError) as parsed:
        Result.from_dict(payload)
    with pytest.raises(ResultValidationError) as direct:
        SafeError("gateway.transport", "Safe failure", (("note", url),))
    with pytest.raises(ResultValidationError) as rendered:
        canonical_json_bytes({"note": url})

    assert parsed.value.code == "url.invalid"
    assert direct.value.code == "url.invalid"
    assert rendered.value.code == "url.invalid"
