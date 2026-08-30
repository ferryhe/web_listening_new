"""Offline Phase 20 parity and non-production rollback evidence."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import hashlib
import json
import runpy
from dataclasses import dataclass
from pathlib import Path

import pytest

from web_listening.artifact.store import ArtifactStore
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.runtime.jobs import JobRepository
from web_listening.runtime.service import RuntimeService
from web_listening.tool_registry.acquisition.builtins.web_http import (
    WEB_HTTP_MANIFEST,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.registry import Registry

HERE = Path(__file__).parent
CORPUS = HERE / "fixtures" / "phase_20_offline_corpus.json"
RUNNER = runpy.run_path(str(HERE / "phase_20_runner.py"))
LOAD_CORPUS = RUNNER["load_corpus"]
NORMALIZE_RESULT = RUNNER["normalize_result"]
COMPARE = RUNNER["compare_semantics"]
ROLLBACK = RUNNER["run_nonproduction_rollback_drill"]


@dataclass(slots=True)
class _FrozenTool:
    output: AcquisitionOutput | AcquisitionFailure
    manifest = WEB_HTTP_MANIFEST

    def acquire(
        self, _tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        return self.output


def _run_new(case: dict[str, object], tmp_path: Path):
    payload = case["input"]
    url = str(payload["url"])
    body = str(payload.get("body", "")).encode("utf-8")
    if case["case_id"] == "success-html":
        output = AcquisitionOutput(
            WEB_HTTP_MANIFEST.tool_id,
            WEB_HTTP_MANIFEST.version,
            url,
            url,
            200,
            "text/html",
            body,
            hashlib.sha256(body).hexdigest(),
            (),
            7,
            requests=1,
            bytes_received=len(body),
        )
    else:
        output = AcquisitionFailure(
            WEB_HTTP_MANIFEST.tool_id,
            WEB_HTTP_MANIFEST.version,
            "robots.timeout",
            requests=1,
            runtime_ms=7,
        )
    registry = Registry()
    registry.register(WEB_HTTP_MANIFEST, _FrozenTool(output))
    store = ArtifactStore(tmp_path / str(case["case_id"]))
    service = RuntimeService(
        registry,
        store,
        JobRepository(),
        clock=lambda: "2026-08-29T12:00:00Z",
        job_id_factory=lambda: f"job-{case['case_id']}",
    )
    request = Request(
        Scope(
            (url,),
            ("https://example.com",),
            ("/**",),
            (ContentType.HTML,),
        ),
        None,
        False,
        Budgets(2, 4096, 30, 1),
    )
    job = service.run(request)
    assert job.result is not None
    stored_observations = [
        store.get_observation(item.observation_id) for item in job.result.artifacts
    ]
    persistence = {
        "observations": [
            {
                "observation_id": row.observation.observation_id,
                "artifact_id": row.observation.artifact_id,
                "blob_sha256": row.blob.sha256,
                "size_bytes": row.blob.size_bytes,
                "mime_type": row.artifact.mime_type,
                "content": row.content,
            }
            for row in stored_observations
        ]
    }
    store.close()
    return job.result, persistence


def test_frozen_corpus_is_safe_complete_and_pre_freezes_normalization() -> None:
    corpus = LOAD_CORPUS(CORPUS)

    assert corpus["old_commit"] == "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5"
    assert {case["case_id"] for case in corpus["cases"]} == {
        "success-html",
        "robots-timeout",
    }
    assert {case["old_observed"]["outcome"] for case in corpus["cases"]} == {
        "success",
        "failure",
    }
    assert corpus["normalization_policy"] == {
        "ignored_fields": [
            "identity.artifact_ids",
            "identity.attempt_ids",
            "identity.observation_ids",
            "identity.run_id",
            "timing.finished_at",
            "timing.runtime_ms",
            "timing.started_at",
        ],
        "normalized_fields": {"tool_id": {"web_http": "acquisition.web_http"}},
    }
    rendered = b"".join(
        path.read_bytes()
        for path in (CORPUS, *(HERE / "fixtures" / "legacy").glob("*.json"))
    ).lower()
    assert not any(
        marker in rendered
        for marker in (b"authorization:", b"bearer ", b"api_key", b"password")
    )


def test_old_projection_is_rebuilt_from_fixed_legacy_fixture_fields() -> None:
    corpus = LOAD_CORPUS(CORPUS)
    project = RUNNER["project_legacy_case"]
    fixture_root = HERE / "fixtures"

    assert {
        case["legacy_fixture"]["source_path"]: case["legacy_fixture"]["sha256_lf"]
        for case in corpus["cases"]
    } == {
        "docs/testing/fixtures/capture-result-v1.sample.json": (
            "bf31d5bfb24a9f1ba27340d4331c1e52e5661585aa1f7071db74123d65d64231"
        ),
        "docs/testing/fixtures/access-rejection-error-v1.sample.json": (
            "88a077f68536241583e06d564c435cc7faf9d5c3731821e42a505b3d59e2c169"
        ),
    }
    for case in corpus["cases"]:
        assert (
            project(
                case,
                fixture_root,
                corpus["normalization_policy"]["normalized_fields"],
            )
            == case["old_observed"]
        )

    success, failure = corpus["cases"]
    assert success["input"] == {
        "url": "https://example.com/news",
        "body": "Example public page content.",
    }
    assert success["old_observed"]["content"] == {
        "availability": "present",
        "sha256": ("cd9f6b6f0e2eaed212131bc9691fcb784c14305eaac49ef5a1fc9e2c3b70417f"),
        "word_count": 4,
    }
    assert failure["input"] == {"url": "https://example.com/"}
    assert failure["old_observed"]["error"] == {
        "availability": "present",
        "codes": ["robots.timeout"],
        "count": 1,
        "details": ["N/A"],
        "error_types": ["N/A"],
        "messages": ["access failed closed while resolving robots policy"],
        "retryable": [True],
    }


def test_error_projection_freezes_message_retryable_and_availability(
    tmp_path: Path,
) -> None:
    corpus = LOAD_CORPUS(CORPUS)
    success, failure = corpus["cases"]
    success_result, success_persistence = _run_new(success, tmp_path)
    success_projection = NORMALIZE_RESULT(
        success_result,
        persistence=success_persistence,
        normalized_fields=corpus["normalization_policy"]["normalized_fields"],
    )
    success_error = success_projection["error"]
    assert set(success_error) == {
        "availability",
        "codes",
        "count",
        "details",
        "error_types",
        "messages",
        "retryable",
    }
    assert success_error["availability"] == "none"
    assert success_error["count"] == 0
    assert success_error["codes"] == success_error["messages"] == []
    assert success_error["details"] == success_error["error_types"] == []
    assert success_error["retryable"] == []

    failure_result, failure_persistence = _run_new(failure, tmp_path)
    projection = NORMALIZE_RESULT(
        failure_result,
        persistence=failure_persistence,
        normalized_fields=corpus["normalization_policy"]["normalized_fields"],
    )
    assert projection["error"] == {
        "availability": "present",
        "codes": ["robots.timeout"],
        "count": 1,
        "details": [{}],
        "error_types": ["N/A"],
        "messages": ["Acquisition did not complete."],
        "retryable": ["N/A"],
    }
    assert not COMPARE(
        failure["old_observed"], projection, failure["accepted_differences"]
    )["blockers"]

    for field, changed_value in (
        ("availability", "none"),
        ("details", [{"reason": "changed"}]),
        ("error_types", ["ChangedError"]),
        ("messages", ["changed"]),
        ("retryable", [False]),
    ):
        changed = json.loads(json.dumps(projection))
        changed["error"][field] = changed_value
        comparison = COMPARE(
            failure["old_observed"], changed, failure["accepted_differences"]
        )
        assert comparison["classification"] == "blocker"
        assert f"error.{field}" in {item["field"] for item in comparison["blockers"]}


def test_offline_projection_uses_actual_persisted_aom_relationships(
    tmp_path: Path,
) -> None:
    corpus = LOAD_CORPUS(CORPUS)
    case = corpus["cases"][0]
    result, persistence = _run_new(case, tmp_path)
    projection = NORMALIZE_RESULT(
        result,
        persistence=persistence,
        normalized_fields=corpus["normalization_policy"]["normalized_fields"],
    )

    assert projection["artifact"] == {
        "availability": "present",
        "count": 1,
        "mime_types": ["text/html"],
        "sha256": ["cd9f6b6f0e2eaed212131bc9691fcb784c14305eaac49ef5a1fc9e2c3b70417f"],
        "size_bytes": [28],
    }
    assert projection["observation"] == {
        "availability": "present",
        "content_matches_artifact": True,
        "count": 1,
        "links_match_artifact": True,
        "stored_content_sha256": [
            "cd9f6b6f0e2eaed212131bc9691fcb784c14305eaac49ef5a1fc9e2c3b70417f"
        ],
        "stored_content_size_bytes": [28],
    }
    assert projection["manifest"] == {
        "artifact_count": 1,
        "availability": "present",
        "content_matches_observation": True,
        "links_match_artifact": True,
        "mime_type": "text/html",
        "sha256": "cd9f6b6f0e2eaed212131bc9691fcb784c14305eaac49ef5a1fc9e2c3b70417f",
        "size_bytes": 28,
        "tool_id": "acquisition.web_http",
        "tool_version": "1.0.0",
    }
    assert projection["attempt"] == {
        "availability": "present",
        "count": 1,
        "tool_ids": ["acquisition.web_http"],
        "tool_versions": ["1.0.0"],
    }


@pytest.mark.parametrize(
    ("dimension", "field", "changed_value"),
    [
        ("artifact", "count", 2),
        ("artifact", "sha256", ["b" * 64]),
        ("artifact", "size_bytes", [29]),
        ("artifact", "mime_types", ["application/pdf"]),
        ("observation", "links_match_artifact", False),
        ("observation", "content_matches_artifact", False),
        ("manifest", "links_match_artifact", False),
        ("manifest", "content_matches_observation", False),
        ("manifest", "tool_id", "acquisition.other"),
        ("manifest", "tool_version", "2.0.0"),
        ("attempt", "tool_ids", ["acquisition.other"]),
        ("attempt", "tool_versions", ["2.0.0"]),
    ],
)
def test_offline_aom_stable_leaf_drift_is_a_blocker(
    tmp_path: Path, dimension: str, field: str, changed_value: object
) -> None:
    corpus = LOAD_CORPUS(CORPUS)
    case = corpus["cases"][0]
    result, persistence = _run_new(case, tmp_path)
    projection = NORMALIZE_RESULT(
        result,
        persistence=persistence,
        normalized_fields=corpus["normalization_policy"]["normalized_fields"],
    )
    projection[dimension][field] = changed_value

    comparison = COMPARE(case["old_observed"], projection, case["accepted_differences"])

    assert comparison["classification"] == "blocker"
    assert f"{dimension}.{field}" in {item["field"] for item in comparison["blockers"]}


def test_tool_identity_uses_only_the_frozen_exact_normalization(
    tmp_path: Path,
) -> None:
    corpus = LOAD_CORPUS(CORPUS)
    success, failure = corpus["cases"]

    assert success["old_observed"]["tool_id"] == "acquisition.web_http"
    assert success["legacy_fixture"]["field_sources"]["tool_id"].startswith(
        "/executor_id"
    )
    assert failure["old_observed"]["tool_id"] == "N/A"
    assert failure["legacy_fixture"]["field_sources"]["tool_id"].startswith("N/A:")

    result, persistence = _run_new(success, tmp_path)
    normalized = NORMALIZE_RESULT(
        result,
        persistence=persistence,
        normalized_fields=corpus["normalization_policy"]["normalized_fields"],
    )
    assert normalized["tool_id"] == "acquisition.web_http"
    correct = COMPARE(
        success["old_observed"], normalized, success["accepted_differences"]
    )
    assert "tool_id" not in {item["field"] for item in correct["blockers"]}

    normalized["tool_id"] = "acquisition.unexpected"
    wrong = COMPARE(
        success["old_observed"], normalized, success["accepted_differences"]
    )
    assert wrong["classification"] == "blocker"
    assert "tool_id" in {item["field"] for item in wrong["blockers"]}


def test_contract_projection_uses_the_public_result_schema_version(
    tmp_path: Path,
) -> None:
    corpus = LOAD_CORPUS(CORPUS)
    case = corpus["cases"][0]
    result, persistence = _run_new(case, tmp_path)

    normalized = NORMALIZE_RESULT(
        result,
        persistence=persistence,
        normalized_fields=corpus["normalization_policy"]["normalized_fields"],
    )
    assert normalized["contract"] == result.schema_version
    assert normalized["contract"] == "web-listening-result.v1"
    comparison = COMPARE(case["old_observed"], normalized, case["accepted_differences"])
    assert "contract" not in {item["field"] for item in comparison["blockers"]}

    normalized["contract"] = "unexpected-result.v1"
    wrong = COMPARE(case["old_observed"], normalized, case["accepted_differences"])
    assert wrong["classification"] == "blocker"
    assert "contract" in {item["field"] for item in wrong["blockers"]}


@pytest.mark.parametrize("case_id", ["success-html", "robots-timeout"])
def test_new_runtime_matches_frozen_old_observable_semantics(
    case_id: str, tmp_path: Path
) -> None:
    corpus = LOAD_CORPUS(CORPUS)
    case = next(item for item in corpus["cases"] if item["case_id"] == case_id)

    result, persistence = _run_new(case, tmp_path)
    comparison = COMPARE(
        case["old_observed"],
        NORMALIZE_RESULT(
            result,
            persistence=persistence,
            normalized_fields=corpus["normalization_policy"]["normalized_fields"],
        ),
        case["accepted_differences"],
    )

    assert comparison["classification"] in {"pass", "accepted"}, comparison
    assert not comparison["blockers"]


def test_unexplained_semantic_difference_is_a_blocker() -> None:
    corpus = LOAD_CORPUS(CORPUS)
    old = corpus["cases"][0]["old_observed"]
    changed = json.loads(json.dumps(old))
    changed["usage"]["requests"] = 1

    comparison = COMPARE(old, changed, {})

    assert comparison["classification"] == "blocker"
    assert comparison["blockers"] == [
        {
            "field": "usage.requests",
            "old": "N/A",
            "new": 1,
            "reason": "unexplained semantic difference",
        }
    ]


def test_accepted_difference_requires_a_frozen_exact_value_pair() -> None:
    old = {"contract": "legacy"}

    accepted = COMPARE(
        old,
        {"contract": "result.v1"},
        {
            "contract": {
                "old": "legacy",
                "new": "result.v1",
                "reason": "Public contract names differ; compared fields are semantic.",
            }
        },
    )
    blocker = COMPARE(
        old,
        {"contract": "unexpected"},
        {
            "contract": {
                "old": "legacy",
                "new": "result.v1",
                "reason": "Public contract names differ; compared fields are semantic.",
            }
        },
    )

    assert accepted["classification"] == "accepted"
    assert blocker["classification"] == "blocker"


def test_nonproduction_rollback_drill_selects_switches_and_returns_to_old() -> None:
    corpus = LOAD_CORPUS(CORPUS)

    evidence = ROLLBACK(corpus["rollback_drill"])

    assert evidence == {
        "environment": "non-production-simulation",
        "selected_release": "new",
        "switch_recommendation": "go",
        "pre_switch_gates": {"contract": "pass", "health": "pass"},
        "post_switch_health": "fail",
        "rollback_release": "old",
        "rollback_health": "pass",
        "evidence_retained": True,
        "production_mutation": False,
        "result": "rollback-pass",
    }
