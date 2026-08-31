"""Offline contract tests for the bounded SOA volatility diagnosis."""

# pylint: disable=duplicate-code,missing-function-docstring,too-many-branches
# pylint: disable=too-many-lines,too-many-locals

from __future__ import annotations

import hashlib
import inspect
import json
import runpy
import sys
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from phase_20_soa_volatility import (  # pylint: disable=import-error
    CASE_IDS,
    CLASSIFICATIONS,
    SAMPLE_ORDER,
    build_evidence,
    classify_samples,
    evidence_json,
    safe_url_descriptor,
    sanitize_errors,
)


def _sha(character: str) -> str:
    return character * 64


def _case(case_id: str, sha256: str) -> dict[str, object]:
    minimum_document_links = 1 if case_id == "document" else 0
    return {
        "case_id": case_id,
        "outcome": "success",
        "status": 200,
        "mime_type": "text/html",
        "requested_url": safe_url_descriptor(
            "https://www.soa.org/"
            if case_id == "monitor"
            else "https://www.soa.org/publications/publications-landing/"
        ),
        "final_url": safe_url_descriptor(
            "https://www.soa.org/"
            if case_id == "monitor"
            else "https://www.soa.org/publications/publications-landing/"
        ),
        "content_sha256": sha256,
        "content_bytes": 100,
        "thresholds": {
            "expected": {
                "minimum_words": 150,
                "minimum_document_links": minimum_document_links,
            },
            "observed": {
                "word_count": 150,
                "document_link_count": minimum_document_links,
            },
            "met": True,
        },
        "usage": {
            "requests": 2,
            "response_bytes": 500,
            "target_bytes": 100,
            "within_budget": True,
        },
        "error": [],
    }


def _samples() -> list[dict[str, object]]:
    samples = []
    for sequence, (system, sample_number) in enumerate(SAMPLE_ORDER, start=1):
        samples.append(
            {
                "sequence": sequence,
                "system": system,
                "sample": sample_number,
                "process_outcome": "exited-success",
                "process_return_code": 0,
                "cases": [
                    _case("monitor", _sha("a")),
                    _case("document", _sha("b")),
                ],
                "budget": {
                    "requests": 4,
                    "response_bytes": 1000,
                    "elapsed_seconds": 1.0,
                    "max_requests": 4,
                    "max_response_bytes": 2 * 1024 * 1024,
                    "max_seconds": 15,
                    "governed_network_seconds": 13,
                    "concurrency": 1,
                    "retry": 0,
                    "within_budget": True,
                },
                "error": [],
            }
        )
    return samples


def _set_case_sha(
    samples: list[dict[str, object]],
    case_id: str,
    values: tuple[str, str, str, str],
) -> None:
    for sample, value in zip(samples, values, strict=True):
        row = next(item for item in sample["cases"] if item["case_id"] == case_id)
        row["content_sha256"] = value


@pytest.mark.parametrize(
    ("expected", "monitor", "document"),
    [
        (
            "stable_match",
            (_sha("a"),) * 4,
            (_sha("b"),) * 4,
        ),
        (
            "stable_cross_system_mismatch",
            (_sha("a"), _sha("c"), _sha("a"), _sha("c")),
            (_sha("b"), _sha("d"), _sha("b"), _sha("d")),
        ),
        (
            "site_dynamic",
            (_sha("a"), _sha("a"), _sha("c"), _sha("c")),
            (_sha("b"), _sha("b"), _sha("d"), _sha("d")),
        ),
    ],
)
def test_classifies_the_three_provable_whole_site_outcomes(
    expected: str,
    monitor: tuple[str, str, str, str],
    document: tuple[str, str, str, str],
) -> None:
    samples = _samples()
    _set_case_sha(samples, "monitor", monitor)
    _set_case_sha(samples, "document", document)

    assert classify_samples(samples) == expected


def test_one_dynamic_case_and_one_stable_match_is_site_dynamic() -> None:
    samples = _samples()
    _set_case_sha(
        samples,
        "monitor",
        (_sha("a"), _sha("a"), _sha("c"), _sha("c")),
    )

    assert classify_samples(samples) == "site_dynamic"


def test_disjoint_sha_sets_with_both_systems_changing_is_site_dynamic() -> None:
    samples = _samples()
    _set_case_sha(
        samples,
        "monitor",
        (_sha("a"), _sha("c"), _sha("b"), _sha("d")),
    )

    assert classify_samples(samples) == "site_dynamic"


def test_one_stable_mismatch_case_and_one_match_is_cross_system_mismatch() -> None:
    samples = _samples()
    _set_case_sha(
        samples,
        "monitor",
        (_sha("a"), _sha("c"), _sha("a"), _sha("c")),
    )

    assert classify_samples(samples) == "stable_cross_system_mismatch"


def test_mixed_dynamic_and_stable_split_evidence_is_inconclusive() -> None:
    samples = _samples()
    _set_case_sha(
        samples,
        "monitor",
        (_sha("a"), _sha("a"), _sha("c"), _sha("c")),
    )
    _set_case_sha(
        samples,
        "document",
        (_sha("b"), _sha("d"), _sha("b"), _sha("d")),
    )

    assert classify_samples(samples) == "inconclusive"


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-sample",
        "process-error",
        "case-error",
        "sample-budget",
        "aggregate-budget",
        "mixed-status",
        "mixed-mime",
        "mixed-requested-url",
        "mixed-final-url",
        "one-sided-change",
    ],
)
def test_unattributable_or_unsafe_evidence_is_inconclusive(mutation: str) -> None:
    samples = _samples()
    if mutation == "missing-sample":
        samples.pop()
    elif mutation == "process-error":
        samples[1]["process_outcome"] = "timeout"
        samples[1]["process_return_code"] = "N/A"
        samples[1]["error"] = [
            {"code": "new.process_timeout", "error_type": "TimeoutExpired"}
        ]
    elif mutation == "case-error":
        samples[1]["cases"][0]["outcome"] = "failure"
        samples[1]["cases"][0]["content_sha256"] = None
        samples[1]["cases"][0]["content_bytes"] = None
        samples[1]["cases"][0]["error"] = [
            {"code": "robots.timeout", "error_type": "TimeoutError"}
        ]
    elif mutation == "sample-budget":
        samples[0]["budget"]["requests"] = 5
    elif mutation == "aggregate-budget":
        samples[2]["budget"]["max_requests"] = 5
    elif mutation == "mixed-status":
        samples[1]["cases"][0]["status"] = 203
    elif mutation == "mixed-mime":
        samples[1]["cases"][0]["mime_type"] = "application/xhtml+xml"
    elif mutation == "mixed-requested-url":
        samples[1]["cases"][0]["requested_url"] = safe_url_descriptor(
            "https://www.soa.org/other"
        )
    elif mutation == "mixed-final-url":
        samples[1]["cases"][0]["final_url"] = safe_url_descriptor(
            "https://www.soa.org/final"
        )
    elif mutation == "one-sided-change":
        _set_case_sha(
            samples,
            "monitor",
            (_sha("a"), _sha("a"), _sha("c"), _sha("a")),
        )

    assert classify_samples(samples) == "inconclusive"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("content_sha256", "not-a-sha"),
        ("content_bytes", True),
        ("status", "200"),
        ("mime_type", "text/html; charset=utf-8"),
    ],
)
def test_content_schema_drift_is_inconclusive(field: str, value: object) -> None:
    samples = _samples()
    samples[0]["cases"][0][field] = value

    assert classify_samples(samples) == "inconclusive"


def test_same_sha_with_different_size_is_inconclusive() -> None:
    samples = _samples()
    samples[1]["cases"][0]["content_bytes"] = 101

    assert classify_samples(samples) == "inconclusive"


@pytest.mark.parametrize("system", ["old", "new"])
@pytest.mark.parametrize("case_id", CASE_IDS)
def test_success_case_requires_at_least_one_request(system: str, case_id: str) -> None:
    samples = _samples()
    for sample in samples:
        if sample["system"] == system:
            row = next(case for case in sample["cases"] if case["case_id"] == case_id)
            row["usage"]["requests"] = 0
            sample["budget"]["requests"] -= 2

    assert classify_samples(samples) == "inconclusive"


@pytest.mark.parametrize("system", ["old", "new"])
def test_success_sample_cannot_claim_zero_total_requests(system: str) -> None:
    samples = _samples()
    for sample in samples:
        if sample["system"] == system:
            for row in sample["cases"]:
                row["usage"]["requests"] = 0
            sample["budget"]["requests"] = 0

    assert classify_samples(samples) == "inconclusive"


def test_one_request_per_success_case_is_valid() -> None:
    samples = _samples()
    for sample in samples:
        for row in sample["cases"]:
            row["usage"]["requests"] = 1
        sample["budget"]["requests"] = 2

    assert classify_samples(samples) == "stable_match"


@pytest.mark.parametrize(
    ("content_sha256", "content_bytes"),
    [
        (_sha("a"), 0),
        (hashlib.sha256(b"").hexdigest(), 100),
        (hashlib.sha256(b"").hexdigest(), 0),
    ],
)
def test_body_sha_size_and_positive_word_threshold_are_consistent(
    content_sha256: str, content_bytes: int
) -> None:
    samples = _samples()
    for sample in samples:
        row = sample["cases"][0]
        row["content_sha256"] = content_sha256
        row["content_bytes"] = content_bytes
        row["usage"]["target_bytes"] = content_bytes

    assert classify_samples(samples) == "inconclusive"


@pytest.mark.parametrize(
    ("case_id", "field", "value"),
    [
        ("monitor", "word_count", None),
        ("monitor", "word_count", 149),
        ("monitor", "document_link_count", None),
        ("document", "word_count", None),
        ("document", "word_count", 149),
        ("document", "document_link_count", None),
        ("document", "document_link_count", 0),
    ],
)
def test_missing_or_low_threshold_evidence_is_inconclusive(
    case_id: str, field: str, value: int | None
) -> None:
    samples = _samples()
    row = next(case for case in samples[0]["cases"] if case["case_id"] == case_id)
    if value is None:
        row["thresholds"]["observed"].pop(field)
    else:
        row["thresholds"]["observed"][field] = value
        row["thresholds"]["met"] = False

    assert classify_samples(samples) == "inconclusive"


@pytest.mark.parametrize("mutation", ["missing", "extra", "duplicate"])
def test_case_set_must_be_exact_and_cannot_be_masked(mutation: str) -> None:
    samples = _samples()
    if mutation == "missing":
        samples[0]["cases"].pop()
    elif mutation == "extra":
        samples[0]["cases"].append(_case("other", _sha("c")))
    else:
        samples[0]["cases"][1] = deepcopy(samples[0]["cases"][0])

    assert classify_samples(samples) == "inconclusive"


def test_extra_unsafe_fields_are_rejected_and_not_serialized() -> None:
    samples = _samples()
    samples[0]["cases"][0]["body"] = "secret page content"
    samples[0]["headers"] = {"authorization": "secret"}

    assert classify_samples(samples) == "inconclusive"
    rendered = evidence_json(build_evidence(samples))
    assert "secret page content" not in rendered
    assert "authorization" not in rendered


def test_sample_order_and_identity_are_exact() -> None:
    samples = _samples()
    samples[0], samples[1] = samples[1], samples[0]
    assert classify_samples(samples) == "inconclusive"

    samples = _samples()
    samples[2]["sample"] = 1
    assert classify_samples(samples) == "inconclusive"

    samples = _samples()
    samples[3]["sequence"] = 5
    assert classify_samples(samples) == "inconclusive"


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("sequence", True),
        ("sequence", 1.0),
        ("sample", True),
        ("sample", 1.0),
        ("process-return", False),
        ("process-return", 0.0),
        ("budget-requests", 4.0),
        ("budget-bytes", 1000.0),
        ("max-requests", 4.0),
        ("max-bytes", float(2 * 1024 * 1024)),
        ("max-seconds", 15.0),
        ("governed-seconds", 13.0),
        ("concurrency", True),
        ("concurrency", 1.0),
        ("retry", False),
        ("retry", 0.0),
        ("minimum-words", 150.0),
        ("minimum-document-links", 0.0),
    ],
)
def test_integer_semantics_reject_bool_and_integral_float_after_json_round_trip(
    mutation: str, value: object
) -> None:
    samples = _samples()
    sample = samples[0]
    if mutation == "sequence":
        sample["sequence"] = value
    elif mutation == "sample":
        sample["sample"] = value
    elif mutation == "process-return":
        sample["process_return_code"] = value
    elif mutation == "minimum-words":
        sample["cases"][0]["thresholds"]["expected"]["minimum_words"] = value
    elif mutation == "minimum-document-links":
        sample["cases"][0]["thresholds"]["expected"]["minimum_document_links"] = value
    else:
        field = {
            "budget-requests": "requests",
            "budget-bytes": "response_bytes",
            "max-requests": "max_requests",
            "max-bytes": "max_response_bytes",
            "max-seconds": "max_seconds",
            "governed-seconds": "governed_network_seconds",
            "concurrency": "concurrency",
            "retry": "retry",
        }[mutation]
        sample["budget"][field] = value

    round_tripped = json.loads(json.dumps(samples))

    assert classify_samples(round_tripped) == "inconclusive"


def test_budget_totals_are_recomputed_per_system() -> None:
    evidence = build_evidence(_samples())

    assert evidence["system_totals"] == {
        "old": {
            "requests": 8,
            "response_bytes": 2000,
            "elapsed_seconds": 2.0,
            "within_budget": True,
        },
        "new": {
            "requests": 8,
            "response_bytes": 2000,
            "elapsed_seconds": 2.0,
            "within_budget": True,
        },
    }
    assert evidence["limits"]["per_system"] == {
        "max_requests": 8,
        "max_response_bytes": 4 * 1024 * 1024,
        "max_seconds": 30,
    }
    assert evidence["limits"]["concurrency"] == 1
    assert evidence["limits"]["retry"] == 0


def test_error_sanitization_keeps_only_stable_sorted_codes_and_types() -> None:
    errors = sanitize_errors(
        [
            {
                "code": "old.process_timeout",
                "message": "token=top-secret",
                "details": {"authorization": "Bearer top-secret"},
                "error_type": "TimeoutExpired",
            },
            {
                "error_code": "new.output_schema",
                "message": "https://user:secret@example.test/",
                "error_type": "SchemaError",
            },
        ]
    )

    assert errors == [
        {"code": "new.output_schema", "error_type": "SchemaError"},
        {"code": "old.process_timeout", "error_type": "TimeoutExpired"},
    ]
    assert "secret" not in json.dumps(errors, sort_keys=True)


def test_error_sanitization_replaces_unstable_values() -> None:
    assert sanitize_errors(RuntimeError("credential")) == [
        {"code": "volatility.unsafe_error", "error_type": "RuntimeError"}
    ]
    assert sanitize_errors({"code": "contains spaces", "error_type": []}) == [
        {"code": "volatility.unsafe_error", "error_type": "N/A"}
    ]


def test_token_shaped_error_code_and_type_are_never_stable_evidence() -> None:
    assert sanitize_errors(
        {
            "code": "BearerTopSecret123",
            "error_type": "BearerTopSecretType",
        }
    ) == [{"code": "volatility.unsafe_error", "error_type": "N/A"}]


def test_url_descriptor_never_contains_query_or_fragment() -> None:
    descriptor = safe_url_descriptor("https://www.soa.org/report?token=secret#fragment")
    rendered = json.dumps(descriptor, sort_keys=True)

    assert descriptor == {
        "scheme": "https",
        "host": "www.soa.org",
        "effective_port": 443,
        "path_sha256": (
            "8cc63f97e8c58d7c5c77d045c486c19c3ac8ef8dfc50a682653175b1121a9e4d"
        ),
        "query_present": True,
        "query_delimiter_present": True,
        "query_sha256": hashlib.sha256(b"token=secret").hexdigest(),
    }
    assert "secret" not in rendered
    assert "token" not in rendered
    assert "fragment" not in rendered


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@www.soa.org/",
        "https://user@www.soa.org/",
        "https://user:@www.soa.org/",
        "https://:secret@www.soa.org/",
        "https://@www.soa.org/",
    ],
)
def test_url_descriptor_rejects_userinfo_without_disclosure(url: str) -> None:
    descriptor = safe_url_descriptor(url)
    rendered = json.dumps(descriptor, sort_keys=True)

    assert descriptor == safe_url_descriptor(None)
    assert "user" not in rendered
    assert "secret" not in rendered


@pytest.mark.parametrize("field", ["requested_url", "final_url"])
@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@www.soa.org/",
        "https://user@www.soa.org/",
        "https://user:@www.soa.org/",
        "https://:secret@www.soa.org/",
        "https://@www.soa.org/",
    ],
)
def test_userinfo_in_requested_or_final_url_is_inconclusive(
    field: str, url: str
) -> None:
    samples = _samples()
    for sample in samples:
        sample["cases"][0][field] = safe_url_descriptor(url)

    evidence = build_evidence(samples)
    rendered = evidence_json(evidence)

    assert evidence["classification"] == "inconclusive"
    assert "user" not in rendered
    assert "secret" not in rendered


def test_query_only_url_drift_is_inconclusive_without_leaking_query() -> None:
    samples = _samples()
    for sample in samples:
        row = sample["cases"][0]
        descriptor = safe_url_descriptor(
            "https://www.soa.org/?request_id=old-1&token=secret"
        )
        row["requested_url"] = descriptor
        row["final_url"] = descriptor
    changed = samples[1]["cases"][0]
    changed_descriptor = safe_url_descriptor(
        "https://www.soa.org/?request_id=new-1&token=secret"
    )
    changed["requested_url"] = changed_descriptor
    changed["final_url"] = changed_descriptor

    evidence = build_evidence(samples)
    rendered = evidence_json(evidence)

    assert evidence["classification"] == "inconclusive"
    assert "request_id" not in rendered
    assert "old-1" not in rendered
    assert "new-1" not in rendered
    assert "token=secret" not in rendered


def test_same_query_keeps_existing_stable_classification() -> None:
    samples = _samples()
    descriptor = safe_url_descriptor("https://www.soa.org/?edition=fixed")
    for sample in samples:
        row = sample["cases"][0]
        row["requested_url"] = descriptor
        row["final_url"] = descriptor

    assert classify_samples(samples) == "stable_match"


def test_missing_and_empty_query_have_distinct_explicit_syntax_contracts() -> None:
    absent = safe_url_descriptor("https://www.soa.org/path")
    empty = safe_url_descriptor("https://www.soa.org/path?")

    assert absent != empty
    assert absent["query_present"] is False
    assert absent["query_delimiter_present"] is False
    assert empty["query_present"] is False
    assert empty["query_delimiter_present"] is True
    assert absent["query_sha256"] == hashlib.sha256(b"").hexdigest()
    assert empty["query_sha256"] == absent["query_sha256"]


def test_explicit_empty_query_drift_is_inconclusive() -> None:
    samples = _samples()
    changed = samples[1]["cases"][0]
    descriptor = safe_url_descriptor("https://www.soa.org/?")
    changed["requested_url"] = descriptor
    changed["final_url"] = descriptor

    assert classify_samples(samples) == "inconclusive"


def test_missing_query_hash_is_an_inconclusive_url_schema() -> None:
    samples = _samples()
    samples[0]["cases"][0]["requested_url"].pop("query_sha256")

    assert classify_samples(samples) == "inconclusive"


def test_query_presence_must_match_the_query_hash_contract() -> None:
    samples = _samples()
    for sample in samples:
        for row in sample["cases"]:
            for field in ("requested_url", "final_url"):
                row[field]["query_present"] = True

    assert classify_samples(samples) == "inconclusive"


def test_round_trip_and_case_sorting_are_deterministic() -> None:
    samples = _samples()
    reversed_cases = deepcopy(samples)
    for sample in reversed_cases:
        sample["cases"].reverse()

    first = build_evidence(samples)
    second = build_evidence(reversed_cases)
    rendered = evidence_json(first)

    assert first == second
    assert json.loads(rendered) == first
    assert [row["case_id"] for row in first["samples"][0]["cases"]] == list(CASE_IDS)
    assert rendered == evidence_json(first)
    assert first["classification"] in CLASSIFICATIONS


LIVE_PATH = (
    Path(__file__).resolve().parents[1]
    / "live"
    / "test_phase_20_soa_volatility_live.py"
)


def _live_harness() -> dict[str, object]:
    return runpy.run_path(str(LIVE_PATH))


def _authorized_profile_result(live: dict[str, object]) -> tuple[str, str]:
    authority = live["PHASE_20_LIVE"]["HTTP_PROFILE_COMPATIBILITY"]
    result = authority["classify_http_profile_compatibility"](
        authority["describe_http_profile"](
            authority["FROZEN_OLD_HTTP_REQUEST_PROFILE"]
        ),
        authority["describe_http_profile"](authority["WEB_HTTP_REQUEST_PROFILE"]),
        old_provenance=authority["FROZEN_OLD_HTTP_PROFILE_PROVENANCE"],
        old_identity=authority["FROZEN_OLD_GATEWAY_IDENTITY"],
    )
    return result.kind.value, result.code


def _valid_worker_evidence(
    live: dict[str, object], classification: str = "stable_match"
) -> dict[str, object]:
    cases = live["_offline_cases"]()
    samples = []
    raw_results = {}
    for sequence, (system, sample_number) in enumerate(SAMPLE_ORDER, start=1):
        raw = live["_offline_child_fixture"](system)
        if classification == "stable_cross_system_mismatch" and system == "new":
            raw["cases"][0]["content_sha256"] = _sha("c")
            raw["cases"][1]["content_sha256"] = _sha("d")
        elif classification == "site_dynamic" and sample_number == 2:
            raw["cases"][0]["content_sha256"] = _sha("c")
            raw["cases"][1]["content_sha256"] = _sha("d")
        process = {"outcome": "exited-success", "return_code": 0, "errors": []}
        if classification == "inconclusive" and sequence == 1:
            process = {
                "outcome": "exited-failure",
                "return_code": 1,
                "errors": [
                    {"code": "old.process_failure", "error_type": "WorkerError"}
                ],
            }
        samples.append(
            live["_normalize_child"](
                raw,
                process,
                system=system,
                sequence=sequence,
                sample_number=sample_number,
                cases=cases,
            )
        )
        raw_results[(system, sample_number)] = raw
    profile_validation_inputs = live["_profile_validation_inputs"](raw_results, cases)
    profile_checks = live["_profile_checks"](profile_validation_inputs, cases, samples)
    evidence = build_evidence(samples)
    snapshot, target, _cases = live["_load_soa_target"]()
    evidence.update(
        {
            "site_key": "soa",
            "old_commit": live["OLD_COMMIT"],
            "source_catalog_sha256": snapshot["source_catalog_sha256"],
            "target_snapshot_sha256": hashlib.sha256(
                live["TARGETS"].read_bytes()
            ).hexdigest(),
            "authorization_window_sha256": "f" * 64,
            "provenance": target["provenance"],
            "execution_order": [
                {"sequence": index, "system": system, "sample": sample_number}
                for index, (system, sample_number) in enumerate(SAMPLE_ORDER, start=1)
            ],
            "http_profile_checks": profile_checks,
            "profile_validation_inputs": profile_validation_inputs,
            "outer_budget": {
                "elapsed_seconds": 1.0,
                "hard_deadline_seconds": live["OUTER_HARD_DEADLINE_SECONDS"],
                "within_budget": True,
            },
        }
    )
    assert evidence["classification"] == classification
    return evidence


def _write_bundle_fixture(root: Path) -> dict[str, bytes]:
    expected = {}
    for sample_number in (1, 2):
        sample_root = root / f"new-sample-{sample_number}"
        database = f"sqlite-{sample_number}".encode("ascii")
        database_path = sample_root / "artifact.sqlite3"
        database_path.parent.mkdir(parents=True)
        database_path.write_bytes(database)
        expected[database_path.relative_to(root).as_posix()] = database
        for blob_number in (1, 2):
            payload = f"blob-{sample_number}-{blob_number}".encode("ascii")
            sha256 = hashlib.sha256(payload).hexdigest()
            blob_path = sample_root / "blobs" / sha256[:2] / f"{sha256}.blob"
            blob_path.parent.mkdir(parents=True, exist_ok=True)
            blob_path.write_bytes(payload)
            expected[blob_path.relative_to(root).as_posix()] = payload
        (sample_root / "not-audit.txt").write_text("exclude", encoding="utf-8")
    legacy = root / "legacy"
    legacy.mkdir()
    (legacy / "old.tar").write_text("exclude", encoding="utf-8")
    return expected


def _run_supervised_fixture(
    live: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    evidence: dict[str, object],
    *,
    elapsed_seconds: float = 1.0,
) -> dict[str, object]:
    run = live["_run_supervised_diagnosis"]
    monkeypatch.setitem(
        run.__globals__,
        "_supervise_worker",
        lambda *_args, **_kwargs: (
            evidence,
            {"outcome": "exited-success", "return_code": 0, "errors": []},
        ),
    )
    readings = iter((100.0, 100.0 + elapsed_seconds))
    monkeypatch.setitem(
        run.__globals__, "time", SimpleNamespace(monotonic=lambda: next(readings))
    )
    return run(Path("unused"), "f" * 64)


def test_live_harness_uses_only_fixed_soa_and_split_aggregate_limits() -> None:
    live = _live_harness()
    snapshot, target, cases = live["_load_soa_target"]()

    assert target["site_key"] == "soa"
    assert [case["case_id"] for case in cases] == list(CASE_IDS)
    assert [case["requested_url"] for case in cases] == [
        "https://www.soa.org/",
        "https://www.soa.org/publications/publications-landing/",
    ]
    assert snapshot["network_limits_per_system_per_site"] == {
        "max_targets": 2,
        "max_total_requests": 8,
        "max_total_response_bytes": 4 * 1024 * 1024,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
    }
    assert live["SAMPLE_LIMITS"] == {
        "max_targets": 2,
        "max_total_requests": 4,
        "max_total_response_bytes": 2 * 1024 * 1024,
        "timeout_seconds": 15,
        "concurrency": 1,
        "retry": 0,
    }
    assert live["GOVERNED_NETWORK_SECONDS"] == 13
    assert live["OUTER_HARD_DEADLINE_SECONDS"] == 65


def test_live_harness_has_one_fixed_interleaved_execution_and_no_url_override() -> None:
    live = _live_harness()
    source = inspect.getsource(live["_run_diagnosis"])
    environment_names = set(
        name
        for name in (
            "WEB_LISTENING_RUN_LIVE",
            "WEB_LISTENING_LIVE_AUTHORIZED_WINDOW",
            "WEB_LISTENING_LIVE_SITE",
        )
        if name in LIVE_PATH.read_text(encoding="utf-8")
    )
    all_environment_names = set(
        __import__("re").findall(
            r'os\.environ(?:\.get)?\[?\(?["\']([A-Z0-9_]+)',
            LIVE_PATH.read_text(encoding="utf-8"),
        )
    )

    assert live["EXECUTION_ORDER"] == SAMPLE_ORDER
    assert "for sequence, (system, sample_number)" in source
    assert "retry" not in source.lower()
    assert environment_names == all_environment_names
    assert environment_names == {
        "WEB_LISTENING_RUN_LIVE",
        "WEB_LISTENING_LIVE_AUTHORIZED_WINDOW",
        "WEB_LISTENING_LIVE_SITE",
    }
    assert all(not name.endswith("_URL") for name in environment_names)


def test_probe_entrypoints_support_the_smaller_per_sample_budget() -> None:
    live = _live_harness()
    legacy = live["LEGACY_HELPERS"]
    current = live["NEW_HELPERS"]

    request_limit, body_limit, robots_limit = legacy["_case_limits"](
        live["SAMPLE_LIMITS"], 2
    )
    new_budget = current["_NetworkBudget"](
        live["SAMPLE_LIMITS"], live["GOVERNED_NETWORK_SECONDS"]
    )

    assert request_limit == 2
    assert body_limit == 512 * 1024
    assert robots_limit == 512 * 1024
    assert new_budget.max_requests == 4
    assert new_budget.max_response_bytes == 2 * 1024 * 1024
    assert new_budget.max_seconds == 13
    run_source = inspect.getsource(live["_run_probe_process"])
    assert "_run_legacy_process" not in run_source
    assert "_run_new_process" not in run_source


def test_fixed_profile_authority_reports_the_only_permitted_nonblocker() -> None:
    live = _live_harness()

    assert _authorized_profile_result(live) == (
        "explained_fixed_difference",
        "profile.fixed_old_accept_encoding",
    )


@pytest.mark.parametrize(
    "classification",
    [
        "stable_match",
        "site_dynamic",
        "stable_cross_system_mismatch",
        "inconclusive",
    ],
)
def test_complete_canonical_worker_evidence_accepts_all_diagnostic_categories(
    classification: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live, classification)

    result = _run_supervised_fixture(live, monkeypatch, evidence)

    assert result["classification"] == classification
    assert result["outer_budget"] == {
        "elapsed_seconds": 1.0,
        "hard_deadline_seconds": live["OUTER_HARD_DEADLINE_SECONDS"],
        "within_budget": True,
    }
    assert result["worker_validation"]["outcome"] == "valid"
    assert result["worker_validation"]["reason_codes"] == []
    assert all(result["worker_validation"]["predicates"].values())


def test_valid_worker_evidence_survives_real_json_round_trip() -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)

    assert live["_success_evidence_is_valid"](evidence, "f" * 64) is True
    round_tripped = json.loads(evidence_json(evidence))

    assert live["_success_evidence_is_valid"](round_tripped, "f" * 64) is True


def test_missing_raw_failure_is_preserved_through_parent_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    cases = live["_offline_cases"]()
    samples = []
    raw_results = {}
    for sequence, (system, sample_number) in enumerate(SAMPLE_ORDER, start=1):
        if system == "old":
            raw = None
            process = {
                "outcome": "not-started",
                "return_code": "N/A",
                "errors": [{"code": "old.setup_failure", "error_type": "RuntimeError"}],
            }
        else:
            raw = live["_offline_child_fixture"](system)
            process = {"outcome": "exited-success", "return_code": 0, "errors": []}
        samples.append(
            live["_normalize_child"](
                raw,
                process,
                system=system,
                sequence=sequence,
                sample_number=sample_number,
                cases=cases,
            )
        )
        raw_results[(system, sample_number)] = raw

    profile_inputs = live["_profile_validation_inputs"](raw_results, cases)
    profile_checks = live["_profile_checks"](profile_inputs, cases, samples)
    evidence = build_evidence(samples)
    fixed = _valid_worker_evidence(live)
    for key in (
        "site_key",
        "old_commit",
        "source_catalog_sha256",
        "target_snapshot_sha256",
        "authorization_window_sha256",
        "provenance",
        "execution_order",
        "outer_budget",
    ):
        evidence[key] = deepcopy(fixed[key])
    evidence["http_profile_checks"] = profile_checks
    evidence["profile_validation_inputs"] = profile_inputs
    round_tripped = json.loads(evidence_json(evidence))
    audit = live["_success_evidence_audit"](round_tripped, "f" * 64)
    expected_samples = deepcopy(round_tripped["samples"])

    result = _run_supervised_fixture(live, monkeypatch, round_tripped)

    expected_outcomes = [
        "not-started",
        "exited-success",
        "not-started",
        "exited-success",
    ]
    assert (
        audit["reason_codes"],
        [sample["process_outcome"] for sample in result["samples"]],
    ) == ([], expected_outcomes)
    assert audit["outcome"] == "valid"
    assert result["worker_validation"] == audit
    assert result["classification"] == "inconclusive"
    assert result["samples"] == expected_samples
    assert "worker_process" not in result
    unavailable_url = safe_url_descriptor(None)
    for sample in result["samples"]:
        if sample["system"] == "old":
            assert sample["process_return_code"] == "N/A"
            assert sample["budget"]["within_budget"] is False
            assert all(
                sample["budget"][field] is None
                for field in ("requests", "response_bytes", "elapsed_seconds")
            )
            for case in sample["cases"]:
                assert case["outcome"] == "failure"
                assert case["requested_url"] == unavailable_url
                assert case["final_url"] == unavailable_url
                assert case["usage"] == {
                    "requests": None,
                    "response_bytes": None,
                    "target_bytes": None,
                    "within_budget": False,
                }
                assert case["error"]
        else:
            assert [
                (case["content_sha256"], case["content_bytes"])
                for case in sample["cases"]
            ] == [("a" * 64, 100), ("b" * 64, 100)]


@pytest.mark.parametrize(
    ("outcome", "field", "descriptor", "expected"),
    [
        ("failure", "requested_url", safe_url_descriptor(None), (True, True)),
        ("failure", "final_url", safe_url_descriptor(None), (True, True)),
        ("success", "requested_url", safe_url_descriptor(None), (False, True)),
        ("success", "final_url", safe_url_descriptor(None), (True, False)),
        ("timeout", "requested_url", safe_url_descriptor(None), (False, True)),
        ("failure", "requested_url", {"scheme": "N/A"}, (False, True)),
        ("failure", "final_url", {"scheme": "N/A"}, (True, False)),
        (
            "failure",
            "final_url",
            safe_url_descriptor("https://example.com/off-origin"),
            (True, False),
        ),
    ],
)
def test_failure_url_sentinel_is_exact_and_scoped_to_failure(
    outcome: str,
    field: str,
    descriptor: dict[str, object],
    expected: tuple[bool, bool],
) -> None:
    live = _live_harness()
    _snapshot, target, cases = live["_load_soa_target"]()
    rows = [
        {
            "case_id": case["case_id"],
            "outcome": outcome,
            "requested_url": safe_url_descriptor(case["requested_url"]),
            "final_url": safe_url_descriptor(case["requested_url"]),
        }
        for case in cases
    ]
    rows[0][field] = descriptor

    assert live["_fixed_url_predicates"]([{"cases": rows}], target, cases) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/not-soa",
        "https://www.soa.org/not-soa",
        "https://www.soa.org/?x=1",
        "https://www.soa.org:444/",
    ],
)
def test_failure_requested_url_rejects_every_nonfixed_safe_shape(url: str) -> None:
    live = _live_harness()
    _snapshot, target, cases = live["_load_soa_target"]()
    rows = [
        {
            "case_id": case["case_id"],
            "outcome": "failure",
            "requested_url": safe_url_descriptor(case["requested_url"]),
            "final_url": safe_url_descriptor(None),
        }
        for case in cases
    ]
    rows[0]["requested_url"] = safe_url_descriptor(url)

    assert live["_fixed_url_predicates"]([{"cases": rows}], target, cases) == (
        False,
        True,
    )


@pytest.mark.parametrize(
    ("mutation", "reason_code"),
    [
        ("top-level", "evidence.top_level_shape"),
        ("schema", "evidence.schema_version"),
        ("sample-order", "evidence.sample_order"),
        ("canonical-core", "evidence.canonical_core"),
        ("fixed-metadata", "evidence.fixed_metadata"),
        ("fixed-digests", "evidence.fixed_digests"),
        ("execution-order", "evidence.execution_order"),
        ("fixed-requested-url", "evidence.fixed_requested_url"),
        ("allowed-final-origin", "evidence.allowed_final_origin"),
        ("outer-budget", "evidence.outer_budget"),
        ("profile-inputs", "evidence.profile_validation_inputs"),
        ("profile-recomputation", "evidence.profile_recomputation"),
        ("profile-check-schema", "evidence.profile_check_schema"),
    ],
)
def test_success_evidence_audit_reports_exact_safe_predicate(
    mutation: str,
    reason_code: str,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)
    if mutation == "top-level":
        evidence["credential"] = "Bearer predicate secret"
    elif mutation == "schema":
        evidence["schema_version"] = "drifted"
    elif mutation == "sample-order":
        evidence["samples"].reverse()
    elif mutation == "canonical-core":
        evidence["classification"] = "site_dynamic"
    elif mutation == "fixed-metadata":
        evidence["site_key"] = "cas"
    elif mutation == "fixed-digests":
        evidence["target_snapshot_sha256"] = "0" * 64
    elif mutation == "execution-order":
        evidence["execution_order"].reverse()
    elif mutation in {"fixed-requested-url", "allowed-final-origin"}:
        field = "requested_url" if mutation == "fixed-requested-url" else "final_url"
        evidence["samples"][0]["cases"][0][field] = safe_url_descriptor(
            "https://example.com/secret?credential=predicate"
        )
        canonical = build_evidence(evidence["samples"])
        for key in ("classification", "limits", "samples", "system_totals"):
            evidence[key] = canonical[key]
    elif mutation == "outer-budget":
        evidence["outer_budget"]["within_budget"] = False
    elif mutation == "profile-inputs":
        evidence["profile_validation_inputs"][0].pop("old")
    elif mutation == "profile-recomputation":
        evidence["http_profile_checks"][0]["cases"][0][
            "code"
        ] = "profile.evidence_invalid"
    else:
        evidence["http_profile_checks"][0]["within_authority"] = "yes"

    audit = live["_success_evidence_audit"](evidence, "f" * 64)
    rendered = json.dumps(audit, sort_keys=True)

    assert audit["outcome"] == "invalid"
    assert reason_code in audit["reason_codes"]
    assert audit["predicates"][reason_code] is False
    assert set(audit["reason_codes"]) <= live["_EVIDENCE_REASON_CODES"]
    assert "predicate secret" not in rendered
    assert "credential" not in rendered


def test_safe_worker_projection_never_echoes_malformed_worker_values() -> None:
    live = _live_harness()
    malformed = {
        "credential": "Bearer projection secret",
        "samples": [{"body": "projection body secret", "system": "old"}],
    }
    audit = live["_success_evidence_audit"](malformed, "f" * 64)

    projection = live["_safe_worker_projection"](malformed, audit)
    rendered = json.dumps(projection, sort_keys=True)

    assert projection["worker_validation"] == audit
    assert projection["worker_shape"] == {
        "sample_count": 1,
        "top_level_key_count": 2,
    }
    assert "projection secret" not in rendered
    assert "projection body" not in rendered
    assert "credential" not in rendered
    assert "body" not in rendered


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/not-soa?x=1",
        "https://www.soa.org/not-soa",
        "https://www.soa.org/?x=1",
        "https://www.soa.org/?",
        "https://www.soa.org:444/",
    ],
)
def test_parent_rejects_uniform_nonfixed_requested_url_shapes(
    url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)
    descriptor = safe_url_descriptor(url)
    for sample in evidence["samples"]:
        for row in sample["cases"]:
            row["requested_url"] = descriptor
            row["final_url"] = descriptor
    canonical = build_evidence(evidence["samples"])
    for key in ("classification", "limits", "samples", "system_totals"):
        evidence[key] = canonical[key]

    result = _run_supervised_fixture(live, monkeypatch, evidence)

    assert result["classification"] == "inconclusive"
    assert result["worker_process"]["outcome"] == "invalid-evidence"


def test_parent_rejects_final_url_outside_fixed_allowed_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)
    descriptor = safe_url_descriptor("https://example.com/final")
    for sample in evidence["samples"]:
        for row in sample["cases"]:
            row["final_url"] = descriptor
    canonical = build_evidence(evidence["samples"])
    for key in ("classification", "limits", "samples", "system_totals"):
        evidence[key] = canonical[key]

    result = _run_supervised_fixture(live, monkeypatch, evidence)

    assert result["classification"] == "inconclusive"
    assert result["worker_process"]["outcome"] == "invalid-evidence"


def test_complete_profile_blocker_diagnostic_remains_a_valid_success_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)
    authority = live["PHASE_20_LIVE"]["HTTP_PROFILE_COMPATIBILITY"]
    drifted_profile = dict(authority["FROZEN_OLD_HTTP_REQUEST_PROFILE"])
    drifted_profile["accept_encoding"] = "identity, deflate"
    descriptor = live["_profile_descriptor_payload"](drifted_profile)
    for validation_input in evidence["profile_validation_inputs"]:
        old_profile = validation_input["old"]
        old_profile["authority"] = deepcopy(descriptor)
        for row in old_profile["cases"]:
            row["observations"] = [
                deepcopy(descriptor) for _item in row["observations"]
            ]
            row["collapsed"] = deepcopy(descriptor)
    evidence["http_profile_checks"] = live["_recomputed_profile_checks"](
        evidence["profile_validation_inputs"],
        evidence["samples"],
        live["_offline_cases"](),
    )
    assert all(
        check["within_authority"] is False
        and {row["kind"] for row in check["cases"]} == {"blocker"}
        for check in evidence["http_profile_checks"]
    )
    for sample in evidence["samples"]:
        sample["error"] = [
            {
                "code": "volatility.http_profile_blocker",
                "error_type": "N/A",
            }
        ]
    canonical = build_evidence(evidence["samples"])
    for key in (
        "classification",
        "limits",
        "samples",
        "schema_version",
        "system_totals",
    ):
        evidence[key] = canonical[key]
    evidence = json.loads(evidence_json(evidence))

    result = _run_supervised_fixture(live, monkeypatch, evidence)

    assert result["classification"] == "inconclusive"
    assert "worker_process" not in result


def test_unknown_case_error_is_redacted_through_parent_json_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)
    row = evidence["samples"][0]["cases"][0]
    row["outcome"] = "failure"
    row["error"] = [
        {
            "code": "BearerTopSecret123",
            "error_type": "BearerTopSecretType",
        }
    ]
    canonical = build_evidence(evidence["samples"])
    for key in (
        "classification",
        "limits",
        "samples",
        "schema_version",
        "system_totals",
    ):
        evidence[key] = canonical[key]
    evidence = json.loads(evidence_json(evidence))

    result = _run_supervised_fixture(live, monkeypatch, evidence)
    rendered = evidence_json(result)

    assert result["classification"] == "inconclusive"
    assert "worker_process" not in result
    assert "BearerTopSecret123" not in rendered
    assert "BearerTopSecretType" not in rendered
    assert "volatility.unsafe_error" in rendered


def test_fabricated_profile_blocker_code_is_invalid_worker_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)
    for check in evidence["http_profile_checks"]:
        check["within_authority"] = False
        check["blockers"] = [
            "document:http_profile",
            "monitor:http_profile",
        ]
        for row in check["cases"]:
            row["kind"] = "blocker"
            row["code"] = "profile.fabricated_typo"
    for sample in evidence["samples"]:
        sample["error"] = [
            {
                "code": "volatility.http_profile_blocker",
                "error_type": "N/A",
            }
        ]
    canonical = build_evidence(evidence["samples"])
    for key in ("classification", "limits", "samples", "system_totals"):
        evidence[key] = canonical[key]

    result = _run_supervised_fixture(live, monkeypatch, evidence)

    assert result["classification"] == "inconclusive"
    assert result["worker_process"]["outcome"] == "invalid-evidence"


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-inputs",
        "missing-round-field",
        "extra-round-field",
        "extra-profile-field",
        "sample-order",
        "profile-drift",
    ],
)
def test_profile_validation_input_drift_fails_closed_without_echo(
    mutation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)
    if mutation == "missing-inputs":
        evidence.pop("profile_validation_inputs")
    elif mutation == "missing-round-field":
        evidence["profile_validation_inputs"][0].pop("old")
    elif mutation == "extra-round-field":
        evidence["profile_validation_inputs"][0]["credential"] = "top-secret"
    elif mutation == "extra-profile-field":
        evidence["profile_validation_inputs"][0]["old"]["headers"] = {
            "authorization": "top-secret"
        }
    elif mutation == "sample-order":
        evidence["profile_validation_inputs"].reverse()
    else:
        evidence["profile_validation_inputs"][0]["old"]["authority"]["fields"][0][
            1
        ] = "identity, deflate"

    result = _run_supervised_fixture(live, monkeypatch, evidence)
    rendered = evidence_json(result)

    assert result["classification"] == "inconclusive"
    assert result["worker_process"]["outcome"] == "invalid-evidence"
    assert "profile_validation_inputs" not in result
    assert "top-secret" not in rendered
    assert "authorization" not in rendered


def test_success_strips_profile_validation_inputs_and_raw_profile_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)
    authority = live["PHASE_20_LIVE"]["HTTP_PROFILE_COMPATIBILITY"]

    result = _run_supervised_fixture(live, monkeypatch, evidence)
    rendered = evidence_json(result)

    assert result["classification"] == "stable_match"
    assert "profile_validation_inputs" not in result
    assert "identity, gzip" not in rendered
    assert authority["WEB_HTTP_REQUEST_PROFILE"]["user_agent"] not in rendered


def test_profile_validation_inputs_contain_only_fixed_profile_evidence() -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)
    validation_inputs = evidence["profile_validation_inputs"]
    rendered = json.dumps(validation_inputs, sort_keys=True)

    assert [set(row) for row in validation_inputs] == [
        {"new", "old", "sample"},
        {"new", "old", "sample"},
    ]
    assert all(
        set(row[system])
        == {"authority", "cases", "identity", "provenance", "schema_version"}
        for row in validation_inputs
        for system in ("old", "new")
    )
    for forbidden in (
        "authorization_window",
        "body",
        "error",
        "final_url",
        "headers",
        "requested_url",
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        ("exact_match", "profile.exact_match"),
        ("explained_fixed_difference", "profile.exact_match"),
    ],
)
def test_other_nonblocking_profile_rows_are_invalid_worker_evidence(
    kind: str,
    code: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)
    for check in evidence["http_profile_checks"]:
        for row in check["cases"]:
            row["kind"] = kind
            row["code"] = code

    result = _run_supervised_fixture(live, monkeypatch, evidence)

    assert result["classification"] == "inconclusive"
    assert result["worker_process"]["outcome"] == "invalid-evidence"


@pytest.mark.parametrize(
    ("content_sha256", "content_bytes"),
    [
        (_sha("a"), 0),
        (hashlib.sha256(b"").hexdigest(), 100),
        (hashlib.sha256(b"").hexdigest(), 0),
    ],
)
def test_inconsistent_body_shape_worker_evidence_fails_closed(
    content_sha256: str,
    content_bytes: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)
    for sample in evidence["samples"]:
        row = next(case for case in sample["cases"] if case["case_id"] == "monitor")
        row["content_sha256"] = content_sha256
        row["content_bytes"] = content_bytes
        row["usage"]["target_bytes"] = content_bytes

    result = _run_supervised_fixture(live, monkeypatch, evidence)

    assert result["classification"] == "inconclusive"
    assert result["worker_process"]["outcome"] == "invalid-evidence"


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-top-field",
        "extra-top-field",
        "classification",
        "totals",
        "limits",
        "sample-order",
        "noncanonical-sample",
        "malformed-case-type",
        "site-key",
        "old-commit",
        "catalog-digest",
        "target-digest",
        "authorization-digest",
        "provenance",
        "execution-order",
        "profile-checks",
        "outer-budget",
    ],
)
def test_malformed_success_worker_evidence_fails_closed(
    mutation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = deepcopy(_valid_worker_evidence(live))
    if mutation == "missing-top-field":
        evidence.pop("provenance")
    elif mutation == "extra-top-field":
        evidence["body"] = "secret query=value"
    elif mutation == "classification":
        evidence["classification"] = "site_dynamic"
    elif mutation == "totals":
        evidence["system_totals"]["old"]["requests"] = 0
    elif mutation == "limits":
        evidence["limits"]["retry"] = 1
    elif mutation == "sample-order":
        evidence["samples"].reverse()
    elif mutation == "noncanonical-sample":
        evidence["samples"][0]["body"] = "secret response"
    elif mutation == "malformed-case-type":
        evidence["samples"][0]["cases"][0]["case_id"] = []
    elif mutation == "site-key":
        evidence["site_key"] = "cas"
    elif mutation == "old-commit":
        evidence["old_commit"] = "0" * 40
    elif mutation == "catalog-digest":
        evidence["source_catalog_sha256"] = "0" * 64
    elif mutation == "target-digest":
        evidence["target_snapshot_sha256"] = "0" * 64
    elif mutation == "authorization-digest":
        evidence["authorization_window_sha256"] = "0" * 64
    elif mutation == "provenance":
        evidence["provenance"] = {}
    elif mutation == "execution-order":
        evidence["execution_order"].reverse()
    elif mutation == "profile-checks":
        evidence["http_profile_checks"][0]["within_authority"] = False
    else:
        evidence["outer_budget"]["hard_deadline_seconds"] = 66

    result = _run_supervised_fixture(live, monkeypatch, evidence)
    rendered = evidence_json(result)

    assert result["classification"] == "inconclusive"
    assert result["worker_process"] == {
        "outcome": "invalid-evidence",
        "return_code": "N/A",
        "error": [
            {
                "code": "volatility.worker_output",
                "error_type": "SchemaError",
            }
        ],
    }
    assert result["worker_validation"]["outcome"] == "invalid"
    assert result["worker_validation"]["reason_codes"]
    assert (
        set(result["worker_validation"]["reason_codes"])
        <= live["_EVIDENCE_REASON_CODES"]
    )
    assert "secret query=value" not in rendered
    assert "secret response" not in rendered


def test_audit_bundle_is_unique_canonical_and_copies_only_new_artifacts(
    tmp_path: Path,
) -> None:
    live = _live_harness()
    worker_root = tmp_path / "worker"
    expected = _write_bundle_fixture(worker_root)
    delivery = tmp_path / "delivery"
    delivery.mkdir()
    first_log = delivery / "issue-67-soa-live-final.log"
    state = delivery / "issue-67.json"
    first_log.write_text("first live log", encoding="utf-8")
    state.write_text("state sentinel", encoding="utf-8")
    digest = "f" * 64
    evidence = _valid_worker_evidence(live)
    audit = live["_success_evidence_audit"](evidence, digest)
    projection = live["_safe_worker_projection"](evidence, audit)

    candidate = live["_prevalidate_audit_bundle_destination"](delivery, digest)
    result = live["_persist_audit_bundle"](
        candidate,
        worker_root,
        projection,
        digest,
    )

    assert candidate == (delivery.resolve() / f"issue-67-soa-audit-{digest}")
    assert result == {
        "outcome": "persisted",
        "bundle_path": str(candidate),
        "manifest_sha256": hashlib.sha256(
            (candidate / "manifest.json").read_bytes()
        ).hexdigest(),
        "file_count": 7,
        "reason_codes": [],
    }
    manifest = json.loads((candidate / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "phase-20-soa-audit-manifest.v1"
    assert manifest["authorization_window_sha256"] == digest
    assert [row["path"] for row in manifest["files"]] == sorted(
        ["projection.json", *expected]
    )
    for row in manifest["files"]:
        path = candidate / Path(row["path"])
        assert path.stat().st_size == row["size"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
    assert json.loads((candidate / "projection.json").read_text(encoding="utf-8")) == (
        projection
    )
    assert not (candidate / "legacy").exists()
    assert not any(candidate.rglob("not-audit.txt"))
    assert first_log.read_text(encoding="utf-8") == "first live log"
    assert state.read_text(encoding="utf-8") == "state sentinel"


def test_existing_audit_bundle_is_rejected_without_overwrite_or_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    delivery = tmp_path / "delivery"
    delivery.mkdir()
    digest = "f" * 64
    candidate = delivery / f"issue-67-soa-audit-{digest}"
    candidate.mkdir()
    sentinel = candidate / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    called = False

    def supervise(*_args: object, **_kwargs: object) -> None:
        nonlocal called
        called = True
        raise AssertionError("worker must not start")

    run = live["_run_supervised_diagnosis"]
    monkeypatch.setitem(run.__globals__, "_supervise_worker", supervise)

    result = run(tmp_path / "worker", digest, bundle_base=delivery)

    assert called is False
    assert result["classification"] == "inconclusive"
    assert result["audit_bundle"] == {
        "outcome": "failed",
        "bundle_path": str(candidate.resolve()),
        "manifest_sha256": "N/A",
        "file_count": 0,
        "reason_codes": ["bundle.destination_exists"],
    }
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_audit_bundle_write_failure_is_fail_closed_and_atomic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    worker_root = tmp_path / "worker"
    _write_bundle_fixture(worker_root)
    delivery = tmp_path / "delivery"
    delivery.mkdir()
    digest = "f" * 64
    candidate = live["_prevalidate_audit_bundle_destination"](delivery, digest)

    def fail_copy(*_args: object, **_kwargs: object) -> None:
        raise OSError("Bearer write failure secret")

    monkeypatch.setattr(live["shutil"], "copyfile", fail_copy)
    result = live["_persist_audit_bundle"](
        candidate,
        worker_root,
        {"schema_version": "safe-projection"},
        digest,
    )

    assert result == {
        "outcome": "failed",
        "bundle_path": str(candidate),
        "manifest_sha256": "N/A",
        "file_count": 0,
        "reason_codes": ["bundle.write_failed"],
    }
    assert not candidate.exists()
    assert not list(delivery.glob(".*.staging-*"))
    assert "secret" not in json.dumps(result)


def test_parent_bundle_write_failure_overrides_valid_worker_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)
    delivery = tmp_path / "delivery"
    delivery.mkdir()
    run = live["_run_supervised_diagnosis"]
    monkeypatch.setitem(
        run.__globals__,
        "_supervise_worker",
        lambda *_args, **_kwargs: (
            evidence,
            {"outcome": "exited-success", "return_code": 0, "errors": []},
        ),
    )
    monkeypatch.setitem(
        run.__globals__,
        "_persist_audit_bundle",
        lambda candidate, *_args: {
            "outcome": "failed",
            "bundle_path": str(candidate),
            "manifest_sha256": "N/A",
            "file_count": 0,
            "reason_codes": ["bundle.write_failed"],
        },
    )
    readings = iter((100.0, 101.0))
    monkeypatch.setitem(
        run.__globals__, "time", SimpleNamespace(monotonic=lambda: next(readings))
    )

    result = run(tmp_path / "worker", "f" * 64, bundle_base=delivery)

    assert result["classification"] == "inconclusive"
    assert result["worker_validation"]["outcome"] == "valid"
    assert result["audit_bundle"]["outcome"] == "failed"
    assert result["audit_bundle"]["reason_codes"] == ["bundle.write_failed"]
    assert result["worker_process"]["error"] == [
        {"code": "volatility.bundle_failure", "error_type": "N/A"}
    ]


def test_real_live_entry_binds_only_the_fixed_external_bundle_base() -> None:
    live = _live_harness()
    source = inspect.getsource(live["test_phase_20_soa_volatility_live"])

    assert live["DELIVERY_STATE"] == Path(
        r"C:\Project\web_listening_new_delivery_state"
    )
    assert "bundle_base=DELIVERY_STATE" in source


def test_parent_elapsed_beyond_hard_deadline_overrides_worker_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _live_harness()
    evidence = _valid_worker_evidence(live)

    result = _run_supervised_fixture(
        live,
        monkeypatch,
        evidence,
        elapsed_seconds=live["OUTER_HARD_DEADLINE_SECONDS"] + 0.001,
    )

    assert result["classification"] == "inconclusive"
    assert result["outer_budget"]["within_budget"] is False
    assert result["worker_process"]["outcome"] == "outer-deadline"
    assert result["error"] == [
        {
            "code": "volatility.outer_deadline",
            "error_type": "TimeoutExpired",
        }
    ]


def test_live_normalization_drops_body_headers_and_raw_errors() -> None:
    live = _live_harness()
    raw = live["_offline_child_fixture"]("old")
    raw["cases"][0]["body"] = "page secret"
    raw["cases"][0]["headers"] = {"authorization": "Bearer secret"}
    raw["cases"][0]["error"] = {
        "error_code": "fixture.error",
        "message": "credential=secret",
        "details": {"token": "secret"},
        "error_type": "FixtureError",
    }
    raw["cases"][0]["outcome"] = "failure"
    normalized = live["_normalize_child"](
        raw,
        {"outcome": "exited-failure", "return_code": 1, "errors": []},
        system="old",
        sequence=1,
        sample_number=1,
        cases=live["_offline_cases"](),
    )
    rendered = evidence_json(build_evidence([normalized]))

    assert normalized["cases"][0]["error"] == [
        {"code": "volatility.unsafe_error", "error_type": "N/A"}
    ]
    assert normalized["error"] == [{"code": "old.process_failure", "error_type": "N/A"}]
    assert "page secret" not in rendered
    assert "authorization" not in rendered
    assert "credential" not in rendered
    assert "token" not in rendered


@pytest.mark.parametrize("system", ["old", "new"])
@pytest.mark.parametrize(
    ("case_id", "field", "value"),
    [
        ("monitor", "word_count", None),
        ("monitor", "word_count", 149),
        ("monitor", "document_link_count", None),
        ("document", "word_count", None),
        ("document", "word_count", 149),
        ("document", "document_link_count", None),
        ("document", "document_link_count", 0),
    ],
)
def test_live_missing_or_low_probe_threshold_is_inconclusive(
    system: str, case_id: str, field: str, value: int | None
) -> None:
    live = _live_harness()
    cases = live["_offline_cases"]()
    samples = []
    for sequence, (sample_system, sample_number) in enumerate(SAMPLE_ORDER, start=1):
        raw = live["_offline_child_fixture"](sample_system)
        for record in raw["cases"]:
            expected_links = 1 if record["case_id"] == "document" else 0
            record["word_count"] = 150
            record["document_link_count"] = expected_links
        if sample_system == system and sample_number == 1:
            record = next(item for item in raw["cases"] if item["case_id"] == case_id)
            if value is None:
                record.pop(field)
            else:
                record[field] = value
        samples.append(
            live["_normalize_child"](
                raw,
                {"outcome": "exited-success", "return_code": 0, "errors": []},
                system=sample_system,
                sequence=sequence,
                sample_number=sample_number,
                cases=cases,
            )
        )

    evidence = build_evidence(samples)

    assert evidence["classification"] == "inconclusive"
    affected = next(
        sample
        for sample in evidence["samples"]
        if sample["system"] == system and sample["sample"] == 1
    )
    affected_case = next(
        item for item in affected["cases"] if item["case_id"] == case_id
    )
    assert affected_case["thresholds"]["met"] is False
    assert affected_case["error"] == [
        {"code": "volatility.threshold_not_met", "error_type": "ThresholdError"}
    ]


def test_outer_supervisor_terminates_a_blocked_diagnosis_worker(
    tmp_path: Path,
) -> None:
    live = _live_harness()
    orphan_marker = tmp_path / "orphaned-probe"
    child = (
        "import pathlib,time; time.sleep(1); "
        f"pathlib.Path({str(orphan_marker)!r}).write_text('orphan', encoding='utf-8')"
    )
    blocked_worker = (
        "import subprocess,sys,time; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[1]]); "
        "time.sleep(30)"
    )
    started = time.monotonic()

    raw, process = live["_supervise_worker"](
        [sys.executable, "-c", blocked_worker, child],
        {},
        timeout_seconds=0.2,
    )

    assert time.monotonic() - started < 5
    assert raw is None
    assert process == {
        "outcome": "outer-deadline",
        "return_code": "N/A",
        "errors": [
            {
                "code": "volatility.outer_deadline",
                "error_type": "TimeoutExpired",
            }
        ],
    }
    time.sleep(1.1)
    assert not orphan_marker.exists()


def test_outer_worker_contains_setup_children_and_profile_checks() -> None:
    live = _live_harness()
    worker_source = inspect.getsource(live["_worker_main"])
    diagnosis_source = inspect.getsource(live["_run_diagnosis"])
    test_source = inspect.getsource(live["test_phase_20_soa_volatility_live"])

    assert "_run_diagnosis" in worker_source
    assert "_prepare_old_context" in diagnosis_source
    assert "_run_old_sample" in diagnosis_source
    assert "_run_new_sample" in diagnosis_source
    assert "_profile_checks" in diagnosis_source
    assert "_run_supervised_diagnosis" in test_source


def test_outer_deadline_emits_only_safe_inconclusive_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    live = _live_harness()
    run = live["_run_supervised_diagnosis"]
    monkeypatch.setitem(
        run.__globals__,
        "_supervise_worker",
        lambda *_args, **_kwargs: (
            None,
            {
                "outcome": "outer-deadline",
                "return_code": "N/A",
                "errors": [
                    {
                        "code": "volatility.outer_deadline",
                        "error_type": "TimeoutExpired",
                    }
                ],
            },
        ),
    )

    evidence = run(tmp_path, "f" * 64)
    rendered = evidence_json(evidence)

    assert evidence["classification"] == "inconclusive"
    assert evidence["outer_budget"]["within_budget"] is False
    assert evidence["error"] == [
        {
            "code": "volatility.outer_deadline",
            "error_type": "TimeoutExpired",
        }
    ]
    assert [
        (sample["system"], sample["sample"]) for sample in evidence["samples"]
    ] == list(SAMPLE_ORDER)
    assert evidence["system_totals"] == {
        "old": {
            "requests": "N/A",
            "response_bytes": "N/A",
            "elapsed_seconds": "N/A",
            "within_budget": False,
        },
        "new": {
            "requests": "N/A",
            "response_bytes": "N/A",
            "elapsed_seconds": "N/A",
            "within_budget": False,
        },
    }
    assert all(
        sample["process_outcome"] == "not-observed"
        and sample["budget"]["requests"] == "N/A"
        and sample["budget"]["response_bytes"] == "N/A"
        and sample["budget"]["elapsed_seconds"] == "N/A"
        and sample["budget"]["within_budget"] is False
        for sample in evidence["samples"]
    )
    assert "authorization" not in rendered
    assert "message" not in rendered
    assert "details" not in rendered


@pytest.mark.parametrize(
    "process",
    [
        {
            "outcome": "outer-deadline",
            "return_code": "N/A",
            "errors": [
                {
                    "code": "volatility.outer_deadline",
                    "error_type": "TimeoutExpired",
                }
            ],
        },
        {
            "outcome": "exited-failure",
            "return_code": 1,
            "errors": [
                {
                    "code": "volatility.worker_failure",
                    "error_type": "WorkerError",
                }
            ],
        },
    ],
)
def test_supervised_failures_never_claim_zero_consumption_or_success(
    process: dict[str, object],
) -> None:
    live = _live_harness()

    evidence = live["_supervised_failure_evidence"](process, 0.5)

    assert evidence["classification"] == "inconclusive"
    assert len(evidence["samples"]) == 4
    assert evidence["worker_process"] == {
        "outcome": process["outcome"],
        "return_code": process["return_code"],
        "error": process["errors"],
    }
    for totals in evidence["system_totals"].values():
        assert totals == {
            "requests": "N/A",
            "response_bytes": "N/A",
            "elapsed_seconds": "N/A",
            "within_budget": False,
        }
    for sample in evidence["samples"]:
        assert sample["process_outcome"] == "not-observed"
        assert sample["process_return_code"] == "N/A"
        assert sample["budget"]["within_budget"] is False
        assert all(
            sample["budget"][field] == "N/A"
            for field in ("requests", "response_bytes", "elapsed_seconds")
        )


def test_live_diagnosis_keeps_exact_order_after_one_boundary_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    live = _live_harness()
    run = live["_run_diagnosis"]
    cases = live["_offline_cases"]()
    calls: list[tuple[str, int]] = []

    def normalized(
        system: str, sequence: int, sample_number: int
    ) -> tuple[dict[str, object], dict[str, object]]:
        raw = live["_offline_child_fixture"](system)
        return (
            live["_normalize_child"](
                raw,
                {"outcome": "exited-success", "return_code": 0, "errors": []},
                system=system,
                sequence=sequence,
                sample_number=sample_number,
                cases=cases,
            ),
            raw,
        )

    def run_old(
        _context,
        _target,
        _cases,
        *,
        sequence,
        sample_number,
        outer_deadline,
    ):
        del outer_deadline
        calls.append(("old", sample_number))
        return normalized("old", sequence, sample_number)

    def run_new(
        _tmp_path,
        _target,
        _cases,
        _window_digest,
        *,
        sequence,
        sample_number,
        outer_deadline,
    ):
        del outer_deadline
        calls.append(("new", sample_number))
        if sample_number == 1:
            raise RuntimeError("must be redacted")
        return normalized("new", sequence, sample_number)

    monkeypatch.setitem(
        run.__globals__,
        "_load_soa_target",
        lambda: (
            {"source_catalog_sha256": "A" * 64},
            {
                "site_key": "soa",
                "allowed_origins": ["https://www.soa.org"],
                "provenance": {"old_commit": live["OLD_COMMIT"]},
            },
            cases,
        ),
    )
    monkeypatch.setitem(
        run.__globals__, "_prepare_old_context", lambda *_args: {"ready": True}
    )
    monkeypatch.setitem(run.__globals__, "_run_old_sample", run_old)
    monkeypatch.setitem(run.__globals__, "_run_new_sample", run_new)
    monkeypatch.setitem(run.__globals__, "_profile_checks", lambda *_args: [])

    evidence = run(tmp_path, "f" * 64)

    assert calls == list(SAMPLE_ORDER)
    assert [
        (sample["system"], sample["sample"]) for sample in evidence["samples"]
    ] == list(SAMPLE_ORDER)
    failed = evidence["samples"][1]
    assert failed["process_outcome"] == "boundary-failure"
    assert failed["error"] == [
        {"code": "new.boundary", "error_type": "RuntimeError"},
        {"code": "new.output_schema", "error_type": "SchemaError"},
    ]
    assert evidence["classification"] == "inconclusive"
    assert "must be redacted" not in evidence_json(evidence)


def test_report_keeps_observations_inferences_and_issue_21_gates_separate() -> None:
    report = (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "phase-20-soa-volatility-report.md"
    ).read_text(encoding="utf-8")
    prose = " ".join(report.split())

    for heading in (
        "## Observed facts",
        "## Allowed inference",
        "## What this cannot prove",
        "## Issue #21 follow-up conditions",
        "## README 1-2 and 18-20 alignment",
    ):
        assert heading in report
    for classification in CLASSIFICATIONS:
        assert f"`{classification}`" in report
    for live_boundary in (
        "first authorized SOA Live run occurred on 2026-08-30",
        "exit 0; 1 passed in 3.72s",
        "pytest result is not an Issue PASS",
        "LIVE FAIL",
        "emitted classification is `inconclusive`",
        "The original worker envelope was not saved",
        "The exact failing child condition",
        "is therefore unknown",
        "historical hashes support only new-side time variation",
        "not complete Live evidence",
        "did not independently repeat the SQLite integrity",
        "No immutable copy was made",
        "deleted that artifact root",
        "no longer available for reinspection",
        "Issue #21 therefore remains `BLOCKED`",
        "must not be overwritten or reused as release evidence",
        "diagnostic launcher exited `1` before pytest started",
        "`Set-Alias -Scope Process` is not valid PowerShell",
        "Native pytest exit and all test counts are `N/A`",
        "Network requests were `0`",
        "no authorization window was generated",
        "No diagnostic log was created",
        "zero JSON evidence records",
        "classification, samples, caps, profile, digests, worker validation",
        "projection, and bundle evidence are all absent",
        "No retry or rerun occurred",
        "At that aborted-launch point, bundle and staging directory counts were",
        "classified this launcher attempt as `ABORTED`",
        "not an actual diagnostic",
        "does not consume the authorized diagnostic Live",
        "one authorized actual diagnostic then completed",
        "native pytest result was `exit 0; 1 passed`",
        "diagnostic pytest result is not an evidence PASS",
        "`evidence.fixed_requested_url`",
        "`evidence.allowed_final_origin`",
        "other eleven predicates were true",
        "issue-67-soa-diagnostic-actual.log",
        "50284f2ac6faac030684d67347c0821529c9c32cd186ec0771fcbc3453bfee99",
        "b985384aa9255130b639eb842864d1f0785fde6412b024bc4cca9806e3a75728",
        "fresh bundle audit passed",
        "diagnostic evidence gate failed",
        "Only new-side artifact I/O is independently supported",
        "Old-side I/O, cumulative caps, and profile evidence remain unknown",
        "historical raw URL values were not retained",
        "does not prove that condition was the historical root cause",
        "The unique final one-shot then completed",
        "native pytest process returned `0`",
        "final agent measured `4.73` seconds",
        "log records `1 passed in 4.62s`",
        "issue-67-soa-final-actual.log",
        "05f9a21c701ebfea0e4a0bad4c25a8a4a3f5cf7c3f0b381abfd7d69dab07510c",
        "valid fail-closed `inconclusive` classification",
        "all `13/13` predicates true and no reason codes",
        "issue-67-soa-audit-009744d9b5a8bbdb2c22e558057472d30ae6490cf82ae9aac60a52857a916a80",
        "a13ff9e2ea8937d9ff2453572928b6b53761e7356c8a4f5813cb38be3ac197e5",
        "FINAL I/O AUDIT PASS",
        "ISSUE #67 EVIDENCE PASS",
        "old-1 and old-2 ended `environment-mismatch` / `not-started`",
        "actual usage is `N/A`, not a fabricated zero",
        "New-1 used 4 requests, 648,431 bytes, and 1.542 seconds",
        "new-2 used 4 requests, 648,431 bytes, and 0.885 seconds",
        "8 requests, 1,296,862 bytes, and 2.427 seconds",
        "outer run used 4.411 of 65 seconds",
        "`profile.old_provenance_mismatch`",
        "validation, recomputation, and check-schema predicates were true",
        "Issue #67 may enter the publication workflow",
        "Issue #21 remains `BLOCKED` until complete fresh `stable_match` evidence",
        (
            "At the time this final evidence was captured, no commit or pull "
            "request had yet been created"
        ),
        "frozen allowlisted reason code",
        "unique checkout-external bundle destination",
        "canonical bundle manifest",
    ):
        assert live_boundary in prose
    assert "completely fresh three-site SOA/CAS/IAA Required Live" in prose
    assert "No normalization, ignore" in prose
