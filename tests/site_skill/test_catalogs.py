"""Pinned old catalog normalization and Phase 6 target tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from web_listening.request.scope import canonicalize_url
from web_listening.site_skill.validate import site_skill_from_mapping

LIVE = Path(__file__).parents[1] / "live"
CATALOG = LIVE / "catalog"
OLD_COMMIT = "9fe9ea53104dd008086dfa0e86c35c50b75f4ce5"
EXPECTED_BLOBS = {
    "dev": "922ddc452e6f8cb1e8e1eee78832ba178f915fe1",
    "smoke": "e50b2c0d29e1b3c5df6473409c1a33ad4ffee4c4",
}
EXPECTED_SITE_KEYS = {
    "a2ii",
    "adb",
    "afdb",
    "bcbs",
    "bis",
    "caf",
    "cas",
    "fao",
    "fit",
    "fsb",
    "g20",
    "gca",
    "iaa",
    "iais",
    "iea",
    "ifac",
    "ilo",
    "imf",
    "ipcc",
    "irff",
    "issa",
    "issb",
    "ngfs",
    "oecd",
    "pcaf",
    "psi",
    "sif",
    "soa",
    "tnfd",
    "un-water",
    "unctad",
    "undp",
    "unep",
    "unfccc",
    "wef",
    "who",
    "wmo",
    "world-bank",
    "wri",
    "wto",
}
EXPECTED_PROJECTION_SHA256 = (
    "f50ca8092efdee652e4e19546184e51a036bf3a2f845a64df873951d429fdc97"
)


def _load(name: str):
    return json.loads((CATALOG / name).read_text(encoding="utf-8"))


def _nested_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        keys.update(value)
        for child in value.values():
            keys.update(_nested_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_nested_keys(child))
    return keys


def _projection(dev: dict, smoke: dict, cases: dict) -> list[dict]:
    case_by_key = {row["site_key"]: row for row in cases["cases"]}
    return sorted(
        (
            {
                "catalog_kind": payload["catalog_kind"],
                "catalog_row": row,
                "case": case_by_key[row["site_key"]],
            }
            for payload in (dev, smoke)
            for row in payload["sites"]
        ),
        key=lambda item: item["catalog_row"]["site_key"],
    )


def _projection_sha256(dev: dict, smoke: dict, cases: dict) -> str:
    payload = json.dumps(
        _projection(dev, smoke, cases),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _assert_fixed_projection(dev: dict, smoke: dict, cases: dict) -> None:
    assert _projection_sha256(dev, smoke, cases) == EXPECTED_PROJECTION_SHA256


def test_catalogs_preserve_all_3_dev_and_37_smoke_rows_with_provenance() -> None:
    dev = _load("dev_test_sites.json")
    smoke = _load("smoke_site_catalog.json")

    assert dev["schema_version"] == smoke["schema_version"]
    assert dev["catalog_kind"] == "dev"
    assert smoke["catalog_kind"] == "smoke"
    assert len(dev["sites"]) == 3
    assert len(smoke["sites"]) == 37
    assert len({row["site_key"] for row in dev["sites"]}) == 3
    assert len({row["site_key"] for row in smoke["sites"]}) == 37
    for kind, payload, source_path in (
        ("dev", dev, "config/dev_test_sites.json"),
        ("smoke", smoke, "config/smoke_site_catalog.json"),
    ):
        for row in payload["sites"]:
            assert row["provenance"] == {
                "old_commit": OLD_COMMIT,
                "old_path": source_path,
                "old_blob": EXPECTED_BLOBS[kind],
                "old_site_key": row["site_key"],
            }
            assert row["allowed_origins"]
            assert row["urls"]["monitor"]
            assert row["historical_classification"]
            assert row["evidence_thresholds"]


def test_catalog_rows_reference_valid_matching_site_skill_cases() -> None:
    dev = _load("dev_test_sites.json")
    smoke = _load("smoke_site_catalog.json")
    cases = _load("site_skill_cases.json")
    by_key = {row["site_key"]: row for row in cases["cases"]}
    assert cases["schema_version"] == "normalized-site-catalog.v1"
    assert cases["catalog_kind"] == "site_skill_cases"
    assert len(cases["cases"]) == 40
    catalog_keys = {
        row["site_key"] for payload in (dev, smoke) for row in payload["sites"]
    }
    assert catalog_keys == set(by_key) == EXPECTED_SITE_KEYS

    for payload in (dev, smoke):
        for row in payload["sites"]:
            case = by_key[row["site_skill_case"]]
            skill = site_skill_from_mapping(case["site_skill"])
            assert case["provenance"] == row["provenance"]
            assert skill.site_key == row["site_key"]
            assert skill.digest == row["site_skill_digest"]
            assert set(skill.scope.allowed_origins) == set(row["allowed_origins"])
            expected_seeds = [canonicalize_url(row["urls"]["monitor"])]
            if row["urls"]["tree_seed"] is not None:
                expected_seeds.append(canonicalize_url(row["urls"]["tree_seed"]))
            assert skill.scope.seeds == tuple(expected_seeds)
            assert row["tool_facts"] == case["site_skill"]["tool"]


def test_fixed_sha_projection_locks_all_retained_catalog_and_case_facts() -> None:
    dev = _load("dev_test_sites.json")
    smoke = _load("smoke_site_catalog.json")
    cases = _load("site_skill_cases.json")

    _assert_fixed_projection(dev, smoke, cases)


def test_coordinated_catalog_case_digest_drift_breaks_fixed_projection() -> None:
    dev = _load("dev_test_sites.json")
    smoke = _load("smoke_site_catalog.json")
    cases = _load("site_skill_cases.json")
    changed_smoke = deepcopy(smoke)
    changed_cases = deepcopy(cases)
    row = next(item for item in changed_smoke["sites"] if item["site_key"] == "ipcc")
    case = next(item for item in changed_cases["cases"] if item["site_key"] == "ipcc")
    row["urls"]["monitor"] = "https://changed.example/"
    row["allowed_origins"] = ["https://changed.example"]
    row["provenance"]["old_site_key"] = "coordinated-change"
    case["site_skill"]["scope"]["seeds"] = ["https://changed.example/"]
    case["site_skill"]["scope"]["allowed_origins"] = ["https://changed.example"]
    case["provenance"] = deepcopy(row["provenance"])
    digest_payload = dict(case["site_skill"])
    digest_payload.pop("digest")
    digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                digest_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )
    case["site_skill"]["digest"] = digest
    row["site_skill_digest"] = digest

    with pytest.raises(AssertionError):
        _assert_fixed_projection(dev, changed_smoke, changed_cases)


def test_tree_memory_and_ipcc_inert_recipe_are_preserved_exactly() -> None:
    smoke = _load("smoke_site_catalog.json")
    cases = _load("site_skill_cases.json")
    rows = {row["site_key"]: row for row in smoke["sites"]}
    case_by_key = {row["site_key"]: row for row in cases["cases"]}

    assert rows["iea"]["urls"]["tree_seed"] == "https://www.iea.org/news"
    assert rows["iea"]["tree_include_paths"] == ["/news"]
    assert rows["unfccc"]["urls"]["tree_seed"] == "https://unfccc.int/documents"
    assert rows["unfccc"]["tree_include_paths"] == ["/documents"]
    assert rows["ipcc"]["allowed_origins"] == ["https://www.ipcc.ch"]
    assert case_by_key["iea"]["site_skill"]["scope"]["include_paths"] == [
        "/",
        "/news/**",
    ]
    assert case_by_key["unfccc"]["site_skill"]["scope"]["include_paths"] == [
        "/news",
        "/documents/**",
    ]
    expected_tool = {
        "tool_id": "acquisition.web_http",
        "version": "1.0.0",
        "category": "acquisition",
        "capabilities": ["http_get"],
        "recipe_id": "catalog-http",
    }
    assert rows["ipcc"]["tool_facts"] == expected_tool
    assert case_by_key["ipcc"]["site_skill"]["tool"] == expected_tool


def test_normalized_catalogs_drop_runtime_and_secret_authority_fields() -> None:
    forbidden = {
        "fetch_config",
        "fetch_mode",
        "user_agent",
        "browser",
        "executor",
        "script",
        "script_path",
        "entrypoint",
        "command",
        "credential",
        "secret",
        "fallback",
        "runtime",
    }
    for name in (
        "dev_test_sites.json",
        "smoke_site_catalog.json",
        "site_skill_cases.json",
    ):
        payload = _load(name)
        assert _nested_keys(payload).isdisjoint(forbidden)


def test_phase_06_target_is_only_ipcc_and_derived_from_catalog() -> None:
    target_payload = json.loads(
        (LIVE / "phase_06_site_targets.json").read_text(encoding="utf-8")
    )
    assert target_payload["schema_version"] == "phase-06-live-targets.v1"
    assert target_payload["network_limits"] == {
        "max_targets": 2,
        "max_content_reads_per_target": 1,
        "max_total_requests": 12,
        "max_bytes_per_response": 2097152,
        "timeout_seconds": 30,
        "concurrency": 1,
        "retry": 0,
    }
    assert len(target_payload["targets"]) == 1
    target = target_payload["targets"][0]
    assert target["site_key"] == "ipcc"
    assert target["url"] == "https://www.ipcc.ch/"
    assert target["historical_expectation"] == "pass_http"
    assert target["minimum_words"] == 300

    ipcc = next(
        row
        for row in _load("smoke_site_catalog.json")["sites"]
        if row["site_key"] == "ipcc"
    )
    assert target["url"] == ipcc["urls"]["monitor"]
    assert target["allowed_origins"] == ipcc["allowed_origins"]
    assert target["site_skill_digest"] == ipcc["site_skill_digest"]
    assert target["site_skill_case"] == ipcc["site_skill_case"]
    assert target["provenance"] == ipcc["provenance"]
    assert (
        target["historical_expectation"]
        == ipcc["historical_classification"]["expectation"]
    )
    assert target["minimum_words"] == ipcc["evidence_thresholds"]["monitor_min_words"]
    case = next(
        row
        for row in _load("site_skill_cases.json")["cases"]
        if row["site_key"] == "ipcc"
    )
    assert target["provenance"] == case["provenance"]
    assert target["site_skill_digest"] == case["site_skill"]["digest"]
    assert (
        target["minimum_words"] == case["site_skill"]["success_checks"]["minimum_words"]
    )
