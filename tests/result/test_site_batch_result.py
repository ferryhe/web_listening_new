"""Strict multi-site batch Result contract tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from web_listening.result.errors import ResultValidationError, SafeError
from web_listening.result.model import ResultStatus
from web_listening.result.site_batch import SiteBatchMode
from web_listening.runtime.site_batch import site_batch_result_from_mapping

FIXTURES = Path(__file__).with_name("fixtures")


def _payload(name: str) -> dict[str, object]:
    value = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_first_usable_fixture_round_trips_with_explicit_availability() -> None:
    payload = _payload("site-batch-first-usable.v1.json")

    result = site_batch_result_from_mapping(payload)

    assert result.status is ResultStatus.COMPLETED
    assert result.site_keys == ("one.test", "two.test")
    assert result.site_modes == (SiteBatchMode.RECOVERED,) * 2
    assert result.usable_site_keys == result.site_keys
    assert (
        tuple(context.site_skill.site_key for context in result.next_refresh_contexts)
        == result.site_keys
    )
    assert all(
        context.site_skill.scope.allowed_origins
        == (f"https://{context.site_skill.site_key}",)
        for context in result.next_refresh_contexts
    )
    assert json.loads(result.canonical_json_bytes()) == payload


def test_recovered_fixture_keeps_partial_coverage_and_rollback_evidence() -> None:
    payload = _payload("site-batch-refresh-recovered.v1.json")

    result = site_batch_result_from_mapping(payload)

    assert result.status is ResultStatus.PARTIAL
    assert result.site_modes == (SiteBatchMode.RECOVERED,) * 2
    assert result.usable_site_keys == result.site_keys
    assert len(result.next_refresh_contexts) == 2
    assert all(not child.refresh_complete for child in result.site_results)
    assert all(not child.missing for child in result.site_results)
    assert all(child.unresolved for child in result.site_results)
    for child, context in zip(
        result.site_results,
        result.next_refresh_contexts,
        strict=True,
    ):
        update = child.site_skill_update
        assert update is not None
        assert context.site_skill.previous_digest == (
            f"sha256:{update.previous.sha256}"
        )
        assert context.site_skill.digest == update.candidate.digest
        assert context.previous_state.site_skill_digest == context.site_skill.digest
        assert context.site_skill.scope.allowed_origins == (
            f"https://{context.site_skill.site_key}",
        )


@pytest.mark.parametrize(
    ("requested_url", "site_key"),
    (
        ("https://[::1]/", "::1"),
        ("https://[::1]:8443/", "::1"),
        ("https://[fe80::1%25eth0]:8443/", "fe80::1%25eth0"),
    ),
)
def test_result_round_trips_canonical_ipv6_request_identity(
    requested_url: str,
    site_key: str,
) -> None:
    payload = _payload("site-batch-first-usable.v1.json")
    child = payload["site_results"][0]
    error = SafeError(
        "budget.exhausted",
        "Exploration budget was exhausted.",
    ).to_dict()
    payload["site_keys"][0] = site_key
    payload["usable_site_keys"][0] = site_key
    payload["next_refresh_contexts"].pop(0)
    payload["status"] = "partial"
    payload["stop_reason"] = "partial"
    payload["errors"] = [error]
    child["status"] = "partial"
    child["exploration_complete"] = False
    child["site_skill_candidate"] = None
    child["site_state"]["complete"] = False
    child["site_state"]["site_skill_digest"] = None
    child["stop_reason"] = "budget_exhausted"
    child["errors"] = [error]
    seed = child["target_results"][0]
    seed["manifest"]["requested_url"] = requested_url
    seed["manifest"]["redirects"] = [
        {
            "order": 0,
            "from_url": requested_url,
            "to_url": "https://one.test/",
            "http_status": 302,
            "decision": "followed",
        }
    ]
    seed["attempts"][0]["requested_url"] = requested_url
    seed["manifest"]["attempts"][0]["requested_url"] = requested_url
    child["attempts"][0]["requested_url"] = requested_url

    result = site_batch_result_from_mapping(payload)

    assert result.site_keys[0] == site_key
    assert result.site_results[0].target_results[0].manifest.requested_url == (
        requested_url
    )
    assert json.loads(result.canonical_json_bytes()) == payload


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda value: value.update({"retry": 1}), "schema.unknown_fields"),
        (
            lambda value: value["site_keys"].__setitem__(1, value["site_keys"][0]),
            "site_batch.site_order_invalid",
        ),
        (
            lambda value: value["site_keys"].reverse(),
            "site_batch.site_order_invalid",
        ),
        (
            lambda value: value.update({"run_id": "unrelated-run"}),
            "site_batch.run_identity_mismatch",
        ),
        (
            lambda value: value["usage"].update(
                {"requests": value["usage"]["requests"] + 1}
            ),
            "site_batch.usage_mismatch",
        ),
        (
            lambda value: value["site_modes"].__setitem__(0, "replayed"),
            "site_batch.mode_mismatch",
        ),
        (
            lambda value: value.update({"usable_site_keys": ["one.test"]}),
            "site_batch.usable_sites_mismatch",
        ),
    ],
)
def test_result_rejects_unknown_duplicate_order_identity_usage_and_fact_drift(
    mutate,
    code: str,
) -> None:
    payload = copy.deepcopy(_payload("site-batch-first-usable.v1.json"))
    mutate(payload)

    with pytest.raises(ResultValidationError, match=f"^{code}$"):
        site_batch_result_from_mapping(payload)


def test_result_rejects_a_next_context_not_bound_to_current_state() -> None:
    payload = _payload("site-batch-refresh-recovered.v1.json")
    payload["next_refresh_contexts"][0]["previous_state"]["site_skill_digest"] = (
        "sha256:" + "f" * 64
    )

    with pytest.raises(
        ResultValidationError,
        match="^site_batch.next_context_invalid$",
    ):
        site_batch_result_from_mapping(payload)
