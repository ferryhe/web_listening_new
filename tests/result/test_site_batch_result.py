"""Strict multi-site batch Result contract tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from web_listening.result.errors import ResultValidationError
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
