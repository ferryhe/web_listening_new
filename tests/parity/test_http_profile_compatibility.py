"""Offline contract tests for the one frozen Phase 20 HTTP profile difference."""

# pylint: disable=duplicate-code,missing-function-docstring

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import fields, replace
from types import MappingProxyType
from typing import Mapping

import http_profile_compatibility as compatibility  # pylint: disable=import-error
import pytest
from http_profile_compatibility import (  # pylint: disable=import-error
    FROZEN_OLD_GATEWAY_IDENTITY,
    FROZEN_OLD_HTTP_PROFILE_PROVENANCE,
    FROZEN_OLD_HTTP_REQUEST_PROFILE,
    FROZEN_OLD_HTTP_REQUEST_PROFILE_SHA256,
    HttpProfileCompatibilityKind,
    HttpProfileDescriptor,
    OldHttpProfileProvenance,
    classify_http_profile_compatibility,
    describe_http_profile,
)

from web_listening.tool_registry.runners.in_process import (
    WEB_HTTP_REQUEST_PROFILE,
    WEB_HTTP_REQUEST_PROFILE_SHA256,
)

OLD_PROFILE_SHA256 = "0f33f242658db454d85940be3392a1fc51054ce4779e53ff6350e3cab42ce5f5"
NEW_PROFILE_SHA256 = "14450398cbe8c3226505fad035a421c1c3b8a50e820c78b02d22a39888855377"


def _mapping(items: tuple[tuple[str, str], ...]) -> Mapping[str, str]:
    return MappingProxyType(dict(items))


def _descriptor(items: tuple[tuple[str, str], ...]) -> HttpProfileDescriptor:
    return describe_http_profile(_mapping(items))


def _classify(
    old: HttpProfileDescriptor | None = None,
    new: HttpProfileDescriptor | None = None,
    provenance: OldHttpProfileProvenance = FROZEN_OLD_HTTP_PROFILE_PROVENANCE,
    identity: Mapping[str, str] = FROZEN_OLD_GATEWAY_IDENTITY,
) -> compatibility.HttpProfileClassification:
    return classify_http_profile_compatibility(
        old or describe_http_profile(FROZEN_OLD_HTTP_REQUEST_PROFILE),
        new or describe_http_profile(WEB_HTTP_REQUEST_PROFILE),
        old_provenance=provenance,
        old_identity=identity,
    )


def test_frozen_sources_and_profiles_retain_independent_identities() -> None:
    """Both sides retain their own source identity, mapping, and digest."""
    assert FROZEN_OLD_HTTP_PROFILE_PROVENANCE == OldHttpProfileProvenance(
        repository="ferryhe/web_listening",
        commit_sha="9fe9ea53104dd008086dfa0e86c35c50b75f4ce5",
        identity_contract_path="web_listening/contracts/site_diagnostic.py",
        identity_contract_blob_sha="852c377607d21abcfd742d3df979a6adaab8d889",
        transport_path="web_listening/blocks/site_diagnostic.py",
        transport_blob_sha="859a28d90fc933685054bb45fac0c19c642ea1e9",
        gateway_path="web_listening/blocks/access_gateway.py",
        gateway_blob_sha="46934a3ffe5ce71105497b1b672d0fe80dba0932",
        caller_path="web_listening/blocks/governed_read.py",
        caller_blob_sha="d9e6262cd139f75f4074b1694c0a5fe8cf0df137",
    )
    assert tuple(FROZEN_OLD_HTTP_REQUEST_PROFILE.items()) == (
        ("accept_encoding", "identity, gzip"),
        ("connection", "close"),
        ("method", "GET"),
        ("user_agent", WEB_HTTP_REQUEST_PROFILE["user_agent"]),
    )
    assert compatibility.WEB_HTTP_REQUEST_PROFILE is WEB_HTTP_REQUEST_PROFILE
    assert FROZEN_OLD_HTTP_REQUEST_PROFILE_SHA256 == OLD_PROFILE_SHA256
    assert WEB_HTTP_REQUEST_PROFILE_SHA256 == NEW_PROFILE_SHA256
    assert FROZEN_OLD_HTTP_REQUEST_PROFILE_SHA256 != WEB_HTTP_REQUEST_PROFILE_SHA256

    old_canonical = json.dumps(
        dict(FROZEN_OLD_HTTP_REQUEST_PROFILE),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    new_canonical = json.dumps(
        dict(WEB_HTTP_REQUEST_PROFILE),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert hashlib.sha256(old_canonical).hexdigest() == OLD_PROFILE_SHA256
    assert hashlib.sha256(new_canonical).hexdigest() == NEW_PROFILE_SHA256


def test_exact_frozen_pair_has_the_only_explained_difference() -> None:
    result = _classify()

    for field in ("method", "user_agent", "connection"):
        assert FROZEN_OLD_HTTP_REQUEST_PROFILE[field] == WEB_HTTP_REQUEST_PROFILE[field]
    assert result.kind is HttpProfileCompatibilityKind.EXPLAINED_FIXED_DIFFERENCE
    assert result.code == "profile.fixed_old_accept_encoding"
    assert result.old_profile_sha256 == OLD_PROFILE_SHA256
    assert result.new_profile_sha256 == NEW_PROFILE_SHA256
    assert result.differences == (
        compatibility.HttpProfileDifference(
            field="accept_encoding",
            old_value="identity, gzip",
            new_value=WEB_HTTP_REQUEST_PROFILE["accept_encoding"],
        ),
    )


@pytest.mark.parametrize(
    "field",
    [
        "repository",
        "commit_sha",
        "identity_contract_path",
        "identity_contract_blob_sha",
        "transport_path",
        "transport_blob_sha",
        "gateway_path",
        "gateway_blob_sha",
        "caller_path",
        "caller_blob_sha",
    ],
)
def test_each_unknown_old_provenance_identity_is_a_blocker(field: str) -> None:
    provenance = replace(FROZEN_OLD_HTTP_PROFILE_PROVENANCE, **{field: "unknown"})

    result = _classify(provenance=provenance)

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == "profile.old_provenance_mismatch"
    assert not result.differences


@pytest.mark.parametrize("side", ["old", "new"])
@pytest.mark.parametrize("drift", ["extra", "missing", "order", "name_case"])
def test_profile_shape_and_order_drifts_are_blockers(side: str, drift: str) -> None:
    old_items = tuple(FROZEN_OLD_HTTP_REQUEST_PROFILE.items())
    new_items = tuple(WEB_HTTP_REQUEST_PROFILE.items())
    selected = old_items if side == "old" else new_items
    if drift == "extra":
        changed = (*selected, ("x-test", "unexpected"))
    elif drift == "missing":
        changed = selected[:-1]
    elif drift == "order":
        changed = (selected[1], selected[0], *selected[2:])
    else:
        changed = ((selected[0][0].upper(), selected[0][1]), *selected[1:])
    descriptor = _descriptor(changed)

    result = _classify(
        old=descriptor if side == "old" else None,
        new=descriptor if side == "new" else None,
    )

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == f"profile.{side}_fields_drift"


@pytest.mark.parametrize("side", ["old", "new"])
@pytest.mark.parametrize(
    "field", ["accept_encoding", "connection", "method", "user_agent"]
)
def test_every_profile_value_drift_is_a_blocker(side: str, field: str) -> None:
    source = (
        FROZEN_OLD_HTTP_REQUEST_PROFILE if side == "old" else WEB_HTTP_REQUEST_PROFILE
    )
    changed = tuple(
        (key, f"{value}-drift" if key == field else value)
        for key, value in source.items()
    )

    result = _classify(
        old=_descriptor(changed) if side == "old" else None,
        new=_descriptor(changed) if side == "new" else None,
    )

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == f"profile.{side}_fields_drift"


@pytest.mark.parametrize("side", ["old", "new"])
def test_profile_value_case_drift_is_a_blocker(side: str) -> None:
    source = (
        FROZEN_OLD_HTTP_REQUEST_PROFILE if side == "old" else WEB_HTTP_REQUEST_PROFILE
    )
    changed = tuple(
        (key, value.lower() if key == "method" else value)
        for key, value in source.items()
    )

    result = _classify(
        old=_descriptor(changed) if side == "old" else None,
        new=_descriptor(changed) if side == "new" else None,
    )

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == f"profile.{side}_fields_drift"


def test_old_user_agent_must_be_aligned_to_the_new_authority() -> None:
    changed = tuple(
        (key, "legacy-agent/1.0" if key == "user_agent" else value)
        for key, value in FROZEN_OLD_HTTP_REQUEST_PROFILE.items()
    )

    result = _classify(old=_descriptor(changed))

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == "profile.old_fields_drift"


@pytest.mark.parametrize("side", ["old", "new"])
def test_supplied_profile_digest_drift_is_a_blocker(side: str) -> None:
    source = (
        FROZEN_OLD_HTTP_REQUEST_PROFILE if side == "old" else WEB_HTTP_REQUEST_PROFILE
    )
    descriptor = replace(describe_http_profile(source), sha256="0" * 64)

    result = _classify(
        old=descriptor if side == "old" else None,
        new=descriptor if side == "new" else None,
    )

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == f"profile.{side}_sha256_drift"


def test_recomputed_old_digest_cannot_make_a_drifted_profile_acceptable() -> None:
    changed = tuple(
        (key, "POST" if key == "method" else value)
        for key, value in FROZEN_OLD_HTTP_REQUEST_PROFILE.items()
    )
    recomputed = _descriptor(changed)

    result = _classify(old=recomputed)

    assert recomputed.sha256 != OLD_PROFILE_SHA256
    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == "profile.old_fields_drift"


def test_new_authority_sha_drift_is_a_blocker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compatibility, "WEB_HTTP_REQUEST_PROFILE_SHA256", "0" * 64)

    result = _classify()

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == "profile.new_authority_sha256_drift"


@pytest.mark.parametrize("drift", ["value", "order"])
def test_new_authority_mapping_drift_is_a_blocker(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    items = tuple(WEB_HTTP_REQUEST_PROFILE.items())
    if drift == "value":
        changed_items = tuple(
            (key, "POST" if key == "method" else value) for key, value in items
        )
    else:
        changed_items = (items[1], items[0], *items[2:])
    changed_authority = _mapping(changed_items)
    monkeypatch.setattr(compatibility, "WEB_HTTP_REQUEST_PROFILE", changed_authority)

    result = _classify()

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == "profile.new_authority_mapping_drift"


def test_old_authority_mapping_order_drift_is_a_blocker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    items = tuple(FROZEN_OLD_HTTP_REQUEST_PROFILE.items())
    changed_authority = _mapping((items[1], items[0], *items[2:]))
    monkeypatch.setattr(
        compatibility,
        "FROZEN_OLD_HTTP_REQUEST_PROFILE",
        changed_authority,
    )

    result = _classify(old=describe_http_profile(changed_authority))

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == "profile.old_authority_mapping_drift"


def test_equal_profile_input_cannot_bypass_fixed_old_facts() -> None:
    new_descriptor = describe_http_profile(WEB_HTTP_REQUEST_PROFILE)

    result = _classify(old=new_descriptor, new=new_descriptor)

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == "profile.old_fields_drift"


@pytest.mark.parametrize("drift", ["extra", "missing", "order", "name_case"])
def test_old_identity_recipe_shape_and_order_drifts_are_blockers(drift: str) -> None:
    items = tuple(FROZEN_OLD_GATEWAY_IDENTITY.items())
    if drift == "extra":
        changed = (*items, ("unexpected", "value"))
    elif drift == "missing":
        changed = items[:-1]
    elif drift == "order":
        changed = (items[1], items[0], *items[2:])
    else:
        changed = ((items[0][0].upper(), items[0][1]), *items[1:])

    result = _classify(identity=_mapping(changed))

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == "profile.old_identity_recipe_mismatch"


@pytest.mark.parametrize(
    "field", ["identity_id", "product_token", "user_agent", "identity_sha256"]
)
def test_each_old_identity_recipe_value_drift_is_a_blocker(field: str) -> None:
    changed = tuple(
        (key, value.upper() if key == field else value)
        for key, value in FROZEN_OLD_GATEWAY_IDENTITY.items()
    )

    result = _classify(identity=_mapping(changed))

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == "profile.old_identity_recipe_mismatch"


def test_recomputed_identity_digest_cannot_make_a_drifted_recipe_acceptable() -> None:
    changed = dict(FROZEN_OLD_GATEWAY_IDENTITY)
    changed["identity_id"] = "web-listening-runtime-v2-drift"
    visible = {
        key: changed[key] for key in ("identity_id", "product_token", "user_agent")
    }
    canonical = json.dumps(
        visible,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    changed["identity_sha256"] = hashlib.sha256(canonical).hexdigest()

    result = _classify(identity=MappingProxyType(changed))

    assert result.kind is HttpProfileCompatibilityKind.BLOCKER
    assert result.code == "profile.old_identity_recipe_mismatch"


def test_classification_evidence_has_no_content_or_ignore_contract() -> None:
    assert {
        field.name for field in fields(compatibility.HttpProfileClassification)
    } == {
        "kind",
        "code",
        "old_profile_sha256",
        "new_profile_sha256",
        "differences",
    }
    assert set(HttpProfileCompatibilityKind) == {
        HttpProfileCompatibilityKind.EXACT_MATCH,
        HttpProfileCompatibilityKind.EXPLAINED_FIXED_DIFFERENCE,
        HttpProfileCompatibilityKind.BLOCKER,
    }


def test_old_gateway_identity_recipe_avoids_the_incompatible_legacy_helper() -> None:
    """The old gateway needs a valid identity that the legacy helper cannot build."""
    authority_user_agent = WEB_HTTP_REQUEST_PROFILE["user_agent"]
    assert "web-listening-bot" not in authority_user_agent.casefold()

    identity = FROZEN_OLD_GATEWAY_IDENTITY

    assert identity["product_token"] == authority_user_agent.split("/", 1)[0]
    assert identity["product_token"] == "web-listening"
    assert re.fullmatch(r"[-A-Za-z_]+", identity["product_token"])
    assert identity["product_token"].casefold() in identity["user_agent"].casefold()
    assert identity["user_agent"] == authority_user_agent
    visible_identity = {
        key: identity[key] for key in ("identity_id", "product_token", "user_agent")
    }
    canonical = json.dumps(
        visible_identity,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == identity["identity_sha256"]
    assert identity["identity_sha256"] == (
        "de7b07e47b4bb10246395f550e81ce66dabc9680747bbf8cb881109a194e70a5"
    )
