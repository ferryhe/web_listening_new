"""Fail-closed Phase 20 evidence for one frozen HTTP profile difference."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from web_listening.tool_registry.runners.in_process import (
    WEB_HTTP_REQUEST_PROFILE,
    WEB_HTTP_REQUEST_PROFILE_SHA256,
)

_PROFILE_FIELD_ORDER = ("accept_encoding", "connection", "method", "user_agent")
_FROZEN_NEW_HTTP_REQUEST_PROFILE_SHA256 = (
    "14450398cbe8c3226505fad035a421c1c3b8a50e820c78b02d22a39888855377"
)
_EXPECTED_OLD_HTTP_REQUEST_PROFILE_SHA256 = (
    "0f33f242658db454d85940be3392a1fc51054ce4779e53ff6350e3cab42ce5f5"
)
_EXPECTED_OLD_GATEWAY_IDENTITY_SHA256 = (
    "de7b07e47b4bb10246395f550e81ce66dabc9680747bbf8cb881109a194e70a5"
)
_OLD_GATEWAY_IDENTITY_FIELD_ORDER = (
    "identity_id",
    "product_token",
    "user_agent",
    "identity_sha256",
)


@dataclass(frozen=True, slots=True)
class OldHttpProfileProvenance:  # pylint: disable=too-many-instance-attributes
    """Git object identities that prove the reachable old gateway behavior."""

    repository: str
    commit_sha: str
    identity_contract_path: str
    identity_contract_blob_sha: str
    transport_path: str
    transport_blob_sha: str
    gateway_path: str
    gateway_blob_sha: str
    caller_path: str
    caller_blob_sha: str


FROZEN_OLD_HTTP_PROFILE_PROVENANCE = OldHttpProfileProvenance(
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

# The fixed transport supplies three wire values. Its caller-supplied User-Agent is
# deliberately aligned to the directly imported new authority for the #21 run.
FROZEN_OLD_HTTP_REQUEST_PROFILE: Mapping[str, str] = MappingProxyType(
    {
        "accept_encoding": "identity, gzip",
        "connection": "close",
        "method": "GET",
        "user_agent": WEB_HTTP_REQUEST_PROFILE["user_agent"],
    }
)


def _canonical_profile_sha256(profile: Mapping[str, str]) -> str:
    canonical = json.dumps(
        dict(profile),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _canonical_old_identity_sha256(identity: Mapping[str, str]) -> str:
    canonical = json.dumps(
        dict(identity),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


_FROZEN_OLD_GATEWAY_VISIBLE_IDENTITY: Mapping[str, str] = MappingProxyType(
    {
        "identity_id": "web-listening-runtime-v2",
        "product_token": WEB_HTTP_REQUEST_PROFILE["user_agent"].split("/", 1)[0],
        "user_agent": WEB_HTTP_REQUEST_PROFILE["user_agent"],
    }
)
FROZEN_OLD_GATEWAY_IDENTITY: Mapping[str, str] = MappingProxyType(
    {
        **_FROZEN_OLD_GATEWAY_VISIBLE_IDENTITY,
        "identity_sha256": _canonical_old_identity_sha256(
            _FROZEN_OLD_GATEWAY_VISIBLE_IDENTITY
        ),
    }
)


FROZEN_OLD_HTTP_REQUEST_PROFILE_SHA256 = _canonical_profile_sha256(
    FROZEN_OLD_HTTP_REQUEST_PROFILE
)


@dataclass(frozen=True, slots=True)
class HttpProfileDescriptor:
    """Order-preserving fields and their independently calculated digest."""

    fields: tuple[tuple[str, str], ...]
    sha256: str


def describe_http_profile(profile: Mapping[str, str]) -> HttpProfileDescriptor:
    """Describe one observed request profile without normalizing field order or case."""
    return HttpProfileDescriptor(
        fields=tuple(profile.items()),
        sha256=_canonical_profile_sha256(profile),
    )


class HttpProfileCompatibilityKind(str, Enum):
    """The only three outcomes permitted in Phase 20 profile evidence."""

    EXACT_MATCH = "exact_match"
    EXPLAINED_FIXED_DIFFERENCE = "explained_fixed_difference"
    BLOCKER = "blocker"


@dataclass(frozen=True, slots=True)
class HttpProfileDifference:
    """One non-secret request-profile field difference."""

    field: str
    old_value: str
    new_value: str


@dataclass(frozen=True, slots=True)
class HttpProfileClassification:
    """Sanitized profile-only evidence produced before content comparison."""

    kind: HttpProfileCompatibilityKind
    code: str
    old_profile_sha256: str
    new_profile_sha256: str
    differences: tuple[HttpProfileDifference, ...]


def _classification(
    kind: HttpProfileCompatibilityKind,
    code: str,
    old_profile: HttpProfileDescriptor,
    new_profile: HttpProfileDescriptor,
    differences: tuple[HttpProfileDifference, ...] = (),
) -> HttpProfileClassification:
    return HttpProfileClassification(
        kind=kind,
        code=code,
        old_profile_sha256=old_profile.sha256,
        new_profile_sha256=new_profile.sha256,
        differences=differences,
    )


def _profile_differences(
    old_profile: HttpProfileDescriptor,
    new_profile: HttpProfileDescriptor,
) -> tuple[HttpProfileDifference, ...]:
    return tuple(
        HttpProfileDifference(field=old_key, old_value=old_value, new_value=new_value)
        for (old_key, old_value), (new_key, new_value) in zip(
            old_profile.fields, new_profile.fields
        )
        if old_key == new_key and old_value != new_value
    )


def _blocker(
    code: str,
    old_profile: HttpProfileDescriptor,
    new_profile: HttpProfileDescriptor,
) -> HttpProfileClassification:
    return _classification(
        HttpProfileCompatibilityKind.BLOCKER,
        code,
        old_profile,
        new_profile,
    )


# pylint: disable=too-many-branches,too-many-return-statements
def classify_http_profile_compatibility(
    old_profile: HttpProfileDescriptor,
    new_profile: HttpProfileDescriptor,
    *,
    old_provenance: OldHttpProfileProvenance,
    old_identity: Mapping[str, str],
) -> HttpProfileClassification:
    """Classify only the fixed old/new pair; every drift is a blocker."""
    if old_provenance != FROZEN_OLD_HTTP_PROFILE_PROVENANCE:
        return _blocker("profile.old_provenance_mismatch", old_profile, new_profile)
    if WEB_HTTP_REQUEST_PROFILE_SHA256 != _FROZEN_NEW_HTTP_REQUEST_PROFILE_SHA256:
        return _blocker(
            "profile.new_authority_sha256_drift",
            old_profile,
            new_profile,
        )
    if tuple(WEB_HTTP_REQUEST_PROFILE) != _PROFILE_FIELD_ORDER:
        return _blocker("profile.new_authority_mapping_drift", old_profile, new_profile)
    authoritative_new = describe_http_profile(WEB_HTTP_REQUEST_PROFILE)
    if authoritative_new.sha256 != WEB_HTTP_REQUEST_PROFILE_SHA256:
        return _blocker("profile.new_authority_mapping_drift", old_profile, new_profile)
    authority_user_agent = WEB_HTTP_REQUEST_PROFILE["user_agent"]
    authority_product_token = authority_user_agent.split("/", 1)[0]
    if tuple(FROZEN_OLD_GATEWAY_IDENTITY) != _OLD_GATEWAY_IDENTITY_FIELD_ORDER:
        return _blocker(
            "profile.old_identity_authority_drift", old_profile, new_profile
        )
    frozen_visible_identity = {
        key: FROZEN_OLD_GATEWAY_IDENTITY[key]
        for key in _OLD_GATEWAY_IDENTITY_FIELD_ORDER[:-1]
    }
    if (
        FROZEN_OLD_GATEWAY_IDENTITY["user_agent"] != authority_user_agent
        or FROZEN_OLD_GATEWAY_IDENTITY["product_token"] != authority_product_token
        or authority_product_token.casefold() not in authority_user_agent.casefold()
        or FROZEN_OLD_GATEWAY_IDENTITY["identity_sha256"]
        != _EXPECTED_OLD_GATEWAY_IDENTITY_SHA256
        or _canonical_old_identity_sha256(frozen_visible_identity)
        != FROZEN_OLD_GATEWAY_IDENTITY["identity_sha256"]
    ):
        return _blocker(
            "profile.old_identity_authority_drift", old_profile, new_profile
        )
    if tuple(old_identity.items()) != tuple(FROZEN_OLD_GATEWAY_IDENTITY.items()):
        return _blocker(
            "profile.old_identity_recipe_mismatch", old_profile, new_profile
        )
    if tuple(FROZEN_OLD_HTTP_REQUEST_PROFILE) != _PROFILE_FIELD_ORDER:
        return _blocker(
            "profile.old_authority_mapping_drift",
            old_profile,
            new_profile,
        )
    authoritative_old = describe_http_profile(FROZEN_OLD_HTTP_REQUEST_PROFILE)
    if (
        FROZEN_OLD_HTTP_REQUEST_PROFILE_SHA256
        != _EXPECTED_OLD_HTTP_REQUEST_PROFILE_SHA256
        or authoritative_old.sha256 != FROZEN_OLD_HTTP_REQUEST_PROFILE_SHA256
    ):
        return _blocker(
            "profile.old_authority_mapping_drift",
            old_profile,
            new_profile,
        )
    if old_profile.fields != authoritative_old.fields:
        return _blocker("profile.old_fields_drift", old_profile, new_profile)
    if old_profile.sha256 != authoritative_old.sha256:
        return _blocker("profile.old_sha256_drift", old_profile, new_profile)
    if new_profile.fields != authoritative_new.fields:
        return _blocker("profile.new_fields_drift", old_profile, new_profile)
    if new_profile.sha256 != authoritative_new.sha256:
        return _blocker("profile.new_sha256_drift", old_profile, new_profile)

    differences = _profile_differences(old_profile, new_profile)
    if not differences:
        return _classification(
            HttpProfileCompatibilityKind.EXACT_MATCH,
            "profile.exact_match",
            old_profile,
            new_profile,
        )
    expected_difference = (
        HttpProfileDifference(
            field="accept_encoding",
            old_value="identity, gzip",
            new_value=WEB_HTTP_REQUEST_PROFILE["accept_encoding"],
        ),
    )
    if differences == expected_difference:
        return _classification(
            HttpProfileCompatibilityKind.EXPLAINED_FIXED_DIFFERENCE,
            "profile.fixed_old_accept_encoding",
            old_profile,
            new_profile,
            differences,
        )
    return _classification(
        HttpProfileCompatibilityKind.BLOCKER,
        "profile.unexpected_difference",
        old_profile,
        new_profile,
        differences,
    )


# pylint: enable=too-many-branches,too-many-return-statements
