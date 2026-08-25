"""Site Skill canonical value and validation contract tests."""

# pylint: disable=duplicate-code,missing-function-docstring

from __future__ import annotations

import ast
import traceback
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from web_listening.request.model import Budgets, ContentType, Scope
from web_listening.site_skill.model import SiteSkillError, SuccessChecks, ToolReference
from web_listening.site_skill.update import create_candidate
from web_listening.site_skill.validate import (
    canonical_site_skill_bytes,
    compute_site_skill_digest,
    site_skill_from_mapping,
    site_skill_to_mapping,
)
from web_listening.tool_registry.manifest import ToolCategory


def _scope(seed: str = "https://example.test/reports/") -> Scope:
    return Scope(
        seeds=(seed,),
        allowed_origins=("https://example.test",),
        include_paths=("/reports/**",),
        content_types=(ContentType.HTML,),
    )


def _candidate(*, previous=None, version: int = 1):
    return create_candidate(
        site_key="example",
        version=version,
        previous=previous,
        scope=_scope(),
        budgets=Budgets(4, 4096, 20, 1),
        tool=ToolReference(
            "acquisition.web_http",
            "1.0.0",
            ToolCategory.ACQUISITION,
            frozenset({"http_get"}),
        ),
        success_checks=SuccessChecks(("text/html",), 100),
        verified_at="2026-08-25T00:00:00Z",
    )


def test_canonical_bytes_and_digest_are_stable() -> None:
    skill = _candidate().skill
    mapping = site_skill_to_mapping(skill)
    rebuilt = site_skill_from_mapping(deepcopy(mapping))

    assert rebuilt == skill
    assert canonical_site_skill_bytes(rebuilt) == canonical_site_skill_bytes(skill)
    assert skill.digest.startswith("sha256:")
    assert len(skill.digest) == 71
    assert canonical_site_skill_bytes(skill) == canonical_site_skill_bytes(skill)


def test_version_requires_explicit_previous_digest() -> None:
    first = _candidate().skill
    second = _candidate(previous=first, version=2).skill

    assert second.previous_digest == first.digest
    assert second.version == 2
    with pytest.raises(SiteSkillError, match="site_skill.previous_required"):
        create_candidate(
            site_key="example",
            version=2,
            previous=None,
            scope=_scope(),
            budgets=first.budgets,
            tool=first.tool,
            success_checks=first.success_checks,
            verified_at=first.verified_at,
        )


class _HostileSiteKey:
    def __init__(self) -> None:
        self.comparisons = 0

    def __eq__(self, _other):
        self.comparisons += 1
        raise RuntimeError("PRIVATE-SITE-KEY-CANARY")

    def __ne__(self, _other):
        self.comparisons += 1
        raise RuntimeError("PRIVATE-SITE-KEY-CANARY")


class _HostileSiteKeyStr(str):
    comparisons = 0

    def __new__(cls):
        return super().__new__(cls, "example")

    def __eq__(self, _other):
        _HostileSiteKeyStr.comparisons += 1
        raise RuntimeError("PRIVATE-STR-SITE-KEY-CANARY")

    def __ne__(self, _other):
        _HostileSiteKeyStr.comparisons += 1
        raise RuntimeError("PRIVATE-STR-SITE-KEY-CANARY")


@pytest.mark.parametrize(
    ("site_key", "canary"),
    [
        (_HostileSiteKey(), "PRIVATE-SITE-KEY-CANARY"),
        (_HostileSiteKeyStr(), "PRIVATE-STR-SITE-KEY-CANARY"),
    ],
)
def test_candidate_rejects_hostile_site_key_before_lineage_comparison(
    site_key: object, canary: str
) -> None:
    first = _candidate().skill

    _assert_stable_rejection(
        lambda: create_candidate(
            site_key=site_key,
            version=2,
            previous=first,
            scope=first.scope,
            budgets=first.budgets,
            tool=first.tool,
            success_checks=first.success_checks,
            verified_at=first.verified_at,
        ),
        "site_skill.site_key_invalid",
        canary,
    )

    assert site_key.comparisons == 0


def test_candidate_lineage_accepts_exact_string_site_key() -> None:
    first = _candidate().skill

    second = _candidate(previous=first, version=2).skill

    assert isinstance(second.site_key, str)
    assert second.site_key == "example"
    assert second.previous_digest == first.digest


def test_same_content_with_different_lineage_has_different_identity() -> None:
    first_parent = _candidate().skill
    other_parent = create_candidate(
        site_key="example",
        version=1,
        previous=None,
        scope=_scope("https://example.test/reports/other"),
        budgets=first_parent.budgets,
        tool=first_parent.tool,
        success_checks=first_parent.success_checks,
        verified_at=first_parent.verified_at,
    ).skill

    left = _candidate(previous=first_parent, version=2).skill
    right = _candidate(previous=other_parent, version=2).skill

    assert left.previous_digest != right.previous_digest
    assert left.digest != right.digest


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("password", "private-canary", "site_skill.sensitive_data"),
        ("credential", "private-canary", "site_skill.sensitive_data"),
        ("secret", "private-canary", "site_skill.sensitive_data"),
        ("code", "print('x')", "site_skill.executable_surface"),
        ("command", "run", "site_skill.executable_surface"),
        ("script_path", "run.py", "site_skill.executable_surface"),
        ("entrypoint", "module:main", "site_skill.executable_surface"),
        ("path", "/tmp/skill", "site_skill.executable_surface"),
        ("authority_override", True, "site_skill.unknown_field"),
    ],
)
def test_authority_bearing_unknown_fields_fail_closed_without_echo(
    field: str, value: object, code: str
) -> None:
    mapping = site_skill_to_mapping(_candidate().skill)
    mapping[field] = value

    with pytest.raises(SiteSkillError) as caught:
        site_skill_from_mapping(mapping)

    assert caught.value.code == code
    assert "private-canary" not in str(caught.value)


def test_secret_value_in_nested_data_is_rejected_without_echo() -> None:
    mapping = site_skill_to_mapping(_candidate().skill)
    mapping["scope"]["seeds"] = ["https://example.test/reports/?token=private-canary"]

    with pytest.raises(SiteSkillError) as caught:
        site_skill_from_mapping(mapping)

    assert caught.value.code == "site_skill.sensitive_data"
    assert "private-canary" not in str(caught.value)


def test_direct_values_revalidate_digest() -> None:
    skill = _candidate().skill
    tampered = replace(skill, digest="sha256:" + "0" * 64)

    with pytest.raises(SiteSkillError, match="site_skill.digest_mismatch"):
        canonical_site_skill_bytes(tampered)


class _HostileMapping(Mapping):
    def __getitem__(self, _key):
        raise RuntimeError("PRIVATE-MAPPING-CANARY")

    def __iter__(self):
        raise RuntimeError("PRIVATE-MAPPING-CANARY")

    def __len__(self):
        raise RuntimeError("PRIVATE-MAPPING-CANARY")


class _HostileList(list):
    def __iter__(self):
        raise RuntimeError("PRIVATE-SEQUENCE-CANARY")


def _assert_stable_rejection(call, code: str, canary: str) -> None:
    with pytest.raises(SiteSkillError) as caught:
        call()

    assert caught.value.code == code
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    if canary:
        assert canary not in "".join(traceback.format_exception(caught.value))


def test_hostile_mapping_and_sequence_are_rejected_before_protocol_calls() -> None:
    _assert_stable_rejection(
        lambda: site_skill_from_mapping(_HostileMapping()),
        "site_skill.invalid",
        "PRIVATE-MAPPING-CANARY",
    )
    mapping = site_skill_to_mapping(_candidate().skill)
    mapping["tool"]["capabilities"] = _HostileList(["http_get"])
    _assert_stable_rejection(
        lambda: site_skill_from_mapping(mapping),
        "site_skill.invalid",
        "PRIVATE-SEQUENCE-CANARY",
    )


@pytest.mark.parametrize(
    ("section", "field", "code"),
    [
        ("tool", "capabilities", "site_skill.tool_capabilities_invalid"),
        ("success_checks", "allowed_mime_types", "site_skill.checks_invalid"),
    ],
)
def test_unhashable_nested_values_return_stable_errors_without_mutation(
    section: str, field: str, code: str
) -> None:
    mapping = site_skill_to_mapping(_candidate().skill)
    mapping[section][field] = [[]]
    before = deepcopy(mapping)

    _assert_stable_rejection(lambda: site_skill_from_mapping(mapping), code, "")

    assert mapping == before


@pytest.mark.parametrize(
    ("field", "replacement", "code"),
    [
        ("category", "acquisition", "site_skill.tool_invalid"),
        ("capabilities", ["http_get"], "site_skill.tool_capabilities_invalid"),
        ("tool_id", 7, "site_skill.tool_invalid"),
    ],
)
def test_forged_direct_tool_reference_is_rejected_not_normalized(
    field: str, replacement: object, code: str
) -> None:
    skill = _candidate().skill
    forged_tool = replace(skill.tool, **{field: replacement})
    forged = replace(skill, tool=forged_tool)

    _assert_stable_rejection(lambda: canonical_site_skill_bytes(forged), code, "")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("allowed_mime_types", ["text/html"]),
        ("allowed_mime_types", (7,)),
        ("minimum_words", True),
    ],
)
def test_forged_direct_success_checks_are_rejected_not_normalized(
    field: str, replacement: object
) -> None:
    skill = _candidate().skill
    forged_checks = replace(skill.success_checks, **{field: replacement})
    forged = replace(skill, success_checks=forged_checks)

    _assert_stable_rejection(
        lambda: canonical_site_skill_bytes(forged),
        "site_skill.checks_invalid",
        "",
    )


def test_recipe_identifier_is_inert_canonical_data_and_strictly_validated() -> None:
    skill = _candidate().skill
    with_recipe = replace(
        skill,
        tool=replace(skill.tool, recipe_id="catalog-http"),
        digest="sha256:" + "0" * 64,
    )
    with_recipe = replace(with_recipe, digest=compute_site_skill_digest(with_recipe))
    mapping = site_skill_to_mapping(with_recipe)

    assert mapping["tool"]["recipe_id"] == "catalog-http"
    assert site_skill_from_mapping(mapping) == with_recipe
    mapping["tool"]["recipe_id"] = "module:main"
    _assert_stable_rejection(
        lambda: site_skill_from_mapping(mapping), "site_skill.tool_invalid", ""
    )


def test_production_modules_have_no_io_or_dynamic_execution_authority() -> None:
    root = Path(__file__).parents[2] / "src" / "web_listening" / "site_skill"
    forbidden_imports = {
        "http",
        "httpx",
        "os",
        "pathlib",
        "requests",
        "shutil",
        "socket",
        "sqlite3",
        "subprocess",
        "tempfile",
        "urllib.request",
        "web_listening.artifact.store",
        "web_listening.runtime",
        "web_listening.tool_registry.runners",
    }
    forbidden_calls = {"compile", "eval", "exec", "__import__"}

    for path in root.glob("*.py"):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module or "")
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert not any(
            module == blocked or module.startswith(f"{blocked}.")
            for module in imports
            for blocked in forbidden_imports
        )
        assert calls.isdisjoint(forbidden_calls)
