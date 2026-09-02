"""Issue #72 evidence projection over existing public production contracts."""

# pylint: disable=line-too-long,too-many-arguments,too-many-boolean-expressions
# pylint: disable=too-many-branches,too-many-instance-attributes,too-many-lines
# pylint: disable=too-many-statements

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from web_listening.artifact.site_state import (
    SiteState,
    SiteStatePage,
    site_state_from_mapping,
)
from web_listening.artifact.store import ArtifactStore
from web_listening.result.model import Result
from web_listening.result.site_refresh import SiteChange, SiteRefreshResult
from web_listening.site_skill.model import SiteSkill
from web_listening.site_skill.validate import (
    canonical_site_skill_bytes,
    site_skill_from_mapping,
)

BASELINE_README_REVISION = "2fed958ee67d3c7d714fde40a372bc8b7389bf87"
BASELINE_README_BLOB = "edcc24b4e09d69a316b28ed403f86107ef5dcb27"
BASELINE_README_SHA256 = (
    "8515ef08f2cb2c81a08db89ba307a37d6d12fcd921782ad567e47b529bcfcB44".lower()
)
BASELINE_README_LINE_COUNT = 731

_NORMATIVE_COLON_CLAIMS = frozenset(
    {
        "The product is organized around five business modules:",
        "Two small supporting layers are allowed:",
        "The common Request should expose only four important inputs:",
        "CLI, REST, and MCP should return the same logical Result:",
        (
            "If it does not implement the Web Listening protocol natively, a "
            "thin Adapter translates between the two systems:"
        ),
    }
)


@dataclass(frozen=True, slots=True)
class FrozenReadme:
    """Exact frozen README identity and decoded text."""

    revision: str
    blob: str
    sha256: str
    line_count: int
    text: str


@dataclass(frozen=True, slots=True)
class ReadmeClause:
    """One deterministic clause reconstructed from the frozen README."""

    clause_id: str
    section: int
    clause_text: str


@dataclass(frozen=True, slots=True)
class EvidenceRow:
    """One README clause linked to reproducible evidence."""

    clause_id: str
    section: int
    clause_text: str
    test_nodeids: tuple[str, ...]
    command: str
    evidence_fields: tuple[str, ...]
    result: str
    na_reason: str | None = None


@dataclass(frozen=True, slots=True)
class _Evidence:
    test_nodeids: tuple[str, ...]
    evidence_fields: tuple[str, ...]

    @property
    def command(self) -> str:
        """Return the exact controlled-interpreter evidence command."""
        return "py -3.14 -m pytest -q " + " ".join(self.test_nodeids)


_SECTION_19_EVIDENCE = (
    _Evidence(
        (
            "tests/interfaces/test_cli.py::test_acquire_parses_request_and_emits_the_unified_job_and_result_contract",
            "tests/interfaces/test_rest.py::test_acquire_maps_a_strict_request_to_runtime_and_returns_exact_result_schema",
            "tests/interfaces/test_mcp.py::test_complete_client_stdio_server_boundary",
            "tests/interfaces/test_mcp.py::test_source_calls_only_public_runtime_and_site_skill_boundaries",
        ),
        ("normalized Request", "logical Result", "public Runtime calls"),
    ),
    _Evidence(
        (
            "tests/runtime/test_service.py::test_no_ai_fake_transport_completes_one_exact_acquisition",
        ),
        ("completed Result without model key",),
    ),
    _Evidence(
        ("tests/interfaces/test_mcp.py::test_complete_client_stdio_server_boundary",),
        ("real MCP client", "governed Result"),
    ),
    _Evidence(
        (
            "tests/parity/test_phase_20_new_system_delivery.py::test_valid_site_skill_uses_preferred_tool_without_rediscovery_or_alternate",
        ),
        (
            "Result.site_skill_used",
            "preferred Acquisition Attempt",
            "zero Discovery/alternate calls",
        ),
    ),
    _Evidence(
        (
            "tests/site_skill/test_repository.py::test_candidate_stays_inactive_until_explicit_activation",
        ),
        ("candidate event", "active value unchanged"),
    ),
    _Evidence(
        (
            "tests/runtime/test_explore_all_tools.py::test_explore_false_never_switches_after_retryable_failure",
        ),
        ("Attempt tool ids", "explore_all_tools=false"),
    ),
    _Evidence(
        (
            "tests/tool_registry/test_explore_all_tools_eligibility.py::test_selection_is_the_explicit_eligible_intersection_with_stable_reasons",
        ),
        ("full eligible intersection", "stable eligibility reasons"),
    ),
    _Evidence(
        (
            "tests/runtime/test_explore_all_tools.py::test_policy_security_and_budget_rejections_stop_without_switching",
        ),
        ("rejection code", "single-tool Attempt evidence"),
    ),
    _Evidence(
        (
            "tests/artifact/test_store.py::test_first_store_and_same_bytes_keep_one_blob_two_observations",
        ),
        ("Observation count",),
    ),
    _Evidence(
        (
            "tests/artifact/test_store.py::test_first_store_and_same_bytes_keep_one_blob_two_observations",
        ),
        ("one Blob", "two Observation ids"),
    ),
    _Evidence(
        (
            "tests/artifact/test_store.py::test_changed_bytes_add_blob_without_overwriting_history",
        ),
        ("two Blob digests", "prior Observation readable"),
    ),
    _Evidence(
        (
            "tests/result/test_result_manifest.py::test_failed_or_rejected_results_keep_evidence_without_snapshot",
        ),
        ("Attempt/Error evidence", "zero Artifact/Observation snapshot"),
    ),
    _Evidence(
        (
            "tests/runtime/test_transform_flow.py::test_transform_failure_preserves_original_and_never_falls_back",
        ),
        ("source Artifact", "Transform failure Attempt", "no Acquisition fallback"),
    ),
    _Evidence(
        (
            "tests/tool_registry/test_subprocess_runner.py::test_output_path_must_be_portable_regular_content_inside_attempt",
            "tests/runtime/test_transform_flow.py::test_success_stores_derived_markdown_lineage_and_tool_attempt",
        ),
        ("attempt-local output", "Runtime final Artifact commit"),
    ),
    _Evidence(
        (
            "tests/tool_registry/test_tool_lifecycle.py::test_failed_upgrade_keeps_old_active",
            "tests/tool_registry/test_tool_lifecycle.py::test_activation_commit_failure_preserves_old_pointer",
            "tests/tool_registry/test_tool_lifecycle.py::test_explicit_rollback_switches_to_qualified_old_version",
        ),
        ("side-by-side versions", "atomic active pointer", "rollback target"),
    ),
    _Evidence(
        (
            "tests/tool_registry/test_registry.py::test_registration_does_not_change_public_request_shape_or_source",
            "tests/interfaces/test_cli.py::test_acquire_parses_request_and_emits_the_unified_job_and_result_contract",
            "tests/interfaces/test_rest.py::test_acquire_maps_a_strict_request_to_runtime_and_returns_exact_result_schema",
            "tests/interfaces/test_mcp.py::test_complete_client_stdio_server_boundary",
        ),
        (
            "registration before/after Request shape",
            "CLI Request contract",
            "REST Request contract",
            "MCP Request contract",
        ),
    ),
)


def _clause_ids(section: int, *fingerprints: str) -> frozenset[str]:
    return frozenset(f"README-{section:02d}-{value}" for value in fingerprints)


_CLAUSE_EVIDENCE_GROUPS = (
    (
        _clause_ids(1, "4585e85c", "789f8d01"),
        _Evidence(
            (
                "tests/request/test_request_validation.py::test_minimal_request_fixture_is_accepted",
            ),
            ("Request.scope seeds/origins/paths/content_types",),
        ),
    ),
    (
        _clause_ids(1, "e9a900d3"),
        _Evidence(
            (
                "tests/request/test_request_validation.py::test_optional_request_values_use_readme_defaults",
            ),
            ("Request.site_skill",),
        ),
    ),
    (
        _clause_ids(1, "7cedde92"),
        _Evidence(
            (
                "tests/runtime/test_explore_all_tools.py::test_explore_false_never_switches_after_retryable_failure",
            ),
            ("Request.explore_all_tools", "Attempt.tool_id"),
        ),
    ),
    (
        _clause_ids(1, "4bb95fc7"),
        _Evidence(
            (
                "tests/request/test_access_policy.py::test_policy_decisions_allow_only_requested_access",
            ),
            ("Request.budgets", "AccessDecision"),
        ),
    ),
    (
        _clause_ids(1, "1c5c2847"),
        _Evidence(
            (
                "tests/runtime/test_discovery_flow.py::test_discovery_is_pure_then_candidates_reauthorize_before_acquisition",
            ),
            ("DiscoveryOutput.candidates/discovered_from", "AccessDecision"),
        ),
    ),
    (
        _clause_ids(1, "35aef3dd"),
        _Evidence(
            (
                "tests/tool_registry/test_explore_all_tools_eligibility.py::test_selection_is_the_explicit_eligible_intersection_with_stable_reasons",
            ),
            ("EligibilityDecision.eligible/reasons",),
        ),
    ),
    (
        _clause_ids(1, "ddc80093"),
        _Evidence(
            (
                "tests/runtime/test_service.py::test_no_ai_fake_transport_completes_one_exact_acquisition",
                "tests/parity/test_phase_20_new_system_delivery.py::test_first_state_projects_only_real_results_and_strictly_persists",
            ),
            ("source HTML Artifact/Observation", "source PDF Artifact/Observation"),
        ),
    ),
    (
        _clause_ids(1, "ea5e06b9"),
        _Evidence(
            (
                "tests/runtime/test_transform_flow.py::test_success_stores_derived_markdown_lineage_and_tool_attempt",
            ),
            ("derived text/markdown Artifact", "Transform Attempt", "lineage"),
        ),
    ),
    (
        _clause_ids(1, "5b83e7e0"),
        _Evidence(
            (
                "tests/artifact/test_store.py::test_first_store_and_same_bytes_keep_one_blob_two_observations",
            ),
            ("Observation IDs", "Blob digest"),
        ),
    ),
    (
        _clause_ids(1, "2143b7e2"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_manifest_builds_only_from_public_artifact_facts",
            ),
            ("Manifest canonical fields",),
        ),
    ),
    (
        _clause_ids(1, "9958b4a3"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_partial_fixture_retains_explicit_attempt_order_and_all_evidence",
            ),
            ("Result.attempts/errors",),
        ),
    ),
    (
        _clause_ids(1, "c6de414b"),
        _Evidence(
            (
                "tests/site_skill/test_repository.py::test_candidate_stays_inactive_until_explicit_activation",
            ),
            ("candidate event", "active SiteSkill unchanged"),
        ),
    ),
    (
        _clause_ids(2, "7266bc92", "c56fa1ee"),
        _Evidence(
            (
                "tests/test_package_smoke.py::test_readme_module_boundaries_are_importable",
            ),
            ("five business module packages", "Runtime/Interfaces support packages"),
        ),
    ),
    (
        _clause_ids(2, "da2f79ce"),
        _Evidence(
            (
                "tests/request/test_access_policy.py::test_policy_decisions_allow_only_requested_access",
            ),
            ("Request scope/content/budget decisions",),
        ),
    ),
    (
        _clause_ids(2, "0daab921"),
        _Evidence(
            (
                "tests/tool_registry/test_registry.py::test_registration_does_not_change_public_request_shape_or_source",
            ),
            ("Request fields/source before and after tool registration",),
        ),
    ),
    (
        _clause_ids(2, "864d4fc0"),
        _Evidence(
            (
                "tests/site_skill/test_validation.py::test_optional_discovery_recipe_round_trips_and_participates_in_digest",
            ),
            ("SiteSkill structured recipe/digest",),
        ),
    ),
    (
        _clause_ids(2, "e0bbe0f8"),
        _Evidence(
            (
                "tests/site_skill/test_resolve.py::test_resolution_rejects_scope_or_budget_expansion",
                "tests/site_skill/test_validation.py::test_production_modules_have_no_io_or_dynamic_execution_authority",
            ),
            (
                "SiteSkill scope/budget intersection",
                "zero network/dynamic execution authority",
            ),
        ),
    ),
    (
        _clause_ids(2, "d336a732"),
        _Evidence(
            (
                "tests/tool_registry/test_registry.py::test_invoke_accepts_conforming_fake_and_rejects_wrong_input",
                "tests/tool_registry/test_registry.py::test_eligibility_returns_compatible_tools_without_ranking",
            ),
            ("Registry invoke result", "eligible tool metadata"),
        ),
    ),
    (
        _clause_ids(2, "786ad1e9"),
        _Evidence(
            (
                "tests/tool_registry/test_registry.py::test_registry_modules_have_no_forbidden_authority_or_discovery_hooks",
            ),
            ("Registry import/authority boundary",),
        ),
    ),
    (
        _clause_ids(2, "6f9c32df"),
        _Evidence(
            (
                "tests/artifact/test_store.py::test_artifact_and_lineage_identity_are_deterministic",
            ),
            ("Blob/Artifact/Observation/Lineage identities",),
        ),
    ),
    (
        _clause_ids(2, "aa3cdf0d"),
        _Evidence(
            (
                "tests/artifact/test_store.py::test_artifact_modules_have_zero_network_or_tool_authority",
            ),
            ("Artifact module authority imports",),
        ),
    ),
    (
        _clause_ids(2, "9ad6c8de"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_versioned_fixtures_round_trip_to_byte_stable_canonical_json",
            ),
            ("Result status/artifacts/manifest/attempts/errors/usage",),
        ),
    ),
    (
        _clause_ids(2, "2d0f0e1c"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_result_modules_have_zero_execution_or_network_authority",
            ),
            ("Result module authority imports",),
        ),
    ),
    (
        _clause_ids(2, "fc37e46f", "c1e6ca19"),
        _Evidence(
            (
                "tests/runtime/test_service.py::test_runtime_source_is_one_ordered_orchestrator_without_new_authority",
            ),
            ("Runtime ordered delegation", "Runtime authority scan"),
        ),
    ),
    (
        _clause_ids(2, "9980425e"),
        _Evidence(
            (
                "tests/interfaces/test_cli.py::test_acquire_parses_request_and_emits_the_unified_job_and_result_contract",
                "tests/interfaces/test_rest.py::test_acquire_maps_a_strict_request_to_runtime_and_returns_exact_result_schema",
                "tests/interfaces/test_mcp.py::test_complete_client_stdio_server_boundary",
            ),
            ("same Request fields", "same Result schema", "public Runtime calls"),
        ),
    ),
    (
        _clause_ids(2, "83376a3b"),
        _Evidence(
            (
                "tests/interfaces/test_cli.py::test_cli_source_has_no_low_level_business_imports",
                "tests/interfaces/test_rest.py::test_rest_source_has_only_interface_dto_and_public_runtime_authority",
                "tests/interfaces/test_mcp.py::test_source_calls_only_public_runtime_and_site_skill_boundaries",
            ),
            ("Interface import/call boundaries",),
        ),
    ),
    (
        _clause_ids(4, "17cda50a", "0f280fe4", "1bbd3482", "be0d8b99"),
        _Evidence(
            (
                "tests/site_skill/test_validation.py::test_canonical_bytes_and_digest_are_stable",
            ),
            ("SiteSkill tool/version/verified_at/digest",),
        ),
    ),
    (
        _clause_ids(4, "7199ae9b", "6972dd19", "7bc242b3"),
        _Evidence(
            (
                "tests/site_skill/test_validation.py::test_production_modules_have_no_io_or_dynamic_execution_authority",
            ),
            ("SiteSkill data-only authority scan",),
        ),
    ),
    (
        _clause_ids(4, "43fc46c5"),
        _Evidence(
            (
                "tests/site_skill/test_validation.py::test_optional_discovery_recipe_round_trips_and_participates_in_digest",
            ),
            ("DiscoveryRecipe source/tool",),
        ),
    ),
    (
        _clause_ids(4, "7c5b00e3"),
        _Evidence(
            (
                "tests/site_skill/test_validation.py::test_recipe_identifier_is_inert_canonical_data_and_strictly_validated",
            ),
            ("ToolReference.recipe_id inert data",),
        ),
    ),
    (
        _clause_ids(4, "a6c63734"),
        _Evidence(
            (
                "tests/site_skill/test_validation.py::test_forged_direct_success_checks_are_rejected_not_normalized",
            ),
            ("SuccessChecks allowed MIME/minimum words",),
        ),
    ),
    (
        _clause_ids(4, "ed34249f"),
        _Evidence(
            (
                "tests/site_skill/test_validation.py::test_version_requires_explicit_previous_digest",
            ),
            ("SiteSkill version/previous_digest",),
        ),
    ),
    (
        _clause_ids(4, "23747313"),
        _Evidence(
            (
                "tests/site_skill/test_validation.py::test_secret_value_in_nested_data_is_rejected_without_echo",
            ),
            ("SiteSkill secret rejection code",),
        ),
    ),
    (
        _clause_ids(4, "7aba5fda"),
        _Evidence(
            (
                "tests/site_skill/test_resolve.py::test_resolution_rejects_scope_or_budget_expansion",
            ),
            ("effective Scope/Budgets",),
        ),
    ),
    (
        _clause_ids(4, "1f99b799"),
        _Evidence(
            (
                "tests/site_skill/test_repository.py::test_candidate_stays_inactive_until_explicit_activation",
            ),
            ("candidate event", "active value"),
        ),
    ),
    (
        _clause_ids(5, "294f18ae"),
        _Evidence(
            (
                "tests/request/test_request_validation.py::test_minimal_request_fixture_is_accepted",
            ),
            ("Request four-field dataclass shape",),
        ),
    ),
    (
        _clause_ids(5, "aaf947e4", "8329c057"),
        _Evidence(
            (
                "tests/request/test_request_validation.py::test_minimal_request_fixture_is_accepted",
            ),
            ("Request.scope/budgets",),
        ),
    ),
    (
        _clause_ids(5, "f58970ae", "b15279b5"),
        _Evidence(
            (
                "tests/request/test_request_validation.py::test_optional_request_values_use_readme_defaults",
            ),
            ("Request.site_skill/explore_all_tools defaults",),
        ),
    ),
    (
        _clause_ids(5, "70e571e1"),
        _Evidence(
            (
                "tests/parity/test_phase_20_new_system_delivery.py::test_public_request_rejects_fenced_forbidden_authority_fields",
            ),
            ("authorized_tool_ids request.unknown_field",),
        ),
    ),
    (
        _clause_ids(5, "2d459ea9"),
        _Evidence(
            (
                "tests/parity/test_phase_20_new_system_delivery.py::test_public_request_rejects_fenced_forbidden_authority_fields",
            ),
            ("authorization_reference request.unknown_field",),
        ),
    ),
    (
        _clause_ids(5, "1b2f60c3"),
        _Evidence(
            (
                "tests/tool_registry/test_explore_all_tools_eligibility.py::test_selection_is_the_explicit_eligible_intersection_with_stable_reasons",
            ),
            ("EligibilityDecision.checks eligibility.registered",),
        ),
    ),
    (
        _clause_ids(5, "69da4e92"),
        _Evidence(
            (
                "tests/tool_registry/test_explore_all_tools_eligibility.py::test_selection_is_the_explicit_eligible_intersection_with_stable_reasons",
            ),
            ("EligibilityDecision.checks eligibility.installed",),
        ),
    ),
    (
        _clause_ids(5, "4f190fc8"),
        _Evidence(
            (
                "tests/tool_registry/test_explore_all_tools_eligibility.py::test_selection_is_the_explicit_eligible_intersection_with_stable_reasons",
            ),
            ("EligibilityDecision.checks eligibility.qualified",),
        ),
    ),
    (
        _clause_ids(5, "6f64a13e"),
        _Evidence(
            (
                "tests/tool_registry/test_explore_all_tools_eligibility.py::test_selection_is_the_explicit_eligible_intersection_with_stable_reasons",
            ),
            ("EligibilityDecision.checks eligibility.healthy",),
        ),
    ),
    (
        _clause_ids(5, "a92f7549"),
        _Evidence(
            (
                "tests/tool_registry/test_explore_all_tools_eligibility.py::test_selection_is_the_explicit_eligible_intersection_with_stable_reasons",
            ),
            ("EligibilityDecision.checks eligibility.capability_compatible",),
        ),
    ),
    (
        _clause_ids(5, "0c1899b0"),
        _Evidence(
            (
                "tests/tool_registry/test_explore_all_tools_eligibility.py::test_selection_is_the_explicit_eligible_intersection_with_stable_reasons",
            ),
            ("EligibilityDecision.checks eligibility.policy_compliant",),
        ),
    ),
    (
        _clause_ids(5, "f4b8b80f"),
        _Evidence(
            (
                "tests/tool_registry/test_explore_all_tools_eligibility.py::test_selection_is_the_explicit_eligible_intersection_with_stable_reasons",
            ),
            ("EligibilityDecision.checks eligibility.within_budget",),
        ),
    ),
    (
        _clause_ids(6, "6519f1aa"),
        _Evidence(
            (
                "tests/interfaces/test_cli.py::test_acquire_parses_request_and_emits_the_unified_job_and_result_contract",
                "tests/interfaces/test_rest.py::test_acquire_maps_a_strict_request_to_runtime_and_returns_exact_result_schema",
                "tests/interfaces/test_mcp.py::test_complete_client_stdio_server_boundary",
            ),
            ("CLI/REST/MCP Result.from_dict", "same logical Result fields"),
        ),
    ),
    (
        _clause_ids(6, "a75f8fed"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_result_status_has_exactly_the_four_versioned_values",
            ),
            ("ResultStatus values",),
        ),
    ),
    (
        _clause_ids(6, "e29fd38f"),
        _Evidence(
            (
                "tests/runtime/test_service.py::test_no_ai_fake_transport_completes_one_exact_acquisition",
                "tests/runtime/test_transform_flow.py::test_success_stores_derived_markdown_lineage_and_tool_attempt",
            ),
            ("source Artifact", "derived Markdown Artifact"),
        ),
    ),
    (
        _clause_ids(
            6, "5acfc963", "bf2fcde1", "6141e241", "c8e2887e", "f71d5414", "406c725d"
        ),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_manifest_builds_only_from_public_artifact_facts",
            ),
            ("Manifest URL/time/run/HTTP/MIME/size/SHA/tool/SiteSkill fields",),
        ),
    ),
    (
        _clause_ids(6, "b2ce64d9", "d944d77f"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_versioned_fixtures_round_trip_to_byte_stable_canonical_json",
            ),
            ("Result.site_skill_used/site_skill_update",),
        ),
    ),
    (
        _clause_ids(6, "d2c528c4", "abdbf09e"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_partial_fixture_retains_explicit_attempt_order_and_all_evidence",
            ),
            ("Attempt order/outcome/error",),
        ),
    ),
    (
        _clause_ids(6, "428b3739"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_safe_error_details_are_sorted_and_frozen",
            ),
            ("SafeError code/message/details",),
        ),
    ),
    (
        _clause_ids(6, "2e5887c8", "1071c68a"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_usage_is_nonnegative_and_consistent_with_attempt_facts",
            ),
            ("Usage requests/bytes/runtime/tool_attempts",),
        ),
    ),
    (
        _clause_ids(6, "0b38aeaa"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_success_redirect_chain_rejects_unrelated_or_rejected_transition",
            ),
            ("RedirectEvidence ordered chain",),
        ),
    ),
    (
        _clause_ids(6, "20dc9c76"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_derived_lineage_must_reference_a_source_role_pair",
            ),
            ("derived/source Artifact lineage",),
        ),
    ),
    (
        _clause_ids(6, "a07490b8"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_secret_like_keys_values_and_absolute_paths_are_rejected",
            ),
            ("safe Manifest/Result rejection",),
        ),
    ),
    (
        _clause_ids(7, "ed97a94c", "c7bf3fb4", "3d35a539", "56ddbf74"),
        _Evidence(
            (
                "tests/artifact/test_store.py::test_first_store_and_same_bytes_keep_one_blob_two_observations",
            ),
            ("one Blob", "two immutable Observation IDs"),
        ),
    ),
    (
        _clause_ids(7, "4d0fb8c3"),
        _Evidence(
            (
                "tests/artifact/test_store.py::test_changed_bytes_add_blob_without_overwriting_history",
            ),
            ("new Blob digest", "prior Observation readable"),
        ),
    ),
    (
        _clause_ids(
            7,
            "fa5132c0",
            "1bbec7b1",
            "22e6d8b6",
            "4b337c01",
            "0ad9f31f",
            "ecc864cc",
            "e71cd332",
            "3321d548",
        ),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_manifest_builds_only_from_public_artifact_facts",
            ),
            (
                "Manifest run/URL/time/HTTP/Artifact/SHA/MIME/size/tool/SiteSkill evidence",
            ),
        ),
    ),
    (
        _clause_ids(7, "ab2b9d48"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_success_redirect_chain_rejects_unrelated_or_rejected_transition",
                "tests/request/test_access_policy.py::test_policy_decisions_allow_only_requested_access",
            ),
            ("RedirectEvidence", "AccessDecision"),
        ),
    ),
    (
        _clause_ids(7, "8beb7288"),
        _Evidence(
            (
                "tests/artifact/test_store.py::test_artifact_and_lineage_identity_are_deterministic",
            ),
            ("source/derived Lineage identity",),
        ),
    ),
    (
        _clause_ids(7, "24bbe63a"),
        _Evidence(
            (
                "tests/tool_registry/test_access_gateway.py::test_robots_denial_precedes_target_content_and_has_no_store_authority",
            ),
            ("robots rejection", "zero target/store access"),
        ),
    ),
    (
        _clause_ids(7, "d8d68a5f"),
        _Evidence(
            (
                "tests/runtime/test_site_explore.py::test_out_of_scope_candidate_is_rejected_before_target_read_or_observation",
            ),
            ("out-of-scope candidate rejection", "zero Observation"),
        ),
    ),
    (
        _clause_ids(7, "00a2076a"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_failed_or_rejected_results_keep_evidence_without_snapshot",
            ),
            ("failed Attempt/Error", "zero Artifact snapshot"),
        ),
    ),
    (
        _clause_ids(7, "5ce9a1e4"),
        _Evidence(
            (
                "tests/tool_registry/test_tool_lifecycle.py::test_broken_health_and_failed_contract_remain_inspectable",
            ),
            ("broken/unqualified tool state",),
        ),
    ),
    (
        _clause_ids(7, "24cb9544"),
        _Evidence(
            (
                "tests/runtime/test_discovery_flow.py::test_discovery_is_pure_then_candidates_reauthorize_before_acquisition",
            ),
            ("DiscoveryOutput without Artifact mutation",),
        ),
    ),
    (
        _clause_ids(7, "66919b72"),
        _Evidence(
            (
                "tests/integration/test_cloakbrowser_adapter.py::test_budget_excess_plain_subresources_are_aborted_but_document_succeeds",
            ),
            ("subresource abort evidence", "document target success"),
        ),
    ),
    (
        _clause_ids(8, "c769bfa2", "009f4059", "1403cfc8"),
        _Evidence(
            (
                "tests/tool_registry/test_protocols.py::test_protocol_inputs_and_outputs_are_immutable_and_category_specific",
            ),
            ("Discovery/Acquisition/Transform input/output types",),
        ),
    ),
    (
        _clause_ids(8, "e13cc4a4", "e3fec118"),
        _Evidence(
            (
                "tests/tool_registry/test_registry.py::test_register_and_query_preserve_order_and_independent_distribution",
                "tests/tool_registry/test_subprocess_runner.py::test_versioned_round_trip_rebuilds_all_three_protocol_results",
            ),
            ("Discovery distribution", "external Discovery protocol result"),
        ),
    ),
    (
        _clause_ids(8, "39af78dd"),
        _Evidence(
            (
                "tests/runtime/test_service.py::test_no_ai_fake_transport_completes_one_exact_acquisition",
            ),
            ("built-in Acquisition result",),
        ),
    ),
    (
        _clause_ids(8, "a1cef502"),
        _Evidence(
            (
                "tests/integration/test_cloakbrowser_adapter.py::test_bound_runtime_preflights_closes_qualifies_and_runs_protocol",
            ),
            ("installed CloakBrowser qualification/invocation",),
        ),
    ),
    (
        _clause_ids(8, "72d590a2"),
        _Evidence(
            (
                "tests/tool_registry/test_simple_html_markdown.py::test_manifest_is_one_small_qualified_builtin_transform",
            ),
            ("built-in Transform manifest/distribution",),
        ),
    ),
    (
        _clause_ids(8, "f80249e3"),
        _Evidence(
            (
                "tests/integration/test_external_transform.py::test_lifecycle_qualifies_activates_and_registers_external_transform",
            ),
            ("installed Transform qualification/activation",),
        ),
    ),
    (
        _clause_ids(8, "4274b356"),
        _Evidence(
            (
                "tests/tool_registry/test_registry.py::test_register_and_query_preserve_order_and_independent_distribution",
            ),
            ("ToolCategory", "ToolDistribution"),
        ),
    ),
    (
        _clause_ids(9, "24bbe63a", "9d7f8ae8", "d65590e8", "2c7dd596", "6d114d00"),
        _Evidence(
            (
                "tests/runtime/test_explore_all_tools.py::test_policy_security_and_budget_rejections_stop_without_switching",
            ),
            ("terminal rejection code", "single-tool Attempt evidence"),
        ),
    ),
    (
        _clause_ids(9, "72d8dbf7"),
        _Evidence(
            (
                "tests/runtime/test_explore_all_tools.py::test_unqualified_tool_is_skipped_and_rank_does_not_use_registration_order",
            ),
            ("EligibilityDecision", "ranked eligible Attempt"),
        ),
    ),
    (
        _clause_ids(10, "9b5397bf"),
        _Evidence(
            (
                "tests/tool_registry/test_subprocess_runner.py::test_versioned_round_trip_rebuilds_all_three_protocol_results",
            ),
            ("external wire result translated to typed tool protocol result",),
        ),
    ),
    (
        _clause_ids(10, "c6898a48"),
        _Evidence(
            (
                "tests/tool_registry/test_subprocess_runner.py::test_fake_fixture_is_versioned_and_has_no_network_code",
            ),
            ("external fixture/process boundary",),
        ),
    ),
    (
        _clause_ids(10, "7fde1158", "93237f53", "b1366fc2", "d6cf7c43"),
        _Evidence(
            (
                "tests/tool_registry/test_subprocess_runner.py::test_request_envelope_is_versioned_and_carries_only_attempt_input",
            ),
            ("attempt target/scope/limits/directory envelope",),
        ),
    ),
    (
        _clause_ids(10, "c85c696d"),
        _Evidence(
            (
                "tests/integration/test_cloakbrowser_adapter.py::test_missing_authorization_or_network_boundary_rejects_before_adapter",
            ),
            ("controlled network boundary/authorization",),
        ),
    ),
    (
        _clause_ids(10, "025191e7"),
        _Evidence(
            (
                "tests/tool_registry/test_subprocess_runner.py::test_versioned_round_trip_rebuilds_all_three_protocol_results",
                "tests/tool_registry/test_subprocess_runner.py::test_external_safe_failure_reuses_category_protocol",
                "tests/tool_registry/test_subprocess_runner.py::test_external_rejection_reuses_category_failure_and_safe_code",
            ),
            ("external success", "external failed", "external rejected"),
        ),
    ),
    (
        _clause_ids(10, "42469e95"),
        _Evidence(
            (
                "tests/parity/test_phase_20_new_system_delivery.py::test_external_success_preserves_acquisition_contract_fields",
            ),
            ("AcquisitionOutput.requested_url/final_url",),
        ),
    ),
    (
        _clause_ids(10, "4b337c01"),
        _Evidence(
            (
                "tests/parity/test_phase_20_new_system_delivery.py::test_external_success_preserves_acquisition_contract_fields",
            ),
            ("AcquisitionOutput.status_code",),
        ),
    ),
    (
        _clause_ids(10, "06db4986"),
        _Evidence(
            (
                "tests/parity/test_phase_20_new_system_delivery.py::test_external_success_preserves_acquisition_contract_fields",
            ),
            ("AcquisitionOutput.mime_type",),
        ),
    ),
    (
        _clause_ids(10, "181f83da"),
        _Evidence(
            (
                "tests/parity/test_phase_20_new_system_delivery.py::test_external_success_preserves_acquisition_contract_fields",
            ),
            ("AcquisitionOutput.redirects",),
        ),
    ),
    (
        _clause_ids(10, "f7560b6f"),
        _Evidence(
            (
                "tests/parity/test_phase_20_new_system_delivery.py::test_external_success_preserves_acquisition_contract_fields",
            ),
            ("AcquisitionOutput.tool_id/tool_version/runtime_ms",),
        ),
    ),
    (
        _clause_ids(10, "9650f26a"),
        _Evidence(
            (
                "tests/tool_registry/test_subprocess_runner.py::test_external_safe_failure_reuses_category_protocol",
                "tests/tool_registry/test_subprocess_runner.py::test_external_rejection_reuses_category_failure_and_safe_code",
            ),
            ("external.unavailable", "external.unsupported"),
        ),
    ),
    (
        _clause_ids(10, "668e9aaa"),
        _Evidence(
            (
                "tests/tool_registry/test_subprocess_runner.py::test_output_path_must_be_portable_regular_content_inside_attempt",
            ),
            ("attempt-local relative output path",),
        ),
    ),
    (
        _clause_ids(10, "5a48d8af"),
        _Evidence(
            (
                "tests/tool_registry/test_subprocess_runner.py::test_parent_rejects_untrusted_content_and_identity_claims",
            ),
            ("parent URL/path/MIME/size/SHA checks",),
        ),
    ),
    (
        _clause_ids(10, "45601e4c"),
        _Evidence(
            (
                "tests/tool_registry/test_subprocess_runner.py::test_runner_does_not_import_final_storage_or_orchestration_authority",
            ),
            ("runner import/authority boundary",),
        ),
    ),
    (
        _clause_ids(11, "c3a8b234"),
        _Evidence(
            (
                "tests/tool_registry/test_protocols.py::test_protocols_are_runtime_checkable_and_category_distinct",
            ),
            ("Acquisition ToolCategory",),
        ),
    ),
    (
        _clause_ids(11, "424b58a8"),
        _Evidence(
            (
                "tests/parity/test_phase_20_new_system_delivery.py::test_default_runtime_composition_disables_browser_target_reads",
            ),
            (
                "RuntimeService.open Acquisition pool",
                "web_http-only target-read/explore_all_tools pool",
                "browser tool IDs absent",
            ),
        ),
    ),
    (
        _clause_ids(11, "471771dd", "faee17af"),
        _Evidence(
            (
                "tests/integration/test_cloakbrowser_adapter.py::test_missing_authorization_or_network_boundary_rejects_before_adapter",
            ),
            (
                "target-read rejection before adapter",
                "network boundary",
                "authorization",
            ),
        ),
    ),
    (
        _clause_ids(11, "e4ce2baf", "e782c76a"),
        _Evidence(
            (
                "tests/integration/test_cloakbrowser_adapter.py::test_version_manifest_and_describe_are_dependency_lazy",
            ),
            ("Adapter/tool pinned version/manifest",),
        ),
    ),
    (
        _clause_ids(11, "d744950e"),
        _Evidence(
            (
                "tests/integration/test_cloakbrowser_adapter.py::test_control_phase_runs_from_explicit_tool_directory",
            ),
            ("isolated tool runtime directory",),
        ),
    ),
    (
        _clause_ids(11, "af187905"),
        _Evidence(
            (
                "tests/integration/test_cloakbrowser_adapter.py::test_generic_lifecycle_and_authorization_only_cannot_qualify",
            ),
            ("health/protocol/network qualification",),
        ),
    ),
    (
        _clause_ids(11, "bf14b2af"),
        _Evidence(
            (
                "tests/integration/test_cloakbrowser_adapter.py::test_parent_rechecks_external_url_path_mime_size_and_hash",
                "tests/integration/test_cloakbrowser_adapter.py::test_adapter_enforces_timeout_and_output_bound",
            ),
            ("scope/redirect/MIME/size/SHA checks", "timeout/output bound"),
        ),
    ),
    (
        _clause_ids(11, "c9c45856"),
        _Evidence(
            (
                "tests/integration/test_cloakbrowser_adapter.py::test_disable_and_rollback_remain_effective",
            ),
            ("disabled/rollback active version",),
        ),
    ),
    (
        _clause_ids(11, "af2da2f5"),
        _Evidence(
            (
                "tests/integration/test_cloakbrowser_adapter.py::test_free_form_network_isolation_claim_is_not_a_boundary",
            ),
            ("unqualified automatic-pool exclusion",),
        ),
    ),
    (
        _clause_ids(12, "377cad72"),
        _Evidence(
            (
                "tests/tool_registry/test_protocols.py::test_protocols_are_runtime_checkable_and_category_distinct",
            ),
            ("Acquisition/Transform category distinction",),
        ),
    ),
    (
        _clause_ids(12, "dbb3ab84"),
        _Evidence(
            (
                "tests/tool_registry/test_simple_html_markdown.py::test_manifest_is_one_small_qualified_builtin_transform",
            ),
            ("SIMPLE_HTML_MARKDOWN_MANIFEST.tool_id",),
        ),
    ),
    (
        _clause_ids(12, "090bbf80"),
        _Evidence(
            (
                "tests/tool_registry/test_simple_html_markdown.py::test_non_html_low_quality_and_complex_inputs_are_explicitly_skipped",
            ),
            ("non-HTML Transform skipped result",),
        ),
    ),
    (
        _clause_ids(12, "d6fb13fb"),
        _Evidence(
            (
                "tests/tool_registry/test_simple_html_markdown.py::test_non_html_low_quality_and_complex_inputs_are_explicitly_skipped",
            ),
            ("low-quality/complex HTML skipped result",),
        ),
    ),
    (
        _clause_ids(12, "884cf8e2"),
        _Evidence(
            (
                "tests/runtime/test_transform_flow.py::test_success_stores_derived_markdown_lineage_and_tool_attempt",
            ),
            ("eligible HTML", "derived Markdown", "Transform Attempt"),
        ),
    ),
    (
        _clause_ids(12, "df852507"),
        _Evidence(
            (
                "tests/runtime/test_transform_flow.py::test_success_stores_derived_markdown_lineage_and_tool_attempt",
            ),
            ("derived Markdown/source/tool lineage",),
        ),
    ),
    (
        _clause_ids(12, "d394f76a", "91f51fea"),
        _Evidence(
            (
                "tests/runtime/test_transform_flow.py::test_transform_failure_preserves_original_and_never_falls_back",
            ),
            (
                "source Artifact retained",
                "Transform failure Attempt",
                "no Acquisition fallback",
            ),
        ),
    ),
    (
        _clause_ids(12, "6d5dd9dd"),
        _Evidence(
            (
                "tests/tool_registry/test_simple_html_markdown.py::test_transform_has_no_network_capability",
                "tests/integration/test_external_transform.py::test_lifecycle_qualifies_activates_and_registers_external_transform",
            ),
            ("Transform zero network capability", "installed Transform lifecycle"),
        ),
    ),
    (
        _clause_ids(13, "e1bfd759"),
        _Evidence(
            (
                "tests/tool_registry/test_registry.py::test_registration_does_not_change_public_request_shape_or_source",
                "tests/tool_registry/test_tool_lifecycle.py::test_qualification_and_activation_are_distinct_and_restart_safe",
            ),
            ("public Request source/fields", "external tool lifecycle state"),
        ),
    ),
    (
        _clause_ids(14, "e86ca830"),
        _Evidence(
            (
                "tests/interfaces/test_cli.py::test_acquire_parses_request_and_emits_the_unified_job_and_result_contract",
                "tests/interfaces/test_rest.py::test_acquire_maps_a_strict_request_to_runtime_and_returns_exact_result_schema",
                "tests/interfaces/test_mcp.py::test_source_calls_only_public_runtime_and_site_skill_boundaries",
            ),
            ("thin CLI/REST/MCP Runtime delegation",),
        ),
    ),
    (
        _clause_ids(14, "c50b2756"),
        _Evidence(
            (
                "tests/interfaces/test_mcp.py::test_source_calls_only_public_runtime_and_site_skill_boundaries",
            ),
            ("MCP public Runtime/SiteSkill calls", "no low-level tool calls"),
        ),
    ),
    (
        _clause_ids(15, "f723bce6"),
        _Evidence(
            (
                "tests/tool_registry/test_tool_lifecycle.py::test_fixture_and_lifecycle_have_no_network_or_cross_module_authority",
            ),
            ("external data-root fixture", "core-module import boundary"),
        ),
    ),
    (
        _clause_ids(16, "638abae3"),
        _Evidence(
            (
                "tests/tool_registry/test_registry.py::test_registration_does_not_change_public_request_shape_or_source",
            ),
            ("Request source/fields independent of registered tool IDs",),
        ),
    ),
    (
        _clause_ids(16, "8b8be630"),
        _Evidence(
            (
                "tests/site_skill/test_validation.py::test_production_modules_have_no_io_or_dynamic_execution_authority",
            ),
            ("structured SiteSkill", "zero dynamic execution"),
        ),
    ),
    (
        _clause_ids(16, "0a13b31d"),
        _Evidence(
            (
                "tests/tool_registry/test_registry.py::test_registry_modules_have_no_forbidden_authority_or_discovery_hooks",
            ),
            ("Registry result/authority boundary",),
        ),
    ),
    (
        _clause_ids(16, "44536348"),
        _Evidence(
            (
                "tests/artifact/test_store.py::test_artifact_modules_have_zero_network_or_tool_authority",
            ),
            ("Artifact module authority scan",),
        ),
    ),
    (
        _clause_ids(16, "8268cac8"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_result_modules_have_zero_execution_or_network_authority",
            ),
            ("Result module authority scan",),
        ),
    ),
    (
        _clause_ids(16, "0474bb23"),
        _Evidence(
            (
                "tests/runtime/test_service.py::test_runtime_source_is_one_ordered_orchestrator_without_new_authority",
            ),
            ("Runtime delegation/authority scan",),
        ),
    ),
    (
        _clause_ids(16, "27fc35f9"),
        _Evidence(
            (
                "tests/interfaces/test_cli.py::test_cli_source_has_no_low_level_business_imports",
                "tests/interfaces/test_rest.py::test_rest_source_has_only_interface_dto_and_public_runtime_authority",
                "tests/interfaces/test_mcp.py::test_source_calls_only_public_runtime_and_site_skill_boundaries",
            ),
            ("Interface low-level import/call scan",),
        ),
    ),
    (
        _clause_ids(16, "f3e09792"),
        _Evidence(
            (
                "tests/tool_registry/test_protocols.py::test_protocols_are_runtime_checkable_and_category_distinct",
            ),
            ("distinct category Protocol/failure types",),
        ),
    ),
    (
        _clause_ids(16, "565b7ae1"),
        _Evidence(
            (
                "tests/tool_registry/test_tool_lifecycle.py::test_fixture_and_lifecycle_have_no_network_or_cross_module_authority",
            ),
            ("isolated external runtime/core boundary",),
        ),
    ),
    (
        _clause_ids(16, "bccf5ccd"),
        _Evidence(
            (
                "tests/runtime/test_service.py::test_no_ai_fake_transport_completes_one_exact_acquisition",
            ),
            ("completed Result without AI/model key",),
        ),
    ),
    (
        _clause_ids(16, "7d75e8d9"),
        _Evidence(
            (
                "tests/runtime/test_agent_assisted_exploration.py::test_run_single_target_signature_and_no_explorer_path_are_unchanged",
            ),
            ("optional explorer path", "unchanged standard signature"),
        ),
    ),
    (
        _clause_ids(16, "1bdb6f7d", "9bea8617"),
        _Evidence(
            (
                "tests/artifact/test_store.py::test_first_store_and_same_bytes_keep_one_blob_two_observations",
            ),
            ("new Observation per visit", "Blob deduplication"),
        ),
    ),
    (
        _clause_ids(17, "9235611c", "aa625d80"),
        _Evidence(
            (
                "tests/test_package_smoke.py::test_readme_module_boundaries_are_importable",
            ),
            ("new package/module contract boundaries",),
        ),
    ),
    (
        _clause_ids(17, "97f0e853", "0413088f"),
        _Evidence(
            (
                "tests/request/test_access_policy.py::test_policy_decisions_allow_only_requested_access",
                "tests/tool_registry/test_access_gateway.py::test_redirect_hop_rechecks_scope_robots_dns_peer_and_budget",
            ),
            ("governed access decision", "robots/scope/redirect/budget hop checks"),
        ),
    ),
    (
        _clause_ids(17, "d17e7d3b"),
        _Evidence(
            (
                "tests/artifact/test_store.py::test_artifact_and_lineage_identity_are_deterministic",
            ),
            ("Blob/Observation/Artifact identity",),
        ),
    ),
    (
        _clause_ids(17, "2e4ef7f6"),
        _Evidence(
            (
                "tests/result/test_result_manifest.py::test_manifest_builds_only_from_public_artifact_facts",
            ),
            ("Manifest identity/lineage",),
        ),
    ),
    (
        _clause_ids(17, "47f21911"),
        _Evidence(
            (
                "tests/site_skill/test_validation.py::test_canonical_bytes_and_digest_are_stable",
                "tests/site_skill/test_validation.py::test_secret_value_in_nested_data_is_rejected_without_echo",
            ),
            ("SiteSkill version/digest", "secret rejection"),
        ),
    ),
    (
        _clause_ids(17, "8fbd8efb"),
        _Evidence(
            (
                "tests/runtime/test_service.py::test_open_run_close_reopen_reads_job_and_artifact_without_network",
                "tests/result/test_result_manifest.py::test_safe_error_details_are_sorted_and_frozen",
            ),
            ("job state", "stable SafeError code/details"),
        ),
    ),
)


def _build_clause_evidence() -> dict[str, _Evidence]:
    mapping: dict[str, _Evidence] = {}
    for clause_ids, evidence in _CLAUSE_EVIDENCE_GROUPS:
        duplicate = set(mapping).intersection(clause_ids)
        if duplicate:
            raise ValueError("baseline_readme.duplicate_evidence_mapping")
        mapping.update(dict.fromkeys(clause_ids, evidence))
    return mapping


_CLAUSE_EVIDENCE = _build_clause_evidence()


def load_frozen_readme(repository_root: Path) -> FrozenReadme:
    """Read and verify the exact baseline README Git object, never the overlay."""
    type_result = subprocess.run(
        ["git", "-C", str(repository_root), "cat-file", "-t", BASELINE_README_BLOB],
        check=True,
        capture_output=True,
        text=True,
    )
    if type_result.stdout.strip() != "blob":
        raise ValueError("baseline_readme.object_type")
    raw = subprocess.run(
        ["git", "-C", str(repository_root), "cat-file", "blob", BASELINE_README_BLOB],
        check=True,
        capture_output=True,
    ).stdout
    canonical_crlf = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    digest = hashlib.sha256(canonical_crlf).hexdigest()
    text = raw.decode("utf-8")
    line_count = len(text.splitlines())
    if digest != BASELINE_README_SHA256 or line_count != BASELINE_README_LINE_COUNT:
        raise ValueError("baseline_readme.identity")
    resolved = subprocess.run(
        [
            "git",
            "-C",
            str(repository_root),
            "rev-parse",
            f"{BASELINE_README_REVISION}:README.md",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if resolved != BASELINE_README_BLOB:
        raise ValueError("baseline_readme.revision_binding")
    return FrozenReadme(
        BASELINE_README_REVISION,
        BASELINE_README_BLOB,
        digest,
        line_count,
        text,
    )


def _section_lines(text: str, section: int) -> list[str]:
    matched = re.search(
        rf"(?ms)^## {section}\. .*?\n(?P<body>.*?)(?=^## \d+\.|\Z)", text
    )
    if matched is None:
        raise ValueError(f"baseline_readme.section_{section}_missing")
    return matched.group("body").splitlines()


def _normative_fence_claims(lead_in: str, fence_lines: list[str]) -> tuple[str, ...]:
    normalized_lead_in = " ".join(lead_in.split())
    values = tuple(line.strip() for line in fence_lines if line.strip())
    if normalized_lead_in == (
        "The public contract should not require callers to provide:"
    ):
        return tuple(
            f"Public Request forbidden caller field: {value}"
            for value in values
            if re.fullmatch(r"[a-z][a-z0-9_]*", value)
        )
    if normalized_lead_in == (
        "`explore_all_tools=true` does not mean “run any installed program.” "
        "It means Web Listening may select from the intersection of tools that are:"
    ):
        members = tuple(value.removeprefix("∩").strip() for value in values)
        return tuple(
            f"explore_all_tools eligible intersection requires: {member}"
            for member in members
            if re.fullmatch(r"[a-z]+(?:[ -][a-z]+)*", member)
        )
    if normalized_lead_in == (
        "The first version should include one built-in Transform:"
    ):
        return tuple(
            f"First-version built-in Transform identifier: {value}"
            for value in values
            if re.fullmatch(r"[a-z][a-z0-9_]*", value)
        )
    return ()


def _paragraphs(lines: list[str]) -> tuple[str, ...]:
    """Extract claims plus only explicitly bound normative contract fences."""
    claims: list[str] = []
    paragraph: list[str] = []
    in_fence = False
    fence_lead_in = ""
    fence_lines: list[str] = []
    pending_fence_lead_in = ""

    def flush() -> None:
        nonlocal pending_fence_lead_in
        if paragraph:
            value = " ".join(item.strip() for item in paragraph).strip()
            paragraph.clear()
            if not value:
                return
            if value.endswith(":"):
                pending_fence_lead_in = value
                if value in _NORMATIVE_COLON_CLAIMS:
                    claims.append(value)
                claims.extend(
                    sentence
                    for sentence in re.split(r"(?<=[.!?])\s+", value)
                    if sentence.endswith((".", "!", "?"))
                )
                return
            pending_fence_lead_in = ""
            claims.append(value)

    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("```"):
            if in_fence:
                claims.extend(_normative_fence_claims(fence_lead_in, fence_lines))
                in_fence = False
            else:
                fence_lead_in = " ".join(paragraph).strip() or pending_fence_lead_in
                fence_lines = []
                flush()
                pending_fence_lead_in = ""
                in_fence = True
            continue
        if in_fence:
            fence_lines.append(stripped)
            continue
        if not stripped:
            flush()
            continue
        if stripped.startswith("###"):
            flush()
            continue
        pending_fence_lead_in = ""
        if re.match(r"^(?:-|\d+\.)\s+", stripped):
            flush()
            claims.append(re.sub(r"^(?:-|\d+\.)\s+", "", stripped))
            continue
        if stripped.startswith("|"):
            flush()
            if re.fullmatch(r"\|?[| :\-]+\|?", stripped):
                continue
            next_line = lines[index + 1].strip() if index + 1 < len(lines) else ""
            if re.fullmatch(r"\|?[| :\-]+\|?", next_line):
                continue
            claims.append(
                "table row: "
                + " | ".join(item.strip() for item in stripped.strip("|").split("|"))
            )
            continue
        paragraph.append(stripped)
    flush()
    return tuple(claims)


def extract_readme_clauses(text: str) -> tuple[ReadmeClause, ...]:
    """Reconstruct the Issue-scoped clause set from the frozen README."""
    clauses: list[ReadmeClause] = []
    for section in (1, 2, *range(4, 18), 19):
        claims = list(_paragraphs(_section_lines(text, section)))
        if section == 1:
            claims = [item for item in claims if not item.startswith("Web Listening")]
        if section == 2:
            expanded: list[str] = []
            for claim in claims:
                if claim.startswith("table row:"):
                    cells = [item.strip() for item in claim[10:].split("|")]
                    if len(cells) == 3:
                        expanded.extend(
                            (
                                f"{cells[0]} responsibility: {cells[1]}",
                                f"{cells[0]} prohibition: {cells[2]}",
                            )
                        )
                        continue
                if "Runtime is not a sixth business authority." in claim:
                    expanded.extend(
                        (
                            "Runtime is not a sixth business authority.",
                            "Interfaces may not implement their own tool selection or acquisition logic.",
                        )
                    )
                    continue
                expanded.append(claim)
            claims = expanded
        if section == 7:
            claims.remove("This rule is essential for website monitoring.")
        if section == 8:
            normalized: list[str] = []
            for claim in claims:
                if claim.startswith("table row:"):
                    cells = [item.strip() for item in claim[10:].split("|")]
                    normalized.append(
                        f"{cells[0]} protocol input: {cells[1]}; output: {cells[2]}"
                    )
                else:
                    normalized.append(claim)
            claims = normalized
        if section == 11:
            claims = [item for item in claims if not item.startswith("table row:")]
        if section == 17:
            claims.remove(
                "The current repository contains several mature but very large "
                "modules. A complete replacement would produce a change that is "
                "difficult to review, verify, and roll back."
            )
        if section == 19:
            claims = [
                re.sub(
                    r"^The first production-ready version must prove that:\s*", "", item
                )
                for item in claims
                if not item.startswith("The first production-ready version")
            ]
            if len(claims) != 16:
                raise ValueError("baseline_readme.section_19_shape")
        for ordinal, claim in enumerate(claims, start=1):
            if section == 19:
                clause_id = f"README-19-{ordinal:02d}"
            else:
                fingerprint = hashlib.sha256(claim.encode("utf-8")).hexdigest()[:8]
                clause_id = f"README-{section:02d}-{fingerprint}"
            clauses.append(ReadmeClause(clause_id, section, claim))
    return tuple(clauses)


def readme_evidence_matrix(text: str) -> tuple[EvidenceRow, ...]:
    """Attach exact test commands and observable fields to every frozen clause."""
    rows: list[EvidenceRow] = []
    for clause in extract_readme_clauses(text):
        if clause.section == 19:
            evidence = _SECTION_19_EVIDENCE[int(clause.clause_id.rsplit("-", 1)[1]) - 1]
        else:
            evidence = _CLAUSE_EVIDENCE.get(clause.clause_id)
            if evidence is None:
                raise ValueError(f"baseline_readme.unmapped_clause:{clause.clause_id}")
        rows.append(
            EvidenceRow(
                clause.clause_id,
                clause.section,
                clause.clause_text,
                evidence.test_nodeids,
                evidence.command,
                evidence.evidence_fields,
                "PASS",
            )
        )
    return tuple(rows)


def project_current_state(
    results: tuple[Result, ...],
    artifact_store: ArtifactStore,
    *,
    site_key: str,
    site_skill_digest: str,
    generated_at: str,
    complete: bool,
) -> SiteState:
    """Project only successful public source evidence into Current SiteState."""
    pages: list[SiteStatePage] = []
    for result in results:
        sources = tuple(item for item in result.artifacts if item.role == "source")
        if len(sources) != 1:
            raise ValueError("delivery.source_required")
        source = sources[0]
        stored = artifact_store.get_observation(source.observation_id)
        observed = stored.observation
        if (
            stored.artifact.artifact_id != source.artifact_id
            or observed.artifact_id != source.artifact_id
            or observed.source_url != source.source_url
            or observed.observed_at != source.observed_at
            or stored.artifact.mime_type != source.mime_type
            or stored.blob.size_bytes != source.size_bytes
            or stored.blob.sha256 != source.sha256
            or hashlib.sha256(stored.content).hexdigest() != source.sha256
            or (urlsplit(source.source_url).hostname or "invalid") != site_key
        ):
            raise ValueError("delivery.artifact_store_mismatch")
        pages.append(
            SiteStatePage(
                source.source_url,
                source.observation_id,
                source.artifact_id,
                f"sha256:{source.sha256}",
            )
        )
    return SiteState(
        site_key,
        generated_at,
        site_skill_digest,
        complete,
        tuple(sorted(pages, key=lambda page: page.canonical_url)),
    )


def persist_site_state(path: Path, state: SiteState) -> None:
    """Persist canonical bytes and require immediate strict round-trip."""
    payload = state.canonical_json_bytes()
    path.write_bytes(payload)
    if load_site_state(path).canonical_json_bytes() != payload:
        raise ValueError("delivery.site_state_roundtrip")


def load_site_state(path: Path) -> SiteState:
    """Strictly reload a persisted Current SiteState."""
    state = site_state_from_mapping(json.loads(path.read_bytes()))
    if state.canonical_json_bytes() != path.read_bytes():
        raise ValueError("delivery.site_state_noncanonical")
    return state


def persist_site_skill(path: Path, skill: SiteSkill) -> None:
    """Persist one validated Site Skill in canonical form and strictly reread it."""
    payload = canonical_site_skill_bytes(skill)
    path.write_bytes(payload)
    if canonical_site_skill_bytes(load_site_skill(path)) != payload:
        raise ValueError("delivery.site_skill_roundtrip")


def load_site_skill(path: Path) -> SiteSkill:
    """Strictly reload a persisted canonical Site Skill."""
    payload = path.read_bytes()
    skill = site_skill_from_mapping(json.loads(payload))
    if canonical_site_skill_bytes(skill) != payload:
        raise ValueError("delivery.site_skill_noncanonical")
    return skill


def _url_id(value: str | None) -> str | None:
    if value is None:
        return None
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _safe_error(error) -> dict[str, object]:
    payload = error.to_dict()
    details = payload.get("details", {})
    return {
        "code": payload["code"],
        "message": payload["message"],
        "detail_keys": sorted(details) if isinstance(details, dict) else [],
    }


def _attempt_record(attempt) -> dict[str, object]:
    return {
        "attempt_id": attempt.attempt_id,
        "order": attempt.order,
        "outcome": attempt.outcome,
        "tool_id": attempt.tool_id,
        "tool_version": attempt.tool_version,
        "requested_url_id": _url_id(attempt.requested_url),
        "final_url_id": _url_id(attempt.final_url),
        "http_status": attempt.http_status,
        "requests": attempt.requests,
        "bytes_received": attempt.bytes_received,
        "runtime_ms": attempt.runtime_ms,
        "error": None if attempt.error is None else _safe_error(attempt.error),
    }


def delivery_record(result: Result) -> dict[str, object]:
    """Return the complete content-free delivery record for one Result."""
    transform_attempt = next(
        (
            attempt
            for attempt in result.attempts
            if attempt.outcome == "succeeded" and attempt.final_url is None
        ),
        None,
    )
    artifacts = []
    for artifact in result.artifacts:
        if artifact.role == "source":
            tool_id = result.manifest.tool_id
            tool_version = result.manifest.tool_version
        else:
            if transform_attempt is None:
                raise ValueError("delivery.transform_attempt_missing")
            tool_id = transform_attempt.tool_id
            tool_version = transform_attempt.tool_version
        artifacts.append(
            {
                "artifact_id": artifact.artifact_id,
                "observation_id": artifact.observation_id,
                "role": artifact.role,
                "mime_type": artifact.mime_type,
                "size_bytes": artifact.size_bytes,
                "sha256": artifact.sha256,
                "tool_id": tool_id,
                "tool_version": tool_version,
                "observed_at": artifact.observed_at,
                "lineage": [
                    {
                        "lineage_id": edge.lineage_id,
                        "source_artifact_id": edge.source_artifact_id,
                        "source_observation_id": edge.source_observation_id,
                        "relation": edge.relation,
                    }
                    for edge in artifact.lineage
                ],
            }
        )
    attempts = [_attempt_record(attempt) for attempt in result.attempts]
    return {
        "schema_version": "phase-20-new-system-delivery.v1",
        "result": {
            "status": result.status.value,
            "site_skill_used": (
                None
                if result.site_skill_used is None
                else result.site_skill_used.to_dict()
            ),
            "site_skill_update": (
                None
                if result.site_skill_update is None
                else {**result.site_skill_update.to_dict(), "active": False}
            ),
            "attempts": attempts,
            "usage": result.usage.to_dict(),
            "errors": [_safe_error(error) for error in result.errors],
        },
        "request_identity": {
            "run_id": result.manifest.run_id,
            "requested_url_id": _url_id(result.manifest.requested_url),
        },
        "http": {
            "requested_url_id": _url_id(result.manifest.requested_url),
            "final_url_id": _url_id(result.manifest.final_url),
            "http_status": result.manifest.http_status,
            "mime_type": result.manifest.mime_type,
            "redirects": [
                {
                    "order": redirect.order,
                    "from_url_id": _url_id(redirect.from_url),
                    "to_url_id": _url_id(redirect.to_url),
                    "http_status": redirect.http_status,
                    "decision": redirect.decision,
                }
                for redirect in result.manifest.redirects
            ],
        },
        "manifest": {
            "schema_version": result.manifest.schema_version,
            "run_id": result.manifest.run_id,
            "site_skill": (
                None
                if result.manifest.site_skill is None
                else result.manifest.site_skill.to_dict()
            ),
            "usage": result.manifest.usage.to_dict(),
        },
        "artifacts": artifacts,
    }


def site_state_record(state: SiteState, store: ArtifactStore) -> dict[str, object]:
    """Project one state plus verified Store fields without content or raw URLs."""
    pages = []
    for page in state.pages:
        stored = store.get_observation(page.observation_id)
        if (
            stored.observation.source_url != page.canonical_url
            or stored.artifact.artifact_id != page.artifact_id
            or f"sha256:{stored.blob.sha256}" != page.content_digest
        ):
            raise ValueError("delivery.site_state_store_mismatch")
        pages.append(
            {
                "url_id": _url_id(page.canonical_url),
                "artifact_id": page.artifact_id,
                "observation_id": page.observation_id,
                "role": stored.artifact.role.value,
                "mime_type": stored.artifact.mime_type,
                "size_bytes": stored.blob.size_bytes,
                "sha256": stored.blob.sha256,
                "observed_at": stored.observation.observed_at,
                "lineage_count": len(stored.lineage),
            }
        )
    return {
        "schema_version": state.schema_version,
        "site_key": state.site_key,
        "generated_at": state.generated_at,
        "site_skill_digest": state.site_skill_digest,
        "complete": state.complete,
        "state_digest": state.digest,
        "pages": pages,
    }


def _feed_change(change: SiteChange) -> dict[str, object]:
    return {
        "change_type": change.change_type,
        "url_id": _url_id(change.url),
        "previous": None if change.previous is None else change.previous.to_dict(),
        "current": None if change.current is None else change.current.to_dict(),
        "attempt_ids": list(change.attempt_ids),
        "error_codes": list(change.error_codes),
    }


def refresh_record(
    result: SiteRefreshResult, store: ArtifactStore
) -> dict[str, object]:
    """Return the safe refresh contract, states, six sets, and update feed."""
    update = result.site_skill_update
    candidate = None
    if update is not None:
        mapping = update.candidate.to_dict()
        candidate = {
            "reason": update.reason,
            "previous": update.previous.to_dict(),
            "candidate": {
                "site_key": mapping["site_key"],
                "version": mapping["version"],
                "digest": update.candidate.digest,
                "active": False,
            },
        }
    return {
        "schema_version": result.schema_version,
        "status": result.status.value,
        "refresh_complete": result.refresh_complete,
        "site_skill_used": result.site_skill_used.to_dict(),
        "site_skill_update": candidate,
        "attempts": [_attempt_record(attempt) for attempt in result.attempts],
        "usage": result.usage.to_dict(),
        "stop_reason": result.stop_reason,
        "errors": [_safe_error(error) for error in result.errors],
        "target_results": [delivery_record(item) for item in result.target_results],
        "changes": {
            name: [_feed_change(change) for change in getattr(result, name)]
            for name in (
                "added",
                "changed",
                "unchanged",
                "missing",
                "failed",
                "unresolved",
            )
        },
        "previous_state": site_state_record(result.previous_state, store),
        "current_state": site_state_record(result.current_state, store),
        "update_feed": build_update_feed(result),
    }


def build_update_feed(result: SiteRefreshResult) -> dict[str, object]:
    """Expose updates while retaining unchanged only as audit evidence."""
    updates = [
        _feed_change(change)
        for changes in (
            result.added,
            result.changed,
            result.missing,
            result.failed,
            result.unresolved,
        )
        for change in changes
    ]
    previous = {page.canonical_url: page for page in result.previous_state.pages}
    current = {page.canonical_url: page for page in result.current_state.pages}
    unchanged_audit = []
    for change in result.unchanged:
        before = previous[change.url]
        after = current[change.url]
        unchanged_audit.append(
            {
                "url_id": _url_id(change.url),
                "previous_observation_id": before.observation_id,
                "current_observation_id": after.observation_id,
                "artifact_id": after.artifact_id,
                "content_digest": after.content_digest,
                "new_observation": before.observation_id != after.observation_id,
                "blob_reused": (
                    before.artifact_id == after.artifact_id
                    and before.content_digest == after.content_digest
                ),
            }
        )
    return {
        "updates": updates,
        "audit": {
            "counts": {
                "added": len(result.added),
                "changed": len(result.changed),
                "unchanged": len(result.unchanged),
                "missing": len(result.missing),
                "failed": len(result.failed),
                "unresolved": len(result.unresolved),
            },
            "unchanged_count": len(result.unchanged),
            "unchanged": unchanged_audit,
        },
    }


__all__ = [
    "BASELINE_README_BLOB",
    "BASELINE_README_LINE_COUNT",
    "BASELINE_README_REVISION",
    "BASELINE_README_SHA256",
    "EvidenceRow",
    "FrozenReadme",
    "ReadmeClause",
    "build_update_feed",
    "delivery_record",
    "extract_readme_clauses",
    "load_frozen_readme",
    "load_site_skill",
    "load_site_state",
    "persist_site_skill",
    "persist_site_state",
    "project_current_state",
    "readme_evidence_matrix",
    "refresh_record",
    "site_state_record",
]
