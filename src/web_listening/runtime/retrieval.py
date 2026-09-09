"""Pure retrieval projections and operation catalog over existing Runtime facts."""

import json
from dataclasses import dataclass

from web_listening.artifact.lineage import validate_artifact_id
from web_listening.request.model import ContentType
from web_listening.request.validate import validate_request
from web_listening.result.errors import (
    ResultValidationError,
    canonical_json_bytes,
    require_exact_fields,
    require_mapping,
    validate_text,
)
from web_listening.result.manifest import Usage
from web_listening.result.model import ResultStatus
from web_listening.runtime.jobs import Job
from web_listening.site_skill.resolve import resolve_site_skill
from web_listening.tool_registry.eligibility import (
    EligibilityFacts,
    EligibilityRequirements,
    acquisition_failure_is_operational,
    rank_eligible_tools,
)
from web_listening.tool_registry.manifest import ToolCategory

# Exact types reject booleans as integers and noncanonical collection shapes.
# pylint: disable=unidiomatic-typecheck,too-many-instance-attributes,duplicate-code


METHOD_TO_TOOL = {
    "HTTP": "acquisition.web_http",
    "BROWSER": "acquisition.playwright",
    "CLOAK": "acquisition.cloakbrowser",
    "FILE": "acquisition.web_http",
    "OFFICIAL_ALTERNATE": None,
}
OPERATIONS = {
    "retrieval-methods": "/v1/retrieval-methods/query",
    "retrieve-http": "/v1/retrievals/http",
    "retrieve-browser": "/v1/retrievals/browser",
    "retrieve-cloak": "/v1/retrievals/cloak",
    "retrieve-file": "/v1/retrievals/file",
    "retrieve-alternate": "/v1/retrievals/alternate",
    "retrieve": "/v1/retrievals",
}
REASONS = frozenset(
    {
        "HTTP_OK",
        "BROWSER_REQUIRED",
        "CLOUDFLARE_BLOCKED",
        "AUTH_REQUIRED",
        "PERMISSION_DENIED",
        "QUALITY_REJECTED",
        "METHODS_EXHAUSTED",
    }
)


def action(name):
    """Return a stable executable action or inert external discovery guidance."""
    if name == "discover_official_alternates":
        return {
            "action_id": name,
            "condition": "caller_or_external_discovery_required",
            "cli": None,
            "rest": None,
            "mcp": None,
            "requires_candidate": True,
        }
    conditions = {
        "retrieve-http": "eligible_http_html_only",
        "retrieve-file": "eligible_http_file_only",
        "retrieve-cloak": "eligible_explicit_or_non_cloudflare_fallback_only",
        "retrieve-browser": "request_exploration_and_browser_eligibility_and_budget",
        "retrieve-alternate": "caller_supplies_full_independently_authorized_request",
    }
    return {
        "action_id": name.replace("-", "_"),
        "condition": conditions[name],
        "cli": name,
        "rest": OPERATIONS[name],
        "mcp": "web_listening_" + name.replace("-", "_"),
        "requires_candidate": name == "retrieve-alternate",
    }


def method_catalog(request, registry):  # pylint: disable=too-many-locals
    """Evaluate the current registered catalog without any acquisition call."""
    request = validate_request(request)
    preferred = "acquisition.web_http"
    skill_reasons = ()
    if request.site_skill is not None:
        resolution = resolve_site_skill(request, request.site_skill, registry)
        request = resolution.request
        preferred = resolution.skill.tool.tool_id
        skill_reasons = resolution.reasons if not resolution.eligible else ()
    requirements = EligibilityRequirements(category=ToolCategory.ACQUISITION)
    manifests = registry.query(category=ToolCategory.ACQUISITION)
    policy_ids = frozenset(
        m.tool_id
        for m in manifests
        if "browser_render" not in m.capabilities
        or ContentType.HTML in request.scope.content_types
    )
    budget = request.budgets
    selection = rank_eligible_tools(
        manifests,
        requirements,
        EligibilityFacts(
            frozenset(m.tool_id for m in manifests),
            policy_ids,
            budget.max_requests,
            budget.max_bytes,
            budget.max_runtime_seconds * 1000,
            budget.max_tool_attempts_per_target,
        ),
        preferred_tool_id=preferred,
        include_alternates=request.explore_all_tools,
        catalog_decisions=registry.eligibility(requirements),
    )
    decisions = {d.tool_id: d for d in selection.decisions}
    ranked = {m.tool_id for m in selection.ranked}
    entries = []
    for method, tool in METHOD_TO_TOOL.items():
        decision = decisions.get(tool)
        reasons = list(decision.reasons) if decision else ["eligibility.not_installed"]
        eligible = tool in ranked and not skill_reasons
        reasons.extend(skill_reasons)
        if method == "FILE" and ContentType.FILE not in request.scope.content_types:
            eligible = False
            reasons.append("retrieval.file_request_required")
        if method == "HTTP" and ContentType.HTML not in request.scope.content_types:
            eligible = False
            reasons.append("retrieval.html_request_required")
        if method == "OFFICIAL_ALTERNATE":
            reasons, eligible = ["retrieval.candidate_request_required"], False
        installed = decision is not None and "eligibility.not_installed" not in reasons
        active = installed and not any(
            "disabled" in r or "inactive" in r for r in reasons
        )
        sound = installed and not any(
            marker in reason
            for reason in reasons
            for marker in (
                "unhealthy",
                "broken",
                "runtime_identity_mismatch",
                "runtime_missing",
            )
        )
        entries.append(
            {
                "method": method,
                "tool_id": tool,
                "eligible": eligible,
                "installed": installed,
                "active": active,
                "healthy": sound,
                "qualified": sound and "eligibility.unqualified" not in reasons,
                "reasons": reasons,
                "auto_after_cloudflare": method == "BROWSER",
                "action": action(
                    "retrieve-alternate"
                    if method == "OFFICIAL_ALTERNATE"
                    else "retrieve-" + method.lower()
                ),
            }
        )
    return entries


@dataclass(frozen=True)
class RetrievalState:
    """Strict immutable projection; Job/Result remain the only persisted truth."""

    outcome: str
    reason: str
    method: str | None
    fallback_used: bool
    job_ids: tuple[str, ...]
    attempts: tuple[tuple[str, str], ...]
    artifacts: tuple[tuple[str, str], ...]
    usage: Usage
    next_actions: tuple[str, ...]

    def __post_init__(self):
        valid = (
            self.outcome in {"FETCHED", "UNRESOLVED"}
            and self.reason in REASONS
            and (self.method is None or self.method in METHOD_TO_TOOL)
            and type(self.fallback_used) is bool
            and type(self.usage) is Usage
        )
        for values in (self.job_ids, self.attempts, self.artifacts, self.next_actions):
            valid = valid and type(values) is tuple and len(set(values)) == len(values)
        valid = valid and all(type(v) is str and v for v in self.job_ids)
        for refs in (self.attempts, self.artifacts):
            valid = valid and all(
                type(r) is tuple
                and len(r) == 2
                and r[0] in self.job_ids
                and type(r[1]) is str
                and bool(r[1])
                for r in refs
            )
        valid = valid and all(
            v
            in {
                "retrieve-browser",
                "retrieve-alternate",
                "discover_official_alternates",
            }
            for v in self.next_actions
        )
        valid = valid and ((self.outcome == "FETCHED") == bool(self.artifacts))
        valid = valid and ((self.outcome == "FETCHED") == (self.reason == "HTTP_OK"))
        if self.outcome == "FETCHED":
            valid = (
                valid
                and self.reason == "HTTP_OK"
                and self.method is not None
                and not self.next_actions
            )
        valid = valid and bool(self.job_ids)
        if not valid:
            raise ResultValidationError("retrieval.state_invalid")
        for value in self.job_ids:
            validate_text(value, code="retrieval.job_id_invalid", maximum=128)
        for _, value in self.attempts:
            validate_text(value, code="retrieval.attempt_id_invalid", maximum=128)
        for _, value in self.artifacts:
            validate_artifact_id(value)

    def to_dict(self):
        """Serialize only canonical v1 fields and stable action definitions."""
        return {
            "schema_version": "retrieval-state.v1",
            "outcome": self.outcome,
            "reason": self.reason,
            "method": self.method,
            "fallback_used": self.fallback_used,
            "job_ids": list(self.job_ids),
            "attempts": [list(v) for v in self.attempts],
            "artifacts": [list(v) for v in self.artifacts],
            "usage": self.usage.to_dict(),
            "next_actions": [action(v) for v in self.next_actions],
        }

    def canonical_json_bytes(self):
        """Return deterministic JSON bytes."""
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value):
        """Reject unknown fields, malformed nested facts and noncanonical actions."""
        value = require_mapping(value)
        require_exact_fields(
            value,
            {
                "schema_version",
                "outcome",
                "reason",
                "method",
                "fallback_used",
                "job_ids",
                "attempts",
                "artifacts",
                "usage",
                "next_actions",
            },
        )
        try:
            result = cls(
                value["outcome"],
                value["reason"],
                value["method"],
                value["fallback_used"],
                tuple(value["job_ids"]),
                tuple(tuple(v) for v in value["attempts"]),
                tuple(tuple(v) for v in value["artifacts"]),
                Usage.from_dict(value["usage"]),
                tuple(
                    (
                        v["action_id"].replace("_", "-")
                        if v["action_id"] != "discover_official_alternates"
                        else v["action_id"]
                    )
                    for v in value["next_actions"]
                ),
            )
            if result.to_dict() != value:
                raise ValueError("noncanonical")
            return result
        except (KeyError, TypeError, ValueError) as exc:
            raise ResultValidationError("retrieval.state_invalid") from exc


def job_payload(job: Job):
    """Use the existing public Job fields and strict Result representation."""
    return {
        "job_id": job.job_id,
        "status": job.status.value,
        "submitted_at": job.submitted_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "cancel_requested_at": job.cancel_requested_at,
        "result": None if job.result is None else job.result.to_dict(),
        "failure_code": job.failure_code,
    }


def project_retrieval(jobs, catalog):
    """Recompute retrieval facts from ordered actual Job Results and eligibility."""
    attempts, artifacts, called = [], [], []
    for job in jobs:
        if job.result is None:
            raise ResultValidationError("retrieval.result_required")
        attempts.extend((job.job_id, a.attempt_id) for a in job.result.attempts)
        artifacts.extend((job.job_id, a.artifact_id) for a in job.result.artifacts)
        called.extend(
            a
            for a in job.result.attempts
            if a.tool_id
            and a.tool_id.startswith("acquisition.")
            and a.outcome != "skipped"
        )
    last = called[-1] if called else None
    method = next(
        (m for m, t in METHOD_TO_TOOL.items() if last and t == last.tool_id), None
    )
    if artifacts and any(
        a.mime_type != "text/html" and a.role == "source"
        for a in jobs[-1].result.artifacts
    ):
        method = "FILE"
    if (
        last
        and last.tool_id == "acquisition.web_http"
        and jobs[-1].execution_request_json is not None
        and json.loads(jobs[-1].execution_request_json)["scope"]["content_types"]
        == ["file"]
    ):
        method = "FILE"
    if len(jobs) > 1:
        method = "OFFICIAL_ALTERNATE"
    code = last.error.code if last and last.error else ""
    reasons = {
        "acquisition.cloudflare_blocked": "CLOUDFLARE_BLOCKED",
        "acquisition.auth_required": "AUTH_REQUIRED",
        "acquisition.permission_denied": "PERMISSION_DENIED",
        "acquisition.script_only": "BROWSER_REQUIRED",
    }
    reason = (
        "HTTP_OK"
        if artifacts
        else reasons.get(
            code,
            (
                "QUALITY_REJECTED"
                if code.startswith(("acquisition.", "runtime.quality"))
                else "METHODS_EXHAUSTED"
            ),
        )
    )
    actions = []
    if not artifacts and reason not in {"AUTH_REQUIRED", "PERMISSION_DENIED"}:
        if (
            method == "HTTP"
            and reason in {"BROWSER_REQUIRED", "CLOUDFLARE_BLOCKED"}
            and any(m["method"] == "BROWSER" and m["eligible"] for m in catalog)
        ):
            actions.append("retrieve-browser")
        actions.extend(("discover_official_alternates", "retrieve-alternate"))
    usage = Usage(
        *(
            sum(getattr(j.result.usage, field) for j in jobs)
            for field in ("requests", "bytes_received", "runtime_ms", "tool_attempts")
        )
    )
    return RetrievalState(
        "FETCHED" if artifacts else "UNRESOLVED",
        reason,
        method,
        len(called) > 1 or len(jobs) > 1,
        tuple(j.job_id for j in jobs),
        tuple(attempts),
        tuple(artifacts),
        usage,
        tuple(actions),
    )


def retrieval_error_code(result):
    """Keep policy/cancellation/budget/infrastructure failures as failures."""
    if result.status is ResultStatus.REJECTED:
        return result.errors[0].code if result.errors else "retrieval.rejected"
    codes = [
        a.error.code for a in result.attempts if a.error and a.outcome != "skipped"
    ]
    codes.extend(e.code for e in result.errors)
    cancellation = next((code for code in codes if "cancel" in code), None)
    operational = next(
        (code for code in codes if acquisition_failure_is_operational(code)), None
    )
    if cancellation or operational or result.artifacts:
        return cancellation or operational
    return next(
        (
            code
            for code in codes
            if code.startswith(
                ("robots.", "policy.", "scope.", "protocol.", "artifact.")
            )
            or "budget" in code
            or "boundary" in code
            or "cancel" in code
            or code
            in {
                "runtime.workflow_failed",
                "gateway.closed",
                "gateway.private_address",
                "gateway.dns_failed",
                "gateway.dns_not_public",
                "gateway.peer_not_public",
                "gateway.https_downgrade",
                "gateway.transport_contract",
                "browser.read_only",
            }
        ),
        None,
    )


def _object_schema(properties):
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


_TEXT_SCHEMA = {"type": "string", "minLength": 1}
_ACTION_SCHEMA = _object_schema(
    {
        "action_id": _TEXT_SCHEMA,
        "condition": _TEXT_SCHEMA,
        **{key: {"type": ["string", "null"]} for key in ("cli", "rest", "mcp")},
        "requires_candidate": {"type": "boolean"},
    }
)
_USAGE_SCHEMA = _object_schema(
    {
        key: {"type": "integer", "minimum": 0}
        for key in ("requests", "bytes_received", "runtime_ms", "tool_attempts")
    }
)
_REFS_SCHEMA = {
    "type": "array",
    "uniqueItems": True,
    "items": {
        "type": "array",
        "minItems": 2,
        "maxItems": 2,
        "items": _TEXT_SCHEMA,
    },
}
RETRIEVAL_STATE_SCHEMA = _object_schema(
    {
        "schema_version": {"const": "retrieval-state.v1"},
        "outcome": {"enum": ["FETCHED", "UNRESOLVED"]},
        "reason": {"enum": sorted(REASONS)},
        "method": {"enum": [*METHOD_TO_TOOL, None]},
        "fallback_used": {"type": "boolean"},
        "job_ids": {"type": "array", "uniqueItems": True, "items": _TEXT_SCHEMA},
        "attempts": _REFS_SCHEMA,
        "artifacts": _REFS_SCHEMA,
        "usage": _USAGE_SCHEMA,
        "next_actions": {"type": "array", "items": _ACTION_SCHEMA},
    }
)
METHOD_CATALOG_SCHEMA = _object_schema(
    {
        "methods": {
            "type": "array",
            "items": _object_schema(
                {
                    "method": {"enum": list(METHOD_TO_TOOL)},
                    "tool_id": {"type": ["string", "null"]},
                    **{
                        key: {"type": "boolean"}
                        for key in (
                            "eligible",
                            "installed",
                            "active",
                            "healthy",
                            "qualified",
                            "auto_after_cloudflare",
                        )
                    },
                    "reasons": {"type": "array", "items": _TEXT_SCHEMA},
                    "action": _ACTION_SCHEMA,
                }
            ),
        }
    }
)


def retrieval_response_schema(job_schema):
    """Compose retrieval around the interface's existing strict Job/Result schema."""
    job_schema = dict(
        job_schema,
        properties=dict(
            job_schema["properties"], cancel_requested_at={"type": ["string", "null"]}
        ),
    )
    return _object_schema(
        {
            "jobs": {"type": "array", "items": job_schema},
            "retrieval": RETRIEVAL_STATE_SCHEMA,
            "provenance": {
                "type": "array",
                "items": _object_schema(
                    {
                        key: _TEXT_SCHEMA
                        for key in (
                            "primary_job_id",
                            "candidate_job_id",
                            "primary_url",
                            "candidate_url",
                        )
                    }
                ),
            },
        }
    )
