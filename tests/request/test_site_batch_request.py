"""Strict multi-site batch Request tests."""

# pylint: disable=duplicate-code,missing-function-docstring

from __future__ import annotations

from dataclasses import replace

import pytest

from web_listening.artifact.site_state import SiteState, SiteStatePage
from web_listening.request.model import (
    Budgets,
    ContentType,
    Request,
    RequestValidationError,
    Scope,
)
from web_listening.request.site_batch import (
    FileDiscoveryGoal,
    SiteBatchPhase,
    SiteBatchRequest,
    SiteBatchSite,
    SiteRefreshContext,
    site_batch_child_scope,
    site_batch_request_from_json,
    site_batch_request_from_mapping,
)
from web_listening.site_skill.model import (
    DiscoveryRecipe,
    SuccessChecks,
    ToolReference,
)
from web_listening.site_skill.update import create_candidate
from web_listening.tool_registry.manifest import ToolCategory

NOW = "2026-09-01T00:00:00Z"
SEEDS = ("https://one.test/", "https://two.test/", "https://three.test/")
LIMITS = Budgets(12, 52_428_800, 60, 3)


def _request() -> Request:
    return Request(
        Scope(
            SEEDS,
            tuple(seed.rstrip("/") for seed in SEEDS),
            ("/**",),
            (ContentType.HTML, ContentType.FILE),
        ),
        None,
        True,
        LIMITS,
    )


def _context(
    seed: str,
    marker: str,
    *,
    complete: bool = True,
    allowed_origins: tuple[str, ...] | None = None,
) -> SiteRefreshContext:
    site_key = seed.removeprefix("https://").rstrip("/")
    scope = Scope(
        (seed,),
        (seed.rstrip("/"),) if allowed_origins is None else allowed_origins,
        ("/**",),
        (ContentType.HTML, ContentType.FILE),
    )
    skill = create_candidate(
        site_key=site_key,
        version=1,
        previous=None,
        scope=scope,
        budgets=LIMITS,
        tool=ToolReference(
            "acquisition.web_http",
            "1.0.0",
            ToolCategory.ACQUISITION,
            frozenset({"http_get"}),
        ),
        success_checks=SuccessChecks(("text/html",), 1),
        verified_at=NOW,
        discovery=DiscoveryRecipe(
            ToolReference(
                "discovery.html_links",
                "1.0.0",
                ToolCategory.DISCOVERY,
                frozenset({"html_links"}),
            ),
            seed,
        ),
    ).skill
    return SiteRefreshContext(
        skill,
        SiteState(
            site_key,
            NOW,
            skill.digest,
            complete,
            (
                SiteStatePage(
                    seed,
                    f"observation-{marker * 32}",
                    f"artifact-{marker * 64}",
                    f"sha256:{marker * 64}",
                ),
            ),
        ),
    )


def _contexts(*, first_complete: bool = True) -> tuple[SiteRefreshContext, ...]:
    return tuple(
        _context(seed, marker, complete=first_complete if index == 0 else True)
        for index, (seed, marker) in enumerate(zip(SEEDS, "abc", strict=True))
    )


def _sites() -> tuple[SiteBatchSite, ...]:
    parent = _request()
    return tuple(
        SiteBatchSite(
            site_batch_child_scope(parent.scope, seed),
            (
                FileDiscoveryGoal.REQUIRED
                if index == 0
                else FileDiscoveryGoal.NOT_REQUIRED
            ),
        )
        for index, seed in enumerate(parent.scope.seeds)
    )


def test_first_and_refresh_are_distinct_strict_round_trippable_requests() -> None:
    first = SiteBatchRequest(SiteBatchPhase.FIRST, _request(), (), sites=_sites())
    refresh = SiteBatchRequest(
        SiteBatchPhase.REFRESH,
        _request(),
        _contexts(),
        sites=_sites(),
    )

    assert site_batch_request_from_mapping(first.to_dict()) == first
    assert site_batch_request_from_json(first.canonical_json_bytes().decode()) == first
    assert site_batch_request_from_mapping(refresh.to_dict()) == refresh
    assert first.site_keys == ("one.test", "two.test", "three.test")
    assert refresh.site_keys == first.site_keys
    assert first.request_sha256 != refresh.request_sha256
    assert first.request.budgets == refresh.request.budgets == LIMITS
    assert first.sites == refresh.sites == _sites()
    assert [item["file_discovery_goal"] for item in first.to_dict()["sites"]] == [
        "required",
        "not_required",
        "not_required",
    ]


@pytest.mark.parametrize(
    ("phase", "contexts"),
    (
        (SiteBatchPhase.FIRST, ()),
        (SiteBatchPhase.REFRESH, _contexts()),
    ),
)
def test_legacy_v1_request_without_sites_defaults_to_not_required(
    phase: SiteBatchPhase,
    contexts: tuple[SiteRefreshContext, ...],
) -> None:
    payload = SiteBatchRequest(
        phase,
        _request(),
        contexts,
        sites=_sites(),
    ).to_dict()
    payload.pop("sites")

    request = site_batch_request_from_mapping(payload)

    assert [site.file_discovery_goal for site in request.sites] == [
        FileDiscoveryGoal.NOT_REQUIRED,
        FileDiscoveryGoal.NOT_REQUIRED,
        FileDiscoveryGoal.NOT_REQUIRED,
    ]
    assert [site.scope for site in request.sites] == [
        site_batch_child_scope(request.request.scope, seed)
        for seed in request.request.scope.seeds
    ]
    assert "sites" in request.to_dict()
    assert site_batch_request_from_mapping(request.to_dict()) == request


def test_explicit_empty_sites_is_not_legacy_missing() -> None:
    payload = SiteBatchRequest(
        SiteBatchPhase.FIRST,
        _request(),
        (),
        sites=_sites(),
    ).to_dict()
    payload["sites"] = []

    with pytest.raises(
        RequestValidationError,
        match="^site_batch_request.sites_invalid$",
    ):
        site_batch_request_from_mapping(payload)


@pytest.mark.parametrize("invalid_sites", ([], None, False))
def test_direct_request_rejects_non_tuple_empty_sites(invalid_sites: object) -> None:
    with pytest.raises(
        RequestValidationError,
        match="^site_batch_request.sites_invalid$",
    ):
        SiteBatchRequest(
            SiteBatchPhase.FIRST,
            _request(),
            (),
            sites=invalid_sites,  # type: ignore[arg-type]
        )


def test_direct_request_defaults_only_exact_empty_tuple_sites() -> None:
    omitted = SiteBatchRequest(SiteBatchPhase.FIRST, _request(), ())
    exact_empty = SiteBatchRequest(
        SiteBatchPhase.FIRST,
        _request(),
        (),
        sites=(),
    )
    explicit = SiteBatchRequest(
        SiteBatchPhase.FIRST,
        _request(),
        (),
        sites=_sites(),
    )

    assert omitted == exact_empty
    assert all(
        site.file_discovery_goal is FileDiscoveryGoal.NOT_REQUIRED
        for site in omitted.sites
    )
    assert explicit.sites == _sites()


@pytest.mark.parametrize(
    "field",
    ("schema_version", "phase", "request", "refresh_contexts"),
)
def test_legacy_compatibility_does_not_relax_other_required_fields(field: str) -> None:
    payload = SiteBatchRequest(
        SiteBatchPhase.FIRST,
        _request(),
        (),
        sites=_sites(),
    ).to_dict()
    payload.pop("sites")
    payload.pop(field)

    with pytest.raises(RequestValidationError, match="^site_batch_request.missing$"):
        site_batch_request_from_mapping(payload)


def test_site_declarations_reject_unknown_goal_expansion_and_missing_file_scope() -> (
    None
):
    parent = _request()
    payload = SiteBatchRequest(
        SiteBatchPhase.FIRST,
        parent,
        (),
        sites=_sites(),
    ).to_dict()
    payload["sites"][0]["hidden"] = True
    with pytest.raises(
        RequestValidationError, match="^site_batch_request.site_unknown_field$"
    ):
        site_batch_request_from_mapping(payload)

    payload = SiteBatchRequest(
        SiteBatchPhase.FIRST,
        parent,
        (),
        sites=_sites(),
    ).to_dict()
    payload["sites"][0]["file_discovery_goal"] = "optional"
    with pytest.raises(
        RequestValidationError,
        match="^site_batch_request.file_discovery_goal_invalid$",
    ):
        site_batch_request_from_mapping(payload)

    with pytest.raises(
        RequestValidationError, match="^site_batch_request.file_scope_required$"
    ):
        SiteBatchSite(
            replace(
                site_batch_child_scope(parent.scope, SEEDS[0]),
                content_types=(ContentType.HTML,),
            ),
            FileDiscoveryGoal.REQUIRED,
        )

    expanded = replace(
        _sites()[0].scope,
        allowed_origins=parent.scope.allowed_origins,
    )
    with pytest.raises(RequestValidationError, match="^policy.scope_expansion$"):
        SiteBatchRequest(
            SiteBatchPhase.FIRST,
            parent,
            (),
            sites=(SiteBatchSite(expanded, FileDiscoveryGoal.REQUIRED), *_sites()[1:]),
        )


def test_refresh_accepts_persisted_incomplete_state_with_usable_pages() -> None:
    refresh = SiteBatchRequest(
        SiteBatchPhase.REFRESH,
        _request(),
        _contexts(first_complete=False),
    )

    reparsed = site_batch_request_from_mapping(refresh.to_dict())

    assert reparsed.refresh_contexts[0].previous_state.complete is False
    assert reparsed.refresh_contexts[0].previous_state.pages


def test_request_rejects_unknown_duplicate_order_and_identity_drift() -> None:
    refresh = SiteBatchRequest(SiteBatchPhase.REFRESH, _request(), _contexts())
    payload = refresh.to_dict()

    with pytest.raises(
        RequestValidationError, match="^site_batch_request.unknown_field$"
    ):
        site_batch_request_from_mapping({**payload, "retry": 1})
    with pytest.raises(
        RequestValidationError, match="^site_batch_request.duplicate_key$"
    ):
        site_batch_request_from_json(
            '{"schema_version":"web-listening-site-batch-request.v1",'
            '"phase":"first","phase":"refresh","request":{},'
            '"refresh_contexts":[]}'
        )
    with pytest.raises(
        RequestValidationError, match="^site_batch_request.site_order_mismatch$"
    ):
        SiteBatchRequest(
            SiteBatchPhase.REFRESH,
            _request(),
            tuple(reversed(_contexts())),
        )
    context = _contexts()[0]
    with pytest.raises(
        RequestValidationError, match="^site_batch_request.skill_state_mismatch$"
    ):
        SiteRefreshContext(
            context.site_skill,
            replace(context.previous_state, site_skill_digest="sha256:" + "f" * 64),
        )


def test_request_rejects_first_contexts_duplicate_sites_and_single_site() -> None:
    with pytest.raises(
        RequestValidationError, match="^site_batch_request.refresh_context_forbidden$"
    ):
        SiteBatchRequest(SiteBatchPhase.FIRST, _request(), _contexts())
    with pytest.raises(
        RequestValidationError, match="^site_batch_request.site_duplicate$"
    ):
        SiteBatchRequest(
            SiteBatchPhase.FIRST,
            replace(
                _request(),
                scope=replace(
                    _request().scope,
                    seeds=(
                        "https://one.test/",
                        "https://one.test/other",
                        "https://three.test/",
                    ),
                ),
            ),
            (),
        )
    with pytest.raises(
        RequestValidationError, match="^site_batch_request.multiple_sites_required$"
    ):
        SiteBatchRequest(
            SiteBatchPhase.FIRST,
            replace(
                _request(),
                scope=replace(_request().scope, seeds=(SEEDS[0],)),
            ),
            (),
        )


def test_refresh_contexts_are_exact_and_cover_every_site() -> None:
    contexts = _contexts()

    with pytest.raises(
        RequestValidationError, match="^site_batch_request.refresh_context_missing$"
    ):
        SiteBatchRequest(SiteBatchPhase.REFRESH, _request(), contexts[:-1])
    payload = contexts[0].to_dict()
    with pytest.raises(
        RequestValidationError, match="^site_batch_request.context_unknown_field$"
    ):
        SiteRefreshContext.from_dict({**payload, "fallback": True})


def test_refresh_rejects_a_context_that_authorizes_a_sibling_seed() -> None:
    contexts = _contexts()
    broad_first = _context(
        SEEDS[0],
        "a",
        allowed_origins=_request().scope.allowed_origins,
    )

    with pytest.raises(RequestValidationError, match="^policy.scope_expansion$"):
        SiteBatchRequest(
            SiteBatchPhase.REFRESH,
            _request(),
            (broad_first, *contexts[1:]),
        )
