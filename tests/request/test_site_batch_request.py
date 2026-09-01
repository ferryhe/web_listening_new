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
    SiteBatchPhase,
    SiteBatchRequest,
    SiteRefreshContext,
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


def test_first_and_refresh_are_distinct_strict_round_trippable_requests() -> None:
    first = SiteBatchRequest(SiteBatchPhase.FIRST, _request(), ())
    refresh = SiteBatchRequest(SiteBatchPhase.REFRESH, _request(), _contexts())

    assert site_batch_request_from_mapping(first.to_dict()) == first
    assert site_batch_request_from_json(first.canonical_json_bytes().decode()) == first
    assert site_batch_request_from_mapping(refresh.to_dict()) == refresh
    assert first.site_keys == ("one.test", "two.test", "three.test")
    assert refresh.site_keys == first.site_keys
    assert first.request_sha256 != refresh.request_sha256
    assert first.request.budgets == refresh.request.budgets == LIMITS


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
