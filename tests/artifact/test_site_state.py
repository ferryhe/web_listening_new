"""Strict Site State v1 contract tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from web_listening.artifact.model import ArtifactStoreError
from web_listening.artifact.site_state import (
    SiteState,
    SiteStatePage,
    site_state_from_mapping,
)


def _page(url: str, marker: str) -> SiteStatePage:
    return SiteStatePage(
        canonical_url=url,
        observation_id=f"observation-{marker * 32}",
        artifact_id=f"artifact-{marker * 64}",
        content_digest=f"sha256:{marker * 64}",
    )


def test_site_state_is_byte_stable_and_strictly_round_trips() -> None:
    state = SiteState(
        site_key="example.test",
        generated_at="2026-08-28T00:00:00Z",
        site_skill_digest="sha256:" + "c" * 64,
        complete=True,
        pages=(
            _page("https://example.test/a", "a"),
            _page("https://example.test/z", "b"),
        ),
    )

    rebuilt = site_state_from_mapping(json.loads(state.canonical_json_bytes()))

    assert rebuilt == state
    assert rebuilt.canonical_json_bytes() == state.canonical_json_bytes()


@pytest.mark.parametrize(
    "changed",
    [
        lambda state: replace(state, pages=tuple(reversed(state.pages))),
        lambda state: replace(state, pages=(state.pages[0], state.pages[0])),
        lambda state: replace(
            state,
            pages=(_page("https://outside.test/a", "a"), state.pages[1]),
        ),
    ],
)
def test_site_state_rejects_unstable_duplicate_or_cross_site_pages(changed) -> None:
    state = SiteState(
        "example.test",
        "2026-08-28T00:00:00Z",
        None,
        False,
        (_page("https://example.test/a", "a"), _page("https://example.test/z", "b")),
    )

    with pytest.raises(ArtifactStoreError):
        changed(state)


def test_site_state_rejects_unknown_fields() -> None:
    state = SiteState(
        "example.test",
        "2026-08-28T00:00:00Z",
        None,
        False,
        (),
    )
    payload = state.to_dict()
    payload["unknown"] = True

    with pytest.raises(ArtifactStoreError, match="schema.unknown_fields"):
        site_state_from_mapping(payload)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test:443/a",
        "https://example.test/a/../b",
        "https://EXAMPLE.test/a",
        "https://example.test/%2f",
        "https://example.test/%7Euser",
    ],
)
def test_site_state_rejects_noncanonical_page_urls(url: str) -> None:
    with pytest.raises(ArtifactStoreError, match="site_state.page_invalid"):
        _page(url, "a")
