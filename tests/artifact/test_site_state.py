"""Strict Site State v1 contract tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import json
from dataclasses import replace
from urllib.parse import quote

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


def _encoded_absolute_path_url(category: str) -> str:
    raw_by_category = {
        "windows": (67, 58, 47, 112, 108, 97, 99, 101, 104, 111, 108, 100, 101, 114),
        "windows-lower": (99, 58, 47, 112),
        "posix": (47, 119, 111, 114, 107, 115, 112, 97, 99, 101, 47, 112),
        "unc": (92, 92, 104, 111, 115, 116, 92, 112),
        "file-uri": (102, 105, 108, 101, 58, 47, 47, 47, 112),
        "nfkc": (67, 58, 0xFF0F, 112),
    }
    selected = "windows" if category == "multilayer" else category
    encoded = quote("".join(chr(item) for item in raw_by_category[selected]), safe="")
    if category == "multilayer":
        encoded = quote(encoded, safe="")
    return f"https://example.test/a?next={encoded}"


def _explicit_token_url(prefix_kind: str, safety_form: str) -> str:
    prefix_by_kind = {
        "sk-dash": "sk-",
        "sk-underscore": "sk_",
        "ghp": "ghp_",
        "github-pat": "github_pat_",
    }
    prefix = prefix_by_kind[prefix_kind]
    if safety_form == "percent":
        prefix = prefix.replace("-", "%2D").replace("_", "%5F")
    elif safety_form == "nfkc":
        prefix = quote(
            "".join(chr(ord(character) + 0xFEE0) for character in prefix), safe=""
        )
    elif safety_form == "multilayer":
        prefix = prefix.replace("-", "%252D").replace("_", "%255F")
    return f"https://example.test/evidence/{prefix}{'x' * 16}"


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
    assert rebuilt.digest == state.digest
    assert state.digest.startswith("sha256:")


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


def test_site_state_rejects_one_observation_reused_for_two_pages() -> None:
    first = _page("https://example.test/a", "a")
    second = replace(
        _page("https://example.test/b", "b"),
        observation_id=first.observation_id,
    )

    with pytest.raises(ArtifactStoreError, match="site_state.observation_duplicate"):
        SiteState(
            "example.test",
            "2026-08-28T00:00:00Z",
            None,
            False,
            (first, second),
        )


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


@pytest.mark.parametrize(
    "query",
    (
        "token=placeholder-value",
        "api_key=placeholder-value",
        "password=placeholder-value",
        "ToKeN=placeholder-value",
        "token%3Dplaceholder-value",
        "%2574oken=placeholder-value",
        "filter=password%3Dplaceholder-value",
    ),
)
def test_site_state_rejects_sensitive_query_evidence_without_echo(query: str) -> None:
    payload = SiteState(
        "example.test",
        "2026-08-28T00:00:00Z",
        None,
        False,
        (_page("https://example.test/a", "a"),),
    ).to_dict()
    payload["pages"][0]["canonical_url"] = f"https://example.test/a?{query}"

    with pytest.raises(
        ArtifactStoreError, match="^site_state.sensitive_data$"
    ) as caught:
        site_state_from_mapping(payload)

    assert "placeholder-value" not in str(caught.value)


def test_site_state_accepts_benign_canonical_query_roundtrip() -> None:
    page = _page("https://example.test/a?page=2&sort=asc", "a")
    state = SiteState(
        "example.test",
        "2026-08-28T00:00:00Z",
        None,
        False,
        (page,),
    )

    assert site_state_from_mapping(state.to_dict()) == state


def test_site_state_accepts_public_natural_language_slug_roundtrip() -> None:
    public_url = (
        "https://www.ipcc.ch/2026/06/25/"
        "keynote-address-ipcc-chair-jim-skea-world-climate-investment-summit/"
    )
    page = _page(public_url, "a")
    state = SiteState(
        "www.ipcc.ch",
        "2026-08-28T00:00:00Z",
        None,
        False,
        (page,),
    )

    assert site_state_from_mapping(state.to_dict()) == state


@pytest.mark.parametrize(
    "prefix_kind", ("sk-dash", "sk-underscore", "ghp", "github-pat")
)
@pytest.mark.parametrize("safety_form", ("raw", "percent", "nfkc", "multilayer"))
def test_site_state_rejects_explicit_token_prefix_categories_without_echo(
    prefix_kind: str,
    safety_form: str,
) -> None:
    expected_code = (
        "site_state.page_invalid"
        if safety_form == "percent"
        else "site_state.sensitive_data"
    )

    with pytest.raises(ArtifactStoreError, match=f"^{expected_code}$") as caught:
        _page(_explicit_token_url(prefix_kind, safety_form), "a")

    assert caught.value.args == (expected_code,)


@pytest.mark.parametrize(
    "category",
    (
        "windows",
        "windows-lower",
        "posix",
        "unc",
        "file-uri",
        "multilayer",
        "nfkc",
    ),
)
def test_site_state_rejects_encoded_absolute_path_categories_without_echo(
    category: str,
) -> None:
    payload = SiteState(
        "example.test",
        "2026-08-28T00:00:00Z",
        None,
        False,
        (_page("https://example.test/a", "a"),),
    ).to_dict()
    payload["pages"][0]["canonical_url"] = _encoded_absolute_path_url(category)

    with pytest.raises(
        ArtifactStoreError, match="^site_state.absolute_path$"
    ) as caught:
        site_state_from_mapping(payload)

    assert caught.value.args == ("site_state.absolute_path",)


def test_site_state_model_rejects_encoded_absolute_path_without_echo() -> None:
    with pytest.raises(
        ArtifactStoreError, match="^site_state.absolute_path$"
    ) as caught:
        _page(_encoded_absolute_path_url("windows"), "a")

    assert caught.value.args == ("site_state.absolute_path",)
