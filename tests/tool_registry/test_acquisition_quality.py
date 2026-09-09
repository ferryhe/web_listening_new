"""Deterministic content validity without article analysis."""

# pylint: disable=missing-function-docstring

import hashlib

import pytest

from web_listening.tool_registry.acquisition.quality import quality_failure_code
from web_listening.tool_registry.eligibility import acquisition_failure_allows_switch
from web_listening.tool_registry.protocols.acquisition import AcquisitionOutput


def output(body, mime="text/html"):
    return AcquisitionOutput(
        "acquisition.web_http",
        "1.0.0",
        "https://example.test/",
        "https://example.test/",
        200,
        mime,
        body,
        hashlib.sha256(body).hexdigest(),
        (),
        0,
    )


@pytest.mark.parametrize(
    "body,code,switch",
    [
        (b"", "acquisition.empty", True),
        (b"<html><body> </body></html>", "acquisition.empty", True),
        (
            b"<script>document.write('content')</script>",
            "acquisition.script_only",
            True,
        ),
        (
            b"<title>Just a moment...</title><script src='/challenge.js'></script>",
            "acquisition.challenge",
            True,
        ),
        (b"<h1>Service unavailable</h1>", "acquisition.error_page", True),
        (b"<input type=password>", "acquisition.auth_required", False),
        (b"<h1>Access denied</h1>", "acquisition.permission_denied", False),
        (b"<h1>Permission denied</h1>", "acquisition.permission_denied", False),
        (b"<h1>Authentication required</h1>", "acquisition.auth_required", False),
        (
            b"<script src='/cf-chl-challenge.js'></script>",
            "acquisition.cloudflare_blocked",
            False,
        ),
        (b"<form><input type='password'></form>", "acquisition.auth_required", False),
        (
            b"<div class='g-recaptcha'>Verify you are human</div>",
            "acquisition.interaction_required",
            False,
        ),
        (b"<main>Useful public content</main>", None, False),
    ],
)
def test_quality_and_switch_classification(body, code, switch):
    assert quality_failure_code(output(body)) == code
    if code:
        assert acquisition_failure_allows_switch(code) is switch


def test_skill_words_use_visible_content_and_files_keep_their_own_capability():
    assert (
        quality_failure_code(
            output(b"<script>many words here</script><p>one</p>"), ("text/html",), 2
        )
        == "runtime.quality_minimum_words"
    )
    assert quality_failure_code(output(b"%PDF-1.7", "application/pdf")) is None
    assert (
        quality_failure_code(output(b"ok"), ("application/pdf",), 0)
        == "runtime.quality_mime_mismatch"
    )


def test_cloudflare_switch_requires_the_http_method():
    assert acquisition_failure_allows_switch(
        "acquisition.cloudflare_blocked", "acquisition.web_http"
    )
    assert not acquisition_failure_allows_switch(
        "acquisition.cloudflare_blocked", "acquisition.playwright"
    )
