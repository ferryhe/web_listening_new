"""Minimal deterministic Acquisition content checks, shared by all readers."""

from html.parser import HTMLParser

from web_listening.request.model import ContentType, classify_mime_type
from web_listening.tool_registry.protocols.acquisition import AcquisitionOutput


class _VisibleText(HTMLParser):
    """Collect text while ignoring non-readable HTML containers."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden: list[str] = []
        self.script = False
        self.navigation = False
        self.authentication = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "input" and (attributes.get("type") or "").casefold() == "password":
            self.authentication = True
        if tag == "script":
            self.script = True
        if tag == "meta" and attributes.get("http-equiv", "").lower() == "refresh":
            self.navigation = True
        if tag in {"script", "style", "head", "template", "noscript", "svg"}:
            self.hidden.append(tag)

    def handle_endtag(self, tag):
        if self.hidden and tag == self.hidden[-1]:
            self.hidden.pop()

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def quality_failure_code(  # pylint: disable=too-many-return-statements,too-many-branches
    output: AcquisitionOutput,
    allowed_mime_types: tuple[str, ...] | None = None,
    minimum_words: int = 0,
) -> str | None:
    """Classify validity only; do not extract articles or infer page meaning."""
    if allowed_mime_types is not None and output.mime_type not in allowed_mime_types:
        return "runtime.quality_mime_mismatch"
    if not output.body.strip():
        return "acquisition.empty"
    source = output.body.decode("utf-8", errors="replace")
    visible = source
    if classify_mime_type(output.mime_type) is ContentType.HTML:
        lowered = source.casefold()
        if any(
            marker in lowered
            for marker in (
                "g-recaptcha",
                "h-captcha",
                "cf-turnstile",
                "verify you are human",
            )
        ):
            return "acquisition.interaction_required"
        if any(marker in lowered for marker in ('type="password"', "type='password'")):
            return "acquisition.auth_required"
        if "cf-chl-" in lowered:
            return "acquisition.cloudflare_blocked"
        if any(
            marker in lowered
            for marker in (
                "<title>just a moment",
                "<title>checking your browser",
            )
        ):
            return "acquisition.challenge"
        parser = _VisibleText()
        parser.feed(source)
        if parser.authentication:
            return "acquisition.auth_required"
        visible = " ".join(parser.parts)
        normalized = " ".join(visible.casefold().split())
        if normalized == "authentication required":
            return "acquisition.auth_required"
        if normalized in {"access denied", "permission denied"}:
            return "acquisition.permission_denied"
        if normalized in {
            "service unavailable",
            "internal server error",
            "bad gateway",
        }:
            return "acquisition.error_page"
        if not normalized and not parser.navigation:
            return "acquisition.script_only" if parser.script else "acquisition.empty"
    if len(visible.split()) < minimum_words:
        return "runtime.quality_minimum_words"
    return None


def response_failure_code(status, headers):
    """Classify rejected responses from existing parent metadata, never a body."""
    if status == 401:
        return "acquisition.auth_required"
    if status != 403:
        return "gateway.http_status"
    headers = {key.lower(): value.lower() for key, value in headers.items()}
    challenge = headers.get("cf-mitigated") == "challenge"
    block_template = (
        headers.get("server") == "cloudflare"
        and bool(headers.get("cf-ray"))
        and headers.get("cache-control")
        == "private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
        and headers.get("x-frame-options") == "sameorigin"
        and headers.get("referrer-policy") == "same-origin"
    )
    if challenge or block_template:
        return "acquisition.cloudflare_blocked"
    return "acquisition.permission_denied"
