"""Pure URL, origin, path, and content-scope rules."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from ipaddress import ip_address
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from web_listening.request.model import ContentType, RequestValidationError, Scope

SCOPE_FIELDS = ("seeds", "allowed_origins", "include_paths", "content_types")
_MALFORMED_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_PATH_RAW_SAFE = "/%:@!$&'()*+,;=-._~"
_QUERY_RAW_SAFE = _UNRESERVED | frozenset("!$&'()*+,;=:@/?")


def _clean_text(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(character) <= 32 or ord(character) == 127 for character in value)
    ):
        raise RequestValidationError(code)
    return value


def _decoded_safe_path(value: str) -> str:
    if not value.startswith("/") or _MALFORMED_PERCENT.search(value):
        raise RequestValidationError("scope.path_invalid")
    decoded = value
    for _unused in range(len(value) + 1):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    else:
        raise RequestValidationError("scope.path_escape")
    if (
        "\\" in decoded
        or any(ord(character) <= 32 or ord(character) == 127 for character in decoded)
        or any(part in {".", ".."} for part in decoded.split("/"))
    ):
        raise RequestValidationError("scope.path_escape")
    return decoded


def _canonical_path(value: str) -> str:
    _decoded_safe_path(value)

    normalized = _canonical_percent_encoding(value, "scope.path_invalid")
    return quote(normalized, safe=_PATH_RAW_SAFE)


def _canonical_percent_encoding(value: str, invalid_code: str) -> str:
    if _MALFORMED_PERCENT.search(value):
        raise RequestValidationError(invalid_code)

    def replace_escape(match: re.Match[str]) -> str:
        character = chr(int(match.group(1), 16))
        return character if character in _UNRESERVED else f"%{ord(character):02X}"

    return _PERCENT_ESCAPE.sub(replace_escape, value)


def _canonical_query(value: str) -> str:
    if any(
        not character.isascii() or not "!" <= character <= "~" for character in value
    ):
        raise RequestValidationError("scope.query_invalid")
    if any(
        character not in _QUERY_RAW_SAFE and character != "%" for character in value
    ):
        raise RequestValidationError("scope.query_invalid")
    return _canonical_percent_encoding(value, "scope.query_invalid")


def _canonical_host(hostname: str) -> str:
    try:
        address = ip_address(hostname)
    except ValueError:
        try:
            host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise RequestValidationError("scope.url_invalid") from exc
        labels = host.split(".")
        if (
            not host
            or len(host) > 253
            or any(not _HOST_LABEL.fullmatch(label) for label in labels)
        ):
            raise RequestValidationError("scope.url_invalid") from None
        return host
    return f"[{address.compressed}]" if address.version == 6 else address.compressed


def canonicalize_url(value: object) -> str:
    """Return one canonical safe HTTP(S) URL without performing I/O."""
    text = _clean_text(value, "scope.url_invalid")
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError as exc:
        raise RequestValidationError("scope.url_invalid") from exc
    if parsed.scheme.lower() not in {"http", "https"} or parsed.hostname is None:
        raise RequestValidationError("scope.url_invalid")
    if port is not None and port < 1:
        raise RequestValidationError("scope.url_invalid")
    if (
        "@" in parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise RequestValidationError("scope.url_userinfo")
    if "#" in text:
        raise RequestValidationError("scope.url_fragment")

    path = _canonical_path(parsed.path or "/")
    host = _canonical_host(parsed.hostname)
    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    authority = host if port in {None, default_port} else f"{host}:{port}"
    query = _canonical_query(parsed.query)
    return urlunsplit((scheme, authority, path, query, ""))


def canonicalize_origin(value: object) -> str:
    """Return a canonical origin and reject URL components beyond an origin."""
    text = _clean_text(value, "scope.origin_invalid")
    try:
        parsed = urlsplit(text)
    except ValueError as exc:
        raise RequestValidationError("scope.origin_invalid") from exc
    if parsed.path not in {"", "/"} or parsed.query or "#" in text:
        raise RequestValidationError("scope.origin_invalid")
    try:
        canonical = canonicalize_url(text)
    except RequestValidationError as exc:
        if exc.code in {"scope.url_userinfo", "scope.url_fragment"}:
            raise
        raise RequestValidationError("scope.origin_invalid") from exc
    parsed = urlsplit(canonical)
    return f"{parsed.scheme}://{parsed.netloc}"


def canonicalize_include_path(value: object) -> str:
    """Return an exact path or a trailing-``/**`` subtree pattern."""
    text = _clean_text(value, "scope.path_invalid")
    if "?" in text or "#" in text or ("*" in text and not text.endswith("/**")):
        raise RequestValidationError("scope.path_invalid")
    if text.count("*") not in {0, 2}:
        raise RequestValidationError("scope.path_invalid")
    base = text[:-3] if text.endswith("/**") else text
    decoded = _canonical_path(base or "/")
    if text.endswith("/**"):
        return "/**" if decoded == "/" else f"{decoded.rstrip('/')}/**"
    return decoded


def path_is_included(path: str, patterns: tuple[str, ...]) -> bool:
    """Return whether a validated URL path matches one include pattern."""
    candidate = _decoded_safe_path(path)
    for pattern in patterns:
        if pattern.endswith("/**"):
            base = pattern[:-3]
            decoded_base = _decoded_safe_path(base) if base else ""
            if (
                not decoded_base
                or candidate == decoded_base
                or candidate.startswith(f"{decoded_base}/")
            ):
                return True
        elif candidate == _decoded_safe_path(pattern):
            return True
    return False


def _strict_sequence(value: object, empty_code: str) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or not value:
        raise RequestValidationError(empty_code)
    return value


def _reject_duplicates(values: tuple[object, ...]) -> None:
    if len(values) != len(set(values)):
        raise RequestValidationError("scope.duplicate")


def validate_scope(value: Scope) -> Scope:
    """Canonicalize and validate an immutable scope."""
    if not isinstance(value, Scope):
        raise RequestValidationError("scope.invalid")
    seeds = tuple(
        canonicalize_url(item)
        for item in _strict_sequence(value.seeds, "scope.empty_seeds")
    )
    origins = tuple(
        canonicalize_origin(item)
        for item in _strict_sequence(
            value.allowed_origins, "scope.empty_allowed_origins"
        )
    )
    paths = tuple(
        canonicalize_include_path(item)
        for item in _strict_sequence(value.include_paths, "scope.empty_include_paths")
    )
    raw_content_types = _strict_sequence(
        value.content_types, "scope.empty_content_types"
    )
    try:
        content_types = tuple(ContentType(item) for item in raw_content_types)
    except (TypeError, ValueError) as exc:
        raise RequestValidationError("scope.content_type_invalid") from exc

    for items in (seeds, origins, paths, content_types):
        _reject_duplicates(items)
    for seed in seeds:
        parsed = urlsplit(seed)
        if f"{parsed.scheme}://{parsed.netloc}" not in origins:
            raise RequestValidationError("scope.origin_not_allowed")
        if not path_is_included(parsed.path, paths):
            raise RequestValidationError("scope.path_not_included")
    return Scope(seeds, origins, paths, content_types)


def scope_from_mapping(value: object) -> Scope:
    """Build a strict Scope from one JSON-compatible object."""
    if not isinstance(value, Mapping):
        raise RequestValidationError("scope.invalid")
    keys = set(value)
    if not all(isinstance(key, str) for key in keys) or keys - set(SCOPE_FIELDS):
        raise RequestValidationError("scope.unknown_field")
    if set(SCOPE_FIELDS) - keys:
        raise RequestValidationError("scope.missing")
    return validate_scope(
        Scope(
            seeds=value["seeds"],  # type: ignore[arg-type]
            allowed_origins=value["allowed_origins"],  # type: ignore[arg-type]
            include_paths=value["include_paths"],  # type: ignore[arg-type]
            content_types=value["content_types"],  # type: ignore[arg-type]
        )
    )


def _pattern_contains(parent: str, child: str) -> bool:
    if not parent.endswith("/**"):
        return parent == child
    base = parent[:-3]
    child_base = child[:-3] if child.endswith("/**") else child
    return not base or child_base == base or child_base.startswith(f"{base}/")


def scope_is_subset(candidate: Scope, original: Scope) -> bool:
    """Return whether candidate authority preserves or narrows original authority."""
    return (
        set(candidate.seeds).issubset(original.seeds)
        and set(candidate.allowed_origins).issubset(original.allowed_origins)
        and set(candidate.content_types).issubset(original.content_types)
        and all(
            any(_pattern_contains(parent, child) for parent in original.include_paths)
            for child in candidate.include_paths
        )
    )


def scope_fingerprint(value: Scope) -> str:
    """Return a stable digest of only the governed scope fields."""
    payload = {
        "allowed_origins": sorted(value.allowed_origins),
        "content_types": sorted(item.value for item in value.content_types),
        "include_paths": sorted(value.include_paths),
        "seeds": sorted(value.seeds),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
