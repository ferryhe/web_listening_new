"""Stable safe errors and strict Result input validation."""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

_SAFE_CODE = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_SECRET_KEYS = {
    "auth",
    "authorization",
    "proxyauthorization",
    "cookie",
    "setcookie",
    "token",
    "accesstoken",
    "refreshtoken",
    "apikey",
    "password",
    "passwd",
    "secret",
    "clientsecret",
    "privatekey",
    "credential",
    "sessionid",
}
_SECRET_KEY_PARTS = (
    "authorization",
    "cookie",
    "credential",
    "password",
    "privatekey",
    "secret",
    "sessionid",
    "token",
)
_SECRET_VALUE = re.compile(
    r"(?i)(?:"
    r"\b(?:auth|authorization|proxy-authorization)\s*[:=]|"
    r"\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{4,}|"
    r"\b(?:cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"password|passwd|client[_-]?secret|sessionid)\s*[:=]|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bAKIA[A-Z0-9]{16}\b|"
    r"\b(?:sk|ghp|github_pat)-?[a-z0-9_-]{16,}\b|"
    r"https?://[^/?#\s]*@"
    r")"
)
_WINDOWS_PATH = re.compile(r"(?i)(?:^|[\s'\"(=:])(?:[a-z]:[\\/]|\\\\)")
_POSIX_PATH = re.compile(
    r"(?i)(?:^|[\s'\"(=:])/(?:home|users|tmp|var|etc|opt|root|mnt|srv|usr|"
    r"private|workspace|project)(?:/|\b)"
)
_GENERIC_POSIX_PATH = re.compile(r"(?:^|[\s'\"(=:])/(?!/)[A-Za-z0-9._~-]+/")
_UNC_PATH = re.compile(r"(?:^|[\s'\"(=])(?:/{2}|\\{2})[^/\\\s]+[/\\]")
_FILE_PATH = re.compile(r"(?i)(?:^|[\s'\"(=:])file:/+")
_PERCENT_RUN = re.compile(r"(?:%[0-9a-fA-F]{2})+")
_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_HTTP_URL = re.compile(r"https?://(?P<authority>[^/?#]+)(?:[/?#].*)?\Z")
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


class ResultValidationError(ValueError):
    """A stable validation failure safe for a Result boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require_mapping(value: object) -> Mapping[str, Any]:
    """Return a string-keyed mapping or reject it as schema drift."""
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ResultValidationError("schema.invalid")
    return value


def require_exact_fields(value: Mapping[str, Any], expected: set[str]) -> None:
    """Reject missing or unknown versioned fields."""
    observed = set(value)
    if observed - expected:
        raise ResultValidationError("schema.unknown_fields")
    if expected - observed:
        raise ResultValidationError("schema.missing_fields")


def validate_text(
    value: object, *, code: str = "schema.invalid", maximum: int = 2048
) -> str:
    """Validate one bounded non-empty safe string."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ResultValidationError(code)
    ensure_safe_text(value)
    return value


def validate_nonnegative_int(value: object, *, code: str) -> int:
    """Validate a non-negative integer while rejecting booleans."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ResultValidationError(code)
    return value


def validate_sha256(value: object, *, code: str = "sha256.invalid") -> str:
    """Validate a canonical SHA-256 digest."""
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ResultValidationError(code)
    return value


def validate_utc_time(value: object) -> str:
    """Validate a canonical whole-second UTC timestamp."""
    if not isinstance(value, str) or _UTC_TIME.fullmatch(value) is None:
        raise ResultValidationError("time.invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ResultValidationError("time.invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ResultValidationError("time.invalid")
    return value


def parse_utc_time(value: str) -> datetime:
    """Parse a timestamp already accepted by ``validate_utc_time``."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def validate_url(value: object, *, allow_urn: bool = False) -> str:
    """Validate inert HTTP(S) evidence without URL/network authority."""
    text = validate_text(value, code="url.invalid")
    if allow_urn and text.startswith("urn:web-listening:"):
        return text
    if not text.startswith(("https://", "http://")):
        raise ResultValidationError("url.invalid")
    _validate_http_url(text, _percent_layers(text)[-1])
    return text


def _validate_http_url(encoded: str, structural: str) -> None:
    """Validate one inert HTTP(S) string without rewriting or resolving it."""
    if _BAD_PERCENT.search(encoded) or "\\" in structural:
        raise ResultValidationError("url.invalid")
    matched = _HTTP_URL.fullmatch(structural)
    if matched is None:
        raise ResultValidationError("url.invalid")
    authority = matched.group("authority")
    if "@" in authority:
        raise ResultValidationError("result.sensitive_data")
    if any(character.isspace() for character in authority) or "\\" in authority:
        raise ResultValidationError("url.invalid")
    host, port = _split_authority(authority)
    if not _valid_host(host):
        raise ResultValidationError("url.invalid")
    if port is not None and (
        not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535
    ):
        raise ResultValidationError("url.invalid")


def _decoded_forms(value: str) -> tuple[str, ...]:
    """Return bounded raw, percent-decoded, and NFKC safety forms."""
    forms: list[str] = []
    for current in _percent_layers(value):
        for candidate in (current, unicodedata.normalize("NFKC", current)):
            if candidate not in forms:
                forms.append(candidate)
    return tuple(forms)


def _percent_layers(value: str) -> tuple[str, ...]:
    """Return raw plus at most three percent-decoded forms without NFKC."""
    layers = [value]
    for _unused in range(3):
        current = layers[-1]
        decoded = _PERCENT_RUN.sub(_decode_percent_run, current)
        if decoded == current:
            break
        layers.append(decoded)
    return tuple(layers)


def _decode_percent_run(matched: re.Match[str]) -> str:
    """Decode one consecutive percent run as UTF-8, with byte-safe fallback."""
    encoded = matched.group(0)
    raw = bytes(
        int(encoded[index + 1 : index + 3], 16) for index in range(0, len(encoded), 3)
    )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _split_authority(authority: str) -> tuple[str, str | None]:
    """Split an already bounded host authority without interpreting URLs."""
    host = ""
    port = None
    if authority.startswith("["):
        close = authority.find("]")
        if close >= 0:
            candidate = authority[: close + 1]
            remainder = authority[close + 1 :]
            if not remainder:
                host = candidate
            elif remainder.startswith(":"):
                host, port = candidate, remainder[1:]
    elif authority.count(":") <= 1 and ":" in authority:
        host, port = authority.rsplit(":", maxsplit=1)
    elif ":" not in authority:
        host = authority
    return host, port


def _valid_host(host: str) -> bool:
    """Accept a conservative DNS/IPv4 label sequence or bracketed IPv6 host."""
    if host.startswith("[") and host.endswith("]"):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ipaddress.AddressValueError:
            valid = False
        else:
            valid = True
    elif len(host) > 253:
        valid = False
    elif host.count(".") == 3 and all(part.isdigit() for part in host.split(".")):
        try:
            ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError:
            valid = False
        else:
            valid = True
    else:
        labels = host.split(".")
        valid = bool(host) and all(_HOST_LABEL.fullmatch(label) for label in labels)
    return valid


def _unsafe_path(value: str) -> bool:
    """Detect local absolute path forms after safety decoding."""
    return bool(
        _FILE_PATH.search(value)
        or _UNC_PATH.search(value)
        or value.startswith("/")
        or _WINDOWS_PATH.search(value)
        or _POSIX_PATH.search(value)
        or _GENERIC_POSIX_PATH.search(value)
    )


def _secret_key(value: str) -> bool:
    """Detect secret-bearing keys in raw or encoded spellings."""
    for form in _decoded_forms(value):
        normalized = re.sub(r"[^a-z0-9]", "", form.lower())
        if (
            normalized in _SECRET_KEYS
            or "apikey" in normalized
            or any(part in normalized for part in _SECRET_KEY_PARTS)
        ):
            return True
    return False


def ensure_safe_text(value: str) -> None:
    """Reject secret-like values and local absolute paths."""
    forms = _decoded_forms(value)
    for form in forms:
        if any(
            unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in form
        ):
            raise ResultValidationError("result.sensitive_data")
        if _SECRET_VALUE.search(form):
            raise ResultValidationError("result.sensitive_data")
        if _unsafe_path(form):
            raise ResultValidationError("result.absolute_path")
    structural_forms = _percent_layers(value)
    http_forms = tuple(
        form for form in structural_forms if form.startswith(("https://", "http://"))
    )
    if http_forms:
        syntax_form = value if value in http_forms else http_forms[0]
        _validate_http_url(syntax_form, http_forms[-1])


def ensure_safe_payload(value: object) -> None:
    """Recursively reject unsafe keys, values, and unsupported JSON shapes."""
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        ensure_safe_text(value)
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ResultValidationError("schema.invalid")
            if _secret_key(key):
                raise ResultValidationError("result.sensitive_data")
            ensure_safe_text(key)
            ensure_safe_payload(child)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            ensure_safe_payload(child)
        return
    raise ResultValidationError("schema.invalid")


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Serialize one safe payload with byte-stable JSON settings."""
    ensure_safe_payload(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class SafeError:
    """A stable error containing only bounded non-sensitive details."""

    code: str
    message: str
    details: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or _SAFE_CODE.fullmatch(self.code) is None:
            raise ResultValidationError("error.code_invalid")
        validate_text(self.message, code="error.message_invalid", maximum=512)
        if not isinstance(self.details, tuple):
            raise ResultValidationError("error.details_invalid")
        observed: set[str] = set()
        normalized: list[tuple[str, str]] = []
        for item in self.details:
            if not isinstance(item, tuple) or len(item) != 2:
                raise ResultValidationError("error.details_invalid")
            key = validate_text(item[0], code="error.details_invalid", maximum=128)
            detail = validate_text(item[1], code="error.details_invalid", maximum=512)
            if key in observed:
                raise ResultValidationError("error.details_invalid")
            ensure_safe_payload({key: detail})
            observed.add(key)
            normalized.append((key, detail))
        object.__setattr__(self, "details", tuple(sorted(normalized)))

    @classmethod
    def from_dict(cls, value: object) -> SafeError:
        """Parse one strict versioned error object."""
        payload = require_mapping(value)
        ensure_safe_payload(payload)
        require_exact_fields(payload, {"code", "message", "details"})
        details = require_mapping(payload["details"])
        return cls(
            code=payload["code"],
            message=payload["message"],
            details=tuple(details.items()),
        )

    def to_dict(self) -> dict[str, object]:
        """Return a plain canonicalizable error object."""
        payload: dict[str, object] = {
            "code": self.code,
            "message": self.message,
            "details": dict(self.details),
        }
        ensure_safe_payload(payload)
        return payload
