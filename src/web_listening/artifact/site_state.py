"""Strict, immutable Site State v1 evidence with no I/O authority."""

# pylint: disable=duplicate-code,missing-function-docstring
# pylint: disable=too-many-boolean-expressions,unidiomatic-typecheck

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass

from web_listening.artifact.lineage import validate_artifact_id
from web_listening.artifact.model import ArtifactStoreError
from web_listening.artifact.observation import (
    validate_observation_id,
    validate_observed_at,
)

SITE_STATE_SCHEMA_VERSION = "web-listening-site-state.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SITE_KEY = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z"
)
_HTTP_URL = re.compile(
    r"(?P<scheme>https?)://"
    r"(?P<host>[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)"
    r"(?::(?P<port>[1-9][0-9]{0,4}))?"
    r"(?P<path>/[^\s#?]*)(?:\?(?P<query>[^\s#]*))?\Z"
)
_MALFORMED_PERCENT = re.compile(r"%(?![0-9A-F]{2})")
_PERCENT_ESCAPE = re.compile(r"%([0-9A-F]{2})")
_PERCENT_RUN = re.compile(r"(?:%[0-9A-F]{2})+")
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_PATH_SAFE = _UNRESERVED | frozenset("/%:@!$&'()*+,;=")
_QUERY_SAFE = _UNRESERVED | frozenset("%!$&'()*+,;=:@/?")
_SECRET_QUERY = re.compile(
    r"(?:^|[?&])(?:auth|authorization|cookie|credential|password|secret|"
    r"token|api[_-]?key)=",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?i)(?:"
    r"\b(?:auth|authorization|proxy-authorization)\s*[:=]|"
    r"\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{4,}|"
    r"\b(?:cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"password|passwd|client[_-]?secret|sessionid)\s*[:=]|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bAKIA[A-Z0-9]{16}\b|"
    r"\b(?:sk[-_]|ghp_|github_pat_)[a-z0-9_-]{16,}\b|"
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


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ArtifactStoreError("site_state.invalid")
    return value


def _exact(value: Mapping[str, object], fields: set[str]) -> None:
    if set(value) - fields:
        raise ArtifactStoreError("schema.unknown_fields")
    if fields - set(value):
        raise ArtifactStoreError("schema.missing_fields")


def _unsafe_path(value: str) -> bool:
    return bool(
        _FILE_PATH.search(value)
        or _UNC_PATH.search(value)
        or value.startswith("/")
        or _WINDOWS_PATH.search(value)
        or _POSIX_PATH.search(value)
        or _GENERIC_POSIX_PATH.search(value)
    )


def _decode_percent_run(matched: re.Match[str]) -> str:
    encoded = matched.group(0)
    raw = bytes(
        int(encoded[index + 1 : index + 3], 16) for index in range(0, len(encoded), 3)
    )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _decoded_forms(value: str) -> tuple[str, ...]:
    layers = [value]
    for _unused in range(3):
        decoded = _PERCENT_RUN.sub(_decode_percent_run, layers[-1])
        if decoded == layers[-1]:
            break
        layers.append(decoded)
    forms: list[str] = []
    for current in layers:
        for candidate in (current, unicodedata.normalize("NFKC", current)):
            if candidate not in forms:
                forms.append(candidate)
    return tuple(forms)


def _url(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or value != value.strip():
        raise ArtifactStoreError("site_state.page_invalid")
    matched = _HTTP_URL.fullmatch(value)
    if matched is None:
        raise ArtifactStoreError("site_state.page_invalid")
    port_text = matched.group("port")
    port = None if port_text is None else int(port_text)
    if port is not None and (
        port > 65535
        or (matched.group("scheme") == "https" and port == 443)
        or (matched.group("scheme") == "http" and port == 80)
    ):
        raise ArtifactStoreError("site_state.page_invalid")
    path = matched.group("path")
    query = matched.group("query")
    if value.endswith("?") or not _canonical_component(path, _PATH_SAFE):
        raise ArtifactStoreError("site_state.page_invalid")
    if query is not None and not _canonical_component(query, _QUERY_SAFE):
        raise ArtifactStoreError("site_state.page_invalid")
    for decoded in _decoded_forms(value):
        if _SECRET_QUERY.search(decoded) or _SECRET_VALUE.search(decoded):
            raise ArtifactStoreError("site_state.sensitive_data")
        if _unsafe_path(decoded):
            raise ArtifactStoreError("site_state.absolute_path")
    decoded_path = path
    for _unused in range(len(path) + 1):
        next_path = _PERCENT_ESCAPE.sub(
            lambda item: chr(int(item.group(1), 16)), decoded_path
        )
        if next_path == decoded_path:
            break
        decoded_path = next_path
    if "\\" in decoded_path or any(
        part in {".", ".."} for part in decoded_path.split("/")
    ):
        raise ArtifactStoreError("site_state.page_invalid")
    return value, matched.group("host")


def _canonical_component(value: str, safe: frozenset[str]) -> bool:
    if _MALFORMED_PERCENT.search(value) or any(
        not character.isascii() or character not in safe for character in value
    ):
        return False
    return all(
        chr(int(match.group(1), 16)) not in _UNRESERVED
        for match in _PERCENT_ESCAPE.finditer(value)
    )


@dataclass(frozen=True, slots=True)
class SiteStatePage:
    """One page backed by a successful Observation and source Artifact."""

    canonical_url: str
    observation_id: str
    artifact_id: str
    content_digest: str

    def __post_init__(self) -> None:
        _url(self.canonical_url)
        validate_observation_id(self.observation_id)
        validate_artifact_id(self.artifact_id)
        if (
            not isinstance(self.content_digest, str)
            or _DIGEST.fullmatch(self.content_digest) is None
        ):
            raise ArtifactStoreError("site_state.digest_invalid")

    @classmethod
    def from_dict(cls, value: object) -> SiteStatePage:
        payload = _mapping(value)
        _exact(
            payload,
            {"canonical_url", "observation_id", "artifact_id", "content_digest"},
        )
        return cls(
            canonical_url=payload["canonical_url"],  # type: ignore[arg-type]
            observation_id=payload["observation_id"],  # type: ignore[arg-type]
            artifact_id=payload["artifact_id"],  # type: ignore[arg-type]
            content_digest=payload["content_digest"],  # type: ignore[arg-type]
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "canonical_url": self.canonical_url,
            "observation_id": self.observation_id,
            "artifact_id": self.artifact_id,
            "content_digest": self.content_digest,
        }


@dataclass(frozen=True, slots=True)
class SiteState:
    """One byte-stable snapshot of successfully observed source pages."""

    site_key: str
    generated_at: str
    site_skill_digest: str | None
    complete: bool
    pages: tuple[SiteStatePage, ...]
    schema_version: str = SITE_STATE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SITE_STATE_SCHEMA_VERSION:
            raise ArtifactStoreError("schema.version_invalid")
        if (
            not isinstance(self.site_key, str)
            or _SITE_KEY.fullmatch(self.site_key) is None
        ):
            raise ArtifactStoreError("site_state.site_key_invalid")
        validate_observed_at(self.generated_at)
        if type(self.complete) is not bool or type(self.pages) is not tuple:
            raise ArtifactStoreError("site_state.invalid")
        if not all(type(page) is SiteStatePage for page in self.pages):
            raise ArtifactStoreError("site_state.page_invalid")
        if self.site_skill_digest is not None and (
            not isinstance(self.site_skill_digest, str)
            or _DIGEST.fullmatch(self.site_skill_digest) is None
        ):
            raise ArtifactStoreError("site_state.digest_invalid")
        urls = tuple(page.canonical_url for page in self.pages)
        if urls != tuple(sorted(urls)):
            raise ArtifactStoreError("site_state.page_order_invalid")
        if len(urls) != len(set(urls)):
            raise ArtifactStoreError("site_state.page_duplicate")
        observation_ids = tuple(page.observation_id for page in self.pages)
        if len(observation_ids) != len(set(observation_ids)):
            raise ArtifactStoreError("site_state.observation_duplicate")
        if any(_url(url)[1] != self.site_key for url in urls):
            raise ArtifactStoreError("site_state.site_mismatch")

    @classmethod
    def from_dict(cls, value: object) -> SiteState:
        payload = _mapping(value)
        _exact(
            payload,
            {
                "schema_version",
                "site_key",
                "generated_at",
                "site_skill_digest",
                "complete",
                "pages",
            },
        )
        if not isinstance(payload["pages"], list):
            raise ArtifactStoreError("site_state.page_invalid")
        return cls(
            schema_version=payload["schema_version"],  # type: ignore[arg-type]
            site_key=payload["site_key"],  # type: ignore[arg-type]
            generated_at=payload["generated_at"],  # type: ignore[arg-type]
            site_skill_digest=payload["site_skill_digest"],  # type: ignore[arg-type]
            complete=payload["complete"],  # type: ignore[arg-type]
            pages=tuple(SiteStatePage.from_dict(page) for page in payload["pages"]),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "site_key": self.site_key,
            "generated_at": self.generated_at,
            "site_skill_digest": self.site_skill_digest,
            "complete": self.complete,
            "pages": [page.to_dict() for page in self.pages],
        }

    def canonical_json_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    @property
    def digest(self) -> str:
        """Return the frozen identity of the canonical state payload."""
        return f"sha256:{hashlib.sha256(self.canonical_json_bytes()).hexdigest()}"


def site_state_from_mapping(value: object) -> SiteState:
    """Parse one strict JSON-compatible Site State."""
    return SiteState.from_dict(value)


def validate_site_state_url(value: object) -> str:
    """Validate and return one canonical Site State page URL."""
    return _url(value)[0]


__all__ = [
    "SITE_STATE_SCHEMA_VERSION",
    "SiteState",
    "SiteStatePage",
    "site_state_from_mapping",
    "validate_site_state_url",
]
