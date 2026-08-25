"""Canonical identities and declarations for immutable Artifact values."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath, PureWindowsPath

from web_listening.artifact.model import ArtifactRole, ArtifactStoreError

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MIME_TYPE = re.compile(
    r"[a-z0-9][a-z0-9!#$%&'*+.^_`|~-]*/[a-z0-9][a-z0-9!#$%&'*+.^_`|~-]*\Z"
)
_PORTABLE_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


def validate_sha256(value: str) -> str:
    """Return a canonical lowercase SHA-256 declaration."""
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ArtifactStoreError("blob.sha256_invalid")
    return value


def validate_size(value: int) -> int:
    """Return a non-negative byte count, rejecting booleans."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ArtifactStoreError("blob.size_invalid")
    return value


def content_sha256(content: bytes) -> str:
    """Hash an exact immutable byte string."""
    if not isinstance(content, bytes):
        raise ArtifactStoreError("blob.content_invalid")
    return hashlib.sha256(content).hexdigest()


def validate_blob_declaration(
    content: bytes, declared_sha256: str, declared_size: int
) -> tuple[str, int]:
    """Recompute and verify the caller's Blob declaration."""
    digest = validate_sha256(declared_sha256)
    size = validate_size(declared_size)
    actual_digest = content_sha256(content)
    if digest != actual_digest:
        raise ArtifactStoreError("blob.sha256_mismatch")
    if size != len(content):
        raise ArtifactStoreError("blob.size_mismatch")
    return digest, size


def validate_mime_type(value: str) -> str:
    """Accept one lowercase MIME type token without parameters."""
    if not isinstance(value, str) or _MIME_TYPE.fullmatch(value) is None:
        raise ArtifactStoreError("mime.invalid")
    return value


def validate_relative_path(value: str) -> str:
    """Accept an unambiguous portable relative path."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1024
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ArtifactStoreError("path.invalid")

    posix_path = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    parts = value.split("/")
    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ArtifactStoreError("path.invalid")

    for part in parts:
        stem = part.split(".", maxsplit=1)[0].upper()
        if (
            len(part) > 255
            or part.endswith((".", " "))
            or _PORTABLE_SEGMENT.fullmatch(part) is None
            or stem in _WINDOWS_RESERVED
        ):
            raise ArtifactStoreError("path.invalid")
    return value


def blob_relative_path(sha256: str) -> str:
    """Map a validated digest to its deterministic CAS path."""
    digest = validate_sha256(sha256)
    return f"blobs/{digest[:2]}/{digest}.blob"


def artifact_id(blob_sha256: str, mime_type: str, role: ArtifactRole) -> str:
    """Return the deterministic identity of an immutable Artifact payload."""
    digest = validate_sha256(blob_sha256)
    mime = validate_mime_type(mime_type)
    try:
        normalized_role = ArtifactRole(role)
    except (TypeError, ValueError) as exc:
        raise ArtifactStoreError("artifact.role_invalid") from exc
    payload = {
        "blob_sha256": digest,
        "mime_type": mime,
        "role": normalized_role.value,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"artifact-{hashlib.sha256(encoded).hexdigest()}"
