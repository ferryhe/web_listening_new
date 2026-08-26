"""Minimal immutable filesystem and SQLite Artifact repository."""

# pylint: disable=too-many-lines

from __future__ import annotations

import os
import sqlite3
import stat
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

from web_listening.artifact.identity import (
    artifact_id,
    blob_relative_path,
    content_sha256,
    validate_blob_declaration,
    validate_mime_type,
    validate_relative_path,
    validate_sha256,
    validate_size,
)
from web_listening.artifact.lineage import (
    DERIVED_FROM,
    lineage_id,
    validate_artifact_id,
    validate_lineage,
    validate_role_lineage,
)
from web_listening.artifact.model import (
    Artifact,
    ArtifactRole,
    ArtifactStoreError,
    Blob,
    Lineage,
    Observation,
    StoredArtifact,
    StoredObservation,
)
from web_listening.artifact.observation import (
    ObservationProposal,
    new_observation_id,
    validate_observation_id,
    validate_observed_at,
    validate_source_url,
)


@dataclass(slots=True)
class _Publication:
    """Filesystem entries owned by the current uncommitted transaction."""

    target: Path
    target_identity: tuple[int, int] | None = None
    parent: Path | None = None
    parent_identity: tuple[int, int] | None = None
    temp: Path | None = None
    temp_identity: tuple[int, int] | None = None


class ArtifactStore:
    """Serialize atomic commits to one immutable local repository."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        self.database_path = self.root / "artifact.sqlite3"
        self._lock = threading.RLock()
        self._closed = False
        self._prepare_root()
        self._reject_symlink_chain(self.database_path)
        database_stat = self._lstat(self.database_path)
        if database_stat is not None:
            if self._is_link_like(self.database_path, database_stat):
                raise ArtifactStoreError("path.symlink")
            if not stat.S_ISREG(database_stat.st_mode):
                raise ArtifactStoreError("path.not_file")
        self._connection = sqlite3.connect(
            self.database_path, isolation_level=None, check_same_thread=False
        )
        self._connection.row_factory = sqlite3.Row
        try:
            self._reject_symlink_chain(self.database_path)
            database_stat = os.lstat(self.database_path)
            if self._is_link_like(self.database_path, database_stat):
                raise ArtifactStoreError("path.symlink")
            if not stat.S_ISREG(database_stat.st_mode):
                raise ArtifactStoreError("path.not_file")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = DELETE")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._create_schema()
        except BaseException:
            self._connection.close()
            raise

    def __enter__(self) -> ArtifactStore:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the repository handle; repeated closes are harmless."""
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def commit_observation(self, proposal: ObservationProposal) -> StoredObservation:
        """Atomically publish one Blob, Artifact, Observation, and optional edge."""
        prepared = self._prepare_proposal(proposal)
        blob, artifact, observation, related_observation_id = prepared
        publication: _Publication | None = None
        edges: tuple[Lineage, ...] = ()

        with self._lock:
            self._ensure_open()
            self._check_repository_paths()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                source_artifact_id = self._source_artifact_for(related_observation_id)
                self._validate_existing_blob(blob)
                self._validate_existing_artifact(artifact)
                publication = self._publish_blob(blob, proposal.content)
                self._commit_checkpoint("after_blob", observation)

                self._connection.execute(
                    "INSERT OR IGNORE INTO blobs"
                    " (sha256, size_bytes, relative_path) VALUES (?, ?, ?)",
                    (blob.sha256, blob.size_bytes, blob.relative_path),
                )
                self._connection.execute(
                    "INSERT OR IGNORE INTO artifacts"
                    " (artifact_id, blob_sha256, mime_type, role)"
                    " VALUES (?, ?, ?, ?)",
                    (
                        artifact.artifact_id,
                        artifact.blob_sha256,
                        artifact.mime_type,
                        artifact.role.value,
                    ),
                )
                self._connection.execute(
                    "INSERT INTO observations"
                    " (observation_id, artifact_id, source_url, observed_at)"
                    " VALUES (?, ?, ?, ?)",
                    (
                        observation.observation_id,
                        observation.artifact_id,
                        observation.source_url,
                        observation.observed_at,
                    ),
                )
                if source_artifact_id is not None:
                    edge = self._make_lineage(
                        observation, source_artifact_id, related_observation_id
                    )
                    edges = (edge,)
                    self._connection.execute(
                        "INSERT INTO lineage"
                        " (lineage_id, observation_id, artifact_id, relation,"
                        " source_observation_id, source_artifact_id)"
                        " VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            edge.lineage_id,
                            edge.observation_id,
                            edge.artifact_id,
                            edge.relation,
                            edge.source_observation_id,
                            edge.source_artifact_id,
                        ),
                    )
                self._commit_checkpoint("after_rows", observation)
                self._connection.execute("COMMIT")
            except BaseException:
                try:
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                finally:
                    self._rollback_publication(publication)
                raise
            return StoredObservation(
                blob, artifact, observation, edges, proposal.content
            )

    def read_blob(self, sha256: str) -> bytes:
        """Read a Blob only after revalidating its path, size, and hash."""
        digest = validate_sha256(sha256)
        with self._lock:
            self._ensure_open()
            self._check_repository_paths()
            row = self._connection.execute(
                "SELECT sha256, size_bytes, relative_path FROM blobs WHERE sha256 = ?",
                (digest,),
            ).fetchone()
            if row is None:
                raise ArtifactStoreError("blob.not_found")
            blob = self._blob_from_row(row)
            return self._read_verified_blob(
                self._path_for(blob.relative_path),
                blob.sha256,
                blob.size_bytes,
                corrupt_code="blob.corrupt",
            )

    def read_artifact(  # pylint: disable=redefined-outer-name
        self, artifact_id: str
    ) -> StoredArtifact:
        """Read an Artifact only after revalidating its identity and Blob."""
        identifier = validate_artifact_id(artifact_id)
        with self._lock:
            self._ensure_open()
            self._check_repository_paths()
            artifact_row = self._connection.execute(
                "SELECT artifact_id, blob_sha256, mime_type, role"
                " FROM artifacts WHERE artifact_id = ?",
                (identifier,),
            ).fetchone()
            if artifact_row is None:
                raise ArtifactStoreError("artifact.not_found")
            artifact = self._artifact_from_row(artifact_row)

            blob_row = self._connection.execute(
                "SELECT sha256, size_bytes, relative_path FROM blobs WHERE sha256 = ?",
                (artifact.blob_sha256,),
            ).fetchone()
            if blob_row is None:
                raise ArtifactStoreError("blob.not_found")
            blob = self._blob_from_row(blob_row)
            if artifact.blob_sha256 != blob.sha256:
                raise ArtifactStoreError("artifact.invalid")
            content = self._read_verified_blob(
                self._path_for(blob.relative_path),
                blob.sha256,
                blob.size_bytes,
                corrupt_code="blob.corrupt",
            )
            return StoredArtifact(
                artifact_id=artifact.artifact_id,
                blob_sha256=blob.sha256,
                size_bytes=blob.size_bytes,
                mime_type=artifact.mime_type,
                content=content,
            )

    def get_observation(self, observation_id: str) -> StoredObservation:
        """Load a complete Observation and fail closed on identity drift."""
        identifier = validate_observation_id(observation_id)
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT o.observation_id, o.artifact_id AS observation_artifact_id,"
                " o.source_url, o.observed_at, a.artifact_id, a.blob_sha256,"
                " a.mime_type, a.role, b.sha256, b.size_bytes, b.relative_path"
                " FROM observations AS o"
                " JOIN artifacts AS a ON a.artifact_id = o.artifact_id"
                " JOIN blobs AS b ON b.sha256 = a.blob_sha256"
                " WHERE o.observation_id = ?",
                (identifier,),
            ).fetchone()
            if row is None:
                raise ArtifactStoreError("observation.not_found")
            blob = self._blob_from_row(row)
            artifact = self._artifact_from_row(row)
            if row["observation_artifact_id"] != artifact.artifact_id:
                raise ArtifactStoreError("observation.invalid")
            observation = Observation(
                observation_id=validate_observation_id(row["observation_id"]),
                artifact_id=artifact.artifact_id,
                source_url=validate_source_url(row["source_url"]),
                observed_at=validate_observed_at(row["observed_at"]),
            )
            edges = self._load_lineage(observation, artifact)
            content = self.read_blob(blob.sha256)
            return StoredObservation(blob, artifact, observation, edges, content)

    @staticmethod
    def _commit_checkpoint(_stage: str, _observation: Observation) -> None:
        """Provide a narrow failure-injection seam for transaction tests."""

    @staticmethod
    def _publication_checkpoint(_stage: str) -> None:
        """Provide a semantic failure seam after filesystem effects."""

    def _prepare_root(self) -> None:
        self._reject_symlink_chain(self.root)
        if self.root.exists():
            self._require_directory(self.root)
        else:
            self.root.mkdir()
            self._require_directory(self.root)
        blobs = self.root / "blobs"
        self._reject_symlink_chain(blobs)
        if blobs.exists():
            self._require_directory(blobs)
        else:
            blobs.mkdir()
            self._require_directory(blobs)

    def _check_repository_paths(self) -> None:
        self._reject_symlink_chain(self.root)
        self._require_directory(self.root)
        self._reject_symlink_chain(self.root / "blobs")
        self._require_directory(self.root / "blobs")
        self._reject_symlink_chain(self.database_path)
        database_stat = os.lstat(self.database_path)
        if self._is_link_like(self.database_path, database_stat):
            raise ArtifactStoreError("path.symlink")
        if not stat.S_ISREG(database_stat.st_mode):
            raise ArtifactStoreError("path.not_file")

    @classmethod
    def _reject_symlink_chain(cls, path: Path) -> None:
        for candidate in (*reversed(path.parents), path):
            try:
                candidate_stat = os.lstat(candidate)
            except FileNotFoundError:
                continue
            if cls._is_link_like(candidate, candidate_stat):
                raise ArtifactStoreError("path.symlink")

    @classmethod
    def _require_directory(cls, path: Path) -> None:
        try:
            path_stat = os.lstat(path)
        except FileNotFoundError as exc:
            raise ArtifactStoreError("path.missing") from exc
        if cls._is_link_like(path, path_stat):
            raise ArtifactStoreError("path.symlink")
        if not stat.S_ISDIR(path_stat.st_mode):
            raise ArtifactStoreError("path.not_directory")

    @staticmethod
    def _is_link_like(path: Path, path_stat: os.stat_result) -> bool:
        """Identify symlinks and Windows junction/reparse traversal points."""
        if stat.S_ISLNK(path_stat.st_mode):
            return True
        is_junction = getattr(path, "is_junction", None)
        try:
            if is_junction is not None and is_junction():
                return True
        except OSError:
            return True
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        file_attributes = getattr(path_stat, "st_file_attributes", 0)
        return bool(
            file_attributes & reparse_flag or getattr(path_stat, "st_reparse_tag", 0)
        )

    def _create_schema(self) -> None:
        self._connection.executescript("""
            CREATE TABLE IF NOT EXISTS blobs (
                sha256 TEXT PRIMARY KEY,
                size_bytes INTEGER NOT NULL,
                relative_path TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id TEXT PRIMARY KEY,
                blob_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
                mime_type TEXT NOT NULL,
                role TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS observations (
                observation_id TEXT PRIMARY KEY,
                artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                source_url TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS lineage (
                lineage_id TEXT PRIMARY KEY,
                observation_id TEXT NOT NULL UNIQUE
                    REFERENCES observations(observation_id),
                artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                relation TEXT NOT NULL,
                source_observation_id TEXT NOT NULL
                    REFERENCES observations(observation_id),
                source_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                CHECK (observation_id <> source_observation_id)
            );
            """)

    @staticmethod
    def _prepare_proposal(
        proposal: ObservationProposal,
    ) -> tuple[Blob, Artifact, Observation, str | None]:
        if not isinstance(proposal, ObservationProposal):
            raise ArtifactStoreError("observation.proposal_invalid")
        digest, size = validate_blob_declaration(
            proposal.content, proposal.sha256, proposal.size_bytes
        )
        mime_type = validate_mime_type(proposal.mime_type)
        try:
            role = ArtifactRole(proposal.role)
        except (TypeError, ValueError) as exc:
            raise ArtifactStoreError("artifact.role_invalid") from exc
        related = validate_role_lineage(role, proposal.derived_from_observation_id)
        relative_path = blob_relative_path(digest)
        blob = Blob(digest, size, relative_path)
        artifact = Artifact(
            artifact_id(digest, mime_type, role), digest, mime_type, role
        )
        observation = Observation(
            new_observation_id(),
            artifact.artifact_id,
            validate_source_url(proposal.source_url),
            validate_observed_at(proposal.observed_at),
        )
        return blob, artifact, observation, related

    def _source_artifact_for(self, observation_id: str | None) -> str | None:
        if observation_id is None:
            return None
        row = self._connection.execute(
            "SELECT a.artifact_id, a.blob_sha256, a.mime_type, a.role"
            " FROM observations AS o"
            " JOIN artifacts AS a ON a.artifact_id = o.artifact_id"
            " WHERE o.observation_id = ?",
            (observation_id,),
        ).fetchone()
        if row is None:
            raise ArtifactStoreError("lineage.missing_reference")
        return self._artifact_from_row(row).artifact_id

    def _validate_existing_blob(self, expected: Blob) -> None:
        row = self._connection.execute(
            "SELECT sha256, size_bytes, relative_path FROM blobs WHERE sha256 = ?",
            (expected.sha256,),
        ).fetchone()
        if row is not None and self._blob_from_row(row) != expected:
            raise ArtifactStoreError("blob.conflict")

    def _validate_existing_artifact(self, expected: Artifact) -> None:
        row = self._connection.execute(
            "SELECT artifact_id, blob_sha256, mime_type, role"
            " FROM artifacts WHERE artifact_id = ?",
            (expected.artifact_id,),
        ).fetchone()
        if row is not None and self._artifact_from_row(row) != expected:
            raise ArtifactStoreError("artifact.conflict")

    def _publish_blob(  # pylint: disable=too-many-branches,too-many-locals,too-many-statements
        self, blob: Blob, content: bytes
    ) -> _Publication:
        target = self._path_for(blob.relative_path)
        parent = target.parent
        publication = _Publication(target=target, parent=parent)
        try:
            self._reject_symlink_chain(parent)
            parent_stat = self._lstat(parent)
            if parent_stat is not None:
                self._require_directory(parent)
            else:
                try:
                    parent.mkdir()
                except FileExistsError:
                    self._require_directory(parent)
                except BaseException:
                    self._claim_created_parent(publication)
                    raise
                else:
                    try:
                        self._publication_checkpoint("after_parent_mkdir")
                        self._claim_created_parent(publication)
                    except BaseException:
                        self._claim_created_parent(publication)
                        raise
                self._require_directory(parent)

            existing = self._lstat(target)
            if existing is not None:
                self._validate_blob_leaf(target, blob, existing, "blob.conflict")
                return publication

            temp = parent / f".{blob.sha256}.{uuid.uuid4().hex}.tmp"
            publication.temp = temp
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(temp, flags, 0o600)
            try:
                try:
                    temp_stat = os.fstat(descriptor)
                    self._publication_checkpoint("after_temp_stat")
                    publication.temp_identity = self._identity(temp_stat)
                except BaseException:
                    publication.temp_identity = self._recover_open_identity(
                        descriptor, temp
                    )
                    raise
                view = memoryview(content)
                written = 0
                while written < len(view):
                    count = os.write(descriptor, view[written:])
                    if count <= 0:
                        raise ArtifactStoreError("blob.publish_failed")
                    written += count
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

            try:
                try:
                    try:
                        os.link(temp, target, follow_symlinks=False)
                    except FileExistsError as exc:
                        target_stat = self._lstat(target)
                        if target_stat is None:
                            raise ArtifactStoreError("blob.publish_failed") from exc
                        self._validate_blob_leaf(
                            target, blob, target_stat, "blob.conflict"
                        )
                    else:
                        self._publication_checkpoint("after_target_link")
                        publication.target_identity = publication.temp_identity
                except BaseException:
                    self._claim_effected_target(publication)
                    raise
            finally:
                self._unlink_owned(publication.temp, publication.temp_identity)
                publication.temp = None
                publication.temp_identity = None
            return publication
        except BaseException:
            self._rollback_publication(publication)
            raise

    def _validate_blob_leaf(
        self, target: Path, blob: Blob, target_stat: os.stat_result, corrupt_code: str
    ) -> None:
        if self._is_link_like(target, target_stat):
            raise ArtifactStoreError("path.symlink")
        if not stat.S_ISREG(target_stat.st_mode):
            raise ArtifactStoreError(corrupt_code)
        self._read_verified_blob(
            target, blob.sha256, blob.size_bytes, corrupt_code=corrupt_code
        )

    def _read_verified_blob(
        self, target: Path, digest: str, size: int, *, corrupt_code: str
    ) -> bytes:
        self._reject_symlink_chain(target.parent)
        target_stat = self._lstat(target)
        if target_stat is None:
            raise ArtifactStoreError(corrupt_code)
        if self._is_link_like(target, target_stat):
            raise ArtifactStoreError("path.symlink")
        if not stat.S_ISREG(target_stat.st_mode) or target_stat.st_size != size:
            raise ArtifactStoreError(corrupt_code)

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(target, flags)
        except OSError as exc:
            raise ArtifactStoreError(corrupt_code) from exc
        try:
            opened_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened_stat.st_mode)
                or opened_stat.st_size != size
                or (opened_stat.st_dev, opened_stat.st_ino)
                != (target_stat.st_dev, target_stat.st_ino)
            ):
                raise ArtifactStoreError(corrupt_code)
            content = b""
            remaining = size + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                content += chunk
                remaining -= len(chunk)
        finally:
            os.close(descriptor)
        if len(content) != size:
            raise ArtifactStoreError(corrupt_code)
        if content_sha256(content) != digest:
            raise ArtifactStoreError(corrupt_code)
        return content

    @staticmethod
    def _lstat(path: Path) -> os.stat_result | None:
        try:
            return os.lstat(path)
        except FileNotFoundError:
            return None

    def _path_for(self, relative_path: str) -> Path:
        validated = validate_relative_path(relative_path)
        target = self.root.joinpath(*validated.split("/"))
        try:
            if os.path.commonpath((self.root, target)) != os.fspath(self.root):
                raise ArtifactStoreError("path.invalid")
        except ValueError as exc:
            raise ArtifactStoreError("path.invalid") from exc
        return target

    def _rollback_publication(self, publication: _Publication | None) -> None:
        if publication is None:
            return
        self._unlink_owned(publication.temp, publication.temp_identity)
        if publication.target_identity is not None:
            self._unlink_owned(publication.target, publication.target_identity)
        if publication.parent_identity is not None and publication.parent is not None:
            current = self._lstat(publication.parent)
            identity = publication.parent_identity
            if (
                current is not None
                and identity is not None
                and not self._is_link_like(publication.parent, current)
                and stat.S_ISDIR(current.st_mode)
                and (current.st_dev, current.st_ino) == identity
            ):
                try:
                    publication.parent.rmdir()
                except OSError:
                    pass

    @classmethod
    def _unlink_owned(cls, path: Path | None, identity: tuple[int, int] | None) -> None:
        if path is None or identity is None:
            return
        try:
            current = os.lstat(path)
        except FileNotFoundError:
            return
        if (
            not cls._is_link_like(path, current)
            and stat.S_ISREG(current.st_mode)
            and (current.st_dev, current.st_ino) == identity
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def _claim_created_parent(self, publication: _Publication) -> None:
        """Record a no-follow identity after an owned mkdir takes effect."""
        if publication.parent is None:
            return
        parent_stat = self._lstat(publication.parent)
        if (
            parent_stat is not None
            and not self._is_link_like(publication.parent, parent_stat)
            and stat.S_ISDIR(parent_stat.st_mode)
        ):
            publication.parent_identity = self._identity(parent_stat)

    def _recover_open_identity(
        self, descriptor: int, path: Path
    ) -> tuple[int, int] | None:
        """Confirm an exclusive temp path still names its opened file."""
        try:
            opened_stat = os.stat(descriptor)
            path_stat = os.lstat(path)
        except OSError:
            return None
        if (
            self._is_link_like(path, path_stat)
            or not stat.S_ISREG(opened_stat.st_mode)
            or not stat.S_ISREG(path_stat.st_mode)
            or self._identity(opened_stat) != self._identity(path_stat)
        ):
            return None
        return self._identity(opened_stat)

    def _claim_effected_target(self, publication: _Publication) -> None:
        """Claim a hardlink effect only when it has the owned temp identity."""
        target_stat = self._lstat(publication.target)
        if (
            target_stat is not None
            and publication.temp_identity is not None
            and not self._is_link_like(publication.target, target_stat)
            and stat.S_ISREG(target_stat.st_mode)
            and self._identity(target_stat) == publication.temp_identity
        ):
            publication.target_identity = publication.temp_identity

    @staticmethod
    def _identity(path_stat: os.stat_result) -> tuple[int, int]:
        return path_stat.st_dev, path_stat.st_ino

    @staticmethod
    def _make_lineage(
        observation: Observation,
        source_artifact_id: str,
        source_observation_id: str | None,
    ) -> Lineage:
        if source_observation_id is None:
            raise ArtifactStoreError("lineage.required")
        edge = Lineage(
            lineage_id=lineage_id(
                observation_id=observation.observation_id,
                artifact_id=observation.artifact_id,
                source_observation_id=source_observation_id,
                source_artifact_id=source_artifact_id,
            ),
            observation_id=observation.observation_id,
            artifact_id=observation.artifact_id,
            relation=DERIVED_FROM,
            source_observation_id=source_observation_id,
            source_artifact_id=source_artifact_id,
        )
        return validate_lineage(edge)

    def _load_lineage(
        self, observation: Observation, artifact: Artifact
    ) -> tuple[Lineage, ...]:
        rows = self._connection.execute(
            "SELECT lineage_id, observation_id, artifact_id, relation,"
            " source_observation_id, source_artifact_id"
            " FROM lineage WHERE observation_id = ? ORDER BY lineage_id",
            (observation.observation_id,),
        ).fetchall()
        edges = tuple(
            validate_lineage(
                Lineage(
                    row["lineage_id"],
                    row["observation_id"],
                    row["artifact_id"],
                    row["relation"],
                    row["source_observation_id"],
                    row["source_artifact_id"],
                )
            )
            for row in rows
        )
        if artifact.role is ArtifactRole.SOURCE and edges:
            raise ArtifactStoreError("lineage.forbidden")
        if artifact.role is ArtifactRole.DERIVED and len(edges) != 1:
            raise ArtifactStoreError("lineage.required")
        for edge in edges:
            if (
                edge.observation_id != observation.observation_id
                or edge.artifact_id != artifact.artifact_id
            ):
                raise ArtifactStoreError("lineage.invalid")
            source = self._connection.execute(
                "SELECT artifact_id FROM observations WHERE observation_id = ?",
                (edge.source_observation_id,),
            ).fetchone()
            if source is None or source["artifact_id"] != edge.source_artifact_id:
                raise ArtifactStoreError("lineage.missing_reference")
        return edges

    @staticmethod
    def _blob_from_row(row: sqlite3.Row) -> Blob:
        digest = validate_sha256(row["sha256"])
        size = validate_size(row["size_bytes"])
        relative_path = validate_relative_path(row["relative_path"])
        if relative_path != blob_relative_path(digest):
            raise ArtifactStoreError("blob.corrupt")
        return Blob(digest, size, relative_path)

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row) -> Artifact:
        identifier = validate_artifact_id(row["artifact_id"])
        digest = validate_sha256(row["blob_sha256"])
        mime_type = validate_mime_type(row["mime_type"])
        try:
            role = ArtifactRole(row["role"])
        except (TypeError, ValueError) as exc:
            raise ArtifactStoreError("artifact.role_invalid") from exc
        if identifier != artifact_id(digest, mime_type, role):
            raise ArtifactStoreError("artifact.invalid")
        return Artifact(identifier, digest, mime_type, role)

    def _ensure_open(self) -> None:
        if self._closed:
            raise ArtifactStoreError("repository.closed")
